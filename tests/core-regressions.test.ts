import { describe, expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import { manifestDigest, publicSourceURL, requireMaintainer, revisionImage, validateRevision } from '../src/lib/server/policy';
import { sha256 } from '../src/lib/server/db';
import { readOprEvidence, sourceRedirects } from '../src/lib/server/sbom';
import { approveRevision, startFactory, submitRequest } from '../src/lib/server/requests';
import { createFactoryRevision } from '../services/pipeline/revision';
import { nextPackageRelease } from '../services/pipeline/pkgrel';
import { finalDescription } from '../src/lib/server/descriptions';
import type { Env } from '../src/lib/server/env';
import type { Revision } from '../src/lib/model';
import { asD1, TestD1 } from './d1';

const requestSchema = `
CREATE TABLE rateLimit(id TEXT PRIMARY KEY,key TEXT NOT NULL UNIQUE,count INTEGER NOT NULL,lastRequest INTEGER NOT NULL);
CREATE TABLE requests(
  id TEXT PRIMARY KEY,name TEXT NOT NULL,upstream_url TEXT NOT NULL,source_kind TEXT NOT NULL,
  area TEXT NOT NULL,description TEXT NOT NULL DEFAULT '',declared_license TEXT NOT NULL DEFAULT 'unknown',requested_by TEXT NOT NULL,status TEXT NOT NULL,created_at INTEGER NOT NULL,updated_at INTEGER NOT NULL,rejection_reason TEXT
);
CREATE UNIQUE INDEX requests_active_name ON requests(name) WHERE status NOT IN ('built','rejected','failed');
CREATE TABLE audit_events(id INTEGER PRIMARY KEY AUTOINCREMENT,actor TEXT,action TEXT,target TEXT,detail TEXT,created_at INTEGER);
`;

function env(db: TestD1): Env {
  return {
    DB: asD1(db), ARTIFACTS: {} as R2Bucket, PUBLIC_ORIGIN: 'https://opr.example',
    MAINTAINER_GITHUB_IDS: '', SECURITY_GITHUB_IDS: '', QUARANTINE_HOURS: '48',
  };
}

const actor = { id: 'github:1', role: 'maintainer' as const, areas: ['system'] };

function revision(overrides: Partial<Revision> = {}): Revision {
  return {
    id: 'revision-1', request_id: 'request-1', version: '1.0.0', recipe: 'pkgname=hello\n', recipe_sha256: '', manifest_sha256: '',
    sources_json: JSON.stringify([{ name: 'hello.tar.gz', url: 'https://example.com/hello.tar.gz', sha256: 'a'.repeat(64) }]),
    dependencies_json: '[]', smoke_commands_json: '["hello --version"]', architectures_json: '["x86_64"]', source_date_epoch: 1_700_000_000,
    image_digest: `ghcr.io/opr/builder@sha256:${'b'.repeat(64)}`, license: 'MIT', surface: 'binary', explanation: '', sbom_json: '{}',
    lint_json: '{"passed":true}', upstream_commit: null, pr_url: 'https://github.com/opr/recipes/pull/1', commit_sha: 'c'.repeat(40), created_at: 1,
    ...overrides,
  };
}

describe('core security regressions', () => {
  test('a failed factory run can restart without a revision and records the reason', async () => {
    const db = new TestD1(requestSchema + 'ALTER TABLE requests ADD COLUMN factory_run_id TEXT;');
    try {
      const service = env(db);
      service.PIPELINE = { fetch: async () => new Response('{}') } as unknown as Fetcher;
      const requestId = await submitRequest(service, actor, { name: 'retry-test', description: 'Factory retry test', upstream_url: 'https://example.com/source.tar.gz', source_kind: 'archive', area: 'system', declared_license: 'MIT' });
      await service.DB.prepare("UPDATE requests SET status='failed' WHERE id=?").bind(requestId).run();
      await expect(startFactory(service, actor, requestId, 'x'.repeat(2001))).rejects.toMatchObject({ status: 400 });
      await startFactory(service, actor, requestId, ' Fixed Git shell compatibility. ');
      expect(await service.DB.prepare('SELECT status FROM requests WHERE id=?').bind(requestId).first<{ status: string }>()).toEqual({ status: 'generating' });
      const event = await service.DB.prepare("SELECT detail FROM audit_events WHERE action='factory.regenerated'").first<{ detail: string }>();
      expect(JSON.parse(event!.detail).reason).toBe('Fixed Git shell compatibility.');
      const { maintainerFeedbackForGeneration } = await import('../services/pipeline/tools');
      const generationId = JSON.parse(event!.detail).generationId as string;
      expect(maintainerFeedbackForGeneration([
        { detail: JSON.stringify({ generationId: 'stale-generation', reason: 'stale repair' }) },
        { detail: event!.detail },
      ], generationId)).toBe('Fixed Git shell compatibility.');
      expect(maintainerFeedbackForGeneration([
        { detail: JSON.stringify({ generationId: 'other-generation', reason: 'wrong run' }) },
      ], generationId)).toBeUndefined();
    } finally { db.close(); }
  });
  test('public recipe binding preserves existing immutable manifests when absent', async () => {
    const original = revision({ recipe_sha256: 'd'.repeat(64) });
    const legacyDigest = 'c812a72af1901ca22614885ebaf639995bedcc1b6625eb3db0315237995cad3c';
    expect(await manifestDigest(original)).toBe(legacyDigest);
    expect(await manifestDigest({ ...original, public_recipe_sha256: null })).toBe(legacyDigest);
    const publicRecipe = { ...original, public_recipe_sha256: 'e'.repeat(64) };
    expect(await manifestDigest(publicRecipe)).not.toBe(legacyDigest);
    expect(await manifestDigest({ ...publicRecipe, public_recipe_sha256: 'f'.repeat(64) })).not.toBe(await manifestDigest(publicRecipe));
  });

  test('security actors can maintain every area', () => {
    const security = { id: 'github:2', role: 'security' as const, areas: [] };
    expect(requireMaintainer(security).role).toBe('security');
    expect(requireMaintainer(security, 'system').id).toBe('github:2');
    expect(requireMaintainer(security, 'gaming').id).toBe('github:2');
  });

  test('source URLs reject credential query parameters while allowing ordinary queries', () => {
    expect(publicSourceURL('https://example.com/source.tar.gz?download=1')).toContain('download=1');
    for (const parameter of ['token', 'api_key', 'client_secret', 'private_key', 'password', 'signature', 'x-amz-credential']) {
      expect(() => publicSourceURL(`https://example.com/source.tar.gz?${parameter}=secret`)).toThrow();
    }
  });

  test('manifest digest binds revision identity and malformed JSON fails as a policy error', async () => {
    const original = revision({ recipe_sha256: await sha256('pkgname=hello\n') });
    original.manifest_sha256 = await manifestDigest(original);
    const other = { ...original, id: 'revision-2' };
    expect(await manifestDigest(other)).not.toBe(original.manifest_sha256);
    const malformedSources = { ...original, sources_json: 'null' };
    malformedSources.manifest_sha256 = await manifestDigest(malformedSources);
    await expect(validateRevision(malformedSources)).rejects.toMatchObject({ status: 409 });
    const malformedLint = { ...original, lint_json: 'null' };
    malformedLint.manifest_sha256 = await manifestDigest(malformedLint);
    await expect(validateRevision(malformedLint)).rejects.toMatchObject({ status: 409 });
  });

  test('per-architecture build images are pinned and included in revision integrity', async () => {
    const multi = revision({
      recipe_sha256: await sha256('pkgname=hello\n'),
      architectures_json: JSON.stringify(['x86_64', 'aarch64']),
      build_images_json: JSON.stringify({
        x86_64: `ghcr.io/opr/builder-x86_64:stable@sha256:${'c'.repeat(64)}`,
        aarch64: `ghcr.io/opr/builder-aarch64@sha256:${'d'.repeat(64)}`,
      }),
    });
    multi.manifest_sha256 = await manifestDigest(multi);
    await validateRevision(multi);
    expect(revisionImage(multi, 'aarch64')).toContain('builder-aarch64');
    const changed = { ...multi, build_images_json: JSON.stringify({ x86_64: `ghcr.io/opr/builder-x86_64:stable@sha256:${'e'.repeat(64)}` }) };
    await expect(validateRevision(changed)).rejects.toMatchObject({ status: 409 });
    const missing = { ...multi, build_images_json: JSON.stringify({ x86_64: `ghcr.io/opr/builder-x86_64:stable@sha256:${'c'.repeat(64)}` }) };
    missing.manifest_sha256 = await manifestDigest(missing);
    await expect(validateRevision(missing)).rejects.toMatchObject({ status: 409 });
    expect(revisionImage(revision(), 'x86_64')).toContain('ghcr.io/opr/builder@sha256:');
  });

  test('factory revisions emit a standard SPDX document with runtime and build dependencies', async () => {
    const image = `ghcr.io/opr/builder@sha256:${'b'.repeat(64)}`;
    const draft = await createFactoryRevision({
      request: { id: 'request-spdx', name: 'hello', upstreamUrl: 'https://example.org/hello.tar.gz', sourceKind: 'archive', area: 'system', declaredLicense: 'unknown' },
      version: '2.12', sources: [{ name: 'hello.tar.gz', url: 'https://example.org/hello.tar.gz', sha256: 'a'.repeat(64) }],
      dependencies: ['glibc'], makeDependencies: ['base-devel'], smokeCommands: ['/usr/bin/hello --version'],
      architectures: ['x86_64'], buildImages: { x86_64: image }, pkgrel: 1, sourceDateEpoch: 1_700_000_000,
      imageDigest: image, license: 'GPL-3.0-or-later', surface: 'binary', buildCommands: ['make'],
      packageCommands: ['install -Dm755 hello "$pkgdir/usr/bin/hello"'], description: 'GNU Hello prints a friendly greeting.', explanation: 'test',
    });
    const sbom = JSON.parse(draft.revision.sbom_json) as Record<string, any>;
    expect(sbom).toMatchObject({ spdxVersion: 'SPDX-2.3', dataLicense: 'CC0-1.0', SPDXID: 'SPDXRef-DOCUMENT' });
    expect(sbom.documentDescribes).toEqual(['SPDXRef-Package-1']);
    expect(sbom.packages.every((item: Record<string, unknown>) => typeof item.SPDXID === 'string' && item.filesAnalyzed === false)).toBe(true);
    expect(sbom.creationInfo.creators).toEqual(['Tool: omapkg-factory-0.1.0']);
    expect(sbom.creationInfo.created).toBe(new Date(draft.revision.created_at * 1_000).toISOString());
    expect(sbom.creationInfo.created).not.toBe(new Date(1_700_000_000 * 1_000).toISOString());
    expect(draft.manifest.sourceDateEpoch).toBe(1_700_000_000);
    expect(draft.revision.description).toBe('GNU Hello prints a friendly greeting.');
    expect(sbom).not.toHaveProperty('oprEvidence');
    expect(sbom).not.toHaveProperty('oprMakeDependencies');
    expect(sbom.relationships).toEqual([
      { spdxElementId: 'SPDXRef-Package-1', relationshipType: 'GENERATED_FROM', relatedSpdxElement: 'SPDXRef-Package-2' },
      { spdxElementId: 'SPDXRef-Package-1', relationshipType: 'DEPENDS_ON', relatedSpdxElement: 'SPDXRef-Package-3' },
      { spdxElementId: 'SPDXRef-Package-4', relationshipType: 'BUILD_DEPENDENCY_OF', relatedSpdxElement: 'SPDXRef-Package-1' },
    ]);
    expect(readOprEvidence(sbom)).toEqual({ makeDependencies: ['base-devel'] });
    expect(readOprEvidence({ oprEvidence: { sourceResolution: { sourceRedirects: ['https://example.org/legacy'] } } })).toEqual({ sourceResolution: { sourceRedirects: ['https://example.org/legacy'] } });
    expect(sourceRedirects({ oprEvidence: { sourceRedirects: ['https://example.org/legacy'] } })).toEqual(['https://example.org/legacy']);
    expect(sourceRedirects({ comment: 'OPR-EVIDENCE-1\n{"sourceResolution":{"redirectChain":["https://example.org/a","https://example.org/b"]}}' })).toEqual(['https://example.org/a', 'https://example.org/b']);
    expect(draft.manifest).toMatchObject({ makeDependencies: ['base-devel'], pkgrel: 1 });
  });

  test('vendor SPDX evidence stays in a standard comment with valid npm checksum and reference', async () => {
    const image = `ghcr.io/opr/builder@sha256:${'b'.repeat(64)}`;
    const integrity = `sha512-${btoa(String.fromCharCode(...new Uint8Array(64).fill(7)))}`;
    const draft = await createFactoryRevision({
      request: { id: 'request-vendor-spdx', name: 'vendor', upstreamUrl: 'https://example.org/vendor.tar.gz', sourceKind: 'archive', area: 'system', declaredLicense: 'unknown' },
      version: '1.0.0', sources: [{ name: 'vendor.tar.gz', url: 'https://example.org/vendor.tar.gz', sha256: 'a'.repeat(64) }],
      dependencies: [], makeDependencies: [], smokeCommands: ['/usr/bin/vendor --version'], architectures: ['x86_64'], buildImages: { x86_64: image },
      pkgrel: 1, sourceDateEpoch: 1_700_000_000, imageDigest: image, license: 'proprietary', surface: 'binary', buildCommands: ['make'],
      packageCommands: ['make install DESTDIR="$pkgdir"'], description: 'Vendor software.', explanation: 'test',
      sbom: {
        sourceResolution: { originalUrl: 'https://example.org/vendor.tar.gz', finalUrl: 'https://cdn.example.org/vendor.tar.gz', redirectChain: ['https://example.org/vendor.tar.gz', 'https://cdn.example.org/vendor.tar.gz'] },
        redistributionEvidence: 'verified',
        vendorBundle: { kind: 'npm', source: { name: 'opr-vendor-npm.tar', url: 'https://omapkg.example/sources/a.tar', sha256: 'c'.repeat(64) }, components: [{ name: 'left-pad', version: '1.3.0', source: 'https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz', integrity, license: 'SEE LICENSE IN LICENSE' }] },
      },
    });
    const sbom = JSON.parse(draft.revision.sbom_json) as Record<string, any>;
    const component = sbom.packages.at(-1);
    expect(sbom).not.toHaveProperty('oprEvidence');
    expect(sbom).not.toHaveProperty('oprMakeDependencies');
    expect(readOprEvidence(sbom)).toMatchObject({ license: 'proprietary', redistributionEvidence: 'verified', sourceResolution: { redirectChain: expect.any(Array) } });
    expect(sbom.packages[0].licenseDeclared).toBe('NOASSERTION');
    expect(component.licenseDeclared).toBe('NOASSERTION');
    expect(component.checksums[0]).toEqual({ algorithm: 'SHA512', checksumValue: '07'.repeat(64) });
    expect(component.externalRefs).toEqual([{ referenceCategory: 'PACKAGE-MANAGER', referenceType: 'npm', referenceLocator: 'left-pad@1.3.0' }]);
  });

  test('final descriptions prefer immutable factory text and preserve legacy pkgdesc fallback', async () => {
    const legacy = revision({ recipe: "pkgname=demo\npkgdesc='A developer'\\''s tool.'\n", explanation: 'Audit explanation should be a last resort.' });
    expect(finalDescription(legacy, 'demo')).toBe("A developer's tool.");
    expect(finalDescription({ ...legacy, recipe: 'pkgname=demo\n', explanation: 'Verified package for developers.' }, 'demo')).toBe('Verified package for developers.');
    expect(finalDescription({ ...legacy, description: 'Factory summary.' }, 'demo')).toBe('Factory summary.');
  });

  test('factory description is bound for new manifests while legacy hashes remain stable', async () => {
    const legacy = revision({ recipe_sha256: await sha256('pkgname=hello\n') });
    const legacyDigest = await manifestDigest(legacy);
    const current = { ...legacy, description: 'A friendly greeting.' };
    expect(await manifestDigest(current)).not.toBe(legacyDigest);
    current.manifest_sha256 = await manifestDigest(current);
    await validateRevision(current);
    await expect(validateRevision({ ...current, description: 'A changed summary.' })).rejects.toMatchObject({ status: 409 });
  });

  test('package release numbers are scoped to package name and upstream version', async () => {
    const db = new TestD1(`
      CREATE TABLE requests(id TEXT PRIMARY KEY,name TEXT NOT NULL);
      CREATE TABLE revisions(request_id TEXT NOT NULL,version TEXT NOT NULL,pkgrel INTEGER);
      INSERT INTO requests VALUES('a','demo'),('b','demo'),('c','other');
      INSERT INTO revisions VALUES('a','1.0',5),('b','1.0',2),('c','1.0',99),('a','2.0',7);
    `);
    try {
      const database = asD1(db);
      expect(await nextPackageRelease({ DB: database }, 'demo', '1.0')).toBe(6);
      expect(await nextPackageRelease({ DB: database }, 'demo', '1.0')).toBe(6);
      expect(await nextPackageRelease({ DB: database }, 'demo', '2.0')).toBe(8);
      expect(await nextPackageRelease({ DB: database }, 'demo', '3.0')).toBe(1);
    } finally {
      db.close();
    }
  });

  test('request quota is enforced inside the write batch', async () => {
    const db = new TestD1(requestSchema);
    try {
      const service = env(db);
      await Promise.all(Array.from({ length: 20 }, (_, index) => submitRequest(service, actor, {
        name: `hello-${index}`, description: 'A package.', upstream_url: 'https://example.com/hello.tar.gz', source_kind: 'archive', area: 'system', declared_license: 'unknown',
      }).catch((cause) => cause)));
      const count = db.prepare("SELECT count(*) AS count FROM requests WHERE requested_by='github:1'").first<{ count: number }>();
      expect(count?.count).toBeLessThanOrEqual(10);
    } finally {
      db.close();
    }
  });

  test('Better Auth account issuer and approval revocation columns are migrated', () => {
    const migration = readFileSync(new URL('../migrations/0007_core_guards.sql', import.meta.url), 'utf8');
    const db = new TestD1(`
      CREATE TABLE account(id TEXT PRIMARY KEY,accountId TEXT NOT NULL,providerId TEXT NOT NULL,userId TEXT NOT NULL,
        accessToken TEXT,refreshToken TEXT,idToken TEXT,accessTokenExpiresAt INTEGER,refreshTokenExpiresAt INTEGER,scope TEXT,password TEXT,createdAt INTEGER NOT NULL,updatedAt INTEGER NOT NULL,
        UNIQUE(providerId,accountId));
      INSERT INTO account(id,accountId,providerId,userId,createdAt,updatedAt) VALUES('a','test-github-id','github','u',1,1);
      CREATE TABLE approvals(id TEXT PRIMARY KEY,revision_id TEXT NOT NULL,actor TEXT NOT NULL,kind TEXT NOT NULL,manifest_sha256 TEXT NOT NULL,created_at INTEGER NOT NULL,
        UNIQUE(revision_id,kind));
      ${migration}
    `);
    try {
      expect(db.prepare('SELECT issuer FROM account WHERE accountId=?').bind('test-github-id').first<{ issuer: string }>()?.issuer).toBe('local:oauth:github');
      const columns = db.prepare('PRAGMA table_info(approvals)').all<{ name: string }>().results.map((column) => column.name);
      expect(columns).toEqual(expect.arrayContaining(['revoked_at', 'revoked_by']));
    } finally {
      db.close();
    }
  });

  test('queued finalization can resume only when no worker job exists', async () => {
    const schema = readFileSync(new URL('../migrations/0001_initial.sql', import.meta.url), 'utf8') +
      readFileSync(new URL('../migrations/0005_factory_run_id.sql', import.meta.url), 'utf8') +
      readFileSync(new URL('../migrations/0007_core_guards.sql', import.meta.url), 'utf8') +
      readFileSync(new URL('../migrations/0011_build_images.sql', import.meta.url), 'utf8') +
      readFileSync(new URL('../migrations/0022_public_recipes.sql', import.meta.url), 'utf8');
    const db = new TestD1(schema);
    const item = revision({ id: 'generation-1', request_id: 'request-1', recipe_sha256: await sha256('pkgname=hello\n') });
    item.manifest_sha256 = await manifestDigest(item);
    db.prepare(`INSERT INTO requests(id,name,upstream_url,source_kind,area,requested_by,status,created_at,updated_at,factory_run_id)
      VALUES(?,?,?,?,?,?,?,?,?,?)`).bind('request-1', 'hello', 'https://example.com/hello.tar.gz', 'archive', 'system', 'github:9', 'queued', 1, 1, item.id).run();
    db.prepare(`INSERT INTO revisions(id,request_id,version,recipe,recipe_sha256,manifest_sha256,sources_json,dependencies_json,smoke_commands_json,
      architectures_json,build_images_json,source_date_epoch,image_digest,license,surface,explanation,sbom_json,lint_json,upstream_commit,pr_url,commit_sha,created_at)
      VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).bind(
      item.id, item.request_id, item.version, item.recipe, item.recipe_sha256, item.manifest_sha256, item.sources_json,
      item.dependencies_json, item.smoke_commands_json, item.architectures_json, '{}', item.source_date_epoch, item.image_digest,
      item.license, item.surface, item.explanation, item.sbom_json, item.lint_json, item.upstream_commit, item.pr_url, item.commit_sha, item.created_at,
    ).run();
    db.prepare('INSERT INTO approvals(id,revision_id,actor,kind,manifest_sha256,created_at) VALUES(?,?,?,?,?,?)')
      .bind('approval-area', item.id, 'github:1', 'area', item.manifest_sha256, 1).run();
    db.prepare('INSERT INTO approvals(id,revision_id,actor,kind,manifest_sha256,created_at) VALUES(?,?,?,?,?,?)')
      .bind('approval-security', item.id, 'github:2', 'security', item.manifest_sha256, 1).run();
    const service = { ...env(db), GITHUB_REPOSITORY: 'opr/recipes', GITHUB_REPO_TOKEN: 'github_pat_test' };
    const previousFetch = globalThis.fetch;
    globalThis.fetch = (async (input) => {
      if (String(input).endsWith('/pulls/1')) return Response.json({ head: { sha: item.commit_sha }, merged: true });
      return new Response('unexpected request', { status: 500 });
    }) as typeof globalThis.fetch;
    try {
      await expect(approveRevision(service, { id: 'github:2', role: 'security', areas: [] }, item.request_id, item.id, 'security', 'x'.repeat(2_001)))
        .rejects.toMatchObject({ status: 400 });
      db.prepare("UPDATE approvals SET revoked_at=2 WHERE revision_id=? AND kind='security'").bind(item.id).run();
      await approveRevision(service, { id: 'github:2', role: 'security', areas: [] }, item.request_id, item.id, 'security', 'Security review checked source and build evidence.');
      expect(db.prepare('SELECT status FROM requests WHERE id=?').bind(item.request_id).first<{ status: string }>()?.status).toBe('queued');
      expect(db.prepare('SELECT status FROM builds WHERE revision_id=?').bind(item.id).first<{ status: string }>()?.status).toBe('queued');
      const approvalRows = db.prepare("SELECT detail FROM audit_events WHERE action='revision.approved' ORDER BY id DESC LIMIT 1").all<{ detail: string }>().results;
      expect(JSON.parse(approvalRows[0]?.detail ?? '{}').reason).toBe('Security review checked source and build evidence.');
      const auditRows = db.prepare("SELECT detail FROM audit_events WHERE action='revision.finalizing'").all<{ detail: string }>().results;
      expect(JSON.parse(auditRows.at(-1)?.detail ?? '{}').resumed).toBe(true);
      await expect(approveRevision(service, { id: 'github:2', role: 'security', areas: [] }, item.request_id, item.id, 'security'))
        .rejects.toMatchObject({ status: 409 });
    } finally {
      globalThis.fetch = previousFetch;
      db.close();
    }
  });
});
