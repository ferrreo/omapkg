import { describe, expect, test } from 'bun:test';
import { gunzipSync } from 'node:zlib';
import { readFileSync } from 'node:fs';
import { manifestDigest } from '../src/lib/server/policy';
import { promoteBatch, publishBuild, publicRelease, quarantineRelease, rollbackRelease } from '../src/lib/server/releases';
import { sha256 } from '../src/lib/server/db';
import type { Env } from '../src/lib/server/env';
import { claimJob } from '../src/lib/server/workers';
import { asD1, TestD1 } from './d1';

const schema = `
CREATE TABLE requests(id TEXT PRIMARY KEY,name TEXT,upstream_url TEXT,source_kind TEXT,area TEXT,requested_by TEXT,status TEXT,created_at INTEGER,updated_at INTEGER);
CREATE TABLE revisions(id TEXT PRIMARY KEY,request_id TEXT,version TEXT,recipe TEXT,recipe_sha256 TEXT,manifest_sha256 TEXT,sources_json TEXT,dependencies_json TEXT,smoke_commands_json TEXT,architectures_json TEXT,source_date_epoch INTEGER,image_digest TEXT,license TEXT,surface TEXT,explanation TEXT,sbom_json TEXT,lint_json TEXT,upstream_commit TEXT,pr_url TEXT,commit_sha TEXT,created_at INTEGER,description TEXT);
CREATE TABLE builds(id TEXT PRIMARY KEY,revision_id TEXT,status TEXT,architecture TEXT,worker_id TEXT,artifact_key TEXT,artifact_sha256 TEXT,artifact_size INTEGER,installed_size INTEGER,dependency_plan_json TEXT,artifact_filename TEXT,provenance TEXT,provenance_signature TEXT,smoke_passed INTEGER,created_at INTEGER);
CREATE TABLE approvals(id TEXT PRIMARY KEY,revision_id TEXT,actor TEXT,kind TEXT,manifest_sha256 TEXT,created_at INTEGER,revoked_at INTEGER,revoked_by TEXT);
CREATE TABLE releases(id TEXT PRIMARY KEY,build_id TEXT,name TEXT,version TEXT,architecture TEXT,surface TEXT,channel TEXT,artifact_key TEXT,signature_key TEXT,recipe_key TEXT,sbom_key TEXT,provenance_key TEXT,published_at INTEGER,stable_at INTEGER,batch_id TEXT,previous_release_id TEXT);
CREATE TABLE crash_reports(id TEXT PRIMARY KEY,release_id TEXT,summary TEXT,consent_version TEXT,created_at INTEGER,resolved_at INTEGER,resolved_by TEXT);
CREATE TABLE audit_events(id INTEGER PRIMARY KEY AUTOINCREMENT,actor TEXT,action TEXT,target TEXT,detail TEXT,created_at INTEGER);
`;

const publicationSchema = [
  '0001_initial.sql', '0003_distribution.sql', '0005_factory_run_id.sql', '0007_core_guards.sql', '0008_distribution_assertions.sql',
  '0009_publication_jobs.sql', '0010_signing_control.sql', '0011_build_images.sql', '0014_package_metadata.sql', '0015_installed_size.sql',
  '0018_worker_metadata.sql', '0019_crash_triage.sql', '0020_worker_lifecycle.sql', '0022_public_recipes.sql', '0023_dependency_plan.sql',
].map((file) => readFileSync(new URL(`../migrations/${file}`, import.meta.url), 'utf8')).join('\n');

class MemoryR2 {
  readonly objects = new Map<string, Uint8Array>();
  private object(key: string) {
    const bytes = this.objects.get(key);
    if (!bytes) return null;
    return { size: bytes.byteLength, etag: key, httpEtag: `"${key}"`, customMetadata: key.startsWith('signatures/') ? { signatureSha256: 'a'.repeat(64) } : {}, httpMetadata: {}, body: new Response(bytes.buffer as ArrayBuffer).body, arrayBuffer: async () => bytes.slice().buffer as ArrayBuffer, text: async () => new TextDecoder().decode(bytes) };
  }
  head(key: string) { return Promise.resolve(this.object(key)); }
  async get(key: string, options?: R2GetOptions) {
    const conditional = options?.onlyIf;
    const etag = conditional && 'etagMatches' in conditional ? conditional.etagMatches : undefined;
    if (typeof etag === 'string' && (etag.startsWith('"') || etag.endsWith('"'))) {
      throw new Error(`Conditional ETag should not be wrapped in quotes (${etag}).`);
    }
    if (typeof etag === 'string' && etag !== key) return null;
    return this.object(key);
  }
  async put(key: string, value: ArrayBuffer | ArrayBufferView | ReadableStream<Uint8Array>, options?: R2PutOptions) {
    const bytes = value instanceof ReadableStream
      ? new Uint8Array(await new Response(value).arrayBuffer())
      : value instanceof ArrayBuffer ? new Uint8Array(value) : new Uint8Array(value.buffer as ArrayBuffer, value.byteOffset, value.byteLength);
    if (typeof options?.sha256 === 'string' && await sha256(bytes) !== options.sha256) throw new Error('checksum mismatch');
    this.objects.set(key, new Uint8Array(bytes));
    return this.object(key);
  }
}

function base64(bytes: ArrayBuffer): string {
  let binary = '';
  for (const byte of new Uint8Array(bytes)) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function env(db: TestD1): Env {
  return { DB: asD1(db), ARTIFACTS: {} as R2Bucket, PUBLIC_ORIGIN: 'https://opr.example', MAINTAINER_GITHUB_IDS: '', SECURITY_GITHUB_IDS: '', QUARANTINE_HOURS: '48' };
}

test('R2 conditional reads require native unquoted etags', async () => {
  const r2 = new MemoryR2();
  r2.objects.set('private/build', new Uint8Array([1]));
  const head = await r2.head('private/build');
  expect(head?.httpEtag).toBe('"private/build"');
  expect(head?.etag).toBe('private/build');
  await expect(r2.get('private/build', { onlyIf: { etagMatches: head!.httpEtag } })).rejects.toThrow('should not be wrapped in quotes');
  expect(await r2.get('private/build', { onlyIf: { etagMatches: head!.etag } })).not.toBeNull();
});

function insertBinaryRelease(db: TestD1, input: {
  id: string; name: string; version: string; dependencies: string[]; channel: 'stable' | 'dev'; requestId?: string;
  nativeDependencies?: string[]; nativeProvides?: string[]; nativeConflicts?: string[]; nativeReplaces?: string[];
}) {
  const requestId = input.requestId ?? `request-${input.id}`;
  const revisionId = `revision-${input.id}`;
  const buildId = `build-${input.id}`;
  db.prepare('INSERT INTO requests VALUES(?,?,?,?,?,?,?,?,?)').bind(requestId, input.name, `https://example.org/${input.name}`, 'archive', 'development', 'github:1', 'built', 1, 1).run();
  db.prepare('INSERT INTO revisions VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)').bind(
    revisionId, requestId, input.version, `pkgname=${input.name}\n`, 'a'.repeat(64), 'b'.repeat(64), '[{"name":"source.tar.gz","url":"https://example.org/source.tar.gz","sha256":"' + 'c'.repeat(64) + '"}]', JSON.stringify(input.dependencies), '[]', '["x86_64"]', 1, 'ghcr.io/opr/builder@sha256:' + 'd'.repeat(64), 'MIT', 'binary', input.name, '{}', '{"passed":true}', null, 'https://github.com/example-owner/recipes/pull/1', 'e'.repeat(40), 1, null,
  ).run();
  db.prepare('INSERT INTO builds VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)').bind(
    buildId, revisionId, 'succeeded', 'x86_64', null, `private/${buildId}`, 'f'.repeat(64), 3, 10, null, `${input.name}-${input.version}-x86_64.pkg.tar.zst`, JSON.stringify({
      buildId, revisionId, workerId: null, recipeSha256: 'a'.repeat(64), pkgrel: 1, installedSize: 10,
      packageMetadata: {
        name: input.name, fullVersion: input.version, architecture: 'x86_64', installedSize: 10,
        depends: input.nativeDependencies ?? input.dependencies, provides: input.nativeProvides ?? [],
        conflicts: input.nativeConflicts ?? [], replaces: input.nativeReplaces ?? [],
      },
      artifactSha256: 'f'.repeat(64), architecture: 'x86_64', imageDigest: 'd'.repeat(64), sourceDateEpoch: 1, sources: [], network: 'disabled', startedAt: '2026-01-01T00:00:00Z', finishedAt: '2026-01-01T00:01:00Z',
    }), 'AA==', 1, 1,
  ).run();
  db.prepare('INSERT INTO releases VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)').bind(
    input.id, buildId, input.name, input.version, 'x86_64', 'binary', input.channel,
    `packages/x86_64/${input.name}-${input.version}-x86_64.pkg.tar.zst`, 'signatures/package.sig', `recipes/${input.name}/${input.version}/x86_64/PKGBUILD`, 'metadata/sbom', 'metadata/provenance', 1,
    input.channel === 'stable' ? 1 : null, null, null,
  ).run();
  db.prepare('INSERT INTO approvals VALUES(?,?,?,?,?,?,?,?)').bind(`approval-area-${input.id}`, revisionId, 'github:1', 'area', 'b'.repeat(64), 1, null, null).run();
  db.prepare('INSERT INTO approvals VALUES(?,?,?,?,?,?,?,?)').bind(`approval-security-${input.id}`, revisionId, 'github:2', 'security', 'b'.repeat(64), 1, null, null).run();
}

describe('release boundary', () => {
  test('binary publication fails closed before writing bytes without signer', async () => {
    const db = new TestD1(schema);
    const recipe = 'pkgname=hello\n';
    const sources = [{ name: 'hello.tar.gz', url: 'https://example.org/hello.tar.gz', sha256: 'a'.repeat(64) }];
    const revision = {
      id: 'revision-1', request_id: 'request-1', version: '1.0.0-1', recipe, recipe_sha256: await sha256(recipe), manifest_sha256: '',
      sources_json: JSON.stringify(sources), dependencies_json: '[]', smoke_commands_json: '["hello --version"]', architectures_json: '["x86_64"]',
      source_date_epoch: 1_700_000_000, image_digest: `ghcr.io/opr/builder@sha256:${'b'.repeat(64)}`, license: 'MIT', surface: 'binary' as const,
      explanation: 'hello', sbom_json: '{}', lint_json: '{"passed":true}', upstream_commit: null,
      pr_url: 'https://github.com/example-owner/recipes/pull/1', commit_sha: 'c'.repeat(40), created_at: 1,
    };
    revision.manifest_sha256 = await manifestDigest(revision);
    const provenance = JSON.stringify({ buildId: 'build-1', revisionId: revision.id, architecture: 'x86_64', recipeSha256: revision.recipe_sha256, artifactSha256: 'd'.repeat(64), imageDigest: revision.image_digest.split('@').at(-1), sourceDateEpoch: revision.source_date_epoch, network: 'disabled', sources });
    db.prepare('INSERT INTO requests VALUES(?,?,?,?,?,?,?,?,?)').bind('request-1', 'hello', sources[0].url, 'archive', 'development', 'github:1', 'queued', 1, 1).run();
    db.prepare('INSERT INTO revisions VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)').bind(
      revision.id, revision.request_id, revision.version, revision.recipe, revision.recipe_sha256, revision.manifest_sha256, revision.sources_json,
      revision.dependencies_json, revision.smoke_commands_json, revision.architectures_json, revision.source_date_epoch, revision.image_digest,
      revision.license, revision.surface, revision.explanation, revision.sbom_json, revision.lint_json, revision.upstream_commit, revision.pr_url,
      revision.commit_sha, revision.created_at, null,
    ).run();
    db.prepare('INSERT INTO builds VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)').bind('build-1', revision.id, 'succeeded', 'x86_64', null, 'private/build-1/hello.pkg.tar.zst', 'd'.repeat(64), 10, null, null, 'hello-1.0.0-1-x86_64.pkg.tar.zst', provenance, 'AA==', 1, 1).run();
    db.prepare('INSERT INTO approvals VALUES(?,?,?,?,?,?,?,?)').bind('approval-area', revision.id, 'github:1', 'area', revision.manifest_sha256, 1, null, null).run();
    db.prepare('INSERT INTO approvals VALUES(?,?,?,?,?,?,?,?)').bind('approval-security', revision.id, 'github:2', 'security', revision.manifest_sha256, 1, null, null).run();
    await expect(publishBuild(env(db), { id: 'github:1', role: 'maintainer', areas: ['development'] }, 'build-1')).rejects.toThrow('Package signing service is not configured');
    db.close();
  });

  test('publication keeps another architecture claimable until every architecture is published', async () => {
    const db = new TestD1(publicationSchema);
    const artifacts = new MemoryR2();
    const timestamp = 1_700_000_000;
    const source = [{ name: 'hello.tar.gz', url: 'https://example.org/hello.tar.gz', sha256: 'a'.repeat(64) }];
    const recipe = 'pkgname=hello\npkgver=1.0\npkgrel=1\n';
    const imageDigest = `ghcr.io/opr/builder@sha256:${'b'.repeat(64)}`;
    const revision = {
      id: 'revision-multiarch', request_id: 'request-multiarch', version: '1.0', recipe,
      recipe_sha256: await sha256(recipe), manifest_sha256: '', public_recipe: null, public_recipe_sha256: null,
      sources_json: JSON.stringify(source), dependencies_json: '[]', make_dependencies_json: '[]', smoke_commands_json: '["true"]',
      architectures_json: '["x86_64","aarch64"]', build_images_json: '{}', pkgrel: 1, source_date_epoch: timestamp,
      image_digest: imageDigest, license: 'MIT', surface: 'recipe' as const, explanation: 'hello', sbom_json: '{}', lint_json: '{"passed":true}',
      upstream_commit: null, pr_url: 'https://github.com/example-owner/recipes/pull/1', commit_sha: 'c'.repeat(40), created_at: timestamp,
    };
    revision.manifest_sha256 = await manifestDigest(revision);
    const x86Keys = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
    const armKeys = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
    const x86Worker = { id: 'worker-x86', name: 'x86', architecture: 'x86_64' as const, public_key: base64(await crypto.subtle.exportKey('raw', x86Keys.publicKey)), status: 'active' as const, enrolled_at: timestamp, last_seen_at: timestamp, daemon_version: null, runtime: null, capabilities_json: null, accepting_jobs: 1, paused_at: null, removed_at: null };
    const armWorker = { id: 'worker-arm', name: 'arm', architecture: 'aarch64' as const, public_key: base64(await crypto.subtle.exportKey('raw', armKeys.publicKey)), status: 'active' as const, enrolled_at: timestamp, last_seen_at: timestamp, daemon_version: null, runtime: null, capabilities_json: null, accepting_jobs: 1, paused_at: null, removed_at: null };
    const provenance = async (buildId: string, worker: typeof x86Worker | typeof armWorker, keys: CryptoKeyPair) => {
      const value = JSON.stringify({ buildId, revisionId: revision.id, workerId: worker.id, recipeSha256: revision.recipe_sha256, artifactSha256: null, architecture: worker.architecture, imageDigest: imageDigest.split('@').at(-1), sourceDateEpoch: timestamp, sources: source, network: 'disabled', startedAt: '2026-01-01T00:00:00Z', finishedAt: '2026-01-01T00:01:00Z' });
      return { value, signature: base64(await crypto.subtle.sign('Ed25519', keys.privateKey, new TextEncoder().encode(value))) };
    };
    const x86Provenance = await provenance('build-multiarch-x86', x86Worker, x86Keys);
    try {
      db.prepare(`INSERT INTO requests(id,name,upstream_url,source_kind,area,requested_by,status,created_at,updated_at,factory_run_id)
        VALUES(?,?,?,?,?,?,?,?,?,?)`).bind(revision.request_id, 'hello', source[0].url, 'archive', 'development', 'github:1', 'building', timestamp, timestamp, revision.id).run();
      db.prepare(`INSERT INTO revisions(id,request_id,version,recipe,recipe_sha256,manifest_sha256,sources_json,dependencies_json,make_dependencies_json,
        smoke_commands_json,architectures_json,build_images_json,pkgrel,source_date_epoch,image_digest,license,surface,explanation,sbom_json,lint_json,
        upstream_commit,pr_url,commit_sha,created_at,public_recipe,public_recipe_sha256)
        VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).bind(
        revision.id, revision.request_id, revision.version, revision.recipe, revision.recipe_sha256, revision.manifest_sha256, revision.sources_json,
        revision.dependencies_json, revision.make_dependencies_json, revision.smoke_commands_json, revision.architectures_json, revision.build_images_json,
        revision.pkgrel, revision.source_date_epoch, revision.image_digest, revision.license, revision.surface, revision.explanation, revision.sbom_json,
        revision.lint_json, revision.upstream_commit, revision.pr_url, revision.commit_sha, revision.created_at, revision.public_recipe, revision.public_recipe_sha256,
      ).run();
      for (const approval of [['area', 'github:1'], ['security', 'github:2']] as const) {
        db.prepare('INSERT INTO approvals(id,revision_id,actor,kind,manifest_sha256,created_at) VALUES(?,?,?,?,?,?)')
          .bind(`approval-${approval[0]}`, revision.id, approval[1], approval[0], revision.manifest_sha256, timestamp).run();
      }
      for (const worker of [x86Worker, armWorker]) {
        db.prepare(`INSERT INTO workers(id,name,architecture,public_key,status,enrolled_at,last_seen_at,daemon_version,runtime,capabilities_json,accepting_jobs,paused_at,removed_at)
          VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`).bind(worker.id, worker.name, worker.architecture, worker.public_key, worker.status, worker.enrolled_at, worker.last_seen_at, worker.daemon_version, worker.runtime, worker.capabilities_json, worker.accepting_jobs, worker.paused_at, worker.removed_at).run();
      }
      db.prepare(`INSERT INTO builds(id,revision_id,architecture,status,worker_id,lease_token,lease_expires_at,attempt,artifact_key,artifact_sha256,artifact_size,artifact_filename,provenance,provenance_signature,smoke_passed,error,created_at,started_at,finished_at,installed_size,dependency_plan_json)
        VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).bind('build-multiarch-x86', revision.id, 'x86_64', 'succeeded', x86Worker.id, null, null, 1, null, null, null, null, x86Provenance.value, x86Provenance.signature, 1, null, timestamp, timestamp, timestamp + 1, null, null).run();
      db.prepare(`INSERT INTO builds(id,revision_id,architecture,status,worker_id,lease_token,lease_expires_at,attempt,created_at)
        VALUES(?,?,?,?,?,?,?,?,?)`).bind('build-multiarch-arm', revision.id, 'aarch64', 'queued', null, null, null, 0, timestamp).run();

      const service = env(db);
      service.ARTIFACTS = artifacts as unknown as R2Bucket;
      const maintainer = { id: 'github:1', role: 'maintainer' as const, areas: ['development'] };
      await publishBuild(service, maintainer, 'build-multiarch-x86');
      expect(db.prepare('SELECT status FROM requests WHERE id=?').bind(revision.request_id).first<{ status: string }>()?.status).toBe('queued');
      expect((await claimJob(asD1(db), armWorker))?.id).toBe('build-multiarch-arm');
      expect(db.prepare('SELECT status FROM requests WHERE id=?').bind(revision.request_id).first<{ status: string }>()?.status).toBe('building');

      const armProvenance = await provenance('build-multiarch-arm', armWorker, armKeys);
      db.prepare(`UPDATE builds SET status='succeeded',provenance=?,provenance_signature=?,smoke_passed=1,finished_at=?,lease_expires_at=? WHERE id=?`)
        .bind(armProvenance.value, armProvenance.signature, timestamp + 2, timestamp + 2, 'build-multiarch-arm').run();
      await publishBuild(service, maintainer, 'build-multiarch-arm');
      expect(db.prepare('SELECT status FROM requests WHERE id=?').bind(revision.request_id).first<{ status: string }>()?.status).toBe('built');
    } finally {
      db.close();
    }
  });

  test('dev release is hidden by default and exposed only by explicit opt in', () => {
    const release = {
      id: 'release-1', build_id: 'build-1', name: 'hello', version: '1.0.0-1', architecture: 'x86_64' as const,
      surface: 'binary' as const, channel: 'dev' as const, artifact_key: 'packages/x86_64/hello.pkg.tar.zst', signature_key: 'signatures/hello.sig',
      recipe_key: 'recipes/hello/1.0.0-1/x86_64/PKGBUILD', sbom_key: 'metadata/releases/release-1/sbom.json', provenance_key: 'metadata/releases/release-1/provenance.json',
      published_at: 1, stable_at: null, batch_id: null, previous_release_id: null,
    };
    const withArtifact = { ...release, artifact_filename: 'hello-1.0.0-1-x86_64.pkg.tar.zst', artifact_sha256: 'd'.repeat(64), artifact_size: 10 };
    expect(publicRelease(withArtifact, 'https://opr.example')).toBeNull();
    expect(publicRelease(withArtifact, 'https://opr.example', true)?.artifact?.url).toBe('https://opr.example/repo/dev/x86_64/hello-1.0.0-1-x86_64.pkg.tar.zst');
  });

  test('promotion signs and atomically activates a repository snapshot', async () => {
    const db = new TestD1(`${schema}
      CREATE TABLE signing_intents(id TEXT PRIMARY KEY,build_id TEXT,revision_id TEXT,object_key TEXT,object_kind TEXT,artifact_sha256 TEXT,artifact_filename TEXT,manifest_sha256 TEXT,status TEXT DEFAULT 'pending',signature_key TEXT,signature_sha256 TEXT,created_at INTEGER,consumed_at INTEGER,expires_at INTEGER,artifact_size INTEGER,key_fingerprint TEXT);
      CREATE TABLE repository_snapshots(id TEXT PRIMARY KEY,architecture TEXT,channel TEXT,db_key TEXT,db_signature_key TEXT,batch_id TEXT,created_at INTEGER,active INTEGER);
      CREATE TABLE promotion_batches(id TEXT PRIMARY KEY,actor TEXT,release_ids_json TEXT,reason TEXT,created_at INTEGER);
      CREATE TABLE distribution_assertions(expected INTEGER,actual INTEGER,CHECK(expected=actual));`);
    const r2 = new MemoryR2();
    r2.objects.set('signatures/package.sig', new Uint8Array([1, 2, 3]));
    r2.objects.set('signatures/database.sig', new Uint8Array([4, 5, 6]));
    const envValue = env(db);
    envValue.ARTIFACTS = r2 as unknown as R2Bucket;
    envValue.SIGNER = { fetch: async (request: Request) => {
      const input = await request.json() as { objectKind: string };
      return Response.json({ signature: { key: input.objectKind === 'database' ? 'signatures/database.sig' : 'signatures/package.sig', sha256: 'a'.repeat(64) } });
    } } as unknown as Fetcher;
    db.prepare('INSERT INTO requests VALUES(?,?,?,?,?,?,?,?,?)').bind('request-2', 'demo', 'https://example.org/demo', 'archive', 'development', 'github:1', 'built', 1, 1).run();
    db.prepare('INSERT INTO revisions VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)').bind('revision-2', 'request-2', '1.0.0-1', 'pkgname=demo\n', 'a'.repeat(64), 'b'.repeat(64), '[{"name":"demo.tar.gz","url":"https://example.org/demo.tar.gz","sha256":"' + 'c'.repeat(64) + '"}]', '["demo=1.0.0"]', '[]', '["x86_64"]', 1, 'ghcr.io/opr/builder@sha256:' + 'd'.repeat(64), 'MIT', 'binary', 'demo', '{}', '{"passed":true}', null, 'https://github.com/example-owner/recipes/pull/2', 'e'.repeat(40), 1, null).run();
    db.prepare('INSERT INTO builds VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)').bind('build-2', 'revision-2', 'succeeded', 'x86_64', null, 'private/demo', 'f'.repeat(64), 3, 10, null, 'demo-1.0.0-1-x86_64.pkg.tar.zst', JSON.stringify({
      packageMetadata: { name: 'demo', fullVersion: '1.0.0-1', architecture: 'x86_64', installedSize: 10, depends: ['demo=1.0.0'], provides: [], conflicts: [], replaces: [] },
    }), 'AA==', 1, 1).run();
    db.prepare('INSERT INTO releases VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)').bind('release-2', 'build-2', 'demo', '1.0.0-1', 'x86_64', 'binary', 'dev', 'packages/x86_64/demo-1.0.0-1-x86_64.pkg.tar.zst', 'signatures/package.sig', 'recipes/demo/1.0.0-1/x86_64/PKGBUILD', 'metadata/sbom', 'metadata/provenance', 1, null, null, null).run();
    db.prepare('INSERT INTO approvals VALUES(?,?,?,?,?,?,?,?)').bind('approval-area-2', 'revision-2', 'github:1', 'area', 'b'.repeat(64), 1, null, null).run();
    db.prepare('INSERT INTO approvals VALUES(?,?,?,?,?,?,?,?)').bind('approval-security-2', 'revision-2', 'github:2', 'security', 'b'.repeat(64), 1, null, null).run();
    const result = await promoteBatch(envValue, { id: 'github:1', role: 'maintainer', areas: ['development'] }, ['release-2'], 'quarantine and smoke checks passed');
    expect(result.releaseIds).toEqual(['release-2']);
    expect(db.prepare("SELECT channel FROM releases WHERE id='release-2'").first<{ channel: string }>()?.channel).toBe('stable');
    expect(db.prepare("SELECT COUNT(*) AS count FROM repository_snapshots WHERE channel='stable' AND active=1").first<{ count: number }>()?.count).toBe(1);
    expect(db.prepare("SELECT COUNT(*) AS count FROM repository_snapshots WHERE channel='dev' AND active=1").first<{ count: number }>()?.count).toBe(1);
    expect([...r2.objects.keys()].some((key) => key.startsWith('repo/dev/x86_64/'))).toBe(true);
    db.close();
  });

  test('promotion rejects malformed Arch dependency constraints', async () => {
    const db = new TestD1(schema);
    insertBinaryRelease(db, { id: 'release-invalid-dependency', name: 'demo', version: '1.0.0-1', dependencies: ['demo>>1'], nativeDependencies: [], channel: 'dev' });
    await expect(promoteBatch(env(db), { id: 'github:1', role: 'maintainer', areas: ['development'] }, ['release-invalid-dependency'], 'dependency validation')).rejects.toThrow('Invalid Arch dependency constraint');
    db.close();
  });

  test('promotion rejects native metadata that omits a reviewed dependency', async () => {
    const db = new TestD1(schema);
    insertBinaryRelease(db, { id: 'release-missing-dependency', name: 'demo', version: '1.0.0-1', dependencies: ['external-base-dep'], nativeDependencies: [], channel: 'dev' });
    await expect(promoteBatch(env(db), { id: 'github:1', role: 'maintainer', areas: ['development'] }, ['release-missing-dependency'], 'dependency validation')).rejects.toThrow('Native package metadata does not contain reviewed dependency external-base-dep');
    db.close();
  });

  test('promotion rejects a known dependency version outside its constraint', async () => {
    const db = new TestD1(schema);
    insertBinaryRelease(db, { id: 'release-libfoo', name: 'libfoo', version: '1.4-1', dependencies: [], channel: 'stable' });
    insertBinaryRelease(db, { id: 'release-demo-version', name: 'demo', version: '1.0-1', dependencies: ['libfoo>=2.0-1'], channel: 'dev' });
    await expect(promoteBatch(env(db), { id: 'github:1', role: 'maintainer', areas: ['development'] }, ['release-demo-version'], 'dependency validation')).rejects.toThrow('is not satisfied by 1.4-1');
    db.close();
  });

  test('promotion rejects a SONAME provider change that breaks a retained package', async () => {
    const db = new TestD1(schema);
    insertBinaryRelease(db, { id: 'release-libfoo-old', name: 'libfoo', version: '1.0-1', dependencies: [], nativeProvides: ['lib:libfoo.so.1'], channel: 'stable' });
    insertBinaryRelease(db, { id: 'release-app', name: 'app', version: '1.0-1', dependencies: ['lib:libfoo.so.1'], nativeDependencies: ['lib:libfoo.so.1'], channel: 'stable' });
    insertBinaryRelease(db, { id: 'release-libfoo-new', name: 'libfoo', version: '2.0-1', dependencies: [], nativeProvides: ['lib:libfoo.so.2'], channel: 'dev' });
    await expect(promoteBatch(env(db), { id: 'github:1', role: 'maintainer', areas: ['development'] }, ['release-libfoo-new'], 'dependency validation')).rejects.toThrow('is not satisfied');
    db.close();
  });

  test('repository metadata preserves native package relations', async () => {
    const db = new TestD1(`${schema}
      CREATE TABLE signing_intents(id TEXT PRIMARY KEY,build_id TEXT,revision_id TEXT,object_key TEXT,object_kind TEXT,artifact_sha256 TEXT,artifact_filename TEXT,manifest_sha256 TEXT,status TEXT DEFAULT 'pending',signature_key TEXT,signature_sha256 TEXT,created_at INTEGER,consumed_at INTEGER,expires_at INTEGER,artifact_size INTEGER,key_fingerprint TEXT);
      CREATE TABLE repository_snapshots(id TEXT PRIMARY KEY,architecture TEXT,channel TEXT,db_key TEXT,db_signature_key TEXT,batch_id TEXT,created_at INTEGER,active INTEGER);
      CREATE TABLE promotion_batches(id TEXT PRIMARY KEY,actor TEXT,release_ids_json TEXT,reason TEXT,created_at INTEGER);
      CREATE TABLE distribution_assertions(expected INTEGER,actual INTEGER,CHECK(expected=actual));`);
    const r2 = new MemoryR2();
    r2.objects.set('signatures/package.sig', new Uint8Array([1, 2, 3]));
    r2.objects.set('signatures/database.sig', new Uint8Array([4, 5, 6]));
    const service = env(db);
    service.ARTIFACTS = r2 as unknown as R2Bucket;
    service.SIGNER = { fetch: async (request: Request) => {
      const input = await request.json() as { objectKind: string };
      return Response.json({ signature: { key: input.objectKind === 'database' ? 'signatures/database.sig' : 'signatures/package.sig', sha256: 'a'.repeat(64) } });
    } } as unknown as Fetcher;
    insertBinaryRelease(db, {
      id: 'release-native-relations', name: 'demo', version: '1.0.0-1', dependencies: [], channel: 'dev',
      nativeProvides: ['virtual-demo'], nativeConflicts: ['old-demo'], nativeReplaces: ['old-demo'],
    });
    const result = await promoteBatch(service, { id: 'github:1', role: 'maintainer', areas: ['development'] }, ['release-native-relations'], 'quarantine and smoke checks passed');
    const databaseKey = [...r2.objects.keys()].find((key) => key.startsWith('repo/stable/x86_64/'));
    if (!databaseKey) throw new Error('expected development repository database');
    const databaseBytes = gunzipSync(r2.objects.get(databaseKey)!);
    const database = new TextDecoder().decode(databaseBytes);
    expect(database).toContain('%PROVIDES%\nvirtual-demo\n');
    expect(database).toContain('%CONFLICTS%\nold-demo\n');
    expect(database).toContain('%REPLACES%\nold-demo\n');
    expect(result.releaseIds).toEqual(['release-native-relations']);
    db.close();
  });

  test('development repository indexes only newest release per package while retaining history', async () => {
    const db = new TestD1(`${schema}
      CREATE TABLE signing_intents(id TEXT PRIMARY KEY,build_id TEXT,revision_id TEXT,object_key TEXT,object_kind TEXT,artifact_sha256 TEXT,artifact_filename TEXT,manifest_sha256 TEXT,status TEXT DEFAULT 'pending',signature_key TEXT,signature_sha256 TEXT,created_at INTEGER,consumed_at INTEGER,expires_at INTEGER,artifact_size INTEGER,key_fingerprint TEXT);
      CREATE TABLE repository_snapshots(id TEXT PRIMARY KEY,architecture TEXT,channel TEXT,db_key TEXT,db_signature_key TEXT,batch_id TEXT,created_at INTEGER,active INTEGER);
      CREATE TABLE promotion_batches(id TEXT PRIMARY KEY,actor TEXT,release_ids_json TEXT,reason TEXT,created_at INTEGER);
      CREATE TABLE distribution_assertions(expected INTEGER,actual INTEGER,CHECK(expected=actual));`);
    const r2 = new MemoryR2();
    r2.objects.set('signatures/package.sig', new Uint8Array([1, 2, 3]));
    r2.objects.set('signatures/database.sig', new Uint8Array([4, 5, 6]));
    const service = env(db);
    service.ARTIFACTS = r2 as unknown as R2Bucket;
    service.SIGNER = { fetch: async (request: Request) => {
      const input = await request.json() as { objectKind: string };
      return Response.json({ signature: { key: input.objectKind === 'database' ? 'signatures/database.sig' : 'signatures/package.sig', sha256: 'a'.repeat(64) } });
    } } as unknown as Fetcher;
    insertBinaryRelease(db, { id: 'release-foo-1', name: 'foo', version: '1.0-1', dependencies: [], channel: 'dev' });
    insertBinaryRelease(db, { id: 'release-foo-2', name: 'foo', version: '2.0-1', dependencies: [], channel: 'dev' });
    insertBinaryRelease(db, { id: 'release-bar-1', name: 'bar', version: '1.0-1', dependencies: [], channel: 'dev' });
    db.prepare("UPDATE releases SET published_at=10 WHERE id='release-foo-1'").run();
    db.prepare("UPDATE releases SET published_at=20 WHERE id='release-foo-2'").run();
    const result = await promoteBatch(service, { id: 'github:1', role: 'maintainer', areas: ['development'] }, ['release-bar-1'], 'index newest development packages');
    expect(result.releaseIds).toEqual(['release-bar-1']);
    const databaseKey = [...r2.objects.keys()].find((key) => key.startsWith('repo/dev/x86_64/'));
    if (!databaseKey) throw new Error('expected development repository database');
    const database = new TextDecoder().decode(gunzipSync(r2.objects.get(databaseKey)!));
    expect(database.match(/%NAME%\nfoo\n/g) ?? []).toHaveLength(1);
    expect(database).toContain('%VERSION%\n2.0-1\n');
    expect(database).not.toContain('%VERSION%\n1.0-1\n');
    expect(db.prepare("SELECT COUNT(*) AS count FROM releases WHERE name='foo' AND channel='dev'").first<{ count: number }>()?.count).toBe(2);
    db.close();
  });

  test('rollback rejects a provider downgrade that breaks a retained SONAME dependency', async () => {
    const db = new TestD1(`${schema}
      CREATE TABLE release_rollbacks(release_id TEXT,previous_release_id TEXT,manifest_key TEXT,created_at INTEGER);
      CREATE TABLE repository_snapshots(id TEXT PRIMARY KEY,architecture TEXT,channel TEXT,db_key TEXT,db_signature_key TEXT,batch_id TEXT,created_at INTEGER,active INTEGER);
      CREATE TABLE distribution_assertions(expected INTEGER,actual INTEGER,CHECK(expected=actual));`);
    const r2 = new MemoryR2();
    r2.objects.set('signatures/package.sig', new Uint8Array([1, 2, 3]));
    const service = env(db);
    service.ARTIFACTS = r2 as unknown as R2Bucket;
    insertBinaryRelease(db, { id: 'release-libfoo-old', name: 'libfoo', version: '1.0-1', dependencies: [], nativeProvides: ['lib:libfoo.so.1'], channel: 'stable' });
    insertBinaryRelease(db, { id: 'release-libfoo-new', name: 'libfoo', version: '2.0-1', dependencies: [], nativeProvides: ['lib:libfoo.so.2'], channel: 'stable' });
    insertBinaryRelease(db, { id: 'release-app', name: 'app', version: '1.0-1', dependencies: ['lib:libfoo.so.2'], nativeDependencies: ['lib:libfoo.so.2'], channel: 'stable' });
    db.prepare("UPDATE releases SET channel='withdrawn' WHERE id='release-libfoo-old'").run();
    db.prepare("UPDATE releases SET previous_release_id='release-libfoo-old' WHERE id='release-libfoo-new'").run();
    const previousBytes = new Uint8Array([1, 2, 3]);
    const previousDigest = await sha256(previousBytes);
    r2.objects.set('packages/x86_64/libfoo-1.0-1-x86_64.pkg.tar.zst', previousBytes);
    db.prepare('UPDATE builds SET artifact_sha256=?,artifact_size=? WHERE id=?').bind(previousDigest, previousBytes.byteLength, 'build-release-libfoo-old').run();
    await expect(rollbackRelease(service, { id: 'github:1', role: 'maintainer', areas: ['development'] }, 'release-libfoo-new', 'restore compatible version'))
      .rejects.toThrow('is not satisfied');
    expect(db.prepare("SELECT channel FROM releases WHERE id='release-libfoo-new'").first<{ channel: string }>()?.channel).toBe('stable');
  });

  test('crash demotion rejects removing a provider needed by a retained package', async () => {
    const db = new TestD1(schema);
    try {
      insertBinaryRelease(db, { id: 'release-libfoo-crash', name: 'libfoo', version: '1.0-1', dependencies: [], nativeProvides: ['lib:libfoo.so.1'], channel: 'stable' });
      insertBinaryRelease(db, { id: 'release-app-crash', name: 'app', version: '1.0-1', dependencies: ['lib:libfoo.so.1'], nativeDependencies: ['lib:libfoo.so.1'], channel: 'stable' });
      await expect(quarantineRelease(env(db), 'release-libfoo-crash', 'confirmed crash threshold')).rejects.toThrow('is not satisfied');
      expect(db.prepare("SELECT channel FROM releases WHERE id='release-libfoo-crash'").first<{ channel: string }>()?.channel).toBe('stable');
    } finally {
      db.close();
    }
  });
});
