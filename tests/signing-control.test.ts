import { runtimeEvidence } from './runtime-fixtures';
import { expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import { manifestDigest } from '../src/lib/server/policy';
import {
  claimSigningIntent,
  completeSigningIntent,
  type SigningControlEnv,
} from '../src/lib/server/signing-control';
import { sha256 } from '../src/lib/server/db';
import { attestationKey, releaseAttestation } from '../src/lib/server/release-attestation';
import { TestD1, asD1 } from './d1';

const schema = [
  '0001_initial.sql', '0003_distribution.sql', '0007_core_guards.sql', '0010_signing_control.sql', '0011_build_images.sql', '0014_package_metadata.sql', '0015_installed_size.sql', '0022_public_recipes.sql', '0023_dependency_plan.sql', '0024_descriptions.sql', '0026_release_attestations.sql',
].map((file) => readFileSync(new URL(`../migrations/${file}`, import.meta.url), 'utf8')).join('\n') + '\nALTER TABLE signing_intents ADD COLUMN build_attempt INTEGER; ALTER TABLE builds ADD COLUMN output_contract_json TEXT; ALTER TABLE builds ADD COLUMN input_lock_sha256 TEXT;';

class MemoryR2 {
  readonly objects = new Map<string, { body: Uint8Array; customMetadata: Record<string, string> }>();

  async head(key: string) {
    const object = this.objects.get(key);
    return object ? { size: object.body.byteLength, customMetadata: object.customMetadata } : null;
  }

  async get(key: string) {
    const object = this.objects.get(key);
    if (!object) return null;
    return {
      size: object.body.byteLength,
      customMetadata: object.customMetadata,
      arrayBuffer: async () => object.body.slice().buffer,
    };
  }
}

function base64(bytes: Uint8Array): string {
  let value = '';
  for (const byte of bytes) value += String.fromCharCode(byte);
  return btoa(value);
}

test('claims only current reviewed evidence and completes signing idempotently', async () => {
  const holder = new TestD1(schema);
  const db = asD1(holder);
  const artifacts = new MemoryR2();
  const fingerprint = 'a'.repeat(40);
  const artifact = new TextEncoder().encode('package bytes');
  const artifactSha256 = await sha256(artifact);
  const source = [{ name: 'hello.tar.gz', url: 'https://example.org/hello.tar.gz', sha256: 'b'.repeat(64) }];
  const recipe = 'pkgname=hello\npkgver=1.0.0\npkgrel=1\n';
  const revision = {
    id: 'revision-1', request_id: 'request-1', version: '1.0.0', recipe,
    recipe_sha256: await sha256(recipe), manifest_sha256: '', sources_json: JSON.stringify(source),
    dependencies_json: '["runtime-dep"]', smoke_commands_json: '["hello --version"]', architectures_json: '["x86_64"]', build_images_json: '{}',
    source_date_epoch: 1_700_000_000, image_digest: `ghcr.io/opr/builder@sha256:${'c'.repeat(64)}`,
    license: 'MIT', surface: 'binary' as const, explanation: 'hello', sbom_json: '{}', lint_json: '{"passed":true}',
    upstream_commit: 'd'.repeat(40), pr_url: 'https://github.com/example-owner/recipes/pull/1', commit_sha: 'e'.repeat(40), created_at: 1,
  };
  revision.manifest_sha256 = await manifestDigest(revision);
  const provenance = JSON.stringify({
    buildId: 'build-1', revisionId: revision.id, workerId: 'worker-1', recipeSha256: revision.recipe_sha256,
    artifactSha256, architecture: 'x86_64', imageDigest: `sha256:${'c'.repeat(64)}`,
    sourceDateEpoch: revision.source_date_epoch, sources: source, network: 'disabled', ...runtimeEvidence(`sha256:${'c'.repeat(64)}`),
    installedSize: 4096,
    packageMetadata: { name: 'hello', fullVersion: '1.0.0-1', architecture: 'x86_64', installedSize: 4096,
      depends: ['runtime-dep', 'lib:libOpenCL.so.1'], provides: [], conflicts: [], replaces: [] },
    startedAt: '2026-09-04T20:00:00.000Z', finishedAt: '2026-09-04T20:01:00.000Z',
  });
  const workerKeys = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
  const workerPublicKey = base64(new Uint8Array(await crypto.subtle.exportKey('raw', workerKeys.publicKey)));
  const provenanceSignature = base64(new Uint8Array(await crypto.subtle.sign(
    'Ed25519', workerKeys.privateKey, new TextEncoder().encode(provenance),
  )));
  const objectKey = 'packages/x86_64/hello-1.0.0-1-x86_64.pkg.tar.zst';
  artifacts.objects.set(objectKey, { body: artifact, customMetadata: { sha256: artifactSha256 } });
  const timestamp = Math.floor(Date.now() / 1000);
  db.prepare('INSERT INTO requests(id,name,upstream_url,source_kind,area,requested_by,status,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)')
    .bind('request-1', 'hello', source[0].url, 'archive', 'development', 'github:1', 'building', timestamp, timestamp).run();
  db.prepare(`INSERT INTO revisions(id,request_id,version,recipe,recipe_sha256,manifest_sha256,sources_json,dependencies_json,
      smoke_commands_json,architectures_json,build_images_json,source_date_epoch,image_digest,license,surface,explanation,sbom_json,lint_json,
      upstream_commit,pr_url,commit_sha,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
    .bind(revision.id, revision.request_id, revision.version, revision.recipe, revision.recipe_sha256, revision.manifest_sha256,
      revision.sources_json, revision.dependencies_json, revision.smoke_commands_json, revision.architectures_json, revision.build_images_json, revision.source_date_epoch,
      revision.image_digest, revision.license, revision.surface, revision.explanation, revision.sbom_json, revision.lint_json,
      revision.upstream_commit, revision.pr_url, revision.commit_sha, revision.created_at).run();
  db.prepare('INSERT INTO workers(id,name,architecture,public_key,status,enrolled_at) VALUES(?,?,?,?,?,?)')
    .bind('worker-1', 'test', 'x86_64', workerPublicKey, 'active', timestamp).run();
  db.prepare('INSERT INTO approvals(id,revision_id,actor,kind,manifest_sha256,created_at) VALUES(?,?,?,?,?,?)')
    .bind('approval-area', revision.id, 'github:1', 'area', revision.manifest_sha256, timestamp).run();
  db.prepare('INSERT INTO approvals(id,revision_id,actor,kind,manifest_sha256,created_at) VALUES(?,?,?,?,?,?)')
    .bind('approval-security', revision.id, 'github:2', 'security', revision.manifest_sha256, timestamp).run();
  db.prepare(`INSERT INTO builds(id,revision_id,status,architecture,worker_id,artifact_key,artifact_sha256,artifact_size,
      artifact_filename,provenance,provenance_signature,smoke_passed,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`)
    .bind('build-1', revision.id, 'succeeded', 'x86_64', 'worker-1', 'private/build-1/package.pkg.tar.zst', artifactSha256,
      artifact.byteLength, 'hello-1.0.0-1-x86_64.pkg.tar.zst', provenance, provenanceSignature, 1, timestamp).run();
  db.prepare('UPDATE builds SET installed_size=4096 WHERE id=?').bind('build-1').run();
  db.prepare(`INSERT INTO signing_intents(id,build_id,revision_id,object_key,object_kind,artifact_sha256,artifact_filename,manifest_sha256,created_at)
    VALUES(?,?,?,?,?,?,?,?,?)`).bind('intent-1', 'build-1', revision.id, objectKey, 'package', artifactSha256,
      'hello-1.0.0-1-x86_64.pkg.tar.zst', revision.manifest_sha256, timestamp).run();
  const env = {
    DB: db, ARTIFACTS: artifacts, CONTROL_TOKEN: 'control-token', PACKAGE_SIGNING_FINGERPRINT: fingerprint,
  } as unknown as SigningControlEnv;
  try {
    const first = await claimSigningIntent(env, 'intent-1');
    expect(first.status).toBe('ready');
    expect(first.artifact.size).toBe(artifact.byteLength);
    expect((await claimSigningIntent(env, 'intent-1')).status).toBe('ready');

    db.prepare('UPDATE builds SET provenance=provenance || ? WHERE id=?').bind(' ', 'build-1').run();
    await expect(claimSigningIntent(env, 'intent-1')).rejects.toThrow('Build provenance signature is invalid');
    db.prepare('UPDATE builds SET provenance=? WHERE id=?').bind(provenance, 'build-1').run();

    const invalidMetadata = JSON.stringify({ ...JSON.parse(provenance), packageMetadata: { ...JSON.parse(provenance).packageMetadata, fullVersion: '99.0-1' } });
    const invalidMetadataSignature = base64(new Uint8Array(await crypto.subtle.sign('Ed25519', workerKeys.privateKey, new TextEncoder().encode(invalidMetadata))));
    db.prepare('UPDATE builds SET provenance=?,provenance_signature=? WHERE id=?').bind(invalidMetadata, invalidMetadataSignature, 'build-1').run();
    await expect(claimSigningIntent(env, 'intent-1')).rejects.toThrow('Package metadata does not match reviewed build');
    db.prepare('UPDATE builds SET provenance=?,provenance_signature=? WHERE id=?').bind(provenance, provenanceSignature, 'build-1').run();

    const missingDependency = JSON.stringify({ ...JSON.parse(provenance), packageMetadata: { ...JSON.parse(provenance).packageMetadata, depends: [] } });
    const missingDependencySignature = base64(new Uint8Array(await crypto.subtle.sign('Ed25519', workerKeys.privateKey, new TextEncoder().encode(missingDependency))));
    db.prepare('UPDATE builds SET provenance=?,provenance_signature=? WHERE id=?').bind(missingDependency, missingDependencySignature, 'build-1').run();
    await expect(claimSigningIntent(env, 'intent-1')).rejects.toThrow('Package metadata does not contain reviewed dependencies');
    db.prepare('UPDATE builds SET provenance=?,provenance_signature=? WHERE id=?').bind(provenance, provenanceSignature, 'build-1').run();

    db.prepare('UPDATE approvals SET revoked_at=? WHERE revision_id=? AND kind=?').bind(timestamp, revision.id, 'security').run();
    await expect(claimSigningIntent(env, 'intent-1')).rejects.toThrow('Current build review approvals are incomplete');
    db.prepare('UPDATE approvals SET revoked_at=NULL WHERE revision_id=? AND kind=?').bind(revision.id, 'security').run();

    const database = new TextEncoder().encode('repository database bytes');
    const databaseSha256 = await sha256(database);
    const databaseKey = 'repo/stable/x86_64/batch-1/opr.db.tar.gz';
    artifacts.objects.set(databaseKey, { body: database, customMetadata: { sha256: databaseSha256 } });
    db.prepare(`INSERT INTO signing_intents(id,build_id,revision_id,object_key,object_kind,artifact_sha256,artifact_filename,manifest_sha256,created_at)
      VALUES(?,?,?,?,?,?,?,?,?)`).bind('intent-db', 'build-1', revision.id, databaseKey, 'database', databaseSha256,
      'opr.db.tar.gz', revision.manifest_sha256, timestamp).run();
    const databaseIntent = await claimSigningIntent(env, 'intent-db');
    expect(databaseIntent.kind).toBe('database');
    expect(databaseIntent.artifact.sha256).toBe(databaseSha256);
    db.prepare('UPDATE builds SET provenance=provenance || ? WHERE id=?').bind(' ', 'build-1').run();
    await expect(claimSigningIntent(env, 'intent-db')).rejects.toThrow('Build provenance signature is invalid');
    db.prepare('UPDATE builds SET provenance=? WHERE id=?').bind(provenance, 'build-1').run();

    const signatureKey = `${objectKey}.sig`;
    const signature = new Uint8Array([1, 2, 3, 4]);
    const signatureSha256 = await sha256(signature);
    artifacts.objects.set(signatureKey, { body: signature, customMetadata: { signatureSha256 } });
    const event = {
      action: 'signing.completed' as const, intentId: 'intent-1', kind: 'package' as const, buildId: 'build-1', revisionId: revision.id,
      artifactKey: objectKey, artifactSha256, signatureKey, signatureSha256, signatureFilename: 'hello-1.0.0-1-x86_64.pkg.tar.zst.sig',
      publicKeyKey: 'keys/opr-package-signing.asc', fingerprint, keyId: 'opr-package-signing-v1', mode: 'cloudflare-worker-secret' as const,
    };
    expect(await completeSigningIntent(env, event)).toEqual({ idempotent: false });
    expect(await completeSigningIntent(env, event)).toEqual({ idempotent: true });
    expect((await db.prepare('SELECT status FROM signing_intents WHERE id=?').bind('intent-1').first<{ status: string }>())?.status).toBe('signed');
    expect((await db.prepare("SELECT COUNT(*) AS count FROM audit_events WHERE action='signing.completed'").first<{ count: number }>())?.count).toBe(1);
    for (const surface of ['binary', 'recipe'] as const) {
      const buildId = `build-${surface}`;
      const publishedRecipe = surface === 'recipe' ? `${recipe}# published source\n` : null;
      const revised = { ...revision, id: `revision-${surface}`, created_at: timestamp + (surface === 'binary' ? 1 : 2), surface,
        public_recipe: publishedRecipe, public_recipe_sha256: publishedRecipe ? await sha256(publishedRecipe) : null };
      revised.manifest_sha256 = await manifestDigest(revised);
      const columns = Object.keys(revised);
      db.prepare(`INSERT INTO revisions(${columns.join(',')}) VALUES(${columns.map(() => '?').join(',')})`).bind(...Object.values(revised)).run();
      for (const kind of ['area', 'security']) {
        db.prepare('INSERT INTO approvals(id,revision_id,actor,kind,manifest_sha256,created_at) VALUES(?,?,?,?,?,?)')
          .bind(`${kind}-${surface}`, revised.id, 'github:1', kind, revised.manifest_sha256, timestamp).run();
      }
      const report = JSON.stringify({ ...JSON.parse(provenance), buildId, revisionId: revised.id,
        artifactSha256: surface === 'binary' ? artifactSha256 : null });
      const reportSignature = base64(new Uint8Array(await crypto.subtle.sign('Ed25519', workerKeys.privateKey, new TextEncoder().encode(report))));
      const filename = surface === 'binary' ? 'hello-1.0.0-1-x86_64.pkg.tar.zst' : null;
      db.prepare(`INSERT INTO builds(id,revision_id,status,architecture,worker_id,artifact_sha256,artifact_filename,provenance,provenance_signature,smoke_passed,created_at,installed_size)
        VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`).bind(buildId, revised.id, 'succeeded', 'x86_64', 'worker-1', surface === 'binary' ? artifactSha256 : null,
          filename, report, reportSignature, 1, timestamp, surface === 'binary' ? 4096 : null).run();
      const statement = await releaseAttestation({
        buildId, revisionId: revised.id, surface, artifactFilename: filename, artifactSha256: surface === 'binary' ? artifactSha256 : null,
        recipe: publishedRecipe ?? recipe, recipeSha256: revised.recipe_sha256, manifestSha256: revised.manifest_sha256,
        sbom: revised.sbom_json, provenance: report, provenanceSignature: reportSignature, workerPublicKey,
      });
      const key = attestationKey(buildId);
      const statementSha256 = await sha256(statement);
      artifacts.objects.set(key, { body: new TextEncoder().encode(statement), customMetadata: { sha256: statementSha256 } });
      const intentId = `attestation-${surface}`;
      db.prepare(`INSERT INTO signing_intents(id,build_id,revision_id,object_key,object_kind,artifact_sha256,artifact_filename,manifest_sha256,created_at)
        VALUES(?,?,?,?,?,?,?,?,?)`).bind(intentId, buildId, revised.id, key, 'attestation', statementSha256, 'attestation.json', revised.manifest_sha256, timestamp).run();
      const claimed = await claimSigningIntent(env, intentId);
      expect(claimed.kind).toBe('attestation');
      expect(claimed.statement).toBe(statement);
      expect(claimed.build?.surface).toBe(surface);
      const substituted = statement.replace(buildId, `x${buildId.slice(1)}`);
      artifacts.objects.set(key, { body: new TextEncoder().encode(substituted), customMetadata: { sha256: await sha256(substituted) } });
      db.prepare('UPDATE signing_intents SET artifact_sha256=? WHERE id=?').bind(await sha256(substituted), intentId).run();
      await expect(claimSigningIntent(env, intentId)).rejects.toThrow('Attestation does not match reviewed build evidence');
    }

  } finally {
    holder.close();
  }
});
