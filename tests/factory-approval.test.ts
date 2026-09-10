import { expect, test } from 'bun:test';
import { readFileSync, readdirSync } from 'node:fs';
import { approveRevision } from '../src/lib/server/requests';
import { manifestDigest } from '../src/lib/server/policy';
import { canonicalJson } from '../src/lib/canonical-json';
import { sha256 } from '../src/lib/server/db';
import type { Revision } from '../src/lib/model';
import { TestD1 } from './d1';
import { base64, env, MemoryR2 } from './release-fixtures';
import { runtimeEvidence } from './runtime-fixtures';

async function fixture(status = 'succeeded') {
  const db = new TestD1(readdirSync('migrations').filter((name) => name.endsWith('.sql')).sort().map((name) => readFileSync(`migrations/${name}`, 'utf8')).join('\n'));
  const insert = (table: string, values: Record<string, unknown>) => db.prepare(`INSERT INTO ${table}(${Object.keys(values).join(',')}) VALUES(${Object.keys(values).map(() => '?').join(',')})`).bind(...Object.values(values)).run();
  const imageDigest = `sha256:${'b'.repeat(64)}`;
  const sources = [{ name: 'hello.tar.gz', url: 'https://example.org/hello.tar.gz', sha256: 'a'.repeat(64) }];
  const revision: Revision = {
    id: 'revision-private', request_id: 'request-private', version: '1.0', pkgrel: 1,
    recipe: 'pkgname=hello\npkgver=1.0\npkgrel=1\n', recipe_sha256: '', manifest_sha256: '',
    sources_json: JSON.stringify(sources), dependencies_json: '[]', make_dependencies_json: '[]', smoke_commands_json: '["hello --version"]',
    architectures_json: '["x86_64"]', build_images_json: '{}', source_date_epoch: 1700000000,
    image_digest: `registry.example/builder@${imageDigest}`, license: 'MIT', surface: 'binary', explanation: 'Fixture', sbom_json: '{}', lint_json: '{"passed":true}',
    upstream_commit: null, pr_url: 'https://github.com/fixture/recipes/pull/1', commit_sha: 'c'.repeat(40), created_at: 1,
  };
  revision.recipe_sha256 = await sha256(revision.recipe);
  revision.manifest_sha256 = await manifestDigest(revision);
  const bytes = new Uint8Array([1, 2, 3]);
  const artifact = { filename: 'hello-1.0-1-x86_64.pkg.tar.zst', size: bytes.length, sha256: await sha256(bytes) };
  const keys = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
  const provenance = JSON.stringify({
    schemaVersion: 1, buildId: 'build-private', revisionId: revision.id, workerId: 'worker-private', recipeSha256: revision.recipe_sha256,
    factoryRunId: 'run-private', factoryAttempt: 1, factoryInputSha256: 'a'.repeat(64),
    architecture: 'x86_64', sourceDateEpoch: revision.source_date_epoch, sources, network: 'disabled', imageDigest, artifactSha256: artifact.sha256,
    packageMetadata: { name: 'hello', fullVersion: '1.0-1', architecture: 'x86_64', installedSize: 3, depends: [], provides: [], conflicts: [], replaces: [] },
    ...runtimeEvidence(imageDigest),
    reproducibility: { schemaVersion: 1, status: 'reproducibility-contract-verified', mode: 'single-build', target: 'x86_64',
      execution: { runId: 'run-private', attempt: 1, inputSha256: 'a'.repeat(64) },
      inputs: { recipeSha256: revision.recipe_sha256, sourceManifestSha256: await sha256(canonicalJson(sources)), inputLockSha256: '', dependencyPlanSha256: '', imageDigest, sourceDateEpoch: revision.source_date_epoch },
      controls: { network: 'disabled', locale: 'C', timezone: 'UTC', umask: '022', hostSecrets: 'excluded', writableCaches: 'excluded', nativeTarget: 'x86_64', archivePathsChecked: true, archiveMetadataChecked: true, timestampOwnershipOrderChecked: true },
      outputs: { setSha256: await sha256(canonicalJson([artifact])), files: [artifact], unexpected: [], prohibitedPaths: [] }, limitations: ['Inert signed fixture; no native reproduction is claimed.'] },
  });
  insert('requests', { id: revision.request_id, name: 'hello', upstream_url: 'https://example.org/hello.tar.gz', source_kind: 'archive', area: 'system', declared_license: 'MIT', requested_by: 'github:1', status: 'review', created_at: 1, updated_at: 1, factory_run_id: 'run-private' });
  insert('revisions', { ...revision });
  insert('workers', { id: 'worker-private', name: 'Fixture', architecture: 'x86_64', public_key: base64(await crypto.subtle.exportKey('raw', keys.publicKey)), status: 'active', enrolled_at: 1 });
  insert('factory_runs', { id: 'run-private', target_kind: 'generated', target_id: revision.request_id, unit_key: 'request', status: 'succeeded', attempt_count: 1, current_attempt: 1, successful_attempt: 1, policy_json: '{}', created_by: 'github:1', created_at: 1, updated_at: 2 });
  insert('factory_run_attempts', { id: 'attempt-private', run_id: 'run-private', attempt: 1, reservation_key: 'first', status: 'succeeded', candidate_revision_id: revision.id, candidate_sha256: revision.recipe_sha256, input_sha256: 'a'.repeat(64), candidate_json: '{}', build_ids_json: '["build-private"]', lease_token: 'test-lease', lease_expires_at: 2, started_at: 1, finished_at: 2, created_at: 1, updated_at: 2 });
  insert('builds', { id: 'build-private', revision_id: revision.id, architecture: 'x86_64', status, worker_id: 'worker-private', attempt: 1, artifact_key: 'private/fixture', artifact_sha256: artifact.sha256, artifact_size: artifact.size, artifact_filename: artifact.filename, installed_size: 3, smoke_passed: 1, provenance, provenance_signature: base64(await crypto.subtle.sign('Ed25519', keys.privateKey, new TextEncoder().encode(provenance))), created_at: 1, factory_run_id: 'run-private', factory_attempt: 1, private_candidate: 1 });
  insert('approvals', { id: 'area-private', revision_id: revision.id, actor: 'github:1', kind: 'area', manifest_sha256: revision.manifest_sha256, created_at: 1 });
  const storage = new MemoryR2();
  storage.objects.set('private/fixture', bytes);
  const service = { ...env(db), ARTIFACTS: storage as unknown as R2Bucket, GITHUB_REPOSITORY: 'fixture/recipes', GITHUB_REPO_TOKEN: 'github_pat_test_only' };
  return { db, revision, storage, service };
}

test('final review reuses the exact private artifact and retains factory history', async () => {
  const { db, revision, storage, service } = await fixture();
  const original = globalThis.fetch;
  let githubCalls = 0;
  globalThis.fetch = Object.assign(async () => { githubCalls += 1; return Response.json({ head: { sha: revision.commit_sha }, merged: true }); }, { preconnect: original.preconnect });
  try {
    await approveRevision(service, { id: 'github:2', role: 'security', areas: [] }, revision.request_id, revision.id, 'security', 'Reviewed exact fixture bytes.', true);
    expect(db.prepare('SELECT COUNT(*) AS n FROM builds').first<{ n: number }>()).toEqual({ n: 1 });
    expect(db.prepare('SELECT status,attempt,private_candidate,factory_run_id,factory_attempt FROM builds').first<{ status: string; attempt: number; private_candidate: number; factory_run_id: string; factory_attempt: number }>()).toEqual({ status: 'succeeded', attempt: 1, private_candidate: 0, factory_run_id: 'run-private', factory_attempt: 1 });
    expect(storage.objects.get('private/fixture')).toEqual(new Uint8Array([1, 2, 3]));
    expect(githubCalls).toBe(1);
  } finally { globalThis.fetch = original; db.close(); }
});

test('failed candidates and changed artifact bytes cannot be promoted or rebuilt through approval', async () => {
  for (const state of ['failed', 'leased', 'tampered']) {
    const { db, revision, storage, service } = await fixture(state === 'tampered' ? 'succeeded' : state);
    if (state === 'tampered') storage.objects.set('private/fixture', new Uint8Array([3, 2, 1]));
    const original = globalThis.fetch;
    globalThis.fetch = Object.assign(async () => { throw new Error('Must stop before GitHub merge.'); }, { preconnect: original.preconnect });
    try {
      await expect(approveRevision(service, { id: 'github:2', role: 'security', areas: [] }, revision.request_id, revision.id, 'security', 'Fixture review.', true)).rejects.toThrow(state === 'tampered' ? 'digest' : 'Only the successful factory attempt');
      expect(db.prepare('SELECT status,attempt,private_candidate FROM builds').first<{ status: string; attempt: number; private_candidate: number }>()).toEqual({ status: state === 'tampered' ? 'succeeded' : state, attempt: 1, private_candidate: 1 });
      expect(db.prepare('SELECT status FROM requests').first<{ status: string }>()).toEqual({ status: 'review' });
    } finally { globalThis.fetch = original; db.close(); }
  }
});

test('private artifact review survives merge recovery and fences approval revocation during merge', async () => {
  for (const failure of ['github', 'revocation']) {
    const { db, revision, service } = await fixture();
    const original = globalThis.fetch;
    globalThis.fetch = Object.assign(async () => {
      if (failure === 'github') return new Response('fixture outage', { status: 503 });
      db.prepare("UPDATE approvals SET revoked_at=3 WHERE kind='security'").run();
      return Response.json({ head: { sha: revision.commit_sha }, merged: true });
    }, { preconnect: original.preconnect });
    try {
      await expect(approveRevision(service, { id: 'github:2', role: 'security', areas: [] }, revision.request_id, revision.id, 'security', 'Fixture review.', true)).rejects.toThrow();
      expect(db.prepare('SELECT status,attempt,private_candidate FROM builds').first<{ status: string; attempt: number; private_candidate: number }>()).toEqual({ status: 'succeeded', attempt: 1, private_candidate: 1 });
      expect(db.prepare('SELECT status FROM requests').first<{ status: string }>()).toEqual({ status: 'review' });
      globalThis.fetch = Object.assign(async () => Response.json({ head: { sha: revision.commit_sha }, merged: true }), { preconnect: original.preconnect });
      await approveRevision(service, { id: 'github:2', role: 'security', areas: [] }, revision.request_id, revision.id, 'security', 'Retry exact fixture review.', true);
      expect(db.prepare('SELECT attempt,private_candidate FROM builds').first<{ attempt: number; private_candidate: number }>()).toEqual({ attempt: 1, private_candidate: 0 });
    } finally { globalThis.fetch = original; db.close(); }
  }
});
