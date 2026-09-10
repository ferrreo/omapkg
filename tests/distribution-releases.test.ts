import { expect, test } from 'bun:test';
import { readFileSync, readdirSync } from 'node:fs';
import { canonicalJson } from '../src/lib/canonical-json';
import { releaseManifestBytes, releaseManifestDigest, type ReleaseManifest } from '../src/lib/distribution-release';
import { sha256 } from '../src/lib/server/db';
import { approveDistributionRelease, assertOmarchyPair, prepareDistributionRelease, type DistributionCandidateInput, type OwnedPackageRow } from '../src/lib/server/distribution-releases';
import { claimSigningIntent } from '../src/lib/server/signing-control';
import type { Env } from '../src/lib/server/env';
import { MemoryR2 } from './release-fixtures';
import { asD1, TestD1 } from './d1';
import { GET as readCandidate } from '../src/routes/api/maintain/distribution-releases/+server';

const schema = readdirSync(new URL('../migrations', import.meta.url)).filter((file) => file.endsWith('.sql')).sort()
  .map((file) => readFileSync(new URL(`../migrations/${file}`, import.meta.url), 'utf8')).join('\n');

function fixture() {
  const db = new TestD1(schema);
  const artifacts = new MemoryR2();
  const env = { DB: asD1(db), ARTIFACTS: artifacts as unknown as R2Bucket, PUBLIC_ORIGIN: 'https://repo.example', QUARANTINE_HOURS: '48' } as Env;
  return { db, artifacts, env };
}

const actor = { id: 'github:42', role: 'maintainer' as const, areas: ['system'] as const };
const releaseActor = { id: 'github:7', role: 'maintainer' as const, areas: ['system'] as const };

function manifest(releaseId = 'opr-20260910-1'): ReleaseManifest {
  return {
    schemaVersion: 1, kind: 'opr', lane: 'opr', channel: 'stable',
    identity: { version: null, generation: releaseId }, releaseId,
    parent: { digest: null, sequence: null }, createdAt: 1_700_000_000, expiresAt: 1_800_000_000, sequence: 1,
    architectures: ['x86_64', 'aarch64'], sourceRefs: [],
    repositories: [{ name: 'omapkg', architecture: 'x86_64', snapshotDigest: 'a'.repeat(64), dbUrl: 'https://repo.example/repo.db', signatureUrl: 'https://repo.example/repo.db.sig', packageBaseUrl: 'https://repo.example/packages/' }],
    packageChunks: [{ url: 'https://repo.example/chunk.json', sha256: 'b'.repeat(64), size: 1, index: 0, count: 1, packageCount: 1 }], packageCount: 1,
    compatibility: { systemManifestDigest: 'c'.repeat(64), systemSnapshotDigests: [], oprManifestDigest: null },
    systemManifest: null, oprManifest: null,
    changelog: { url: 'https://repo.example/changelog.json', sha256: 'd'.repeat(64), size: 1, approvedBy: '', cohortDigests: [] },
    approvals: { releaseTeam: [], baseOwners: [] },
    recovery: { fromDigest: null, target: null, authorized: false, reason: null, constraints: [] },
    policy: { schemaVersion: 1, version: 'distribution-release-v1' },
  };
}

async function insertCandidate(db: TestD1, artifacts: MemoryR2, value: ReleaseManifest, id: string, status: 'candidate' | 'signed' = 'candidate') {
  const digest = await releaseManifestDigest(value);
  const bytes = new TextEncoder().encode(releaseManifestBytes(value));
  const key = `distribution/releases/${value.kind}/${value.channel}/${value.releaseId}/manifest.json`;
  artifacts.objects.set(key, bytes);
  db.prepare(`INSERT INTO distribution_release_candidates
    (id,kind,lane,channel,release_id,sequence,parent_digest,parent_sequence,manifest_json,manifest_sha256,manifest_key,manifest_size,changelog_key,changelog_sha256,status,created_by,created_at)
    VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).bind(
    id, value.kind, value.lane, value.channel, value.releaseId, value.sequence, value.parent.digest, value.parent.sequence,
    releaseManifestBytes(value), digest, key, bytes.byteLength, 'changelog.json', value.changelog.sha256, status, 'github:42', value.createdAt,
  ).run();
  return { digest, bytes, key };
}

async function missingGateInput(artifacts: MemoryR2): Promise<DistributionCandidateInput> {
  const chunk = { schemaVersion: 1, index: 0, count: 1, packages: [{
    releaseId: 'missing-package', name: 'missing-package', version: '1.0-1', architecture: 'x86_64',
    artifactUrl: 'https://repo.example/packages/missing-package.pkg.tar.zst', artifactSha256: 'a'.repeat(64),
    artifactSignatureUrl: 'https://repo.example/packages/missing-package.pkg.tar.zst.sig', artifactSignatureSha256: 'b'.repeat(64),
    cohortId: 'missing-cohort', evidence: [],
  }] };
  const chunkBytes = new TextEncoder().encode(canonicalJson(chunk));
  const changelogBytes = new TextEncoder().encode('{}');
  artifacts.objects.set('missing/chunk.json', chunkBytes);
  artifacts.objects.set('missing/changelog.json', changelogBytes);
  return {
    kind: 'opr', channel: 'quarantine', releaseId: 'opr-20260910-1', architectures: ['x86_64', 'aarch64'], packageCount: 1,
    compatibility: { systemManifestDigest: 'e'.repeat(64), systemSnapshotDigests: [], oprManifestDigest: null }, repositories: [],
    packageChunks: [{ key: 'missing/chunk.json', url: 'https://repo.example/missing/chunk.json', sha256: await sha256(chunkBytes), size: chunkBytes.byteLength }],
    changelog: { key: 'missing/changelog.json', url: 'https://repo.example/missing/changelog.json', sha256: await sha256(changelogBytes), size: changelogBytes.byteLength },
  };
}

test('release manifests bind exact canonical bytes', async () => {
  const value = manifest();
  const bytes = new TextEncoder().encode(releaseManifestBytes(value));
  expect(await releaseManifestDigest(value)).toBe(await sha256(bytes));
  expect(releaseManifestBytes(JSON.parse(new TextDecoder().decode(bytes)) as ReleaseManifest)).toBe(new TextDecoder().decode(bytes));
});

test('authenticated candidate lookup uses candidate ID before signing', async () => {
  const { db, artifacts, env } = fixture();
  try {
    await insertCandidate(db, artifacts, manifest(), 'draft-candidate-id');
    const url = new URL('https://repo.example/api/maintain/distribution-releases?candidateId=draft-candidate-id');
    const response = await readCandidate({ url, request: new Request(url), locals: { actor }, platform: { env } } as never);
    expect(response.status).toBe(200);
    const value = await response.json() as { candidate: { id: string; release_id: string; status: string } };
    expect(value.candidate).toMatchObject({ id: 'draft-candidate-id', release_id: 'opr-20260910-1', status: 'candidate' });
  } finally { db.close(); }
});

test('release preparation fails closed when cohort qualification is missing', async () => {
  const { db, artifacts, env } = fixture();
  try {
    await expect(prepareDistributionRelease(env, actor, await missingGateInput(artifacts))).rejects.toThrow('not qualified for release activation');
  } finally { db.close(); }
});

test('release approval requires current release-team membership and remains digest-bound', async () => {
  const { db, artifacts, env } = fixture();
  try {
    const candidate = await insertCandidate(db, artifacts, manifest(), 'candidate-approval');
    await expect(approveDistributionRelease(env.DB, releaseActor, { candidateId: 'candidate-approval', kind: 'release', reason: 'Ship exact candidate.' })).rejects.toThrow('Explicit release team membership');
    db.prepare('INSERT INTO team_memberships VALUES(?,?)').bind('7', 'release').run();
    const approved = await approveDistributionRelease(env.DB, releaseActor, { candidateId: 'candidate-approval', kind: 'release', reason: 'Ship exact candidate.' });
    expect(approved.manifestSha256).toBe(candidate.digest);
    expect((await db.prepare('SELECT actor,manifest_sha256 FROM distribution_release_approvals').first<{ actor: string; manifest_sha256: string }>())).toEqual({ actor: 'github:7', manifest_sha256: candidate.digest });
  } finally { db.close(); }
});

test('manifest signing control claims exact candidate bytes without mutating immutable inputs', async () => {
  const { db, artifacts, env } = fixture();
  try {
    const candidate = await insertCandidate(db, artifacts, manifest(), 'candidate-signing');
    const intentId = 'manifest-intent-1';
    db.prepare('INSERT INTO team_memberships(github_id,team) VALUES(?,?)').bind('7', 'release').run();
    db.prepare('INSERT INTO distribution_release_approvals(id,candidate_id,manifest_sha256,kind,actor,area,reason,created_at) VALUES(?,?,?,?,?,?,?,?)')
      .bind('approval-signing', 'candidate-signing', candidate.digest, 'release', 'github:7', null, 'fixture', 1).run();
    db.prepare(`INSERT INTO distribution_manifest_signing_intents
      (id,candidate_id,object_key,artifact_sha256,artifact_filename,manifest_sha256,status,created_at,expires_at,key_fingerprint)
      VALUES(?,?,?,?,?,?,?,?,?,?)`).bind(intentId, 'candidate-signing', candidate.key, candidate.digest, 'manifest.json', candidate.digest, 'pending', Math.floor(Date.now() / 1000), Math.floor(Date.now() / 1000) + 3_600, 'a'.repeat(40)).run();
    const claimed = await claimSigningIntent({ ...env, PACKAGE_SIGNING_FINGERPRINT: 'a'.repeat(40) }, intentId);
    expect(claimed.kind).toBe('manifest');
    expect(claimed.build).toBeUndefined();
    expect(claimed.artifact.sha256).toBe(candidate.digest);
  } finally { db.close(); }
});

test.each(['held candidate', 'revoked approver'])('manifest claim rechecks %s state', async (caseName) => {
  const { db, artifacts, env } = fixture();
  try {
    const candidateId = `candidate-${caseName.replaceAll(' ', '-')}`;
    const candidate = await insertCandidate(db, artifacts, manifest(), candidateId);
    const intentId = `manifest-intent-${caseName.replaceAll(' ', '-')}`;
    db.prepare('INSERT INTO team_memberships(github_id,team) VALUES(?,?)').bind('7', 'release').run();
    db.prepare('INSERT INTO distribution_release_approvals(id,candidate_id,manifest_sha256,kind,actor,area,reason,created_at) VALUES(?,?,?,?,?,?,?,?)')
      .bind(`approval-${intentId}`, candidateId, candidate.digest, 'release', 'github:7', null, 'fixture', 1).run();
    db.prepare(`INSERT INTO distribution_manifest_signing_intents
      (id,candidate_id,object_key,artifact_sha256,artifact_filename,manifest_sha256,status,created_at,expires_at,key_fingerprint)
      VALUES(?,?,?,?,?,?,?,?,?,?)`).bind(intentId, candidateId, candidate.key, candidate.digest, 'manifest.json', candidate.digest, 'pending', Math.floor(Date.now() / 1000), Math.floor(Date.now() / 1000) + 3_600, 'a'.repeat(40)).run();
    if (caseName === 'held candidate') db.prepare("UPDATE distribution_release_candidates SET status='held' WHERE id=?").bind(candidateId).run();
    else db.prepare("DELETE FROM team_memberships WHERE github_id=? AND team='release'").bind('7').run();
    await expect(claimSigningIntent({ ...env, PACKAGE_SIGNING_FINGERPRINT: 'a'.repeat(40) }, intentId)).rejects.toThrow();
  } finally { db.close(); }
});

function pairRows(): Array<{ item: Record<string, unknown>; row: OwnedPackageRow }> {
  return ['x86_64', 'aarch64'].flatMap((architecture) => ['omarchy', 'omarchy-settings'].map((name, index) => ({
    item: { releaseId: `${name}-${architecture}`, name, version: '4.0.3-1', architecture, artifactSha256: `${String(index + architecture.length).repeat(64).slice(0, 64)}`, cohortId: 'cohort-1' },
    row: { id: `${name}-${architecture}`, name, version: '4.0.3-1', architecture, artifact_key: `${name}-${architecture}`, signature_key: `${name}-${architecture}.sig`, artifact_sha256: `${String(index + architecture.length).repeat(64).slice(0, 64)}`, artifact_size: 1, filename: `${name}-4.0.3-1-${architecture}.pkg.tar.zst`, collection: 'omarchy', target_architecture: architecture as 'x86_64' | 'aarch64', cohort_id: 'cohort-1', revision_id: `${name}-${architecture}-revision` },
  })));
}

function insertOmarchySource(db: TestD1, revisionId: string, commit: string) {
  db.prepare(`INSERT INTO requests(id,name,upstream_url,source_kind,area,requested_by,status,created_at,updated_at,upstream_ref)
    VALUES(?,?,?,?,?,?,?,?,?,?)`).bind(`request-${revisionId}`, revisionId, 'https://example.org/omarchy.git', 'git', 'system', 'github:1', 'built', 1, 1, commit).run();
  db.prepare(`INSERT INTO revisions(id,request_id,version,recipe,recipe_sha256,manifest_sha256,sources_json,dependencies_json,smoke_commands_json,architectures_json,source_date_epoch,image_digest,license,surface,explanation,sbom_json,lint_json,upstream_commit,created_at,pkgrel)
    VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).bind(revisionId, `request-${revisionId}`, '4.0.3', 'pkgname=omarchy\n', '1'.repeat(64), `manifest-${revisionId}`, '[]', '[]', '[]', '["x86_64","aarch64"]', 1, 'sha256:image', 'MIT', 'binary', '', '{}', '{}', commit, 1, 1).run();
}

test('system Omarchy pair gate rejects missing/mismatched pairs and enforces RC final-byte carry-forward', async () => {
  const mismatch = fixture();
  try {
    const rows = pairRows();
    for (const [index, row] of rows.entries()) insertOmarchySource(mismatch.db, row.row.revision_id!, index === 3 ? 'b'.repeat(40) : 'a'.repeat(40));
    await expect(assertOmarchyPair(mismatch.env, rows.slice(0, 3), '4.0.3')).rejects.toThrow('both architectures');
    await expect(assertOmarchyPair(mismatch.env, rows, '4.0.3')).rejects.toThrow('same upstream commit');
  } finally { mismatch.db.close(); }

  const { db, artifacts, env } = fixture();
  try {
    const rows = pairRows();
    for (const row of rows) insertOmarchySource(db, row.row.revision_id!, 'a'.repeat(40));
    const rcPackages = rows.map(({ row }) => ({ name: row.name, architecture: row.architecture, version: row.version, artifactSha256: row.artifact_sha256 }));
    const rc = new TextEncoder().encode(JSON.stringify({ packages: rcPackages }));
    artifacts.objects.set('rc.json', rc);
    db.prepare(`INSERT INTO distribution_release_candidates
      (id,kind,lane,channel,release_id,sequence,parent_digest,parent_sequence,manifest_json,manifest_sha256,manifest_key,manifest_size,changelog_key,changelog_sha256,status,created_by,created_at)
      VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).bind('rc-candidate-1','system','system','rc','rc-any',1,null,null,'{}','1'.repeat(64),'rc-manifest',1,'rc-change','2'.repeat(64),'signed','github:1',1).run();
    db.prepare('INSERT INTO distribution_release_objects(candidate_id,kind,digest,object_key,size) VALUES(?,?,?,?,?)').bind('rc-candidate-1','package-chunk',await sha256(rc),'rc.json',rc.byteLength).run();
    await expect(assertOmarchyPair(env, rows, '4.0.3')).resolves.toMatchObject({ commit: 'a'.repeat(40) });
    const relabeled = new TextEncoder().encode(JSON.stringify({ packages: rcPackages.map((item) => ({ ...item, version: '4.0.3rc1-1' })) }));
    artifacts.objects.set('rc-relabeled.json', relabeled);
    db.prepare("UPDATE distribution_release_candidates SET status='superseded' WHERE id='rc-candidate-1'").run();
    db.prepare(`INSERT INTO distribution_release_candidates
      (id,kind,lane,channel,release_id,sequence,parent_digest,parent_sequence,manifest_json,manifest_sha256,manifest_key,manifest_size,changelog_key,changelog_sha256,status,created_by,created_at)
      VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).bind('rc-candidate-2','system','system','rc','rc-any-2',1,null,null,'{}','3'.repeat(64),'rc-manifest-2',1,'rc-change-2','4'.repeat(64),'signed','github:1',1).run();
    db.prepare('INSERT INTO distribution_release_objects(candidate_id,kind,digest,object_key,size) VALUES(?,?,?,?,?)').bind('rc-candidate-2','package-chunk',await sha256(relabeled),'rc-relabeled.json',relabeled.byteLength).run();
    await expect(assertOmarchyPair(env, rows, '4.0.3')).rejects.toThrow('relabels earlier RC metadata');
    const untested = new TextEncoder().encode(JSON.stringify({ packages: rcPackages.map((item) => ({ ...item, artifactSha256: 'a'.repeat(63) + 'b' })) }));
    artifacts.objects.set('rc-untested.json', untested);
    db.prepare("UPDATE distribution_release_candidates SET status='superseded' WHERE id='rc-candidate-2'").run();
    db.prepare(`INSERT INTO distribution_release_candidates
      (id,kind,lane,channel,release_id,sequence,parent_digest,parent_sequence,manifest_json,manifest_sha256,manifest_key,manifest_size,changelog_key,changelog_sha256,status,created_by,created_at)
      VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).bind('rc-candidate-3','system','system','rc','rc-any-3',1,null,null,'{}','5'.repeat(64),'rc-manifest-3',1,'rc-change-3','6'.repeat(64),'signed','github:1',1).run();
    db.prepare('INSERT INTO distribution_release_objects(candidate_id,kind,digest,object_key,size) VALUES(?,?,?,?,?)').bind('rc-candidate-3','package-chunk',await sha256(untested),'rc-untested.json',untested.byteLength).run();
    await expect(assertOmarchyPair(env, rows, '4.0.3')).rejects.toThrow('bytes were not qualified');
  } finally { db.close(); }
});
