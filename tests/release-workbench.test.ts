import { expect, test } from 'bun:test';
import type { ReleaseManifest } from '../src/lib/distribution-release';
import { distributionReleaseWorkbench, getDistributionReleaseView, listDistributionReleaseCandidates } from '../src/lib/server/release-workbench';
import { env } from './release-fixtures';
import { TestD1 } from './d1';

const digest = (letter: string) => letter.repeat(64);

function manifest(kind: ReleaseManifest['kind'], releaseId: string, sequence: number, systemDigest: string | null, oprDigest: string | null): ReleaseManifest {
  const system = kind === 'system' || kind === 'resolved-transaction';
  const opr = kind === 'opr' || kind === 'resolved-transaction';
  return {
    schemaVersion: 1, kind, lane: kind === 'resolved-transaction' ? 'transaction' : kind, channel: kind === 'opr' ? 'stable' : 'stable',
    identity: { version: system ? '4.0.3' : null, generation: opr ? 'opr-20260910-1' : null }, releaseId,
    parent: { digest: null, sequence: null }, createdAt: 1_700_000_000, expiresAt: 1_800_000_000, sequence,
    architectures: ['aarch64', 'x86_64'], sourceRefs: [],
    repositories: ['aarch64', 'x86_64'].map((architecture) => ({ name: 'omapkg', architecture: architecture as 'aarch64' | 'x86_64', snapshotDigest: digest(architecture[0]), dbUrl: `https://repo.test/${architecture}.db`, signatureUrl: `https://repo.test/${architecture}.db.sig`, packageBaseUrl: `https://repo.test/${architecture}/` })),
    packageChunks: [{ url: `https://repo.test/${releaseId}.json`, sha256: digest('c'), size: 10, index: 0, count: 1, packageCount: 2 }], packageCount: 2,
    compatibility: { systemManifestDigest: systemDigest, systemSnapshotDigests: [], oprManifestDigest: oprDigest },
    systemManifest: kind === 'resolved-transaction' ? { url: 'https://repo.test/system.json', digest: digest('s'), signatureUrl: 'https://repo.test/system.json.sig', channel: 'stable', sequence: 1, version: '4.0.3', generation: null } : null,
    oprManifest: kind === 'resolved-transaction' ? { url: 'https://repo.test/opr.json', digest: digest('o'), signatureUrl: 'https://repo.test/opr.json.sig', channel: 'stable', sequence: 1, version: null, generation: 'opr-20260910-1' } : null,
    changelog: { url: `https://repo.test/${releaseId}.md`, sha256: digest('d'), size: 20, approvedBy: 'github:1', cohortDigests: [] },
    approvals: { releaseTeam: ['github:1'], baseOwners: [] },
    recovery: { fromDigest: null, target: null, authorized: false, reason: null, constraints: [] },
    policy: { schemaVersion: 1, version: 'distribution-release-v1' },
  };
}

test('release workbench preserves independent system and OPR identities with exact transaction compatibility', async () => {
  const db = new TestD1(`
    CREATE TABLE distribution_release_candidates (id TEXT PRIMARY KEY,kind TEXT,lane TEXT,channel TEXT,release_id TEXT,sequence INTEGER,parent_digest TEXT,parent_sequence INTEGER,manifest_json TEXT,manifest_sha256 TEXT,status TEXT,created_at INTEGER,activated_at INTEGER,signature_key TEXT DEFAULT 'fixture.sig',signature_sha256 TEXT DEFAULT 'fixture-signature');
    CREATE TABLE distribution_activation_pointers (lane TEXT,channel TEXT,release_id TEXT,manifest_sha256 TEXT,sequence INTEGER,system_manifest_sha256 TEXT,opr_manifest_sha256 TEXT,updated_at INTEGER,PRIMARY KEY(lane,channel));
    CREATE TABLE distribution_release_approvals (candidate_id TEXT,kind TEXT,area TEXT);
  `);
  const system = manifest('system', '4.0.3', 1, null, digest('o'));
  const opr = manifest('opr', 'opr-20260910-1', 1, digest('s'), null);
  const transaction = manifest('resolved-transaction', 'txn-4.0.3-opr-20260910-1', 1, digest('s'), digest('o'));
  const insert = (id: string, value: ReleaseManifest, status = 'active') => db.prepare(`INSERT INTO distribution_release_candidates
    (id,kind,lane,channel,release_id,sequence,parent_digest,parent_sequence,manifest_json,manifest_sha256,status,created_at,activated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`)
    .bind(id, value.kind, value.lane, value.channel, value.releaseId, value.sequence, null, null, JSON.stringify(value), digest(id[0]), status, value.createdAt, value.createdAt).run();
  insert('system-candidate', system); insert('opr-candidate', opr); insert('transaction-candidate', transaction);
  insert('rc-candidate', { ...system, channel: 'rc', sequence: 99 });
  insert('unsigned-superseded', { ...system, releaseId: '4.0.4', sequence: 100 }, 'superseded');
  db.prepare("UPDATE distribution_release_candidates SET signature_key=NULL,signature_sha256=NULL WHERE id='unsigned-superseded'").run();
  insert('opr-pending', { ...opr, releaseId: 'opr-20260910-2', identity: { version: null, generation: 'opr-20260910-2' }, sequence: 2 }, 'signed');
  db.prepare('INSERT INTO distribution_activation_pointers VALUES(?,?,?,?,?,?,?,?)').bind('system', 'stable', system.releaseId, digest('s'), 1, digest('s'), digest('o'), system.createdAt).run();
  db.prepare('INSERT INTO distribution_activation_pointers VALUES(?,?,?,?,?,?,?,?)').bind('opr', 'stable', opr.releaseId, digest('o'), 1, digest('s'), digest('o'), opr.createdAt).run();
  db.prepare('INSERT INTO distribution_activation_pointers VALUES(?,?,?,?,?,?,?,?)').bind('transaction', 'stable', transaction.releaseId, digest('t'), 1, digest('s'), digest('o'), transaction.createdAt).run();
  try {
    const view = await distributionReleaseWorkbench(env(db), null, null);
    expect(view.engine).toBe('published');
    expect(view.systemReleases[0]?.identity.version).toBe('4.0.3');
    expect(view.oprReleases[0]?.identity.generation).toBe('opr-20260910-1');
    expect(view.transactions[0]?.identity.version).toBe('4.0.3');
    expect(view.transactions[0]?.identity.generation).toBe('opr-20260910-1');
    expect(view.oprReleases[0]?.systemCompatibility).toEqual(['4.0.3', 'manifest ' + digest('s')]);
    expect(view.systemReleases[0]?.architectures).toEqual(['aarch64', 'x86_64']);
    expect(view.systemReleases[0]?.changelog.digest).toBe(digest('d'));
    const arm = await distributionReleaseWorkbench(env(db), '4.0.3', 'aarch64');
    expect(arm.oprReleases[0]?.systemCompatibility).toEqual(['4.0.3', 'manifest ' + digest('s')]);
    expect(arm.oprReleases[0]?.architectures).toEqual(['aarch64']);
    const candidates = await listDistributionReleaseCandidates(env(db));
    const rc = candidates.find((candidate) => candidate.candidateId === 'rc-candidate');
    expect(rc?.status).toBe('testing');
    expect(rc?.href).toBe('/releases/system/4.0.3?channel=rc');
    expect((await getDistributionReleaseView(env(db), 'system', '4.0.3'))?.candidateId).toBe('system-candidate');
    expect((await getDistributionReleaseView(env(db), 'system', '4.0.3', null, 'rc'))?.candidateId).toBe('rc-candidate');
    expect(await getDistributionReleaseView(env(db), 'system', '4.0.4')).toBeNull();
    const pending = candidates.find((candidate) => candidate.candidateId === 'opr-pending');
    expect(pending?.blockers.map((blocker) => blocker.code)).toContain('release-review');
    expect(pending?.blockers.map((blocker) => blocker.code)).toContain('parent-race');
  } finally { db.close(); }
});
