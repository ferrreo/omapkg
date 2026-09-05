import { expect, test } from 'bun:test';
import { gunzipSync } from 'node:zlib';
import { promoteBatch, quarantineRelease, rollbackRelease } from '../src/lib/server/releases';
import { sha256 } from '../src/lib/server/db';
import { GET as repositoryGet } from '../src/routes/repo/[...path]/+server';
import { TestD1 } from './d1';
import { schema, MemoryR2, base64, env, insertBinaryRelease } from './release-fixtures';

const reviewer = { id: 'github:1', role: 'maintainer' as const, areas: ['development'] };
const signed = () => Response.json({ signature: { key: 'signatures/database.sig', sha256: 'a'.repeat(64) } });

function serviceFixture() {
  const db = new TestD1(`${schema}
    CREATE TABLE signing_intents(id TEXT PRIMARY KEY,build_id TEXT,revision_id TEXT,object_key TEXT,object_kind TEXT,artifact_sha256 TEXT,artifact_filename TEXT,manifest_sha256 TEXT,status TEXT DEFAULT 'pending',signature_key TEXT,signature_sha256 TEXT,created_at INTEGER,consumed_at INTEGER,expires_at INTEGER,artifact_size INTEGER,key_fingerprint TEXT);
    CREATE TABLE repository_snapshots(id TEXT PRIMARY KEY,architecture TEXT,channel TEXT,db_key TEXT,db_signature_key TEXT,batch_id TEXT,created_at INTEGER,active INTEGER);
    CREATE TABLE promotion_batches(id TEXT PRIMARY KEY,actor TEXT,release_ids_json TEXT,reason TEXT,created_at INTEGER);
    CREATE TABLE distribution_assertions(expected INTEGER,actual INTEGER,CHECK(expected=actual));
    CREATE TABLE release_rollbacks(release_id TEXT PRIMARY KEY,previous_release_id TEXT,manifest_key TEXT,created_at INTEGER);
    CREATE TABLE workers(id TEXT PRIMARY KEY,public_key TEXT,status TEXT);
    ALTER TABLE crash_reports ADD COLUMN confirmed_at INTEGER;`);
  const r2 = new MemoryR2();
  r2.objects.set('signatures/package.sig', new Uint8Array([1, 2, 3]));
  r2.objects.set('signatures/database.sig', new Uint8Array([4, 5, 6]));
  const service = env(db);
  service.ARTIFACTS = r2 as unknown as R2Bucket;
  service.SIGNER = { fetch: async () => signed() } as unknown as Fetcher;
  return { db, service, r2 };
}

function channel(db: TestD1, releaseId: string): string | undefined {
  return db.prepare('SELECT channel FROM releases WHERE id=?').bind(releaseId).first<{ channel: string }>()?.channel;
}

function repositoryText(db: TestD1, r2: MemoryR2, channel: string): string {
  const row = db.prepare('SELECT db_key FROM repository_snapshots WHERE channel=? AND active=1').bind(channel).first<{ db_key: string }>();
  expect(row).not.toBeNull();
  return new TextDecoder().decode(gunzipSync(r2.objects.get(row!.db_key)!));
}

async function makeRecipe(db: TestD1, r2: MemoryR2, releaseId: string) {
  db.prepare("UPDATE releases SET surface='recipe',artifact_key=NULL,signature_key=NULL WHERE id=?").bind(releaseId).run();
  db.prepare("UPDATE revisions SET surface='recipe' WHERE id=?").bind(`revision-${releaseId}`).run();
  const keys = await crypto.subtle.generateKey('Ed25519', true, ['sign', 'verify']);
  const sources = JSON.parse(db.prepare('SELECT sources_json FROM revisions WHERE id=?')
    .bind(`revision-${releaseId}`).first<{ sources_json: string }>()!.sources_json);
  const provenance = JSON.stringify({
    buildId: `build-${releaseId}`, revisionId: `revision-${releaseId}`, workerId: releaseId,
    architecture: 'x86_64', recipeSha256: 'a'.repeat(64), imageDigest: 'sha256:' + 'd'.repeat(64),
    sourceDateEpoch: 1, network: 'disabled', artifactSha256: null, sources,
  });
  db.prepare("INSERT INTO workers VALUES(?,?,'active')").bind(releaseId, base64(await crypto.subtle.exportKey('raw', keys.publicKey))).run();
  db.prepare(`UPDATE builds SET worker_id=?,provenance=?,provenance_signature=?,artifact_key=NULL,
    artifact_sha256=NULL,artifact_size=NULL,artifact_filename=NULL WHERE id=?`)
    .bind(releaseId, provenance, base64(await crypto.subtle.sign('Ed25519', keys.privateKey, new TextEncoder().encode(provenance))), `build-${releaseId}`).run();
  const recipeKey = db.prepare('SELECT recipe_key FROM releases WHERE id=?').bind(releaseId).first<{ recipe_key: string }>()!.recipe_key;
  r2.objects.set(recipeKey, new TextEncoder().encode('pkgname=foo\n'));
}

test('promotion retains dev history and indexes the remaining version', async () => {
  const { db, service, r2 } = serviceFixture();
  try {
    insertBinaryRelease(db, { id: 'old', name: 'foo', version: '1.0-1', dependencies: [], channel: 'dev' });
    insertBinaryRelease(db, { id: 'new', name: 'foo', version: '2.0-1', dependencies: [], channel: 'dev' });
    await promoteBatch(service, reviewer, ['new'], 'promote reviewed latest');
    expect(channel(db, 'new')).toBe('stable');
    expect(channel(db, 'old')).toBe('dev');
    expect(repositoryText(db, r2, 'dev')).toContain('%VERSION%\n1.0-1\n');
    expect(repositoryText(db, r2, 'stable')).toContain('%VERSION%\n2.0-1\n');
  } finally { db.close(); }
});

test('crash quarantine preserves newer dev history', async () => {
  const { db, service, r2 } = serviceFixture();
  try {
    insertBinaryRelease(db, { id: 'stable', name: 'foo', version: '1.0-1', dependencies: [], channel: 'stable' });
    insertBinaryRelease(db, { id: 'new-dev', name: 'foo', version: '2.0-1', dependencies: [], channel: 'dev' });
    db.prepare("UPDATE releases SET published_at=2 WHERE id='new-dev'").run();
    expect(await quarantineRelease(service, 'stable', 'confirmed crashes')).toBe(true);
    expect(channel(db, 'stable')).toBe('dev');
    expect(channel(db, 'new-dev')).toBe('dev');
    expect(repositoryText(db, r2, 'dev')).toContain('%VERSION%\n2.0-1\n');
    expect(repositoryText(db, r2, 'stable')).not.toContain('%NAME%\nfoo\n');
  } finally { db.close(); }
});

test.each(['crash', 'approval'])('%s changing during signing blocks promotion atomically', async (change) => {
  const { db, service } = serviceFixture();
  try {
    insertBinaryRelease(db, { id: 'old', name: 'foo', version: '1.0-1', dependencies: [], channel: 'stable' });
    insertBinaryRelease(db, { id: 'new', name: 'foo', version: '2.0-1', dependencies: [], channel: 'dev' });
    let changed = false;
    service.SIGNER = {
      fetch: async () => {
        if (!changed) {
          if (change === 'crash') db.prepare("INSERT INTO crash_reports(id,release_id,summary,consent_version,created_at) VALUES('crash','new','crash during promotion','v1',1)").run();
          else db.prepare("UPDATE approvals SET revoked_at=2 WHERE revision_id='revision-new' AND kind='security'").run();
          changed = true;
        }
        return signed();
      },
    } as unknown as Fetcher;
    await expect(promoteBatch(service, reviewer, ['new'], 'promote reviewed latest')).rejects.toThrow();
    expect(channel(db, 'new')).toBe('dev');
    expect(channel(db, 'old')).toBe('stable');
    expect(db.prepare('SELECT count(*) AS count FROM repository_snapshots').first<{ count: number }>()?.count).toBe(0);
  } finally { db.close(); }
});

test('Surface B rollback hashes the published recipe', async () => {
  const { db, service, r2 } = serviceFixture();
  try {
    insertBinaryRelease(db, { id: 'old', name: 'foo', version: '1.0-1', dependencies: [], channel: 'stable' });
    insertBinaryRelease(db, { id: 'new', name: 'foo', version: '2.0-1', dependencies: [], channel: 'stable' });
    await makeRecipe(db, r2, 'old');
    await makeRecipe(db, r2, 'new');
    db.exec("UPDATE releases SET channel='withdrawn' WHERE id='old'; UPDATE releases SET previous_release_id='old' WHERE id='new';");
    const internalRecipe = "pkgname=foo\nsource=('https://opr.example/sources/private.tar')\n";
    const publicRecipe = "pkgname=foo\nsource=('https://vendor.example/foo.tar')\n";
    db.prepare("UPDATE revisions SET recipe=?,recipe_sha256=? WHERE id='revision-old'").bind(internalRecipe, await sha256(internalRecipe)).run();
    const recipeKey = 'recipes/foo/1.0-1/x86_64/PKGBUILD';
    r2.objects.set(recipeKey, new TextEncoder().encode(publicRecipe));
    const result = await rollbackRelease(service, reviewer, 'new', 'restore previous public recipe');
    const manifest = JSON.parse(new TextDecoder().decode(r2.objects.get(result.manifestKey)!));
    expect(manifest.recipe.sha256).not.toBe(await sha256(internalRecipe));
    expect(manifest.recipe.sha256).toBe(await sha256(r2.objects.get(recipeKey)!));
  } finally { db.close(); }
});

test.each(['signer', 'transaction'])('rollback retries after a transient %s failure', async (failure) => {
  const { db, service, r2 } = serviceFixture();
  const originalNow = Date.now;
  const originalBatch = db.batch.bind(db);
  try {
    insertBinaryRelease(db, { id: 'old', name: 'foo', version: '1.0-1', dependencies: [], channel: 'stable' });
    insertBinaryRelease(db, { id: 'new', name: 'foo', version: '2.0-1', dependencies: [], channel: 'stable' });
    db.exec("UPDATE releases SET channel='withdrawn' WHERE id='old'; UPDATE releases SET previous_release_id='old' WHERE id='new';");
    const bytes = new Uint8Array([1, 2, 3]);
    r2.objects.set('packages/x86_64/foo-1.0-1-x86_64.pkg.tar.zst', bytes);
    db.prepare("UPDATE builds SET artifact_sha256=?,artifact_size=? WHERE id='build-old'").bind(await sha256(bytes), bytes.length).run();
    Date.now = () => 1800000000000;
    if (failure === 'signer') service.SIGNER = { fetch: async () => new Response('temporary outage', { status: 503 }) } as unknown as Fetcher;
    else db.batch = () => { throw new Error('injected commit failure'); };
    await expect(rollbackRelease(service, reviewer, 'new', 'restore prior package')).rejects.toThrow();
    expect(channel(db, 'new')).toBe('stable');
    Date.now = () => 1800000002000;
    db.batch = originalBatch;
    service.SIGNER = { fetch: async () => signed() } as unknown as Fetcher;
    await rollbackRelease(service, reviewer, 'new', 'restore prior package');
    expect(channel(db, 'new')).toBe('withdrawn');
    expect(channel(db, 'old')).toBe('stable');
    expect(repositoryText(db, r2, 'stable')).toContain('%VERSION%\n1.0-1\n');
    const response = await repositoryGet({ platform: { env: service }, params: { path: 'rollback/new.json' } } as Parameters<typeof repositoryGet>[0]);
    expect(response.status).toBe(200);
    expect((await response.json() as { to: { releaseId: string } }).to.releaseId).toBe('old');
  } finally { Date.now = originalNow; db.close(); }
});

test('recipe upgrade records its predecessor and can roll back', async () => {
  const { db, service, r2 } = serviceFixture();
  try {
    insertBinaryRelease(db, { id: 'old', name: 'foo', version: '1.0-1', dependencies: [], channel: 'stable' });
    insertBinaryRelease(db, { id: 'new', name: 'foo', version: '2.0-1', dependencies: [], channel: 'dev' });
    await makeRecipe(db, r2, 'old');
    await makeRecipe(db, r2, 'new');
    await promoteBatch(service, reviewer, ['new'], 'promote recipe update');
    expect(channel(db, 'old')).toBe('withdrawn');
    expect(db.prepare("SELECT previous_release_id FROM releases WHERE id='new'").first<{ previous_release_id: string | null }>()?.previous_release_id).toBe('old');
    await rollbackRelease(service, reviewer, 'new', 'restore recipe');
    expect(channel(db, 'old')).toBe('stable');
    expect(channel(db, 'new')).toBe('withdrawn');
  } finally { db.close(); }
});

test.each(['old', 'new'])('promotion handles a recipe at the %s end of a surface change', async (recipeId) => {
  const { db, service, r2 } = serviceFixture();
  try {
    insertBinaryRelease(db, { id: 'old', name: 'foo', version: '1.0-1', dependencies: [], channel: 'stable' });
    insertBinaryRelease(db, { id: 'new', name: 'foo', version: '2.0-1', dependencies: [], channel: 'dev' });
    await makeRecipe(db, r2, recipeId);
    await promoteBatch(service, reviewer, ['new'], 'change distribution surface');
    expect(channel(db, 'old')).toBe('withdrawn');
    expect(channel(db, 'new')).toBe('stable');
    const database = repositoryText(db, r2, 'stable');
    expect(database.includes('%NAME%\nfoo\n')).toBe(recipeId === 'old');
    expect(database).not.toContain('%VERSION%\n1.0-1\n');
  } finally { db.close(); }
});

test('external signer rejects nonlocal HTTP and redirects before publishing evidence', async () => {
  const { signingRequest } = await import('../src/lib/server/release-evidence');
  const { db, service } = serviceFixture();
  const originalFetch = globalThis.fetch;
  const requests: Request[] = [];
  globalThis.fetch = (async (input: RequestInfo | URL) => {
    requests.push(input as Request);
    return new Response(null, { status: 302, headers: { Location: 'http://untrusted.example/sign' } });
  }) as typeof fetch;
  const input = {
    buildId: 'build-test', revisionId: 'revision-test', manifestSha256: 'a'.repeat(64),
    objectKey: 'packages/x86_64/foo.pkg.tar.zst', objectKind: 'package' as const,
    artifactSha256: 'b'.repeat(64), artifactSize: 3, artifactFilename: 'foo.pkg.tar.zst',
  };
  try {
    delete service.SIGNER;
    service.SIGNER_TOKEN = 'dummy-signing-token';
    service.SIGNER_URL = 'http://signer.example';
    await expect(signingRequest(service, input)).rejects.toThrow('must use HTTPS');
    expect(requests).toHaveLength(0);
    for (const origin of ['https://signer.example', 'http://127.0.0.1:8080']) {
      service.SIGNER_URL = origin;
      await expect(signingRequest(service, input)).rejects.toThrow('rejected request (302)');
      const request = requests.at(-1)!;
      expect(request.url).toBe(`${origin}/v1/sign`);
      expect(request.redirect).toBe('manual');
      expect(request.headers.get('Authorization')).toBe('Bearer dummy-signing-token');
    }
    expect(requests).toHaveLength(2);
  } finally { globalThis.fetch = originalFetch; db.close(); }
});
