import { expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import type { Worker } from '../src/lib/model';
import { sha256 } from '../src/lib/server/db';
import { claimJob } from '../src/lib/server/workers';
import { TestD1, asD1 } from './d1';
import { GET } from '../src/routes/sources/[filename]/+server';

const digest = 'a'.repeat(64);
const origin = 'https://omapkg.example';
const source = `${origin}/sources/${digest}.tar`;
function database() {
  const db = new TestD1(readFileSync('migrations/0001_initial.sql', 'utf8'));
  db.exec(readFileSync('migrations/0005_factory_run_id.sql', 'utf8'));
  db.exec(readFileSync('migrations/0007_core_guards.sql', 'utf8'));
  db.exec(readFileSync('migrations/0011_build_images.sql', 'utf8'));
  db.exec(readFileSync('migrations/0014_package_metadata.sql', 'utf8'));
  db.exec(readFileSync('migrations/0015_installed_size.sql', 'utf8'));
  db.exec(readFileSync('migrations/0018_worker_metadata.sql', 'utf8'));
  db.exec(readFileSync('migrations/0019_crash_triage.sql', 'utf8'));
  db.exec(readFileSync('migrations/0020_worker_lifecycle.sql', 'utf8'));
  db.exec(readFileSync('migrations/0023_dependency_plan.sql', 'utf8'));
  db.exec(`INSERT INTO requests(id,name,upstream_url,source_kind,area,requested_by,status,created_at,updated_at)
    VALUES('q','hello','https://github.com/example/hello','git','development','github:1','built',1,1)`);
  db.prepare(`INSERT INTO revisions(id,request_id,version,recipe,recipe_sha256,manifest_sha256,sources_json,dependencies_json,smoke_commands_json,
    architectures_json,source_date_epoch,image_digest,license,surface,explanation,sbom_json,lint_json,created_at)
    VALUES('r','q','1','pkgname=hello',?,? ,?,'[]','[]','["x86_64"]',1,'image@sha256:${'c'.repeat(64)}','MIT','binary','','{}','{}',1)`)
    .bind(digest, 'b'.repeat(64), JSON.stringify([{ name: 'hello.tar', url: source, sha256: digest }])).run();
  db.exec("INSERT INTO builds(id,revision_id,architecture,status,created_at) VALUES('b','r','x86_64','succeeded',1)");
  return db;
}
function requestEvent(db: TestD1, reads: string[], request = new Request(source)) {
  return {
    request, url: new URL(source), params: { filename: `${digest}.tar` },
    platform: { env: { DB: asD1(db), PUBLIC_ORIGIN: origin, ARTIFACTS: {
      async get(key: string) { reads.push(key); return { body: new Blob(['source']).stream(), size: 6, httpEtag: '"test"' }; }
    } } }
  } as unknown as Parameters<typeof GET>[0];
}

async function normalClaimFixture() {
  const db = new TestD1(readFileSync('migrations/0001_initial.sql', 'utf8'));
  db.exec(readFileSync('migrations/0007_core_guards.sql', 'utf8'));
  db.exec(readFileSync('migrations/0011_build_images.sql', 'utf8'));
  db.exec(readFileSync('migrations/0014_package_metadata.sql', 'utf8'));
  db.exec(readFileSync('migrations/0015_installed_size.sql', 'utf8'));
  db.exec(readFileSync('migrations/0018_worker_metadata.sql', 'utf8'));
  db.exec(readFileSync('migrations/0019_crash_triage.sql', 'utf8'));
  db.exec(readFileSync('migrations/0020_worker_lifecycle.sql', 'utf8'));
  db.exec(readFileSync('migrations/0023_dependency_plan.sql', 'utf8'));
  const keys = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
  const publicKey = (() => {
    let binary = '';
    return async () => {
      binary = '';
      for (const byte of new Uint8Array(await crypto.subtle.exportKey('raw', keys.publicKey))) binary += String.fromCharCode(byte);
      return btoa(binary);
    };
  })();
  const timestamp = Math.floor(Date.now() / 1000);
  const sourceRecord = { name: 'hello.tar', url: source, sha256: digest };
  const manifest = 'b'.repeat(64);
  const recipe = 'pkgname=hello\npkgver=1\npkgrel=1\n';
  db.exec(`INSERT INTO requests(id,name,upstream_url,source_kind,area,requested_by,status,created_at,updated_at)
    VALUES('queued-request','hello-queued','https://github.com/example/hello','git','development','github:1','queued',${timestamp},${timestamp})`);
  db.prepare(`INSERT INTO revisions(id,request_id,version,recipe,recipe_sha256,manifest_sha256,sources_json,dependencies_json,smoke_commands_json,
    architectures_json,source_date_epoch,image_digest,license,surface,explanation,sbom_json,lint_json,upstream_commit,pr_url,commit_sha,created_at)
    VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).bind(
    'queued-revision', 'queued-request', '1.0.0', recipe, await sha256(recipe), manifest,
    JSON.stringify([sourceRecord]), '[]', '[]', '["x86_64"]', 1, `image@sha256:${'c'.repeat(64)}`, 'MIT', 'binary', '', '{}', '{}', 'commit', 'https://github.com/example/hello/pull/1', 'd'.repeat(40), timestamp
  ).run();
  db.prepare('INSERT INTO approvals(id,revision_id,actor,kind,manifest_sha256,created_at) VALUES(?,?,?,?,?,?)')
    .bind('approval-area', 'queued-revision', 'github:area', 'area', manifest, timestamp).run();
  db.prepare('INSERT INTO approvals(id,revision_id,actor,kind,manifest_sha256,created_at) VALUES(?,?,?,?,?,?)')
    .bind('approval-security', 'queued-revision', 'github:security', 'security', manifest, timestamp).run();
  const encodedPublicKey = await publicKey();
  db.prepare('INSERT INTO workers(id,name,architecture,public_key,status,enrolled_at,last_seen_at) VALUES(?,?,?,?,?,?,?)')
    .bind('source-worker', 'source-worker', 'x86_64', encodedPublicKey, 'active', timestamp, timestamp).run();
  db.prepare('INSERT INTO builds(id,revision_id,architecture,status,created_at) VALUES(?,?,?,?,?)')
    .bind('queued-build', 'queued-revision', 'x86_64', 'queued', timestamp).run();
  const worker = await db.prepare('SELECT * FROM workers WHERE id=?').bind('source-worker').first<Worker>();
  if (!worker) throw new Error('source worker fixture failed');
  return { db, worker, privateKey: keys.privateKey };
}

async function signedSourceRequest(workerId: string, privateKey: CryptoKey): Promise<Request> {
  const timestamp = Math.floor(Date.now() / 1000).toString();
  const nonce = crypto.randomUUID().replaceAll('-', '').slice(0, 32);
  const bodyHash = await sha256(new Uint8Array());
  const message = new TextEncoder().encode(`GET\n/sources/${digest}.tar\n${timestamp}\n${nonce}\n${bodyHash}`);
  const signature = await crypto.subtle.sign({ name: 'Ed25519' }, privateKey, message as BufferSource);
  let binary = '';
  for (const byte of new Uint8Array(signature)) binary += String.fromCharCode(byte);
  return new Request(source, { headers: {
    'X-OPR-Worker': workerId,
    'X-OPR-Timestamp': timestamp,
    'X-OPR-Nonce': nonce,
    'X-OPR-Signature': btoa(binary)
  } });
}
test('unpublished archives stay private; only published redistributable sources are public', async () => {
  const db = database();
  const reads: string[] = [];
  try {
    await expect(GET(requestEvent(db, reads))).rejects.toMatchObject({ status: 401 });
    expect(reads).toEqual([]);
    db.exec(`INSERT INTO releases(id,build_id,name,version,architecture,surface,channel,artifact_key,signature_key,recipe_key,sbom_key,provenance_key,published_at)
      VALUES('release','b','hello','1','x86_64','binary','dev','artifact','signature','recipe','sbom','provenance',1)`);
    const response = await GET(requestEvent(db, reads));
    expect(response.status).toBe(200);
    expect(await response.text()).toBe('source');
    expect(reads).toEqual([`sources/${digest}.tar`]);
    db.exec("UPDATE releases SET surface='recipe' WHERE id='release'");
    await expect(GET(requestEvent(db, reads))).rejects.toMatchObject({ status: 401 });
    expect(reads.length).toBe(1);
  } finally { db.close(); }
});

test('a normal queued claim can read its signed materialized source while queued or building, but revoked and cancelled work cannot', async () => {
  const { db, worker, privateKey } = await normalClaimFixture();
  const reads: string[] = [];
  try {
    const job = await claimJob(asD1(db), worker);
    expect(job?.id).toBe('queued-build');
    expect(db.prepare("SELECT status FROM requests WHERE id='queued-request'").first<{ status: string }>()?.status).toBe('building');

    const queued = await GET(requestEvent(db, reads, await signedSourceRequest(worker.id, privateKey)));
    expect(queued.status).toBe(200);
    expect(await queued.text()).toBe('source');

    db.prepare("UPDATE requests SET status='building' WHERE id='queued-request'").run();
    const building = await GET(requestEvent(db, reads, await signedSourceRequest(worker.id, privateKey)));
    expect(building.status).toBe(200);
    expect(await building.text()).toBe('source');

    db.prepare("UPDATE requests SET status='rejected' WHERE id='queued-request'").run();
    await expect(GET(requestEvent(db, reads, await signedSourceRequest(worker.id, privateKey)))).rejects.toMatchObject({ status: 403 });
    db.prepare("UPDATE requests SET status='queued' WHERE id='queued-request'").run();
    db.prepare("UPDATE builds SET status='cancelled' WHERE id='queued-build'").run();
    await expect(GET(requestEvent(db, reads, await signedSourceRequest(worker.id, privateKey)))).rejects.toMatchObject({ status: 403 });
    db.prepare("UPDATE builds SET status='leased' WHERE id='queued-build'").run();
    db.prepare("UPDATE workers SET status='revoked' WHERE id='source-worker'").run();
    await expect(GET(requestEvent(db, reads, await signedSourceRequest(worker.id, privateKey)))).rejects.toMatchObject({ status: 403 });
    expect(reads).toEqual(['sources/' + digest + '.tar', 'sources/' + digest + '.tar']);
  } finally { db.close(); }
});
