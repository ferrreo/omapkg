import { expect, test } from 'bun:test';
import { readFileSync, readdirSync } from 'node:fs';
import { asD1, TestD1 } from './d1';
import { POST as feedback } from '../src/routes/api/feedback/+server';
import { POST as crash, PATCH as resolveCrash } from '../src/routes/api/crashes/+server';
import type { Actor } from '../src/lib/model';
import { CRASH_CONSENT_VERSION } from '../src/lib/reports';
import { expireCrashReports, processCrashQuarantines } from '../src/lib/server/crashes';
import { PolicyError } from '../src/lib/server/policy';
import type { Env } from '../src/lib/server/env';

const origin = 'https://test.example';
const actor: Actor = { id: 'github:1', role: 'public', areas: [] };
function database() {
  const db = new TestD1();
  for (const file of readdirSync('migrations').filter((f) => f.endsWith('.sql')).sort()) db.exec(readFileSync(`migrations/${file}`, 'utf8'));
  db.exec(`INSERT INTO requests(id,name,upstream_url,source_kind,area,requested_by,status,created_at,updated_at)
    VALUES('q','hello','https://example.org/hello.tar','archive','development','github:1','built',1,1);
    INSERT INTO revisions(id,request_id,version,recipe,recipe_sha256,manifest_sha256,sources_json,dependencies_json,smoke_commands_json,architectures_json,source_date_epoch,image_digest,license,surface,explanation,sbom_json,lint_json,created_at)
    VALUES('r','q','1','pkgname=hello','hash','manifest','[]','[]','[]','["x86_64"]',1,'image@sha256:abc','MIT','binary','','{}','{}',1);
    INSERT INTO builds(id,revision_id,architecture,status,created_at) VALUES('b','r','x86_64','succeeded',1);
    INSERT INTO releases(id,build_id,name,version,architecture,surface,channel,artifact_key,signature_key,recipe_key,sbom_key,provenance_key,published_at)
    VALUES('release','b','hello','1','x86_64','binary','dev','artifact','sig','recipe','sbom','provenance',1);`);
  return db;
}
function event(db: TestD1, body: unknown, currentActor: Actor | null = actor, method = 'POST', requestOrigin = origin, ip = '192.0.2.1') {
  return {
    request: new Request(`${origin}/api/report`, { method, headers: { 'Content-Type': 'application/json', Origin: requestOrigin, 'CF-Connecting-IP': ip }, body: JSON.stringify(body) }),
    url: new URL(`${origin}/api/report`),
    locals: { actor: currentActor }, platform: { env: { DB: asD1(db), PUBLIC_ORIGIN: origin, BETTER_AUTH_SECRET: 'test-only-crash-rate-secret'  } }
  } as unknown as Parameters<typeof feedback>[0];
}

test('feedback is authenticated, same-origin and bound to one actor/release record', async () => {
  const db = database();
  try {
    const body = { releaseId: 'release', works: 1, comment: 'Runs correctly.' };
    expect((await feedback(event(db, body, null))).status).toBe(401);
    expect((await feedback(event(db, body, actor, 'POST', 'https://other.example'))).status).toBe(403);
    expect((await feedback(event(db, body))).status).toBe(202);
    expect((await feedback(event(db, { ...body, works: 0, comment: 'Startup fails.' }))).status).toBe(202);
    expect(db.prepare('SELECT actor,works,comment FROM feedback').first<{actor:string;works:number;comment:string}>()).toEqual({ actor: actor.id, works: 0, comment: 'Startup fails.' });
    expect(db.prepare('SELECT count(*) AS count FROM feedback').first<{count:number}>()).toEqual({ count: 1 });
    expect((await feedback(event(db, { ...body, comment: 'x'.repeat(20000) }))).status).toBe(413);
  } finally { db.close(); }
});

test('crash reports require explicit current consent and omit signed-in identity', async () => {
  const db = database();
  try {
    const body = { releaseId: 'release', summary: 'Crashes on launch.', consentVersion: CRASH_CONSENT_VERSION };
    expect((await crash(event(db, body))).status).toBe(400);
    expect((await crash(event(db, { ...body, consent: false }))).status).toBe(400);
    expect((await crash(event(db, { ...body, consent: true, consentVersion: 'old' }))).status).toBe(400);
    const response = await crash(event(db, { ...body, consent: true }));
    expect(response.status).toBe(202);
    const { id } = await response.json() as { id: string };
    expect(db.prepare("SELECT actor FROM audit_events WHERE action='crash.reported'").first<{actor:string}>()).toEqual({ actor: 'anonymous' });
    const resolution = { reportId: id, reason: 'Fixed and smoke-tested.' };
    expect((await resolveCrash(event(db, resolution, { ...actor, role: 'maintainer', areas: ['development'] }, 'PATCH'))).status).toBe(403);
    expect((await resolveCrash(event(db, resolution, { ...actor, role: 'admin' }, 'PATCH'))).status).toBe(200);
  } finally { db.close(); }
});


test('anonymous reports are limited and quarantine waits for confirmed reports with durable retry', async () => {
  const db = database();
  const env = { DB: asD1(db), CRASH_THRESHOLD: '3' } as Env;
  const admin = { ...actor, role: 'admin' as const };
  try {
    db.exec("UPDATE releases SET channel='stable' WHERE id='release'");
    const input = { releaseId: 'release', summary: 'Crashes on launch.', consent: true, consentVersion: CRASH_CONSENT_VERSION };
    const reports: string[] = [];
    for (let index = 0; index < 3; index++) {
      const response = await crash(event(db, input, null, 'POST', origin, `192.0.2.${index + 1}`));
      expect(response.status).toBe(202);
      reports.push((await response.json() as { id: string }).id);
    }
    expect((await crash(event(db, input, null))).status).toBe(429);
    expect(db.prepare('SELECT COUNT(*) AS count FROM crash_reports').first<{ count: number }>()).toEqual({ count: 3 });
    expect(db.prepare('SELECT COUNT(*) AS count FROM crash_quarantines').first<{ count: number }>()).toEqual({ count: 0 });
    expect(db.prepare('SELECT channel FROM releases').first<{ channel: string }>()).toEqual({ channel: 'stable' });
    for (const reportId of reports) {
      expect((await resolveCrash(event(db, { reportId, action: 'confirm', reason: 'Reproduced in an isolated environment.' }, admin, 'PATCH'))).status).toBe(200);
    }
    expect(db.prepare('SELECT status FROM crash_quarantines').first<{ status: string }>()).toEqual({ status: 'queued' });
    await processCrashQuarantines(env, async () => { throw new PolicyError(503, 'Signer is temporarily unavailable.'); });
    expect(db.prepare('SELECT status,attempts FROM crash_quarantines').first<{ status: string; attempts: number }>()).toEqual({ status: 'queued', attempts: 1 });
    db.exec('UPDATE crash_quarantines SET next_attempt_at=0');
    let calls = 0;
    await processCrashQuarantines(env, async (_env, releaseId, _reason, minimum) => {
      calls++;
      expect(releaseId).toBe('release');
      expect(minimum).toBe(3);
      db.exec("UPDATE releases SET channel='dev' WHERE id='release'");
      return true;
    });
    expect(calls).toBe(1);
    expect(db.prepare('SELECT status FROM crash_quarantines').first<{ status: string }>()).toEqual({ status: 'completed' });
    await processCrashQuarantines(env, async () => { throw new Error('Completed job must not run twice.'); });
    expect(db.prepare("SELECT COUNT(*) AS count FROM audit_events WHERE action='crash.quarantine_failed'").first<{ count: number }>()).toEqual({ count: 1 });
    const keys = db.prepare("SELECT key FROM rateLimit WHERE key LIKE 'crash:%'").all<{ key: string }>().results;
    expect(keys.every(({ key }) => !key.includes('192.0.2.') && !key.includes(actor.id))).toBe(true);
  } finally { db.close(); }
});

test('crash retention removes old summaries without clearing confirmed incidents', async () => {
  const db = database();
  try {
    db.exec(`INSERT INTO crash_reports(id,release_id,summary,consent_version,created_at,confirmed_at,confirmed_by)
      VALUES('old-confirmed','release','private diagnostic text','privacy-v1',1,2,'github:1'),
      ('old-unconfirmed','release','stale report text','privacy-v1',1,NULL,NULL);`);
    await expireCrashReports({ DB: asD1(db) } as Env);
    const rows = db.prepare('SELECT id,summary,resolved_at FROM crash_reports ORDER BY id').all<{ id: string; summary: string; resolved_at: number | null }>().results;
    expect(rows.every((row) => row.summary === '[Report text removed after retention period.]')).toBe(true);
    expect(rows[0].resolved_at).toBeNull();
    expect(rows[1].resolved_at).not.toBeNull();
  } finally { db.close(); }
});
