import { CRASH_REPORT_RETENTION_DAYS } from '../reports';
import type { Actor } from '../model';
import { audit, now } from './db';
import type { Env } from './env';
import { PolicyError, requireMaintainer } from './policy';
import { quarantineRelease } from './releases';

const MAX_ATTEMPTS = 5;

function threshold(env: Env): number {
  const value = Number(env.CRASH_THRESHOLD ?? 3);
  return Number.isSafeInteger(value) && value > 0 ? value : 3;
}

export async function crashRateKeys(env: Env, request: Request, releaseId: string): Promise<[string, string]> {
  if (!env.BETTER_AUTH_SECRET) throw new PolicyError(503, 'Crash reporting is unavailable.');
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(env.BETTER_AUTH_SECRET), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const day = Math.floor(now() / 86_400);
  const address = request.headers.get('CF-Connecting-IP') ?? 'unavailable';
  const signature = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(`crash:${day}:${address}`));
  const digest = Array.from(new Uint8Array(signature), (byte) => byte.toString(16).padStart(2, '0')).join('');
  return [`crash:${digest}`, `crash:${digest}:${releaseId}`];
}

export function crashRateLimit(db: D1Database, key: string, limit: number, timestamp: number) {
  return db.prepare(`INSERT INTO rateLimit(id,key,count,lastRequest) VALUES(?,?,1,?)
    ON CONFLICT(key) DO UPDATE SET count=MIN(rateLimit.count+1,?),lastRequest=excluded.lastRequest`)
    .bind(key, key, timestamp, limit + 1);
}

function enqueue(env: Env, releaseId: string, timestamp: number) {
  return env.DB.prepare(`INSERT INTO crash_quarantines(release_id,status,next_attempt_at,updated_at)
    SELECT ?,'queued',?,? WHERE EXISTS(SELECT 1 FROM releases WHERE id=? AND channel='stable')
    AND changes()=1 AND (SELECT COUNT(*) FROM crash_reports WHERE release_id=? AND confirmed_at IS NOT NULL AND resolved_at IS NULL)>=?
    ON CONFLICT(release_id) DO UPDATE SET status='queued',attempts=0,next_attempt_at=excluded.next_attempt_at,
      lease_expires_at=NULL,last_error=NULL,updated_at=excluded.updated_at WHERE crash_quarantines.status IN ('completed','failed')`)
    .bind(releaseId, timestamp, timestamp, releaseId, releaseId, threshold(env));
}

export async function reviewCrash(env: Env, actor: Actor | null, input: { reportId: string; reason: string; action: 'confirm' | 'resolve' }) {
  const reviewer = requireMaintainer(actor);
  if (reviewer.role !== 'admin') throw new PolicyError(403, 'Administrator access is required to review crash reports.');
  const report = await env.DB.prepare('SELECT release_id,resolved_at FROM crash_reports WHERE id=?')
    .bind(input.reportId).first<{ release_id: string; resolved_at: number | null }>();
  if (!report) throw new PolicyError(404, 'Crash report not found.');
  if (report.resolved_at !== null) throw new PolicyError(409, 'Crash report is already resolved.');
  const timestamp = now();
  const update = input.action === 'confirm'
    ? env.DB.prepare('UPDATE crash_reports SET confirmed_at=?,confirmed_by=? WHERE id=? AND confirmed_at IS NULL AND resolved_at IS NULL')
    : env.DB.prepare('UPDATE crash_reports SET resolved_at=?,resolved_by=? WHERE id=? AND resolved_at IS NULL');
  const result = await env.DB.batch([
    update.bind(timestamp, reviewer.id, input.reportId),
    env.DB.prepare(`INSERT INTO audit_events(actor,action,target,detail,created_at) SELECT ?,?,?,?,? WHERE changes()=1`)
      .bind(reviewer.id, input.action === 'confirm' ? 'crash.confirmed' : 'crash.resolved', report.release_id,
        JSON.stringify({ crashReportId: input.reportId, reason: input.reason }), timestamp),
    enqueue(env, report.release_id, timestamp),
  ]);
  if (!result[0]?.meta.changes) throw new PolicyError(409, 'Crash report changed. Refresh and retry.');
  return { reportId: input.reportId, action: input.action, reviewedAt: timestamp };
}

export async function retryCrashQuarantine(env: Env, actor: Actor | null, releaseId: string) {
  const reviewer = requireMaintainer(actor);
  if (reviewer.role !== 'admin') throw new PolicyError(403, 'Administrator access is required to retry quarantine.');
  const timestamp = now();
  const results = await env.DB.batch([
    env.DB.prepare("UPDATE crash_quarantines SET status='queued',attempts=0,next_attempt_at=?,last_error=NULL,updated_at=? WHERE release_id=? AND status='failed'")
      .bind(timestamp, timestamp, releaseId),
    env.DB.prepare(`INSERT INTO audit_events(actor,action,target,detail,created_at) SELECT ?,'crash.quarantine_retried',?,'{}',? WHERE changes()=1`)
      .bind(reviewer.id, releaseId, timestamp),
  ]);
  if (!results[0]?.meta.changes) throw new PolicyError(409, 'No failed quarantine job is waiting for retry.');
}

export async function processCrashQuarantines(env: Env, publish = quarantineRelease): Promise<void> {
  const timestamp = now();
  const jobs = await env.DB.prepare(`SELECT release_id FROM crash_quarantines
    WHERE (status='queued' AND next_attempt_at<=?) OR (status='processing' AND lease_expires_at<=?)
    ORDER BY next_attempt_at LIMIT 10`).bind(timestamp, timestamp).all<{ release_id: string }>();
  for (const { release_id: releaseId } of jobs.results) {
    const lease = now() + 300;
    const claimed = await env.DB.prepare(`UPDATE crash_quarantines SET status='processing',attempts=attempts+1,lease_expires_at=?,updated_at=?
      WHERE release_id=? AND ((status='queued' AND next_attempt_at<=?) OR (status='processing' AND lease_expires_at<=?))`)
      .bind(lease, now(), releaseId, now(), now()).run();
    if (!claimed.meta.changes) continue;
    try {
      const count = await env.DB.prepare('SELECT COUNT(*) AS count FROM crash_reports WHERE release_id=? AND confirmed_at IS NOT NULL AND resolved_at IS NULL')
        .bind(releaseId).first<{ count: number }>();
      const warranted = (count?.count ?? 0) >= threshold(env);
      if (warranted) await publish(env, releaseId, `Confirmed unresolved crash reports reached threshold (${count!.count}).`, threshold(env));
      await env.DB.batch([
        env.DB.prepare("UPDATE crash_quarantines SET status='completed',lease_expires_at=NULL,last_error=NULL,updated_at=? WHERE release_id=? AND status='processing' AND lease_expires_at=?")
          .bind(now(), releaseId, lease),
        env.DB.prepare(`INSERT INTO audit_events(actor,action,target,detail,created_at) SELECT 'system:crash-policy',?,?,?,? WHERE changes()=1`)
          .bind(warranted ? 'crash.quarantine_completed' : 'crash.quarantine_cancelled', releaseId, '{}', now()),
      ]);
    } catch {
      await env.DB.batch([
        env.DB.prepare(`UPDATE crash_quarantines SET status=CASE WHEN attempts>=? THEN 'failed' ELSE 'queued' END,
          next_attempt_at=?,lease_expires_at=NULL,last_error='Quarantine publication failed.',updated_at=?
          WHERE release_id=? AND status='processing' AND lease_expires_at=?`)
          .bind(MAX_ATTEMPTS, now() + 900, now(), releaseId, lease),
        env.DB.prepare(`INSERT INTO audit_events(actor,action,target,detail,created_at)
          SELECT 'system:crash-policy','crash.quarantine_failed',release_id,json_object('status',status,'attempts',attempts),?
          FROM crash_quarantines WHERE release_id=? AND changes()=1`).bind(now(), releaseId),
      ]);
    }
  }
}

export async function expireCrashReports(env: Env): Promise<void> {
  const timestamp = now();
  await env.DB.batch([
    env.DB.prepare(`UPDATE crash_reports SET summary='[Report text removed after retention period.]',
      resolved_at=CASE WHEN confirmed_at IS NULL THEN COALESCE(resolved_at,?) ELSE resolved_at END,
      resolved_by=CASE WHEN confirmed_at IS NULL THEN COALESCE(resolved_by,'system:retention') ELSE resolved_by END
      WHERE created_at<? AND summary<>'[Report text removed after retention period.]'`)
      .bind(timestamp, timestamp - CRASH_REPORT_RETENTION_DAYS * 86_400),
    env.DB.prepare(`INSERT INTO audit_events(actor,action,target,detail,created_at)
      SELECT 'system:retention','crash.retention_applied','crash-reports',json_object('count',changes()),? WHERE changes()>0`).bind(timestamp),
    env.DB.prepare("DELETE FROM rateLimit WHERE key LIKE 'crash:%' AND lastRequest<?").bind(timestamp - 86_400),
  ]);
}
