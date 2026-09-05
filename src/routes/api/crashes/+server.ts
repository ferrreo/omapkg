import { json, type RequestHandler } from '@sveltejs/kit';
import type { Actor, Release } from '$lib/model';
import { id, now, query } from '$lib/server/db';
import { PolicyError, requireMaintainer } from '$lib/server/policy';
import { crashRateKeys, crashRateLimit, reviewCrash } from '$lib/server/crashes';
import { CRASH_CONSENT_VERSION } from '$lib/reports';
import { jsonBody, sameOrigin } from '$lib/server/http';

type CrashInput = { releaseId: string; summary: string; consentVersion: string };
type ResolutionInput = { reportId: string; reason: string; action: 'confirm' | 'resolve' };
const RELEASE_ID = /^[A-Za-z0-9_-]{1,128}$/;
const CONSENT = /^[A-Za-z0-9._-]{1,32}$/;
const MAX_BODY = 16 * 1024;

function parseInput(value: unknown): CrashInput {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new PolicyError(400, 'Crash report must be a JSON object.');
  const row = value as Record<string, unknown>;
  const releaseId = typeof row.releaseId === 'string' ? row.releaseId : '';
  const summary = typeof row.summary === 'string' ? row.summary.replace(/[\u0000\r\n]+/g, ' ').trim() : '';
  const consentVersion = typeof row.consentVersion === 'string' ? row.consentVersion : '';
  if (row.consent !== true || consentVersion !== CRASH_CONSENT_VERSION || !RELEASE_ID.test(releaseId) || !summary || summary.length > 4_000 || !CONSENT.test(consentVersion)) {
    throw new PolicyError(400, 'Release ID, crash summary and consent version are required.');
  }
  return { releaseId, summary, consentVersion };
}

function parseResolution(value: unknown): ResolutionInput {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new PolicyError(400, 'Crash resolution must be a JSON object.');
  const row = value as Record<string, unknown>;
  const reportId = typeof row.reportId === 'string' ? row.reportId : '';
  const reason = typeof row.reason === 'string' ? row.reason.replace(/[\u0000\r\n]+/g, ' ').trim() : '';
  if (!RELEASE_ID.test(reportId) || !reason || reason.length > 2_000) throw new PolicyError(400, 'Report ID and resolution reason are required.');
  const action = row.action ?? 'resolve';
  if (action !== 'confirm' && action !== 'resolve') throw new PolicyError(400, 'Choose confirm or resolve.');
  return { reportId, reason, action };
}

async function body(event: Parameters<RequestHandler>[0]): Promise<CrashInput> {
  return parseInput(await jsonBody(event.request, MAX_BODY));
}

function responseError(cause: unknown) {
  if (cause instanceof PolicyError) return json({ error: cause.message }, { status: cause.status });
  console.error(cause instanceof Error ? cause.message : 'Crash report failed');
  return json({ error: 'Crash report could not be recorded.' }, { status: 500 });
}

export const POST: RequestHandler = async (event) => {
  if (!event.platform?.env?.DB) return json({ error: 'Crash reporting is unavailable.' }, { status: 503 });
  try {
    sameOrigin(event.request, event.platform.env.PUBLIC_ORIGIN, true);
    const input = await body(event);
    const release = await event.platform.env.DB.prepare(`SELECT id,channel FROM releases
      WHERE id=? AND channel IN ('dev','stable','withdrawn')`).bind(input.releaseId).first<Pick<Release, 'id' | 'channel'>>();
    if (!release) throw new PolicyError(404, 'Published release not found.');
    const env = event.platform.env;
    const crashId = id();
    const timestamp = now();
    const [dailyKey, releaseKey] = await crashRateKeys(env, event.request, release.id);
    const result = await env.DB.batch([
      crashRateLimit(env.DB, dailyKey, 10, timestamp),
      crashRateLimit(env.DB, releaseKey, 1, timestamp),
      env.DB.prepare(`INSERT INTO crash_reports(id,release_id,summary,consent_version,created_at)
        SELECT ?,?,?,?,? WHERE EXISTS(SELECT 1 FROM rateLimit WHERE key=? AND count<=10)
        AND EXISTS(SELECT 1 FROM rateLimit WHERE key=? AND count<=1)`)
        .bind(crashId, release.id, input.summary, input.consentVersion, timestamp, dailyKey, releaseKey),
      env.DB.prepare(`INSERT INTO audit_events(actor,action,target,detail,created_at)
        SELECT 'anonymous','crash.reported',?,?,? WHERE changes()=1`)
        .bind(release.id, JSON.stringify({ crashReportId: crashId, consentVersion: input.consentVersion, channel: release.channel }), timestamp),
    ]);
    if (!result[2]?.meta.changes) throw new PolicyError(429, 'One crash report per release per day is allowed, up to ten reports per day.');
    return json({ id: crashId, accepted: true }, { status: 202, headers: { 'Cache-Control': 'no-store' } });
  } catch (cause) {
    return responseError(cause);
  }
};

export const GET: RequestHandler = async (event) => {
  if (!event.platform?.env?.DB) return json({ error: 'Crash reporting is unavailable.' }, { status: 503 });
  try {
    let actor: Actor;
    try { actor = requireMaintainer(event.locals.actor); }
    catch (cause) { if (cause instanceof PolicyError) throw cause; throw cause; }
    const releaseId = event.url.searchParams.get('releaseId');
    if (releaseId && !RELEASE_ID.test(releaseId)) throw new PolicyError(400, 'Invalid release ID.');
    const rows = await query(event.platform.env.DB, `SELECT id,release_id,summary,consent_version,created_at,resolved_at,resolved_by,confirmed_at,confirmed_by
      FROM crash_reports ${releaseId ? 'WHERE release_id=?' : ''} ORDER BY created_at DESC LIMIT 200`, ...(releaseId ? [releaseId] : []));
    return json({ reports: rows }, { headers: { 'Cache-Control': 'private, no-store' } });
  } catch (cause) {
    return responseError(cause);
  }
};

export const PATCH: RequestHandler = async (event) => {
  if (!event.platform?.env?.DB) return json({ error: 'Crash reporting is unavailable.' }, { status: 503 });
  try {
    sameOrigin(event.request, event.platform.env.PUBLIC_ORIGIN);
    const input = parseResolution(await jsonBody(event.request, MAX_BODY));
    const result = await reviewCrash(event.platform.env, event.locals.actor, input);
    return json(result, { headers: { 'Cache-Control': 'no-store' } });
  } catch (cause) {
    return responseError(cause);
  }
};
