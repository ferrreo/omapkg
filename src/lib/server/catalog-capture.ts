import type { Actor } from '../model';
import type { Env } from './env';
import { canonicalJson } from '../canonical-json';
import { audit, id, now, query, sha256 } from './db';
import { humanMaintainer } from './catalog-ownership';
import { PolicyError, publicSourceURL } from './policy';

export type CapturePayload = { kind: 'arch' | 'omarchy' | 'opr'; channel: 'upstream' | 'stable' | 'rc' | 'edge' | 'dev'; oprOrigin: string | null; oprLayout: 'omapkg' | 'omarchy' };
export type CaptureJob = { id: string; payload_json: string; status: 'queued' | 'capturing' | 'uploading' | 'captured' | 'failed'; import_id: string | null; progress_json: string; error: string | null; created_by: string; created_at: number; updated_at: number };

export async function startCatalogCapture(env: Env, actor: Actor | null, kind: string, channel: string, oprLayout: string) {
  const reviewer = humanMaintainer(actor, 'system');
  if (!['arch', 'omarchy', 'opr'].includes(kind) || !['omapkg', 'omarchy'].includes(oprLayout)) throw new PolicyError(400, 'Choose Arch, Omarchy baseline or existing OPR capture.');
  if (kind === 'arch') channel = 'upstream';
  const channels = kind === 'arch' ? ['upstream'] : kind === 'opr' && oprLayout === 'omapkg' ? ['stable', 'dev'] : ['stable', 'rc', 'edge'];
  if (!channels.includes(channel)) throw new PolicyError(400, 'Channel does not exist for this repository layout.');
  if (!env.PIPELINE) throw new PolicyError(503, 'The import pipeline is not configured.');
  const payload: CapturePayload = { kind: kind as CapturePayload['kind'], channel: channel as CapturePayload['channel'], oprLayout: oprLayout as CapturePayload['oprLayout'],
    oprOrigin: kind === 'opr' ? oprLayout === 'omarchy' ? 'https://pkgs.omarchy.org' : publicSourceURL(env.PUBLIC_ORIGIN).replace(/\/$/, '') : null };
  const json = canonicalJson(payload); const digest = await sha256(json);
  const existing = await env.DB.prepare("SELECT id FROM catalog_import_jobs WHERE request_sha256=? AND status IN ('queued','capturing','uploading')").bind(digest).first<{ id: string }>();
  if (existing) return { jobId: existing.id };
  const jobId = id(); const timestamp = now();
  try {
    await env.DB.batch([
      env.DB.prepare("INSERT INTO catalog_import_jobs(id,payload_json,request_sha256,status,created_by,created_at,updated_at) VALUES(?,?,?,'queued',?,?,?)").bind(jobId, json, digest, reviewer.id, timestamp, timestamp),
      audit(env.DB, reviewer.id, 'catalog.capture_requested', jobId, payload),
    ]);
  } catch (cause) {
    if (cause instanceof Error && /unique|constraint/i.test(cause.message)) throw new PolicyError(409, 'This repository capture was queued concurrently. Refresh its status.');
    throw cause;
  }
  try {
    const response = await env.PIPELINE.fetch('https://pipeline.internal/import', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ jobId }) });
    if (!response.ok) throw new Error('Capture workflow dispatch failed.');
  } catch {
    await env.DB.prepare("UPDATE catalog_import_jobs SET status='failed',error='Capture workflow could not be queued.',updated_at=? WHERE id=? AND status='queued'").bind(now(), jobId).run();
    throw new PolicyError(503, 'Capture workflow could not be queued. Retry from the import workspace.');
  }
  return { jobId };
}

export async function listCaptureJobs(db: D1Database) {
  return query<CaptureJob>(db, 'SELECT * FROM catalog_import_jobs ORDER BY created_at DESC,id LIMIT 30');
}
