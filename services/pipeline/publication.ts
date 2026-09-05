import { publishBuild } from '../../src/lib/server/releases';
import { audit, now } from '../../src/lib/server/db';
import type { Actor } from '../../src/lib/model';
import type { Env } from '../../src/lib/server/env';
import { WorkflowEntrypoint, type WorkflowEvent, type WorkflowStep } from 'cloudflare:workers';
import { enqueuePublication } from './publication-dispatch';
import type { PublicationPayload } from './publication-dispatch';

type WorkflowBinding = {
  create(options: { id: string; params: PublicationPayload }): Promise<{ id: string }>;
};

type PublicationEnv = Env & {
  PUBLICATION?: WorkflowBinding;
  PUBLICATION_TOKEN?: string;
  PIPELINE_TOKEN?: string;
};

const SYSTEM_ACTOR: Actor = { id: 'workflow:publication', role: 'admin', areas: [] };
const BUILD_ID = /^[A-Za-z0-9_-]{1,128}$/;
const MAX_BODY = 8 * 1024;

function parsePayload(input: unknown): PublicationPayload {
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw new Error('publication payload must be an object');
  const buildId = (input as Record<string, unknown>).buildId;
  if (typeof buildId !== 'string' || !BUILD_ID.test(buildId)) throw new Error('buildId is required');
  return { buildId };
}

async function mark(env: PublicationEnv, buildId: string, status: 'dispatched' | 'completed' | 'failed', error?: string) {
  await env.DB.prepare(`INSERT INTO publication_jobs(build_id,status,attempts,next_attempt_at,last_error,created_at,updated_at)
    VALUES(?,?,1,?,?,?,?)
    ON CONFLICT(build_id) DO UPDATE SET
      status=CASE WHEN publication_jobs.status='completed' AND excluded.status<>'completed' THEN publication_jobs.status ELSE excluded.status END,
      attempts=CASE WHEN publication_jobs.status='completed' AND excluded.status<>'completed' THEN publication_jobs.attempts ELSE publication_jobs.attempts+1 END,
      next_attempt_at=CASE WHEN publication_jobs.status='completed' AND excluded.status<>'completed' THEN publication_jobs.next_attempt_at ELSE excluded.next_attempt_at END,
      last_error=CASE WHEN publication_jobs.status='completed' AND excluded.status<>'completed' THEN publication_jobs.last_error ELSE excluded.last_error END,
      updated_at=excluded.updated_at`)
    .bind(buildId, status, status === 'failed' ? now() + 60 : now(), error?.slice(0, 1_000) ?? null, now(), now()).run();
}

export async function requeuePublications(envInput: Env, limit = 20): Promise<number> {
  const env = envInput as PublicationEnv;
  const rows = await env.DB.prepare(`SELECT build_id FROM publication_jobs
    WHERE status IN ('queued','failed') AND next_attempt_at<=? ORDER BY next_attempt_at,build_id LIMIT ?`).bind(now(), Math.min(Math.max(limit, 1), 100)).all<{ build_id: string }>();
  let dispatched = 0;
  for (const row of rows.results) {
    try { await enqueuePublication(env, row.build_id); dispatched += 1; } catch { /* next cron run retries with backoff */ }
  }
  return dispatched;
}

export async function publicationEndpoint(request: Request, envInput: Env): Promise<Response> {
  const env = envInput as PublicationEnv;
  if (request.method !== 'POST') return new Response('Method Not Allowed', { status: 405, headers: { Allow: 'POST' } });
  if (env.PUBLICATION_TOKEN && request.headers.get('Authorization') !== `Bearer ${env.PUBLICATION_TOKEN}`) return Response.json({ error: 'Unauthorized' }, { status: 401 });
  const length = Number(request.headers.get('content-length') ?? 0);
  if (length > MAX_BODY) return Response.json({ error: 'Request too large' }, { status: 413 });
  let payload: PublicationPayload;
  try { payload = parsePayload(await request.json()); }
  catch (cause) { return Response.json({ error: cause instanceof Error ? cause.message : 'Invalid JSON' }, { status: 400 }); }
  if (!env.PUBLICATION) return Response.json({ error: 'Publication workflow is not configured' }, { status: 503 });
  try {
    const queued = await enqueuePublication(env, payload.buildId);
    return Response.json({ workflowId: queued.id, buildId: payload.buildId, dispatched: queued.dispatched }, { status: 202 });
  } catch {
    return Response.json({ error: 'Publication workflow could not be queued' }, { status: 503 });
  }
}

/** Cloudflare Workflow entrypoint. Keep publication in one retryable step. */
export class PublicationWorkflow extends WorkflowEntrypoint<PublicationEnv, PublicationPayload> {
  async run(event: Readonly<WorkflowEvent<PublicationPayload>>, step: WorkflowStep) {
    const input = parsePayload(event.payload);
    try {
      return await step.do('publish-build', { retries: { limit: 3, delay: '30 seconds', backoff: 'exponential' }, timeout: '15 minutes' }, async () => {
        const release = await publishBuild(this.env, SYSTEM_ACTOR, input.buildId);
        await mark(this.env, input.buildId, 'completed');
        await this.env.DB.batch([audit(this.env.DB, SYSTEM_ACTOR.id, 'publication.completed', input.buildId, { releaseId: release.id })]);
        return { releaseId: release.id, channel: release.channel };
      });
    } catch (cause) {
      await mark(this.env, input.buildId, 'failed', cause instanceof Error ? cause.message : 'publication failed');
      throw cause;
    }
  }
}

export { SYSTEM_ACTOR };
export { enqueuePublication };
export type { PublicationPayload };
