import { now } from '../../src/lib/server/db';
import type { Env } from '../../src/lib/server/env';

export type PublicationPayload = { buildId: string };

type WorkflowBinding = {
  create(options: { id: string; params: PublicationPayload }): Promise<{ id: string }>;
  get(id: string): Promise<{ status(): Promise<{ status: string }>; restart(): Promise<unknown> }>;
};

type PublicationEnv = Env & {
  PUBLICATION?: WorkflowBinding;
  PIPELINE_TOKEN?: string;
};

const BUILD_ID = /^[A-Za-z0-9_-]{1,128}$/;

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

/** Enqueue a successful build; callers can retry safely after a dispatch failure. */
export async function enqueuePublication(envInput: Env, buildId: string): Promise<{ id: string; dispatched: boolean }> {
  const env = envInput as PublicationEnv;
  const payload = parsePayload({ buildId });
  const workflowId = `publish-${payload.buildId}`;
  await env.DB.prepare(`INSERT OR IGNORE INTO publication_jobs(build_id,status,attempts,next_attempt_at,created_at,updated_at)
    VALUES(?,'queued',0,?,?,?)`).bind(payload.buildId, now(), now(), now()).run();
  const current = await env.DB.prepare('SELECT status FROM publication_jobs WHERE build_id=?').bind(payload.buildId).first<{ status: string }>();
  if (current?.status === 'dispatched' || current?.status === 'completed') {
    return { id: workflowId, dispatched: false };
  }
  try {
    let instanceId = workflowId;
    if (env.PUBLICATION) {
      try {
        instanceId = (await env.PUBLICATION.create({ id: workflowId, params: payload })).id;
      } catch (cause) {
        const instance = await env.PUBLICATION.get(workflowId).catch(() => null);
        if (!instance) throw cause;
        const state = await instance.status();
        if (state.status === 'errored' || state.status === 'terminated') await instance.restart();
        else if (state.status === 'complete') {
          const release = await env.DB.prepare('SELECT id FROM releases WHERE build_id=?').bind(payload.buildId).first<{ id: string }>();
          if (release) {
            await mark(env, payload.buildId, 'completed');
            return { id: workflowId, dispatched: false };
          }
          throw cause;
        }
      }
    }
    else if (env.PIPELINE) {
      const headers = new Headers({ 'Content-Type': 'application/json' });
      if (env.PIPELINE_TOKEN) headers.set('Authorization', `Bearer ${env.PIPELINE_TOKEN}`);
      const response = await env.PIPELINE.fetch('https://pipeline.internal/publish', { method: 'POST', headers, body: JSON.stringify(payload) });
      if (!response.ok) throw new Error(`publication dispatch rejected (${response.status})`);
    } else throw new Error('publication workflow is not configured');
    await mark(env, payload.buildId, 'dispatched');
    return { id: instanceId, dispatched: true };
  } catch (cause) {
    await mark(env, payload.buildId, 'failed', cause instanceof Error ? cause.message : 'dispatch failed');
    throw cause;
  }
}
