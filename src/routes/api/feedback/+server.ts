import { json, type RequestHandler } from '@sveltejs/kit';
import { audit, id, now } from '$lib/server/db';
import { PolicyError } from '$lib/server/policy';
import { jsonBody, sameOrigin } from '$lib/server/http';

const RELEASE_ID = /^[A-Za-z0-9_-]{1,128}$/;
const MAX_BODY = 16 * 1024;

function parseInput(value: unknown): { releaseId: string; works: 0 | 1; comment: string } {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new PolicyError(400, 'Feedback must be a JSON object.');
  const row = value as Record<string, unknown>;
  const releaseId = typeof row.releaseId === 'string' ? row.releaseId : '';
  const works = row.works === 1 ? 1 : row.works === 0 ? 0 : null;
  const comment = typeof row.comment === 'string' ? row.comment.replace(/[\u0000\r\n]+/g, ' ').trim() : '';
  if (!RELEASE_ID.test(releaseId) || works === null || !comment || comment.length > 2_000) {
    throw new PolicyError(400, 'Release ID, result and comment are required.');
  }
  return { releaseId, works, comment };
}

function failure(cause: unknown): Response {
  if (cause instanceof PolicyError) return json({ error: cause.message }, { status: cause.status });
  console.error(cause instanceof Error ? cause.message : 'Feedback failed');
  return json({ error: 'Feedback could not be recorded.' }, { status: 500 });
}

export const POST: RequestHandler = async (event) => {
  if (!event.platform?.env?.DB) return json({ error: 'Feedback is unavailable.' }, { status: 503 });
  try {
    sameOrigin(event.request, event.platform.env.PUBLIC_ORIGIN);
    const actor = event.locals.actor;
    if (!actor) throw new PolicyError(401, 'Sign in with GitHub to record feedback.');
    const parsed = await jsonBody(event.request, MAX_BODY);
    const input = parseInput(parsed);
    const release = await event.platform.env.DB.prepare(`SELECT id,channel FROM releases
      WHERE id=? AND channel IN ('dev','stable','withdrawn')`).bind(input.releaseId).first<{ id: string; channel: string }>();
    if (!release) throw new PolicyError(404, 'Published release not found.');
    const timestamp = now();
    await event.platform.env.DB.batch([
      event.platform.env.DB.prepare(`INSERT INTO feedback(id,release_id,actor,works,comment,created_at)
        VALUES(?,?,?,?,?,?) ON CONFLICT(release_id,actor) DO UPDATE SET works=excluded.works,comment=excluded.comment,created_at=excluded.created_at`)
        .bind(id(), release.id, actor.id, input.works, input.comment, timestamp),
      audit(event.platform.env.DB, actor.id, 'feedback.recorded', release.id, { works: input.works, channel: release.channel }),
    ]);
    return json({ accepted: true, releaseId: release.id, works: input.works }, { status: 202, headers: { 'Cache-Control': 'no-store' } });
  } catch (cause) {
    return failure(cause);
  }
};
