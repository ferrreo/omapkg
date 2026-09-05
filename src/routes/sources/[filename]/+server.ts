import { error, type RequestHandler } from '@sveltejs/kit';
import { environment } from '$lib/server/http';
import { now } from '$lib/server/db';
import { authenticateWorker, workerRouteFailure, WorkerProtocolError } from '$lib/server/workers';

export const GET: RequestHandler = async (event) => {
  const match = /^([a-f0-9]{64})\.tar$/.exec(event.params.filename ?? '');
  if (!match || event.url.search) error(404, 'Source archive not found.');
  const env = environment(event);
  const digest = match[1];
  const sourceURL = `${env.PUBLIC_ORIGIN}/sources/${digest}.tar`;
  const published = await env.DB.prepare(`SELECT 1 FROM releases p JOIN builds b ON b.id=p.build_id
    JOIN revisions r ON r.id=b.revision_id
    WHERE p.surface='binary' AND p.channel IN ('dev','stable','withdrawn')
    AND EXISTS(SELECT 1 FROM json_each(r.sources_json) s WHERE json_extract(s.value,'$.sha256')=? AND json_extract(s.value,'$.url')=?) LIMIT 1`)
    .bind(digest, sourceURL).first();
  if (!published) {
    try {
      const auth = await authenticateWorker(env.DB, event.request, event.url.pathname, new Uint8Array());
      const allowed = await env.DB.prepare(`SELECT 1 FROM builds b JOIN revisions r ON r.id=b.revision_id
        JOIN requests q ON q.id=r.request_id
        WHERE b.worker_id=? AND b.status='leased' AND b.lease_expires_at>? AND q.status IN ('queued','building')
        AND r.id=(SELECT latest.id FROM revisions latest WHERE latest.request_id=q.id ORDER BY latest.created_at DESC,latest.rowid DESC LIMIT 1)
        AND 2=(SELECT count(*) FROM approvals a WHERE a.revision_id=r.id AND a.manifest_sha256=r.manifest_sha256 AND a.revoked_at IS NULL)
        AND EXISTS(SELECT 1 FROM json_each(r.sources_json) s WHERE json_extract(s.value,'$.sha256')=? AND json_extract(s.value,'$.url')=?) LIMIT 1`)
        .bind(auth.worker.id, now(), digest, sourceURL).first();
      if (!allowed) throw new WorkerProtocolError(403, 'This source archive is not assigned to your active build.');
    } catch (cause) { workerRouteFailure(cause); }
  }
  const object = await env.ARTIFACTS.get(`sources/${digest}.tar`);
  if (!object) error(404, 'Source archive not found.');
  return new Response(event.request.method === 'HEAD' ? null : object.body, { headers: {
    'Content-Type': 'application/x-tar',
    'Content-Length': String(object.size),
    'Cache-Control': published ? 'public, max-age=31536000, immutable' : 'private, no-store',
    ETag: object.httpEtag
  } });
};
export const HEAD = GET;
