import { error, type RequestHandler } from '@sveltejs/kit';
import { environment, maintainer } from '$lib/server/http';
import type { Build } from '$lib/model';

export const GET: RequestHandler = async (event) => {
  maintainer(event);
  const { DB, ARTIFACTS } = environment(event);
  const signature = event.url.searchParams.get('signature') === '1';
  const filename = event.url.searchParams.get('filename');
  const build = signature || filename === 'attestation.json'
    ? await DB.prepare(`SELECT CASE WHEN ? THEN i.signature_key ELSE i.object_key END AS artifact_key,
        i.artifact_filename||CASE WHEN ? THEN '.sig' ELSE '' END AS artifact_filename FROM builds b
        JOIN signing_intents i ON i.build_id=b.id AND i.build_attempt=b.attempt AND i.status='signed'
        WHERE b.id=? AND i.artifact_filename=? ORDER BY i.created_at DESC LIMIT 1`).bind(signature ? 1 : 0, signature ? 1 : 0, event.params.id, filename).first<Pick<Build, 'artifact_key' | 'artifact_filename'>>()
    : event.url.searchParams.has('filename')
    ? await DB.prepare(`SELECT a.artifact_key,a.filename AS artifact_filename FROM builds b JOIN build_artifacts a ON a.build_id=b.id AND a.attempt=b.attempt
        WHERE b.id=? AND a.filename=?`).bind(event.params.id, event.url.searchParams.get('filename')).first<Pick<Build, 'artifact_key' | 'artifact_filename'>>()
    : await DB.prepare('SELECT artifact_key,artifact_filename FROM builds WHERE id=?')
    .bind(event.params.id).first<Pick<Build, 'artifact_key' | 'artifact_filename'>>();
  if (!build?.artifact_key || !build.artifact_filename) error(404, 'Artifact not found.');
  const object = await ARTIFACTS.get(build.artifact_key);
  if (!object) error(404, 'Artifact not found.');
  return new Response(event.request.method === 'HEAD' ? null : object.body, { headers: {
    'Content-Type': 'application/octet-stream',
    'Content-Disposition': `attachment; filename="${encodeURIComponent(build.artifact_filename)}"; filename*=UTF-8''${encodeURIComponent(build.artifact_filename)}`,
    'Content-Length': String(object.size),
    'Cache-Control': 'private, no-store',
    ETag: object.httpEtag
  } });
};
export const HEAD = GET;
