import { error, type RequestHandler } from '@sveltejs/kit';
import { environment, maintainer } from '$lib/server/http';
import type { Build } from '$lib/model';

export const GET: RequestHandler = async (event) => {
  maintainer(event);
  const { DB, ARTIFACTS } = environment(event);
  const build = await DB.prepare('SELECT artifact_key,artifact_filename FROM builds WHERE id=?')
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
