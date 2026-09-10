import { error, type RequestHandler } from '@sveltejs/kit';
import { SHA256 } from '$lib/server/release-storage';

export const GET: RequestHandler = async ({ platform, params }) => {
  if (!platform?.env?.DB || !platform.env.ARTIFACTS) error(503, 'Repository is unavailable.');
  const kind = params.kind === 'chunks' ? 'package-chunk' : params.kind === 'changelogs' ? 'changelog' : null;
  const digest = params.digest?.replace(/\.json$/, '') ?? '';
  if (!kind || !SHA256.test(digest)) error(404, 'Distribution object not found.');
  const row = await platform.env.DB.prepare(`SELECT o.object_key FROM distribution_release_objects o
    JOIN distribution_release_candidates c ON c.id=o.candidate_id
    WHERE o.kind=? AND o.digest=? AND c.status IN ('signed','active') ORDER BY c.sequence DESC LIMIT 1`).bind(kind, digest).first<{ object_key: string }>();
  if (!row) error(404, 'Distribution object not found.');
  const object = await platform.env.ARTIFACTS.get(row.object_key);
  if (!object) error(404, 'Distribution object not found.');
  return new Response(object.body, { headers: { 'Content-Type': kind === 'changelog' ? 'application/json' : 'application/json', 'Cache-Control': 'public, max-age=31536000, immutable' } });
};

export const HEAD = GET;
