import { error } from '@sveltejs/kit';
import { environment, maintainer } from '$lib/server/http';
import { sha256 } from '$lib/server/db';
import type { RequestHandler } from './$types';

export const GET: RequestHandler = async (event) => {
  maintainer(event);
  const digest = event.url.searchParams.get('digest') ?? '';
  if (!/^[a-f0-9]{64}$/.test(digest)) error(400, 'Select an exact changelog digest.');
  const row = await environment(event).DB.prepare('SELECT document_json,markdown FROM cohort_changelogs WHERE cohort_id=? AND digest=?')
    .bind(event.params.id, digest).first<{ document_json: string; markdown: string }>();
  if (!row || await sha256(row.document_json) !== digest) error(404, 'Verified changelog not found.');
  const markdown = event.url.searchParams.get('format') === 'markdown';
  return new Response(markdown ? row.markdown : row.document_json, { headers: {
    'Content-Type': markdown ? 'text/markdown; charset=utf-8' : 'application/json',
    'Content-Disposition': `attachment; filename="${markdown ? 'CHANGELOG.md' : 'changelog.json'}"`,
    'Cache-Control': 'private, no-store', 'X-Content-Type-Options': 'nosniff',
  } });
};
