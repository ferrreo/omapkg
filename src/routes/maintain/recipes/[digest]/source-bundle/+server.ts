import { error } from '@sveltejs/kit';
import { environment, maintainer } from '$lib/server/http';
import { sha256 } from '$lib/server/db';
import type { RequestHandler } from './$types';

export const GET: RequestHandler = async (event) => {
  maintainer(event);

  const bundle = await environment(event).DB.prepare('SELECT sha256,manifest_json FROM recipe_source_bundles WHERE capture_sha256=? AND sha256=?')
    .bind(event.params.digest, event.url.searchParams.get('bundle') ?? '').first<{ sha256: string; manifest_json: string }>();

  if (!bundle) error(404, 'Retained source bundle not found.');

  if (await sha256(bundle.manifest_json) !== bundle.sha256) error(409, 'Retained source bundle checksum changed.');

  return new Response(bundle.manifest_json, { headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', 'Content-Disposition': 'attachment; filename="recipe-source-bundle.json"' } });
};
