import { error } from '@sveltejs/kit';
import { environment, maintainer } from '$lib/server/http';
import { getRecipeCapture } from '$lib/server/recipe-captures';
import { inputObject } from '$lib/server/input-objects';
import type { RequestHandler } from './$types';

export const GET: RequestHandler = async (event) => {
  maintainer(event); const env = environment(event), detail = await getRecipeCapture(env, event.params.digest);
  const file = detail.manifest.files.find((file) => file.path === event.url.searchParams.get('path'));

  if (!file) error(404, 'File is outside this recipe capture.');
  const object = file.object.size ? await env.ARTIFACTS.get((await inputObject(env.DB, file.object.sha256)).object_key) : null;

  if (file.object.size && (!object || object.size !== file.object.size)) error(503, 'Retained recipe file is unavailable.');

  return new Response(object?.body ?? new Uint8Array(), { headers: { 'Content-Type': 'application/octet-stream', 'Content-Length': String(file.object.size),
    'Content-Disposition': `attachment; filename="recipe-file"; filename*=UTF-8''${encodeURIComponent(file.path.split('/').at(-1)!).replace(/['()*]/g, (value) => '%' + value.charCodeAt(0).toString(16))}`, 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' } });
};
