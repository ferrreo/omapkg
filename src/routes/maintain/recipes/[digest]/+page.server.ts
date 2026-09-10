import { getRecipeCapture, type RecipeComparison } from '$lib/server/recipe-captures';
import { inputObject } from '$lib/server/input-objects';
import { environment, maintainer } from '$lib/server/http';
import { query, sha256 } from '$lib/server/db';
import { error } from '@sveltejs/kit';
import type { PageServerLoad } from './$types';

export const load: PageServerLoad = async (event) => {
  maintainer(event); const env = environment(event), detail = await getRecipeCapture(env, event.params.digest);
  const selectedPath = event.url.searchParams.get('file') ?? 'PKGBUILD';
  const selected = detail.manifest.files.find((file) => file.path === selectedPath);
  if (!selected) error(404, 'File is outside this recipe capture.');
  let preview: string | null = null;
  if (selected.object.size <= 256 * 1024) {
    const body = selected.object.size ? await env.ARTIFACTS.get((await inputObject(env.DB, selected.object.sha256)).object_key) : null;
    if (selected.object.size && (!body || body.size !== selected.object.size)) error(503, 'Retained recipe file is unavailable.');
    const bytes = body ? new Uint8Array(await body.arrayBuffer()) : new Uint8Array();
    if (bytes.length !== selected.object.size || await sha256(bytes) !== selected.object.sha256) error(409, 'Retained recipe file changed.');
    try { const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes); if (!text.includes('\0')) preview = text; } catch { /* Binary data is available as a download. */ }
  }
  const links = await query<{ import_id: string; source_id: string; reason: string; comparison_json: string; kind: string; channel: string }>(env.DB,
    `SELECT l.*,json_extract(i.manifest_json,'$.kind') AS kind,json_extract(i.manifest_json,'$.channel') AS channel
      FROM recipe_capture_links l JOIN catalog_imports i ON i.id=l.import_id WHERE l.capture_sha256=? ORDER BY l.created_at DESC LIMIT 50`, event.params.digest);
  return { ...detail, selected, preview, links: links.map((link) => ({ ...link, comparison: JSON.parse(link.comparison_json) as RecipeComparison })) };
};
