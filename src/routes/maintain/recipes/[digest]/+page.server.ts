import { getRecipeCapture, recipeCapturedEntries, compareRecipeMetadata, type RecipeComparison } from '$lib/server/recipe-captures';
import { inputAuthority, inputObject } from '$lib/server/input-objects';
import { environment, field, formAction, maintainer } from '$lib/server/http';
import { requestRecipeInspection, cancelRecipeInspection, listRecipeInspections } from '$lib/server/recipe-inspections';
import { getBuildImages } from '$lib/server/build-images';
import { query, sha256 } from '$lib/server/db';
import { error } from '@sveltejs/kit';
import type { Actions, PageServerLoad } from './$types';
import type { Srcinfo } from '$lib/srcinfo';
import { recipeSources } from '$lib/recipe-sources';

export const load: PageServerLoad = async (event) => {
  const actor = maintainer(event), env = environment(event), detail = await getRecipeCapture(env, event.params.digest);
  let canInspect = false; try { await inputAuthority(env.DB, actor); canInspect = true; } catch { /* Other maintainers can inspect retained evidence. */ }
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
  const [inspections, images, attempts] = await Promise.all([listRecipeInspections(env.DB, event.params.digest), getBuildImages(env),
    query<{ job_id: string; attempt: number; error: string | null; created_at: number }>(env.DB,
      'SELECT r.job_id,r.attempt,r.error,r.created_at FROM recipe_inspection_results r JOIN recipe_inspections i ON i.id=r.job_id WHERE i.capture_sha256=? ORDER BY r.created_at DESC,r.attempt DESC LIMIT 100', event.params.digest)]);
  const inspected = inspections.map((inspection) => {
    const metadata = inspection.metadata_json ? JSON.parse(inspection.metadata_json) as Srcinfo : null;
    let sourceCount: number | null = null, sourceError: string | null = null;
    if (metadata && inspection.current) {
      try { sourceCount = recipeSources(detail.manifest, metadata, inspection.architecture).sources.length; }
      catch (cause) { sourceError = cause instanceof Error ? cause.message : 'Source plan requires recipe adaptation.'; }
    }
    return { ...inspection, metadata, sourceCount, sourceError };
  });
  const sourceBundles = await query<{ sha256: string; architecture: string; created_at: number; reason: string; sources: number; caches: number; keys: number; current: number }>(env.DB,
    `SELECT b.sha256,b.architecture,b.created_at,b.reason,json_array_length(b.manifest_json,'$.sources') AS sources,
      json_array_length(b.manifest_json,'$.caches') AS caches,json_array_length(b.manifest_json,'$.keys') AS keys,
      EXISTS(SELECT 1 FROM current_recipe_source_bundles current WHERE current.sha256=b.sha256) AS current
      FROM recipe_source_bundles b WHERE b.capture_sha256=? ORDER BY b.created_at DESC,b.sha256 LIMIT 50`, event.params.digest);
  const mappings = [];
  for (const link of links) {
    const entries = await recipeCapturedEntries(env.DB, link.import_id, link.source_id, detail.manifest.pkgbase);
    const inspection = inspected.find((inspection) => inspection.architecture === entries[0].target && inspection.current && inspection.metadata);
    mappings.push({ ...link, comparison: inspection ? compareRecipeMetadata(inspection.metadata, entries) : JSON.parse(link.comparison_json) as RecipeComparison,
      inspected: Boolean(inspection), target: entries[0].target });
  }
  return { ...detail, selected, preview, canInspect, images: images.filter((image) => image.enabled === 1),
    inspections: inspected, attempts, links: mappings, sourceBundles };
};

export const actions: Actions = {
  inspect: (event) => formAction(event, (form) => requestRecipeInspection(environment(event), event.locals.actor, event.params.digest, field(form, 'imageId'), field(form, 'reason'))),
  cancel: (event) => formAction(event, (form) => cancelRecipeInspection(environment(event).DB, event.locals.actor, event.params.digest, field(form, 'jobId'), field(form, 'reason'))),
};
