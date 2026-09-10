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
import { preservedCatalog } from '../../../../../services/pipeline/preserved-revision';
import { importPreservedRecipe, resumePreservedImport, cancelPreservedImport } from '$lib/server/preserved-imports';
import type { Architecture } from '$lib/model';
import { PolicyError } from '$lib/server/policy';

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
  let importTargets: Architecture[] = [], importBlocked: string | null = null;
  try { importTargets = (await preservedCatalog(env.DB, detail.manifest.pkgbase)).policy.architectures; }
  catch (cause) { if (cause instanceof PolicyError) importBlocked = cause.message; else throw cause; }
  const recipeImports = await query<{ id: string; request_id: string; status: string; reason: string; pr_url: string | null; current: number }>(env.DB,
    `SELECT i.id,i.request_id,i.reason,q.status,r.pr_url,EXISTS(SELECT 1 FROM current_preserved_recipe_imports current WHERE current.id=i.id) AS current
      FROM preserved_recipe_imports i JOIN requests q ON q.id=i.request_id LEFT JOIN revisions r ON r.id=i.revision_id
      WHERE i.capture_sha256=? ORDER BY i.created_at DESC,i.id LIMIT 50`, event.params.digest);
  return { ...detail, selected, preview, canInspect, images: images.filter((image) => image.enabled === 1),
    inspections: inspected, attempts, links: mappings, sourceBundles, importTargets, importBlocked, recipeImports };
};

export const actions: Actions = {
  inspect: (event) => formAction(event, (form) => requestRecipeInspection(environment(event), event.locals.actor, event.params.digest, field(form, 'imageId'), field(form, 'reason'))),
  cancel: (event) => formAction(event, (form) => cancelRecipeInspection(environment(event).DB, event.locals.actor, event.params.digest, field(form, 'jobId'), field(form, 'reason'))),
  importRecipe: (event) => formAction(event, (form) => importPreservedRecipe(environment(event), event.locals.actor, event.params.digest,
    form.getAll('bundle').map(String), field(form, 'smokeCommands').split('\n').map((line) => line.trim()).filter(Boolean), field(form, 'reason'))),
  resumeImport: (event) => formAction(event, (form) => resumePreservedImport(environment(event), event.locals.actor, event.params.digest, field(form, 'importId'))),
  cancelImport: (event) => formAction(event, (form) => cancelPreservedImport(environment(event).DB, event.locals.actor, event.params.digest, field(form, 'importId'), field(form, 'reason'))),
};
