import { error, redirect } from '@sveltejs/kit';
import { getCatalogImport, listCatalogImports, listImportEntries, parseImportManifest, reviewImportEntry } from '$lib/server/catalog-imports';
import { importBuildCoverage, reconcileCatalogImports, type ImportDifference } from '$lib/server/catalog-reconciliation';
import { recipeCaptureCoverage } from '$lib/server/recipe-captures';
import { environment, field, formAction, maintainer } from '$lib/server/http';
import { query, sha256 } from '$lib/server/db';
import type { ImportEntry } from '$lib/imports';
import type { Actions, PageServerLoad } from './$types';

export const load: PageServerLoad = async (event) => {
  const actor = maintainer(event); const { DB } = environment(event);
  const search = event.url.searchParams.get('q') ?? '';
  const disposition = event.url.searchParams.get('disposition') ?? '';
  const after = event.url.searchParams.get('after') ?? '';
  const reportId = event.url.searchParams.get('report') ?? '';
  const differenceKind = event.url.searchParams.get('difference') ?? '';
  const differenceAfter = event.url.searchParams.get('differenceAfter') ?? '';
  const [detail, entries, captures, coverage, comparisons, observedVersions, recipeCoverage] = await Promise.all([
    getCatalogImport(DB, event.params.id), listImportEntries(DB, event.params.id, { search, disposition, after }), listCatalogImports(DB), importBuildCoverage(DB, event.params.id),
    query<{ id: string; report_json: string; report_sha256: string; created_at: number }>(DB, "SELECT id,report_json,report_sha256,created_at FROM catalog_reconciliations WHERE candidate_import_id=? AND status='ready' ORDER BY created_at DESC,id LIMIT 20", event.params.id),
    query<{ version: string; target: string }>(DB, "SELECT json_extract(entry_json,'$.version') AS version,target_architecture AS target FROM catalog_import_entries WHERE import_id=? AND name='omarchy'", event.params.id),
    recipeCaptureCoverage(DB, event.params.id),
  ]);
  for (const comparison of comparisons) if (await sha256(comparison.report_json) !== comparison.report_sha256) error(409, 'Stored reconciliation integrity check failed.');
  const recipeLinks = await query<{ source_id: string; pkgbase: string; capture_sha256: string; matches: number; metadata_present: number; inspected: number }>(DB,
    `SELECT l.source_id,l.pkgbase,l.capture_sha256,json_extract(l.comparison_json,'$.matches') AS matches,
      json_extract(l.comparison_json,'$.metadataPresent') AS metadata_present,
      EXISTS(SELECT 1 FROM current_recipe_inspections i JOIN recipe_inspection_results r ON r.job_id=i.id AND r.attempt=i.attempt
        JOIN recipe_inspection_attempts a ON a.job_id=i.id AND a.attempt=i.attempt JOIN workers w ON w.id=a.worker_id AND w.public_key=a.public_key AND w.status='active'
        WHERE i.capture_sha256=l.capture_sha256 AND i.status='succeeded' AND r.error IS NULL AND r.metadata_json IS NOT NULL
        AND i.architecture=(SELECT target_architecture FROM catalog_import_entries WHERE import_id=l.import_id AND source_id=l.source_id AND pkgbase=l.pkgbase LIMIT 1)) AS inspected
      FROM recipe_capture_links l WHERE l.import_id=?
      AND EXISTS(SELECT 1 FROM json_each(?) scope WHERE json_extract(scope.value,'$.source')=l.source_id AND json_extract(scope.value,'$.pkgbase')=l.pkgbase)
      AND l.rowid=(SELECT latest.rowid FROM recipe_capture_links latest WHERE latest.import_id=l.import_id AND latest.source_id=l.source_id
        AND latest.pkgbase=l.pkgbase ORDER BY latest.created_at DESC,latest.rowid DESC LIMIT 1)`, event.params.id, JSON.stringify(entries.map((entry) => ({ source: entry.source_id, pkgbase: entry.pkgbase }))));
  const selected = comparisons.find((comparison) => comparison.id === reportId) ?? comparisons[0];
  const summary = selected ? JSON.parse(selected.report_json) as Awaited<ReturnType<typeof reconcileCatalogImports>>['report'] : null;
  const baseline = summary ? await getCatalogImport(DB, summary.baselineId) : null;
  const differences = selected ? await query<{ item_json: string }>(DB, `SELECT item_json FROM catalog_reconciliation_items WHERE report_id=?
    AND (?='' OR kind=?) AND package_key>? ORDER BY package_key LIMIT 50`, selected.id, differenceKind, differenceKind, differenceAfter) : [];
  return { ...detail, entries: entries.map((entry) => ({ ...entry, recipeCapture: recipeLinks.find((link) => link.source_id === entry.source_id && link.pkgbase === entry.pkgbase), metadata: JSON.parse(entry.entry_json) as ImportEntry })),
    captures: captures.filter((capture) => capture.id !== event.params.id && capture.status !== 'capturing').map((capture) => ({ ...capture, manifest: parseImportManifest(JSON.parse(capture.manifest_json)) })),
    coverage, recipeCoverage, comparisons: comparisons.map((comparison) => ({ id: comparison.id, summary: JSON.parse(comparison.report_json) as Awaited<ReturnType<typeof reconcileCatalogImports>>['report'] })),
    selectedReport: selected && summary ? { id: selected.id, summary } : null,
    uncomparedBaselineSources: baseline && summary ? baseline.manifest.sources.filter((source) => source.status === 'captured' && source.entries > 0 && !summary.scope.includes(source.collection)) : [],
    differences: differences.map((item) => JSON.parse(item.item_json) as ImportDifference), observedVersions,
    search, disposition, after, differenceKind, canManage: actor.role !== 'maintainer' || actor.areas.includes('system') };
};
export const actions: Actions = {
  reconcile: (event) => formAction(event, async (form) => {
    const { reportId } = await reconcileCatalogImports(environment(event).DB, event.locals.actor, event.params.id, field(form, 'baselineId'));
    redirect(303, `/maintain/imports/${event.params.id}?report=${reportId}`);
  }),
  review: (event) => formAction(event, async (form) => reviewImportEntry(environment(event).DB, event.locals.actor, event.params.id,
    field(form, 'sourceId'), field(form, 'name'), field(form, 'disposition'), field(form, 'reason'))),
};
