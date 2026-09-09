import { redirect } from '@sveltejs/kit';
import { getCatalogImport, listCatalogImports, listImportEntries, parseImportManifest, reviewImportEntry } from '$lib/server/catalog-imports';
import { importBuildCoverage, reconcileCatalogImports, type ImportDifference } from '$lib/server/catalog-reconciliation';
import { environment, field, formAction, maintainer } from '$lib/server/http';
import { query } from '$lib/server/db';
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
  const [detail, entries, captures, coverage, comparisons, observedVersions] = await Promise.all([
    getCatalogImport(DB, event.params.id), listImportEntries(DB, event.params.id, { search, disposition, after }), listCatalogImports(DB), importBuildCoverage(DB, event.params.id),
    query<{ id: string; report_json: string; created_at: number }>(DB, "SELECT id,report_json,created_at FROM catalog_reconciliations WHERE candidate_import_id=? AND status='ready' ORDER BY created_at DESC,id LIMIT 20", event.params.id),
    query<{ version: string; target: string }>(DB, "SELECT json_extract(entry_json,'$.version') AS version,target_architecture AS target FROM catalog_import_entries WHERE import_id=? AND name='omarchy'", event.params.id),
  ]);
  const selected = comparisons.find((comparison) => comparison.id === reportId) ?? comparisons[0];
  const differences = selected ? await query<{ item_json: string }>(DB, `SELECT item_json FROM catalog_reconciliation_items WHERE report_id=?
    AND (?='' OR kind=?) AND package_key>? ORDER BY package_key LIMIT 50`, selected.id, differenceKind, differenceKind, differenceAfter) : [];
  return { ...detail, entries: entries.map((entry) => ({ ...entry, metadata: JSON.parse(entry.entry_json) as ImportEntry })),
    captures: captures.filter((capture) => capture.id !== event.params.id && capture.status !== 'capturing').map((capture) => ({ ...capture, manifest: parseImportManifest(JSON.parse(capture.manifest_json)) })),
    coverage, comparisons: comparisons.map((comparison) => ({ id: comparison.id, summary: JSON.parse(comparison.report_json) as Awaited<ReturnType<typeof reconcileCatalogImports>>['report'] })),
    selectedReport: selected ? { id: selected.id, summary: JSON.parse(selected.report_json) as Awaited<ReturnType<typeof reconcileCatalogImports>>['report'] } : null,
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
