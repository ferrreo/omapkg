import { redirect } from '@sveltejs/kit';
import { cohortPhases } from '$lib/distribution';
import { getCatalogPackage, listCatalogPackages } from '$lib/server/catalog-ownership';
import { listCohorts, proposeCohort } from '$lib/server/cohorts';
import { id } from '$lib/server/db';
import { environment, field, formAction, maintainer } from '$lib/server/http';
import { PolicyError } from '$lib/server/policy';
import type { Actions, PageServerLoad } from './$types';

export const load: PageServerLoad = async (event) => {
  maintainer(event); const { DB } = environment(event); const search = event.url.searchParams;
  return {
    cohorts: await listCohorts(DB, { search: search.get('q') ?? '', lane: search.get('lane') ?? '', phase: search.get('phase') ?? '', after: search.get('after') ?? '' }),
    packages: await listCatalogPackages(DB, { search: search.get('package') ?? '', limit: 25 }),
    cohortId: id(), phases: cohortPhases, selectedPackage: search.get('package') ?? '',
    filters: { q: search.get('q') ?? '', lane: search.get('lane') ?? '', phase: search.get('phase') ?? '' },
  };
};
export const actions: Actions = {
  create: (event) => formAction(event, async (form) => {
    const { DB } = environment(event); const pkgbase = field(form, 'pkgbase');
    const catalog = await getCatalogPackage(DB, pkgbase);
    if (!catalog || catalog.revision !== Number(field(form, 'catalogRevision'))) throw new PolicyError(409, 'Catalog selection changed. Refresh and select its current policy.');
    const lane = field(form, 'lane');
    const cohort = await proposeCohort(DB, event.locals.actor, field(form, 'cohortId'), null, {
      title: field(form, 'title'), lane, systemVersion: lane === 'system' ? field(form, 'systemVersion') : null,
      parentSnapshot: null, compatibleSystems: [],
      members: [{ pkgbase, catalogRevision: catalog.revision, recipeRevisionId: null, cause: field(form, 'cause'), reason: field(form, 'reason') }],
    }, field(form, 'reason'));
    redirect(303, `/maintain/cohorts/${encodeURIComponent(cohort.id)}`);
  }),
};
