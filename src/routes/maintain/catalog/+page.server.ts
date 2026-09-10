import { redirect } from '@sveltejs/kit';
import { catalogManifestFromForm, listCatalogPackages, proposeCatalogPackage } from '$lib/server/catalog-ownership';
import { environment, field, formAction, maintainer } from '$lib/server/http';
import type { Actions, PageServerLoad } from './$types';

export const load: PageServerLoad = async (event) => {
  maintainer(event);
  const search = event.url.searchParams.get('q') ?? '';
  const collection = event.url.searchParams.get('collection') ?? '';
  const after = event.url.searchParams.get('after') ?? '';
  const packages = await listCatalogPackages(environment(event).DB, { search, collection, after });

  return { packages, search, collection, after };
};

export const actions: Actions = {
  propose: (event) => formAction(event, async (form) => {
    const result = await proposeCatalogPackage(environment(event).DB, event.locals.actor, catalogManifestFromForm(form), null, field(form, 'reason'));
    redirect(303, `/maintain/catalog/${encodeURIComponent(result.pkgbase)}`);
  }),
};
