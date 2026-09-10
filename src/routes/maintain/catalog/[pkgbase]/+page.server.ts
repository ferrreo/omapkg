import { error, redirect } from '@sveltejs/kit';
import { approveCatalogPackage, catalogManifestFromForm, getCatalogPackage, proposeCatalogPackage } from '$lib/server/catalog-ownership';
import { query } from '$lib/server/db';
import { environment, field, formAction, maintainer } from '$lib/server/http';
import type { CatalogManifest } from '$lib/distribution';
import type { Actions, PageServerLoad } from './$types';

export const load: PageServerLoad = async (event) => {
  const actor = maintainer(event); const { DB } = environment(event);
  const record = await getCatalogPackage(DB, event.params.pkgbase);

  if (!record) error(404, 'Catalog package not found.');

  return { record, manifest: JSON.parse(record.manifest_json) as CatalogManifest, actor,
    reviews: await query<{ kind: string; actor: string; reason: string; created_at: number }>(DB, 'SELECT kind,actor,reason,created_at FROM catalog_reviews WHERE pkgbase=? AND revision=?', record.pkgbase, record.revision),
    history: await query<{ revision: number; reason: string; manifest_sha256: string; created_at: number }>(DB, 'SELECT revision,reason,manifest_sha256,created_at FROM catalog_revisions WHERE pkgbase=? ORDER BY revision DESC LIMIT 50', record.pkgbase),
  };
};

export const actions: Actions = {
  propose: (event) => formAction(event, async (form) => {
    const value = catalogManifestFromForm(form);

    if (value.pkgbase !== event.params.pkgbase) error(400, 'Package identity cannot change.');
    await proposeCatalogPackage(environment(event).DB, event.locals.actor, value, Number(field(form, 'expectedRevision')), field(form, 'reason'));
    redirect(303, `/maintain/catalog/${encodeURIComponent(value.pkgbase)}`);
  }),
  approve: (event) => formAction(event, async (form) => approveCatalogPackage(environment(event).DB, event.locals.actor, event.params.pkgbase,
    Number(field(form, 'revision')), field(form, 'digest'), field(form, 'kind'), field(form, 'reason'))),
};
