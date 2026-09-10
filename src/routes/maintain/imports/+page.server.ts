import { redirect } from '@sveltejs/kit';
import { listCatalogImports, parseImportManifest } from '$lib/server/catalog-imports';
import { listCaptureJobs, startCatalogCapture } from '$lib/server/catalog-capture';
import { environment, field, formAction, maintainer } from '$lib/server/http';
import type { Actions, PageServerLoad } from './$types';

export const load: PageServerLoad = async (event) => {
  const actor = maintainer(event); const env = environment(event);
  const [imports, jobs] = await Promise.all([listCatalogImports(env.DB), listCaptureJobs(env.DB)]);

  return { imports: imports.map((item) => ({ ...item, manifest: parseImportManifest(JSON.parse(item.manifest_json)) })), jobs,
    canManage: actor.role !== 'maintainer' || actor.areas.includes('system'), pipelineAvailable: Boolean(env.PIPELINE) };
};

export const actions: Actions = {
  capture: (event) => formAction(event, async (form) => {
    const { jobId } = await startCatalogCapture(environment(event), event.locals.actor, field(form, 'kind'), field(form, 'channel'), field(form, 'oprLayout'));
    redirect(303, `/maintain/imports?job=${jobId}`);
  }),
};
