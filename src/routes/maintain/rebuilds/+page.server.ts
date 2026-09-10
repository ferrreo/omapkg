import { redirect } from '@sveltejs/kit';
import { listCohorts } from '$lib/server/cohorts';
import { createRebuildCohortDraft, previewRebuildCohort, rebuildCoverage } from '$lib/server/rebuild-cohort';
import { environment, field, formAction, maintainer } from '$lib/server/http';
import { PolicyError } from '$lib/server/policy';
import type { Actions, PageServerLoad } from './$types';

function report(form: FormData) {
  const value = field(form, 'report');
  if (new TextEncoder().encode(value).byteLength > 8 * 1024 * 1024) throw new PolicyError(413, 'Rebuild report exceeds 8 MiB.');
  try { return JSON.parse(value); } catch { throw new PolicyError(400, 'Rebuild report contains invalid JSON.'); }
}

export const load: PageServerLoad = async (event) => {
  maintainer(event); const DB = environment(event).DB;
  const [allCohorts, coverage] = await Promise.all([listCohorts(DB, {}), rebuildCoverage(DB)]);
  return { cohorts: allCohorts.filter((cohort) => !['publish', 'observe'].includes(cohort.phase)), coverage };
};

export const actions: Actions = {
  preview: (event) => { maintainer(event); return formAction(event, async (form) => ({ preview: await previewRebuildCohort(environment(event).DB, field(form, 'cohortId'), report(form)) })); },
  create: (event) => { maintainer(event); return formAction(event, async (form) => {
    const result = await createRebuildCohortDraft(environment(event).DB, event.locals.actor, field(form, 'cohortId'), report(form), field(form, 'reason'));
    redirect(303, `/maintain/cohorts/${encodeURIComponent(result.cohortId)}`);
  }); },
};
