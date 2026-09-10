import { error } from '@sveltejs/kit';
import { environment, maintainer } from '$lib/server/http';
import { storedFactoryDossier } from '$lib/server/factory-dossier';
import { PolicyError } from '$lib/server/policy';
import type { PageServerLoad } from './$types';

export const load: PageServerLoad = async (event) => {
  maintainer(event);

  try {
    const env = environment(event);
    const stored = await storedFactoryDossier(env, event.params.id ?? '');
    const run = await env.DB.prepare('SELECT id FROM factory_runs WHERE id=?').bind(stored.dossier.identity.runId).first<{ id: string }>();

    return { dossier: stored.dossier, canonicalSha256: stored.canonicalSha256, markdownSha256: stored.markdownSha256, runUrl: run ? `/maintain/factory-runs/${encodeURIComponent(run.id)}` : '' };
  } catch (cause) {
    if (cause instanceof PolicyError) error(cause.status, cause.message);
    throw cause;
  }
};
