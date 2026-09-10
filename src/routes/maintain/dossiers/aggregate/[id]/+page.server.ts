import { error } from '@sveltejs/kit';
import { environment, maintainer } from '$lib/server/http';
import { storedFactoryAggregateDossier } from '$lib/server/factory-aggregate-dossier';
import { PolicyError } from '$lib/server/policy';
import type { PageServerLoad } from './$types';

export const load: PageServerLoad = async (event) => {
  maintainer(event);
  try {
    return { dossier: (await storedFactoryAggregateDossier(environment(event), event.params.id)).dossier };
  } catch (cause) {
    if (cause instanceof PolicyError) error(cause.status, cause.message);
    throw cause;
  }
};
