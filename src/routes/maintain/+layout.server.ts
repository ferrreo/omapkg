import { maintainer } from '$lib/server/http';
import { environment } from '$lib/server/http';
import { githubActorNames } from '$lib/server/identities';
import type { LayoutServerLoad } from './$types';
export const load: LayoutServerLoad = async (event) => { maintainer(event); return { actorNames: await githubActorNames(environment(event).DB) }; };
