import { environment } from '$lib/server/http';
import { repositoryStatus } from '$lib/server/repository-status';
import type { PageServerLoad } from './$types';

export const load: PageServerLoad = (event) => repositoryStatus(environment(event));
