import { error } from '@sveltejs/kit';
import { listAuditEvents, parseAuditQuery } from '$lib/server/audit';
import { environment, maintainer } from '$lib/server/http';
import { PolicyError } from '$lib/server/policy';
import type { PageServerLoad } from './$types';
export const load: PageServerLoad = async (event) => {
  maintainer(event);
  try {
    const options = parseAuditQuery(event.url);
    const page = await listAuditEvents(environment(event).DB, options);
    return { ...page, query: options.q, requestId: options.requestId, before: options.before, from: options.from, to: options.to, range: options.range };
  } catch (cause) {
    if (cause instanceof PolicyError) error(cause.status, cause.message);
    throw cause;
  }
};
