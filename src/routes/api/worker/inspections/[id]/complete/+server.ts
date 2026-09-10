import { json } from '@sveltejs/kit';
import { authenticateWorker, parseJsonRequest, readBody, requireJsonContentType, WorkerProtocolError, workerRouteFailure } from '$lib/server/worker-protocol';
import { completeRecipeInspection } from '$lib/server/recipe-inspections';
import type { RequestHandler } from './$types';

export const POST: RequestHandler = async (event) => {
  try {
    const env = event.platform?.env;

    if (!env) throw new WorkerProtocolError(503, 'Inspection storage is unavailable');
    requireJsonContentType(event.request);
    const body = await readBody(event.request, 4 * 1024 * 1024), input = parseJsonRequest(body);
    const auth = await authenticateWorker(env.DB, event.request, event.url.pathname + event.url.search, body);

    return json(await completeRecipeInspection(env.DB, auth.worker, event.params.id!, input), { headers: { 'Cache-Control': 'no-store' } });
  } catch (cause) { return workerRouteFailure(cause); }
};
