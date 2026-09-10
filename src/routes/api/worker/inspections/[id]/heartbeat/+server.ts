import { json } from '@sveltejs/kit';
import { authenticateWorker, parseJsonRequest, readBody, requireExactKeys, requireJsonContentType, WorkerProtocolError, workerRouteFailure } from '$lib/server/worker-protocol';
import { requireRecipeInspectionLease } from '$lib/server/recipe-inspections';
import type { RequestHandler } from './$types';

export const POST: RequestHandler = async (event) => {
  try {
    const env = event.platform?.env;

    if (!env) throw new WorkerProtocolError(503, 'Inspection storage is unavailable');
    requireJsonContentType(event.request);
    const body = await readBody(event.request, 1024), input = parseJsonRequest(body); requireExactKeys(input, ['leaseToken']);
    const auth = await authenticateWorker(env.DB, event.request, event.url.pathname + event.url.search, body);

    try { await requireRecipeInspectionLease(env.DB, auth.worker, event.params.id!, input.leaseToken); }
    catch (cause) { if (cause instanceof WorkerProtocolError && cause.status === 409) return json({ cancel: true }); throw cause; }

    return json({ cancel: false }, { headers: { 'Cache-Control': 'no-store' } });
  } catch (cause) { return workerRouteFailure(cause); }
};
