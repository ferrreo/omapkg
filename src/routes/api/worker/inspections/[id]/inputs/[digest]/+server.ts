import { authenticateWorker, parseJsonRequest, readBody, requireExactKeys, requireJsonContentType, WorkerProtocolError, workerRouteFailure } from '$lib/server/worker-protocol';
import { requireRecipeInspectionLease, recipeInspectionObject } from '$lib/server/recipe-inspections';
import type { RequestHandler } from './$types';

export const POST: RequestHandler = async (event) => {
  try {
    const env = event.platform?.env;
    if (!env) throw new WorkerProtocolError(503, 'Inspection storage is unavailable');
    requireJsonContentType(event.request);
    const body = await readBody(event.request, 1024), input = parseJsonRequest(body); requireExactKeys(input, ['leaseToken']);
    const auth = await authenticateWorker(env.DB, event.request, event.url.pathname + event.url.search, body);
    const job = await requireRecipeInspectionLease(env.DB, auth.worker, event.params.id!, input.leaseToken);
    const ref = await recipeInspectionObject(env.DB, job, event.params.digest!);
    const object = await env.ARTIFACTS.get(ref.object_key);
    if (!object || object.size !== ref.size) throw new WorkerProtocolError(503, 'Retained recipe object is unavailable');
    return new Response(object.body, { headers: { 'Content-Type': 'application/octet-stream', 'Content-Length': String(ref.size),
      'Content-Encoding': 'identity', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' } });
  } catch (cause) { return workerRouteFailure(cause); }
};
