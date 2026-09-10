import { json, type RequestHandler } from '@sveltejs/kit';
import { completePrivateFactoryImage } from '$lib/server/factory-image-run';
import { authenticateWorker, MAX_JSON_BODY_BYTES, parseJsonRequest, readBody, requireJsonContentType, WorkerProtocolError, workerRouteFailure } from '$lib/server/workers';

export const POST: RequestHandler = async (event) => {
  try {
    const env = event.platform?.env;

    if (!env) throw new WorkerProtocolError(503, 'Worker protocol unavailable');
    requireJsonContentType(event.request);
    const body = await readBody(event.request, MAX_JSON_BODY_BYTES);
    const auth = await authenticateWorker(env.DB, event.request, event.url.pathname + event.url.search, body);

    if (!event.params.id) throw new WorkerProtocolError(400, 'Invalid private image job id');

    return json(await completePrivateFactoryImage(env, auth.worker, event.params.id, parseJsonRequest(body)), { headers: { 'Cache-Control': 'no-store' } });
  } catch (cause) { return workerRouteFailure(cause); }
};
