import { json, type RequestHandler } from '@sveltejs/kit';
import { completeFactoryImageUpload } from '$lib/server/factory-image-run';
import { authenticateWorker, MAX_JSON_BODY_BYTES, parseJsonRequest, readBody, requireJsonContentType, WorkerProtocolError, workerRouteFailure } from '$lib/server/workers';

export const POST: RequestHandler = async (event) => {
  try {
    const env = event.platform?.env;

    if (!env) throw new WorkerProtocolError(503, 'Worker protocol unavailable');
    requireJsonContentType(event.request);
    const body = await readBody(event.request, MAX_JSON_BODY_BYTES);
    const input = parseJsonRequest(body);
    const leaseToken = input.leaseToken;

    if (!event.params.id || !event.params.uploadId || typeof leaseToken !== 'string') throw new WorkerProtocolError(400, 'Invalid private image upload completion');
    const auth = await authenticateWorker(env.DB, event.request, event.url.pathname + event.url.search, body);

    return json(await completeFactoryImageUpload(env, auth.worker, event.params.id, event.params.uploadId, leaseToken));
  } catch (cause) { return workerRouteFailure(cause); }
};
