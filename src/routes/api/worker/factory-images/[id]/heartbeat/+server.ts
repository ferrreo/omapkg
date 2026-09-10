import { json, type RequestHandler } from '@sveltejs/kit';
import { heartbeatPrivateFactoryImage } from '$lib/server/factory-image-run';
import { authenticateWorker, MAX_JSON_BODY_BYTES, parseJsonRequest, parseWorkerMetadata, readBody, requireJsonContentType, WorkerProtocolError, workerRouteFailure } from '$lib/server/workers';

export const POST: RequestHandler = async (event) => {
  try {
    const env = event.platform?.env;

    if (!env) throw new WorkerProtocolError(503, 'Worker protocol unavailable');
    requireJsonContentType(event.request);
    const body = await readBody(event.request, MAX_JSON_BODY_BYTES);
    const input = parseJsonRequest(body);

    if (Object.keys(input).some((key) => !['leaseToken', 'version', 'runtime', 'capabilities'].includes(key))) throw new WorkerProtocolError(400, 'Unexpected heartbeat field');
    const leaseToken = input.leaseToken;
    const metadata = parseWorkerMetadata(Object.fromEntries(Object.entries(input).filter(([key]) => key !== 'leaseToken')));
    const auth = await authenticateWorker(env.DB, event.request, event.url.pathname + event.url.search, body);

    if (!event.params.id || typeof leaseToken !== 'string') throw new WorkerProtocolError(400, 'Invalid private image heartbeat');

    return json(await heartbeatPrivateFactoryImage(env.DB, auth.worker, event.params.id, leaseToken, metadata), { headers: { 'Cache-Control': 'no-store' } });
  } catch (cause) { return workerRouteFailure(cause); }
};
