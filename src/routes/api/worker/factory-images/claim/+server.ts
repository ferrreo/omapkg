import { json, type RequestHandler } from '@sveltejs/kit';
import { claimPrivateFactoryImage } from '$lib/server/factory-image-run';
import { authenticateWorker, MAX_JSON_BODY_BYTES, parseJsonRequest, parseWorkerMetadata, readBody, requireJsonContentType, WorkerProtocolError, workerRouteFailure } from '$lib/server/workers';

export const POST: RequestHandler = async (event) => {
  try {
    const env = event.platform?.env;

    if (!env) throw new WorkerProtocolError(503, 'Worker protocol unavailable');
    requireJsonContentType(event.request);
    const body = await readBody(event.request, MAX_JSON_BODY_BYTES);
    const input = parseJsonRequest(body);

    if (Object.keys(input).some((key) => !['version', 'runtime', 'capabilities'].includes(key))) throw new WorkerProtocolError(400, 'Unexpected claim field');
    const metadata = parseWorkerMetadata(input);
    const auth = await authenticateWorker(env.DB, event.request, event.url.pathname + event.url.search, body);

    return json({ job: await claimPrivateFactoryImage(env.DB, auth.worker, metadata) }, { headers: { 'Cache-Control': 'no-store' } });
  } catch (cause) { return workerRouteFailure(cause); }
};
