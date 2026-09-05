import { json } from '@sveltejs/kit';
import type { RequestHandler } from '@sveltejs/kit';
import {
  MAX_JSON_BODY_BYTES,
  authenticateWorker,
  heartbeatJob,
  parseWorkerMetadata,
  parseJsonRequest,
  readBody,
  requireJsonContentType,
  WorkerProtocolError,
  workerRouteFailure
} from '$lib/server/workers';

export const POST: RequestHandler = async (event) => {
  try {
    const env = event.platform?.env;
    if (!env) throw new WorkerProtocolError(500, 'Worker protocol unavailable');
    requireJsonContentType(event.request);
    const body = await readBody(event.request, MAX_JSON_BODY_BYTES);
    const input = parseJsonRequest(body);
    if (Object.keys(input).some((key) => !['leaseToken', 'version', 'runtime', 'capabilities'].includes(key))) throw new WorkerProtocolError(400, 'Unexpected heartbeat field');
    const metadata = parseWorkerMetadata(input);
    const auth = await authenticateWorker(env.DB, event.request, event.url.pathname + event.url.search, body);
    if (!event.params.id) throw new WorkerProtocolError(400, 'Invalid job id');
    return json(await heartbeatJob(env.DB, auth.worker, event.params.id, input.leaseToken, metadata));
  } catch (cause) {
    return workerRouteFailure(cause);
  }
};
