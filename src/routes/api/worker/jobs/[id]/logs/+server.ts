import { json } from '@sveltejs/kit';
import type { RequestHandler } from '@sveltejs/kit';
import {
  MAX_JSON_BODY_BYTES,
  appendJobLog,
  authenticateWorker,
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
    const allowed = new Set(['leaseToken', 'sequence', 'text']);
    if (Object.keys(input).some((key) => !allowed.has(key))) throw new WorkerProtocolError(400, 'Unexpected log field');
    const auth = await authenticateWorker(env.DB, event.request, event.url.pathname + event.url.search, body);
    if (!event.params.id) throw new WorkerProtocolError(400, 'Invalid job id');
    return json(await appendJobLog(env.DB, auth.worker, event.params.id, input));
  } catch (cause) {
    return workerRouteFailure(cause);
  }
};
