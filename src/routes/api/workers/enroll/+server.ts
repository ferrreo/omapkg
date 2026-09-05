import { json } from '@sveltejs/kit';
import type { RequestHandler } from '@sveltejs/kit';
import {
  MAX_JSON_BODY_BYTES,
  enrollWorker,
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
    const result = await enrollWorker(env.DB, input);
    return json({ id: result.id });
  } catch (cause) {
    return workerRouteFailure(cause);
  }
};
