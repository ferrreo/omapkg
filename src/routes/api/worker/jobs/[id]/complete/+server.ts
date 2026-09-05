import { json } from '@sveltejs/kit';
import type { RequestHandler } from '@sveltejs/kit';
import { enqueuePublication } from '../../../../../../../services/pipeline/publication-dispatch';
import {
  MAX_JSON_BODY_BYTES,
  authenticateWorker,
  completeJob,
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
    const auth = await authenticateWorker(env.DB, event.request, event.url.pathname + event.url.search, body);
    if (!event.params.id) throw new WorkerProtocolError(400, 'Invalid job id');
    const completion = await completeJob(env.DB, env.ARTIFACTS, auth.worker, event.params.id, input);
    if (completion.status === 'succeeded') {
      try {
        await enqueuePublication(env, event.params.id);
      } catch {
        // The build remains succeeded; publication outbox retry handles transient dispatch failures.
        throw new WorkerProtocolError(503, 'Publication dispatch unavailable');
      }
    }
    return json(completion);
  } catch (cause) {
    return workerRouteFailure(cause);
  }
};
