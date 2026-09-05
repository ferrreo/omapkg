import { json } from '@sveltejs/kit';
import type { RequestHandler } from '@sveltejs/kit';
import { MAX_UPLOAD_JSON_BYTES, completeMultipartUpload } from '$lib/server/worker-uploads';
import {
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
    const body = await readBody(event.request, MAX_UPLOAD_JSON_BYTES);
    const input = parseJsonRequest(body);
    const auth = await authenticateWorker(env.DB, event.request, event.url.pathname + event.url.search, body);
    if (!event.params.id || !event.params.uploadId) throw new WorkerProtocolError(400, 'Invalid upload path');
    return json(await completeMultipartUpload(env.DB, env.ARTIFACTS, auth.worker, event.params.id, event.params.uploadId, input));
  } catch (cause) {
    return workerRouteFailure(cause);
  }
};
