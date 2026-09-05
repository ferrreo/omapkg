import { json } from '@sveltejs/kit';
import type { RequestHandler } from '@sveltejs/kit';
import { abortMultipartUpload } from '$lib/server/worker-uploads';
import {
  authenticateWorker,
  readBody,
  WorkerProtocolError,
  workerRouteFailure
} from '$lib/server/workers';

export const DELETE: RequestHandler = async (event) => {
  try {
    const env = event.platform?.env;
    if (!env) throw new WorkerProtocolError(500, 'Worker protocol unavailable');
    const tokens = event.url.searchParams.getAll('leaseToken');
    if (tokens.length !== 1) throw new WorkerProtocolError(400, 'Missing lease token');
    const body = await readBody(event.request, 0);
    const auth = await authenticateWorker(env.DB, event.request, event.url.pathname + event.url.search, body);
    if (!event.params.id || !event.params.uploadId) throw new WorkerProtocolError(400, 'Invalid upload path');
    return json(await abortMultipartUpload(env.DB, env.ARTIFACTS, auth.worker, event.params.id, event.params.uploadId, { leaseToken: tokens[0] }));
  } catch (cause) {
    return workerRouteFailure(cause);
  }
};
