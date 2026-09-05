import { json } from '@sveltejs/kit';
import type { RequestHandler } from '@sveltejs/kit';
import {
  UPLOAD_PART_SIZE,
  uploadMultipartPart
} from '$lib/server/worker-uploads';
import {
  authenticateWorker,
  readBody,
  WorkerProtocolError,
  workerRouteFailure
} from '$lib/server/workers';

export const PUT: RequestHandler = async (event) => {
  try {
    const env = event.platform?.env;
    if (!env) throw new WorkerProtocolError(500, 'Worker protocol unavailable');
    const tokens = event.url.searchParams.getAll('leaseToken');
    if (tokens.length !== 1) throw new WorkerProtocolError(400, 'Missing lease token');
    const body = await readBody(event.request, UPLOAD_PART_SIZE);
    const auth = await authenticateWorker(env.DB, event.request, event.url.pathname + event.url.search, body);
    if (!event.params.id || !event.params.uploadId || !event.params.partNumber) throw new WorkerProtocolError(400, 'Invalid upload path');
    const partNumber = Number(event.params.partNumber);
    if (!Number.isSafeInteger(partNumber)) throw new WorkerProtocolError(400, 'Invalid upload part number');
    return json(await uploadMultipartPart(env.DB, env.ARTIFACTS, auth.worker, event.params.id, event.params.uploadId, partNumber, tokens[0], body));
  } catch (cause) {
    return workerRouteFailure(cause);
  }
};
