import { json } from '@sveltejs/kit';
import type { RequestHandler } from '@sveltejs/kit';
import {
  MAX_DIRECT_ARTIFACT_BYTES,
  authenticateWorker,
  readBody,
  uploadArtifact,
  WorkerProtocolError,
  workerRouteFailure
} from '$lib/server/workers';

export const PUT: RequestHandler = async (event) => {
  try {
    const env = event.platform?.env;
    if (!env) throw new WorkerProtocolError(500, 'Worker protocol unavailable');
    const tokens = event.url.searchParams.getAll('leaseToken');
    if (tokens.length !== 1) throw new WorkerProtocolError(400, 'Missing lease token');
    const body = await readBody(event.request, MAX_DIRECT_ARTIFACT_BYTES);
    const auth = await authenticateWorker(env.DB, event.request, event.url.pathname + event.url.search, body);
    if (!event.params.id || !event.params.filename) throw new WorkerProtocolError(400, 'Invalid artifact path');
    const reference = await uploadArtifact(env.DB, env.ARTIFACTS, auth.worker, event.params.id, tokens[0], event.params.filename, body);
    return json(reference);
  } catch (cause) {
    return workerRouteFailure(cause);
  }
};
