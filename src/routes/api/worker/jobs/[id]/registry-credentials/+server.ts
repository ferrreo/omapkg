import { json } from '@sveltejs/kit';
import type { RequestHandler } from '@sveltejs/kit';
import {
  authenticateWorker,
  parseJsonRequest,
  readBody,
  requireJsonContentType,
  WorkerProtocolError,
  workerRouteFailure
} from '$lib/server/workers';
import { issueRegistryCredentials, MAX_REGISTRY_JSON_BODY_BYTES } from '$lib/server/worker-registry';

export const POST: RequestHandler = async (event) => {
  try {
    const env = event.platform?.env;
    if (!env) throw new WorkerProtocolError(500, 'Worker protocol unavailable');
    requireJsonContentType(event.request);
    const body = await readBody(event.request, MAX_REGISTRY_JSON_BODY_BYTES);
    const input = parseJsonRequest(body);
    const auth = await authenticateWorker(env.DB, event.request, event.url.pathname + event.url.search, body);
    if (!event.params.id) throw new WorkerProtocolError(400, 'Invalid job id');
    const credentials = await issueRegistryCredentials(env, auth.worker, event.params.id, input);
    return json(credentials, {
      headers: {
        'Cache-Control': 'no-store',
        Pragma: 'no-cache',
        'Referrer-Policy': 'no-referrer'
      }
    });
  } catch (cause) {
    return workerRouteFailure(cause);
  }
};
