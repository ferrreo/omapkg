import { json, type RequestHandler } from '@sveltejs/kit';
import { MAX_ABI_DOCUMENT } from '$lib/abi-inventory';
import { uploadAbiEvidence } from '$lib/server/build-abi-evidence';
import { authenticateWorker, readBody, WorkerProtocolError, workerRouteFailure } from '$lib/server/worker-protocol';

export const PUT: RequestHandler = async (event) => {
  try {
    const env = event.platform?.env;

    if (!env) throw new WorkerProtocolError(503, 'Worker evidence storage unavailable');
    const tokens = event.url.searchParams.getAll('leaseToken');

    if (tokens.length !== 1) throw new WorkerProtocolError(400, 'Missing lease token');
    const body = await readBody(event.request, MAX_ABI_DOCUMENT);
    const auth = await authenticateWorker(env.DB, event.request, event.url.pathname + event.url.search, body);

    return json(await uploadAbiEvidence(env, auth.worker, event.params.id!, tokens[0], event.params.digest!, body));
  } catch (cause) { return workerRouteFailure(cause); }
};
