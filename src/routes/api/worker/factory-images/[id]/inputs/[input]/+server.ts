import { type RequestHandler } from '@sveltejs/kit';
import { factoryImageInputForWorker, type FactoryImageInputName } from '$lib/server/factory-image-run';
import { authenticateWorker, WorkerProtocolError, workerRouteFailure } from '$lib/server/workers';

const names = new Set<FactoryImageInputName>(['profile', 'candidate-lock', 'candidate-lock-signature', 'native-plan', 'native-plan-signature', 'trusted-authority-key', 'builder', 'context', 'dockerfile']);

export const GET: RequestHandler = async (event) => {
  try {
    const env = event.platform?.env;

    if (!env) throw new WorkerProtocolError(503, 'Worker protocol unavailable');
    const leaseTokens = event.url.searchParams.getAll('leaseToken');

    if (leaseTokens.length !== 1 || !event.params.id || !event.params.input || !names.has(event.params.input as FactoryImageInputName)) throw new WorkerProtocolError(400, 'Invalid private image input path');
    const auth = await authenticateWorker(env.DB, event.request, event.url.pathname + event.url.search, new Uint8Array());
    const input = await factoryImageInputForWorker(env, auth, event.params.id, leaseTokens[0], event.params.input as FactoryImageInputName);

    return new Response(event.request.method === 'HEAD' ? null : input.body, { headers: { 'Content-Type': 'application/octet-stream', 'Content-Length': String(input.ref.size), ETag: input.ref.sha256, 'Cache-Control': 'private, no-store', 'X-Content-Type-Options': 'nosniff' } });
  } catch (cause) { return workerRouteFailure(cause); }
};

export const HEAD = GET;
