import { error, json, type RequestHandler } from '@sveltejs/kit';
import { qualificationPlanForWorker, recordNativeQualification } from '$lib/server/native-qualification';
import { MAX_JSON_BODY_BYTES, authenticateWorker, parseJsonRequest, readBody, requireJsonContentType, WorkerProtocolError, workerRouteFailure } from '$lib/server/worker-protocol';
import { PolicyError } from '$lib/server/policy';

function failure(cause: unknown): never {
  if (cause instanceof PolicyError) throw error(cause.status, cause.message);
  return workerRouteFailure(cause);
}

export const POST: RequestHandler = async (event) => {
  try {
    const env = event.platform?.env;
    if (!env) throw new WorkerProtocolError(503, 'Worker qualification storage unavailable');
    requireJsonContentType(event.request);
    const body = await readBody(event.request, MAX_JSON_BODY_BYTES);
    const auth = await authenticateWorker(env.DB, event.request, event.url.pathname + event.url.search, body);
    return json(await recordNativeQualification(env, auth, parseJsonRequest(body)));
  } catch (cause) { return failure(cause); }
};

export const GET: RequestHandler = async (event) => {
  try {
    const env = event.platform?.env;
    if (!env) throw new WorkerProtocolError(503, 'Worker qualification storage unavailable');
    const body = new Uint8Array();
    const auth = await authenticateWorker(env.DB, event.request, event.url.pathname + event.url.search, body);
    const planId = event.url.searchParams.get('planId');
    if (!planId) throw new WorkerProtocolError(400, 'Missing qualification plan');
    return json(await qualificationPlanForWorker(env, auth, planId));
  } catch (cause) { return failure(cause); }
};
