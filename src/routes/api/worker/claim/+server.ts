import { json } from '@sveltejs/kit';
import type { RequestHandler } from '@sveltejs/kit';
import {
  MAX_JSON_BODY_BYTES,
  authenticateWorker,
  claimJob,
  parseWorkerMetadata,
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
    if (Object.keys(input).some((key) => !['version', 'runtime', 'capabilities'].includes(key))) throw new WorkerProtocolError(400, 'Unexpected claim field');
    const metadata = parseWorkerMetadata(input);
    const auth = await authenticateWorker(env.DB, event.request, event.url.pathname + event.url.search, body);
    return json({ job: await claimJob(env.DB, auth.worker, metadata, {
      ARTIFACTS: env.ARTIFACTS,
      PUBLIC_ORIGIN: env.PUBLIC_ORIGIN,
      PACKAGE_SIGNING_FINGERPRINT: env.PACKAGE_SIGNING_FINGERPRINT,
      SIGNING_FINGERPRINT: env.SIGNING_FINGERPRINT,
    }) });
  } catch (cause) {
    return workerRouteFailure(cause);
  }
};
