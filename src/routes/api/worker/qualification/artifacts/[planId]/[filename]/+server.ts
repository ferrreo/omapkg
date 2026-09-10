import { error, type RequestHandler } from '@sveltejs/kit';
import { qualificationArtifactForWorker } from '$lib/server/native-qualification';
import { authenticateWorker, workerRouteFailure, WorkerProtocolError } from '$lib/server/worker-protocol';
import { PolicyError } from '$lib/server/policy';

function failure(cause: unknown): never { if (cause instanceof PolicyError) throw error(cause.status, cause.message); return workerRouteFailure(cause); }

export const GET: RequestHandler = async (event) => {
  try {
    const env = event.platform?.env;
    if (!env) throw new WorkerProtocolError(503, 'Worker qualification storage unavailable');
    const body = new Uint8Array();
    const auth = await authenticateWorker(env.DB, event.request, event.url.pathname + event.url.search, body);
    if (!event.params.planId || !event.params.filename) throw new WorkerProtocolError(400, 'Invalid qualification artifact path');
    const artifact = await qualificationArtifactForWorker(env, auth, event.params.planId, event.params.filename);
    return new Response(event.request.method === 'HEAD' ? null : artifact.body, { headers: {
      'Content-Type': 'application/octet-stream', 'Content-Disposition': `attachment; filename="${encodeURIComponent(artifact.filename)}"`,
      'Content-Length': String(artifact.size), 'Cache-Control': 'private, no-store', 'X-Content-Type-Options': 'nosniff', ETag: artifact.sha256,
    } });
  } catch (cause) { return failure(cause); }
};
export const HEAD = GET;
