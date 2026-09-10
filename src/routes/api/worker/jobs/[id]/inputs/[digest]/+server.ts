import { authenticateWorker, parseJsonRequest, readBody, requireExactKeys, requireJsonContentType, requireWorkerLease,
  WorkerProtocolError, workerRouteFailure } from '$lib/server/worker-protocol';
import { INPUT_HASH } from '$lib/frozen-inputs';
import type { RequestHandler } from './$types';

export const POST: RequestHandler = async (event) => {
  try {
    const env = event.platform?.env;
    if (!env) throw new WorkerProtocolError(503, 'Input storage is unavailable');
    requireJsonContentType(event.request);
    const body = await readBody(event.request, 1024); const input = parseJsonRequest(body);
    requireExactKeys(input, ['leaseToken']);
    const auth = await authenticateWorker(env.DB, event.request, event.url.pathname + event.url.search, body);
    const build = await requireWorkerLease(env.DB, auth.worker, event.params.id!, input.leaseToken as string);
    if (!build.input_lock_sha256 || !INPUT_HASH.test(event.params.digest!)) throw new WorkerProtocolError(409, 'Build has no frozen input grant');
    const ref = await env.DB.prepare(`SELECT o.object_key,o.size FROM input_lock_objects i JOIN input_objects o ON o.sha256=i.object_sha256
      WHERE i.lock_sha256=? AND i.object_sha256=?`).bind(build.input_lock_sha256, event.params.digest).first<{ object_key: string; size: number }>();
    if (!ref) throw new WorkerProtocolError(403, 'Object is outside the leased input lock');
    const object = await env.ARTIFACTS.get(ref.object_key);
    if (!object || object.size !== ref.size) throw new WorkerProtocolError(503, 'Retained input object is unavailable');
    return new Response(object.body, { headers: { 'Content-Type': 'application/octet-stream', 'Content-Length': String(ref.size),
      'Content-Encoding': 'identity', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer' } });
  } catch (cause) { return workerRouteFailure(cause); }
};
