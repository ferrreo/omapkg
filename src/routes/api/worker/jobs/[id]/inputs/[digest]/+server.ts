import { authenticateWorker, parseJsonRequest, readBody, requireExactKeys, requireJsonContentType, requireWorkerLease,
  WorkerProtocolError, workerRouteFailure } from '$lib/server/worker-protocol';
import { INPUT_HASH } from '$lib/frozen-inputs';
import { parsePreservedBuildInputs } from '$lib/preserved-recipe';
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
    const preserved = build.preserved_inputs_json ? parsePreservedBuildInputs(JSON.parse(build.preserved_inputs_json)) : null;
    const ref = await env.DB.prepare(`SELECT o.object_key,o.size FROM input_objects o WHERE o.sha256=? AND (
      EXISTS(SELECT 1 FROM input_lock_objects i WHERE i.lock_sha256=? AND i.object_sha256=o.sha256) OR
      EXISTS(SELECT 1 FROM recipe_captures c WHERE c.sha256=? AND (c.sha256=o.sha256 OR
        EXISTS(SELECT 1 FROM json_tree(c.manifest_json) ref WHERE ref.key='sha256' AND ref.value=o.sha256))) OR
      EXISTS(SELECT 1 FROM recipe_source_bundles b WHERE b.sha256=? AND (b.sha256=o.sha256 OR
        EXISTS(SELECT 1 FROM json_tree(b.manifest_json) ref WHERE ref.key='sha256' AND ref.value=o.sha256))))`)
      .bind(event.params.digest, build.input_lock_sha256, preserved?.capture.sha256 ?? null, preserved?.sourceBundle.sha256 ?? null)
      .first<{ object_key: string; size: number }>();
    if (!ref) throw new WorkerProtocolError(403, 'Object is outside the leased build inputs');
    const object = await env.ARTIFACTS.get(ref.object_key);
    if (!object || object.size !== ref.size) throw new WorkerProtocolError(503, 'Retained input object is unavailable');
    return new Response(object.body, { headers: { 'Content-Type': 'application/octet-stream', 'Content-Length': String(ref.size),
      'Content-Encoding': 'identity', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer' } });
  } catch (cause) { return workerRouteFailure(cause); }
};
