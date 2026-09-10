import { json } from '@sveltejs/kit';
import { environment, jsonBody, sameOrigin } from '$lib/server/http';
import { completeInputUpload, inputAuthority, inputObject, startInputUpload, writeInputPart } from '$lib/server/input-objects';
import { humanMaintainer } from '$lib/server/catalog-ownership';
import { PolicyError } from '$lib/server/policy';
import { readBody, WorkerProtocolError } from '$lib/server/worker-protocol';
import { UPLOAD_PART_SIZE } from '$lib/server/worker-uploads';
import type { RequestHandler } from './$types';

const headers = { 'Cache-Control': 'no-store' };

const handle: RequestHandler = async (event) => {
  try {
    sameOrigin(event.request, event.url.origin);
    const env = environment(event); await inputAuthority(env.DB, event.locals.actor);

    if (event.request.method === 'PUT') return json(await writeInputPart(env, event.locals.actor, event.params.digest!,
      event.url.searchParams.get('uploadId') ?? '', Number(event.url.searchParams.get('part')), await readBody(event.request, UPLOAD_PART_SIZE)), { headers });
    const input = await jsonBody(event.request) as Record<string, unknown>;

    if (!input || typeof input !== 'object' || Array.isArray(input)) throw new PolicyError(400, 'Choose an input upload operation.');

    if (input.operation === 'start' && Object.keys(input).sort().join(',') === 'operation,size') {
      return json(await startInputUpload(env, event.locals.actor, { sha256: event.params.digest!, size: input.size as number }), { headers });
    }

    if (input.operation === 'complete' && Object.keys(input).sort().join(',') === 'operation,uploadId' && typeof input.uploadId === 'string') {
      return json(await completeInputUpload(env, event.locals.actor, event.params.digest!, input.uploadId), { headers });
    }

    throw new PolicyError(400, 'Invalid input upload operation.');
  } catch (cause) {
    if (cause instanceof PolicyError || cause instanceof WorkerProtocolError) return json({ error: cause.message }, { status: cause.status, headers });
    throw cause;
  }
};

export const POST = handle;

export const PUT = handle;

export const GET: RequestHandler = async (event) => {
  try {
    humanMaintainer(event.locals.actor); const env = environment(event); const ref = await inputObject(env.DB, event.params.digest!);
    const filename = event.url.searchParams.get('filename') ?? ref.sha256;

    if (!/^[A-Za-z0-9][A-Za-z0-9._+@%~:-]{0,254}$/.test(filename)) throw new PolicyError(400, 'Invalid download filename.');
    const object = await env.ARTIFACTS.get(ref.object_key);

    if (!object || object.size !== ref.size) throw new PolicyError(503, 'Retained input object is unavailable.');

    return new Response(object.body, { headers: { ...headers, 'Content-Type': 'application/octet-stream', 'Content-Length': String(ref.size),
      'Content-Disposition': `attachment; filename="${filename}"`, 'X-Content-Type-Options': 'nosniff' } });
  } catch (cause) {
    if (cause instanceof PolicyError) return json({ error: cause.message }, { status: cause.status, headers });
    throw cause;
  }
};
