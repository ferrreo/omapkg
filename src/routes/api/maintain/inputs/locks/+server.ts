import { json } from '@sveltejs/kit';
import { proposeInputLock } from '$lib/server/input-locks';
import { inputAuthority } from '$lib/server/input-objects';
import { environment, jsonBody, sameOrigin } from '$lib/server/http';
import { PolicyError } from '$lib/server/policy';
import type { InputObject } from '$lib/frozen-inputs';
import type { RequestHandler } from './$types';

export const POST: RequestHandler = async (event) => {
  try {
    sameOrigin(event.request, event.url.origin); const env = environment(event); await inputAuthority(env.DB, event.locals.actor);
    const input = await jsonBody(event.request) as Record<string, unknown>;

    if (!input || typeof input !== 'object' || Object.keys(input).sort().join(',') !== 'lock,reason,revisionId' ||
        typeof input.revisionId !== 'string' || typeof input.reason !== 'string') throw new PolicyError(400, 'Choose a recipe, capture reference and review reason.');
    const lock = await proposeInputLock(env, event.locals.actor, input.revisionId, input.lock as InputObject, input.reason);

    return json({ sha256: lock.sha256 }, { headers: { 'Cache-Control': 'no-store' } });
  } catch (cause) {
    if (cause instanceof PolicyError) return json({ error: cause.message }, { status: cause.status, headers: { 'Cache-Control': 'no-store' } });
    throw cause;
  }
};
