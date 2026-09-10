import { json } from '@sveltejs/kit';
import { environment, jsonBody, sameOrigin } from '$lib/server/http';
import { PolicyError } from '$lib/server/policy';
import { inputAuthority } from '$lib/server/input-objects';
import { retainRecipeCapture } from '$lib/server/recipe-captures';
import type { InputObject } from '$lib/frozen-inputs';
import type { RequestHandler } from './$types';

export const POST: RequestHandler = async (event) => {
  try {
    sameOrigin(event.request, event.url.origin); const env = environment(event); await inputAuthority(env.DB, event.locals.actor);
    const input = await jsonBody(event.request) as Record<string, unknown>;

    if (!input || typeof input !== 'object' || Object.keys(input).sort().join(',') !== 'capture,importId,reason,sourceId' ||
        typeof input.importId !== 'string' || typeof input.sourceId !== 'string' || typeof input.reason !== 'string') throw new PolicyError(400, 'Choose a recipe capture, captured inventory and reason.');

    return json(await retainRecipeCapture(env, event.locals.actor, input.capture as InputObject, input.importId, input.sourceId, input.reason), { headers: { 'Cache-Control': 'no-store' } });
  } catch (cause) {
    if (cause instanceof PolicyError) return json({ error: cause.message }, { status: cause.status, headers: { 'Cache-Control': 'no-store' } });
    throw cause;
  }
};
