import { json } from '@sveltejs/kit';
import { environment, jsonBody, sameOrigin } from '$lib/server/http';
import { PolicyError } from '$lib/server/policy';
import { inputAuthority } from '$lib/server/input-objects';
import { retainRecipeSources } from '$lib/server/recipe-source-plans';
import type { InputObject } from '$lib/frozen-inputs';
import type { RequestHandler } from './$types';

export const POST: RequestHandler = async (event) => {
  try {
    sameOrigin(event.request, event.url.origin); const env = environment(event); await inputAuthority(env.DB, event.locals.actor);
    const input = await jsonBody(event.request) as Record<string, unknown>;
    if (!input || typeof input !== 'object' || Object.keys(input).sort().join(',') !== 'bundle,reason' || typeof input.reason !== 'string') throw new PolicyError(400, 'Choose a source bundle and preparation reason.');
    return json(await retainRecipeSources(env, event.locals.actor, event.params.digest, input.bundle as InputObject, input.reason), { headers: { 'Cache-Control': 'no-store' } });
  } catch (cause) {
    if (cause instanceof PolicyError) return json({ error: cause.message }, { status: cause.status, headers: { 'Cache-Control': 'no-store' } });
    throw cause;
  }
};
