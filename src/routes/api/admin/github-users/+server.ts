import { json, type RequestHandler } from '@sveltejs/kit';
import { githubAccessTokenForActor } from '$lib/server/auth';
import { environment, jsonBody, maintainer } from '$lib/server/http';
import { PolicyError } from '$lib/server/policy';
import {
  githubIdentitySuggestions,
  normalizeGithubUsername,
  validateGithubUsername,
} from '$lib/server/identities';

const privateHeaders = { 'Cache-Control': 'private, no-store' };

function admin(event: Parameters<RequestHandler>[0]) {
  const actor = maintainer(event);
  if (actor.role !== 'admin') throw new PolicyError(403, 'You need administrator access.');
  const env = environment(event);
  return { DB: env.DB, env, actor };
}

async function validate(DB: D1Database, input: unknown, accessToken?: string) {
  const username = normalizeGithubUsername(input);
  const profile = await validateGithubUsername(username, accessToken);
  if (!profile) return json({ exists: false, username }, { status: 404, headers: privateHeaders });
  return json({ exists: true, ...profile }, { headers: privateHeaders });
}

export const GET: RequestHandler = async (event) => {
  try {
    const { DB, env, actor } = admin(event);
    if (event.url.searchParams.get('suggestions') === '1') {
      return json({ suggestions: await githubIdentitySuggestions(DB) }, { headers: privateHeaders });
    }
    return await validate(DB, event.url.searchParams.get('username') ?? '', await githubAccessTokenForActor(env, actor) ?? undefined);
  } catch (cause) {
    if (cause instanceof PolicyError) return json({ error: cause.message }, { status: cause.status, headers: privateHeaders });
    throw cause;
  }
};

export const POST: RequestHandler = async (event) => {
  try {
    const body = await jsonBody(event.request, 4 * 1024);
    const username = body && typeof body === 'object' && !Array.isArray(body) ? (body as Record<string, unknown>).username : undefined;
    const { DB, env, actor } = admin(event);
    return await validate(DB, username, await githubAccessTokenForActor(env, actor) ?? undefined);
  } catch (cause) {
    if (cause instanceof PolicyError) return json({ error: cause.message }, { status: cause.status, headers: privateHeaders });
    throw cause;
  }
};
