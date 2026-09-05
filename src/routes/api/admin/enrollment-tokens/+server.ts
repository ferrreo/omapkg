import { error, json } from '@sveltejs/kit';
import { environment } from '$lib/server/http';
import { requireSecurity, PolicyError } from '$lib/server/policy';
import { createEnrollmentToken, WorkerProtocolError } from '$lib/server/workers';
import type { RequestHandler } from './$types';
export const POST: RequestHandler = async (event) => {
  const env = environment(event);
  if (event.request.headers.get('origin') !== env.PUBLIC_ORIGIN) error(403, 'Same-origin request required.');
  try {
    const actor = requireSecurity(event.locals.actor);
    const body = await event.request.json() as { architecture: 'x86_64' | 'aarch64' };
    return json(await createEnrollmentToken(env.DB, actor.id, body.architecture));
  } catch (cause) {
    if (cause instanceof PolicyError || cause instanceof WorkerProtocolError) error(cause.status, cause.message);
    if (cause instanceof SyntaxError) error(400, 'Invalid JSON.');
    throw cause;
  }
};
