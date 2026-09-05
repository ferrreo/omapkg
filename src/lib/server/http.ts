import { error, fail, type RequestEvent } from '@sveltejs/kit';
import { PolicyError } from './policy';
import { readBody, WorkerProtocolError } from './workers';
export function environment(event: Pick<RequestEvent, 'platform'>) {
  if (!event.platform?.env?.DB) error(503, 'Platform database is unavailable.');
  return event.platform.env;
}
export function maintainer(event: Pick<RequestEvent, 'locals'>) {
  const actor = event.locals.actor;
  if (!actor) error(401, 'Sign in with GitHub to continue.');
  if (actor.role === 'public') error(403, 'You need maintainer or security reviewer access.');
  return actor;
}
export async function formAction<T extends object | void>(event: RequestEvent, action: (form: FormData) => Promise<T>) {
  try {
    const result = await action(await event.request.formData());
    return { success: true, ...result };
  } catch (cause) {
    if (cause instanceof PolicyError) return fail(cause.status, { success: false, error: cause.message });
    throw cause;
  }
}
export const field = (form: FormData, name: string) => String(form.get(name) ?? '');

export async function jsonBody(request: Request, maxBytes = 16 * 1024): Promise<unknown> {
  if (request.headers.get('content-type')?.split(';', 1)[0].trim() !== 'application/json') {
    throw new PolicyError(415, 'Send JSON with Content-Type: application/json.');
  }
  try { return JSON.parse(new TextDecoder().decode(await readBody(request, maxBytes))); }
  catch (cause) {
    if (cause instanceof WorkerProtocolError) throw new PolicyError(cause.status, cause.message);
    if (cause instanceof SyntaxError) throw new PolicyError(400, 'Request contains invalid JSON.');
    throw cause;
  }
}

export function sameOrigin(request: Request, origin: string, allowMissing = false): void {
  const actual = request.headers.get('origin');
  if (actual !== origin && !(allowMissing && actual === null)) throw new PolicyError(403, 'Send this request from the application.');
}
