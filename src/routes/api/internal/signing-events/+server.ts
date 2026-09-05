import { json, type RequestHandler } from '@sveltejs/kit';
import {
  authorizeControlRequest,
  completeSigningIntent,
  parseSigningEvent,
  SigningControlError,
  type SigningControlEnv,
} from '$lib/server/signing-control';

const MAX_BODY_BYTES = 32 * 1024;

function failure(cause: unknown): Response {
  if (cause instanceof SigningControlError) {
    return json({ error: cause.message }, { status: cause.status, headers: { 'Cache-Control': 'no-store' } });
  }
  console.error(cause instanceof Error ? cause.message : 'Signing event failed');
  return json({ error: 'Signing control failed.' }, { status: 500, headers: { 'Cache-Control': 'no-store' } });
}

export const POST: RequestHandler = async ({ platform, request }) => {
  const env = platform?.env as unknown as SigningControlEnv | undefined;
  if (!env?.DB || !env.ARTIFACTS) return json({ error: 'Signing control is unavailable.' }, { status: 503, headers: { 'Cache-Control': 'no-store' } });
  try {
    await authorizeControlRequest(request, env);
    const contentLength = Number(request.headers.get('content-length') ?? 0);
    if (contentLength > MAX_BODY_BYTES) throw new SigningControlError(413, 'Signing event is too large.');
    const body = await request.arrayBuffer();
    if (body.byteLength > MAX_BODY_BYTES) throw new SigningControlError(413, 'Signing event is too large.');
    let input: unknown;
    try { input = JSON.parse(new TextDecoder().decode(body)); }
    catch { throw new SigningControlError(400, 'Signing event must contain valid JSON.'); }
    const result = await completeSigningIntent(env, parseSigningEvent(input));
    return json({ ok: true, ...result }, { headers: { 'Cache-Control': 'no-store' } });
  } catch (cause) {
    return failure(cause);
  }
};
