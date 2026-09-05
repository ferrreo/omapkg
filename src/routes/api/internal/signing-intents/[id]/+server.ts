import { json, type RequestHandler } from '@sveltejs/kit';
import {
  authorizeControlRequest,
  claimSigningIntent,
  SigningControlError,
  type SigningControlEnv,
} from '$lib/server/signing-control';

function failure(cause: unknown): Response {
  if (cause instanceof SigningControlError) {
    return json({ error: cause.message }, { status: cause.status, headers: { 'Cache-Control': 'no-store' } });
  }
  console.error(cause instanceof Error ? cause.message : 'Signing intent claim failed');
  return json({ error: 'Signing control failed.' }, { status: 500, headers: { 'Cache-Control': 'no-store' } });
}

export const GET: RequestHandler = async ({ platform, params, request }) => {
  const env = platform?.env as unknown as SigningControlEnv | undefined;
  if (!env?.DB || !env.ARTIFACTS) return json({ error: 'Signing control is unavailable.' }, { status: 503, headers: { 'Cache-Control': 'no-store' } });
  try {
    await authorizeControlRequest(request, env);
    return json(await claimSigningIntent(env, params.id ?? ''), {
      headers: { 'Cache-Control': 'no-store', Vary: 'Authorization' },
    });
  } catch (cause) {
    return failure(cause);
  }
};
