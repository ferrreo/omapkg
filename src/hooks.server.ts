import type { Handle, HandleServerError } from '@sveltejs/kit';
import { actorFor, authReady, createAuth } from '$lib/server/auth';
import { correlationId, deniedAuditFailure, recordDeniedRequest, shouldAuditDenied } from '$lib/server/denied-audit';

export const handle: Handle = async ({ event, resolve }) => {
  const requestCorrelationId = correlationId(event.request);
  event.locals.user = null;
  event.locals.actor = null;
  const env = event.platform?.env;
  event.locals.authReady = Boolean(env && authReady(env));
  if (env && event.locals.authReady && !event.url.pathname.startsWith('/api/worker')) {
    const session = await createAuth(env).api.getSession({ headers: event.request.headers });
    if (session) {
      event.locals.user = session.user;
      event.locals.actor = await actorFor(env, session.user.id);
    }
  }
  const response = await resolve(event);
  if (shouldAuditDenied(event.url.pathname, response.status)) {
    if (!env?.DB) return deniedAuditFailure(requestCorrelationId);
    try {
      await recordDeniedRequest(env.DB, event.locals.actor, event.request, response.status, requestCorrelationId);
    } catch {
      return deniedAuditFailure(requestCorrelationId);
    }
  }
  response.headers.set('X-Correlation-ID', requestCorrelationId);
  response.headers.set('X-Content-Type-Options', 'nosniff');
  response.headers.set('Referrer-Policy', 'strict-origin-when-cross-origin');
  response.headers.set('X-Frame-Options', 'DENY');
  if (event.locals.user || event.url.pathname.startsWith('/maintain') || event.url.pathname.startsWith('/api/admin')) response.headers.set('Cache-Control', 'private, no-store');
  return response;
};
export const handleError: HandleServerError = ({ error }) => {
  console.error(error instanceof Error ? error.message : 'Unexpected request failure');
  return { message: 'Request failed. Please retry or contact a maintainer.' };
};
