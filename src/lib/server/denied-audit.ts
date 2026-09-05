import type { Actor } from '../model';
import { audit } from './db';

const CORRELATION = /^[A-Za-z0-9._:-]{1,128}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const DIGEST = /^[a-f0-9]{64}$/i;
const DENIED_REASONS: Record<number, string> = {
  400: 'bad_request',
  401: 'unauthorized',
  403: 'forbidden',
  404: 'not_found',
  405: 'method_not_allowed',
  409: 'conflict',
  410: 'gone',
  411: 'length_required',
  412: 'precondition_failed',
  413: 'payload_too_large',
  415: 'unsupported_media_type',
  422: 'unprocessable_entity',
  429: 'rate_limited',
};

export class DeniedAuditError extends Error {
  constructor() {
    super('Denied action could not be recorded.');
    this.name = 'DeniedAuditError';
  }
}

function routeSegment(value: string): string {
  if (UUID.test(value) || DIGEST.test(value) || /^\d+$/.test(value)) return ':id';
  return value;
}

export function normalizedRoute(pathname: string): string {
  const path = pathname.replace(/\/+/g, '/');
  const parts = path.split('/').filter(Boolean).map(routeSegment);
  const result = `/${parts.join('/')}`.replace(/\/$/, '') || '/';
  return result.slice(0, 512);
}

export function correlationId(request: Request): string {
  const value = request.headers.get('x-correlation-id') ?? request.headers.get('x-request-id') ?? '';
  return CORRELATION.test(value) ? value : crypto.randomUUID();
}

export function deniedReason(status: number): string {
  return DENIED_REASONS[status] ?? `http_${status}`;
}

export function shouldAuditDenied(pathname: string, status: number): boolean {
  if (status < 400 || status >= 500) return false;
  return pathname === '/request' || pathname.startsWith('/request/') ||
    pathname === '/maintain' || pathname.startsWith('/maintain/') ||
    pathname === '/api/auth' || pathname.startsWith('/api/auth/') ||
    pathname === '/api/worker' || pathname.startsWith('/api/worker/') ||
    pathname === '/api/workers' || pathname.startsWith('/api/workers/') ||
    pathname === '/api/admin' || pathname.startsWith('/api/admin/') ||
    pathname === '/api/internal' || pathname.startsWith('/api/internal/') ||
    pathname === '/api/feedback' || pathname.startsWith('/api/feedback/') ||
    pathname === '/api/mcp' || pathname.startsWith('/api/mcp/');
}

export async function recordDeniedRequest(
  db: D1Database,
  actor: Actor | null,
  request: Request,
  status: number,
  correlation: string,
): Promise<void> {
  const route = normalizedRoute(new URL(request.url).pathname);
  const detail = {
    correlationId: correlation,
    method: request.method.toUpperCase().slice(0, 16),
    route,
    status,
    reason: deniedReason(status),
  };
  try {
    await audit(db, actor?.id ?? 'anonymous', 'http.denied', route, detail).run();
  } catch (cause) {
    console.error(cause instanceof Error ? cause.message : 'Denied request audit failed');
    throw new DeniedAuditError();
  }
}

export function deniedAuditFailure(correlation: string): Response {
  return new Response(JSON.stringify({ error: 'Request could not be recorded. Retry.', correlationId: correlation }), {
    status: 503,
    headers: {
      'Cache-Control': 'no-store',
      'Content-Type': 'application/json; charset=utf-8',
      'Retry-After': '1',
      'X-Correlation-ID': correlation,
    },
  });
}
