import { expect, test } from 'bun:test';
import { handle } from '../src/hooks.server';
import type { Actor } from '../src/lib/model';
import {
  DeniedAuditError,
  correlationId,
  deniedAuditFailure,
  normalizedRoute,
  recordDeniedRequest,
  shouldAuditDenied,
} from '../src/lib/server/denied-audit';
import { TestD1, asD1 } from './d1';

const schema = 'CREATE TABLE audit_events(id INTEGER PRIMARY KEY AUTOINCREMENT,actor TEXT NOT NULL,action TEXT NOT NULL,target TEXT NOT NULL,detail TEXT NOT NULL,created_at INTEGER NOT NULL);';
const actor: Actor = { id: 'github:1', role: 'admin', areas: [] };

function event(db: TestD1, pathname: string, status: number, headers: Record<string, string> = {}) {
  const request = new Request(`https://opr.test${pathname}`, { headers });
  return {
    request,
    url: new URL(request.url),
    locals: { user: null, actor },
    platform: { env: { DB: asD1(db) } },
  } as any;
}

test('central hook audits protected denials with a redacted route and correlation ID', async () => {
  const db = new TestD1(schema);
  try {
    const response = await handle({
      event: event(db, '/api/admin/github-users?username=secret-token', 403, { 'x-correlation-id': 'corr-123' }),
      resolve: async () => new Response('denied', { status: 403 }),
    } as any);
    expect(response.status).toBe(403);
    expect(response.headers.get('X-Correlation-ID')).toBe('corr-123');
    const row = await db.prepare("SELECT actor,action,target,detail FROM audit_events WHERE action='http.denied'").first<{ actor: string; action: string; target: string; detail: string }>();
    expect(row?.actor).toBe('anonymous');
    expect(row?.target).toBe('/api/admin/github-users');
    expect(row?.detail).not.toContain('secret-token');
    expect(JSON.parse(row?.detail ?? '{}')).toEqual({
      correlationId: 'corr-123', method: 'GET', route: '/api/admin/github-users', status: 403, reason: 'forbidden',
    });
    await recordDeniedRequest(asD1(db), actor, new Request('https://opr.test/maintain/team'), 403, 'corr-actor');
    expect((await db.prepare("SELECT actor FROM audit_events WHERE action='http.denied' ORDER BY id DESC LIMIT 1").first<{ actor: string }>())?.actor).toBe(actor.id);
  } finally {
    db.close();
  }
});

test('OAuth and worker protocol denials are audited without request data', async () => {
  expect(shouldAuditDenied('/api/auth/callback/github', 401)).toBe(true);
  expect(shouldAuditDenied('/api/worker/jobs/build/complete', 409)).toBe(true);
  expect(shouldAuditDenied('/api/workers/enroll', 401)).toBe(true);
  expect(shouldAuditDenied('/maintain/team', 403)).toBe(true);
  expect(shouldAuditDenied('/api/admin/github-users', 403)).toBe(true);
  expect(shouldAuditDenied('/maintain/team', 200)).toBe(false);
  expect(normalizedRoute('/api/admin/123/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')).toBe('/api/admin/:id/:id');

  const db = new TestD1(schema);
  try {
    for (const [pathname, status] of [
      ['/api/auth/callback/github?code=oauth-secret', 400],
      ['/api/worker/jobs/123e4567-e89b-12d3-a456-426614174000/complete?token=worker-secret', 409],
    ] as const) {
      await handle({
        event: event(db, pathname, status),
        resolve: async () => new Response('denied', { status }),
      } as any);
    }
    const rows = (await db.prepare("SELECT actor,target,detail FROM audit_events WHERE action='http.denied' ORDER BY id").all<{ actor: string; target: string; detail: string }>()).results;
    expect(rows).toHaveLength(2);
    expect(rows[0]?.actor).toBe('anonymous');
    expect(rows[0]?.target).toBe('/api/auth/callback/github');
    expect(rows[1]?.target).toBe('/api/worker/jobs/:id/complete');
    expect(rows.map((row) => row.detail).join('\n')).not.toContain('secret');
  } finally {
    db.close();
  }
});

test('audit failure becomes safe 503 and does not expose request data', async () => {
  const request = new Request('https://opr.test/maintain/team?password=secret');
  const failing = { prepare: () => ({ bind: () => ({ run: async () => { throw new Error('database unavailable'); } }) }) } as unknown as D1Database;
  await expect(recordDeniedRequest(failing, actor, request, 403, correlationId(request))).rejects.toBeInstanceOf(DeniedAuditError);
  const response = deniedAuditFailure('corr-safe');
  expect(response.status).toBe(503);
  expect(response.headers.get('Retry-After')).toBe('1');
  expect(await response.text()).not.toContain('secret');
});

test('successful responses never create central denial events', async () => {
  const db = new TestD1(schema);
  try {
    const response = await handle({
      event: event(db, '/maintain/team', 200),
      resolve: async () => new Response('ok', { status: 200 }),
    } as any);
    expect(response.status).toBe(200);
    expect((await db.prepare("SELECT COUNT(*) AS count FROM audit_events WHERE action='http.denied'").first<{ count: number }>())?.count).toBe(0);
  } finally {
    db.close();
  }
});

test('public pages and layout data cannot cache signed-in user information', async () => {
  const db = new TestD1(schema);
  try {
    for (const path of ['/', '/packages/hello/__data.json']) {
      for (const signedIn of [false, true]) {
        const requestEvent = event(db, path, 200);
        const response = await handle({
          event: requestEvent,
          resolve: async () => {
            requestEvent.locals.user = signedIn ? { id: 'viewer', name: 'viewer' } : null;
            return Response.json({ user: requestEvent.locals.user }, { headers: { 'Cache-Control': 'public, max-age=60' } });
          },
        } as any);
        expect(response.headers.get('Cache-Control')).toBe(signedIn ? 'private, no-store' : 'public, max-age=60');
      }
    }
  } finally {
    db.close();
  }
});
