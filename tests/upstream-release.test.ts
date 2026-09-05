import { describe, expect, mock, test } from 'bun:test';
import { dispatchUpstreamFactory, inspectArchiveRelease, recordUpstreamRelease, parseGitTags, trackedUpstreamRequests } from '../services/pipeline/release';
import type { FactoryWorkflowBinding } from '../services/pipeline/types';
import { gitInspectCommand } from '../services/pipeline/security';
import type { Sandbox } from '@flue/runtime';
import { asD1, TestD1 } from './d1';

const schema = `
CREATE TABLE requests(
  id TEXT PRIMARY KEY,name TEXT NOT NULL,upstream_url TEXT NOT NULL,source_kind TEXT NOT NULL,
  area TEXT NOT NULL,declared_license TEXT NOT NULL,upstream_ref TEXT,requested_by TEXT NOT NULL,
  status TEXT NOT NULL,created_at INTEGER NOT NULL,updated_at INTEGER NOT NULL
);
CREATE UNIQUE INDEX requests_active_name ON requests(name) WHERE status NOT IN ('built','rejected','failed');
CREATE TABLE revisions(id TEXT PRIMARY KEY,request_id TEXT NOT NULL,version TEXT NOT NULL,upstream_commit TEXT,created_at INTEGER NOT NULL);
CREATE TABLE builds(id TEXT PRIMARY KEY,revision_id TEXT NOT NULL,status TEXT NOT NULL);
CREATE TABLE releases(id TEXT PRIMARY KEY,build_id TEXT NOT NULL,channel TEXT NOT NULL);
CREATE TABLE upstream_checks(request_id TEXT PRIMARY KEY,last_version TEXT,last_checked_at INTEGER,error TEXT);
CREATE TABLE audit_events(id INTEGER PRIMARY KEY AUTOINCREMENT,actor TEXT,action TEXT,target TEXT,detail TEXT,created_at INTEGER);
`;

describe('upstream release tracking', () => {
  test('uses peeled commit for annotated tags', () => {
    const objectCommit = 'a'.repeat(40);
    const releaseCommit = 'b'.repeat(40);
    const olderCommit = 'c'.repeat(40);
    expect(parseGitTags([
      `${objectCommit} refs/tags/v2.12^{}`,
      `${releaseCommit} refs/tags/v2.12.3^{}`,
      `${olderCommit} refs/tags/v2.12.3`,
    ].join('\n'))).toEqual({ version: 'v2.12.3', commit: releaseCommit });
  });

  test('tracks only requests with a published build and preserves its ref', async () => {
    const db = new TestD1(schema);
    try {
      db.prepare(`INSERT INTO requests VALUES(?,?,?,?,?,?,?,?,?,?,?)`).bind(
        'request-pending', 'pending', 'https://example.test/pending.git', 'git', 'system', 'unknown', null, 'system', 'pending', 1, 1,
      ).run();
      db.prepare(`INSERT INTO requests VALUES(?,?,?,?,?,?,?,?,?,?,?)`).bind(
        'request-published', 'published', 'https://example.test/published.git', 'git', 'system', 'unknown', null, 'system', 'review', 2, 2,
      ).run();
      db.prepare('INSERT INTO revisions VALUES(?,?,?,?,?)').bind('revision-old', 'request-published', '1.0.0', 'd'.repeat(40), 3).run();
      db.prepare('INSERT INTO revisions VALUES(?,?,?,?,?)').bind('revision-new', 'request-published', '2.0.0', 'e'.repeat(40), 4).run();
      db.prepare('INSERT INTO builds VALUES(?,?,?)').bind('build-old', 'revision-old', 'succeeded').run();
      db.prepare('INSERT INTO releases VALUES(?,?,?)').bind('release-old', 'build-old', 'stable').run();
      const rows = await trackedUpstreamRequests({ DB: asD1(db) });
      expect(rows).toEqual([expect.objectContaining({
        id: 'request-published', published_version: '1.0.0', upstream_ref: 'd'.repeat(40),
      })]);
    } finally {
      db.close();
    }
  });

  test('tracks one latest published request per package name', async () => {
    const db = new TestD1(schema);
    try {
      const upstreamUrl = 'https://example.test/project.git';
      const refA = 'a'.repeat(40);
      const refB = 'b'.repeat(40);
      db.prepare(`INSERT INTO requests VALUES(?,?,?,?,?,?,?,?,?,?,?)`).bind(
        'request-old', 'hello', upstreamUrl, 'git', 'system', 'unknown', refA, 'system', 'built', 1, 1,
      ).run();
      db.prepare(`INSERT INTO requests VALUES(?,?,?,?,?,?,?,?,?,?,?)`).bind(
        'request-new', 'hello', upstreamUrl, 'git', 'system', 'unknown', refB, 'system', 'built', 2, 2,
      ).run();
      db.prepare('INSERT INTO revisions VALUES(?,?,?,?,?)').bind('revision-old', 'request-old', '1.0.0', refA, 3).run();
      db.prepare('INSERT INTO revisions VALUES(?,?,?,?,?)').bind('revision-new', 'request-new', '2.0.0', refB, 4).run();
      db.prepare('INSERT INTO builds VALUES(?,?,?)').bind('build-old', 'revision-old', 'succeeded').run();
      db.prepare('INSERT INTO builds VALUES(?,?,?)').bind('build-new', 'revision-new', 'succeeded').run();
      db.prepare('INSERT INTO releases VALUES(?,?,?)').bind('release-old', 'build-old', 'stable').run();
      db.prepare('INSERT INTO releases VALUES(?,?,?)').bind('release-new', 'build-new', 'stable').run();
      const rows = await trackedUpstreamRequests({ DB: asD1(db) });
      expect(rows).toEqual([expect.objectContaining({ id: 'request-new', published_version: '2.0.0', upstream_ref: refB })]);
      db.prepare('INSERT INTO upstream_checks VALUES(?,?,?,?)').bind(
        'request-new', `git:${upstreamUrl}:v2.0.0:${refB}`, 5, null,
      ).run();
      const result = await recordUpstreamRelease(
        { DB: asD1(db) },
        { id: 'request-new', name: 'hello', upstreamUrl, sourceKind: 'git', area: 'system', declaredLicense: 'unknown', upstreamRef: refB },
        { sourceKind: 'git', version: 'v2.0.0', commit: refB, signal: `git:${upstreamUrl}:v2.0.0:${refB}` },
        '2.0.0',
      );
      expect(result.pendingRequestId).toBeNull();
      expect(db.prepare("SELECT count(*) AS count FROM requests WHERE name='hello'").first<{ count: number }>()?.count).toBe(2);
    } finally {
      db.close();
    }
  });

  test('creates pending release request pinned to discovered commit', async () => {
    const db = new TestD1(schema);
    try {
      const upstreamUrl = 'https://example.test/project.git';
      db.prepare(`INSERT INTO requests VALUES(?,?,?,?,?,?,?,?,?,?,?)`).bind(
        'request-current', 'hello', upstreamUrl, 'git', 'development', 'unknown', null, 'github:1', 'built', 1, 1,
      ).run();
      db.prepare('INSERT INTO upstream_checks VALUES(?,?,?,?)').bind(
        'request-current', `git:${upstreamUrl}:v1.0.0:${'a'.repeat(40)}`, 1, null,
      ).run();
      const result = await recordUpstreamRelease(
        { DB: asD1(db) },
        { id: 'request-current', name: 'hello', upstreamUrl, sourceKind: 'git', area: 'development', declaredLicense: 'unknown' },
        { sourceKind: 'git', version: 'v2.0.0', commit: 'b'.repeat(40), signal: `git:${upstreamUrl}:v2.0.0:${'b'.repeat(40)}` },
        '1.0.0',
      );
      expect(result.pendingRequestId).toBeString();
      expect(db.prepare('SELECT status,upstream_ref FROM requests WHERE id=?').bind(result.pendingRequestId).first<{ status: string; upstream_ref: string }>() ?? undefined)
        .toEqual({ status: 'pending', upstream_ref: 'b'.repeat(40) });
    } finally {
      db.close();
    }
  });

  test('does not miss a newer release on the first scheduled observation', async () => {
    const db = new TestD1(schema);
    try {
      const upstreamUrl = 'https://example.test/hello/hello-1.0.tar.gz';
      db.prepare(`INSERT INTO requests VALUES(?,?,?,?,?,?,?,?,?,?,?)`).bind(
        'request-current', 'hello', upstreamUrl, 'archive', 'development', 'unknown', null, 'github:1', 'built', 1, 1,
      ).run();
      db.prepare('INSERT INTO revisions VALUES(?,?,?,?,?)').bind('revision-current', 'request-current', '1.0', null, 2).run();
      db.prepare('INSERT INTO builds VALUES(?,?,?)').bind('build-current', 'revision-current', 'succeeded').run();
      db.prepare('INSERT INTO releases VALUES(?,?,?)').bind('release-current', 'build-current', 'stable').run();
      const result = await recordUpstreamRelease(
        { DB: asD1(db) },
        { id: 'request-current', name: 'hello', upstreamUrl, sourceKind: 'archive', area: 'development', declaredLicense: 'unknown' },
        { sourceKind: 'archive', version: '2.0', commit: null, upstreamUrl: 'https://example.test/hello/hello-2.0.tar.gz', signal: 'archive:v2' },
        '1.0',
      );
      expect(result.pendingRequestId).toBeString();
      expect(db.prepare('SELECT upstream_url FROM requests WHERE id=?').bind(result.pendingRequestId).first<{ upstream_url: string }>()?.upstream_url)
        .toBe('https://example.test/hello/hello-2.0.tar.gz');
    } finally {
      db.close();
    }
  });

  test('automatically queues a published Git release without approvals or merge', async () => {
    const db = new TestD1(`${schema}
      ALTER TABLE requests ADD COLUMN factory_run_id TEXT;
      CREATE TABLE approvals(id TEXT PRIMARY KEY,revision_id TEXT,kind TEXT);`);
    try {
      const upstreamUrl = 'https://example.test/project.git';
      const oldCommit = 'a'.repeat(40);
      const newCommit = 'b'.repeat(40);
      db.prepare(`INSERT INTO requests(
        id,name,upstream_url,source_kind,area,declared_license,upstream_ref,requested_by,status,created_at,updated_at,factory_run_id
      ) VALUES(?,?,?,?,?,?,?,?,'built',?,?,NULL)`).bind(
        'request-current', 'hello', upstreamUrl, 'git', 'development', 'unknown', oldCommit, 'github:1', 1, 1,
      ).run();
      db.prepare('INSERT INTO revisions VALUES(?,?,?,?,?)').bind('revision-current', 'request-current', '1.0.0', oldCommit, 2).run();
      db.prepare('INSERT INTO builds VALUES(?,?,?)').bind('build-current', 'revision-current', 'succeeded').run();
      db.prepare('INSERT INTO releases VALUES(?,?,?)').bind('release-current', 'build-current', 'stable').run();
      db.prepare('INSERT INTO upstream_checks VALUES(?,?,?,?)').bind(
        'request-current', `git:${upstreamUrl}:v1.0.0:${oldCommit}`, 2, null,
      ).run();

      const result = await recordUpstreamRelease(
        { DB: asD1(db) },
        { id: 'request-current', name: 'hello', upstreamUrl, sourceKind: 'git', area: 'development', declaredLicense: 'unknown' },
        { sourceKind: 'git', version: 'v2.0.0', commit: newCommit, signal: `git:${upstreamUrl}:v2.0.0:${newCommit}` },
        '1.0.0',
      );
      expect(result.pendingRequestId).toBeString();
      const requestId = result.pendingRequestId;
      if (!requestId) throw new Error('expected detected release request');

      const creates: Array<{ id: string; params: { requestId: string; generationId?: string } }> = [];
      const factory: FactoryWorkflowBinding = {
        create: async (input) => { creates.push(input); },
        get: async () => ({ status: async () => ({ status: 'running' }) }),
      };
      const generationId = await dispatchUpstreamFactory({ DB: asD1(db), FACTORY: factory }, requestId);
      expect(generationId).toBeString();
      if (!generationId) throw new Error('expected workflow generation');
      expect(creates).toHaveLength(1);
      expect(creates[0]?.params.requestId).toBe(requestId);
      expect(creates[0]?.params.generationId).toBe(generationId);
      expect(db.prepare('SELECT status,factory_run_id,requested_by FROM requests WHERE id=?').bind(requestId).first<{ status: string; factory_run_id: string | null; requested_by: string }>() ?? undefined).toEqual({
        status: 'generating', factory_run_id: generationId, requested_by: 'system:upstream-check',
      });
      expect(db.prepare('SELECT count(*) AS count FROM approvals').first<{ count: number }>()?.count).toBe(0);
      expect(db.prepare("SELECT count(*) AS count FROM audit_events WHERE action IN ('revision.finalizing','builds.queued')").first<{ count: number }>()?.count).toBe(0);
    } finally {
      db.close();
    }
  });

  test('scheduled Git release checks dispatch the factory workflow', async () => {
    const db = new TestD1(`${schema}
      ALTER TABLE requests ADD COLUMN factory_run_id TEXT;
      CREATE TABLE approvals(id TEXT PRIMARY KEY,revision_id TEXT,kind TEXT);`);
    try {
      const upstreamUrl = 'https://example.test/project.git';
      const oldCommit = 'a'.repeat(40);
      const newCommit = 'b'.repeat(40);
      db.prepare(`INSERT INTO requests(
        id,name,upstream_url,source_kind,area,declared_license,upstream_ref,requested_by,status,created_at,updated_at,factory_run_id
      ) VALUES(?,?,?,?,?,?,?,?,'built',?,?,NULL)`).bind(
        'request-current', 'hello', upstreamUrl, 'git', 'development', 'unknown', oldCommit, 'github:1', 1, 1,
      ).run();
      db.prepare('INSERT INTO revisions VALUES(?,?,?,?,?)').bind('revision-current', 'request-current', '1.0.0', oldCommit, 2).run();
      db.prepare('INSERT INTO builds VALUES(?,?,?)').bind('build-current', 'revision-current', 'succeeded').run();
      db.prepare('INSERT INTO releases VALUES(?,?,?)').bind('release-current', 'build-current', 'stable').run();
      db.prepare('INSERT INTO upstream_checks VALUES(?,?,?,?)').bind(
        'request-current', `git:${upstreamUrl}:v1.0.0:${oldCommit}`, 2, null,
      ).run();

      mock.module('@cloudflare/sandbox', () => ({
        getSandbox: () => ({ setAllowedHosts: async () => undefined }),
      }));
      mock.module('@flue/runtime/cloudflare', () => ({
        cloudflareSandbox: () => ({
          createSandbox: async () => ({
            exec: async () => ({
              exitCode: 0,
              stdout: `${newCommit} refs/tags/v2.0.0\n`,
              stderr: '',
            }),
          }),
        }),
      }));
      const { checkUpstreams } = await import('../services/pipeline/schedule');
      const creates: Array<{ id: string; params: { requestId: string; generationId?: string } }> = [];
      const result = await checkUpstreams({
        DB: asD1(db),
        Sandbox: {} as DurableObjectNamespace,
        FACTORY: {
          create: async (input) => { creates.push(input); },
          get: async () => ({ status: async () => ({ status: 'running' }) }),
        },
      });
      expect(result.checked).toBe(1);
      expect(result.failed).toBe(0);
      expect(result.pendingRequestIds).toHaveLength(1);
      expect(creates).toHaveLength(1);
      expect(db.prepare('SELECT status,upstream_ref FROM requests WHERE id=?').bind(result.pendingRequestIds[0]).first<{ status: string; upstream_ref: string }>() ?? undefined).toEqual({
        status: 'generating', upstream_ref: newCommit,
      });
      expect(db.prepare("SELECT count(*) AS count FROM audit_events WHERE action='request.approved'").first<{ count: number }>()?.count).toBe(0);
    } finally {
      db.close();
    }
  });

  test('retries a lost workflow dispatch without losing the detected release', async () => {
    const db = new TestD1(`${schema}
      ALTER TABLE requests ADD COLUMN factory_run_id TEXT;`);
    try {
      const upstreamUrl = 'https://example.test/project.git';
      const oldCommit = 'a'.repeat(40);
      const newCommit = 'b'.repeat(40);
      db.prepare(`INSERT INTO requests(
        id,name,upstream_url,source_kind,area,declared_license,upstream_ref,requested_by,status,created_at,updated_at,factory_run_id
      ) VALUES(?,?,?,?,?,?,?,?,'built',?,?,NULL)`).bind(
        'request-current', 'hello', upstreamUrl, 'git', 'development', 'unknown', oldCommit, 'github:1', 1, 1,
      ).run();
      db.prepare('INSERT INTO revisions VALUES(?,?,?,?,?)').bind('revision-current', 'request-current', '1.0.0', oldCommit, 2).run();
      db.prepare('INSERT INTO builds VALUES(?,?,?)').bind('build-current', 'revision-current', 'succeeded').run();
      db.prepare('INSERT INTO releases VALUES(?,?,?)').bind('release-current', 'build-current', 'stable').run();
      db.prepare('INSERT INTO upstream_checks VALUES(?,?,?,?)').bind(
        'request-current', `git:${upstreamUrl}:v1.0.0:${oldCommit}`, 2, null,
      ).run();
      const detected = await recordUpstreamRelease(
        { DB: asD1(db) },
        { id: 'request-current', name: 'hello', upstreamUrl, sourceKind: 'git', area: 'development', declaredLicense: 'unknown' },
        { sourceKind: 'git', version: 'v2.0.0', commit: newCommit, signal: `git:${upstreamUrl}:v2.0.0:${newCommit}` },
        '1.0.0',
      );
      const requestId = detected.pendingRequestId!;
      let attempt = 0;
      const generationIds: string[] = [];
      const factory: FactoryWorkflowBinding = {
        create: async ({ id: workflowId }) => {
          attempt += 1;
          generationIds.push(workflowId);
          if (attempt === 1) throw new Error('connection lost after create');
        },
        get: async () => { throw new Error('workflow lookup unavailable'); },
      };
      await expect(dispatchUpstreamFactory({ DB: asD1(db), FACTORY: factory }, requestId)).rejects.toThrow('factory workflow could not be queued');
      expect(db.prepare('SELECT status FROM requests WHERE id=?').bind(requestId).first<{ status: string }>()?.status).toBe('failed');
      const second = await dispatchUpstreamFactory({ DB: asD1(db), FACTORY: factory }, requestId);
      expect(second).toBeString();
      expect(generationIds).toHaveLength(2);
      expect(generationIds[0]).not.toBe(generationIds[1]);
      expect(db.prepare('SELECT status,upstream_ref FROM requests WHERE id=?').bind(requestId).first<{ status: string; upstream_ref: string }>() ?? undefined).toEqual({ status: 'generating', upstream_ref: newCommit });
      expect(db.prepare("SELECT count(*) AS count FROM audit_events WHERE action='factory.auto_retry'").first<{ count: number }>()?.count).toBe(1);
    } finally {
      db.close();
    }
  });

  test('stops automatic generations after three failed attempts', async () => {
    const db = new TestD1(`${schema}
      ALTER TABLE requests ADD COLUMN factory_run_id TEXT;`);
    try {
      const upstreamUrl = 'https://example.test/project.git';
      const oldCommit = 'a'.repeat(40);
      const newCommit = 'b'.repeat(40);
      db.prepare(`INSERT INTO requests(
        id,name,upstream_url,source_kind,area,declared_license,upstream_ref,requested_by,status,created_at,updated_at,factory_run_id
      ) VALUES(?,?,?,?,?,?,?,?,'built',?,?,NULL)`).bind(
        'request-current', 'hello', upstreamUrl, 'git', 'development', 'unknown', oldCommit, 'github:1', 1, 1,
      ).run();
      db.prepare('INSERT INTO revisions VALUES(?,?,?,?,?)').bind('revision-current', 'request-current', '1.0.0', oldCommit, 2).run();
      db.prepare('INSERT INTO builds VALUES(?,?,?)').bind('build-current', 'revision-current', 'succeeded').run();
      db.prepare('INSERT INTO releases VALUES(?,?,?)').bind('release-current', 'build-current', 'stable').run();
      db.prepare('INSERT INTO upstream_checks VALUES(?,?,?,?)').bind(
        'request-current', `git:${upstreamUrl}:v1.0.0:${oldCommit}`, 2, null,
      ).run();
      const detected = await recordUpstreamRelease(
        { DB: asD1(db) },
        { id: 'request-current', name: 'hello', upstreamUrl, sourceKind: 'git', area: 'development', declaredLicense: 'unknown' },
        { sourceKind: 'git', version: 'v2.0.0', commit: newCommit, signal: `git:${upstreamUrl}:v2.0.0:${newCommit}` },
        '1.0.0',
      );
      const requestId = detected.pendingRequestId;
      if (!requestId) throw new Error('expected detected release request');
      const generationIds: string[] = [];
      const factory: FactoryWorkflowBinding = {
        create: async ({ id: workflowId }) => {
          generationIds.push(workflowId);
          throw new Error('workflow unavailable');
        },
        get: async () => { throw new Error('workflow lookup unavailable'); },
      };
      for (let attempt = 0; attempt < 3; attempt += 1) {
        await expect(dispatchUpstreamFactory({ DB: asD1(db), FACTORY: factory }, requestId)).rejects.toThrow('factory workflow could not be queued');
      }
      expect(generationIds).toHaveLength(3);
      expect(await dispatchUpstreamFactory({ DB: asD1(db), FACTORY: factory }, requestId)).toBeNull();
      expect(await dispatchUpstreamFactory({ DB: asD1(db), FACTORY: factory }, requestId)).toBeNull();
      expect(generationIds).toHaveLength(3);
      expect(db.prepare('SELECT status FROM requests WHERE id=?').bind(requestId).first<{ status: string }>()?.status).toBe('failed');
      expect(db.prepare("SELECT count(*) AS count FROM audit_events WHERE target=? AND action='factory.auto_retry_exhausted'").bind(requestId).first<{ count: number }>()?.count).toBe(1);
      expect(db.prepare("SELECT count(*) AS count FROM audit_events WHERE target=? AND action IN ('factory.auto_queued','factory.auto_retry')").bind(requestId).first<{ count: number }>()?.count).toBe(3);

      const nextDetected = await recordUpstreamRelease(
        { DB: asD1(db) },
        { id: 'request-current', name: 'hello', upstreamUrl, sourceKind: 'git', area: 'development', declaredLicense: 'unknown' },
        { sourceKind: 'git', version: 'v3.0.0', commit: 'c'.repeat(40), signal: `git:${upstreamUrl}:v3.0.0:${'c'.repeat(40)}` },
        '1.0.0',
      );
      expect(nextDetected.pendingRequestId).not.toBe(requestId);
      if (!nextDetected.pendingRequestId) throw new Error('expected a new detected release request');
      const nextGeneration = await dispatchUpstreamFactory({
        DB: asD1(db),
        FACTORY: {
          create: async () => undefined,
          get: async () => ({ status: async () => ({ status: 'running' }) }),
        },
      }, nextDetected.pendingRequestId);
      expect(nextGeneration).toBeString();
    } finally {
      db.close();
    }
  });

  test('reuses a live workflow identity after a lost create response', async () => {
    const db = new TestD1(`${schema}
      ALTER TABLE requests ADD COLUMN factory_run_id TEXT;`);
    try {
      db.prepare(`INSERT INTO requests(
        id,name,upstream_url,source_kind,area,declared_license,requested_by,status,created_at,updated_at,factory_run_id
      ) VALUES(?,?,?,?,?,?,?,'generating',?,?,?)`).bind(
        'request-auto', 'hello', 'https://example.test/project.git', 'git', 'development', 'unknown', 'system:upstream-check', 1, 1, 'generation-existing',
      ).run();
      const workflowIds: string[] = [];
      const factory: FactoryWorkflowBinding = {
        create: async ({ id: workflowId }) => { workflowIds.push(workflowId); throw new Error('response lost'); },
        get: async () => ({ status: async () => ({ status: 'running' }) }),
      };
      const first = await dispatchUpstreamFactory({ DB: asD1(db), FACTORY: factory }, 'request-auto');
      const second = await dispatchUpstreamFactory({ DB: asD1(db), FACTORY: factory }, 'request-auto');
      expect(first).toBe('generation-existing');
      expect(second).toBe(first);
      expect(workflowIds).toEqual(['generation-existing', 'generation-existing']);
      expect(db.prepare('SELECT status FROM requests WHERE id=?').bind('request-auto').first<{ status: string }>()?.status).toBe('generating');
    } finally {
      db.close();
    }
  });

  test('does not dispatch an initial user request', async () => {
    const db = new TestD1(`${schema}
      ALTER TABLE requests ADD COLUMN factory_run_id TEXT;`);
    try {
      db.prepare(`INSERT INTO requests(
        id,name,upstream_url,source_kind,area,declared_license,requested_by,status,created_at,updated_at,factory_run_id
      ) VALUES(?,?,?,?,?,?,?,'pending',?,?,NULL)`).bind(
        'request-user', 'hello', 'https://example.test/project.git', 'git', 'development', 'unknown', 'github:1', 1, 1,
      ).run();
      let created = false;
      const result = await dispatchUpstreamFactory({
        DB: asD1(db),
        FACTORY: {
          create: async () => { created = true; },
          get: async () => ({ status: async () => ({ status: 'running' }) }),
        },
      }, 'request-user');
      expect(result).toBeNull();
      expect(created).toBe(false);
      expect(db.prepare('SELECT status FROM requests WHERE id=?').bind('request-user').first<{ status: string }>()?.status).toBe('pending');
    } finally {
      db.close();
    }
  });

  test('pins source inspection to requested commit', () => {
    const commit = 'f'.repeat(40);
    const command = gitInspectCommand('https://example.test/project.git', '/workspace/source', commit);
    expect(command).toContain(`fetch --depth 1 origin`);
    expect(command).toContain(commit);
    expect(command).toContain('checkout --detach FETCH_HEAD');
    expect(command).not.toContain('git clone');
  });

  test('falls back to a bounded range request when archive hosts reject HEAD', async () => {
    const previousFetch = globalThis.fetch;
    const calls: RequestInit[] = [];
    let rangeCancelled = false;
    globalThis.fetch = (async (_input, init) => {
      calls.push(init ?? {});
      return calls.length === 1
        ? new Response(null, { status: 403 })
        : new Response(new ReadableStream({
          start(controller) { controller.enqueue(new Uint8Array([0])); },
          cancel() { rangeCancelled = true; },
        }), { status: 206, headers: { etag: '"release-2"', 'content-length': '1', 'content-range': 'bytes 0-0/4242' } });
    }) as typeof globalThis.fetch;
    try {
      const result = await inspectArchiveRelease({
        id: 'request-archive', name: 'archive', upstreamUrl: 'https://example.test/archive-v2.0.0.tar.gz',
        sourceKind: 'archive', area: 'development', declaredLicense: 'unknown',
      });
      expect(result.version).toBe('2.0.0');
      const fallback = calls.find((call) => new Headers(call.headers).get('Range') === 'bytes=0-0');
      expect(fallback).toBeDefined();
      expect(new Headers(fallback?.headers).get('User-Agent')).toContain('omapkg-upstream-check');
      expect(rangeCancelled).toBe(true);
    } finally {
      globalThis.fetch = previousFetch;
    }
  });

  test('falls back to Sandbox metadata after a Worker timeout and keeps final headers', async () => {
    const previousFetch = globalThis.fetch;
    const commands: string[] = [];
    const allowed: string[] = [];
    let hadAbortSignal = false;
    globalThis.fetch = (async (_input, init) => {
      if (!init?.method) return new Response(null, { status: 404 });
      hadAbortSignal = init.signal instanceof AbortSignal;
      throw new DOMException('upstream timed out', 'AbortError');
    }) as typeof globalThis.fetch;
    const sandbox = {
      exec: async (command: string) => {
        commands.push(command);
        if (commands.length === 1) {
          return {
            exitCode: 0,
            stdout: 'HTTP/2 200 OK\r\nETag: "sandbox-release"\r\nLast-Modified: Tue, 02 Sep 2026 12:00:00 GMT\r\nContent-Length: 42\r\n\r\n\nhttp_status=200\ncurl_status=0\n',
            stderr: '',
          };
        }
        throw new Error('unexpected metadata command');
      },
    } as unknown as Sandbox;
    try {
      const result = await inspectArchiveRelease({
        id: 'request-archive-timeout', name: 'archive', upstreamUrl: 'https://example.test/archive-v2.0.0.tar.gz',
        sourceKind: 'archive', area: 'development', declaredLicense: 'unknown',
      }, sandbox, async (host) => { allowed.push(host); });
      expect(result.version).toBe('2.0.0');
      expect(result.upstreamUrl).toBe('https://example.test/archive-v2.0.0.tar.gz');
      expect(result.signal).toContain('etag="sandbox-release"');
      expect(result.signal).toContain('last-modified=Tue, 02 Sep 2026 12:00:00 GMT');
      expect(result.signal).toContain('length=42');
      expect(commands).toHaveLength(1);
      expect(commands[0]).toContain('--head');
      expect(commands[0]).not.toContain('--range');
      expect(commands[0]).not.toContain('/workspace/source.bundle');
      expect(allowed).toEqual([]);
      expect(hadAbortSignal).toBe(true);
    } finally {
      globalThis.fetch = previousFetch;
    }
  });

  test('rejects private Sandbox metadata redirects before host authorization', async () => {
    const previousFetch = globalThis.fetch;
    const allowed: string[] = [];
    globalThis.fetch = (async (_input, init) => {
      if (!init?.method) return new Response(null, { status: 404 });
      throw new DOMException('upstream timed out', 'AbortError');
    }) as typeof globalThis.fetch;
    const sandbox = {
      exec: async () => ({
        exitCode: 0,
        stdout: 'HTTP/2 302 Found\r\nLocation: https://127.0.0.1/private.tar.gz\r\n\nhttp_status=302\ncurl_status=0\n',
        stderr: '',
      }),
    } as unknown as Sandbox;
    try {
      await expect(inspectArchiveRelease({
        id: 'request-archive-redirect', name: 'archive', upstreamUrl: 'https://example.test/archive-v2.0.0.tar.gz',
        sourceKind: 'archive', area: 'development', declaredLicense: 'unknown',
      }, sandbox, async (host) => { allowed.push(host); })).rejects.toThrow('source URL host is not public');
      expect(allowed).toEqual([]);
    } finally {
      globalThis.fetch = previousFetch;
    }
  });

  test('discovers the next archive version from its own directory listing', async () => {
    const previousFetch = globalThis.fetch;
    const calls: Array<{ url: string; init: RequestInit }> = [];
    globalThis.fetch = (async (input, init) => {
      const url = String(input);
      calls.push({ url, init: init ?? {} });
      if (calls.length === 1) {
        return new Response('<a href="hello-2.12.tar.gz">old</a><a href="hello-2.13.tar.gz">new</a><a href="hello-v2.14.tar.gz">newest</a><a href="other-9.0.tar.gz">other</a><a href="https://other.test/hello-99.0.tar.gz">external</a><a href="https://user:pass@example.test/gnu/hello/hello-100.0.tar.gz">credentialed</a>', { status: 200 });
      }
      return new Response(null, { status: 200, headers: { etag: '"release-3"', 'content-length': '1' } });
    }) as typeof globalThis.fetch;
    try {
      const result = await inspectArchiveRelease({
        id: 'request-archive', name: 'hello', upstreamUrl: 'https://example.test/gnu/hello/hello-2.12.tar.gz',
        sourceKind: 'archive', area: 'development', declaredLicense: 'unknown',
      });
      expect(result.version).toBe('2.14');
      expect(result.upstreamUrl).toBe('https://example.test/gnu/hello/hello-v2.14.tar.gz');
      expect(calls[0]?.url).toBe('https://example.test/gnu/hello/');
      expect(calls[1]?.url).toBe('https://example.test/gnu/hello/hello-v2.14.tar.gz');
      expect(calls[1]?.init.method).toBe('HEAD');
    } finally {
      globalThis.fetch = previousFetch;
    }
  });
});
