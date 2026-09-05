import { describe, expect, test } from 'bun:test';
import { POST } from '../src/routes/api/mcp/+server';
import { asD1, TestD1 } from './d1';

const schema = `
CREATE TABLE requests(id TEXT PRIMARY KEY,name TEXT NOT NULL,upstream_url TEXT NOT NULL);
CREATE TABLE revisions(id TEXT PRIMARY KEY,request_id TEXT NOT NULL,sources_json TEXT NOT NULL,license TEXT NOT NULL,dependencies_json TEXT NOT NULL,explanation TEXT,description TEXT,recipe TEXT);
CREATE TABLE builds(id TEXT PRIMARY KEY,revision_id TEXT NOT NULL,status TEXT NOT NULL,artifact_filename TEXT,artifact_sha256 TEXT,artifact_size INTEGER);
CREATE TABLE releases(id TEXT PRIMARY KEY,build_id TEXT NOT NULL,name TEXT NOT NULL,version TEXT NOT NULL,architecture TEXT NOT NULL,surface TEXT NOT NULL,channel TEXT NOT NULL,artifact_key TEXT,signature_key TEXT,recipe_key TEXT,sbom_key TEXT,provenance_key TEXT,published_at INTEGER,stable_at INTEGER);
CREATE TABLE audit_events(id INTEGER PRIMARY KEY AUTOINCREMENT,actor TEXT,action TEXT,target TEXT,detail TEXT,created_at INTEGER);
`;

const origin = 'https://omapkg.example';
const protocolMeta = { _meta: {
  'io.modelcontextprotocol/protocolVersion': '2026-07-28',
  'io.modelcontextprotocol/clientInfo': { name: 'mcp-test', version: '1.0.0' },
  'io.modelcontextprotocol/clientCapabilities': {},
} };

function event(db: TestD1, body: unknown, method: string, actor: unknown = null, name?: string, requestInit: RequestInit = {}) {
  const headers = new Headers({ 'content-type': 'application/json', 'MCP-Protocol-Version': '2026-07-28', 'Mcp-Method': method });
  if (name) headers.set('Mcp-Name', name);
  const request = new Request(`${origin}/api/mcp`, { ...requestInit, method: 'POST', headers, body: JSON.stringify(body) });
  return {
    request, url: new URL(request.url), locals: { actor },
    platform: { env: { DB: asD1(db), ARTIFACTS: { get: async () => null } } },
  } as unknown as Parameters<typeof POST>[0];
}

function call(name: string, argumentsValue: Record<string, unknown> = {}, extra: Record<string, unknown> = {}) {
  return { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name, arguments: argumentsValue, ...protocolMeta, ...extra } };
}

function seed(db: TestD1): void {
  db.prepare('INSERT INTO requests VALUES(?,?,?)').bind('q1', 'alpha', 'https://example.test/alpha.tar.gz').run();
  db.prepare('INSERT INTO requests VALUES(?,?,?)').bind('q2', 'beta', 'https://example.test/beta.tar.gz').run();
  db.prepare('INSERT INTO requests VALUES(?,?,?)').bind('q3', 'gamma', 'https://example.test/gamma.tar.gz').run();
  for (const [id, requestId, name] of [['v1', 'q1', 'alpha'], ['v2', 'q2', 'beta'], ['v3', 'q3', 'gamma']] as const) {
    db.prepare('INSERT INTO revisions(id,request_id,sources_json,license,dependencies_json,explanation,description,recipe) VALUES(?,?,?,?,?,?,?,?)').bind(id, requestId, JSON.stringify([{ name: `${name}.tar.gz`, url: `https://example.test/${name}.tar.gz`, sha256: 'a'.repeat(64) }]), 'MIT', '[]', `${name} package`, `${name} package`, `pkgdesc='${name} package'`).run();
  }
  for (const [id, revisionId, name, version, status] of [['b1', 'v1', 'alpha', '1.0.0', 'succeeded'], ['b2', 'v2', 'beta', '1.0.0', 'succeeded'], ['b3', 'v3', 'gamma', '1.0.0', 'queued']] as const) {
    db.prepare('INSERT INTO builds VALUES(?,?,?,?,?,?)').bind(id, revisionId, status, `${name}-1.0.0-x86_64.pkg.tar.zst`, 'b'.repeat(64), 10).run();
    db.prepare(`INSERT INTO releases(id,build_id,name,version,architecture,surface,channel,artifact_key,signature_key,recipe_key,sbom_key,provenance_key,published_at,stable_at)
      VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).bind(`r-${id}`, id, name, version, 'x86_64', 'binary', 'stable', `packages/${name}`, `signatures/${name}`, `recipes/${name}`, `sbom/${name}`, `provenance/${name}`, 1, 1).run();
  }
}

async function responseJSON(response: Response): Promise<any> {
  return await response.json();
}

describe('read-only MCP endpoint', () => {
  test('advertises a valid stateless discover and tools/list envelope', async () => {
    const db = new TestD1(schema);
    try {
      const discovered = await responseJSON(await POST(event(db, { jsonrpc: '2.0', id: 1, method: 'server/discover', params: protocolMeta }, 'server/discover')));
      expect(discovered.result).toMatchObject({ resultType: 'complete', supportedVersions: ['2026-07-28'], capabilities: { tools: { listChanged: false } }, ttlMs: 300_000, cacheScope: 'public' });
      expect(discovered.result.capabilities.resources).toBeUndefined();
      expect(discovered.result._meta['io.modelcontextprotocol/serverInfo']).toEqual({ name: 'omapkg', version: '0.1.0' });
      const listed = await responseJSON(await POST(event(db, { jsonrpc: '2.0', id: 2, method: 'tools/list', params: protocolMeta }, 'tools/list')));
      expect(listed.result.resultType).toBe('complete');
      expect(listed.result.tools.map((tool: { name: string }) => tool.name)).toEqual(['packages.search', 'packages.get', 'provenance.get', 'metrics.get']);
      expect(listed.result).toMatchObject({ nextCursor: null, ttlMs: 300_000, cacheScope: 'public' });
      expect((await POST(event(db, call('packages.search'), 'tools/call', null, 'packages.search'))).headers.get('cache-control')).toBe('no-store');
    } finally { db.close(); }
  });

  test('keeps maintainer metrics private and paginates search in SQL', async () => {
    const db = new TestD1(schema);
    seed(db);
    const maintainer = { id: 'github:1', role: 'maintainer' as const, areas: ['development'] };
    try {
      const metrics = await POST(event(db, call('metrics.get'), 'tools/call', maintainer, 'metrics.get'));
      expect(metrics.headers.get('cache-control')).toBe('no-store');
      const metricsBody = await responseJSON(metrics);
      expect(metricsBody.result).toMatchObject({ ttlMs: 0, cacheScope: 'private' });
      expect(metricsBody.result.structuredContent.pipeline).toEqual([{ status: 'queued', count: 1 }, { status: 'succeeded', count: 2 }]);

      const first = await responseJSON(await POST(event(db, call('packages.search', { limit: 1 }), 'tools/call', null, 'packages.search')));
      expect(first.result).toMatchObject({ ttlMs: 300_000, cacheScope: 'public' });
      expect(first.result.structuredContent.items).toHaveLength(1);
      expect(typeof first.result.structuredContent.nextCursor).toBe('string');
      const second = await responseJSON(await POST(event(db, call('packages.search', { limit: 1, cursor: first.result.structuredContent.nextCursor }), 'tools/call', null, 'packages.search')));
      expect(second.result.structuredContent.items).toHaveLength(1);
      expect(second.result.structuredContent.items[0].name).not.toBe(first.result.structuredContent.items[0].name);
    } finally { db.close(); }
  });

  test('returns invalid params for malformed filters and never echoes header data', async () => {
    const db = new TestD1(schema);
    try {
      const invalidResponse = await POST(event(db, call('packages.search', { architecture: 'mips' }), 'tools/call', null, 'packages.search'));
      expect(invalidResponse.headers.get('cache-control')).toBe('no-store');
      const invalid = await responseJSON(invalidResponse);
      expect(invalid.error.code).toBe(-32602);
      const redacted = await responseJSON(await POST(event(db, { jsonrpc: '2.0', id: 2, method: 'tools/list', params: protocolMeta }, 'header-secret-value')));
      expect(JSON.stringify(redacted)).not.toContain('header-secret-value');
    } finally { db.close(); }
  });

  test('bounds streamed bodies without trusting Content-Length', async () => {
    const db = new TestD1(schema);
    try {
      const oversized = new ReadableStream<Uint8Array>({
        start(controller) {
          controller.enqueue(new Uint8Array(256 * 1024 + 1));
          controller.close();
        },
      });
      const request = new Request(`${origin}/api/mcp`, { method: 'POST', headers: { 'content-type': 'application/json', 'MCP-Protocol-Version': '2026-07-28', 'Mcp-Method': 'tools/list' }, body: oversized, duplex: 'half' } as RequestInit & { duplex: 'half' });
      const result = await POST({ request, url: new URL(request.url), locals: { actor: null }, platform: { env: { DB: asD1(db), ARTIFACTS: {} } } } as unknown as Parameters<typeof POST>[0]);
      expect(result.status).toBe(413);
      expect((await responseJSON(result)).error.code).toBe(-32600);
    } finally { db.close(); }
  });
});
