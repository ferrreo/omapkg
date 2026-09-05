import { describe, expect, test } from 'bun:test';
import { GET } from '../src/routes/api/admin/audit/export/+server';
import { auditCsv, auditNdjson, listAuditEvents, parseAuditQuery } from '../src/lib/server/audit';
import { asD1, TestD1 } from './d1';

const schema = `
CREATE TABLE audit_events(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  actor TEXT NOT NULL,
  action TEXT NOT NULL,
  target TEXT NOT NULL,
  detail TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE TABLE github_identities(github_id TEXT PRIMARY KEY, username TEXT NOT NULL);
`;

function event(db: TestD1, url: string, role: 'maintainer' | 'security' | 'admin' | 'public' = 'maintainer') {
  return {
    request: new Request(`https://omapkg.example${url}`),
    url: new URL(`https://omapkg.example${url}`),
    locals: { actor: { id: 'github:1', role, areas: ['system'] } },
    platform: { env: { DB: asD1(db) } },
  } as any;
}

function insert(db: TestD1, actor: string, action: string, target: string, detail: string, createdAt: number) {
  db.prepare('INSERT INTO audit_events(actor,action,target,detail,created_at) VALUES(?,?,?,?,?)')
    .bind(actor, action, target, detail, createdAt).run();
}

describe('audit query and export boundary', () => {
  test('request scope follows revisions, builds, signing and historical promotion batches in exports', async () => {
    const db = new TestD1(schema + `
      CREATE TABLE requests(id TEXT PRIMARY KEY);
      CREATE TABLE revisions(id TEXT PRIMARY KEY, request_id TEXT);
      CREATE TABLE builds(id TEXT PRIMARY KEY, revision_id TEXT);
      CREATE TABLE releases(id TEXT PRIMARY KEY, build_id TEXT);
      CREATE TABLE signing_intents(id TEXT PRIMARY KEY, build_id TEXT);
      CREATE TABLE promotion_batches(id TEXT PRIMARY KEY, release_ids_json TEXT);
      INSERT INTO requests VALUES('request-1'),('request-2');
      INSERT INTO revisions VALUES('revision-old','request-1'),('revision-new','request-1'),('revision-other','request-2');
      INSERT INTO builds VALUES('build-1','revision-new'),('build-other','revision-other');
      INSERT INTO releases VALUES('release-1','build-1'),('release-other','build-other');
      INSERT INTO signing_intents VALUES('intent-1','build-1'),('intent-other','build-other');
      INSERT INTO promotion_batches VALUES('batch-1','["release-1","release-other"]'),('batch-other','["release-other"]');
    `);
    try {
      for (const target of ['request-1', 'revision-old', 'revision-new', 'build-1', 'intent-1', 'release-1', 'batch-1']) {
        insert(db, 'system', 'pipeline.event', target, '{}', 1_000);
      }
      for (const target of ['request-2', 'build-other', 'intent-other', 'batch-other']) {
        insert(db, 'system', 'pipeline.event', target, '{"requestId":"request-1"}', 1_000);
      }
      const scope = parseAuditQuery(new URLSearchParams({ request: 'request-1', limit: '2' }));
      const first = await listAuditEvents(asD1(db), scope);
      expect(first.events.map((item) => item.target)).toEqual(['batch-1', 'release-1']);
      expect(first.nextBefore).toBe(6);
      const response = await GET(event(db, '/api/admin/audit/export?request=request-1&format=ndjson&limit=2'));
      expect(response.status).toBe(200);
      const rows = (await response.text()).trim().split('\n').map((line) => JSON.parse(line));
      expect(rows.map((row) => row.target)).toEqual(['batch-1', 'release-1', 'intent-1', 'build-1', 'revision-new', 'revision-old', 'request-1']);
      const recorded = db.prepare("SELECT detail FROM audit_events WHERE action='audit.export_completed'").first<{ detail: string }>();
      expect(JSON.parse(recorded!.detail).requestId).toBe('request-1');
      const missing = await listAuditEvents(asD1(db), { ...scope, requestId: 'missing' });
      expect(missing.events).toHaveLength(0);
      const filtered = await listAuditEvents(asD1(db), { ...scope, q: 'intent-1' });
      expect(filtered.events.map((item) => item.target)).toEqual(['intent-1']);
    } finally {
      db.close();
    }
  });

  test('search is applied server-side and cursor pagination covers a complete scope', async () => {
    const db = new TestD1(schema);
    try {
      insert(db, 'github:1', 'build.completed', 'request-1', '{"package":"hello"}', 1_000);
      insert(db, 'github:2', 'release.published', 'release-1', '{"package":"world"}', 2_000);
      insert(db, 'github:1', 'build.failed', 'request-2', '{"package":"hello"}', 3_000);
      db.prepare('INSERT INTO github_identities(github_id,username) VALUES(?,?)').bind('test-github-id', 'fixture-user').run();
      insert(db, 'github:test-github-id', 'auth.signed_in', 'session-1', '{}', 4_000);

      const filtered = parseAuditQuery(new URL('https://omapkg.example/maintain/audit?q=hello&limit=1'));
      const first = await listAuditEvents(asD1(db), filtered);
      expect(first.events.map((item) => item.action)).toEqual(['build.failed']);
      expect(first.nextBefore).toBe(3);
      const username = await listAuditEvents(asD1(db), parseAuditQuery(new URL('https://omapkg.example/maintain/audit?q=%40fixture-user')));
      expect(username.events.map((item) => item.action)).toEqual(['auth.signed_in']);

      const page = parseAuditQuery(new URL('https://omapkg.example/maintain/audit?limit=1'));
      const ids: number[] = [];
      let before = page.before;
      let nextBefore: number | null = before;
      while (nextBefore !== null) {
        const current = await listAuditEvents(asD1(db), { ...page, before });
        ids.push(...current.events.map((item) => item.id));
        nextBefore = current.nextBefore;
        if (nextBefore !== null) before = nextBefore;
      }
      expect(ids).toEqual([4, 3, 2, 1]);
    } finally {
      db.close();
    }
  });

  test('range and query inputs are bounded', () => {
    const current = Math.floor(Date.now() / 1_000);
    const parsed = parseAuditQuery(new URL(`https://omapkg.example/maintain/audit?range=30d&from=${current - 100}&to=${current}&limit=50`));
    expect(parsed.range).toBe('30d');
    expect(parsed.from).toBeGreaterThanOrEqual(current - 100);
    expect(parsed.to).toBe(current);
    for (const url of [
      'https://omapkg.example/maintain/audit?range=forever',
      'https://omapkg.example/maintain/audit?range=toString',
      'https://omapkg.example/maintain/audit?limit=1001',
      'https://omapkg.example/maintain/audit?before=nope',
      'https://omapkg.example/maintain/audit?request=invalid%2Fid',
      'https://omapkg.example/maintain/audit?from=200&to=100',
      `https://omapkg.example/maintain/audit?q=${'x'.repeat(257)}`,
    ]) expect(() => parseAuditQuery(new URL(url), 1_000)).toThrow();
  });

  test('export is authenticated, bounded, paginated, and records its own audit event', async () => {
    const db = new TestD1(schema);
    try {
      insert(db, 'github:1', 'build.completed', 'request-1', '{"package":"hello"}', 1_000);
      insert(db, 'github:2', 'release.published', 'release-1', '{"package":"world"}', 2_000);
      const response = await GET(event(db, '/api/admin/audit/export?format=csv&limit=1&paged=1'));
      expect(response.status).toBe(200);
      expect(response.headers.get('content-type')).toContain('text/csv');
      expect(response.headers.get('content-disposition')).toContain('omapkg-audit.csv');
      expect(response.headers.get('x-audit-next-before')).toBe('2');
      expect(await response.text()).toContain('release.published');
      expect(db.prepare("SELECT action FROM audit_events WHERE action='audit.exported'").first<{ action: string }>())
        .toEqual({ action: 'audit.exported' });

      const ndjson = await GET(event(db, '/api/admin/audit/export?format=ndjson&q=release.published'));
      expect(ndjson.status).toBe(200);
      const rows = (await ndjson.text()).trim().split('\n').map((line) => JSON.parse(line));
      expect(rows).toHaveLength(1);
      expect(rows[0].action).toBe('release.published');
    } finally {
      db.close();
    }
  });

  test('default export streams every event from a fixed snapshot and audits completion', async () => {
    const db = new TestD1(schema);
    try {
      insert(db, 'github:1', 'build.completed', 'request-1', '{"package":"hello"}', 1_000);
      insert(db, 'github:2', 'release.published', 'release-1', '{"package":"world"}', 2_000);
      const response = await GET(event(db, '/api/admin/audit/export?format=csv&limit=1'));
      expect(response.status).toBe(200);
      expect(response.headers.get('x-audit-snapshot-max')).toBe('2');
      expect(response.headers.get('x-audit-next-before')).toBeNull();
      const reader = response.body!.getReader();
      const decoder = new TextDecoder();
      const chunks: string[] = [];
      let result = await reader.read();
      insert(db, 'github:3', 'late.event', 'request-3', '{"package":"late"}', 3_000);
      while (!result.done) {
        chunks.push(decoder.decode(result.value, { stream: true }));
        result = await reader.read();
      }
      chunks.push(decoder.decode());
      const body = chunks.join('');
      expect(body).toContain('build.completed');
      expect(body).toContain('release.published');
      expect(body).not.toContain('late.event');
      expect(db.prepare("SELECT COUNT(*) AS count FROM audit_events WHERE action='audit.export_started'").first<{ count: number }>()?.count).toBe(1);
      expect(db.prepare("SELECT COUNT(*) AS count FROM audit_events WHERE action='audit.export_completed'").first<{ count: number }>()?.count).toBe(1);
    } finally {
      db.close();
    }
  });

  test('cancelled export records failure before cancellation resolves', async () => {
    const db = new TestD1(schema);
    try {
      insert(db, 'github:1', 'build.completed', 'request-1', '{}', 1_000);
      insert(db, 'github:2', 'release.published', 'release-1', '{}', 2_000);
      const response = await GET(event(db, '/api/admin/audit/export?format=ndjson&limit=1'));
      const reader = response.body!.getReader();
      await reader.read();
      await reader.cancel();
      expect(db.prepare("SELECT COUNT(*) AS count FROM audit_events WHERE action='audit.export_failed'").first<{ count: number }>()?.count).toBe(1);
      expect(db.prepare("SELECT COUNT(*) AS count FROM audit_events WHERE action='audit.export_completed'").first<{ count: number }>()?.count).toBe(0);
    } finally {
      db.close();
    }
  });

  test('CSV cells are escaped and spreadsheet formulas are neutralized', () => {
    const row = { id: 1, actor: '=formula', action: 'audit', target: 'x,y', detail: '{"quote":"yes"}', created_at: 1 };
    const csv = auditCsv([row]);
    expect(csv).toContain(`"'=formula"`);
    expect(auditCsv([{ ...row, actor: '  =formula' }])).toContain(`"'  =formula"`);
    expect(csv).toContain('"x,y"');
    expect(csv).toContain('"{""quote"":""yes""}"');
    expect(auditNdjson([row])).toContain('"actor":"=formula"');
  });
});
