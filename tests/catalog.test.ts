import { expect, test } from 'bun:test';
import { GET } from '../src/routes/api/catalog/+server';
import { catalogPage, publicSources, stringList } from '../src/lib/server/catalog';
import { asD1, TestD1 } from './d1';

const schema = `
CREATE TABLE requests(id TEXT PRIMARY KEY,upstream_url TEXT);
CREATE TABLE revisions(id TEXT PRIMARY KEY,request_id TEXT,sources_json TEXT,license TEXT,description TEXT,recipe TEXT,explanation TEXT);
CREATE TABLE builds(id TEXT PRIMARY KEY,revision_id TEXT,artifact_filename TEXT,artifact_sha256 TEXT,artifact_size INTEGER);
CREATE TABLE releases(id TEXT PRIMARY KEY,build_id TEXT,name TEXT,version TEXT,architecture TEXT,surface TEXT,channel TEXT,artifact_key TEXT,signature_key TEXT,recipe_key TEXT,sbom_key TEXT,provenance_key TEXT,published_at INTEGER,stable_at INTEGER);
`;

function seed(db: TestD1, id: string, name: string, architecture = 'x86_64', channel = 'stable', surface = 'binary') {
  db.prepare('INSERT INTO requests VALUES(?,?)').bind(id, `https://example.com/${name}`).run();
  db.prepare('INSERT INTO revisions VALUES(?,?,?,?,?,?,?)').bind(id, id,
    JSON.stringify([{ name: 'source.tar', url: 'https://example.com/source.tar', sha256: 'a'.repeat(64) }]),
    'MIT', `${name} description`, `pkgname=${name}`, 'Review evidence').run();
  db.prepare('INSERT INTO builds VALUES(?,?,?,?,?)').bind(id, id, `${name}-${id}-${architecture}.pkg.tar.zst`, 'b'.repeat(64), 10).run();
  db.prepare('INSERT INTO releases VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)').bind(id, id, name, id, architecture, surface, channel,
    surface === 'binary' ? `packages/${id}` : null, surface === 'binary' ? `signatures/${id}` : null,
    `recipes/${id}`, `sbom/${id}`, `provenance/${id}`, 1, channel === 'stable' ? 1 : null).run();
}

async function page(db: TestD1, search = '') {
  const response = await GET({
    url: new URL(`https://omapkg.example/api/catalog?${search}`), platform: { env: { DB: asD1(db) } },
  } as Parameters<typeof GET>[0]);
  expect(response.status).toBe(200);
  return response.json() as Promise<{ items: Array<{ id: string; name: string; architecture: string; }>; nextCursor: string | null; }>;
}

test('catalog bounds latest rows in SQL and preserves cursor order across releases', async () => {
  const db = new TestD1(schema);
  try {
    seed(db, 'alpha-1', 'alpha');
    seed(db, 'alpha-2', 'alpha');
    seed(db, 'alpha-arm', 'alpha', 'aarch64');
    seed(db, 'beta', 'beta');
    seed(db, 'delta', 'delta', 'x86_64', 'dev');
    seed(db, 'gamma', 'gamma', 'x86_64', 'stable', 'recipe');
    const first = await page(db, 'limit=2');
    expect(first.items.map((item) => item.id)).toEqual(['alpha-arm', 'alpha-2']);
    expect(first.nextCursor).not.toBeNull();
    // An update to the last package on a page must not restart pagination.
    seed(db, 'alpha-3', 'alpha');
    const second = await page(db, `limit=2&cursor=${encodeURIComponent(first.nextCursor!)}`);
    expect(second.items.map((item) => item.id)).toEqual(['beta', 'gamma']);
    expect(second.nextCursor).toBeNull();
    const offsetPage = await catalogPage(asD1(db), { channel: 'stable', search: '', limit: 2, offset: 2 });
    expect(offsetPage.map((row) => row.id)).toEqual(['beta', 'gamma']);
    expect((await page(db, 'q=alpha&architecture=x86_64')).items.map((item) => item.id)).toEqual(['alpha-3']);
    expect((await page(db, 'surface=recipe')).items.map((item) => item.id)).toEqual(['gamma']);
    expect((await page(db, 'channel=dev')).items.map((item) => item.id)).toEqual(['delta']);
    expect((await page(db, 'limit=1.5')).nextCursor).not.toBeNull();
  } finally { db.close(); }
});

test('shared public evidence parsers preserve malformed-input behavior', () => {
  const source = { name: 'source.tar', url: 'https://example.com/source.tar', sha256: 'a'.repeat(64) };
  expect(publicSources(JSON.stringify([null, {}, source, { ...source, sha256: 5 }]))).toEqual([source]);
  expect(publicSources('{')).toEqual([]);
  expect(publicSources('{}')).toEqual([]);
  expect(stringList('[null,"one",1,"two"]')).toEqual(['one', 'two']);
  expect(stringList('{')).toEqual([]);
});
