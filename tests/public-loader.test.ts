import { expect, test } from 'bun:test';
import { load } from '../src/routes/+page.server';
import { asD1, TestD1 } from './d1';

const schema = `
CREATE TABLE requests(id TEXT PRIMARY KEY,status TEXT NOT NULL);
CREATE TABLE revisions(id TEXT PRIMARY KEY,request_id TEXT NOT NULL,description TEXT,recipe TEXT,explanation TEXT);
CREATE TABLE builds(id TEXT PRIMARY KEY,revision_id TEXT NOT NULL,artifact_filename TEXT,artifact_sha256 TEXT,artifact_size INTEGER);
CREATE TABLE releases(id TEXT PRIMARY KEY,build_id TEXT NOT NULL,name TEXT NOT NULL,version TEXT NOT NULL,architecture TEXT NOT NULL,surface TEXT NOT NULL,channel TEXT NOT NULL,artifact_key TEXT,signature_key TEXT,recipe_key TEXT,sbom_key TEXT,provenance_key TEXT,published_at INTEGER,stable_at INTEGER);
`;

function event(db: TestD1, search = '') {
  return {
    url: new URL(`https://omapkg.example/?${search}`),
    platform: { env: { DB: asD1(db) } },
  } as unknown as Parameters<typeof load>[0];
}

const pageLoad = load as unknown as (event: Parameters<typeof load>[0]) => Promise<{
  packages: Array<{ description?: string | null }>;
  channel: string;
  surface: string;
  architecture: string;
}>;

test('public loader honors channel, surface, and architecture filters and returns final descriptions', async () => {
  const db = new TestD1(schema);
  try {
    db.prepare('INSERT INTO requests VALUES(?,?), (?,?)').bind('q1', 'built', 'q2', 'pending').run();
    db.prepare('INSERT INTO revisions VALUES(?,?,?,?,?), (?,?,?,?,?), (?,?,?,?,?)').bind(
      'v-stable', 'q1', 'Stable description', "pkgdesc='Ignored legacy text'", 'audit detail',
      'v-dev', 'q1', 'Dev description', "pkgdesc='Dev legacy text'", 'audit detail',
      'v-old', 'q1', null, "pkgdesc='Legacy parsed text'", 'audit detail',
    ).run();
    db.prepare('INSERT INTO builds VALUES(?,?,?,?,?), (?,?,?,?,?), (?,?,?,?,?)').bind(
      'b-stable', 'v-stable', 'stable.pkg.tar.zst', 'a'.repeat(64), 10,
      'b-dev', 'v-dev', 'dev.pkg.tar.zst', 'b'.repeat(64), 10,
      'b-old', 'v-old', 'old.pkg.tar.zst', 'c'.repeat(64), 10,
    ).run();
    db.prepare('INSERT INTO releases VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?), (?,?,?,?,?,?,?,?,?,?,?,?,?,?), (?,?,?,?,?,?,?,?,?,?,?,?,?,?)').bind(
      'r-stable', 'b-stable', 'demo', '1.0-1', 'x86_64', 'binary', 'stable', 'a', 'a', 'a', 'a', 'a', 3, 3,
      'r-dev', 'b-dev', 'demo', '1.1-1', 'x86_64', 'binary', 'dev', 'b', 'b', 'b', 'b', 'b', 2, null,
      'r-old', 'b-old', 'legacy', '0.9-1', 'aarch64', 'recipe', 'withdrawn', null, null, 'c', 'c', 'c', 1, 1,
    ).run();

    const stable = await pageLoad(event(db));
    expect(stable.channel).toBe('stable');
    expect(stable.packages).toHaveLength(1);
    expect(stable.packages[0]?.description).toBe('Stable description');
    expect(stable.packages[0]).not.toHaveProperty('recipe');
    expect(stable.packages[0]).not.toHaveProperty('explanation');

    const all = await pageLoad(event(db, 'channel=all&surface=recipe&architecture=aarch64'));
    expect(all.channel).toBe('all');
    expect(all.surface).toBe('recipe');
    expect(all.architecture).toBe('aarch64');
    expect(all.packages).toHaveLength(1);
    expect(all.packages[0]?.description).toBe('Legacy parsed text');
  } finally {
    db.close();
  }
});
