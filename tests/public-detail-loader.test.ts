import { expect, test } from 'bun:test';
import { load } from '../src/routes/packages/[name]/+page.server';
import { asD1, TestD1 } from './d1';

const schema = `
CREATE TABLE requests(id TEXT PRIMARY KEY,name TEXT,description TEXT,upstream_url TEXT,source_kind TEXT,area TEXT,status TEXT,created_at INTEGER,updated_at INTEGER);
CREATE TABLE revisions(id TEXT PRIMARY KEY,request_id TEXT,version TEXT,description TEXT,recipe TEXT,explanation TEXT,dependencies_json TEXT,license TEXT,upstream_commit TEXT);
CREATE TABLE builds(id TEXT PRIMARY KEY,revision_id TEXT,architecture TEXT,artifact_filename TEXT,artifact_sha256 TEXT,artifact_size INTEGER);
CREATE TABLE releases(id TEXT PRIMARY KEY,build_id TEXT,name TEXT,version TEXT,architecture TEXT,surface TEXT,channel TEXT,published_at INTEGER,stable_at INTEGER,sbom_key TEXT,provenance_key TEXT);
CREATE TABLE feedback(id TEXT PRIMARY KEY,release_id TEXT,works INTEGER,comment TEXT,created_at INTEGER);
`;

function event(db: TestD1, search = '') {
  return {
    params: { name: 'demo' },
    url: new URL(`https://omapkg.example/packages/demo?${search}`),
    platform: { env: { DB: asD1(db) } },
    locals: { actor: null }
  } as unknown as Parameters<typeof load>[0];
}

const pageLoad = load as unknown as (event: Parameters<typeof load>[0]) => Promise<{
  architecture: string;
  architectures: string[];
  channel: string;
  releases: Array<{ id: string; build_id: string; architecture: string }>;
  revisions: Array<{ id: string; description: string | null }>;
  feedback: Array<{ comment: string }>;
}>;

test('public package detail keeps selected architecture and channel across evidence', async () => {
  const db = new TestD1(schema);
  try {
    db.prepare('INSERT INTO requests VALUES(?,?,?,?,?,?,?,?,?)').bind('request-1', 'demo', 'Requester text', 'https://example.com/demo.tar.gz', 'archive', 'desktop', 'built', 1, 1).run();
    db.prepare('INSERT INTO revisions VALUES(?,?,?,?,?,?,?,?,?), (?,?,?,?,?,?,?,?,?), (?,?,?,?,?,?,?,?,?)').bind(
      'revision-x86-stable', 'request-1', '1.0-1', 'x86 stable final', "pkgdesc='x86 stable'", 'x86 stable explanation', '[]', 'MIT', null,
      'revision-arm-stable', 'request-1', '1.0-1', 'ARM stable final', "pkgdesc='ARM stable'", 'ARM stable explanation', '[]', 'MIT', null,
      'revision-x86-dev', 'request-1', '1.1-1', 'x86 dev final', "pkgdesc='x86 dev'", 'x86 dev explanation', '[]', 'MIT', null,
    ).run();
    db.prepare('INSERT INTO builds VALUES(?,?,?,?,?,?), (?,?,?,?,?,?), (?,?,?,?,?,?)').bind(
      'build-x86-stable', 'revision-x86-stable', 'x86_64', 'demo-x86.pkg.tar.zst', 'a'.repeat(64), 10,
      'build-arm-stable', 'revision-arm-stable', 'aarch64', 'demo-arm.pkg.tar.zst', 'b'.repeat(64), 10,
      'build-x86-dev', 'revision-x86-dev', 'x86_64', 'demo-dev.pkg.tar.zst', 'c'.repeat(64), 10,
    ).run();
    db.prepare('INSERT INTO releases VALUES(?,?,?,?,?,?,?,?,?,?,?), (?,?,?,?,?,?,?,?,?,?,?), (?,?,?,?,?,?,?,?,?,?,?)').bind(
      'release-x86-stable', 'build-x86-stable', 'demo', '1.0-1', 'x86_64', 'binary', 'stable', 3, 3, null, null,
      'release-arm-stable', 'build-arm-stable', 'demo', '1.0-1', 'aarch64', 'binary', 'stable', 3, 3, null, null,
      'release-x86-dev', 'build-x86-dev', 'demo', '1.1-1', 'x86_64', 'binary', 'dev', 4, null, null, null,
    ).run();
    db.prepare('INSERT INTO feedback VALUES(?,?,?,?,?), (?,?,?,?,?)').bind(
      'feedback-x86', 'release-x86-stable', 1, 'x86 feedback', 5,
      'feedback-arm', 'release-arm-stable', 1, 'ARM feedback', 5,
    ).run();

    const arm = await pageLoad(event(db, 'architecture=aarch64'));
    expect(arm.architecture).toBe('aarch64');
    expect(arm.architectures).toEqual(['x86_64', 'aarch64']);
    expect(arm.releases.map((release) => release.id)).toEqual(['release-arm-stable']);
    expect(arm.revisions.map((revision) => revision.id)).toEqual(['revision-arm-stable']);
    expect(arm.feedback.map((entry) => entry.comment)).toEqual(['ARM feedback']);

    const x86 = await pageLoad(event(db, 'architecture=x86_64'));
    expect(x86.architecture).toBe('x86_64');
    expect(x86.releases.map((release) => release.id)).toEqual(['release-x86-stable']);
    expect(x86.revisions.map((revision) => revision.id)).toEqual(['revision-x86-stable']);
    expect(x86.feedback.map((entry) => entry.comment)).toEqual(['x86 feedback']);

    const dev = await pageLoad(event(db, 'channel=dev&architecture=x86_64'));
    expect(dev.channel).toBe('dev');
    expect(dev.architecture).toBe('x86_64');
    expect(dev.releases.map((release) => release.id)).toEqual(['release-x86-dev']);
    expect(dev.revisions.map((revision) => revision.id)).toEqual(['revision-x86-dev']);
  } finally {
    db.close();
  }
});
