import { expect, test } from 'bun:test';
import { checkSourceOfTruth } from '../services/pipeline/integrity';
import { asD1, TestD1 } from './d1';

const schema = `
CREATE TABLE requests(
  id TEXT PRIMARY KEY,name TEXT NOT NULL,upstream_url TEXT NOT NULL,source_kind TEXT NOT NULL,
  area TEXT NOT NULL,declared_license TEXT NOT NULL,requested_by TEXT NOT NULL,status TEXT NOT NULL,
  created_at INTEGER NOT NULL,updated_at INTEGER NOT NULL,rejection_reason TEXT
);
CREATE TABLE revisions(
  id TEXT PRIMARY KEY,request_id TEXT NOT NULL,version TEXT NOT NULL,recipe TEXT NOT NULL,recipe_sha256 TEXT NOT NULL,
  manifest_sha256 TEXT NOT NULL,sources_json TEXT NOT NULL,dependencies_json TEXT NOT NULL,make_dependencies_json TEXT NOT NULL,
  smoke_commands_json TEXT NOT NULL,architectures_json TEXT NOT NULL,build_images_json TEXT NOT NULL,pkgrel INTEGER NOT NULL,
  source_date_epoch INTEGER NOT NULL,image_digest TEXT NOT NULL,license TEXT NOT NULL,surface TEXT NOT NULL,description TEXT,explanation TEXT NOT NULL,
  public_recipe TEXT,public_recipe_sha256 TEXT,
  lint_json TEXT NOT NULL,sbom_json TEXT NOT NULL,upstream_commit TEXT,pr_url TEXT,commit_sha TEXT,created_at INTEGER NOT NULL
);
CREATE TABLE builds(id TEXT PRIMARY KEY,revision_id TEXT NOT NULL,status TEXT NOT NULL,error TEXT);
CREATE TABLE approvals(id TEXT PRIMARY KEY,revision_id TEXT NOT NULL,kind TEXT NOT NULL,manifest_sha256 TEXT NOT NULL,revoked_at INTEGER,revoked_by TEXT);
CREATE TABLE factory_events(id INTEGER PRIMARY KEY AUTOINCREMENT,request_id TEXT NOT NULL,stage TEXT NOT NULL,detail TEXT NOT NULL,created_at INTEGER NOT NULL);
CREATE TABLE audit_events(id INTEGER PRIMARY KEY AUTOINCREMENT,actor TEXT NOT NULL,action TEXT NOT NULL,target TEXT NOT NULL,detail TEXT NOT NULL,created_at INTEGER NOT NULL);
`;

type RevisionSeed = {
  id: string;
  requestId: string;
  version: string;
  createdAt: number;
};

function encode(value: string): string {
  return btoa(String.fromCharCode(...new TextEncoder().encode(value)));
}

function manifest(revision: RevisionSeed): Record<string, unknown> {
  return {
    requestId: revision.requestId,
    packageName: 'demo',
    version: revision.version,
    sourceKind: 'archive',
    sources: [],
    dependencies: [],
    makeDependencies: [],
    smokeCommands: [],
    architectures: ['x86_64'],
    buildImages: {},
    pkgrel: 1,
    sourceDateEpoch: 1_700_000_000,
    imageDigest: `registry.example/demo@sha256:${'a'.repeat(64)}`,
    license: 'MIT',
    surface: 'binary',
    publicRecipeSha256: null,
  };
}

function filesFor(revision: RevisionSeed): Record<string, string> {
  return {
    'packages/demo/PKGBUILD': 'pkgname=demo\n',
    'packages/demo/opr-manifest.json': `${JSON.stringify(manifest(revision), null, 2)}\n`,
    'packages/demo/opr-lint.json': '{"passed":true}\n',
    'packages/demo/opr-sbom.json': '{}\n',
  };
}

function seedRevision(db: TestD1, request: RevisionSeed): void {
  db.prepare(`INSERT INTO requests(
    id,name,upstream_url,source_kind,area,declared_license,requested_by,status,created_at,updated_at,rejection_reason
  ) VALUES(?,?,?,?,?,?,?,'built',?,?,NULL)`).bind(
    request.requestId, 'demo', 'https://example.test/demo.tar.gz', 'archive', 'development', 'unknown', 'github:1', request.createdAt, request.createdAt,
  ).run();
  db.prepare(`INSERT INTO revisions(
    id,request_id,version,recipe,recipe_sha256,manifest_sha256,sources_json,dependencies_json,make_dependencies_json,
    smoke_commands_json,architectures_json,build_images_json,pkgrel,source_date_epoch,image_digest,license,surface,explanation,
    lint_json,sbom_json,upstream_commit,pr_url,commit_sha,created_at
  ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).bind(
    request.id, request.requestId, request.version, 'pkgname=demo\n', 'recipe-hash', 'manifest-hash', '[]', '[]', '[]',
    '[]', '["x86_64"]', '{}', 1, 1_700_000_000, `registry.example/demo@sha256:${'a'.repeat(64)}`, 'MIT', 'binary', '',
    '{"passed":true}', '{}', null, 'https://github.com/owner/recipes/pull/1', `${request.id.padEnd(40, 'c').slice(0, 40)}`, request.createdAt,
  ).run();
  db.prepare('INSERT INTO builds(id,revision_id,status) VALUES(?,?,?)').bind(`build-${request.id}`, request.id, 'succeeded').run();
  for (const kind of ['area', 'security']) {
    db.prepare('INSERT INTO approvals(id,revision_id,kind,manifest_sha256,revoked_at,revoked_by) VALUES(?,?,?,?,NULL,NULL)')
      .bind(`${kind}-${request.id}`, request.id, kind, 'manifest-hash').run();
  }
}

function sourceOfTruthEnv(db: TestD1) {
  return {
    DB: asD1(db),
    ARTIFACTS: {} as R2Bucket,
    GITHUB_REPOSITORY: 'owner/recipes',
    GITHUB_REPO_TOKEN: 'github_pat_test',
  };
}

test('source-of-truth checks only the latest eligible published revision per package', async () => {
  const db = new TestD1(schema);
  const oldRevision = { id: 'revision-old', requestId: 'request-old', version: '1.0.0', createdAt: 1 };
  const newRevision = { id: 'revision-new', requestId: 'request-new', version: '2.0.0', createdAt: 2 };
  seedRevision(db, oldRevision);
  seedRevision(db, newRevision);
  const files = filesFor(newRevision);
  const requestedPaths: string[] = [];
  const previousFetch = globalThis.fetch;
  globalThis.fetch = (async (input) => {
    const url = new URL(String(input));
    if (url.pathname === '/repos/owner/recipes') return Response.json({ default_branch: 'main' });
    if (url.pathname === '/repos/owner/recipes/branches/main') return Response.json({ commit: { sha: 'd'.repeat(40) } });
    const prefix = '/repos/owner/recipes/contents/';
    if (!url.pathname.startsWith(prefix)) return new Response('unexpected', { status: 500 });
    const path = decodeURIComponent(url.pathname.slice(prefix.length));
    requestedPaths.push(path);
    const value = files[path];
    return value === undefined ? new Response('missing', { status: 404 }) : Response.json({ type: 'file', encoding: 'base64', content: encode(value) });
  }) as typeof globalThis.fetch;
  try {
    const result = await checkSourceOfTruth(sourceOfTruthEnv(db));
    expect(result).toMatchObject({ checked: 1, passed: true, issues: [], frozenRequestIds: [] });
    expect(requestedPaths.sort()).toEqual(Object.keys(files).sort());
  } finally {
    globalThis.fetch = previousFetch;
    db.close();
  }
});

test('source-of-truth checks still report a manual tamper on the latest revision', async () => {
  const db = new TestD1(schema);
  const oldRevision = { id: 'revision-old', requestId: 'request-old', version: '1.0.0', createdAt: 1 };
  const newRevision = { id: 'revision-new', requestId: 'request-new', version: '2.0.0', createdAt: 2 };
  seedRevision(db, oldRevision);
  seedRevision(db, newRevision);
  const files = filesFor(newRevision);
  files['packages/demo/PKGBUILD'] = 'pkgname=changed\n';
  const previousFetch = globalThis.fetch;
  globalThis.fetch = (async (input) => {
    const url = new URL(String(input));
    if (url.pathname === '/repos/owner/recipes') return Response.json({ default_branch: 'main' });
    if (url.pathname === '/repos/owner/recipes/branches/main') return Response.json({ commit: { sha: 'd'.repeat(40) } });
    const path = decodeURIComponent(url.pathname.split('/contents/')[1] ?? '');
    return Response.json({ type: 'file', encoding: 'base64', content: encode(files[path] ?? '') });
  }) as typeof globalThis.fetch;
  try {
    const result = await checkSourceOfTruth(sourceOfTruthEnv(db));
    expect(result.checked).toBe(1);
    expect(result.passed).toBe(false);
    expect(result.issues).toEqual([expect.objectContaining({ revisionId: 'revision-new', requestId: 'request-new', frozen: false })]);
    expect(result.issues[0]?.paths).toEqual(['packages/demo/PKGBUILD']);
    expect(db.prepare("SELECT target FROM audit_events WHERE action='source_of_truth.integrity_failed'").first<{ target: string }>())
      .toEqual({ target: 'request-new' });
  } finally {
    globalThis.fetch = previousFetch;
    db.close();
  }
});
