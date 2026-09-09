import { expect, test } from 'bun:test';
import { readFileSync, readdirSync } from 'node:fs';
import { asD1, TestD1 } from './d1';
import { blockerStatements, getDependencyBlockers, linkDependencyRequest, parseDependencyBlockers, resolveDependencyBlockers } from '../src/lib/server/dependency-blockers';
import type { Env } from '../src/lib/server/env';

const files = readdirSync(new URL('../migrations', import.meta.url)).filter((name) => name.endsWith('.sql')).sort();
const migration = (name: string) => readFileSync(new URL(`../migrations/${name}`, import.meta.url), 'utf8');
const allSchema = files.map(migration).join('\n');
const maintainer = { id: 'github:1', role: 'maintainer' as const, areas: ['development'] };

function request(db: TestD1, id: string) {
  db.prepare(`INSERT INTO requests(id,name,upstream_url,source_kind,area,requested_by,status,created_at,updated_at,factory_run_id)
    VALUES(?,?,?,'git','development','github:1','generating',1,1,?)`).bind(id, id, `https://example.org/${id}.git`, `generation-${id}`).run();
}

async function block(db: TestD1, id: string, relation: string) {
  await asD1(db).batch(await blockerStatements(asD1(db), { requestId: id, scopeId: `generation-${id}`, revisionId: null, architecture: 'x86_64', timestamp: 2 },
    parseDependencyBlockers([{ relation, phase: 'factory', resolution: 'dependency', detail: `Missing ${relation}` }]), 'factory'));
  return (await getDependencyBlockers(asD1(db), id))[0];
}

test('blocked-state migration preserves referenced request data with foreign keys enabled', () => {
  const db = new TestD1(files.filter((file) => file < '0027').map(migration).join('\n'));
  try {
    db.exec('PRAGMA foreign_keys=ON');
    request(db, 'parent');
    db.prepare('INSERT INTO upstream_checks(request_id,last_version) VALUES(?,?)').bind('parent', '1.0').run();
    db.exec(`BEGIN; ${migration('0027_dependency_blockers.sql')} COMMIT;`);
    expect(db.prepare('SELECT name FROM requests WHERE id=?').bind('parent').first<Record<string, unknown>>()).toEqual({ name: 'parent' });
    expect(db.prepare('SELECT last_version FROM upstream_checks WHERE request_id=?').bind('parent').first<Record<string, unknown>>()).toEqual({ last_version: '1.0' });
    expect(db.prepare('PRAGMA foreign_key_check').all().results).toEqual([]);
    db.prepare("UPDATE requests SET status='blocked' WHERE id=?").bind('parent').run();
    expect(() => db.prepare('INSERT INTO upstream_checks(request_id) VALUES(?)').bind('missing').run()).toThrow();
  } finally { db.close(); }
});

test('factory detection blocks only its own generation; admission needs a maintainer and rejects cycles', async () => {
  const db = new TestD1(allSchema);
  const env = { DB: asD1(db) } as Env;
  try {
    request(db, 'parent');
    const parent = await block(db, 'parent', 'child>=2');
    expect(db.prepare('SELECT status FROM requests WHERE id=?').bind('parent').first<Record<string, unknown>>()).toEqual({ status: 'blocked' });
    expect(db.prepare('SELECT count(*) AS count FROM requests').first<Record<string, unknown>>()).toEqual({ count: 1 });
    expect(() => parseDependencyBlockers([{ relation: 'child', phase: 'factory', resolution: 'dependency', detail: 'x', upstream_url: 'https://attacker.invalid' }])).toThrow();
    request(db, 'child');
    const child = await block(db, 'child', 'parent');
    await expect(linkDependencyRequest(env, { id: 'github:9', role: 'public', areas: [] }, 'parent', parent.id, 'child')).rejects.toMatchObject({ status: 403 });
    await linkDependencyRequest(env, maintainer, 'parent', parent.id, 'child');
    await expect(linkDependencyRequest(env, maintainer, 'child', child.id, 'parent')).rejects.toThrow('cycle');
    await asD1(db).batch(await blockerStatements(asD1(db), { requestId: 'parent', scopeId: 'stale-generation', revisionId: null, architecture: 'x86_64', timestamp: 3 },
      [{ relation: 'injected', phase: 'factory', resolution: 'dependency', detail: 'stale' }], 'factory'));
    expect((await getDependencyBlockers(asD1(db), 'parent')).length).toBe(1);
    await resolveDependencyBlockers(env);
    expect(db.prepare('SELECT status FROM requests WHERE id=?').bind('parent').first<Record<string, unknown>>()).toEqual({ status: 'blocked' });
  } finally { db.close(); }
});

test('simultaneous dependency links cannot introduce a cycle and depth budget checks ancestors', async () => {
  const db = new TestD1(allSchema);
  const env = { DB: asD1(db) } as Env;
  try {
    request(db, 'left'); request(db, 'right');
    const left = await block(db, 'left', 'right');
    const right = await block(db, 'right', 'left');
    const results = await Promise.allSettled([
      linkDependencyRequest(env, maintainer, 'left', left.id, 'right'),
      linkDependencyRequest(env, maintainer, 'right', right.id, 'left'),
    ]);
    expect(results.filter((result) => result.status === 'fulfilled').length).toBe(1);
    expect(db.prepare('SELECT count(*) AS count FROM dependency_blockers WHERE dependency_request_id IS NOT NULL').first<Record<string, unknown>>()).toEqual({ count: 1 });
    const chain = [];
    for (let index = 0; index < 9; index++) {
      request(db, `node-${index}`);
      chain.push(await block(db, `node-${index}`, `node-${index + 1}`));
    }
    for (let index = 0; index < 7; index++) await linkDependencyRequest(env, maintainer, `node-${index}`, chain[index].id, `node-${index + 1}`);
    await expect(linkDependencyRequest(env, maintainer, 'node-7', chain[7].id, 'node-8')).rejects.toThrow('8 levels');
  } finally { db.close(); }
});

test('resolution requires matching version, architecture and approvals and returns parent to review only', async () => {
  const db = new TestD1(allSchema);
  const env = { DB: asD1(db) } as Env;
  try {
    request(db, 'parent'); request(db, 'provider');
    await block(db, 'parent', 'library>=2');
    db.exec(`INSERT INTO revisions(id,request_id,version,recipe,recipe_sha256,manifest_sha256,sources_json,dependencies_json,smoke_commands_json,architectures_json,source_date_epoch,image_digest,license,surface,explanation,sbom_json,lint_json,created_at)
      VALUES('revision','provider','1','recipe','hash','manifest','[]','[]','[]','["x86_64"]',1,'image','MIT','binary','','{}','{}',1);
      INSERT INTO builds(id,revision_id,architecture,status,created_at) VALUES('build','revision','x86_64','succeeded',1);
      INSERT INTO releases(id,build_id,name,version,architecture,surface,channel,signature_key,recipe_key,sbom_key,provenance_key,artifact_key,published_at) VALUES('release','build','library','1-1','aarch64','binary','dev','signature','recipe','sbom','provenance','artifact',1);`);
    const metadata = { name: 'library', fullVersion: '1-1', architecture: 'x86_64', installedSize: 1, depends: [], provides: [], conflicts: [], replaces: [] };
    const updateMetadata = () => db.prepare('UPDATE builds SET provenance=?').bind(JSON.stringify({ packageMetadata: metadata })).run();
    updateMetadata();
    await resolveDependencyBlockers(env);
    expect((await getDependencyBlockers(asD1(db), 'parent'))[0].status).toBe('open');
    db.exec("INSERT INTO approvals(id,revision_id,actor,kind,manifest_sha256,created_at) VALUES('a','revision','area','area','manifest',1),('s','revision','security','security','manifest',1)");
    metadata.fullVersion = '2-1'; updateMetadata();
    await resolveDependencyBlockers(env);
    expect((await getDependencyBlockers(asD1(db), 'parent'))[0].status).toBe('open');
    db.exec("UPDATE releases SET architecture='x86_64'");
    await resolveDependencyBlockers(env);
    expect((await getDependencyBlockers(asD1(db), 'parent'))[0].status).toBe('resolved');
    expect(db.prepare("SELECT status FROM requests WHERE id='parent'").first<Record<string, unknown>>()).toEqual({ status: 'pending' });
    expect(db.prepare("SELECT count(*) AS n FROM approvals WHERE revision_id IN (SELECT id FROM revisions WHERE request_id='parent')").first<Record<string, unknown>>()).toEqual({ n: 0 });
  } finally { db.close(); }
});
