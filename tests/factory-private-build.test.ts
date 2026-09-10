import { expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import { asD1, TestD1 } from './d1';
import { queuePrivateFactoryBuilds, privateFactoryBuildResult } from '../src/lib/server/factory-private-build';
import { finishFactoryAttempt, reserveFactoryAttempt, startFactoryRun } from '../src/lib/server/factory-runs';

const digest = (value: string) => value.repeat(64);

function database() {
  return new TestD1(`CREATE TABLE builds(
    id TEXT PRIMARY KEY,revision_id TEXT,architecture TEXT,status TEXT,created_at INTEGER,error TEXT,
    artifact_key TEXT,artifact_sha256 TEXT,artifact_size INTEGER,artifact_filename TEXT,input_lock_sha256 TEXT,dependency_plan_json TEXT,output_contract_json TEXT,
    UNIQUE(revision_id,architecture));
    CREATE TABLE revisions(id TEXT PRIMARY KEY,surface TEXT,request_id TEXT);
    CREATE TABLE build_artifacts(build_id TEXT,attempt INTEGER,filename TEXT,artifact_key TEXT,sha256 TEXT,size INTEGER);
    CREATE TABLE audit_events(actor TEXT,action TEXT,target TEXT,detail TEXT,created_at INTEGER);
    ${readFileSync('migrations/0052_factory_runs.sql', 'utf8')}`);
}

test('private queue is idempotent and split outputs are retained', async () => {
  const db = database();

  try {
    const env = { DB: asD1(db) };
    const policy = { network: 'disabled', input: 'locked' };
    const run = await startFactoryRun(env.DB, { id: 'private-build-run', targetKind: 'generated', targetId: 'request', unitKey: 'request', policy, createdBy: 'factory' });
    const attempt = await reserveFactoryAttempt(env.DB, { runId: run.id, reservationKey: 'attempt:1', candidateSha256: digest('a'), inputSha256: digest('b'), candidateRevisionId: 'revision', policy });
    const revision = { id: 'revision', architectures_json: '["x86_64","aarch64"]' } as const;
    db.prepare("INSERT INTO revisions(id,surface) VALUES('revision','binary')").run();
    const [first, second] = await Promise.all([queuePrivateFactoryBuilds(env, run.id, attempt, revision), queuePrivateFactoryBuilds(env, run.id, attempt, revision)]);
    expect(second).toEqual(first);
    const x86 = first.find((build) => build.architecture === 'x86_64')!;
    db.prepare("UPDATE builds SET status='succeeded',artifact_key='primary',artifact_sha256=?,artifact_size=1,artifact_filename='primary.pkg.tar.zst',input_lock_sha256=? WHERE id=?").bind(digest('c'), digest('d'), x86.id).run();
    db.prepare("UPDATE builds SET status='succeeded' WHERE id<>? AND factory_run_id=?").bind(x86.id, run.id).run();
    const missing = await privateFactoryBuildResult(env, run.id, 1, first.map((build) => build.id));
    expect(missing.status).toBe('failed');
    expect(missing.failure?.architecture).toBe('aarch64');

    for (const build of first) db.prepare('INSERT INTO build_artifacts(build_id,attempt,filename,artifact_key,sha256,size) VALUES(?,?,?,?,?,?)').bind(build.id, 1, `${build.architecture}.pkg.tar.zst`, `${build.id}/split`, digest('e'), 1).run();
    const result = await privateFactoryBuildResult(env, run.id, 1, first.map((build) => build.id));
    expect(result.status).toBe('succeeded');
    expect(result.artifacts).toHaveLength(2);
    await finishFactoryAttempt(env.DB, run.id, 1, attempt.leaseToken, { status: 'succeeded', artifact: result });
  } finally { db.close(); }
});

test('failed private attempt cancels sibling queued builds before repair', async () => {
  const db = database();

  try {
    const env = { DB: asD1(db) };
    const policy = { network: 'disabled' };
    const run = await startFactoryRun(env.DB, { id: 'private-fail-run', targetKind: 'image', targetId: 'image', unitKey: 'x86_64', policy, createdBy: 'factory' });
    const attempt = await reserveFactoryAttempt(env.DB, { runId: run.id, reservationKey: 'attempt:1', candidateSha256: digest('a'), inputSha256: digest('b'), candidateRevisionId: 'revision', policy });
    db.prepare("INSERT INTO revisions(id,surface) VALUES('revision','binary')").run();
    const builds = await queuePrivateFactoryBuilds(env, run.id, attempt, { id: 'revision', architectures_json: '["x86_64","aarch64"]' });
    await finishFactoryAttempt(env.DB, run.id, 1, attempt.leaseToken, { status: 'failed', failureKind: 'build', failure: { message: 'compile' } });
    expect(db.prepare(`SELECT COUNT(*) AS count FROM builds WHERE factory_run_id=? AND status='cancelled'`).bind(run.id).first<{ count: number }>()?.count).toBe(builds.length);
  } finally { db.close(); }
});

test('recipe-only private target succeeds without retained binary outputs', async () => {
  const db = database();

  try {
    const env = { DB: asD1(db) };
    const policy = { network: 'disabled' };
    db.prepare("INSERT INTO revisions(id,surface) VALUES('recipe-revision','recipe')").run();
    const run = await startFactoryRun(env.DB, { id: 'private-recipe-run', targetKind: 'preserved', targetId: 'recipe', unitKey: 'x86_64', policy, createdBy: 'factory' });
    const attempt = await reserveFactoryAttempt(env.DB, { runId: run.id, reservationKey: 'attempt:1', candidateSha256: digest('a'), inputSha256: digest('b'), candidateRevisionId: 'recipe-revision', policy });
    const builds = await queuePrivateFactoryBuilds(env, run.id, attempt, { id: 'recipe-revision', architectures_json: '["x86_64"]' });
    db.prepare("UPDATE builds SET status='succeeded' WHERE id=?").bind(builds[0].id).run();
    const result = await privateFactoryBuildResult(env, run.id, 1, builds.map((build) => build.id));
    expect(result.status).toBe('succeeded');
    expect(result.artifacts).toEqual([]);
  } finally { db.close(); }
});
