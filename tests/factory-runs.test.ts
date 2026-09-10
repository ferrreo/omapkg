import { expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import { asD1, TestD1 } from './d1';
import {
  createFactorySuccessorRun,
  finishFactoryAttempt,
  getFactoryRun,
  reserveFactoryAttempt,
  reuseSuccessfulFactoryArtifact,
  startFactoryRun,
  stopFactoryRun,
} from '../src/lib/server/factory-runs';

const policy = { source: 'source-a', allowNetwork: false, checks: ['build', 'smoke'] };

const digest = (character: string) => character.repeat(64);

function database() {
  return new TestD1(`CREATE TABLE builds(id TEXT PRIMARY KEY,revision_id TEXT,architecture TEXT,status TEXT,created_at INTEGER,UNIQUE(revision_id,architecture));
    ${readFileSync('migrations/0052_factory_runs.sql', 'utf8')}
    CREATE TABLE audit_events(actor TEXT,action TEXT,target TEXT,detail TEXT,created_at INTEGER);`);
}

test('factory run reserves three total attempts and reuses successful output', async () => {
  const db = database();

  try {
    const run = await startFactoryRun(asD1(db), { id: 'run-repair', targetKind: 'generated', targetId: 'request-1', unitKey: 'x86_64', policy, createdBy: 'maintainer' });
    const first = await reserveFactoryAttempt(asD1(db), { runId: run.id, reservationKey: 'attempt-1', candidateSha256: digest('a'), inputSha256: digest('b'), policy });
    await finishFactoryAttempt(asD1(db), run.id, first.attempt, first.leaseToken, { status: 'failed', failureKind: 'build', failure: { message: 'compile' } });
    const second = await reserveFactoryAttempt(asD1(db), { runId: run.id, reservationKey: 'attempt-2', candidateSha256: digest('c'), inputSha256: digest('b'), policy });
    await finishFactoryAttempt(asD1(db), run.id, second.attempt, second.leaseToken, { status: 'failed', failureKind: 'runtime', failure: { message: 'smoke' } });
    const third = await reserveFactoryAttempt(asD1(db), { runId: run.id, reservationKey: 'attempt-3', candidateSha256: digest('d'), inputSha256: digest('b'), policy });
    await finishFactoryAttempt(asD1(db), run.id, third.attempt, third.leaseToken, { status: 'succeeded', artifact: { buildId: 'build-3', sha256: digest('e') } });
    expect((await getFactoryRun(asD1(db), run.id))?.status).toBe('succeeded');
    expect((await reuseSuccessfulFactoryArtifact(asD1(db), run.id, { candidateSha256: digest('d'), inputSha256: digest('b') }))?.attempt).toBe(3);
    expect(() => db.prepare("UPDATE factory_runs SET artifact_json='{}' WHERE id=?").bind(run.id).run()).toThrow('completed factory run evidence');
    expect(() => db.prepare("UPDATE factory_run_attempts SET artifact_json='{}' WHERE run_id=? AND attempt=3").bind(run.id).run()).toThrow('completed factory attempt evidence');
    expect((await startFactoryRun(asD1(db), { targetKind: 'generated', targetId: 'request-1', unitKey: 'x86_64', policy, createdBy: 'retry-endpoint' })).id).toBe(run.id);
    await expect(reserveFactoryAttempt(asD1(db), { runId: run.id, reservationKey: 'attempt-4', candidateSha256: digest('f'), inputSha256: digest('b'), policy })).rejects.toThrow('successful artifact');
  } finally { db.close(); }
});

test('third failed attempt closes budget and blocks fourth reservation', async () => {
  const db = database();

  try {
    const run = await startFactoryRun(asD1(db), { id: 'run-exhausted', targetKind: 'image', targetId: 'image-1', unitKey: 'aarch64', policy, createdBy: 'factory' });

    for (const attempt of [1, 2, 3]) {
      const reserved = await reserveFactoryAttempt(asD1(db), { runId: run.id, reservationKey: `attempt-${attempt}`, candidateSha256: digest(String.fromCharCode(96 + attempt)), inputSha256: digest('b'), policy });
      await finishFactoryAttempt(asD1(db), run.id, reserved.attempt, reserved.leaseToken, { status: 'failed', failureKind: 'build', failure: { attempt } });
    }

    await expect(reserveFactoryAttempt(asD1(db), { runId: run.id, reservationKey: 'attempt-4', candidateSha256: digest('d'), inputSha256: digest('b'), policy })).rejects.toMatchObject({ code: 'budget-exhausted' });
    expect((await getFactoryRun(asD1(db), run.id))?.attemptCount).toBe(3);
  } finally { db.close(); }
});

test('policy expansion stops a run before another build', async () => {
  const db = database();

  try {
    const run = await startFactoryRun(asD1(db), { id: 'run-policy', targetKind: 'manual', targetId: 'recipe-1', unitKey: 'x86_64', policy, createdBy: 'maintainer' });
    await expect(reserveFactoryAttempt(asD1(db), { runId: run.id, reservationKey: 'attempt-1', candidateSha256: digest('a'), inputSha256: digest('b'), policy: { ...policy, allowNetwork: true } })).rejects.toMatchObject({ code: 'policy-stop' });
    expect((await getFactoryRun(asD1(db), run.id))?.status).toBe('needs-human-intervention');
  } finally { db.close(); }
});

test('reservation redelivery is idempotent and stale lease is fenced', async () => {
  const db = database();

  try {
    const run = await startFactoryRun(asD1(db), { id: 'run-race', targetKind: 'cohort', targetId: 'cohort-1', unitKey: 'member:x86_64', policy, createdBy: 'coordinator' });
    const first = await reserveFactoryAttempt(asD1(db), { runId: run.id, reservationKey: 'same-key', candidateSha256: digest('a'), inputSha256: digest('b'), policy });
    const replay = await reserveFactoryAttempt(asD1(db), { runId: run.id, reservationKey: 'same-key', candidateSha256: digest('a'), inputSha256: digest('b'), policy });
    expect(replay.id).toBe(first.id);
    await expect(finishFactoryAttempt(asD1(db), run.id, first.attempt, 'stale-token', { status: 'failed', failureKind: 'build', failure: { message: 'stale' } })).rejects.toMatchObject({ code: 'lease-fenced' });
    await stopFactoryRun(asD1(db), run.id, 'human cancelled ambiguous execution');
    await expect(startFactoryRun(asD1(db), { targetKind: 'cohort', targetId: 'cohort-1', unitKey: 'member:x86_64', policy, createdBy: 'retry-endpoint' })).rejects.toMatchObject({ code: 'human-intervention' });
    const successor = await createFactorySuccessorRun(asD1(db), run.id, { id: 'run-race-successor', targetKind: 'cohort', targetId: 'cohort-1', unitKey: 'member:x86_64', policy, createdBy: 'human' });
    expect(successor.sourceRunId).toBe(run.id);
  } finally { db.close(); }
});
