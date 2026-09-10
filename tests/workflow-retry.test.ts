import { expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import { runFactoryWithRecovery } from '../services/pipeline/workflow-retry';
import { runFactoryRepairLoop } from '../services/pipeline/workflow-retry';
import { reserveFactoryAttempt, startFactoryRun } from '../src/lib/server/factory-runs';
import { asD1, TestD1 } from './d1';

const repairPolicy = { network: 'disabled', checks: ['build', 'runtime'] };

const digest = (character: string) => character.repeat(64);

function repairDb() {
  return new TestD1(`CREATE TABLE builds(id TEXT PRIMARY KEY,revision_id TEXT,architecture TEXT,status TEXT,created_at INTEGER,UNIQUE(revision_id,architecture));
    ${readFileSync('migrations/0052_factory_runs.sql', 'utf8')}
    CREATE TABLE audit_events(actor TEXT,action TEXT,target TEXT,detail TEXT,created_at INTEGER);`);
}

test('factory workflow recovers transient resets in bounded durable steps before terminalizing', async () => {
  const calls: string[] = [];
  const sleeps: string[] = [];
  let attempts = 0;

  const step = {
    do: async <T>(name: string, _config: unknown, callback: () => Promise<T>) => {
      calls.push(name);

      return callback();
    },
    sleep: async (name: string) => { sleeps.push(name); },
  };

  const retryAudits: Array<[number, string]> = [];
  let terminal = '';

  const result = await runFactoryWithRecovery({
    step,
    generate: async () => {
      attempts += 1;

      if (attempts < 3) throw new Error('Durable Object reset because its code was updated.');

      return 'review-created';
    },
    onRetry: async (recovery, message) => { retryAudits.push([recovery, message]); },
    onTerminalFailure: async (message) => { terminal = message; },
  });

  expect(result).toBe('review-created');
  expect(calls).toEqual(['generate-and-open-review', 'generate-and-open-review-recovery-1', 'generate-and-open-review-recovery-2']);
  expect(sleeps).toEqual(['wait-for-factory-recovery-1', 'wait-for-factory-recovery-2']);
  expect(retryAudits).toHaveLength(2);
  expect(terminal).toBe('');
});

test('factory workflow terminalizes permanent failures without recovery sleep', async () => {
  const calls: string[] = [];
  const sleeps: string[] = [];
  let terminal = '';

  const step = {
    do: async <T>(name: string, _config: unknown, callback: () => Promise<T>) => { calls.push(name);

 return callback(); },
    sleep: async (name: string) => { sleeps.push(name); },
  };

  await expect(runFactoryWithRecovery({
    step,
    generate: async () => { throw new Error('vendor archive is empty'); },
    onRetry: async () => { throw new Error('unexpected recovery'); },
    onTerminalFailure: async (message) => { terminal = message; },
  })).rejects.toThrow('vendor archive is empty');
  expect(calls).toEqual(['generate-and-open-review']);
  expect(sleeps).toEqual([]);
  expect(terminal).toBe('vendor archive is empty');
});

test('factory repair loop reuses durable budget across ordinary failures', async () => {
  const db = repairDb();

  try {
    await startFactoryRun(asD1(db), { id: 'workflow-repair', targetKind: 'generated', targetId: 'request-1', unitKey: 'x86_64', policy: repairPolicy, createdBy: 'factory' });
    const attempts: number[] = [];

    const result = await runFactoryRepairLoop({
      db: asD1(db), runId: 'workflow-repair', policy: repairPolicy,
      prepare: async (attempt) => ({ candidateSha256: digest(String.fromCharCode(96 + attempt)), inputSha256: digest('b'), candidate: { attempt } }),
      execute: async (attempt) => { attempts.push(attempt.attempt);

 return attempt.attempt === 1 ? { status: 'failed' as const, failureKind: 'build' as const, failure: { message: 'compile' } } : { status: 'succeeded' as const, value: 'artifact-reused' }; },
    });

    expect(result).toBe('artifact-reused');
    expect(attempts).toEqual([1, 2]);
  } finally { db.close(); }
});

test('factory repair loop resumes a pre-dispatched attempt before opening repair budget', async () => {
  const db = repairDb();

  try {
    const run = await startFactoryRun(asD1(db), { id: 'workflow-pre-dispatched', targetKind: 'preserved', targetId: 'recipe-1', unitKey: 'x86_64', policy: repairPolicy, createdBy: 'factory' });
    const reserved = await reserveFactoryAttempt(asD1(db), {
      runId: run.id, reservationKey: 'attempt:1', candidateSha256: digest('a'), inputSha256: digest('b'), policy: repairPolicy,
    });
    const result = await runFactoryRepairLoop({
      db: asD1(db), runId: run.id, policy: repairPolicy, resumeRunningAttempt: 1,
      prepare: async () => ({ candidateSha256: digest('a'), inputSha256: digest('b') }),
      execute: async (attempt) => {
        expect(attempt.attempt).toBe(1);
        expect(attempt.leaseToken).toBe(reserved.leaseToken);
        return { status: 'succeeded' as const, value: 'pre-dispatched-success' };
      },
    });
    expect(result).toBe('pre-dispatched-success');
  } finally { db.close(); }
});

test('factory repair loop charges candidate preparation failures to same budget', async () => {
  const db = repairDb();

  try {
    await startFactoryRun(asD1(db), { id: 'workflow-preparation', targetKind: 'preserved', targetId: 'recipe-1', unitKey: 'x86_64', policy: repairPolicy, createdBy: 'factory' });
    const prepared: number[] = [];
    const executed: number[] = [];

    const result = await runFactoryRepairLoop({
      db: asD1(db), runId: 'workflow-preparation', policy: repairPolicy,
      prepare: async (attempt) => { prepared.push(attempt);

 if (attempt === 1) throw new Error('recipe validation failed');

 return { candidateSha256: digest('c'), inputSha256: digest('b') }; },
      execute: async (attempt) => { executed.push(attempt.attempt);

 return { status: 'succeeded' as const, value: 'ok' }; },
    });

    expect(result).toBe('ok');
    expect(prepared).toEqual([1, 2]);
    expect(executed).toEqual([2]);
  } finally { db.close(); }
});

test('factory repair loop restart feeds retained failure to next candidate', async () => {
  const db = repairDb();

  try {
    await startFactoryRun(asD1(db), { id: 'workflow-restart', targetKind: 'manual', targetId: 'recipe-2', unitKey: 'x86_64', policy: repairPolicy, createdBy: 'factory' });
    await expect(runFactoryRepairLoop({
      db: asD1(db), runId: 'workflow-restart', policy: repairPolicy,
      prepare: async () => ({ candidateSha256: digest('a'), inputSha256: digest('b') }),
      execute: async () => ({ status: 'failed' as const, failureKind: 'build' as const, failure: { message: 'compiler' } }),
      onRepair: async () => { throw new Error('workflow redelivery'); },
    })).rejects.toThrow('workflow redelivery');
    let feedback: unknown;

    const result = await runFactoryRepairLoop({
      db: asD1(db), runId: 'workflow-restart', policy: repairPolicy,
      prepare: async (_attempt, previousFailure) => { feedback = previousFailure;

 return { candidateSha256: digest('c'), inputSha256: digest('b') }; },
      execute: async () => ({ status: 'succeeded' as const, value: 'recovered' }),
    });

    expect(result).toBe('recovered');
    expect(feedback).toEqual({ message: 'compiler' });
  } finally { db.close(); }
});

test('factory repair loop stops after third failure without fourth execution', async () => {
  const db = repairDb();

  try {
    await startFactoryRun(asD1(db), { id: 'workflow-exhausted', targetKind: 'image', targetId: 'image-1', unitKey: 'x86_64', policy: repairPolicy, createdBy: 'factory' });
    let executions = 0;
    await expect(runFactoryRepairLoop({
      db: asD1(db), runId: 'workflow-exhausted', policy: repairPolicy,
      prepare: async (attempt) => ({ candidateSha256: digest(String.fromCharCode(96 + attempt)), inputSha256: digest('b') }),
      execute: async () => { executions += 1;

 return { status: 'failed' as const, failureKind: 'runtime' as const, failure: { message: 'smoke' } }; },
    })).rejects.toThrow('budget exhausted');
    expect(executions).toBe(3);
  } finally { db.close(); }
});
