import { expect, test } from 'bun:test';
import { runFactoryWithRecovery } from '../services/pipeline/workflow-retry';

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
    do: async <T>(name: string, _config: unknown, callback: () => Promise<T>) => { calls.push(name); return callback(); },
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
