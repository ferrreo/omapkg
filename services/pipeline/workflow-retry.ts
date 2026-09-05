export const MAX_TRANSIENT_RECOVERIES = 2;

export interface FactoryRecoveryStep {
  do<T>(name: string, config: {
    retries: { limit: number; delay: string; backoff: 'exponential' };
    timeout: string;
  }, callback: () => Promise<T>): Promise<T>;
  sleep(name: string, duration: string): Promise<void>;
}

export function isTransientFactoryFailure(message: string): boolean {
  return /durable object reset because its code was updated/i.test(message);
}

export function factoryRecoveryAction(message: string, recovery: number): 'retry' | 'failed' {
  return isTransientFactoryFailure(message) && recovery < MAX_TRANSIENT_RECOVERIES ? 'retry' : 'failed';
}

export async function runFactoryWithRecovery<T>(input: {
  step: FactoryRecoveryStep;
  generate: () => Promise<T>;
  onRetry: (recovery: number, message: string) => Promise<void>;
  onTerminalFailure: (message: string) => Promise<void>;
}): Promise<T> {
  let lastError: unknown;
  for (let recovery = 0; recovery <= MAX_TRANSIENT_RECOVERIES; recovery += 1) {
    const stepName = recovery === 0 ? 'generate-and-open-review' : `generate-and-open-review-recovery-${recovery}`;
    try {
      return await input.step.do(stepName, {
        retries: { limit: 2, delay: '1 minute', backoff: 'exponential' },
        timeout: '30 minutes',
      }, input.generate);
    } catch (cause) {
      lastError = cause;
      const message = cause instanceof Error ? cause.message : 'factory failed';
      if (factoryRecoveryAction(message, recovery) === 'retry') {
        await input.onRetry(recovery, message);
        await input.step.sleep(`wait-for-factory-recovery-${recovery + 1}`, '1 minute');
        continue;
      }
      await input.onTerminalFailure(message);
      throw cause;
    }
  }
  throw lastError instanceof Error ? lastError : new Error('factory failed');
}
