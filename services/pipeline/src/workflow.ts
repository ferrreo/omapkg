import { WorkflowEntrypoint, type WorkflowEvent, type WorkflowStep } from 'cloudflare:workers';
import { factoryEndpoint, type FactoryRunResult } from '../../../src/lib/server/factory';
import { audit, now } from '../../../src/lib/server/db';
import { PackageFactory } from './factory-agent';
import { runFactoryWithRecovery } from '../workflow-retry';
import type { FactoryEnv } from '../types';
import type { FactoryWorkflowParams, PipelineEnv } from '../types';

function requestForFactory(params: FactoryWorkflowParams): Request {
  return new Request('https://pipeline.internal/factory', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(params),
  });
}

export class FactoryWorkflow extends WorkflowEntrypoint<PipelineEnv, FactoryWorkflowParams> {
  async run(event: Readonly<WorkflowEvent<FactoryWorkflowParams>>, step: WorkflowStep): Promise<FactoryRunResult> {
    return runFactoryWithRecovery({
      step: step as unknown as Parameters<typeof runFactoryWithRecovery<FactoryRunResult>>[0]['step'],
      generate: async () => {
        const response = await factoryEndpoint(requestForFactory(event.payload), this.env as unknown as FactoryEnv, PackageFactory);
        const body = await response.json() as Partial<FactoryRunResult> & { error?: string };
        if (!response.ok || typeof body.revisionId !== 'string' || typeof body.pullRequestUrl !== 'string') {
          throw new Error(typeof body.error === 'string' ? body.error.slice(0, 1_000) : 'factory run failed');
        }
        return body as FactoryRunResult;
      },
      onRetry: async (recovery, message) => {
        await audit(this.env.DB, 'factory-workflow', 'factory.retryable_failure', event.payload.requestId, {
          generationId: event.payload.generationId,
          recovery,
          message: message.slice(0, 1_000),
        }).run();
      },
      onTerminalFailure: async (message) => {
        await this.env.DB.batch([
          this.env.DB.prepare("UPDATE requests SET status='failed',updated_at=? WHERE id=? AND status='generating' AND factory_run_id=?")
            .bind(now(), event.payload.requestId, event.payload.generationId ?? ''),
          audit(this.env.DB, 'factory-workflow', 'factory.failed', event.payload.requestId, {
            generationId: event.payload.generationId,
            message: message.slice(0, 1_000),
          }),
        ]);
      },
    });
  }
}
