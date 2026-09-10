import { WorkflowEntrypoint, type WorkflowEvent, type WorkflowStep } from 'cloudflare:workers';
import { factoryEndpoint, type FactoryRunResult, type FactoryOutcome } from '../../../src/lib/server/factory';
import { audit, now } from '../../../src/lib/server/db';
import { PackageFactory, PreservedRepairFactory } from './factory-agent';
import { runFactoryRepairLoop, runFactoryWithRecovery } from '../workflow-retry';
import { FactoryPolicyStopError, getFactoryAttempt, getFactoryRun, stopFactoryRun } from '../../../src/lib/server/factory-runs';
import { privateFactoryBuildResult, queuePrivateFactoryBuilds } from '../../../src/lib/server/factory-private-build';
import { createFactoryPullRequest } from '../../../services/pipeline/github-pr';
import { persistFactoryRevision } from '../../../services/pipeline/revision';
import { createPreservedSuccessorDraft, runPreservedRepair } from '../../../src/lib/server/preserved-factory';
import { canonicalJson } from '../../../src/lib/canonical-json';
import type { Revision } from '../../../src/lib/model';
import { preservedRecipe } from '../../../src/lib/preserved-recipe';
import { sha256 } from '../../../src/lib/server/db';
import type { FactoryEnv } from '../types';
import type { FactoryWorkflowParams, PipelineEnv } from '../types';

function requestForFactory(params: FactoryWorkflowParams): Request {
  return new Request('https://pipeline.internal/factory', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(params),
  });
}

async function revisionForUnit(env: PipelineEnv, revisionId: string): Promise<Revision> {
  const revision = await env.DB.prepare('SELECT * FROM revisions WHERE id=?').bind(revisionId).first<Revision>();
  if (!revision) throw new Error('factory unit revision is missing');
  return revision;
}

async function runFactoryUnit(params: FactoryWorkflowParams, env: PipelineEnv, step: WorkflowStep) {
  if (!params.factoryRunId || !params.attempt || !params.buildIds?.length) throw new Error('factory unit workflow identity is incomplete');
  const run = await getFactoryRun(env.DB, params.factoryRunId);
  if (!run) throw new Error('factory unit run is missing');
  const prepared = new Map<number, Revision>();
  const initial = await revisionForUnit(env, params.revisionId ?? '');
  prepared.set(1, initial);

  const value = await runFactoryRepairLoop({
    db: env.DB,
    runId: params.factoryRunId,
    policy: run.policy,
    prepare: async (attempt, previousFailure) => {
      let revision = prepared.get(attempt);
      if (!revision) {
        const parent = prepared.get(attempt - 1) ?? await revisionForUnit(env, (await getFactoryAttempt(env.DB, params.factoryRunId!, attempt - 1))?.candidateRevisionId ?? '');
        let preserved = false;
        try { preserved = Boolean(preservedRecipe(parent)); } catch { /* validation below stops the run */ }
        if (!preserved) throw new FactoryPolicyStopError('Automatic repair is only enabled for preserved recipe units.');
        const finding = `${params.repairReason ? `Human guidance: ${params.repairReason}\n` : ''}${JSON.stringify(previousFailure ?? { message: 'private preserved build failed' })}`.slice(0, 2_000);
        const repair = await runPreservedRepair({ requestId: params.targetId ?? params.requestId, runId: params.factoryRunId!, attempt, revisionId: parent.id, recipe: parent.recipe, failure: finding }, PreservedRepairFactory);
        const draft = await createPreservedSuccessorDraft(env as unknown as Parameters<typeof createPreservedSuccessorDraft>[0], parent, repair.recipe, attempt, previousFailure, repair.explanation, `factory-${params.factoryRunId}-attempt-${attempt}`);
        const pull = await createFactoryPullRequest(env as unknown as Parameters<typeof createFactoryPullRequest>[0], draft);
        draft.revision.pr_url = pull.url;
        draft.revision.commit_sha = pull.commitSha;
        const request = await env.DB.prepare('SELECT factory_run_id FROM requests WHERE id=?').bind(parent.request_id).first<{ factory_run_id: string | null }>();
        await persistFactoryRevision(env as unknown as Parameters<typeof persistFactoryRevision>[0], draft, 'factory', request?.factory_run_id ?? undefined, { privateCandidate: true });
        revision = await revisionForUnit(env, draft.revision.id);
        prepared.set(attempt, revision);
      }
      return {
        candidateSha256: revision.manifest_sha256,
        inputSha256: await sha256(canonicalJson({ revisionId: revision.id, recipeSha256: revision.recipe_sha256, policy: run.policy })),
        candidateRevisionId: revision.id,
        candidate: { revisionId: revision.id, recipeSha256: revision.recipe_sha256, targetKind: params.targetKind },
      };
    },
    execute: async (attempt) => {
      const revision = prepared.get(attempt.attempt) ?? await revisionForUnit(env, attempt.candidateRevisionId ?? '');
      const builds = await queuePrivateFactoryBuilds(env as unknown as Parameters<typeof queuePrivateFactoryBuilds>[0], params.factoryRunId!, attempt, revision);
      let result = await privateFactoryBuildResult(env as unknown as Parameters<typeof privateFactoryBuildResult>[0], params.factoryRunId!, attempt.attempt, builds.map((build) => build.id));
      for (let wait = 0; result.status === 'pending' && wait < 300; wait += 1) {
        await step.sleep(`factory-unit-wait-${params.factoryRunId}-${attempt.attempt}-${wait}`, '5 seconds');
        result = await privateFactoryBuildResult(env as unknown as Parameters<typeof privateFactoryBuildResult>[0], params.factoryRunId!, attempt.attempt, builds.map((build) => build.id));
      }
      if (result.status === 'pending' || result.status === 'ambiguous') throw new Error('factory unit build status is ambiguous');
      if (result.status === 'failed') return { status: 'failed' as const, failureKind: 'build' as const, failure: result.failure };
      return { status: 'succeeded' as const, artifact: result, value: { requestId: params.targetId ?? params.requestId, runId: params.factoryRunId!, attempt: attempt.attempt, status: 'succeeded' as const, artifact: result } };
    },
    onRepair: async (attempt, failure) => {
      await audit(env.DB, 'factory', 'factory.unit_repair_requested', params.factoryRunId!, { targetKind: params.targetKind, targetId: params.targetId, attempt, failure }).run();
    },
    onHumanIntervention: async (reason, attempt) => {
      await audit(env.DB, 'factory', 'factory.unit_needs_human_intervention', params.factoryRunId!, { attempt, reason }).run();
    },
    resumeRunningAttempt: params.attempt,
  });
  if (typeof value === 'object' && value && 'requestId' in value) return value;
  const completed = value as Awaited<ReturnType<typeof getFactoryAttempt>>;
  return { requestId: params.targetId ?? params.requestId, runId: params.factoryRunId, attempt: completed?.attempt ?? params.attempt, status: 'succeeded' as const, artifact: completed?.artifact ?? null };
}

export class FactoryWorkflow extends WorkflowEntrypoint<PipelineEnv, FactoryWorkflowParams> {
  async run(event: Readonly<WorkflowEvent<FactoryWorkflowParams>>, step: WorkflowStep): Promise<FactoryOutcome> {
    if (event.payload.factoryRunId) return runFactoryUnit(event.payload, this.env, step) as unknown as FactoryOutcome;
    return runFactoryWithRecovery({
      step: step as unknown as Parameters<typeof runFactoryWithRecovery<FactoryOutcome>>[0]['step'],
      generate: async () => {
        const response = await factoryEndpoint(requestForFactory(event.payload), this.env as unknown as FactoryEnv, PackageFactory);
        const body = await response.json() as Partial<FactoryRunResult> & { error?: string; status?: string };

        if (response.ok && body.status === 'blocked') return { requestId: event.payload.requestId, status: 'blocked' as const };

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
        if (event.payload.generationId) {
          try {
            await stopFactoryRun(this.env.DB, event.payload.generationId, message);
          } catch (cause) {
            await audit(this.env.DB, 'factory-workflow', 'factory.stop_failed', event.payload.requestId, {
              generationId: event.payload.generationId,
              message: cause instanceof Error ? cause.message : 'factory run stop failed',
            }).run();
          }
        }

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
