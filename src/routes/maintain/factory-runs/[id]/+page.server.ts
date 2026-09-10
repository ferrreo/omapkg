import { error, fail } from '@sveltejs/kit';
import { environment, field, maintainer } from '$lib/server/http';
import { getFactoryRun, listFactoryAttempts, FactoryRunError, factoryRunErrorStatus } from '$lib/server/factory-runs';
import { FACTORY_UNIT_KINDS, pipelineFactoryQueue, startFactoryUnitIntervention } from '$lib/server/factory-entrypoints';
import { startFactory } from '$lib/server/requests';
import { PolicyError } from '$lib/server/policy';
import { query } from '$lib/server/db';
import { redactText } from '../../../../../services/pipeline/security';
import type { Actions, PageServerLoad } from './$types';

export const load: PageServerLoad = async (event) => {
  maintainer(event);
  const env = environment(event);
  const run = await getFactoryRun(env.DB, event.params.id);
  if (!run) error(404, 'Factory run not found.');
  const attempts = await listFactoryAttempts(env.DB, run.id);
  const revisionId = attempts.find((attempt) => attempt.attempt === run.successfulAttempt)?.candidateRevisionId ?? attempts.at(-1)?.candidateRevisionId ?? run.requestedRevisionId;
  const requestId = revisionId
    ? (await env.DB.prepare('SELECT request_id FROM revisions WHERE id=?').bind(revisionId).first<{ request_id: string }>())?.request_id ?? null
    : run.targetKind === 'generated' ? run.targetId : null;
  const dossiers = await query<{ id: string; revision_id: string; created_at: number }>(env.DB, 'SELECT id,revision_id,created_at FROM factory_dossiers WHERE run_id=? ORDER BY created_at DESC,id', run.id);

  return {
    run: { id: run.id, targetKind: run.targetKind, targetId: run.targetId, unitKey: run.unitKey, status: run.status,
      attemptCount: run.attemptCount, maxAttempts: run.maxAttempts, sourceRunId: run.sourceRunId, createdBy: run.createdBy,
      failure: redactText(JSON.stringify(run.failure, null, 2)), policy: redactText(JSON.stringify(run.policy, null, 2)) },
    attempts: attempts.map((attempt) => ({ attempt: attempt.attempt, status: attempt.status, candidateRevisionId: attempt.candidateRevisionId,
      candidateSha256: attempt.candidateSha256, inputSha256: attempt.inputSha256, buildIds: attempt.buildIds,
      failureKind: attempt.failureKind, failure: redactText(JSON.stringify(attempt.failure, null, 2)) })),
    requestId, dossiers, canIntervene: run.targetKind === 'generated' || FACTORY_UNIT_KINDS.some((kind) => kind === run.targetKind),
  };
};

export const actions: Actions = {
  intervene: async (event) => {
    const form = await event.request.formData();
    const reason = field(form, 'reason');
    try {
      const actor = maintainer(event);
      const env = environment(event);
      const run = await getFactoryRun(env.DB, event.params.id);
      if (!run || run.status !== 'needs-human-intervention') throw new PolicyError(409, 'This run is not awaiting human intervention.');
      if (!reason.trim() || reason.length > 2_000) throw new PolicyError(400, 'Provide intervention guidance, up to 2,000 characters.');
      if (run.targetKind === 'generated') {
        const current = await env.DB.prepare('SELECT factory_run_id FROM requests WHERE id=?').bind(run.targetId).first<{ factory_run_id: string | null }>();
        if (current?.factory_run_id !== run.id) throw new PolicyError(409, 'A newer factory run exists. Open the current request.');
        await startFactory(env, actor, run.targetId, reason);
        const successor = await env.DB.prepare('SELECT factory_run_id FROM requests WHERE id=?').bind(run.targetId).first<{ factory_run_id: string }>();
        return { success: true, successorId: successor?.factory_run_id, successorRequestId: run.targetId };
      }
      const targetKind = FACTORY_UNIT_KINDS.find((kind) => kind === run.targetKind);
      if (!targetKind || !env.PIPELINE) throw new PolicyError(503, 'The factory workflow for this unit is unavailable.');
      const attempts = await listFactoryAttempts(env.DB, run.id);
      const requestedRevisionId = attempts.at(-1)?.candidateRevisionId ?? run.requestedRevisionId ?? undefined;
      const successor = await startFactoryUnitIntervention(env.DB, actor, pipelineFactoryQueue(env.PIPELINE), {
        targetKind, targetId: run.targetId, unitKey: run.unitKey, policy: run.policy,
        requestedRevisionId, sourceRunId: run.id, reason,
      });
      const successorRequestId = successor.run.requestedRevisionId
        ? (await env.DB.prepare('SELECT request_id FROM revisions WHERE id=?').bind(successor.run.requestedRevisionId).first<{ request_id: string }>())?.request_id
        : undefined;
      return { success: true, successorId: successor.run.id, successorRequestId };
    } catch (cause) {
      if (cause instanceof FactoryRunError) return fail(factoryRunErrorStatus(cause), { error: cause.message, reason });
      if (cause instanceof PolicyError) return fail(cause.status, { error: cause.message, reason });
      throw cause;
    }
  },
};
