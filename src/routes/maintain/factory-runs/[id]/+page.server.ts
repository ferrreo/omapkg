import { error, fail } from '@sveltejs/kit';
import { environment, field, formAction, maintainer } from '$lib/server/http';
import { getFactoryRun, listFactoryAttempts, stopFactoryRun, FactoryRunError, factoryRunErrorStatus } from '$lib/server/factory-runs';
import { FACTORY_UNIT_KINDS, pipelineFactoryQueue, startFactoryUnitIntervention } from '$lib/server/factory-entrypoints';
import { latestPrivateFactoryImageCandidate, startPrivateFactoryImageWorkflow } from '$lib/server/factory-private-image';
import { startFactory } from '$lib/server/requests';
import { humanMaintainer } from '$lib/server/catalog-ownership';
import { PolicyError } from '$lib/server/policy';
import { audit, query } from '$lib/server/db';
import { redactText } from '../../../../../services/pipeline/security';
import type { Actions, PageServerLoad } from './$types';

export const load: PageServerLoad = async (event) => {
  const actor = maintainer(event);
  const env = environment(event);
  const run = await getFactoryRun(env.DB, event.params.id);
  if (!run) error(404, 'Factory run not found.');
  const attempts = await listFactoryAttempts(env.DB, run.id);
  const revisionId = attempts.find((attempt) => attempt.attempt === run.successfulAttempt)?.candidateRevisionId ?? attempts.at(-1)?.candidateRevisionId ?? run.requestedRevisionId;
  const requestId = revisionId
    ? (await env.DB.prepare('SELECT request_id FROM revisions WHERE id=?').bind(revisionId).first<{ request_id: string }>())?.request_id ?? null
    : run.targetKind === 'generated' ? run.targetId : null;
  const dossiers = await query<{ id: string; revision_id: string; created_at: number }>(env.DB, 'SELECT id,revision_id,created_at FROM factory_dossiers WHERE run_id=? ORDER BY created_at DESC,id', run.id);
  const aggregateDossiers = await query<{ id: string; target_kind: string; target_id: string; run_id: string; created_at: number }>(env.DB, 'SELECT id,target_kind,target_id,run_id,created_at FROM factory_aggregate_dossiers WHERE target_kind=? AND target_id=? AND run_id=? ORDER BY created_at DESC,id', run.targetKind, run.targetId, run.id);
  const pagedCohortCoordinator = run.targetKind === 'cohort' && /^revision:[1-9][0-9]*$/.test(run.unitKey);
  const cohortChildren = pagedCohortCoordinator
    ? await query<{ id: string; target_kind: string; target_id: string; unit_key: string; status: string }>(env.DB, `SELECT id,target_kind,target_id,unit_key,status FROM factory_runs
      WHERE target_kind='cohort-member' AND target_id=? AND json_extract(policy_json,'$.cohortRevision')=? ORDER BY unit_key,id`, run.targetId, Number(run.unitKey.slice('revision:'.length)))
    : [];
  const imageCandidateAvailable = run.targetKind === 'image' && Boolean(await env.DB.prepare('SELECT 1 FROM factory_image_jobs WHERE run_id=? LIMIT 1').bind(run.id).first());

  return {
    run: { id: run.id, targetKind: run.targetKind, targetId: run.targetId, unitKey: run.unitKey, status: run.status,
      attemptCount: run.attemptCount, maxAttempts: run.maxAttempts, sourceRunId: run.sourceRunId, createdBy: run.createdBy,
      failure: redactText(JSON.stringify(run.failure, null, 2)), policy: redactText(JSON.stringify(run.policy, null, 2)) },
    attempts: attempts.map((attempt) => ({ attempt: attempt.attempt, status: attempt.status, candidateRevisionId: attempt.candidateRevisionId,
      candidateSha256: attempt.candidateSha256, inputSha256: attempt.inputSha256, buildIds: attempt.buildIds,
      failureKind: attempt.failureKind, failure: redactText(JSON.stringify(attempt.failure, null, 2)) })),
    requestId, dossiers, aggregateDossiers, cohortChildren, pagedCohortCoordinator, imageCandidateAvailable,
    canStop: actor.id === run.createdBy || actor.role === 'admin' || actor.role === 'security',
    canIntervene: run.targetKind === 'generated' || run.targetKind === 'image' && imageCandidateAvailable || FACTORY_UNIT_KINDS.some((kind) => kind === run.targetKind) && !pagedCohortCoordinator,
  };
};

export const actions: Actions = {
  stop: (event) => formAction(event, async (form) => {
    const actor = humanMaintainer(maintainer(event));
    const env = environment(event);
    const run = await getFactoryRun(env.DB, event.params.id);
    if (!run || !['queued', 'running'].includes(run.status)) throw new PolicyError(409, 'This run is already closed.');
    if (run.createdBy !== actor.id && actor.role !== 'admin' && actor.role !== 'security') throw new PolicyError(403, 'Only the run owner or an operator can stop it.');
    const reason = field(form, 'reason').trim();
    if (!reason || reason.length > 2000) throw new PolicyError(400, 'Give a short reason for stopping the run.');
    const stopped = await stopFactoryRun(env.DB, run.id, reason);
    if (stopped.status !== 'needs-human-intervention') throw new PolicyError(409, 'The run finished before it could be stopped.');
    await audit(env.DB, actor.id, 'factory.human_stopped', run.id, { reason }).run();
    return { stopped: true };
  }),
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
      if (run.targetKind === 'cohort' && /^revision:[1-9][0-9]*$/.test(run.unitKey)) {
        throw new PolicyError(409, 'Cohort coordinator runs are completed through their member runs. Open an exhausted member run to intervene.');
      }
      if (run.targetKind === 'image') {
        const reviewer = humanMaintainer(actor);
        const candidate = await latestPrivateFactoryImageCandidate(env.DB, run.id);
        const successor = await startPrivateFactoryImageWorkflow(env, {
          targetId: run.targetId, unitKey: run.unitKey, policy: run.policy, createdBy: reviewer.id,
          sourceRunId: run.id, interventionReason: reason, candidate,
        });
        return { success: true, successorId: successor.run.id };
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
