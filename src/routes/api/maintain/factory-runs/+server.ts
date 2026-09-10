import { json, type RequestHandler } from '@sveltejs/kit';
import { environment, jsonBody, sameOrigin } from '$lib/server/http';
import { humanMaintainer } from '$lib/server/catalog-ownership';
import { startFactoryUnit, startFactoryUnitIntervention, pipelineFactoryQueue, type FactoryUnitKind } from '$lib/server/factory-entrypoints';
import { FactoryRunError, factoryRunErrorStatus } from '$lib/server/factory-runs';
import { PolicyError } from '$lib/server/policy';
import { startPrivateFactoryImageWorkflow } from '$lib/server/factory-private-image';
import { pipelineFactoryCohortPageQueue, startFactoryCohortPaged } from '$lib/server/factory-cohort-dispatch';

const headers = { 'Cache-Control': 'private, no-store' };

const kinds = new Set<FactoryUnitKind>(['preserved', 'manual', 'cohort', 'cohort-member', 'bootstrap', 'toolchain']);

export const POST: RequestHandler = async (event) => {
  try {
    sameOrigin(event.request, event.url.origin);
    const actor = humanMaintainer(event.locals.actor);
    const input = await jsonBody(event.request, 256 * 1024) as Record<string, unknown>;
    const operation = input.operation;
    const env = environment(event);

    if (operation === 'image' || operation === 'image-intervene') {
      if (typeof input.targetId !== 'string' || typeof input.unitKey !== 'string' || !input.policy || !input.candidate || typeof input.candidate !== 'object' || Array.isArray(input.candidate)) {
        throw new PolicyError(400, 'Image target, execution policy and reviewed image candidate are required.');
      }
      if (operation === 'image-intervene' && typeof input.sourceRunId !== 'string') throw new PolicyError(400, 'Source factory run is required for image intervention.');
      if (!env.PIPELINE) throw new PolicyError(503, 'Factory workflow service is not configured.');
      const prepared = await startPrivateFactoryImageWorkflow(env, {
        runId: typeof input.runId === 'string' ? input.runId : undefined,
        sourceRunId: operation === 'image-intervene' ? input.sourceRunId as string : undefined,
        interventionReason: operation === 'image-intervene' && typeof input.reason === 'string' ? input.reason : undefined,
        targetId: input.targetId,
        unitKey: input.unitKey,
        policy: input.policy,
        createdBy: actor.id,
        candidate: input.candidate as Parameters<typeof startPrivateFactoryImageWorkflow>[1]['candidate'],
        alternatives: Array.isArray(input.alternatives) ? input.alternatives as Parameters<typeof startPrivateFactoryImageWorkflow>[1]['alternatives'] : undefined,
      });
      return json({ runId: prepared.run.id, workflowId: prepared.workflowId, status: 'queued' }, { status: 202, headers });
    }

    if (!env.PIPELINE) throw new PolicyError(503, 'Factory workflow service is not configured.');
    const queue = pipelineFactoryQueue(env.PIPELINE);

    if (operation === 'cohort') {
      if (typeof input.cohortId !== 'string' || !input.policy) throw new PolicyError(400, 'Cohort and execution policy are required.');

      return json(await startFactoryCohortPaged(env.DB, actor, pipelineFactoryCohortPageQueue(env.PIPELINE), { cohortId: input.cohortId, policy: input.policy }), { status: 202, headers });
    }

    if (operation !== 'start' && operation !== 'intervene') throw new PolicyError(400, 'Choose a factory start operation.');

    if (typeof input.targetKind !== 'string' || !kinds.has(input.targetKind as FactoryUnitKind) || typeof input.targetId !== 'string' || typeof input.unitKey !== 'string' || !input.policy) {
      throw new PolicyError(400, 'Factory unit identity and execution policy are required.');
    }

    const unit = { targetKind: input.targetKind as FactoryUnitKind, targetId: input.targetId, unitKey: input.unitKey, policy: input.policy, requestedRevisionId: typeof input.requestedRevisionId === 'string' ? input.requestedRevisionId : undefined, runId: typeof input.runId === 'string' ? input.runId : undefined };

    const result = operation === 'intervene'
      ? await startFactoryUnitIntervention(env.DB, actor, queue, { ...unit, reason: typeof input.reason === 'string' ? input.reason : '', sourceRunId: typeof input.sourceRunId === 'string' ? input.sourceRunId : (() => { throw new PolicyError(400, 'Source factory run is required for intervention.'); })() })
      : await startFactoryUnit(env.DB, actor, queue, unit);

    return json(result, { status: 202, headers });
  } catch (cause) {
    if (cause instanceof PolicyError) return json({ error: cause.message }, { status: cause.status, headers });
    if (cause instanceof FactoryRunError) return json({ error: cause.message }, { status: factoryRunErrorStatus(cause), headers });
    throw cause;
  }
};
