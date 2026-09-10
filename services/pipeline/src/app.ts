import { setProvider } from '@flue/runtime';
import { gatewayProvider, type GatewayEnv } from '../model';
import type { Fetchable } from '@flue/runtime/routing';
import { env } from 'cloudflare:workers';
import type { FactoryWorkflowParams, PipelineEnv } from '../types';
import { publicationEndpoint } from '../publication';
import type { Env } from '../../../src/lib/server/env';
import { catalogImportEndpoint } from '../catalog-import';

setProvider(gatewayProvider(env as unknown as GatewayEnv));

const idPattern = /^[A-Za-z0-9_-]{8,128}$/;

function bodyValue(value: unknown): FactoryWorkflowParams | null {
  if (!value || typeof value !== 'object') return null;
  const input = value as Record<string, unknown>;

  if (typeof input.requestId !== 'string' || !idPattern.test(input.requestId)) return null;

  if (input.generationId !== undefined && (typeof input.generationId !== 'string' || !idPattern.test(input.generationId))) return null;

  const params = { requestId: input.requestId };

  if (input.generationId !== undefined) Object.assign(params, { generationId: input.generationId });

  return params;
}

async function enqueueFactory(request: Request, env: PipelineEnv): Promise<Response> {
  if (request.method !== 'POST') return new Response('Method Not Allowed', { status: 405 });

  if (!env.FACTORY) return Response.json({ error: 'Factory workflow is not configured' }, { status: 503 });

  let params: FactoryWorkflowParams | null;

  try {
    params = bodyValue(await request.json());
  } catch {
    params = null;
  }

  if (!params) return Response.json({ error: 'requestId is required' }, { status: 400 });

  const id = params.generationId ?? `factory-${params.requestId}`;

  try {
    await env.FACTORY.create({ id, params });
  } catch {
    // Service binding retries can repeat a successful create after its
    // response was lost. Reuse an existing non-terminal instance safely.
    try {
      const status = await (await env.FACTORY.get(id)).status();

      if (!['errored', 'terminated'].includes(status.status)) {
        return Response.json({ workflowId: id, requestId: params.requestId, deduplicated: true }, { status: 202 });
      }
    } catch {
      // Return one stable error below; do not expose platform details.
    }

    return Response.json({ error: 'Factory workflow could not be queued' }, { status: 503 });
  }

  return Response.json({ workflowId: id, requestId: params.requestId }, { status: 202 });
}

async function enqueueFactoryUnit(request: Request, env: PipelineEnv): Promise<Response> {
  if (request.method !== 'POST') return new Response('Method Not Allowed', { status: 405 });
  if (!env.FACTORY) return Response.json({ error: 'Factory workflow is not configured' }, { status: 503 });
  let input: Record<string, unknown>;
  try { input = await request.json() as Record<string, unknown>; } catch { return Response.json({ error: 'invalid JSON' }, { status: 400 }); }
  const required = ['workflowId', 'runId', 'targetKind', 'targetId', 'unitKey', 'revisionId'];
  if (required.some((key) => typeof input[key] !== 'string' || !(input[key] as string).length) || !Number.isSafeInteger(input.attempt) || !Array.isArray(input.buildIds)) {
    return Response.json({ error: 'factory unit identity is invalid' }, { status: 400 });
  }
  const workflowId = input.workflowId as string;
  const params = { requestId: input.targetId as string, generationId: workflowId, factoryRunId: input.runId as string, targetKind: input.targetKind as string,
    targetId: input.targetId as string, unitKey: input.unitKey as string, attempt: input.attempt as number, buildIds: input.buildIds as string[], revisionId: input.revisionId as string, policy: input.policy,
    repairReason: typeof input.repairReason === 'string' ? input.repairReason.slice(0, 2_000) : undefined };
  try { await env.FACTORY.create({ id: workflowId, params }); }
  catch {
    try {
      const status = await (await env.FACTORY.get(workflowId)).status();
      if (!['errored', 'terminated'].includes(status.status)) return Response.json({ workflowId, runId: input.runId, deduplicated: true }, { status: 202 });
    } catch { /* return stable error */ }
    return Response.json({ error: 'Factory workflow could not be queued' }, { status: 503 });
  }
  return Response.json({ workflowId, runId: input.runId }, { status: 202 });
}

async function enqueueFactoryImage(request: Request, env: PipelineEnv): Promise<Response> {
  if (request.method !== 'POST') return new Response('Method Not Allowed', { status: 405 });
  if (!env.FACTORY) return Response.json({ error: 'Factory workflow is not configured' }, { status: 503 });
  let input: Record<string, unknown>;
  try { input = await request.json() as Record<string, unknown>; } catch { return Response.json({ error: 'invalid JSON' }, { status: 400 }); }
  const required = ['workflowId', 'factoryRunId', 'targetId', 'unitKey', 'imageCandidate'];
  if (required.some((key) => typeof input[key] !== 'string' && key !== 'imageCandidate') || !input.imageCandidate || typeof input.imageCandidate !== 'object' || Array.isArray(input.imageCandidate)) {
    return Response.json({ error: 'factory image identity is invalid' }, { status: 400 });
  }
  if (input.imageAlternatives !== undefined && (!Array.isArray(input.imageAlternatives) || input.imageAlternatives.length > 8)) return Response.json({ error: 'factory image repair choices are bounded' }, { status: 400 });
  const workflowId = input.workflowId as string;
  const params: FactoryWorkflowParams = {
    requestId: input.targetId as string, generationId: workflowId, factoryRunId: input.factoryRunId as string, targetKind: 'image', targetId: input.targetId as string,
    unitKey: input.unitKey as string, policy: input.policy, imageCandidate: input.imageCandidate as FactoryWorkflowParams['imageCandidate'],
    imageAlternatives: Array.isArray(input.imageAlternatives) ? input.imageAlternatives as FactoryWorkflowParams['imageAlternatives'] : [],
  };
  try { await env.FACTORY.create({ id: workflowId, params }); }
  catch {
    try { const status = await (await env.FACTORY.get(workflowId)).status(); if (!['errored', 'terminated'].includes(status.status)) return Response.json({ workflowId, runId: params.factoryRunId, deduplicated: true }, { status: 202 }); } catch { /* stable error below */ }
    return Response.json({ error: 'Factory image workflow could not be queued' }, { status: 503 });
  }
  return Response.json({ workflowId, runId: params.factoryRunId }, { status: 202 });
}

async function enqueueFactoryCohortPage(request: Request, env: PipelineEnv): Promise<Response> {
  if (request.method !== 'POST') return new Response('Method Not Allowed', { status: 405 });
  if (!env.FACTORY) return Response.json({ error: 'Factory workflow is not configured' }, { status: 503 });
  let input: Record<string, unknown>;
  try { input = await request.json() as Record<string, unknown>; } catch { return Response.json({ error: 'invalid JSON' }, { status: 400 }); }
  const strings = ['workflowId', 'runId', 'cohortId'];
  if (strings.some((key) => typeof input[key] !== 'string' || !(input[key] as string).length) ||
      !Number.isSafeInteger(input.revision) || !Number.isSafeInteger(input.offset) || !Number.isSafeInteger(input.pageSize) || !input.coordinator) {
    return Response.json({ error: 'cohort page identity is invalid' }, { status: 400 });
  }
  const workflowId = input.workflowId as string;
  const params: FactoryWorkflowParams = {
    requestId: input.cohortId as string, generationId: workflowId, factoryRunId: input.runId as string,
    targetKind: 'cohort', targetId: input.cohortId as string, unitKey: `revision:${input.revision as number}`,
    cohortRunId: input.runId as string, cohortId: input.cohortId as string, cohortRevision: input.revision as number,
    cohortOffset: input.offset as number, cohortPageSize: input.pageSize as number, cohortPolicy: input.policy,
    cohortCoordinator: input.coordinator as FactoryWorkflowParams['cohortCoordinator'],
  };
  try { await env.FACTORY.create({ id: workflowId, params }); }
  catch {
    try { const status = await (await env.FACTORY.get(workflowId)).status(); if (!['errored', 'terminated'].includes(status.status)) return Response.json({ workflowId, runId: input.runId, deduplicated: true }, { status: 202 }); } catch { /* stable error below */ }
    return Response.json({ error: 'Factory cohort workflow could not be queued' }, { status: 503 });
  }
  return Response.json({ workflowId, runId: input.runId }, { status: 202 });
}

const app: Fetchable = {
  fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === '/import') return catalogImportEndpoint(request, env as PipelineEnv);

    if (url.pathname === '/publish') return publicationEndpoint(request, env as unknown as Env);

    if (url.pathname === '/factory-unit') return enqueueFactoryUnit(request, env as PipelineEnv);
    if (url.pathname === '/factory-image') return enqueueFactoryImage(request, env as PipelineEnv);
    if (url.pathname === '/factory-cohort-page') return enqueueFactoryCohortPage(request, env as PipelineEnv);
    if (url.pathname !== '/factory') return new Response('Not Found', { status: 404 });

    return enqueueFactory(request, env as PipelineEnv);
  },
};

export default app;
