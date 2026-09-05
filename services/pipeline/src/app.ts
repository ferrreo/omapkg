import { setProvider } from '@flue/runtime';
import { gatewayProvider, type GatewayEnv } from '../model';
import type { Fetchable } from '@flue/runtime/routing';
import { env } from 'cloudflare:workers';
import type { FactoryWorkflowParams, PipelineEnv } from '../types';
import { publicationEndpoint } from '../publication';
import type { Env } from '../../../src/lib/server/env';

setProvider(gatewayProvider(env as unknown as GatewayEnv));

const idPattern = /^[A-Za-z0-9_-]{8,128}$/;

function bodyValue(value: unknown): FactoryWorkflowParams | null {
  if (!value || typeof value !== 'object') return null;
  const input = value as Record<string, unknown>;
  if (typeof input.requestId !== 'string' || !idPattern.test(input.requestId)) return null;
  if (input.generationId !== undefined && (typeof input.generationId !== 'string' || !idPattern.test(input.generationId))) return null;
  return {
    requestId: input.requestId,
    ...(input.generationId === undefined ? {} : { generationId: input.generationId }),
  };
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

const app: Fetchable = {
  fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname === '/publish') return publicationEndpoint(request, env as unknown as Env);
    if (url.pathname !== '/factory') return new Response('Not Found', { status: 404 });
    return enqueueFactory(request, env as PipelineEnv);
  },
};

export default app;
