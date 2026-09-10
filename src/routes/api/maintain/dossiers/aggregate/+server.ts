import { json, type RequestHandler } from '@sveltejs/kit';
import { environment, jsonBody, maintainer, sameOrigin } from '$lib/server/http';
import { buildFactoryAggregateDossier, createFactoryAggregateDossier, factoryAggregateDossierMarkdown, type AggregateDossierKind } from '$lib/server/factory-aggregate-dossier';
import { PolicyError } from '$lib/server/policy';

const headers = { 'Cache-Control': 'private, no-store', 'X-Content-Type-Options': 'nosniff' };
const targetKinds = new Set<AggregateDossierKind>(['cohort', 'image']);

function inputFromParams(url: URL): { targetKind: AggregateDossierKind; targetId: string; runId?: string } {
  const targetKind = url.searchParams.get('targetKind') as AggregateDossierKind;
  const targetId = url.searchParams.get('targetId') ?? '';
  const runId = url.searchParams.get('runId') ?? undefined;
  if (!targetKinds.has(targetKind) || !targetId) throw new PolicyError(400, 'targetKind and targetId are required.');
  return { targetKind, targetId, ...(runId ? { runId } : {}) };
}

export const GET: RequestHandler = async (event) => {
  try {
    maintainer(event);
    const dossier = await buildFactoryAggregateDossier(environment(event), inputFromParams(event.url));
    const format = event.url.searchParams.get('format') ?? 'json';
    if (format === 'markdown') return new Response(factoryAggregateDossierMarkdown(dossier), { headers: { ...headers, 'Content-Type': 'text/markdown; charset=utf-8' } });
    if (format !== 'json') throw new PolicyError(400, 'Aggregate dossier format must be json or markdown.');
    return json(dossier, { headers });
  } catch (cause) {
    if (cause instanceof PolicyError) return json({ error: cause.message }, { status: cause.status, headers });
    throw cause;
  }
};

export const POST: RequestHandler = async (event) => {
  try {
    sameOrigin(event.request, event.url.origin);
    const actor = maintainer(event);
    const body = await jsonBody(event.request) as Record<string, unknown>;
    if (!body || typeof body !== 'object' || Array.isArray(body) || Object.keys(body).some((key) => !['targetKind', 'targetId', 'runId'].includes(key)) ||
        !targetKinds.has(body.targetKind as AggregateDossierKind) || typeof body.targetId !== 'string' || (body.runId !== undefined && typeof body.runId !== 'string')) {
      throw new PolicyError(400, 'targetKind, targetId and optional runId are required.');
    }
    const dossier = await createFactoryAggregateDossier(environment(event), actor.id, { targetKind: body.targetKind as AggregateDossierKind, targetId: body.targetId, ...(typeof body.runId === 'string' ? { runId: body.runId } : {}) });
    return json({ id: dossier.dossier.id, canonicalSha256: dossier.canonicalSha256, markdownSha256: dossier.markdownSha256 }, { status: 201, headers });
  } catch (cause) {
    if (cause instanceof PolicyError) return json({ error: cause.message }, { status: cause.status, headers });
    throw cause;
  }
};
