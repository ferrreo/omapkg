import { json, type RequestHandler } from '@sveltejs/kit';
import { environment, jsonBody, maintainer, sameOrigin } from '$lib/server/http';
import { createFactoryDossier, listFactoryDossiers } from '$lib/server/factory-dossier';
import { PolicyError } from '$lib/server/policy';

const headers = { 'Cache-Control': 'private, no-store' };

export const GET: RequestHandler = async (event) => {
  try {
    maintainer(event);
    const env = environment(event);

    return json({ dossiers: await listFactoryDossiers(env, event.url.searchParams.get('request') ?? undefined) }, { headers });
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

    if (!body || typeof body !== 'object' || Array.isArray(body) || Object.keys(body).some((key) => !['requestId', 'revisionId', 'runId', 'id'].includes(key)) ||
        !['requestId', 'revisionId', 'runId', 'id'].every((key) => body[key] === undefined || typeof body[key] === 'string') ||
        typeof body.requestId !== 'string' || typeof body.revisionId !== 'string') {
      throw new PolicyError(400, 'requestId and revisionId are required.');
    }

    const dossier = await createFactoryDossier(environment(event), actor.id, {
      requestId: body.requestId,
      revisionId: body.revisionId,
      ...(typeof body.runId === 'string' ? { runId: body.runId } : {}),
      ...(typeof body.id === 'string' ? { id: body.id } : {}),
    });

    return json({ id: dossier.dossier.id, canonicalSha256: dossier.canonicalSha256, markdownSha256: dossier.markdownSha256 }, { status: 201, headers });
  } catch (cause) {
    if (cause instanceof PolicyError) return json({ error: cause.message }, { status: cause.status, headers });
    throw cause;
  }
};
