import { json } from '@sveltejs/kit';
import { beginCatalogImport, appendCatalogImport, sealCatalogImport } from '$lib/server/catalog-imports';
import { environment, jsonBody, sameOrigin } from '$lib/server/http';
import { humanMaintainer } from '$lib/server/catalog-ownership';
import { PolicyError } from '$lib/server/policy';
import type { RequestHandler } from './$types';

export const POST: RequestHandler = async (event) => {
  try {
    sameOrigin(event.request, event.url.origin);
    humanMaintainer(event.locals.actor, 'system');
    const input = await jsonBody(event.request, 1024 * 1024) as Record<string, unknown>;

    if (!input || typeof input !== 'object' || Array.isArray(input)) throw new PolicyError(400, 'Send a capture operation.');
    const { DB } = environment(event);

    if (input.operation === 'begin') return json(await beginCatalogImport(DB, event.locals.actor, input.manifest));

    if (typeof input.importId !== 'string' || !/^[a-f0-9]{64}$/.test(input.importId)) throw new PolicyError(400, 'An import ID is required.');

    if (input.operation === 'append') return json(await appendCatalogImport(DB, event.locals.actor, input.importId, input.entries));

    if (input.operation === 'seal') return json(await sealCatalogImport(DB, event.locals.actor, input.importId));
    throw new PolicyError(400, 'Unknown import operation.');
  } catch (cause) {
    if (cause instanceof PolicyError) return json({ error: cause.message }, { status: cause.status });
    throw cause;
  }
};
