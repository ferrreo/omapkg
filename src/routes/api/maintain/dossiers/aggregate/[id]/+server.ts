import { json, type RequestHandler } from '@sveltejs/kit';
import { environment, maintainer } from '$lib/server/http';
import { factoryAggregateDossierMarkdown, storedFactoryAggregateDossier } from '$lib/server/factory-aggregate-dossier';
import { PolicyError } from '$lib/server/policy';

const headers = { 'Cache-Control': 'private, no-store', 'X-Content-Type-Options': 'nosniff' };

export const GET: RequestHandler = async (event) => {
  try {
    maintainer(event);
    const stored = await storedFactoryAggregateDossier(environment(event), event.params.id ?? '');
    if (event.url.searchParams.get('format') === 'markdown') return new Response(stored.markdown, { headers: { ...headers, 'Content-Type': 'text/markdown; charset=utf-8' } });
    if (event.url.searchParams.has('format') && event.url.searchParams.get('format') !== 'json') throw new PolicyError(400, 'Aggregate dossier format must be json or markdown.');
    return new Response(stored.canonicalJson, { headers: { ...headers, 'Content-Type': 'application/json; charset=utf-8', ETag: `"${stored.canonicalSha256}"` } });
  } catch (cause) {
    if (cause instanceof PolicyError) return json({ error: cause.message }, { status: cause.status, headers });
    throw cause;
  }
};
