import { json, type RequestHandler } from '@sveltejs/kit';
import { environment } from '$lib/server/http';
import { factoryDossierMarkdown, factoryDossierPublicCanonicalJson, publishedFactoryDossier, storedFactoryDossier } from '$lib/server/factory-dossier';
import { PolicyError } from '$lib/server/policy';
import { sha256 } from '$lib/server/db';

const headers = { 'Cache-Control': 'public, max-age=60', 'X-Content-Type-Options': 'nosniff' };

export const GET: RequestHandler = async (event) => {
  try {
    const env = environment(event);
    const stored = await storedFactoryDossier(env, event.params.id ?? '');
    const published = await publishedFactoryDossier(env, stored);
    const format = event.url.searchParams.get('format') ?? 'json';

    if (format === 'markdown') {
      const body = factoryDossierMarkdown(published, true);

      return new Response(body, { headers: { ...headers, 'Content-Type': 'text/markdown; charset=utf-8', ETag: `"${await sha256(body)}"` } });
    }

    if (format !== 'json') throw new PolicyError(400, 'Dossier format must be json or markdown.');
    const body = factoryDossierPublicCanonicalJson(published);

    return new Response(body, { headers: { ...headers, 'Content-Type': 'application/json; charset=utf-8', ETag: `"${await sha256(body)}"` } });
  } catch (cause) {
    if (cause instanceof PolicyError) return json({ error: cause.message }, { status: cause.status, headers });
    throw cause;
  }
};
