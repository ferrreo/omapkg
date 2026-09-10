import { json, type RequestHandler } from '@sveltejs/kit';
import { sha256 } from '$lib/server/db';
import { catalogPage, catalogRelease, decodeCatalogCursor, encodeCatalogCursor } from '$lib/server/catalog';

const LIMIT = 100;

export const GET: RequestHandler = async ({ platform, url }) => {
  if (!platform?.env?.DB) return json({ error: 'Catalog is unavailable.' }, { status: 503 });
  const env = platform.env;
  const search = (url.searchParams.get('q') ?? '').trim().slice(0, 80);
  const surface = url.searchParams.get('surface');
  const architecture = url.searchParams.get('architecture');
  const channel = url.searchParams.get('channel') === 'dev' ? 'dev' : 'stable';
  const limit = Math.trunc(Math.min(Math.max(Number(url.searchParams.get('limit') ?? 30) || 30, 1), LIMIT));
  const page = decodeCatalogCursor(url.searchParams.get('cursor'));

  const options: Parameters<typeof catalogPage>[1] = { channel, search, limit: limit + 1, after: page };

  if (surface === 'binary' || surface === 'recipe') options.surface = surface;

  if (architecture === 'x86_64' || architecture === 'aarch64') options.architecture = architecture;

  const rows = await catalogPage(env.DB, options);

  const selected = rows.slice(0, limit);
  const items = selected.map((row) => catalogRelease(row, url.origin, channel === 'dev')).filter(Boolean);
  const body = { items, nextCursor: rows.length > limit ? encodeCatalogCursor(selected[selected.length - 1]) : null };
  const digest = await sha256(JSON.stringify(body));

  return json(body, { headers: { 'Cache-Control': channel === 'dev' ? 'public, max-age=30, s-maxage=60' : 'public, max-age=60, s-maxage=300, stale-while-revalidate=60', ETag: `"${digest}"` } });
};
