import { json, type RequestHandler } from '@sveltejs/kit';
import type { Architecture } from '$lib/model';
import { sha256 } from '$lib/server/db';
import { catalogPage, catalogRelease, type CatalogRow } from '$lib/server/catalog';

const LIMIT = 100;

function cursor(value: string | null): { name: string; architecture: Architecture; id: string } | null {
  if (!value) return null;
  try {
    const decoded = atob(value.replaceAll('-', '+').replaceAll('_', '/') + '='.repeat((4 - value.length % 4) % 4));
    const parsed: unknown = JSON.parse(decoded);
    if (!parsed || typeof parsed !== 'object') return null;
    const item = parsed as Record<string, unknown>;
    if (typeof item.name !== 'string' || !['x86_64', 'aarch64'].includes(String(item.architecture)) || typeof item.id !== 'string') return null;
    return { name: item.name, architecture: item.architecture as Architecture, id: item.id };
  } catch {
    return null;
  }
}

function nextCursor(row: CatalogRow): string {
  return btoa(JSON.stringify({ name: row.name, architecture: row.architecture, id: row.id }))
    .replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
}

export const GET: RequestHandler = async ({ platform, url }) => {
  if (!platform?.env?.DB) return json({ error: 'Catalog is unavailable.' }, { status: 503 });
  const env = platform.env;
  const search = (url.searchParams.get('q') ?? '').trim().slice(0, 80);
  const surface = url.searchParams.get('surface');
  const architecture = url.searchParams.get('architecture');
  const channel = url.searchParams.get('channel') === 'dev' ? 'dev' : 'stable';
  const limit = Math.trunc(Math.min(Math.max(Number(url.searchParams.get('limit') ?? 30) || 30, 1), LIMIT));
  const page = cursor(url.searchParams.get('cursor'));
  const rows = await catalogPage(env.DB, {
    channel, search, limit: limit + 1, after: page,
    ...(surface === 'binary' || surface === 'recipe' ? { surface } : {}),
    ...(architecture === 'x86_64' || architecture === 'aarch64' ? { architecture } : {}),
  });
  const selected = rows.slice(0, limit);
  const items = selected.map((row) => catalogRelease(row, url.origin, channel === 'dev')).filter(Boolean);
  const body = { items, nextCursor: rows.length > limit ? nextCursor(selected[selected.length - 1]) : null };
  const digest = await sha256(JSON.stringify(body));
  return json(body, { headers: { 'Cache-Control': channel === 'dev' ? 'public, max-age=30, s-maxage=60' : 'public, max-age=60, s-maxage=300, stale-while-revalidate=60', ETag: `"${digest}"` } });
};
