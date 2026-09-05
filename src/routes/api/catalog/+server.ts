import { json, type RequestHandler } from '@sveltejs/kit';
import type { Architecture, Release } from '$lib/model';
import { sha256, query } from '$lib/server/db';
import { publicRelease } from '$lib/server/releases';
import { finalDescription } from '$lib/server/descriptions';

type CatalogRow = Release & {
  artifact_filename: string | null;
  artifact_sha256: string | null;
  artifact_size: number | null;
  source_json: string;
  license: string;
  upstream_url: string;
  description?: string | null;
  recipe?: string;
  explanation?: string;
};

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

function safeSources(value: string): Array<{ name: string; url: string; sha256: string }> {
  try {
    const parsed: unknown = JSON.parse(value);
    if (!Array.isArray(parsed)) return [];
    return parsed.filter((item): item is { name: string; url: string; sha256: string } => {
      if (!item || typeof item !== 'object') return false;
      const row = item as Record<string, unknown>;
      return typeof row.name === 'string' && typeof row.url === 'string' && typeof row.sha256 === 'string';
    });
  } catch {
    return [];
  }
}

export const GET: RequestHandler = async ({ platform, url }) => {
  if (!platform?.env?.DB) return json({ error: 'Catalog is unavailable.' }, { status: 503 });
  const env = platform.env;
  const search = (url.searchParams.get('q') ?? '').trim().slice(0, 80);
  const surface = url.searchParams.get('surface');
  const architecture = url.searchParams.get('architecture');
  const channel = url.searchParams.get('channel') === 'dev' ? 'dev' : 'stable';
  const limit = Math.min(Math.max(Number(url.searchParams.get('limit') ?? 30) || 30, 1), LIMIT);
  const page = cursor(url.searchParams.get('cursor'));
  const filters: string[] = [`r.channel='${channel}'`];
  const values: unknown[] = [];
  if (search) { filters.push('lower(r.name) LIKE ?'); values.push(`%${search.toLowerCase()}%`); }
  if (surface === 'binary' || surface === 'recipe') { filters.push('r.surface=?'); values.push(surface); }
  if (architecture === 'x86_64' || architecture === 'aarch64') { filters.push('r.architecture=?'); values.push(architecture); }
  const rows = await query<CatalogRow>(env.DB, `SELECT r.*, b.artifact_filename, b.artifact_sha256, b.artifact_size,
    v.sources_json AS source_json, v.license, v.description, v.recipe, v.explanation, q.upstream_url
    FROM releases r JOIN builds b ON b.id=r.build_id JOIN revisions v ON v.id=b.revision_id JOIN requests q ON q.id=v.request_id
    WHERE ${filters.join(' AND ')} ORDER BY r.name COLLATE NOCASE, r.architecture, r.published_at DESC, r.id DESC`, ...values);
  const latest: CatalogRow[] = [];
  const seen = new Set<string>();
  for (const row of rows) {
    const key = `${row.name}:${row.architecture}`;
    if (!seen.has(key)) { latest.push(row); seen.add(key); }
  }
  const start = page ? Math.max(0, latest.findIndex((row) => row.name === page.name && row.architecture === page.architecture && row.id === page.id) + 1) : 0;
  const selected = latest.slice(start, start + limit);
  const items = selected.map((row) => {
    const release = publicRelease(row, url.origin, channel === 'dev');
    return release ? { ...release, description: finalDescription(row, row.name), source: { upstreamUrl: row.upstream_url, files: safeSources(row.source_json) }, license: row.license } : null;
  }).filter(Boolean);
  const body = { items, nextCursor: selected.length === limit && start + limit < latest.length ? nextCursor(selected[selected.length - 1]) : null };
  const digest = await sha256(JSON.stringify(body));
  return json(body, { headers: { 'Cache-Control': channel === 'dev' ? 'public, max-age=30, s-maxage=60' : 'public, max-age=60, s-maxage=300, stale-while-revalidate=60', ETag: `"${digest}"` } });
};
