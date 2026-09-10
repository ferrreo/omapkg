import * as v from 'valibot';
import type { Architecture, Release } from '../model';
import { query } from './db';
import { finalDescription } from './descriptions';
import { publicRelease } from './releases';

export type CatalogRow = Release & {
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

export type CatalogChannel = 'stable' | 'dev' | 'withdrawn' | 'all';

export type CatalogCursor = { name: string; architecture: Architecture; id: string; channel?: Exclude<CatalogChannel, 'all'> };

const catalogCursorSchema = v.object({
  name: v.string(),
  architecture: v.picklist(['x86_64', 'aarch64']),
  id: v.string(),
  channel: v.optional(v.picklist(['stable', 'dev', 'withdrawn'])),
});

const publicSourceSchema = v.object({ name: v.string(), url: v.string(), sha256: v.string() });

export function decodeCatalogCursor(value: string | null): CatalogCursor | null {
  if (!value) return null;

  try {
    const decoded = atob(value.replaceAll('-', '+').replaceAll('_', '/') + '='.repeat((4 - value.length % 4) % 4));
    const parsed = v.safeParse(catalogCursorSchema, JSON.parse(decoded));

    return parsed.success ? parsed.output : null;
  } catch {
    return null;
  }
}

export function encodeCatalogCursor(row: Pick<CatalogRow, 'name' | 'architecture' | 'id' | 'channel'>): string {
  return btoa(JSON.stringify({ name: row.name, architecture: row.architecture, id: row.id, channel: row.channel }))
    .replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
}

export function publicSources(value: string): Array<{ name: string; url: string; sha256: string }> {
  try {
    const parsed: unknown = JSON.parse(value);

    if (!Array.isArray(parsed)) return [];

    return parsed.flatMap((item) => {
      const source = v.safeParse(publicSourceSchema, item);

      return source.success ? [source.output] : [];
    });
  } catch { return []; }
}

export function stringList(value: string): string[] {
  try {
    const parsed: unknown = JSON.parse(value);

    if (!Array.isArray(parsed)) return [];

    return parsed.flatMap((item) => {
      const string = v.safeParse(v.string(), item);

      return string.success ? [string.output] : [];
    });
  } catch { return []; }
}

export function catalogRelease(row: CatalogRow, origin: string, includeDev = false) {
  const release = publicRelease(row, origin, includeDev);

  return release ? {
    ...release, description: finalDescription(row, row.name),
    source: { upstreamUrl: row.upstream_url, files: publicSources(row.source_json) }, license: row.license,
  } : null;
}

export async function catalogPage(db: D1Database, input: {
  channel: CatalogChannel; search: string; surface?: 'binary' | 'recipe'; architecture?: Architecture;
  limit: number; offset?: number; after?: CatalogCursor | null;
}): Promise<CatalogRow[]> {
  const filters = [input.channel === 'all' ? "r.channel IN ('stable','dev','withdrawn')" : 'r.channel=?'];
  const values: unknown[] = input.channel === 'all' ? [] : [input.channel];

  if (input.search) { filters.push('lower(r.name) LIKE ?'); values.push(`%${input.search.toLowerCase()}%`); }

  if (input.surface) { filters.push('r.surface=?'); values.push(input.surface); }

  if (input.architecture) { filters.push('r.architecture=?'); values.push(input.architecture); }

  const after = input.after ? input.channel === 'all'
    ? 'AND (name COLLATE NOCASE>? OR (name=? COLLATE NOCASE AND (architecture>? OR (architecture=? AND CASE channel WHEN \'stable\' THEN 0 WHEN \'dev\' THEN 1 ELSE 2 END > CASE ? WHEN \'stable\' THEN 0 WHEN \'dev\' THEN 1 ELSE 2 END))))'
    : 'AND (name COLLATE NOCASE>? OR (name=? COLLATE NOCASE AND architecture>?))' : '';

  if (input.after) {
    values.push(input.after.name, input.after.name, input.after.architecture);

    if (input.channel === 'all') values.push(input.after.architecture, input.after.channel ?? 'stable');
  }

  values.push(input.limit, input.offset ?? 0);

  return query<CatalogRow>(db, `WITH ranked AS (
      SELECT r.id,r.name,r.architecture,r.channel,r.published_at,
        ROW_NUMBER() OVER (PARTITION BY r.name,r.architecture${input.channel === 'all' ? ',r.channel' : ''} ORDER BY r.published_at DESC,r.id DESC) AS position
      FROM releases r WHERE ${filters.join(' AND ')}
    ), page AS (
      SELECT * FROM ranked WHERE position=1 ${after}
      ORDER BY name COLLATE NOCASE,architecture${input.channel === 'all' ? ",CASE channel WHEN 'stable' THEN 0 WHEN 'dev' THEN 1 ELSE 2 END" : ''} LIMIT ? OFFSET ?
    )
    SELECT r.*,b.artifact_filename,b.artifact_sha256,b.artifact_size,
      v.sources_json AS source_json,v.license,v.description,v.recipe,v.explanation,q.upstream_url
    FROM page p JOIN releases r ON r.id=p.id JOIN builds b ON b.id=r.build_id
      JOIN revisions v ON v.id=b.revision_id JOIN requests q ON q.id=v.request_id
    ORDER BY p.name COLLATE NOCASE,p.architecture${input.channel === 'all' ? ",CASE p.channel WHEN 'stable' THEN 0 WHEN 'dev' THEN 1 ELSE 2 END" : ''}`, ...values);
}
