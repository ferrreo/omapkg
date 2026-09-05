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

export function publicSources(value: string): Array<{ name: string; url: string; sha256: string }> {
  try {
    const parsed: unknown = JSON.parse(value);
    if (!Array.isArray(parsed)) return [];
    return parsed.filter((item): item is { name: string; url: string; sha256: string } => {
      if (!item || typeof item !== 'object') return false;
      const row = item as Record<string, unknown>;
      return typeof row.name === 'string' && typeof row.url === 'string' && typeof row.sha256 === 'string';
    });
  } catch { return []; }
}

export function stringList(value: string): string[] {
  try {
    const parsed: unknown = JSON.parse(value);
    return Array.isArray(parsed) ? parsed.filter((item): item is string => typeof item === 'string') : [];
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
  channel: 'stable' | 'dev'; search: string; surface?: 'binary' | 'recipe'; architecture?: Architecture;
  limit: number; offset?: number; after?: { name: string; architecture: Architecture } | null;
}): Promise<CatalogRow[]> {
  const filters = ['r.channel=?'];
  const values: unknown[] = [input.channel];
  if (input.search) { filters.push('lower(r.name) LIKE ?'); values.push(`%${input.search.toLowerCase()}%`); }
  if (input.surface) { filters.push('r.surface=?'); values.push(input.surface); }
  if (input.architecture) { filters.push('r.architecture=?'); values.push(input.architecture); }
  const after = input.after ? 'AND (name COLLATE NOCASE>? OR (name=? COLLATE NOCASE AND architecture>?))' : '';
  if (input.after) values.push(input.after.name, input.after.name, input.after.architecture);
  values.push(input.limit, input.offset ?? 0);
  return query<CatalogRow>(db, `WITH ranked AS (
      SELECT r.id,r.name,r.architecture,r.published_at,
        ROW_NUMBER() OVER (PARTITION BY r.name,r.architecture ORDER BY r.published_at DESC,r.id DESC) AS position
      FROM releases r WHERE ${filters.join(' AND ')}
    ), page AS (
      SELECT * FROM ranked WHERE position=1 ${after}
      ORDER BY name COLLATE NOCASE,architecture LIMIT ? OFFSET ?
    )
    SELECT r.*,b.artifact_filename,b.artifact_sha256,b.artifact_size,
      v.sources_json AS source_json,v.license,v.description,v.recipe,v.explanation,q.upstream_url
    FROM page p JOIN releases r ON r.id=p.id JOIN builds b ON b.id=r.build_id
      JOIN revisions v ON v.id=b.revision_id JOIN requests q ON q.id=v.request_id
    ORDER BY p.name COLLATE NOCASE,p.architecture`, ...values);
}
