import { error, json, type RequestHandler } from '@sveltejs/kit';
import type { Release } from '$lib/model';
import { query } from '$lib/server/db';
import { publicRelease } from '$lib/server/releases';
import { finalDescription } from '$lib/server/descriptions';

type DetailRow = Release & {
  artifact_filename: string | null;
  artifact_sha256: string | null;
  artifact_size: number | null;
  source_json: string;
  dependencies_json: string;
  smoke_commands_json: string;
  license: string;
  upstream_url: string;
  explanation: string;
  description?: string | null;
  recipe?: string;
};

function sources(value: string): Array<{ name: string; url: string; sha256: string }> {
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

function list(value: string): string[] {
  try {
    const parsed: unknown = JSON.parse(value);
    return Array.isArray(parsed) ? parsed.filter((item): item is string => typeof item === 'string') : [];
  } catch {
    return [];
  }
}

export const GET: RequestHandler = async ({ platform, params, url }) => {
  if (!platform?.env?.DB) return json({ error: 'Catalog is unavailable.' }, { status: 503 });
  const name = params.name ?? '';
  if (!/^[a-z0-9][a-z0-9@._+:-]{0,63}$/.test(name)) error(404, 'Package not found.');
  const dev = url.searchParams.get('channel') === 'dev';
  const rows = await query<DetailRow>(platform.env.DB, `SELECT r.*, b.artifact_filename, b.artifact_sha256, b.artifact_size,
    v.sources_json AS source_json, v.dependencies_json, v.smoke_commands_json, v.license, v.description, v.recipe, v.explanation, q.upstream_url
    FROM releases r JOIN builds b ON b.id=r.build_id JOIN revisions v ON v.id=b.revision_id JOIN requests q ON q.id=v.request_id
    WHERE r.name=? AND r.channel ${dev ? '= \'dev\'' : "IN ('stable','withdrawn')"} ORDER BY r.published_at DESC, r.id DESC`, name);
  if (!rows.length) error(404, 'Package not found.');
  const versions = rows.map((row) => {
    const release = publicRelease(row, url.origin, dev);
    if (!release) return null;
    return {
      ...release,
      description: finalDescription(row, row.name),
      source: { upstreamUrl: row.upstream_url, files: sources(row.source_json) },
      license: row.license,
      dependencies: list(row.dependencies_json),
      smokeCommands: list(row.smoke_commands_json),
      explanation: row.explanation,
    };
  }).filter(Boolean);
  return json({ name, versions }, { headers: { 'Cache-Control': dev ? 'public, max-age=30, s-maxage=60' : 'public, max-age=60, s-maxage=300, stale-while-revalidate=60' } });
};
