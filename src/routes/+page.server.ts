import { parseSystemVersion } from '$lib/distribution';
import { releaseManifestDigest } from '$lib/distribution-release';
import { getActiveDistributionRelease } from '$lib/server/distribution-releases';
import { catalogPage, decodeCatalogCursor, encodeCatalogCursor, type CatalogChannel, type CatalogRow } from '$lib/server/catalog';
import { query } from '$lib/server/db';
import { environment } from '$lib/server/http';
import { finalDescription } from '$lib/server/descriptions';
import type { PageServerLoad } from './$types';

const PAGE_SIZE = 50;

function channel(value: string | null): CatalogChannel {
  return value === '' || value === 'all' || value === 'dev' || value === 'withdrawn' ? value || 'all' : 'stable';
}

async function activeSystemVersion(db: D1Database): Promise<string | null> {
  try {
    const active = await getActiveDistributionRelease(db, 'system');

    if (!active || active.manifest.kind !== 'system' || await releaseManifestDigest(active.manifest) !== active.candidate.manifest_sha256) return null;
    const version = active.manifest.identity.version;

    return version && parseSystemVersion(version) ? version : null;
  } catch {
    return null;
  }
}

function publicCatalogRow(row: CatalogRow) {
  const { recipe: _recipe, explanation: _explanation, source_json: _source, license: _license, upstream_url: _upstream, ...release } = row;

  return { ...release, description: finalDescription(row, row.name) };
}

export const load: PageServerLoad = async (event) => {
  const env = environment(event);
  const search = event.url.searchParams.get('q')?.trim().slice(0, 100) ?? '';
  const selectedChannel = channel(event.url.searchParams.get('channel'));
  const surfaceParam = event.url.searchParams.get('surface');
  const surface = surfaceParam === 'binary' || surfaceParam === 'recipe' ? surfaceParam : '';
  const architectureParam = event.url.searchParams.get('architecture');
  const architecture = architectureParam === 'x86_64' || architectureParam === 'aarch64' ? architectureParam : '';
  const cursor = decodeCatalogCursor(event.url.searchParams.get('cursor'));
  const after = cursor && (selectedChannel === 'all' || !cursor.channel || cursor.channel === selectedChannel) ? cursor : null;
  const options: Parameters<typeof catalogPage>[1] = { channel: selectedChannel, search, limit: PAGE_SIZE + 1, after };

  if (surface) options.surface = surface;

  if (architecture) options.architecture = architecture;

  const [rows, counts, pending, systemVersion] = await Promise.all([
    catalogPage(env.DB, options),
    query<{ channel: string; count: number }>(env.DB, "SELECT channel,count(DISTINCT name) as count FROM releases WHERE channel IN ('stable','dev') GROUP BY channel"),
    query<{ count: number }>(env.DB, "SELECT count(*) as count FROM requests WHERE status NOT IN ('built','rejected','failed')"),
    activeSystemVersion(env.DB),
  ]);

  const packages = rows.slice(0, PAGE_SIZE).map(publicCatalogRow);

  return {
    packages,
    nextCursor: rows.length > PAGE_SIZE ? encodeCatalogCursor(rows[PAGE_SIZE - 1]!) : null,
    hasNext: rows.length > PAGE_SIZE,
    stats: { stable: counts.find((c) => c.channel === 'stable')?.count ?? 0, dev: counts.find((c) => c.channel === 'dev')?.count ?? 0, requests: pending[0]?.count ?? 0 },
    query: search, channel: selectedChannel, surface, architecture, systemVersion,
  };
};
