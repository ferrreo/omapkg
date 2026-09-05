import { query } from '$lib/server/db';
import { environment } from '$lib/server/http';
import type { CatalogRelease } from '$lib/model';
import { finalDescription } from '$lib/server/descriptions';
import type { PageServerLoad } from './$types';

type CatalogRow = CatalogRelease & { description?: string | null; recipe?: string; explanation?: string };

export const load: PageServerLoad = async (event) => {
  const env = environment(event);
  const search = event.url.searchParams.get('q')?.trim().slice(0, 100) ?? '';
  const requestedChannel = event.url.searchParams.get('channel');
  const channel = requestedChannel === 'dev' || requestedChannel === 'withdrawn' || requestedChannel === 'all' ? requestedChannel : 'stable';
  const surface = event.url.searchParams.get('surface') === 'binary' || event.url.searchParams.get('surface') === 'recipe' ? event.url.searchParams.get('surface') : '';
  const architecture = event.url.searchParams.get('architecture') === 'x86_64' || event.url.searchParams.get('architecture') === 'aarch64' ? event.url.searchParams.get('architecture') : '';
  const channelPredicate = channel === 'all' ? "r.channel IN ('stable','dev','withdrawn')" : 'r.channel=?';
  const filters = [channelPredicate, "r.name LIKE ? ESCAPE '\\'", 'r.published_at=(SELECT max(published_at) FROM releases WHERE name=r.name AND architecture=r.architecture AND channel=r.channel)'];
  const values: unknown[] = channel === 'all' ? [] : [channel];
  values.push(`%${search.replace(/[\\%_]/g, '\\$&')}%`);
  if (surface) { filters.push('r.surface=?'); values.push(surface); }
  if (architecture) { filters.push('r.architecture=?'); values.push(architecture); }
  const [packages, counts, pending] = await Promise.all([
    query<CatalogRow>(env.DB, `SELECT r.*,b.artifact_filename,b.artifact_sha256,b.artifact_size,v.description,v.recipe,v.explanation
      FROM releases r JOIN builds b ON b.id=r.build_id JOIN revisions v ON v.id=b.revision_id
      WHERE ${filters.join(' AND ')} ORDER BY r.name, r.architecture LIMIT 200`, ...values),
    query<{ channel: string; count: number }>(env.DB, "SELECT channel,count(DISTINCT name) as count FROM releases WHERE channel IN ('stable','dev') GROUP BY channel"),
    query<{ count: number }>(env.DB, "SELECT count(*) as count FROM requests WHERE status NOT IN ('built','rejected','failed')")
  ]);
  return { packages: packages.map(({ recipe, explanation, ...release }) => ({ ...release, description: finalDescription({ ...release, recipe, explanation }, release.name) })), stats: { stable: counts.find((c) => c.channel === 'stable')?.count ?? 0, dev: counts.find((c) => c.channel === 'dev')?.count ?? 0, requests: pending[0]?.count ?? 0 }, query: search, channel, surface, architecture };
};
