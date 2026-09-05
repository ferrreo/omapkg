import { query } from '$lib/server/db';
import { environment, maintainer } from '$lib/server/http';
import type { PackageRequest, Build } from '$lib/model';
import type { PageServerLoad } from './$types';
export const load: PageServerLoad = async (event) => {
  maintainer(event);
  const { DB } = environment(event);
  const [requests, builds, counts] = await Promise.all([
    query<PackageRequest>(DB, 'SELECT * FROM requests ORDER BY created_at DESC LIMIT 200'),
    query<Build & { name: string }>(DB, 'SELECT b.*,q.name FROM builds b JOIN revisions r ON r.id=b.revision_id JOIN requests q ON q.id=r.request_id ORDER BY b.created_at DESC LIMIT 50'),
    query<{ status: string; count: number }>(DB, 'SELECT status,count(*) as count FROM requests GROUP BY status')
  ]);
  return { requests, builds, counts: Object.fromEntries(counts.map((row) => [row.status, row.count])) };
};
