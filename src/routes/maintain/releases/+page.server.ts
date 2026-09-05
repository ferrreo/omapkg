import type { Build, Release } from '$lib/model';
import { query } from '$lib/server/db';
import { environment, field, formAction, maintainer } from '$lib/server/http';
import { publishBuild, promoteBatch, rollbackRelease } from '$lib/server/releases';
import { retryCrashQuarantine } from '$lib/server/crashes';
import type { Actions, PageServerLoad } from './$types';
export const load: PageServerLoad = async (event) => {
  maintainer(event);
  const { DB } = environment(event);
  const [releases, builds, crashQuarantines] = await Promise.all([
    query<Release>(DB, 'SELECT * FROM releases ORDER BY published_at DESC LIMIT 200'),
    query<Build>(DB, 'SELECT * FROM builds WHERE id NOT IN (SELECT build_id FROM releases) ORDER BY created_at DESC LIMIT 100'),
    query<{ release_id: string; name: string; version: string; status: string; attempts: number; last_error: string | null }>(DB,
      `SELECT q.release_id,r.name,r.version,q.status,q.attempts,q.last_error FROM crash_quarantines q
        JOIN releases r ON r.id=q.release_id WHERE q.status<>'completed' ORDER BY q.updated_at DESC LIMIT 100`)
  ]);
  return { releases, builds, crashQuarantines };
};
export const actions: Actions = {
  retryQuarantine: (event) => formAction(event, async (form) => {
    await retryCrashQuarantine(environment(event), event.locals.actor, field(form, 'release_id'));
  }),
  publish: (event) => formAction(event, async (form) => ({ release: await publishBuild(environment(event), event.locals.actor, field(form, 'build_id')) })),
  promote: (event) => formAction(event, async (form) => {
    await promoteBatch(environment(event), event.locals.actor, field(form, 'release_ids').split(',').map((id) => id.trim()).filter(Boolean), field(form, 'reason'));
  }),
  rollback: (event) => formAction(event, async (form) => { await rollbackRelease(environment(event), event.locals.actor, field(form, 'release_id'), field(form, 'reason')); })
};
