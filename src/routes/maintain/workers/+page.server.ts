import { query } from '$lib/server/db';
import { environment, field, formAction, maintainer } from '$lib/server/http';
import { requireSecurity, PolicyError } from '$lib/server/policy';
import { archiveWorker, createEnrollmentToken, pauseWorker, resumeWorker, revokeWorker, WorkerProtocolError } from '$lib/server/workers';
import type { Architecture, Worker } from '$lib/model';
import type { Actions, PageServerLoad } from './$types';
export const load: PageServerLoad = async (event) => {
  const actor = maintainer(event);
  const includeArchived = event.url.searchParams.get('archived') === '1';
  return {
    workers: await query<Worker & { active_leases: number }>(environment(event).DB,
      `SELECT w.*,(SELECT COUNT(*) FROM builds b WHERE b.worker_id=w.id AND b.status='leased' AND b.lease_expires_at>unixepoch()) AS active_leases
        FROM workers w WHERE ?=1 OR w.removed_at IS NULL ORDER BY w.enrolled_at DESC`, Number(includeArchived)),
    includeArchived, canManage: actor.role === 'admin' || actor.role === 'security',
  };
};
const lifecycleAction = (action: (db: D1Database, actor: string, workerId: string) => Promise<Worker>) => (event: Parameters<NonNullable<Actions[string]>>[0]) => formAction(event, async (form) => {
  const actor = requireSecurity(event.locals.actor);
  try { return await action(environment(event).DB, actor.id, field(form, 'id')); }
  catch (cause) { if (cause instanceof WorkerProtocolError) throw new PolicyError(cause.status, cause.message); throw cause; }
});
export const actions: Actions = {
  enroll: (event) => formAction(event, async (form) => {
    const actor = requireSecurity(event.locals.actor);
    try { return await createEnrollmentToken(environment(event).DB, actor.id, field(form, 'architecture') as Architecture); }
    catch (cause) { if (cause instanceof WorkerProtocolError) throw new PolicyError(cause.status, cause.message); throw cause; }
  }),
  revoke: (event) => formAction(event, async (form) => {
    const actor = requireSecurity(event.locals.actor);
    try { await revokeWorker(environment(event).DB, actor.id, field(form, 'id')); }
    catch (cause) { if (cause instanceof WorkerProtocolError) throw new PolicyError(cause.status, cause.message); throw cause; }
  }),
  pause: lifecycleAction(pauseWorker),
  resume: lifecycleAction(resumeWorker),
  archive: lifecycleAction(archiveWorker)
};
