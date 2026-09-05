import { error } from '@sveltejs/kit';
import { query } from '$lib/server/db';
import { environment, maintainer, field, formAction } from '$lib/server/http';
import { approveRevision, getRequest, rejectRequest, startFactory } from '$lib/server/requests';
import { PolicyError } from '$lib/server/policy';
import { listAuditEvents, parseAuditQuery } from '$lib/server/audit';
import { finalDescription } from '$lib/server/descriptions';
import type { Approval, Build, Revision } from '$lib/model';
import type { Actions, PageServerLoad } from './$types';
export const load: PageServerLoad = async (event) => {
  maintainer(event);
  const env = environment(event);
  let request;
  try { request = await getRequest(env, event.params.id); }
  catch (cause) { if (cause instanceof PolicyError) error(cause.status, cause.message); throw cause; }
  const [revisionRows, approvals, builds, events, factoryEvents] = await Promise.all([
    query<Revision>(env.DB, 'SELECT * FROM revisions WHERE request_id=? ORDER BY created_at DESC,rowid DESC', request.id),
    query<Approval>(env.DB, 'SELECT a.* FROM approvals a JOIN revisions r ON r.id=a.revision_id WHERE r.request_id=?', request.id),
    query<Build>(env.DB, 'SELECT b.* FROM builds b JOIN revisions r ON r.id=b.revision_id WHERE r.request_id=? ORDER BY b.created_at DESC', request.id),
    listAuditEvents(env.DB, parseAuditQuery(new URLSearchParams({ request: request.id }))).then((page) => page.events),
    query<{ id: number; stage: string; detail: string; created_at: number }>(env.DB, 'SELECT * FROM factory_events WHERE request_id=? ORDER BY id LIMIT 200', request.id)
  ]);
  const revisions = revisionRows.map((revision) => ({ ...revision, description: finalDescription(revision, request.name) }));
  return { request, revisions, approvals, builds, events, factoryEvents };
};
export const actions: Actions = {
  approveRequest: (event) => formAction(event, async () => startFactory(environment(event), event.locals.actor, event.params.id)),
  regenerate: (event) => formAction(event, async (form) => startFactory(environment(event), event.locals.actor, event.params.id, field(form, 'reason'))),
  rejectRequest: (event) => formAction(event, async (form) => rejectRequest(environment(event), event.locals.actor, event.params.id, field(form, 'reason'))),
  approveRevision: (event) => formAction(event, async (form) => approveRevision(environment(event), event.locals.actor, event.params.id, field(form, 'revision_id'), field(form, 'kind'), field(form, 'reason')))
};
