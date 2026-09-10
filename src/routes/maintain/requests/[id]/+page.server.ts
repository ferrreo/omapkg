import { error } from '@sveltejs/kit';
import { query } from '$lib/server/db';
import { environment, maintainer, field, formAction } from '$lib/server/http';
import { approveRevision, getRequest, rejectRequest, startFactory } from '$lib/server/requests';
import { PolicyError, requireMaintainer } from '$lib/server/policy';
import { listAuditEvents, parseAuditQuery } from '$lib/server/audit';
import { finalDescription } from '$lib/server/descriptions';
import { revisionRecipePolicy } from '../../../../../services/pipeline/recipe-policy';
import { createDependencyRequest, getDependencyBlockers, linkDependencyRequest, resolveDependencyBlockers } from '$lib/server/dependency-blockers';
import { reviewedRuntimeExceptions } from '$lib/server/runtime-evidence';
import { recipeGitUrl } from '$lib/server/catalog-recipe';
import { preservedRecipe } from '$lib/preserved-recipe';
import { reviewedPackageVersion } from '$lib/server/build-outputs';
import { createFactoryDossier, listFactoryDossiers } from '$lib/server/factory-dossier';
import { reviewFactoryRevisionBinding } from '$lib/server/preserved-factory';
import { FactoryRunError, factoryRunErrorStatus } from '$lib/server/factory-runs';
import type { Approval, Build, Revision } from '$lib/model';
import type { Actions, PageServerLoad } from './$types';

export const load: PageServerLoad = async (event) => {
  maintainer(event);
  const env = environment(event);
  let request;

  try { request = await getRequest(env, event.params.id); }
  catch (cause) { if (cause instanceof PolicyError) error(cause.status, cause.message); throw cause; }

  const [revisionRows, approvals, builds, events, factoryEvents, dossiers, factoryRuns, factoryBindings] = await Promise.all([
    query<Revision>(env.DB, 'SELECT * FROM revisions WHERE request_id=? ORDER BY created_at DESC,rowid DESC', request.id),
    query<Approval>(env.DB, 'SELECT a.* FROM approvals a JOIN revisions r ON r.id=a.revision_id WHERE r.request_id=?', request.id),
    query<Build>(env.DB, 'SELECT b.* FROM builds b JOIN revisions r ON r.id=b.revision_id WHERE r.request_id=? ORDER BY b.created_at DESC', request.id),
    listAuditEvents(env.DB, parseAuditQuery(new URLSearchParams({ request: request.id }))).then((page) => page.events),
    query<{ id: number; stage: string; detail: string; created_at: number }>(env.DB, 'SELECT * FROM factory_events WHERE request_id=? ORDER BY id LIMIT 200', request.id),
    listFactoryDossiers(env, request.id),
    query<{ id: string; target_kind: string; status: string; attempt_count: number }>(env.DB, `SELECT id,target_kind,status,attempt_count FROM factory_runs
      WHERE target_id=? OR id IN (SELECT a.run_id FROM factory_run_attempts a JOIN revisions r ON r.id=a.candidate_revision_id WHERE r.request_id=?)
      ORDER BY updated_at DESC,id LIMIT 50`, request.id, request.id),
    query<{ revision_id: string; source_revision_id: string; cohort_id: string; status: string }>(env.DB, `SELECT b.revision_id,b.source_revision_id,b.cohort_id,b.status
      FROM factory_revision_bindings b JOIN revisions r ON r.id=b.revision_id WHERE r.request_id=? ORDER BY b.created_at DESC,b.revision_id`, request.id),
  ]);

  const revisions = revisionRows.map((revision) => ({ ...revision, preserved: preservedRecipe(revision), fullVersion: reviewedPackageVersion(revision), recipeUrl: recipeGitUrl(env.GITHUB_REPOSITORY, revision.commit_sha, request.name, revision.sbom_json), recipePolicy: revisionRecipePolicy(revision.sbom_json), runtimeExceptions: reviewedRuntimeExceptions(revision.sbom_json), description: finalDescription(revision, request.name) }));
  const imported = await env.DB.prepare('SELECT capture_sha256 FROM preserved_recipe_imports WHERE request_id=?').bind(request.id).first<{ capture_sha256: string }>();
  const blockers = await getDependencyBlockers(env.DB, request.id);

  const dependencyProposals = await query<{ id: string; blocker_id: string; status: string }>(env.DB,
    `SELECT p.id,l.blocker_id,p.status FROM dependency_proposals p JOIN dependency_proposal_blockers l ON l.proposal_id=p.id
      JOIN dependency_blockers d ON d.id=l.blocker_id WHERE d.request_id=? AND p.status<>'superseded'`, request.id);

  return { request, revisions, approvals, builds, events, factoryEvents, blockers, dependencyProposals, imported, dossiers, factoryRuns, factoryBindings };
};

export const actions: Actions = {
  reviewFactoryBinding: (event) => formAction(event, async (form) => {
    const env = environment(event);
    const revisionId = field(form, 'revision_id');
    const revision = await env.DB.prepare('SELECT id FROM revisions WHERE id=? AND request_id=?').bind(revisionId, event.params.id).first<{ id: string }>();
    if (!revision || form.get('inputs_acknowledged') !== 'on') throw new PolicyError(400, 'Confirm review of this revision and its retained parent inputs.');
    try { await reviewFactoryRevisionBinding(env.DB, event.locals.actor, revision.id, field(form, 'reason')); }
    catch (cause) {
      if (cause instanceof FactoryRunError) throw new PolicyError(factoryRunErrorStatus(cause), cause.message);
      throw cause;
    }
  }),
  createDossier: (event) => formAction(event, async (form) => {
    const env = environment(event);
    const request = await getRequest(env, event.params.id);
    const actor = requireMaintainer(event.locals.actor, request.area);
    const stored = await createFactoryDossier(env, actor.id, { requestId: request.id, revisionId: field(form, 'revision_id') });

    return { dossierId: stored.dossier.id };
  }),
  approveRequest: (event) => formAction(event, async () => startFactory(environment(event), event.locals.actor, event.params.id)),
  regenerate: (event) => formAction(event, async (form) => startFactory(environment(event), event.locals.actor, event.params.id, field(form, 'reason'))),
  rejectRequest: (event) => formAction(event, async (form) => rejectRequest(environment(event), event.locals.actor, event.params.id, field(form, 'reason'))),
  approveRevision: (event) => formAction(event, async (form) => approveRevision(environment(event), event.locals.actor, event.params.id, field(form, 'revision_id'), field(form, 'kind'), field(form, 'reason'), form.get('custom_shell_acknowledged') === 'on', form.get('runtime_exceptions_acknowledged') === 'on')),
  linkDependency: (event) => formAction(event, async (form) => linkDependencyRequest(environment(event), event.locals.actor, event.params.id, field(form, 'blocker_id'), field(form, 'dependency_request_id'))),
  createDependency: (event) => formAction(event, async (form) => ({ requestId: await createDependencyRequest(environment(event), event.locals.actor, event.params.id, field(form, 'blocker_id'), {
    name: field(form, 'name'), upstream_url: field(form, 'upstream_url'), source_kind: field(form, 'source_kind'),
    area: field(form, 'area'), declared_license: field(form, 'declared_license'), description: field(form, 'description'),
  }) })),
  recheckDependencies: (event) => formAction(event, async () => {
    const env = environment(event);
    const request = await getRequest(env, event.params.id);
    requireMaintainer(event.locals.actor, request.area);
    await resolveDependencyBlockers(env, request.id);
  }),
};
