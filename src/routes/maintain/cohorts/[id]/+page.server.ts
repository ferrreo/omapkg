import { error, redirect } from '@sveltejs/kit';
import { canonicalJson } from '$lib/canonical-json';
import { cohortMemberCount, cohortPageSize, type CohortManifest, type CohortEvent } from '$lib/cohorts';
import { approveCohortChangelog, cohortChangePage, generateCohortFacts, saveCohortChangelog, type ChangelogRow } from '$lib/server/cohort-changelogs';
import { evaluateCohortGate } from '$lib/server/cohort-gates';
import { aggregateCohortGate, cohortPageView } from '$lib/server/cohort-gate-pages';
import { cohortMembers, readCohortManifest } from '$lib/server/cohort-members';
import { changeCohortPhase } from '$lib/server/cohort-phases';
import { cohortEvents, getCohort, proposeCohort, scopeAuthority, type CohortScopeInput } from '$lib/server/cohorts';
import { getCatalogPackage, listCatalogPackages } from '$lib/server/catalog-ownership';
import { query, sha256 } from '$lib/server/db';
import { environment, field, formAction, maintainer } from '$lib/server/http';
import { PolicyError } from '$lib/server/policy';
import { createQualificationPlan, reviewQualificationPlan } from '$lib/server/native-qualification';
import type { Actions, PageServerLoad } from './$types';

export const load: PageServerLoad = async (event) => {
  const actor = maintainer(event); const env = environment(event); const record = await getCohort(env.DB, event.params.id);
  const manifest = await readCohortManifest(record); const memberCount = cohortMemberCount(manifest);
  const memberSearch = (event.url.searchParams.get('member') ?? '').trim().slice(0, 64);

  const location = memberSearch ? manifest.schemaVersion === 1
    ? manifest.members.findIndex((member) => member.pkgbase === memberSearch)
    : (await env.DB.prepare('SELECT ordinal FROM cohort_members WHERE cohort_id=? AND revision=? AND pkgbase=?')
      .bind(record.id, record.current_revision, memberSearch).first<{ ordinal: number }>())?.ordinal ?? -1 : -1;

  const page = location >= 0 ? Math.floor(location / cohortPageSize) : Number(event.url.searchParams.get('page') ?? '0');

  if (!Number.isSafeInteger(page) || page < 0 || page * cohortPageSize >= memberCount) error(400, 'Choose an existing cohort member page.');

  if (location >= 0 && !event.url.searchParams.has('page')) {
    const target = new URL(event.url); target.searchParams.set('page', String(page));
    target.hash = `member-${memberSearch}${event.url.searchParams.get('tab') === 'tests' ? '-x86_64' : ''}`;
    redirect(303, target.pathname + target.search + target.hash);
  }

  const members = await cohortMembers(env.DB, record, page * cohortPageSize);
  const progress = manifest.schemaVersion === 2 ? await aggregateCohortGate(env.DB, record) : null;
  const gate = progress ?? await evaluateCohortGate(env, record, false);
  const checkedPage = progress ? await cohortPageView(env.DB, record, members, page) : null;
  const pageGate = checkedPage ?? gate;
  const facts = await generateCohortFacts(env.DB, record);
  const changes = await cohortChangePage(env.DB, record, event.url.searchParams.get('changeAfter') ?? '');
  let canEdit = true;

 try { scopeAuthority(actor, manifest); } catch { canEdit = false; }

  const after = Math.max(0, Number(event.url.searchParams.get('after')) || 0);
  const events = await cohortEvents(env.DB, record.id, after);

  const updates = await query<{ pkgbase: string; catalog_revision: number; recipe_revision_id: string | null; full_version: string | null }>(env.DB, `
    SELECT p.pkgbase,p.current_revision AS catalog_revision,r.id AS recipe_revision_id,
      CASE WHEN r.id IS NOT NULL THEN r.version||'-'||COALESCE(r.pkgrel,1) END AS full_version
    FROM cohort_members m JOIN catalog_packages p ON p.pkgbase=m.pkgbase
    LEFT JOIN requests q ON q.name=p.pkgbase AND q.status NOT IN ('rejected','generating')
    LEFT JOIN revisions r ON r.request_id=q.id
      AND r.id=(SELECT latest.id FROM revisions latest WHERE latest.request_id=q.id ORDER BY latest.created_at DESC,latest.rowid DESC LIMIT 1)
      AND NOT EXISTS(SELECT 1 FROM builds b JOIN releases rel ON rel.build_id=b.id WHERE b.revision_id=r.id)
    WHERE m.cohort_id=? AND m.revision=? AND m.pkgbase IN (SELECT value FROM json_each(?)) ORDER BY p.pkgbase,r.created_at DESC LIMIT 1024`, record.id, record.current_revision, JSON.stringify(members.map((member) => member.pkgbase)));

  const packages = event.url.searchParams.has('search') ? await listCatalogPackages(env.DB, { search: event.url.searchParams.get('search') ?? '', limit: 25 }) : [];

  const existingMembers = await query<{ pkgbase: string }>(env.DB, 'SELECT pkgbase FROM cohort_members WHERE cohort_id=? AND revision=? AND pkgbase IN (SELECT value FROM json_each(?))',
    record.id, record.current_revision, JSON.stringify(packages.map((item) => item.pkgbase)));

  const qualificationPlans = await query<any>(env.DB, `SELECT p.id,p.operation,p.architecture,p.coverage_kind,p.coverage_pkgbase,p.coverage_root_sha256,p.coverage_release_id,p.coverage_sha256,p.plan_sha256,p.plan_json,p.created_by,p.created_at,
    (SELECT COUNT(DISTINCT r.kind) FROM native_qualification_plan_reviews r WHERE r.plan_id=p.id) AS review_kinds,
    (SELECT COUNT(DISTINCT r.actor) FROM native_qualification_plan_reviews r WHERE r.plan_id=p.id) AS review_actors
    FROM native_qualification_plans p WHERE p.cohort_id=? AND p.revision=? ORDER BY p.created_at DESC,p.rowid DESC LIMIT 100`, record.id, record.current_revision);

  const qualificationEvidence = await query<any>(env.DB, `SELECT e.id,e.plan_id,e.operation,e.architecture,e.coverage_kind,e.coverage_pkgbase,e.coverage_root_sha256,e.status,e.reproducibility_status,e.worker_id,e.created_at,
    (SELECT COUNT(*) FROM native_qualification_exceptions x WHERE x.evidence_id=e.id AND x.expires_at>unixepoch()) AS exception_count
    FROM native_qualification_evidence e WHERE e.cohort_id=? AND e.revision=? ORDER BY e.created_at DESC,e.rowid DESC LIMIT 256`, record.id, record.current_revision);

  return { record, manifest, gate: { next: gate.next, blockers: gate.blockers, matrix: gate.matrix }, facts,
    members, memberCount, page, pageCount: Math.ceil(memberCount / cohortPageSize), progress: progress?.pages ?? null,
    memberSearch, memberFound: location >= 0,
    pageGate: { blockers: pageGate.blockers, matrix: pageGate.matrix.filter((row) => members.some((member) => member.pkgbase === row.pkgbase)) },
    pageCheckedAt: checkedPage?.checkedAt ?? null, changes: changes.changes, nextChange: changes.next,
    factsSha256: await sha256(canonicalJson(facts)), canEdit, updates,
    events: events.map((row) => ({ ...JSON.parse(row.event_json) as CohortEvent, digest: row.event_sha256 })),
    changelogs: await query<ChangelogRow & { review_count: number }>(env.DB, `SELECT c.*,
      (SELECT COUNT(*) FROM cohort_changelog_reviews r WHERE r.cohort_id=c.cohort_id AND r.revision=c.revision AND r.changelog_sha256=c.digest) AS review_count
      FROM cohort_changelogs c WHERE c.cohort_id=? AND c.revision=? ORDER BY c.created_at DESC,c.rowid DESC LIMIT 20`, record.id, record.current_revision),
    history: await query<{ revision: number; manifest_sha256: string; created_at: number; title: string }>(env.DB,
      'SELECT revision,manifest_sha256,created_at,title FROM cohort_revisions WHERE cohort_id=? ORDER BY revision DESC LIMIT 50', record.id),
    search: event.url.searchParams.get('search') ?? '',
    packages, existingMembers: existingMembers.map((item) => item.pkgbase),
    qualificationPlans, qualificationEvidence,
    tab: ['overview', 'changes', 'phases', 'tests', 'history'].includes(event.url.searchParams.get('tab') ?? '') ? event.url.searchParams.get('tab')! : 'overview',
  };
};

export const actions: Actions = {
  phase: (event) => formAction(event, async (form) => changeCohortPhase(environment(event), event.locals.actor, event.params.id, {
    revision: Number(field(form, 'revision')), sequence: Number(field(form, 'sequence')), manifestSha256: field(form, 'digest'),
    action: field(form, 'action') as 'advance' | 'recheck' | 'hold' | 'resume', reason: field(form, 'reason'),
  })),
  scope: (event) => formAction(event, async (form) => {
    const { DB } = environment(event); const record = await getCohort(DB, event.params.id);

    if (record.current_revision !== Number(field(form, 'revision')) || record.manifest_sha256 !== field(form, 'digest')) throw new PolicyError(409, 'Cohort scope changed. Refresh and review it.');
    const manifest: CohortManifest = JSON.parse(record.manifest_json);

    if (manifest.schemaVersion === 2) throw new PolicyError(400, 'Upload the complete revised scope to change a chunked cohort.');

    const input: CohortScopeInput = { title: manifest.title, lane: manifest.lane, systemVersion: manifest.systemVersion,
      parentSnapshot: manifest.parentSnapshot, compatibleSystems: manifest.compatibleSystems,
      members: manifest.members.map((member) => ({ pkgbase: member.pkgbase, catalogRevision: member.catalogRevision, recipeRevisionId: member.recipe?.id ?? null, cause: member.cause, reason: member.reason })) };

    const pkgbase = field(form, 'pkgbase'); const action = field(form, 'action');

    if (action === 'remove') input.members = input.members.filter((member) => member.pkgbase !== pkgbase);
    else if (action === 'bind') {
      const member = input.members.find((member) => member.pkgbase === pkgbase);

      if (!member) error(400, 'Select a current cohort member.');
      member.catalogRevision = Number(field(form, 'catalogRevision'));
      member.recipeRevisionId = field(form, 'recipeRevisionId') || null;
    } else if (action === 'add') {
      const catalog = await getCatalogPackage(DB, pkgbase);

      if (!catalog || catalog.revision !== Number(field(form, 'catalogRevision'))) throw new PolicyError(409, 'Catalog selection changed.');
      input.members.push({ pkgbase, catalogRevision: catalog.revision, recipeRevisionId: null, cause: field(form, 'cause') as CohortScopeInput['members'][number]['cause'], reason: field(form, 'reason') });
    } else throw new PolicyError(400, 'Choose a scope action.');
    await proposeCohort(DB, event.locals.actor, record.id, record.current_revision, input, field(form, 'reason'));
  }),
  changelog: (event) => formAction(event, async (form) => saveCohortChangelog(environment(event).DB, event.locals.actor, event.params.id,
    Number(field(form, 'revision')), field(form, 'factsDigest'), field(form, 'narrative'))),
  approveChangelog: (event) => formAction(event, async (form) => approveCohortChangelog(environment(event).DB, event.locals.actor, event.params.id,
    Number(field(form, 'revision')), field(form, 'digest'), field(form, 'reason'))),
  qualificationPlan: (event) => formAction(event, async (form) => {
    const raw = field(form, 'planJson');
    let plan: unknown;

 try { plan = JSON.parse(raw); } catch { throw new PolicyError(400, 'Qualification plan JSON is invalid.'); }

    if (!plan || typeof plan !== 'object' || Array.isArray(plan) || (plan as { cohortId?: unknown }).cohortId !== event.params.id || (plan as { revision?: unknown }).revision !== (await getCohort(environment(event).DB, event.params.id)).current_revision) throw new PolicyError(409, 'Qualification plan must target this current cohort revision.');
    const result = await createQualificationPlan(environment(event), event.locals.actor, plan);

    return { qualificationPlanId: result.id, qualificationPlanSha256: result.planSha256 };
  }),
  qualificationReview: (event) => formAction(event, async (form) => {
    const DB = environment(event).DB; const planId = field(form, 'planId');
    const plan = await DB.prepare('SELECT cohort_id,revision FROM native_qualification_plans WHERE id=?').bind(planId).first<{ cohort_id: string; revision: number }>();
    const current = await getCohort(DB, event.params.id);

    if (!plan || plan.cohort_id !== event.params.id || plan.revision !== current.current_revision) throw new PolicyError(409, 'Qualification plan is not part of this current cohort revision.');

    return reviewQualificationPlan(environment(event), event.locals.actor, planId, field(form, 'kind') as 'area' | 'security', field(form, 'reason'));
  }),
};
