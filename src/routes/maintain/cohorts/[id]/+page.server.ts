import { error } from '@sveltejs/kit';
import { canonicalJson } from '$lib/canonical-json';
import type { CohortManifest, CohortEvent } from '$lib/cohorts';
import { approveCohortChangelog, generateCohortFacts, saveCohortChangelog, type ChangelogRow } from '$lib/server/cohort-changelogs';
import { evaluateCohortGate } from '$lib/server/cohort-gates';
import { changeCohortPhase } from '$lib/server/cohort-phases';
import { cohortEvents, getCohort, proposeCohort, scopeAuthority, type CohortScopeInput } from '$lib/server/cohorts';
import { getCatalogPackage, listCatalogPackages } from '$lib/server/catalog-ownership';
import { query, sha256 } from '$lib/server/db';
import { environment, field, formAction, maintainer } from '$lib/server/http';
import { PolicyError } from '$lib/server/policy';
import type { Actions, PageServerLoad } from './$types';

export const load: PageServerLoad = async (event) => {
  const actor = maintainer(event); const env = environment(event); const record = await getCohort(env.DB, event.params.id);
  const manifest: CohortManifest = JSON.parse(record.manifest_json);
  const gate = await evaluateCohortGate(env, record, false); const facts = await generateCohortFacts(env.DB, record);
  let canEdit = true; try { scopeAuthority(actor, manifest); } catch { canEdit = false; }
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
    WHERE m.cohort_id=? AND m.revision=? ORDER BY p.pkgbase,r.created_at DESC LIMIT 1024`, record.id, record.current_revision);
  return { record, manifest, gate: { next: gate.next, blockers: gate.blockers, matrix: gate.matrix }, facts,
    factsSha256: await sha256(canonicalJson(facts)), canEdit, updates,
    events: events.map((row) => ({ ...JSON.parse(row.event_json) as CohortEvent, digest: row.event_sha256 })),
    changelogs: await query<ChangelogRow & { review_count: number }>(env.DB, `SELECT c.*,
      (SELECT COUNT(*) FROM cohort_changelog_reviews r WHERE r.cohort_id=c.cohort_id AND r.revision=c.revision AND r.changelog_sha256=c.digest) AS review_count
      FROM cohort_changelogs c WHERE c.cohort_id=? AND c.revision=? ORDER BY c.created_at DESC,c.rowid DESC LIMIT 20`, record.id, record.current_revision),
    history: await query<{ revision: number; manifest_sha256: string; created_at: number; title: string }>(env.DB,
      'SELECT revision,manifest_sha256,created_at,title FROM cohort_revisions WHERE cohort_id=? ORDER BY revision DESC LIMIT 50', record.id),
    search: event.url.searchParams.get('search') ?? '',
    packages: event.url.searchParams.has('search') ? await listCatalogPackages(env.DB, { search: event.url.searchParams.get('search') ?? '', limit: 25 }) : [],
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
};
