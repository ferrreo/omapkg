import { prepareReleaseSelection } from "$lib/server/release-preparation";
import type { Build, Release } from '$lib/model';
import { query } from '$lib/server/db';
import { environment, field, formAction, maintainer } from '$lib/server/http';
import { publishBuild, promoteBatch, rollbackRelease } from '$lib/server/releases';
import { retryCrashQuarantine } from '$lib/server/crashes';
import { listDistributionReleaseCandidates } from '$lib/server/release-workbench';
import type { Actions, PageServerLoad } from './$types';

export const load: PageServerLoad = async (event) => {
  const actor = maintainer(event);
  const { DB } = environment(event);

  const [releases, builds, crashQuarantines, cohorts, releaseTeam, distributionCandidates, systems] = await Promise.all([
    query<Release>(DB, 'SELECT * FROM releases ORDER BY published_at DESC LIMIT 200'),
    query<Build & { cohort_id: string | null }>(DB, `SELECT b.*,c.cohort_id FROM builds b
      LEFT JOIN cohort_recipe_ownership c ON c.recipe_revision_id=b.revision_id
      WHERE b.id NOT IN (SELECT build_id FROM releases) ORDER BY b.created_at DESC LIMIT 100`),
    query<{ release_id: string; name: string; version: string; status: string; attempts: number; last_error: string | null }>(DB,
      `SELECT q.release_id,r.name,r.version,q.status,q.attempts,q.last_error FROM crash_quarantines q
        JOIN releases r ON r.id=q.release_id WHERE q.status<>'completed' ORDER BY q.updated_at DESC LIMIT 100`),
    query<{ id: string; phase: string; condition: string; current_revision: number; updated_at: number; title: string; lane: 'system' | 'opr'; manifest_json: string; manifest_sha256: string; opr_count: number }>(DB,
      `SELECT c.id,c.phase,c.condition,c.current_revision,c.updated_at,r.title,r.lane,r.manifest_json,r.manifest_sha256,
         (SELECT COUNT(*) FROM cohort_members m JOIN catalog_revisions p ON p.pkgbase=m.pkgbase AND p.revision=m.catalog_revision WHERE m.cohort_id=c.id AND m.revision=c.current_revision AND p.lane='opr') AS opr_count
       FROM cohorts c JOIN cohort_revisions r ON r.cohort_id=c.id AND r.revision=c.current_revision
       WHERE c.phase NOT IN ('publish','observe') ORDER BY c.updated_at DESC LIMIT 100`),
    actor.id.startsWith('github:')
      ? DB.prepare("SELECT 1 FROM team_memberships WHERE github_id=? AND team='release'").bind(actor.id.slice(7)).first<{ 1: number }>().then(Boolean)
      : Promise.resolve(false),
    listDistributionReleaseCandidates(environment(event)),
    query<{ manifest_sha256: string; release_id: string; channel: string }>(DB, `SELECT manifest_sha256,release_id,channel FROM distribution_release_candidates WHERE kind='system' AND status IN ('signed','active') AND signature_key IS NOT NULL ORDER BY (status='active' AND channel='stable') DESC,sequence DESC LIMIT 100`),
  ]);

  return {
    releases, builds, crashQuarantines,
    releaseTeam,
    distributionCandidates, systems,
    candidates: cohorts.map((cohort) => {
      let systemVersion: string | null = null;
      let compatibleSystems: string[] = [];

      try {
        const manifest = JSON.parse(cohort.manifest_json) as { systemVersion?: unknown; compatibleSystems?: unknown };
        systemVersion = typeof manifest.systemVersion === 'string' ? manifest.systemVersion : null;
        compatibleSystems = Array.isArray(manifest.compatibleSystems) ? manifest.compatibleSystems.filter((value): value is string => typeof value === 'string') : [];
      } catch { /* A malformed immutable manifest remains visible as missing evidence. */ }

      return { ...cohort, systemVersion, compatibleSystems };
    }),
  };
};

export const actions: Actions = {
  prepareRelease: (event) => formAction(event, (form) => prepareReleaseSelection(environment(event), event.locals.actor, form)),
  retryQuarantine: (event) => formAction(event, async (form) => {
    await retryCrashQuarantine(environment(event), event.locals.actor, field(form, 'release_id'));
  }),
  publish: (event) => formAction(event, async (form) => ({ release: await publishBuild(environment(event), event.locals.actor, field(form, 'build_id')) })),
  promote: (event) => formAction(event, async (form) => {
    await promoteBatch(environment(event), event.locals.actor, field(form, 'release_ids').split(',').map((id) => id.trim()).filter(Boolean), field(form, 'reason'));
  }),
  rollback: (event) => formAction(event, async (form) => { await rollbackRelease(environment(event), event.locals.actor, field(form, 'release_id'), field(form, 'reason')); })
};
