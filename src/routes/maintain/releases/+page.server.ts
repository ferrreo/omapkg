import type { Build, Release } from '$lib/model';
import { query } from '$lib/server/db';
import { environment, field, formAction, maintainer } from '$lib/server/http';
import { publishBuild, promoteBatch, rollbackRelease } from '$lib/server/releases';
import { retryCrashQuarantine } from '$lib/server/crashes';
import { listDistributionReleaseCandidates } from '$lib/server/release-workbench';
import { prepareDistributionRelease, type DistributionCandidateInput } from '$lib/server/distribution-releases';
import { ownedRepositoryReleaseRepositories, prepareOwnedRepositorySnapshots } from '$lib/server/owned-repository';
import { humanMaintainer } from '$lib/server/catalog-ownership';
import { PolicyError } from '$lib/server/policy';
import type { Actions, PageServerLoad } from './$types';

function candidateInput(form: FormData): DistributionCandidateInput {
  const raw = field(form, 'candidate_json');
  if (raw.length > 4 * 1024 * 1024) throw new PolicyError(413, 'Candidate JSON is too large.');
  let value: unknown;
  try { value = JSON.parse(raw); } catch { throw new PolicyError(400, 'Candidate JSON is invalid.'); }
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new PolicyError(400, 'Candidate JSON must be an object.');
  const candidate = { ...(value as Record<string, unknown>) };
  const preparedRaw = field(form, 'prepared_json');
  if (preparedRaw) {
    if (preparedRaw.length > 8 * 1024 * 1024) throw new PolicyError(413, 'Prepared repository output is too large.');
    let prepared: unknown;
    try { prepared = JSON.parse(preparedRaw); } catch { throw new PolicyError(400, 'Prepared repository output is invalid.'); }
    if (!prepared || typeof prepared !== 'object' || Array.isArray(prepared)) throw new PolicyError(400, 'Prepared repository output is invalid.');
    const output = prepared as { preparation?: Record<string, unknown>; repositories?: unknown };
    const preparation = output.preparation ?? (prepared as Record<string, unknown>);
    if (!candidate.repositories && Array.isArray(output.repositories)) candidate.repositories = output.repositories;
    if (!candidate.packageChunks && Array.isArray(preparation.packageChunks)) candidate.packageChunks = preparation.packageChunks;
    if (candidate.packageCount === undefined && typeof preparation.packageCount === 'number') candidate.packageCount = preparation.packageCount;
    if (!candidate.architectures && Array.isArray(output.repositories)) {
      candidate.architectures = [...new Set(output.repositories.flatMap((item) => item && typeof item === 'object' && 'architecture' in item ? [(item as { architecture?: unknown }).architecture] : []))];
    }
  }
  if (!Array.isArray(candidate.repositories) || !Array.isArray(candidate.packageChunks) || typeof candidate.packageCount !== 'number') {
    throw new PolicyError(400, 'Candidate JSON must include repositories, package chunks, and package count, or a prepared repository output.');
  }
  return candidate as unknown as DistributionCandidateInput;
}
export const load: PageServerLoad = async (event) => {
  const actor = maintainer(event);
  const { DB } = environment(event);
  const [releases, builds, crashQuarantines, cohorts, releaseTeam, distributionCandidates] = await Promise.all([
    query<Release>(DB, 'SELECT * FROM releases ORDER BY published_at DESC LIMIT 200'),
    query<Build & { cohort_id: string | null }>(DB, `SELECT b.*,c.cohort_id FROM builds b
      LEFT JOIN cohort_recipe_ownership c ON c.recipe_revision_id=b.revision_id
      WHERE b.id NOT IN (SELECT build_id FROM releases) ORDER BY b.created_at DESC LIMIT 100`),
    query<{ release_id: string; name: string; version: string; status: string; attempts: number; last_error: string | null }>(DB,
      `SELECT q.release_id,r.name,r.version,q.status,q.attempts,q.last_error FROM crash_quarantines q
        JOIN releases r ON r.id=q.release_id WHERE q.status<>'completed' ORDER BY q.updated_at DESC LIMIT 100`),
    query<{ id: string; phase: string; condition: string; current_revision: number; updated_at: number; title: string; lane: 'system' | 'opr'; manifest_json: string; manifest_sha256: string }>(DB,
      `SELECT c.id,c.phase,c.condition,c.current_revision,c.updated_at,r.title,r.lane,r.manifest_json,r.manifest_sha256
       FROM cohorts c JOIN cohort_revisions r ON r.cohort_id=c.id AND r.revision=c.current_revision
       WHERE c.phase NOT IN ('publish','observe') ORDER BY c.updated_at DESC LIMIT 100`),
    actor.id.startsWith('github:')
      ? DB.prepare("SELECT 1 FROM team_memberships WHERE github_id=? AND team='release'").bind(actor.id.slice(7)).first<{ 1: number }>().then(Boolean)
      : Promise.resolve(false),
    listDistributionReleaseCandidates(environment(event)),
  ]);
  return {
    releases, builds, crashQuarantines,
    releaseTeam,
    distributionCandidates,
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
  prepareRepositories: (event) => formAction(event, async (form) => {
    const lane = field(form, 'lane');
    if (lane !== 'system' && lane !== 'opr') throw new PolicyError(400, 'Choose a repository lane.');
    humanMaintainer(event.locals.actor, lane === 'system' ? 'system' : undefined);
    const preparation = await prepareOwnedRepositorySnapshots(environment(event), {
      lane,
      releaseId: field(form, 'release_id'),
      cohortIds: field(form, 'cohort_ids').split(',').map((value) => value.trim()).filter(Boolean),
      trustedParentReleaseId: field(form, 'trusted_parent_release_id') || null,
    });
    return { preparation, repositories: ownedRepositoryReleaseRepositories(preparation) };
  }),
  prepareCandidate: (event) => formAction(event, async (form) => {
    const result = await prepareDistributionRelease(environment(event), event.locals.actor, candidateInput(form));
    return { candidateId: result.candidate.id, manifestSha256: result.candidate.manifest_sha256 };
  }),
  retryQuarantine: (event) => formAction(event, async (form) => {
    await retryCrashQuarantine(environment(event), event.locals.actor, field(form, 'release_id'));
  }),
  publish: (event) => formAction(event, async (form) => ({ release: await publishBuild(environment(event), event.locals.actor, field(form, 'build_id')) })),
  promote: (event) => formAction(event, async (form) => {
    await promoteBatch(environment(event), event.locals.actor, field(form, 'release_ids').split(',').map((id) => id.trim()).filter(Boolean), field(form, 'reason'));
  }),
  rollback: (event) => formAction(event, async (form) => { await rollbackRelease(environment(event), event.locals.actor, field(form, 'release_id'), field(form, 'reason')); })
};
