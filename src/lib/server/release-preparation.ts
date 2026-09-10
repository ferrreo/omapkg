import { canonicalJson } from '../canonical-json';
import type { Actor } from '../model';
import type { Env } from './env';
import { humanMaintainer } from './catalog-ownership';
import { getCohort } from './cohorts';
import { readCohortManifest } from './cohort-members';
import { sha256 } from './db';
import { getActiveDistributionRelease, prepareStoredRelease } from './distribution-releases';
import { prepareOwnedRepositorySnapshots } from './owned-repository';
import { PolicyError } from './policy';

export async function prepareReleaseSelection(env: Env, actor: Actor | null, form: FormData) {
  const lane = String(form.get('lane') ?? '');
  const channel = String(form.get('channel') ?? '');
  if (lane !== 'system' && lane !== 'opr') throw new PolicyError(400, 'Choose a release type.');
  const human = humanMaintainer(actor, lane === 'system' ? 'system' : undefined);
  if (channel !== 'stable' && !(lane === 'system' && (channel === 'edge' || channel === 'rc')) && !(lane === 'opr' && channel === 'quarantine')) {
    throw new PolicyError(400, 'Choose a channel for this release type.');
  }
  const selections = form.getAll('changes').map(String);
  if (!selections.length || selections.length > 100 || new Set(selections).size !== selections.length) throw new PolicyError(400, 'Select the changes to include.');
  const cohorts = [];
  for (const selection of selections) {
    const match = selection.match(/^([A-Za-z0-9_-]{1,128})@([a-f0-9]{64})$/);
    if (!match) throw new PolicyError(400, 'Refresh the page and select the changes again.');
    const cohort = await getCohort(env.DB, match[1]);
    if (cohort.manifest_sha256 !== match[2]) throw new PolicyError(409, `${cohort.title} changed. Refresh and review it again.`);
    if (cohort.condition === 'held' || (cohort.lane !== lane && !(lane === 'opr' && cohort.lane === 'system'))) throw new PolicyError(409, `${cohort.title} is not available for this release.`);
    cohorts.push({ ...cohort, metadata: await readCohortManifest(cohort) });
  }
  const parent = await getActiveDistributionRelease(env.DB, lane, channel) ?? await getActiveDistributionRelease(env.DB, lane, 'stable');
  const systemDigest = lane === 'opr' ? String(form.get('system') ?? '') : null;
  if (lane === 'opr') {
    const system = await env.DB.prepare("SELECT 1 FROM distribution_release_candidates WHERE kind='system' AND manifest_sha256=? AND status IN ('signed','active') AND signature_key IS NOT NULL")
      .bind(systemDigest).first();
    if (!system) throw new PolicyError(409, 'Choose a tested system release for these app updates.');
  }
  const versions = [...new Set(cohorts.map((cohort) => cohort.metadata.systemVersion))];
  if (lane === 'system' && (versions.length !== 1 || !versions[0])) throw new PolicyError(409, 'Select changes planned for the same system version. Set the version in the change set first.');
  const selectionDigest = await sha256(canonicalJson({ lane, channel, systemDigest, parent: parent?.candidate.manifest_sha256 ?? null,
    cohorts: cohorts.map((cohort) => ({ id: cohort.id, digest: cohort.manifest_sha256 })).sort((a, b) => a.id.localeCompare(b.id)) }));
  const releaseId = lane === 'system' ? versions[0]! : `opr-${selectionDigest.slice(0, 16)}`;
  const preparation = await prepareOwnedRepositorySnapshots(env, { lane, releaseId, cohortIds: cohorts.map((cohort) => cohort.id), trustedParentReleaseId: parent?.candidate.release_id ?? null });
  for (const cohort of cohorts) {
    const included = await env.DB.prepare(`SELECT 1 FROM owned_repository_universe_packages u JOIN owned_repository_artifacts a ON a.id=u.artifact_id
      WHERE u.universe_id=? AND a.cohort_id=? AND a.cohort_revision=? LIMIT 1`).bind(preparation.universeId, cohort.id, cohort.current_revision).first();
    if (!included) throw new PolicyError(409, 'This release version was already prepared with different changes. Choose a new version before preparing it again.');
  }
  if (cohorts.some((cohort) => !['approve', 'publish', 'observe'].includes(cohort.phase) || cohort.condition !== 'ready')) {
    return { message: 'Release files are prepared. Complete the remaining checks and reviews, then return here to create the release candidate.',
      preparedRelease: { releaseId, packageCount: preparation.packageCount }, nextChanges: cohorts.map((cohort) => ({ id: cohort.id, title: cohort.title })) };
  }
  const result = await prepareStoredRelease(env, human, preparation, channel, systemDigest);
  return { message: 'Release candidate created. Review it below before approving publication.', candidateId: result.candidate.id };
}
