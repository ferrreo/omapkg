import { canonicalJson } from '../canonical-json';
import { cohortGatePageSize, cohortMemberCount, type CohortBlocker, type CohortRow } from '../cohorts';
import { cohortPhases, requiredArchitectures, type CohortPhase } from '../distribution';
import type { Architecture, Build, Revision } from '../model';
import { assertExplicitReview } from '../../../services/pipeline/recipe-policy';
import { actorForGithubId } from './auth';
import { humanMaintainer } from './catalog-ownership';
import { query } from './db';
import type { Env } from './env';
import { PolicyError, requireSecurity, validateRevision } from './policy';
import { assertAttestation, assertReviewed, joinedBuild } from './release-evidence';
import { verifyR2Object } from './release-storage';
import { buildArtifacts, cohortOutputContract, storedOutputContract } from './build-outputs';
import { verifyOutputProvenance } from './build-output-evidence';
import { getBuildForWorker } from './worker-protocol';
import type { Worker } from '../model';
import type { FrozenEvidence } from '../frozen-inputs';
import { selectedInputLock } from './input-locks';
import { cohortMembers, readCohortManifest } from './cohort-members';
import { assertRetainedAbiEvidence } from './build-abi-evidence';

export interface CohortMatrixRow {
  pkgbase: string; architecture: Architecture; required: boolean; status: string;
  buildId: string | null; attempt: number | null; reason: string | null;
}
export type CohortGate = { next: CohortPhase | null; blockers: CohortBlocker[]; matrix: CohortMatrixRow[]; fences: D1PreparedStatement[] };
const message = (cause: unknown) => cause instanceof Error ? cause.message : 'Evidence could not be verified.';

async function reviewAuthority(env: Env, actorId: string, kind: string, area: string) {
  const actor = await actorForGithubId(env.DB, actorId.startsWith('github:') ? actorId.slice(7) : '');
  humanMaintainer(actor, area);
  if (kind === 'security') requireSecurity(actor);
}

export async function evaluateCohortGate(env: Env, current: CohortRow, verifyArtifacts = true, page?: number): Promise<CohortGate> {
  const manifest = await readCohortManifest(current);
  const pageSize = cohortGatePageSize(current.phase);
  if (page !== undefined && (!Number.isSafeInteger(page) || page < 0 || page * pageSize >= cohortMemberCount(manifest))) throw new PolicyError(400, 'Choose an existing cohort member page.');
  if (manifest.schemaVersion === 2 && page === undefined) throw new PolicyError(400, 'Check each member page before advancing this complete cohort.');
  const members = manifest.schemaVersion === 1 && page === undefined ? manifest.members : await cohortMembers(env.DB, current, (page ?? 0) * pageSize, pageSize);
  const gate: CohortGate = { next: cohortPhases[cohortPhases.indexOf(current.phase) + 1] ?? null, blockers: [], matrix: [], fences: [] };
  const block = (code: string, reason: string, pkgbase: string | null = null, architecture: Architecture | null = null, href: string | null = null) => {
    gate.blockers.push({ code, reason, pkgbase, architecture, href });
  };
  const phaseIndex = cohortPhases.indexOf(current.phase);
  for (const member of members) {
    const catalogLink = `/maintain/catalog/${encodeURIComponent(member.pkgbase)}`;
    const policy = await env.DB.prepare('SELECT current_revision,admitted_revision FROM catalog_packages WHERE pkgbase=?')
      .bind(member.pkgbase).first<{ current_revision: number; admitted_revision: number | null }>();
    if (policy?.current_revision !== member.catalogRevision || policy.admitted_revision !== member.catalogRevision) {
      block('catalog-review', 'Current catalog policy needs independent area and security admission.', member.pkgbase, null, catalogLink);
    } else {
      const reviews = await query<{ kind: string; actor: string }>(env.DB,
        'SELECT kind,actor FROM catalog_reviews WHERE pkgbase=? AND revision=? AND manifest_sha256=?', member.pkgbase, member.catalogRevision, member.catalogSha256);
      if (new Set(reviews.map((row) => row.kind)).size !== 2 || new Set(reviews.map((row) => row.actor)).size !== 2) {
        block('catalog-review', 'Independent catalog reviewers are required.', member.pkgbase, null, catalogLink);
      }
      for (const review of reviews) {
        try { await reviewAuthority(env, review.actor, review.kind, member.policy.ownerArea); }
        catch { block('catalog-authority', `${review.kind} catalog reviewer no longer has required access.`, member.pkgbase, null, catalogLink); }
        gate.fences.push(env.DB.prepare(`INSERT INTO distribution_assertions(expected,actual)
          SELECT 1,COUNT(*) FROM catalog_reviews WHERE pkgbase=? AND revision=? AND manifest_sha256=? AND kind=? AND actor=?`)
          .bind(member.pkgbase, member.catalogRevision, member.catalogSha256, review.kind, review.actor));
        gate.fences.push(authorityFence(env.DB, review.actor, review.kind, member.policy.ownerArea));
      }
    }
    gate.fences.push(env.DB.prepare(`INSERT INTO distribution_assertions(expected,actual)
      SELECT 1,COUNT(*) FROM catalog_packages WHERE pkgbase=? AND current_revision=? AND admitted_revision=?`)
      .bind(member.pkgbase, member.catalogRevision, member.catalogRevision));
    const revision = member.recipe ? await env.DB.prepare('SELECT * FROM revisions WHERE id=?').bind(member.recipe.id).first<Revision>() : null;
    if (phaseIndex >= 1 && !revision) block('recipe-missing', 'Generate and bind an exact recipe revision.', member.pkgbase, null, '/maintain/requests');
    const builds = member.recipe ? await query<Build>(env.DB, 'SELECT * FROM builds WHERE revision_id=? ORDER BY architecture', member.recipe.id) : [];
    for (const architecture of requiredArchitectures) {
      const required = member.policy.architectures.includes(architecture);
      const build = builds.find((row) => row.architecture === architecture);
      gate.matrix.push({ pkgbase: member.pkgbase, architecture, required, status: required ? build?.status ?? 'missing' : 'not-required',
        buildId: build?.id ?? null, attempt: build?.attempt ?? null,
        reason: required ? build?.error ?? null : member.policy.architectureExceptions.find((exception) => exception.architecture === architecture)?.reason ?? null });
    }
    if (!revision || !member.recipe) continue;
    const requestLink = `/maintain/requests/${encodeURIComponent(revision.request_id)}`;
    const request = await env.DB.prepare(`SELECT status,
      (SELECT r.id FROM revisions r WHERE r.request_id=requests.id ORDER BY r.created_at DESC,r.rowid DESC LIMIT 1) AS latest
      FROM requests WHERE id=?`).bind(revision.request_id).first<{ status: string; latest: string }>();
    if (request?.latest !== revision.id || ['blocked', 'rejected', 'generating'].includes(request?.status ?? '')) {
      block('recipe-changed', 'Request is blocked, rejected or has a newer recipe. Update cohort scope.', member.pkgbase, null, requestLink);
    }
    gate.fences.push(env.DB.prepare(`INSERT INTO distribution_assertions(expected,actual) SELECT 1,COUNT(*) FROM requests q WHERE id=?
      AND status NOT IN ('blocked','rejected','generating')
      AND ?=(SELECT r.id FROM revisions r WHERE r.request_id=q.id ORDER BY r.created_at DESC,r.rowid DESC LIMIT 1)`)
      .bind(revision.request_id, revision.id));
    const dependencyCount = await env.DB.prepare("SELECT COUNT(*) AS count FROM dependency_blockers WHERE request_id=? AND status='open'").bind(revision.request_id).first<{ count: number }>();
    if (dependencyCount?.count) block('dependency', `${dependencyCount.count} unresolved dependency findings need owned providers.`, member.pkgbase, null, requestLink);
    gate.fences.push(env.DB.prepare("INSERT INTO distribution_assertions(expected,actual) SELECT 0,COUNT(*) FROM dependency_blockers WHERE request_id=? AND status='open'").bind(revision.request_id));
    if (phaseIndex < 1) continue;
    try {
      if (revision.manifest_sha256 !== member.recipe.manifestSha256 || canonicalJson((JSON.parse(revision.architectures_json) as string[]).sort()) !== canonicalJson(member.policy.architectures)) {
        throw new PolicyError(409, 'Recipe inputs or targets differ from the cohort.');
      }
      await validateRevision(revision);
      await assertExplicitReview(env.DB, revision.id, revision.manifest_sha256, revision.sbom_json);
    } catch (cause) { block('recipe-integrity', message(cause), member.pkgbase, null, requestLink); }
    const reviews = await query<{ kind: string; actor: string }>(env.DB,
      'SELECT kind,actor FROM approvals WHERE revision_id=? AND manifest_sha256=? AND revoked_at IS NULL', revision.id, revision.manifest_sha256);
    if (new Set(reviews.map((review) => review.kind)).size !== 2 || new Set(reviews.map((review) => review.actor)).size !== 2) {
      block('recipe-review', 'Independent area and security approval of exact recipe inputs is required.', member.pkgbase, null, requestLink);
    }
    for (const review of reviews) {
      try { await reviewAuthority(env, review.actor, review.kind, member.policy.ownerArea); }
      catch { block('recipe-authority', `${review.kind} recipe reviewer no longer has required access.`, member.pkgbase, null, requestLink); }
      gate.fences.push(env.DB.prepare(`INSERT INTO distribution_assertions(expected,actual) SELECT 1,COUNT(*) FROM approvals
        WHERE revision_id=? AND manifest_sha256=? AND kind=? AND actor=? AND revoked_at IS NULL`)
        .bind(revision.id, revision.manifest_sha256, review.kind, review.actor));
      gate.fences.push(authorityFence(env.DB, review.actor, review.kind, member.policy.ownerArea));
    }
    if (phaseIndex < 2) continue;
    const portablePayloads = new Map<string, string>();
    for (const architecture of member.policy.architectures) {
      const build = builds.find((row) => row.architecture === architecture);
      const buildLink = build ? `/maintain/builds/${encodeURIComponent(build.id)}` : requestLink;
      if (!build || build.status !== 'succeeded' || build.smoke_passed !== 1) {
        block('native-build', build?.error ?? `A successful native ${architecture} build is required.`, member.pkgbase, architecture, buildLink);
        continue;
      }
      let ownedInputs = false;
      try {
        const joined = await joinedBuild(env, build.id);
        await assertReviewed(joined, env);
        if (build.output_contract_json) {
          const worker = build.worker_id ? await env.DB.prepare('SELECT * FROM workers WHERE id=?').bind(build.worker_id).first<Worker>() : null;
          const lease = worker ? await getBuildForWorker(env.DB, build.id, worker.id) : null;
          if (!worker || worker.status !== 'active' || !lease || !build.provenance || !build.provenance_signature) throw new PolicyError(409, 'Native worker output evidence is missing.');
          gate.fences.push(env.DB.prepare("INSERT INTO distribution_assertions(expected,actual) SELECT 1,COUNT(*) FROM workers WHERE id=? AND public_key=? AND status='active' AND architecture=?")
            .bind(worker.id, worker.public_key, architecture));
          const contract = storedOutputContract(lease);
          const expected = await cohortOutputContract(env.DB, { ...revision, pkgrel: revision.pkgrel ?? 1 }, architecture);
          if (canonicalJson(contract) !== canonicalJson(expected)) throw new PolicyError(409, 'Output evidence belongs to a different cohort revision.');
          if (build.input_lock_sha256) {
            const selected = await selectedInputLock(env, revision.id, architecture, expected!);
            if (selected?.sha256 !== build.input_lock_sha256) throw new PolicyError(409, 'Native build no longer uses the selected reviewed input lock.');
            gate.fences.push(env.DB.prepare(`INSERT INTO distribution_assertions(expected,actual) SELECT 1,COUNT(*)
              FROM build_input_selections s JOIN current_input_locks l ON l.sha256=s.lock_sha256
              WHERE s.recipe_revision_id=? AND s.architecture=? AND s.cohort_id=? AND s.cohort_revision=? AND s.lock_sha256=?`)
              .bind(revision.id, architecture, current.id, current.current_revision, selected.sha256));
          }
          const artifacts = await buildArtifacts(env.DB, lease);
          await verifyOutputProvenance(worker, lease, artifacts, build.provenance, build.provenance_signature, build.installed_size ?? undefined);
          await assertRetainedAbiEvidence(env.DB, lease, JSON.parse(build.provenance));
          if (verifyArtifacts) for (const artifact of artifacts) await verifyR2Object(env, artifact.key, artifact.sha256, artifact.size);
          const report = JSON.parse(build.provenance) as { frozenInputs?: FrozenEvidence; outputs: { packageMetadata: { name: string; architecture: string } }[];
            runtimeTests: { analyses: { name: string; runtimeAnalysis: { payloadSha256: string } }[] }[] };
          ownedInputs = Boolean(build.input_lock_sha256 && report.frozenInputs?.manifest.purpose === 'owned');
          const portable = new Set(report.outputs.filter((output) => output.packageMetadata.architecture === 'any').map((output) => output.packageMetadata.name));
          for (const analysis of report.runtimeTests.flatMap((test) => test.analyses).filter((item) => portable.has(item.name))) {
            const previous = portablePayloads.get(analysis.name);
            if (previous && previous !== analysis.runtimeAnalysis.payloadSha256) throw new PolicyError(409, `Portable output ${analysis.name} differs between native targets.`);
            portablePayloads.set(analysis.name, analysis.runtimeAnalysis.payloadSha256);
          }
        } else if (revision.surface === 'binary') {
          throw new PolicyError(409, 'Native binary evidence must bind every output to this exact cohort revision. Rebuild using a v2 worker.');
        } else await assertAttestation(joined, env);
      } catch (cause) { block('native-evidence', message(cause), member.pkgbase, architecture, buildLink); }
      if (phaseIndex >= 3 && !ownedInputs) block('check-owned-inputs', 'Build and runtime environments must use the selected reviewed owned input lock. Bootstrap builds do not qualify.', member.pkgbase, architecture, buildLink);
      gate.fences.push(env.DB.prepare(`INSERT INTO distribution_assertions(expected,actual) SELECT 1,COUNT(*) FROM builds
        WHERE id=? AND status='succeeded' AND smoke_passed=1 AND artifact_sha256 IS ? AND provenance_signature IS ? AND input_lock_sha256 IS ?`)
        .bind(build.id, build.artifact_sha256, build.provenance_signature, build.input_lock_sha256 ?? null));
      gate.fences.push(env.DB.prepare("INSERT INTO distribution_assertions(expected,actual) SELECT 1,COUNT(*) FROM workers WHERE id=? AND status='active' AND architecture=?")
        .bind(build.worker_id, architecture));
    }
  }
  if (phaseIndex >= 3) {
    const kinds = phaseIndex === 3 ? ['dependency-closure', 'abi', 'reproducibility']
      : ['dependency-closure', 'abi', 'reproducibility', 'install', 'upgrade', 'recovery', ...(manifest.lane === 'system' ? ['boot'] : [])];
    const targets = manifest.schemaVersion === 2 ? manifest.architectures : requiredArchitectures.filter((target) => manifest.members.some((member) => member.policy.architectures.includes(target)));
    for (const architecture of targets) {
      for (const kind of kinds) block(`check-${kind}`, `Verified ${kind} evidence bound to this candidate is required.`, null, architecture);
    }
    if (manifest.lane === 'opr' && !manifest.compatibleSystems.length) block('supported-systems', 'Choose exact supported system snapshots for the independent OPR cohort.');
  }
  if (current.condition === 'held' || current.condition === 'recovering') block('held', 'A maintainer must resolve the hold before progression.');
  if (phaseIndex >= 5) {
    gate.next = null;
    block('release-activation', current.phase === 'approve' ? 'Publication uses the separate reviewed release candidate action.' : 'Publication and observation follow confirmed release activation.');
  }
  return gate;
}

function authorityFence(db: D1Database, actorId: string, kind: string, area: string) {
  return db.prepare(`INSERT INTO distribution_assertions(expected,actual) SELECT 1,CASE WHEN EXISTS(
    SELECT 1 FROM team_memberships WHERE github_id=? AND (team IN ('security','admin') OR (?='area' AND team=?))) THEN 1 ELSE 0 END`)
    .bind(actorId.slice(7), kind, area);
}
