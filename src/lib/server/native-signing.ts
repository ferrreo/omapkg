import type { Actor, Revision, Worker } from '../model';
import type { Env } from './env';
import { cohortRecipeMember } from './cohort-members';
import { canonicalJson } from '../canonical-json';
import { humanMaintainer } from './catalog-ownership';
import { actorForGithubId } from './auth';
import { query, sha256, audit } from './db';
import { PolicyError, requireSecurity } from './policy';
import { buildArtifacts, cohortOutputContract, storedOutputContract } from './build-outputs';
import { verifyOutputProvenance } from './build-output-evidence';
import { getBuildForWorker } from './worker-protocol';
import { assertReviewed, joinedBuild, signingRequest } from './release-evidence';
import { attestationKey, releaseAttestation } from './release-attestation';
import { selectedInputLock } from './input-locks';
import { assertRetainedAbiEvidence } from './build-abi-evidence';

export async function currentNativeBuild(env: Pick<Env, 'DB' | 'ARTIFACTS'>, buildId: string) {
  const joined = await joinedBuild(env as Env, buildId);
  const worker = joined.worker_id ? await env.DB.prepare('SELECT * FROM workers WHERE id=?').bind(joined.worker_id).first<Worker>() : null;
  const build = worker ? await getBuildForWorker(env.DB, buildId, worker.id) : null;
  if (!worker || worker.status !== 'active' || !build || build.status !== 'succeeded' || build.smoke_passed !== 1 || !build.provenance || !build.provenance_signature) {
    throw new PolicyError(409, 'A successful current native build and active worker are required.');
  }
  await assertReviewed(joined, env as Env);
  const revision = (await env.DB.prepare('SELECT * FROM revisions WHERE id=?').bind(build.revision_id).first<Revision>())!;
  const contract = storedOutputContract(build);
  if (!contract || canonicalJson(contract) !== canonicalJson(await cohortOutputContract(env.DB, { ...revision, pkgrel: revision.pkgrel ?? 1 }, build.architecture))) throw new PolicyError(409, 'Native output contract is no longer current.');
  const scope = await env.DB.prepare(`SELECT r.manifest_json,r.manifest_sha256,c.condition FROM cohort_revisions r JOIN cohorts c ON c.id=r.cohort_id
    WHERE r.cohort_id=? AND r.revision=c.current_revision`).bind(contract.cohort.id).first<{ manifest_json: string; manifest_sha256: string; condition: string }>();
  if (!scope || scope.manifest_sha256 !== contract.cohort.manifestSha256 || scope.condition === 'held') throw new PolicyError(409, 'Cohort is unavailable for signing.');
  const member = await cohortRecipeMember(env.DB, { ...scope, id: contract.cohort.id, current_revision: contract.cohort.revision }, revision.id);
  if (!member) throw new PolicyError(409, 'Build left the current cohort scope.');
  const catalog = await env.DB.prepare('SELECT current_revision,admitted_revision FROM catalog_packages WHERE pkgbase=?').bind(member.pkgbase)
    .first<{ current_revision: number; admitted_revision: number | null }>();
  if (catalog?.current_revision !== member.catalogRevision || catalog.admitted_revision !== member.catalogRevision) throw new PolicyError(409, 'Current catalog admission is required for native signing.');
  for (const reviews of [
    await query<{ kind: string; actor: string }>(env.DB, 'SELECT kind,actor FROM catalog_reviews WHERE pkgbase=? AND revision=? AND manifest_sha256=?', member.pkgbase, member.catalogRevision, member.catalogSha256),
    await query<{ kind: string; actor: string }>(env.DB, 'SELECT kind,actor FROM approvals WHERE revision_id=? AND manifest_sha256=? AND revoked_at IS NULL', revision.id, revision.manifest_sha256),
  ]) {
    if (new Set(reviews.map((review) => review.kind)).size !== 2 || new Set(reviews.map((review) => review.actor)).size !== 2) throw new PolicyError(409, 'Independent current native reviews are required.');
    for (const review of reviews) {
      const actor = await actorForGithubId(env.DB, review.actor.startsWith('github:') ? review.actor.slice(7) : '');
      humanMaintainer(actor, member.policy.ownerArea);
      if (review.kind === 'security') requireSecurity(actor);
    }
  }
  if (build.input_lock_sha256) {
    const selected = await selectedInputLock(env, revision.id, build.architecture, contract);
    if (selected?.sha256 !== build.input_lock_sha256) throw new PolicyError(409, 'Native input lock is no longer selected.');
  }
  const attempt = await env.DB.prepare(`SELECT a.worker_public_key,a.output_contract_json,a.dependency_plan_json,a.input_lock_sha256,a.preserved_inputs_json,r.provenance,r.provenance_signature,r.installed_size,r.status
    FROM build_attempts a JOIN build_attempt_results r USING(build_id,attempt) WHERE a.build_id=? AND a.attempt=?`).bind(build.id, build.attempt)
    .first<{ worker_public_key: string; output_contract_json: string; dependency_plan_json: string | null; input_lock_sha256: string | null; preserved_inputs_json: string | null; provenance: string; provenance_signature: string; installed_size: number; status: string }>();
  if (!attempt || attempt.status !== 'succeeded' || attempt.worker_public_key !== worker.public_key || attempt.output_contract_json !== build.output_contract_json ||
      attempt.dependency_plan_json !== build.dependency_plan_json || attempt.input_lock_sha256 !== (build.input_lock_sha256 ?? null) || attempt.provenance !== build.provenance || attempt.provenance_signature !== build.provenance_signature ||
      attempt.preserved_inputs_json !== (build.preserved_inputs_json ?? null) || attempt.installed_size !== build.installed_size) throw new PolicyError(409, 'Native signing must match immutable attempt evidence.');
  const artifacts = await buildArtifacts(env.DB, build);
  await verifyOutputProvenance(worker, build, artifacts, build.provenance, build.provenance_signature, build.installed_size ?? undefined);
  await assertRetainedAbiEvidence(env.DB, build, JSON.parse(build.provenance));
  return { build, revision, worker, artifacts, contract, area: member.policy.ownerArea };
}

export async function nativeBuildStatement(context: Awaited<ReturnType<typeof currentNativeBuild>>) {
  const { build, revision, worker } = context;
  return releaseAttestation({ buildId: build.id, revisionId: revision.id, surface: 'binary', artifactFilename: null, artifactSha256: null,
    recipe: revision.recipe, recipeSha256: revision.recipe_sha256, manifestSha256: revision.manifest_sha256, sbom: revision.sbom_json,
    provenance: build.provenance!, provenanceSignature: build.provenance_signature!, workerPublicKey: worker.public_key });
}

export async function signNativeOutput(env: Env, actor: Actor | null, buildId: string, attempt: number, filename: string) {
  humanMaintainer(actor);
  const context = await currentNativeBuild(env, buildId);
  humanMaintainer(actor, context.area);
  const { build, revision } = context;
  if (attempt !== build.attempt) throw new PolicyError(409, 'Build attempt changed. Reload before signing.');
  let artifact = context.artifacts.find((item) => item.filename === filename);
  const statement = filename === 'attestation.json';
  if (statement) {
    const text = await nativeBuildStatement(context);
    artifact = { key: attestationKey(build.id, build.attempt), filename, size: new TextEncoder().encode(text).byteLength, sha256: await sha256(text) };
    const existing = await env.ARTIFACTS.get(artifact.key);
    if (existing && await sha256(new Uint8Array(await existing.arrayBuffer())) !== artifact.sha256) throw new PolicyError(409, 'Immutable native statement already exists with different bytes.');
    if (!existing) await env.ARTIFACTS.put(artifact.key, text, { httpMetadata: { contentType: 'application/json' }, customMetadata: { sha256: artifact.sha256 } });
  }
  if (!artifact) throw new PolicyError(400, 'Choose a registered package output or the native build statement.');
  const result = await signingRequest(env, { buildId, buildAttempt: attempt, revisionId: revision.id, manifestSha256: revision.manifest_sha256,
    objectKey: artifact.key, objectKind: statement ? 'attestation' : 'package', artifactSha256: artifact.sha256, artifactSize: artifact.size, artifactFilename: filename });
  await audit(env.DB, actor!.id, 'native-output.signed', buildId, { attempt, filename, artifactSha256: artifact.sha256, ...result }).run();
  return result;
}
