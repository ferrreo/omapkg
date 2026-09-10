import { FactoryRunError, createFactorySuccessorRun, reserveFactoryAttempt, startFactoryRun, type FactoryAttempt } from './factory-runs';
import { canonicalJson } from '../canonical-json';
import { audit, sha256 } from './db';
import { verifyR2Object } from './release-storage';
import type { Env } from './env';
import {
  dispatchPrivateFactoryImage,
  factoryImageInputSha256,
  type FactoryImageArtifact,
  type FactoryImageCandidate,
  type FactoryImageEnvironment,
} from './factory-image-run';

export interface PrivateFactoryImageResult {
  status: 'pending' | 'succeeded' | 'failed' | 'ambiguous';
  dispatchId: string;
  artifact?: FactoryImageArtifact;
  evidence?: unknown;
  evidenceSha256?: string;
  failure?: { message: string };
}

export interface StartPrivateFactoryImageInput {
  runId?: string;
  sourceRunId?: string;
  interventionReason?: string;
  targetId: string;
  unitKey: string;
  policy: unknown;
  createdBy: string;
  candidate: FactoryImageCandidate;
}

export type FactoryImageCoordinatorEnvironment = FactoryImageEnvironment & {
  PACKAGE_SIGNING_FINGERPRINT?: string;
  SIGNING_FINGERPRINT?: string;
  PACKAGE_SIGNING_PUBLIC_KEY_R2_KEY?: string;
  FACTORY_IMAGE_BUILDER_SHA256?: string;
};

async function assertCurrentNativePlan(env: FactoryImageCoordinatorEnvironment, candidate: FactoryImageCandidate): Promise<FactoryImageCandidate> {
  const fingerprint = (env.PACKAGE_SIGNING_FINGERPRINT ?? env.SIGNING_FINGERPRINT ?? '').toLowerCase();
  const publicKeyKey = env.PACKAGE_SIGNING_PUBLIC_KEY_R2_KEY ?? 'keys/opr-package-signing.asc';
  const builderSha256 = (env.FACTORY_IMAGE_BUILDER_SHA256 ?? '').toLowerCase();
  if (!/^[a-f0-9]{40}$/.test(fingerprint) || !/^[a-f0-9]{64}$/.test(builderSha256) || candidate.trustedAuthorityFingerprint.toLowerCase() !== fingerprint || candidate.trustedAuthorityKey.key !== publicKeyKey || candidate.builder.sha256 !== builderSha256) {
    throw new FactoryRunError('policy-stop', 'Private image authority must match the configured coordinator signing key.');
  }
  const plan = await env.DB.prepare(`SELECT p.plan_json,p.plan_sha256,p.cohort_id,p.revision,p.operation,p.architecture,p.candidate_sha256,p.input_sha256,p.profile_id,p.profile_sha256,
      c.current_revision FROM native_qualification_plans p JOIN cohorts c ON c.id=p.cohort_id WHERE p.id=?`)
    .bind(candidate.nativePlanId).first<{ plan_json: string; plan_sha256: string; cohort_id: string; revision: number; operation: string; architecture: string; candidate_sha256: string; input_sha256: string; profile_id: string; profile_sha256: string; current_revision: number }>();
  const requiredOperation = candidate.kind === 'system' ? 'boot' : 'install';
  if (!plan || plan.operation !== requiredOperation || plan.architecture !== candidate.architecture || plan.current_revision !== plan.revision || plan.profile_id !== candidate.profileId || plan.profile_sha256 !== candidate.profile.sha256) {
    throw new FactoryRunError('policy-stop', 'Private image candidate must bind the current reviewed native boot plan.');
  }
  await verifyR2Object(env as Env, candidate.nativePlan.key, candidate.nativePlan.sha256, candidate.nativePlan.size);
  const nativePlanObject = await env.ARTIFACTS.get(candidate.nativePlan.key);
  if (!nativePlanObject) throw new FactoryRunError('policy-stop', 'Private image native plan bytes are unavailable.');
  let issuedPlan: Record<string, unknown>;
  try { issuedPlan = JSON.parse(await new Response(nativePlanObject.body).text()) as Record<string, unknown>; } catch { throw new FactoryRunError('policy-stop', 'Private image native plan bytes are invalid.'); }
  if (issuedPlan.kind !== 'factory-image-native-plan' || issuedPlan.status !== 'reviewed' || issuedPlan.operation !== requiredOperation || issuedPlan.nativePlanId !== candidate.nativePlanId || issuedPlan.qualificationPlanSha256 !== plan.plan_sha256 || issuedPlan.candidateId !== candidate.id || issuedPlan.architecture !== candidate.architecture || issuedPlan.profileSha256 !== candidate.profile.sha256 || issuedPlan.inputLockSha256 !== plan.input_sha256) {
    throw new FactoryRunError('policy-stop', 'Private image native plan issuer proof is stale or mismatched.');
  }
  const reviews = await env.DB.prepare('SELECT kind,actor FROM native_qualification_plan_reviews WHERE plan_id=?').bind(candidate.nativePlanId).all<{ kind: string; actor: string }>();
  if (new Set(reviews.results.map((review) => review.kind)).size !== 2 || new Set(reviews.results.map((review) => review.actor)).size !== 2) throw new FactoryRunError('policy-stop', 'Native boot plan requires independent area and security review.');
  for (const review of reviews.results) {
    const githubId = review.actor.startsWith('github:') ? review.actor.slice(7) : '';
    const authority = review.kind === 'security' ? "team IN ('security','admin')" : "team IN ('desktop','development','gaming','multimedia','productivity','system','admin')";
    if (!githubId || !await env.DB.prepare(`SELECT 1 FROM team_memberships WHERE github_id=? AND ${authority} LIMIT 1`).bind(githubId).first()) throw new FactoryRunError('policy-stop', 'Native boot plan review authority is no longer current.');
  }
  return { ...candidate, trustedAuthorityFingerprint: fingerprint };
}

export const authorizeFactoryImageCandidate = assertCurrentNativePlan;

export async function startPrivateFactoryImageRun(env: FactoryImageCoordinatorEnvironment, input: StartPrivateFactoryImageInput): Promise<{ runId: string; attempt: FactoryAttempt; dispatchId: string; inputSha256: string }> {
  const candidate = await assertCurrentNativePlan(env, input.candidate);
  let run;
  if (input.sourceRunId) {
    const reason = input.interventionReason?.replace(/[\u0000\r\n]+/g, ' ').trim() ?? '';
    if (!reason || reason.length > 2_000) throw new FactoryRunError('invalid-input', 'Human image intervention reason is required, up to 2,000 characters.');
    run = await createFactorySuccessorRun(env.DB, input.sourceRunId, { id: input.runId, targetKind: 'image', targetId: input.targetId, unitKey: input.unitKey, policy: input.policy, createdBy: input.createdBy });
    await audit(env.DB, input.createdBy, 'factory.image_human_successor_started', run.id, { sourceRunId: input.sourceRunId, reason }).run();
  } else {
    run = await startFactoryRun(env.DB, { id: input.runId, targetKind: 'image', targetId: input.targetId, unitKey: input.unitKey, policy: input.policy, createdBy: input.createdBy });
  }
  const inputSha256 = await factoryImageInputSha256(candidate);
  const candidateSha256 = await sha256(canonicalJson(candidate));
  const attempt = await reserveFactoryAttempt(env.DB, { runId: run.id, reservationKey: `image:attempt:${run.attemptCount + 1}`, candidateSha256, inputSha256, candidate, policy: input.policy, architecture: candidate.architecture });
  const queued = await queuePrivateFactoryImage(env, run.id, attempt, candidate);
  return { runId: run.id, attempt, dispatchId: queued.dispatchId, inputSha256 };
}

export async function queuePrivateFactoryImage(env: FactoryImageEnvironment, runId: string, attempt: FactoryAttempt, candidate: FactoryImageCandidate): Promise<{ dispatchId: string; inputSha256: string }> {
  return dispatchPrivateFactoryImage(env, runId, attempt, candidate);
}

export async function privateFactoryImageResult(env: Pick<FactoryImageEnvironment, 'DB'>, runId: string, attempt: number, dispatchId: string): Promise<PrivateFactoryImageResult> {
  const row = await env.DB.prepare(`SELECT id,status,artifact_key,artifact_sha256,artifact_size,artifact_filename,evidence_json,evidence_sha256,error
    FROM factory_image_jobs WHERE id=? AND run_id=? AND attempt=?`).bind(dispatchId, runId, attempt).first<{
    id: string; status: 'queued' | 'leased' | 'succeeded' | 'failed' | 'cancelled'; artifact_key: string | null; artifact_sha256: string | null;
    artifact_size: number | null; artifact_filename: string | null; evidence_json: string | null; evidence_sha256: string | null; error: string | null;
  }>();
  if (!row) throw new FactoryRunError('not-found', 'Private image dispatch was not found.');
  if (row.status === 'succeeded') {
    if (!row.artifact_key || !row.artifact_sha256 || row.artifact_size === null || !row.artifact_filename) throw new FactoryRunError('storage', 'Private image success has no complete artifact.');
    return { status: 'succeeded', dispatchId, artifact: { key: row.artifact_key, sha256: row.artifact_sha256, size: row.artifact_size, filename: row.artifact_filename }, evidence: row.evidence_json ? JSON.parse(row.evidence_json) : undefined, evidenceSha256: row.evidence_sha256 ?? undefined };
  }
  if (row.status === 'failed' || row.status === 'cancelled') return { status: 'failed', dispatchId, failure: { message: row.error ?? `Private image job ${row.status}.` } };
  return { status: 'pending', dispatchId };
}

export async function waitForPrivateFactoryImage(env: Pick<FactoryImageEnvironment, 'DB'>, runId: string, attempt: number, dispatchId: string, options: { timeoutMs?: number; pollMs?: number } = {}): Promise<PrivateFactoryImageResult> {
  const timeoutMs = options.timeoutMs ?? 25 * 60_000;
  const pollMs = options.pollMs ?? 5_000;
  const deadline = Date.now() + timeoutMs;
  while (Date.now() <= deadline) {
    const result = await privateFactoryImageResult(env, runId, attempt, dispatchId);
    if (result.status !== 'pending') return result;
    await new Promise((resolve) => setTimeout(resolve, pollMs));
  }
  return { status: 'ambiguous', dispatchId, failure: { message: 'Private image execution timed out; status is ambiguous and requires human intervention.' } };
}
