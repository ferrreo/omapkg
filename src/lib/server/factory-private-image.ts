import { FactoryRunError, createFactorySuccessorRun, reserveFactoryAttempt, startFactoryRun, type FactoryAttempt } from './factory-runs';
import { canonicalJson } from '../canonical-json';
import { audit, sha256 } from './db';
import { verifyR2Object } from './release-storage';
import type { Env } from './env';
import {
  dispatchPrivateFactoryImage,
  factoryImageInputSha256,
  validateFactoryImageCandidate,
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

export type PrivateFactoryImageStatus = 'pending' | 'succeeded' | 'failed';

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

export interface StartPrivateFactoryImageWorkflowInput extends StartPrivateFactoryImageInput {
  alternatives?: FactoryImageCandidate[];
}

export type FactoryImageCoordinatorEnvironment = FactoryImageEnvironment & {
  PACKAGE_SIGNING_FINGERPRINT?: string;
  SIGNING_FINGERPRINT?: string;
  PACKAGE_SIGNING_PUBLIC_KEY_R2_KEY?: string;
  FACTORY_IMAGE_BUILDER_SHA256?: string;
};

async function assertConstructionPolicy(env: FactoryImageCoordinatorEnvironment, candidate: FactoryImageCandidate, policy: unknown): Promise<FactoryImageCandidate> {
  const fingerprint = (env.PACKAGE_SIGNING_FINGERPRINT ?? env.SIGNING_FINGERPRINT ?? '').toLowerCase();
  const publicKeyKey = env.PACKAGE_SIGNING_PUBLIC_KEY_R2_KEY ?? 'keys/opr-package-signing.asc';
  const builderSha256 = (env.FACTORY_IMAGE_BUILDER_SHA256 ?? '').toLowerCase();
  if (!/^[a-f0-9]{40}$/.test(fingerprint) || !/^[a-f0-9]{64}$/.test(builderSha256) || candidate.trustedAuthorityFingerprint.toLowerCase() !== fingerprint || candidate.trustedAuthorityKey.key !== publicKeyKey || candidate.builder.sha256 !== builderSha256) {
    throw new FactoryRunError('policy-stop', 'Private image authority must match the configured coordinator signing key.');
  }
  const policySha256 = await sha256(canonicalJson(policy));
  if (candidate.constructionPolicySha256 !== policySha256) throw new FactoryRunError('policy-stop', 'Private image candidate does not bind the authenticated construction policy.');
  await verifyR2Object(env as Env, candidate.nativePlan.key, candidate.nativePlan.sha256, candidate.nativePlan.size);
  const nativePlanObject = await env.ARTIFACTS.get(candidate.nativePlan.key);
  if (!nativePlanObject) throw new FactoryRunError('policy-stop', 'Private image native plan bytes are unavailable.');
  let issuedPlan: Record<string, unknown>;
  try { issuedPlan = JSON.parse(await new Response(nativePlanObject.body).text()) as Record<string, unknown>; } catch { throw new FactoryRunError('policy-stop', 'Private image native plan bytes are invalid.'); }
  if (issuedPlan.kind !== 'factory-image-construction-proof' || issuedPlan.status !== 'reviewed' || issuedPlan.runPolicySha256 !== policySha256 || issuedPlan.candidateId !== candidate.id || issuedPlan.architecture !== candidate.architecture || issuedPlan.profileSha256 !== candidate.profile.sha256 || typeof issuedPlan.inputLockSha256 !== 'string') throw new FactoryRunError('policy-stop', 'Private image construction proof is stale or mismatched.');
  return { ...candidate, trustedAuthorityFingerprint: fingerprint };
}

export const authorizeFactoryImageCandidate = assertConstructionPolicy;

const MAX_DOCKERFILE_BYTES = 4 * 1024 * 1024;

async function verifiedImageObject(env: FactoryImageCoordinatorEnvironment, ref: { key: string; sha256: string; size: number }): Promise<Uint8Array> {
  await verifyR2Object(env as Env, ref.key, ref.sha256, ref.size);
  const object = await env.ARTIFACTS.get(ref.key);
  if (!object?.body) throw new FactoryRunError('policy-stop', 'Private image input bytes are unavailable.');
  const bytes = new Uint8Array(await new Response(object.body).arrayBuffer());
  if (bytes.byteLength !== ref.size || await sha256(bytes) !== ref.sha256) throw new FactoryRunError('policy-stop', 'Private image input bytes changed during verification.');
  return bytes;
}

export async function readVerifiedFactoryImageDockerfile(env: FactoryImageCoordinatorEnvironment, candidate: FactoryImageCandidate): Promise<string> {
  if (candidate.kind !== 'oci' || !candidate.dockerfile) throw new FactoryRunError('policy-stop', 'Only OCI image definitions have mutable Dockerfile repair inputs.');
  if (candidate.dockerfile.size > MAX_DOCKERFILE_BYTES) throw new FactoryRunError('policy-stop', 'Reviewed Dockerfile exceeds the repair limit.');
  const bytes = await verifiedImageObject(env, candidate.dockerfile);
  if (bytes.byteLength === 0 || bytes.byteLength > MAX_DOCKERFILE_BYTES || bytes.includes(0)) throw new FactoryRunError('policy-stop', 'Reviewed Dockerfile bytes are invalid.');
  let text: string;
  try { text = new TextDecoder('utf-8', { fatal: true }).decode(bytes); } catch { throw new FactoryRunError('policy-stop', 'Reviewed Dockerfile is not valid UTF-8.'); }
  return text;
}

async function retainFactoryImageObject(env: FactoryImageCoordinatorEnvironment, key: string, bytes: Uint8Array, digest: string): Promise<{ key: string; sha256: string; size: number; filename: string }> {
  const existing = await env.ARTIFACTS.head(key);
  if (existing) await verifyR2Object(env as Env, key, digest, bytes.byteLength);
  else {
    const result = await env.ARTIFACTS.put(key, bytes, { onlyIf: { etagDoesNotMatch: '*' }, customMetadata: { sha256: digest }, httpMetadata: { contentType: 'application/octet-stream', cacheControl: 'public, max-age=31536000, immutable' } });
    if (!result) await verifyR2Object(env as Env, key, digest, bytes.byteLength);
  }
  await verifyR2Object(env as Env, key, digest, bytes.byteLength);
  return { key, sha256: digest, size: bytes.byteLength, filename: key.slice(key.lastIndexOf('/') + 1) };
}

function parsedObject(bytes: Uint8Array, label: string): Record<string, unknown> {
  try {
    const value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)) as unknown;
    if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('not an object');
    return value as Record<string, unknown>;
  } catch { throw new FactoryRunError('policy-stop', `${label} bytes are invalid.`); }
}

export async function retainFactoryImageDockerfileRepair(env: FactoryImageCoordinatorEnvironment, input: { runId: string; attempt: number; candidate: FactoryImageCandidate; policy: unknown; dockerfile: string }): Promise<FactoryImageCandidate> {
  if (input.candidate.kind !== 'oci' || !input.candidate.dockerfile) throw new FactoryRunError('policy-stop', 'System image definitions require an authorized mutable candidate before repair.');
  const dockerfileBytes = new TextEncoder().encode(input.dockerfile);
  if (!dockerfileBytes.byteLength || dockerfileBytes.byteLength > MAX_DOCKERFILE_BYTES || dockerfileBytes.includes(0)) throw new FactoryRunError('policy-stop', 'Repaired Dockerfile bytes are invalid.');
  const dockerfileSha256 = await sha256(dockerfileBytes);
  if (dockerfileSha256 === input.candidate.dockerfile.sha256) throw new FactoryRunError('policy-stop', 'OCI Dockerfile repair did not change the reviewed bytes.');
  const policySha256 = await sha256(canonicalJson(input.policy));
  if (input.candidate.constructionPolicySha256 !== policySha256) throw new FactoryRunError('policy-stop', 'Image repair policy differs from the retained construction policy.');
  const lockBytes = await verifiedImageObject(env, input.candidate.candidateLock);
  const proofBytes = await verifiedImageObject(env, input.candidate.nativePlan);
  const lock = parsedObject(lockBytes, 'Candidate lock');
  const lockCandidate = lock.candidate;
  if (!lockCandidate || typeof lockCandidate !== 'object' || Array.isArray(lockCandidate)) throw new FactoryRunError('policy-stop', 'Candidate lock has no mutable candidate binding.');
  const proof = parsedObject(proofBytes, 'Construction proof');
  const candidateId = `${input.candidate.id.slice(0, 100)}-repair-${input.attempt}`;
  const repairPrefix = `private/factory-images/${input.runId}/repairs/attempt-${input.attempt}`;
  const dockerfileRef = await retainFactoryImageObject(env, `${repairPrefix}/Dockerfile`, dockerfileBytes, dockerfileSha256);
  const nextProof = { ...proof, candidateId, runPolicySha256: policySha256, profileSha256: input.candidate.profile.sha256 };
  const nextProofBytes = new TextEncoder().encode(canonicalJson(nextProof));
  const nextProofSha256 = await sha256(nextProofBytes);
  const nextProofRef = await retainFactoryImageObject(env, `${repairPrefix}/construction-proof.json`, nextProofBytes, nextProofSha256);
  const nextLock = { ...lock, candidate: { ...(lockCandidate as Record<string, unknown>), id: candidateId, nativePlanSha256: nextProofSha256 } };
  const nextLockBytes = new TextEncoder().encode(canonicalJson(nextLock));
  const nextLockSha256 = await sha256(nextLockBytes);
  const nextLockRef = await retainFactoryImageObject(env, `${repairPrefix}/candidate-lock.json`, nextLockBytes, nextLockSha256);
  const nextCandidate = validateFactoryImageCandidate({ ...input.candidate, id: candidateId, candidateLock: nextLockRef, nativePlan: nextProofRef, dockerfile: dockerfileRef });
  return authorizeFactoryImageCandidate(env, nextCandidate, input.policy);
}

export async function preparePrivateFactoryImageRun(env: FactoryImageCoordinatorEnvironment, input: StartPrivateFactoryImageInput): Promise<{ run: Awaited<ReturnType<typeof startFactoryRun>>; candidate: FactoryImageCandidate }> {
  const candidate = await assertConstructionPolicy(env, input.candidate, input.policy);
  let run;
  if (input.sourceRunId) {
    const reason = input.interventionReason?.replace(/[\u0000\r\n]+/g, ' ').trim() ?? '';
    if (!reason || reason.length > 2_000) throw new FactoryRunError('invalid-input', 'Human image intervention reason is required, up to 2,000 characters.');
    run = await createFactorySuccessorRun(env.DB, input.sourceRunId, { id: input.runId, targetKind: 'image', targetId: input.targetId, unitKey: input.unitKey, policy: input.policy, createdBy: input.createdBy });
    await audit(env.DB, input.createdBy, 'factory.image_human_successor_started', run.id, { sourceRunId: input.sourceRunId, reason }).run();
  } else {
    run = await startFactoryRun(env.DB, { id: input.runId, targetKind: 'image', targetId: input.targetId, unitKey: input.unitKey, policy: input.policy, createdBy: input.createdBy });
  }
  return { run, candidate };
}

export async function latestPrivateFactoryImageCandidate(db: Pick<FactoryImageEnvironment, 'DB'>['DB'], runId: string): Promise<FactoryImageCandidate> {
  const row = await db.prepare('SELECT candidate_json FROM factory_image_jobs WHERE run_id=? ORDER BY attempt DESC,id DESC LIMIT 1').bind(runId).first<{ candidate_json: string }>();
  if (!row) throw new FactoryRunError('not-found', 'Private image run has no retained candidate.');
  try {
    return validateFactoryImageCandidate(JSON.parse(row.candidate_json) as FactoryImageCandidate);
  } catch (cause) {
    throw new FactoryRunError('storage', cause instanceof Error ? `Retained private image candidate is invalid: ${cause.message}` : 'Retained private image candidate is invalid.');
  }
}

export async function startPrivateFactoryImageWorkflow(env: FactoryImageCoordinatorEnvironment & { PIPELINE?: Fetcher }, input: StartPrivateFactoryImageWorkflowInput): Promise<{ run: Awaited<ReturnType<typeof startFactoryRun>>; candidate: FactoryImageCandidate; workflowId: string }> {
  if (!env.PIPELINE) throw new FactoryRunError('dispatch-failed', 'Factory workflow service is not configured.');
  const prepared = await preparePrivateFactoryImageRun(env, input);
  const workflowId = `factory-image-${prepared.run.id}`;
  const response = await env.PIPELINE.fetch(new Request('https://pipeline.internal/factory-image', {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({
      workflowId, requestId: input.targetId, generationId: workflowId, factoryRunId: prepared.run.id, targetId: input.targetId, unitKey: input.unitKey,
      policy: prepared.run.policy, imageCandidate: prepared.candidate, imageAlternatives: input.alternatives ?? [],
    }),
  }));
  if (!response.ok) throw new FactoryRunError('dispatch-failed', 'Factory image workflow could not be queued.');
  return { ...prepared, workflowId };
}

export async function startPrivateFactoryImageRun(env: FactoryImageCoordinatorEnvironment, input: StartPrivateFactoryImageInput): Promise<{ runId: string; attempt: FactoryAttempt; dispatchId: string; inputSha256: string }> {
  const { run, candidate } = await preparePrivateFactoryImageRun(env, input);
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

export async function privateFactoryImageStatus(env: Pick<FactoryImageEnvironment, 'DB'>, runId: string, attempt: number, dispatchId: string): Promise<PrivateFactoryImageStatus> {
  const row = await env.DB.prepare('SELECT status FROM factory_image_jobs WHERE id=? AND run_id=? AND attempt=?').bind(dispatchId, runId, attempt).first<{ status: 'queued' | 'leased' | 'succeeded' | 'failed' | 'cancelled' }>();
  if (!row) throw new FactoryRunError('not-found', 'Private image dispatch was not found.');
  if (row.status === 'failed' || row.status === 'cancelled') return 'failed';
  if (row.status === 'succeeded') return 'succeeded';
  return 'pending';
}

export async function waitForPrivateFactoryImage(env: Pick<FactoryImageEnvironment, 'DB'>, runId: string, attempt: number, dispatchId: string, options: { timeoutMs?: number; pollMs?: number } = {}): Promise<PrivateFactoryImageResult> {
  const timeoutMs = options.timeoutMs ?? 150 * 60_000;
  const pollMs = options.pollMs ?? 30_000;
  const deadline = Date.now() + timeoutMs;
  while (Date.now() <= deadline) {
    const status = await privateFactoryImageStatus(env, runId, attempt, dispatchId);
    if (status !== 'pending') return privateFactoryImageResult(env, runId, attempt, dispatchId);
    await new Promise((resolve) => setTimeout(resolve, pollMs));
  }
  const status = await privateFactoryImageStatus(env, runId, attempt, dispatchId);
  return status === 'pending' ? { status: 'ambiguous', dispatchId, failure: { message: 'Private image execution timed out; status is ambiguous and requires human intervention.' } } : privateFactoryImageResult(env, runId, attempt, dispatchId);
}
