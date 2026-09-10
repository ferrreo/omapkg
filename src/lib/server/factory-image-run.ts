import type { Architecture, Worker } from '../model';
import type { Env } from './env';
import { canonicalJson } from '../canonical-json';
import { audit, id, now, sha256 } from './db';
import { FactoryRunError, renewFactoryAttempt, type FactoryAttempt } from './factory-runs';
import { safeKey, verifyR2Object } from './release-storage';
import {
  decodeBase64,
  requireObject,
  type AuthenticatedWorker,
  type WorkerMetadata,
  verifyEd25519,
  WorkerProtocolError,
  LEASE_SECONDS,
} from './worker-protocol';
import { hashObject } from './worker-uploads';

const SHA256 = /^[a-f0-9]{64}$/;
const ID = /^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,255}$/;
const FINGERPRINT = /^[a-f0-9]{40}$/i;
const IMAGE_FILENAME = /^[A-Za-z0-9][A-Za-z0-9@._+%~:-]{0,220}$/;
const IMAGE_REPOSITORY = /^(?=.{1,512}$)[a-z0-9][a-z0-9.-]*(?::[0-9]{1,5})?(?:\/[a-z0-9][a-z0-9._-]*)+(?::[a-z0-9][a-z0-9._-]{0,127})?(?:@sha256:[a-f0-9]{64})?$/;
const MAX_INPUT_BYTES = 4 * 1024 * 1024 * 1024;
const MAX_OUTPUT_BYTES = 64 * 1024 * 1024 * 1024;
const MAX_EVIDENCE_BYTES = 2 * 1024 * 1024;
export const FACTORY_IMAGE_UPLOAD_PART_SIZE = 8 * 1024 * 1024;
export const FACTORY_IMAGE_MAX_UPLOAD_SIZE = MAX_OUTPUT_BYTES;
export const FACTORY_IMAGE_MAX_UPLOAD_PARTS = MAX_OUTPUT_BYTES / FACTORY_IMAGE_UPLOAD_PART_SIZE;

export type FactoryImageKind = 'oci' | 'system';
export type FactoryImageInputName =
  | 'profile'
  | 'candidate-lock'
  | 'candidate-lock-signature'
  | 'native-plan'
  | 'native-plan-signature'
  | 'trusted-authority-key'
  | 'builder'
  | 'context'
  | 'dockerfile';

export interface FactoryImageObjectRef {
  key: string;
  sha256: string;
  size: number;
  filename: string;
}

export interface FactoryImageCandidate {
  id: string;
  architecture: Architecture;
  kind: FactoryImageKind;
  profileId: string;
  constructionPolicySha256: string;
  profile: FactoryImageObjectRef;
  candidateLock: FactoryImageObjectRef;
  candidateLockSignature?: FactoryImageObjectRef;
  nativePlan: FactoryImageObjectRef;
  nativePlanSignature?: FactoryImageObjectRef;
  trustedAuthorityKey: FactoryImageObjectRef;
  builder: FactoryImageObjectRef;
  context?: FactoryImageObjectRef;
  dockerfile?: FactoryImageObjectRef;
  imageRef?: string;
  trustedAuthorityFingerprint: string;
  sourceDateEpoch: number;
  outputFilename: string;
}

export interface FactoryImageWorkerJob {
  id: string;
  runId: string;
  attempt: number;
  leaseToken: string;
  leaseExpiresAt: string;
  candidate: FactoryImageCandidate;
  inputSha256: string;
}

export interface FactoryImageArtifact {
  key: string;
  sha256: string;
  size: number;
  filename: string;
}

interface FactoryImageJobRow {
  id: string;
  run_id: string;
  attempt: number;
  candidate_id: string;
  architecture: Architecture;
  kind: FactoryImageKind;
  input_sha256: string;
  candidate_json: string;
  status: 'queued' | 'leased' | 'succeeded' | 'failed' | 'cancelled';
  worker_id: string | null;
  lease_token: string | null;
  lease_expires_at: number | null;
  artifact_key: string | null;
  artifact_sha256: string | null;
  artifact_size: number | null;
  artifact_filename: string | null;
  evidence_json: string | null;
  evidence_sha256: string | null;
  evidence_signature: string | null;
  error: string | null;
  created_at: number;
  started_at: number | null;
  finished_at: number | null;
  factory_lease_token?: string | null;
  factory_lease_expires_at?: number | null;
}

interface FactoryImageUploadRow {
  id: string;
  job_id: string;
  worker_id: string;
  attempt: number;
  lease_token: string;
  filename: string;
  object_key: string;
  r2_upload_id: string;
  expected_size: number;
  expected_sha256: string;
  status: 'active' | 'completed' | 'aborted' | 'failed';
  actual_size: number | null;
  actual_sha256: string | null;
  created_at: number;
  completed_at: number | null;
}

interface FactoryImageUploadPart {
  partNumber: number;
  sha256: string;
  size: number;
  etag: string;
}

export type FactoryImageEnvironment = Pick<Env, 'DB' | 'ARTIFACTS'>;

function changed(result: unknown): boolean {
  return Number((result as { meta?: { changes?: number } } | undefined)?.meta?.changes ?? 0) > 0;
}

function imageFailure(message: string): never {
  throw new FactoryRunError('policy-stop', message);
}

function safeImageKey(value: string, label: string): string {
  try { return safeKey(value, label); } catch (cause) { imageFailure(cause instanceof Error ? cause.message : `Invalid ${label}`); }
}

function requireText(value: unknown, label: string, max: number): string {
  if (typeof value !== 'string' || value.length === 0 || value.length > max || /[\u0000\r\n]/.test(value)) imageFailure(`${label} is invalid.`);
  return value;
}

function validateObject(value: unknown, label: string, maxSize = MAX_INPUT_BYTES): FactoryImageObjectRef {
  const object = requireObject(value);
  if (Object.keys(object).sort().join(',') !== 'filename,key,sha256,size') imageFailure(`${label} identity is invalid.`);
  const filename = requireText(object.filename, `${label} filename`, 256);
  if (!IMAGE_FILENAME.test(filename)) imageFailure(`${label} filename is invalid.`);
  const key = safeImageKey(requireText(object.key, `${label} key`, 1024), `${label} key`);
  const digest = requireText(object.sha256, `${label} digest`, 64);
  if (!SHA256.test(digest)) imageFailure(`${label} digest is invalid.`);
  const size = object.size;
  if (!Number.isSafeInteger(size) || (size as number) <= 0 || (size as number) > maxSize) imageFailure(`${label} size is invalid.`);
  return { key, sha256: digest, size: size as number, filename };
}

export function validateFactoryImageCandidate(value: FactoryImageCandidate): FactoryImageCandidate {
  const allowedKeys = ['architecture','builder','candidateLock','candidateLockSignature','constructionPolicySha256','context','dockerfile','id','imageRef','kind','nativePlan','nativePlanSignature','outputFilename','profile','profileId','sourceDateEpoch','trustedAuthorityFingerprint','trustedAuthorityKey'];
  if (!value || typeof value !== 'object' || Object.keys(value).some((key) => !allowedKeys.includes(key))) imageFailure('Private image candidate contains unsupported fields.');
  if (!value || typeof value !== 'object' || !ID.test(value.id) ||
      !['x86_64', 'aarch64'].includes(value.architecture) || !['oci', 'system'].includes(value.kind) ||
      !ID.test(value.profileId) || !SHA256.test(value.constructionPolicySha256) || !FINGERPRINT.test(value.trustedAuthorityFingerprint) ||
      !Number.isSafeInteger(value.sourceDateEpoch) || value.sourceDateEpoch <= 0 || !IMAGE_FILENAME.test(value.outputFilename) ||
      (value.imageRef !== undefined && !IMAGE_REPOSITORY.test(value.imageRef))) {
    imageFailure('Private image candidate identity or policy is invalid.');
  }
  const names: Array<[string, FactoryImageObjectRef | undefined, number?]> = [
    ['profile', value.profile, 8 * 1024 * 1024], ['candidate lock', value.candidateLock, 8 * 1024 * 1024], ['candidate lock signature', value.candidateLockSignature, 64 * 1024],
    ['native plan', value.nativePlan, 8 * 1024 * 1024], ['native plan signature', value.nativePlanSignature, 64 * 1024], ['trusted authority key', value.trustedAuthorityKey, 4 * 1024 * 1024],
    ['builder', value.builder, 16 * 1024 * 1024], ['context', value.context], ['Dockerfile', value.dockerfile, 4 * 1024 * 1024],
  ];
  for (const [name, ref, maxSize] of names) if (ref !== undefined) validateObject(ref, name, maxSize);
  if (value.kind === 'oci' && (!value.context || !value.dockerfile)) imageFailure('OCI image candidates require a context and Dockerfile input.');
  if (value.kind === 'system' && value.dockerfile) imageFailure('System image candidates cannot carry an OCI Dockerfile input.');
  if (value.kind === 'oci' && !value.imageRef) imageFailure('OCI image candidates require an image repository reference.');
  if (value.kind === 'system' && value.imageRef) imageFailure('System image candidates cannot carry an OCI image reference.');
  return { ...value, trustedAuthorityFingerprint: value.trustedAuthorityFingerprint.toLowerCase() };
}

export async function factoryImageInputSha256(candidate: FactoryImageCandidate): Promise<string> {
  const checked = validateFactoryImageCandidate(candidate);
  return sha256(canonicalJson({
    id: checked.id, architecture: checked.architecture, kind: checked.kind, profileId: checked.profileId, constructionPolicySha256: checked.constructionPolicySha256,
    profile: checked.profile, candidateLock: checked.candidateLock, candidateLockSignature: checked.candidateLockSignature ?? null,
    nativePlan: checked.nativePlan, nativePlanSignature: checked.nativePlanSignature ?? null, trustedAuthorityKey: checked.trustedAuthorityKey,
    builder: checked.builder, context: checked.context ?? null, dockerfile: checked.dockerfile ?? null, imageRef: checked.imageRef ?? null,
    trustedAuthorityFingerprint: checked.trustedAuthorityFingerprint, sourceDateEpoch: checked.sourceDateEpoch, outputFilename: checked.outputFilename,
  }));
}

function candidateFromRow(row: FactoryImageJobRow): FactoryImageCandidate {
  try { return validateFactoryImageCandidate(JSON.parse(row.candidate_json) as FactoryImageCandidate); }
  catch (cause) { throw new FactoryRunError('storage', cause instanceof Error ? cause.message : 'Stored image candidate is invalid.'); }
}

async function imageJob(db: D1Database, jobId: string): Promise<FactoryImageJobRow | null> {
  if (!ID.test(jobId)) throw new FactoryRunError('invalid-input', 'Invalid private image job id.');
  return db.prepare(`SELECT j.*,a.lease_token AS factory_lease_token,a.lease_expires_at AS factory_lease_expires_at
    FROM factory_image_jobs j JOIN factory_runs r ON r.id=j.run_id
    JOIN factory_run_attempts a ON a.run_id=j.run_id AND a.attempt=j.attempt WHERE j.id=?`).bind(jobId).first<FactoryImageJobRow>();
}

async function verifyCandidateObjects(env: FactoryImageEnvironment, candidate: FactoryImageCandidate): Promise<void> {
  const refs = [candidate.profile, candidate.candidateLock, ...(candidate.candidateLockSignature ? [candidate.candidateLockSignature] : []), candidate.nativePlan,
    ...(candidate.nativePlanSignature ? [candidate.nativePlanSignature] : []), candidate.trustedAuthorityKey, candidate.builder, ...(candidate.context ? [candidate.context] : []),
    ...(candidate.dockerfile ? [candidate.dockerfile] : [])];
  await Promise.all(refs.map((ref) => verifyR2Object(env as Env, ref.key, ref.sha256, ref.size)));
}

/** Queue reviewed immutable image inputs for one already-reserved factory attempt. */
export async function dispatchPrivateFactoryImage(env: FactoryImageEnvironment, runId: string, attempt: FactoryAttempt, candidate: FactoryImageCandidate): Promise<{ dispatchId: string; inputSha256: string }> {
  if (attempt.status !== 'running' || attempt.runId !== runId) throw new FactoryRunError('attempt-complete', 'Factory image attempt is not executable.');
  const checked = validateFactoryImageCandidate(candidate); const inputSha256 = await factoryImageInputSha256(checked);
  if (attempt.inputSha256 !== inputSha256) throw new FactoryRunError('policy-stop', 'Private image candidate inputs differ from the reserved run.');
  await verifyCandidateObjects(env, checked);
  const dispatchId = attempt.dispatchId ?? `factory-image-${(await sha256(`${runId}:${attempt.attempt}`)).slice(0, 48)}`; const timestamp = now();
  const reserved = await env.DB.prepare(`UPDATE factory_run_attempts SET dispatch_id=?,updated_at=? WHERE run_id=? AND attempt=? AND status='running' AND lease_token=? AND lease_expires_at>? AND dispatch_id IS NULL`)
    .bind(dispatchId, timestamp, runId, attempt.attempt, attempt.leaseToken, timestamp).run();
  if (!changed(reserved)) {
    const current = await env.DB.prepare('SELECT dispatch_id FROM factory_run_attempts WHERE run_id=? AND attempt=? AND lease_token=?').bind(runId, attempt.attempt, attempt.leaseToken).first<{ dispatch_id: string | null }>();
    if (current?.dispatch_id !== dispatchId) throw new FactoryRunError('lease-fenced', 'Private image dispatch lease is fenced.');
  }
  try {
    await env.DB.batch([
      env.DB.prepare(`INSERT INTO factory_image_jobs(id,run_id,attempt,candidate_id,architecture,kind,input_sha256,candidate_json,created_at) VALUES(?,?,?,?,?,?,?,?,?)`)
        .bind(dispatchId, runId, attempt.attempt, checked.id, checked.architecture, checked.kind, inputSha256, canonicalJson(checked), timestamp),
      audit(env.DB, 'factory', 'factory.private_image_queued', runId, { attempt: attempt.attempt, candidateId: checked.id, dispatchId, inputSha256 }),
    ]);
  } catch (cause) {
    if (!/unique|constraint/i.test(cause instanceof Error ? cause.message : '')) throw cause;
    const existing = await imageJob(env.DB, dispatchId);
    if (!existing || existing.run_id !== runId || existing.attempt !== attempt.attempt || existing.input_sha256 !== inputSha256) throw new FactoryRunError('reservation-conflict', 'Private image dispatch already belongs to different inputs.');
  }
  return { dispatchId, inputSha256 };
}

export async function claimPrivateFactoryImage(db: D1Database, worker: Worker, metadata: WorkerMetadata | null = null): Promise<FactoryImageWorkerJob | null> {
  const timestamp = now();
  const capabilities = metadata?.capabilities ?? (() => { try { return JSON.parse(worker.capabilities_json ?? '[]') as string[]; } catch { return []; } })();
  if (!capabilities.includes('factory-image-v1')) return null;
  const candidate = await db.prepare(`SELECT j.*,a.lease_token AS factory_lease_token,a.lease_expires_at AS factory_lease_expires_at
    FROM factory_image_jobs j JOIN factory_runs r ON r.id=j.run_id JOIN factory_run_attempts a ON a.run_id=j.run_id AND a.attempt=j.attempt
    WHERE j.status='queued' AND j.architecture=? AND r.status='running' AND r.current_attempt=j.attempt AND a.status='running' AND a.lease_expires_at>? AND r.lease_expires_at>?
    ORDER BY j.created_at,j.id LIMIT 1`).bind(worker.architecture, timestamp, timestamp).first<FactoryImageJobRow>();
  if (!candidate) return null;
  const leaseToken = id(); const expires = timestamp + LEASE_SECONDS;
  const result = await db.prepare(`UPDATE factory_image_jobs SET status='leased',worker_id=?,lease_token=?,lease_expires_at=?,started_at=?,error=NULL WHERE id=? AND status='queued'
    AND EXISTS(SELECT 1 FROM workers WHERE id=? AND status='active' AND accepting_jobs=1 AND removed_at IS NULL)
    AND EXISTS(SELECT 1 FROM factory_runs r JOIN factory_run_attempts a ON a.run_id=r.id AND a.attempt=? WHERE r.id=? AND r.status='running' AND r.current_attempt=? AND r.lease_expires_at>? AND a.status='running' AND a.lease_expires_at>?)`)
    .bind(worker.id, leaseToken, expires, timestamp, candidate.id, worker.id, candidate.attempt, candidate.run_id, candidate.attempt, timestamp, timestamp).run();
  if (!changed(result)) return null;
  await db.batch([audit(db, `worker:${worker.id}`, 'worker.factory_image_claimed', candidate.id, { runId: candidate.run_id, attempt: candidate.attempt, metadata })]);
  const row = await imageJob(db, candidate.id);
  if (!row || row.worker_id !== worker.id || row.lease_token !== leaseToken) throw new WorkerProtocolError(409, 'Private image lease was fenced.');
  return { id: row.id, runId: row.run_id, attempt: row.attempt, leaseToken, leaseExpiresAt: new Date(expires * 1000).toISOString(), candidate: candidateFromRow(row), inputSha256: row.input_sha256 };
}

function assertImageLease(row: FactoryImageJobRow, worker: Worker, leaseToken: string): void {
  if (row.status !== 'leased' || row.worker_id !== worker.id || row.lease_token !== leaseToken || !row.lease_expires_at || row.lease_expires_at <= now() || !row.factory_lease_token) throw new WorkerProtocolError(409, 'Private image lease is fenced or expired.');
}

export async function heartbeatPrivateFactoryImage(db: D1Database, worker: Worker, jobId: string, leaseToken: string, metadata: WorkerMetadata | null = null): Promise<{ leaseExpiresAt: string; cancel: boolean }> {
  const row = await imageJob(db, jobId); if (!row) throw new WorkerProtocolError(404, 'Private image job not found.');
  if (row.status === 'cancelled') return { leaseExpiresAt: new Date().toISOString(), cancel: true };
  assertImageLease(row, worker, leaseToken); await renewFactoryAttempt(db, row.run_id, row.attempt, row.factory_lease_token!);
  const expires = now() + LEASE_SECONDS;
  const result = await db.prepare(`UPDATE factory_image_jobs SET lease_expires_at=? WHERE id=? AND status='leased' AND worker_id=? AND lease_token=? AND lease_expires_at>?`).bind(expires, jobId, worker.id, leaseToken, now()).run();
  if (!changed(result)) throw new WorkerProtocolError(409, 'Private image lease is fenced.');
  if (metadata) await db.prepare("UPDATE workers SET last_seen_at=?,daemon_version=?,runtime=?,capabilities_json=? WHERE id=? AND status='active'").bind(now(), metadata.version, metadata.runtime, JSON.stringify(metadata.capabilities), worker.id).run();
  return { leaseExpiresAt: new Date(expires * 1000).toISOString(), cancel: false };
}

export async function factoryImageInputForWorker(env: FactoryImageEnvironment, auth: AuthenticatedWorker, jobId: string, leaseToken: string, inputName: FactoryImageInputName): Promise<{ body: ReadableStream<Uint8Array>; ref: FactoryImageObjectRef }> {
  const row = await imageJob(env.DB, jobId); if (!row) throw new WorkerProtocolError(404, 'Private image job not found.');
  assertImageLease(row, auth.worker, leaseToken); const candidate = candidateFromRow(row);
  const refs: Partial<Record<FactoryImageInputName, FactoryImageObjectRef>> = {
    profile: candidate.profile, 'candidate-lock': candidate.candidateLock, ...(candidate.candidateLockSignature ? { 'candidate-lock-signature': candidate.candidateLockSignature } : {}),
    'native-plan': candidate.nativePlan, ...(candidate.nativePlanSignature ? { 'native-plan-signature': candidate.nativePlanSignature } : {}), 'trusted-authority-key': candidate.trustedAuthorityKey,
    builder: candidate.builder, context: candidate.context, dockerfile: candidate.dockerfile,
  };
  const ref = refs[inputName]; if (!ref) throw new WorkerProtocolError(404, 'Private image input is not part of the reviewed candidate.');
  await verifyR2Object(env as Env, ref.key, ref.sha256, ref.size); const object = await env.ARTIFACTS.get(ref.key);
  if (!object?.body) throw new WorkerProtocolError(503, 'Private image input is unavailable.');
  return { body: object.body, ref };
}

interface ImageEvidence {
  schemaVersion: 1; kind: 'factory-image-result'; jobId: string; runId: string; attempt: number; candidateId: string; architecture: Architecture; imageKind: FactoryImageKind;
  inputSha256: string; profileSha256: string; nativePlanSha256: string; artifact: FactoryImageArtifact; builderSha256: string; imageRef: string | null; observed: Record<string, unknown>;
}

function parseEvidence(value: unknown, row: FactoryImageJobRow, artifact: FactoryImageArtifact): ImageEvidence {
  const object = requireObject(value); const keys = ['architecture','artifact','attempt','builderSha256','candidateId','imageKind','imageRef','inputSha256','jobId','kind','nativePlanSha256','observed','profileSha256','runId','schemaVersion'];
  if (Object.keys(object).sort().join(',') !== keys.sort().join(',')) throw new WorkerProtocolError(400, 'Private image evidence fields are invalid.');
  const evidence = object as Partial<ImageEvidence>;
  if (evidence.schemaVersion !== 1 || evidence.kind !== 'factory-image-result' || evidence.jobId !== row.id || evidence.runId !== row.run_id || evidence.attempt !== row.attempt || evidence.candidateId !== row.candidate_id || evidence.architecture !== row.architecture || evidence.imageKind !== row.kind || evidence.inputSha256 !== row.input_sha256 || typeof evidence.profileSha256 !== 'string' || !SHA256.test(evidence.profileSha256) || typeof evidence.nativePlanSha256 !== 'string' || !SHA256.test(evidence.nativePlanSha256) || typeof evidence.builderSha256 !== 'string' || !SHA256.test(evidence.builderSha256) || (evidence.imageRef !== null && typeof evidence.imageRef !== 'string') || !evidence.observed || typeof evidence.observed !== 'object' || Array.isArray(evidence.observed)) throw new WorkerProtocolError(409, 'Private image evidence does not bind the reviewed job.');
  const saved = evidence.artifact; if (!saved || typeof saved !== 'object' || saved.key !== artifact.key || saved.sha256 !== artifact.sha256 || saved.size !== artifact.size || saved.filename !== artifact.filename) throw new WorkerProtocolError(409, 'Private image evidence does not bind the uploaded artifact.');
  const candidate = candidateFromRow(row); if (evidence.profileSha256 !== candidate.profile.sha256 || evidence.nativePlanSha256 !== candidate.nativePlan.sha256 || evidence.builderSha256 !== candidate.builder.sha256) throw new WorkerProtocolError(409, 'Private image evidence input digests differ from the reviewed candidate.');
  if (row.kind === 'oci') {
    if (typeof evidence.imageRef !== 'string' || !IMAGE_REPOSITORY.test(evidence.imageRef) || !evidence.imageRef.includes('@sha256:')) throw new WorkerProtocolError(409, 'OCI evidence has no actual output image digest.');
    const requestedRepository = candidate.imageRef!.split('@', 1)[0];
    if (evidence.imageRef.split('@', 1)[0] !== requestedRepository) throw new WorkerProtocolError(409, 'OCI output image repository differs from the reviewed request.');
  } else if (evidence.imageRef !== null) throw new WorkerProtocolError(409, 'System image evidence cannot claim an OCI image reference.');
  return evidence as ImageEvidence;
}

export async function completePrivateFactoryImage(env: FactoryImageEnvironment, worker: Worker, jobId: string, value: unknown): Promise<{ status: 'succeeded' | 'failed'; artifact?: FactoryImageArtifact; evidenceSha256?: string }> {
  const input = requireObject(value); if (Object.keys(input).some((key) => !['leaseToken','status','error','evidence','evidenceSignature'].includes(key))) throw new WorkerProtocolError(400, 'Unexpected private image completion field.');
  const leaseToken = requireText(input.leaseToken, 'lease token', 128); const row = await imageJob(env.DB, jobId); if (!row) throw new WorkerProtocolError(404, 'Private image job not found.');
  if (row.status === 'succeeded') return { status: 'succeeded', artifact: row.artifact_key && row.artifact_sha256 && row.artifact_size && row.artifact_filename ? { key: row.artifact_key, sha256: row.artifact_sha256, size: row.artifact_size, filename: row.artifact_filename } : undefined, evidenceSha256: row.evidence_sha256 ?? undefined };
  assertImageLease(row, worker, leaseToken);
  if (input.status === 'failed') { const error = requireText(input.error, 'private image failure', 2_000); await dbFinishImageFailure(env.DB, row, worker, leaseToken, error); return { status: 'failed' }; }
  if (input.status !== 'succeeded' || typeof input.evidence !== 'string' || typeof input.evidenceSignature !== 'string') throw new WorkerProtocolError(400, 'Private image success requires signed evidence.');
  if (!input.evidence.length || new TextEncoder().encode(input.evidence).byteLength > MAX_EVIDENCE_BYTES) throw new WorkerProtocolError(413, 'Private image evidence is too large.');
  const artifact = row.artifact_key && row.artifact_sha256 && row.artifact_size && row.artifact_filename ? { key: row.artifact_key, sha256: row.artifact_sha256, size: row.artifact_size, filename: row.artifact_filename } : null;
  if (!artifact) throw new WorkerProtocolError(409, 'Private image output must be uploaded before completion.');
  await verifyR2Object(env as Env, artifact.key, artifact.sha256, artifact.size); const evidence = parseEvidence(JSON.parse(input.evidence) as unknown, row, artifact);
  const publicKey = decodeBase64(worker.public_key, 'worker public key'); const signature = decodeBase64(input.evidenceSignature, 'private image evidence signature');
  if (!await verifyEd25519(publicKey, new TextEncoder().encode(input.evidence), signature)) throw new WorkerProtocolError(403, 'Private image evidence signature is invalid.');
  const evidenceSha256 = await sha256(input.evidence);
  const result = await env.DB.prepare(`UPDATE factory_image_jobs SET status='succeeded',evidence_json=?,evidence_sha256=?,evidence_signature=?,finished_at=?,lease_expires_at=? WHERE id=? AND status='leased' AND worker_id=? AND lease_token=?`).bind(input.evidence, evidenceSha256, input.evidenceSignature, now(), now(), jobId, worker.id, leaseToken).run();
  if (!changed(result)) throw new WorkerProtocolError(409, 'Private image completion was fenced.');
  await audit(env.DB, `worker:${worker.id}`, 'worker.factory_image_completed', jobId, { runId: row.run_id, attempt: row.attempt, artifact, evidenceSha256 });
  return { status: 'succeeded', artifact, evidenceSha256 };
}

async function dbFinishImageFailure(db: D1Database, row: FactoryImageJobRow, worker: Worker, leaseToken: string, error: string): Promise<void> {
  const result = await db.prepare(`UPDATE factory_image_jobs SET status='failed',error=?,finished_at=?,lease_expires_at=? WHERE id=? AND status='leased' AND worker_id=? AND lease_token=?`).bind(error, now(), now(), row.id, worker.id, leaseToken).run();
  if (!changed(result)) throw new WorkerProtocolError(409, 'Private image failure was fenced.');
  await audit(db, `worker:${worker.id}`, 'worker.factory_image_failed', row.id, { runId: row.run_id, attempt: row.attempt, error });
}

function parseUpload(value: unknown): { leaseToken: string; filename: string; size: number; sha256: string } {
  const object = requireObject(value); if (Object.keys(object).sort().join(',') !== 'filename,leaseToken,sha256,size') throw new WorkerProtocolError(400, 'Invalid private image upload fields.');
  const filename = requireText(object.filename, 'image filename', 256); if (!IMAGE_FILENAME.test(filename)) throw new WorkerProtocolError(400, 'Invalid image filename.');
  const leaseToken = requireText(object.leaseToken, 'lease token', 128); const digest = requireText(object.sha256, 'image digest', 64);
  if (!SHA256.test(digest) || !Number.isSafeInteger(object.size) || (object.size as number) <= 0 || (object.size as number) > MAX_OUTPUT_BYTES) throw new WorkerProtocolError(400, 'Invalid private image upload metadata.');
  return { leaseToken, filename, size: object.size as number, sha256: digest };
}

async function imageUploadRow(db: D1Database, jobId: string, uploadId: string, workerId: string): Promise<FactoryImageUploadRow | null> { return db.prepare('SELECT * FROM factory_image_uploads WHERE id=? AND job_id=? AND worker_id=?').bind(uploadId, jobId, workerId).first<FactoryImageUploadRow>(); }
async function imageUploadParts(db: D1Database, uploadId: string): Promise<FactoryImageUploadPart[]> {
  const rows = await db.prepare('SELECT part_number AS partNumber,sha256,size,etag FROM factory_image_upload_parts WHERE upload_id=? ORDER BY part_number').bind(uploadId).all<FactoryImageUploadPart>(); return rows.results;
}
function uploadPartSize(size: number, partNumber: number): { total: number; size: number } {
  const total = Math.ceil(size / FACTORY_IMAGE_UPLOAD_PART_SIZE); if (!Number.isSafeInteger(partNumber) || partNumber < 1 || partNumber > total || partNumber > FACTORY_IMAGE_MAX_UPLOAD_PARTS) throw new WorkerProtocolError(400, 'Invalid private image upload part.');
  return { total, size: partNumber === total ? size - (partNumber - 1) * FACTORY_IMAGE_UPLOAD_PART_SIZE : FACTORY_IMAGE_UPLOAD_PART_SIZE };
}

export async function startFactoryImageUpload(env: FactoryImageEnvironment, worker: Worker, jobId: string, value: unknown): Promise<Record<string, unknown>> {
  const input = parseUpload(value); const job = await imageJob(env.DB, jobId); if (!job) throw new WorkerProtocolError(404, 'Private image job not found.'); assertImageLease(job, worker, input.leaseToken);
  if (input.filename !== candidateFromRow(job).outputFilename) throw new WorkerProtocolError(409, 'Image filename differs from the reviewed candidate.');
  const active = await env.DB.prepare("SELECT * FROM factory_image_uploads WHERE job_id=? AND status='active'").bind(jobId).first<FactoryImageUploadRow>();
  if (active) {
    if (active.worker_id !== worker.id || active.lease_token !== input.leaseToken || active.filename !== input.filename || active.expected_size !== input.size || active.expected_sha256 !== input.sha256) throw new WorkerProtocolError(409, 'Private image already has a different upload.');
    return { uploadId: active.id, partSize: FACTORY_IMAGE_UPLOAD_PART_SIZE, maxSize: MAX_OUTPUT_BYTES, filename: active.filename, size: active.expected_size, sha256: active.expected_sha256, parts: await imageUploadParts(env.DB, active.id) };
  }
  const uploadId = id(); const key = `private/factory-images/${jobId}/attempt-${job.attempt}/upload-${uploadId}/${input.sha256}-${input.filename}`; const multipart = await env.ARTIFACTS.createMultipartUpload(key, { customMetadata: { factoryImageJobId: jobId, sha256: input.sha256 } });
  try { await env.DB.prepare(`INSERT INTO factory_image_uploads(id,job_id,worker_id,attempt,lease_token,filename,object_key,r2_upload_id,expected_size,expected_sha256,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)`).bind(uploadId, jobId, worker.id, job.attempt, input.leaseToken, input.filename, key, multipart.uploadId, input.size, input.sha256, now()).run(); }
  catch (cause) { await multipart.abort().catch(() => undefined); throw cause; }
  return { uploadId, partSize: FACTORY_IMAGE_UPLOAD_PART_SIZE, maxSize: MAX_OUTPUT_BYTES, filename: input.filename, size: input.size, sha256: input.sha256, parts: [] };
}

export async function uploadFactoryImagePart(env: FactoryImageEnvironment, worker: Worker, jobId: string, uploadId: string, partNumber: number, leaseToken: string, body: Uint8Array): Promise<FactoryImageUploadPart> {
  const row = await imageUploadRow(env.DB, jobId, uploadId, worker.id); if (!row) throw new WorkerProtocolError(404, 'Private image upload not found.'); const job = await imageJob(env.DB, jobId); if (!job) throw new WorkerProtocolError(404, 'Private image job not found.'); assertImageLease(job, worker, leaseToken);
  if (row.status !== 'active' || row.lease_token !== leaseToken || row.attempt !== job.attempt) throw new WorkerProtocolError(409, 'Private image upload lease is fenced.'); const expected = uploadPartSize(row.expected_size, partNumber); if (body.byteLength !== expected.size) throw new WorkerProtocolError(400, 'Private image upload part size is invalid.');
  const digest = await sha256(body); const existing = (await imageUploadParts(env.DB, uploadId)).find((part) => part.partNumber === partNumber); if (existing) { if (existing.sha256 !== digest || existing.size !== body.byteLength) throw new WorkerProtocolError(409, 'Private image upload part conflicts.'); return existing; }
  const uploaded = await env.ARTIFACTS.resumeMultipartUpload(row.object_key, row.r2_upload_id).uploadPart(partNumber, body); if (!uploaded.etag) throw new WorkerProtocolError(503, 'Private image upload storage returned no ETag.');
  await env.DB.prepare('INSERT INTO factory_image_upload_parts(upload_id,part_number,sha256,size,etag,created_at) VALUES(?,?,?,?,?,?)').bind(uploadId, partNumber, digest, body.byteLength, uploaded.etag, now()).run();
  return { partNumber, sha256: digest, size: body.byteLength, etag: uploaded.etag };
}

export async function completeFactoryImageUpload(env: FactoryImageEnvironment, worker: Worker, jobId: string, uploadId: string, leaseToken: string): Promise<FactoryImageArtifact> {
  const row = await imageUploadRow(env.DB, jobId, uploadId, worker.id); if (!row) throw new WorkerProtocolError(404, 'Private image upload not found.'); if (row.status === 'completed' && row.actual_sha256 && row.actual_size !== null) return { key: row.object_key, sha256: row.actual_sha256, size: row.actual_size, filename: row.filename };
  const job = await imageJob(env.DB, jobId); if (!job) throw new WorkerProtocolError(404, 'Private image job not found.'); assertImageLease(job, worker, leaseToken); if (row.status !== 'active' || row.lease_token !== leaseToken) throw new WorkerProtocolError(409, 'Private image upload lease is fenced.');
  const parts = await imageUploadParts(env.DB, uploadId); const expected = uploadPartSize(row.expected_size, Math.ceil(row.expected_size / FACTORY_IMAGE_UPLOAD_PART_SIZE)); if (parts.length !== expected.total || parts.some((part, index) => part.partNumber !== index + 1 || part.size !== uploadPartSize(row.expected_size, part.partNumber).size)) throw new WorkerProtocolError(409, 'Private image upload is incomplete.');
  await env.ARTIFACTS.resumeMultipartUpload(row.object_key, row.r2_upload_id).complete(parts.map((part) => ({ partNumber: part.partNumber, etag: part.etag }))); const actual = await hashObject(env.ARTIFACTS, row.object_key, MAX_OUTPUT_BYTES);
  if (actual.sha256 !== row.expected_sha256 || actual.size !== row.expected_size) { await env.ARTIFACTS.delete(row.object_key).catch(() => undefined); throw new WorkerProtocolError(409, 'Private image bytes do not match declaration.'); }
  const timestamp = now(); const result = await env.DB.batch([
    env.DB.prepare(`UPDATE factory_image_uploads SET status='completed',actual_sha256=?,actual_size=?,completed_at=? WHERE id=? AND status='active' AND lease_token=?`).bind(actual.sha256, actual.size, timestamp, uploadId, leaseToken),
    env.DB.prepare(`UPDATE factory_image_jobs SET artifact_key=?,artifact_sha256=?,artifact_size=?,artifact_filename=? WHERE id=? AND status='leased' AND worker_id=? AND lease_token=?`).bind(row.object_key, actual.sha256, actual.size, row.filename, jobId, worker.id, leaseToken),
    audit(env.DB, `worker:${worker.id}`, 'worker.factory_image_upload_completed', jobId, { uploadId, sha256: actual.sha256, size: actual.size, filename: row.filename }),
  ]);
  if (!changed(result[0]) || !changed(result[1])) throw new WorkerProtocolError(409, 'Private image upload completion was fenced.'); return { key: row.object_key, sha256: actual.sha256, size: actual.size, filename: row.filename };
}
