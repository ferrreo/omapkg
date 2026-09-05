import { createHash } from 'node:crypto';
import type { Worker, Architecture } from '../model';
import {
  WorkerProtocolError,
  MAX_ARTIFACT_BYTES,
  type ArtifactReference,
  type WorkerLease,
  requireWorkerLease,
  validateArtifactFilename
} from './workers';
import { audit, id, now, sha256 } from './db';

export const UPLOAD_PART_SIZE = 8 * 1024 * 1024;
export const MAX_UPLOAD_SIZE = MAX_ARTIFACT_BYTES;
export const MAX_UPLOAD_PARTS = MAX_UPLOAD_SIZE / UPLOAD_PART_SIZE;
export const MAX_UPLOAD_JSON_BYTES = 64 * 1024;

const sha256Pattern = /^[0-9a-f]{64}$/;

export interface UploadPart {
  partNumber: number;
  sha256: string;
  size: number;
  etag: string;
}

export interface UploadStartResponse {
  uploadId: string;
  partSize: number;
  maxSize: number;
  filename: string;
  size: number;
  sha256: string;
  parts: UploadPart[];
}

export type UploadStartResult = UploadStartResponse | { completed: ArtifactReference };

interface UploadRow {
  id: string;
  build_id: string;
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
  revision_surface: 'binary' | 'recipe';
  build_status: WorkerLease['status'];
  build_artifact_key: string | null;
  build_artifact_sha256: string | null;
  build_artifact_size: number | null;
  build_artifact_filename: string | null;
}

interface UploadPartRow {
  part_number: number;
  sha256: string;
  size: number;
  etag: string;
}

interface StartInput {
  leaseToken: string;
  filename: string;
  size: number;
  sha256: string;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function requireString(value: unknown, field: string, maxLength: number): string {
  if (typeof value !== 'string' || value.length === 0 || value.length > maxLength || value.includes('\u0000')) {
    throw new WorkerProtocolError(400, `Invalid ${field}`);
  }
  return value;
}

function requireLeaseToken(value: unknown): string {
  return requireString(value, 'leaseToken', 128);
}

function parseObject(value: unknown): Record<string, unknown> {
  if (!isRecord(value)) throw new WorkerProtocolError(400, 'JSON body must be an object');
  return value;
}

function parseStartInput(value: unknown): StartInput {
  const object = parseObject(value);
  const allowed = new Set(['leaseToken', 'filename', 'size', 'sha256']);
  if (Object.keys(object).some((key) => !allowed.has(key))) throw new WorkerProtocolError(400, 'Unexpected upload field');
  const leaseToken = requireLeaseToken(object.leaseToken);
  const filename = validateArtifactFilename(object.filename);
  if (!Number.isSafeInteger(object.size) || (object.size as number) <= 0 || (object.size as number) > MAX_UPLOAD_SIZE) {
    throw new WorkerProtocolError(400, 'Invalid upload size');
  }
  if (typeof object.sha256 !== 'string' || !sha256Pattern.test(object.sha256)) throw new WorkerProtocolError(400, 'Invalid upload checksum');
  return { leaseToken, filename, size: object.size as number, sha256: object.sha256 };
}

function parseLeaseInput(value: unknown): string {
  const object = parseObject(value);
  if (Object.keys(object).some((key) => key !== 'leaseToken')) throw new WorkerProtocolError(400, 'Unexpected upload field');
  return requireLeaseToken(object.leaseToken);
}

function storageFailure(): never {
  throw new WorkerProtocolError(503, 'Upload storage unavailable');
}

function databaseFailure(): never {
  throw new WorkerProtocolError(500, 'Upload storage failure');
}

function isUnique(cause: unknown): boolean {
  return cause instanceof Error && /unique|primary key|constraint/i.test(cause.message);
}

function uploadArtifactReference(row: UploadRow, digest = row.actual_sha256, size = row.actual_size): ArtifactReference {
  if (!digest || size === null) throw new WorkerProtocolError(500, 'Completed upload metadata is incomplete');
  return { key: row.object_key, sha256: digest, size, filename: row.filename };
}

function uploadQuery(): string {
  return `
    SELECT u.id, u.build_id, u.worker_id, u.attempt, u.lease_token, u.filename, u.object_key, u.r2_upload_id,
      u.expected_size, u.expected_sha256, u.status, u.actual_size, u.actual_sha256, u.created_at, u.completed_at,
      r.surface AS revision_surface, b.status AS build_status, b.artifact_key AS build_artifact_key,
      b.artifact_sha256 AS build_artifact_sha256, b.artifact_size AS build_artifact_size,
      b.artifact_filename AS build_artifact_filename
    FROM worker_uploads u
    JOIN builds b ON b.id = u.build_id
    JOIN revisions r ON r.id = b.revision_id`;
}

async function getUpload(db: D1Database, buildId: string, uploadId: string, workerId: string): Promise<UploadRow | null> {
  try {
    return await db.prepare(`${uploadQuery()} WHERE u.id = ? AND u.build_id = ? AND u.worker_id = ?`)
      .bind(uploadId, buildId, workerId).first<UploadRow>();
  } catch {
    return databaseFailure();
  }
}

async function getUploadById(db: D1Database, uploadId: string, workerId: string): Promise<UploadRow | null> {
  try {
    return await db.prepare(`${uploadQuery()} WHERE u.id = ? AND u.worker_id = ?`).bind(uploadId, workerId).first<UploadRow>();
  } catch {
    return databaseFailure();
  }
}

async function getParts(db: D1Database, uploadId: string): Promise<UploadPartRow[]> {
  try {
    const result = await db.prepare('SELECT part_number, sha256, size, etag FROM worker_upload_parts WHERE upload_id = ? ORDER BY part_number')
      .bind(uploadId).all<UploadPartRow>();
    return result.results;
  } catch {
    return databaseFailure();
  }
}

function assertActiveUpload(row: UploadRow, worker: Worker, build: WorkerLease, leaseToken: string): void {
  if (row.status !== 'active' || row.lease_token !== leaseToken || row.attempt !== build.attempt || row.worker_id !== worker.id || row.build_status !== 'leased') {
    throw new WorkerProtocolError(409, 'Upload lease is fenced');
  }
  if (row.revision_surface !== 'binary') throw new WorkerProtocolError(409, 'Recipe builds cannot upload artifacts');
  if (row.build_artifact_key !== null) throw new WorkerProtocolError(409, 'Build already has an artifact');
}

function responseParts(parts: UploadPartRow[]): UploadPart[] {
  return parts.map((part) => ({ partNumber: part.part_number, sha256: part.sha256, size: part.size, etag: part.etag }));
}

function completedArtifact(build: WorkerLease): ArtifactReference | null {
  if (build.artifact_key === null) return null;
  if (!build.artifact_sha256 || build.artifact_size === null || !build.artifact_filename) {
    throw new WorkerProtocolError(500, 'Completed artifact metadata is incomplete');
  }
  return {
    key: build.artifact_key,
    sha256: build.artifact_sha256,
    size: build.artifact_size,
    filename: build.artifact_filename
  };
}

export async function startMultipartUpload(
  db: D1Database,
  bucket: R2Bucket,
  worker: Worker,
  buildId: string,
  value: unknown
): Promise<UploadStartResult> {
  const input = parseStartInput(value);
  const build = await requireWorkerLease(db, worker, buildId, input.leaseToken);
  if (build.revision_surface !== 'binary') throw new WorkerProtocolError(409, 'Build cannot accept an artifact upload');
  const completed = completedArtifact(build);
  if (completed) {
    if (completed.filename !== input.filename || completed.sha256 !== input.sha256 || completed.size !== input.size) {
      throw new WorkerProtocolError(409, 'Build already has a different artifact');
    }
    return { completed };
  }
  const active = await getAnyActiveUploadForBuild(db, buildId);
  if (active) {
    if (active.worker_id === worker.id && active.status === 'active' && active.attempt === build.attempt && active.lease_token === input.leaseToken &&
        active.filename === input.filename && active.expected_size === input.size && active.expected_sha256 === input.sha256) {
      return {
        uploadId: active.id, partSize: UPLOAD_PART_SIZE, maxSize: MAX_UPLOAD_SIZE, filename: active.filename,
        size: active.expected_size, sha256: active.expected_sha256, parts: responseParts(await getParts(db, active.id))
      };
    }
    if (active.attempt === build.attempt && active.worker_id === worker.id && active.lease_token === input.leaseToken) {
      throw new WorkerProtocolError(409, 'Build already has a different upload');
    }
    await abortR2(bucket, active);
    await markFailed(db, active, { reason: 'superseded worker lease' });
  }
  const uploadId = id();
  const objectKey = `private/builds/${build.id}/attempt-${build.attempt}/${input.sha256}-${input.filename}`;
  let multipart: R2MultipartUpload;
  try {
    multipart = await bucket.createMultipartUpload(objectKey, { customMetadata: { buildId: build.id, sha256: input.sha256 } });
  } catch {
    return storageFailure();
  }
  const timestamp = now();
  try {
    await db.batch([
      db.prepare(`INSERT INTO worker_uploads
        (id, build_id, worker_id, attempt, lease_token, filename, object_key, r2_upload_id, expected_size, expected_sha256, status, created_at)
        SELECT ?, ?, ?, b.attempt, ?, ?, ?, ?, ?, ?, 'active', ? FROM builds b
        JOIN revisions r ON r.id = b.revision_id
        WHERE b.id = ? AND b.worker_id = ? AND b.lease_token = ? AND b.status = 'leased' AND b.lease_expires_at > ?
          AND b.artifact_key IS NULL AND r.surface = 'binary'
          AND b.revision_id = (SELECT latest.id FROM revisions latest WHERE latest.request_id = r.request_id ORDER BY latest.created_at DESC, latest.rowid DESC LIMIT 1)
          AND EXISTS (SELECT 1 FROM approvals a WHERE a.revision_id = b.revision_id AND a.kind = 'area' AND a.manifest_sha256 = r.manifest_sha256 AND a.revoked_at IS NULL)
          AND EXISTS (SELECT 1 FROM approvals a WHERE a.revision_id = b.revision_id AND a.kind = 'security' AND a.manifest_sha256 = r.manifest_sha256 AND a.revoked_at IS NULL)
          AND EXISTS (SELECT 1 FROM workers w WHERE w.id = ? AND w.status = 'active')`)
        .bind(uploadId, build.id, worker.id, input.leaseToken, input.filename, objectKey, multipart.uploadId, input.size, input.sha256,
          timestamp, build.id, worker.id, input.leaseToken, timestamp, worker.id),
      db.prepare(`INSERT INTO audit_events(actor, action, target, detail, created_at)
        SELECT ?, 'worker.upload_started', ?, ?, ? WHERE changes() = 1`)
        .bind(`worker:${worker.id}`, build.id, JSON.stringify({ uploadId, attempt: build.attempt, filename: input.filename, size: input.size, sha256: input.sha256 }), timestamp)
    ]);
  } catch (cause) {
    await multipart.abort().catch(() => undefined);
    if (isUnique(cause)) {
      const existing = await getUploadForBuild(db, buildId, worker.id);
      if (existing && existing.status === 'active' && existing.attempt === build.attempt && existing.lease_token === input.leaseToken &&
          existing.filename === input.filename && existing.expected_size === input.size && existing.expected_sha256 === input.sha256) {
        return {
          uploadId: existing.id, partSize: UPLOAD_PART_SIZE, maxSize: MAX_UPLOAD_SIZE, filename: existing.filename,
          size: existing.expected_size, sha256: existing.expected_sha256, parts: responseParts(await getParts(db, existing.id))
        };
      }
      throw new WorkerProtocolError(409, 'Build already has an upload');
    }
    return databaseFailure();
  }
  return { uploadId, partSize: UPLOAD_PART_SIZE, maxSize: MAX_UPLOAD_SIZE, filename: input.filename, size: input.size, sha256: input.sha256, parts: [] };
}

async function getUploadForBuild(db: D1Database, buildId: string, workerId: string): Promise<UploadRow | null> {
  try {
    return await db.prepare(`${uploadQuery()} WHERE u.build_id = ? AND u.worker_id = ? AND u.status = 'active' LIMIT 1`)
      .bind(buildId, workerId).first<UploadRow>();
  } catch {
    return databaseFailure();
  }
}

async function getAnyActiveUploadForBuild(db: D1Database, buildId: string): Promise<UploadRow | null> {
  try {
    return await db.prepare(`${uploadQuery()} WHERE u.build_id = ? AND u.status = 'active' LIMIT 1`)
      .bind(buildId).first<UploadRow>();
  } catch {
    return databaseFailure();
  }
}

function partSize(expectedSize: number, partNumber: number): { totalParts: number; size: number } {
  const totalParts = Math.ceil(expectedSize / UPLOAD_PART_SIZE);
  if (!Number.isSafeInteger(partNumber) || partNumber < 1 || partNumber > totalParts || partNumber > MAX_UPLOAD_PARTS) {
    throw new WorkerProtocolError(400, 'Invalid upload part number');
  }
  return {
    totalParts,
    size: partNumber === totalParts ? expectedSize - (partNumber - 1) * UPLOAD_PART_SIZE : UPLOAD_PART_SIZE
  };
}

export async function uploadMultipartPart(
  db: D1Database,
  bucket: R2Bucket,
  worker: Worker,
  buildId: string,
  uploadId: string,
  partNumber: number,
  leaseTokenValue: unknown,
  body: Uint8Array
): Promise<UploadPart> {
  const leaseToken = requireLeaseToken(leaseTokenValue);
  const build = await requireWorkerLease(db, worker, buildId, leaseToken);
  const row = await getUpload(db, buildId, uploadId, worker.id);
  if (!row) throw new WorkerProtocolError(404, 'Upload not found');
  assertActiveUpload(row, worker, build, leaseToken);
  const expected = partSize(row.expected_size, partNumber);
  if (body.byteLength !== expected.size) throw new WorkerProtocolError(400, 'Upload part has an invalid size');
  const digest = await sha256(body);
  const existing = (await getParts(db, uploadId)).find((part) => part.part_number === partNumber);
  if (existing) {
    if (existing.sha256 !== digest || existing.size !== body.byteLength) throw new WorkerProtocolError(409, 'Upload part already contains different bytes');
    return { partNumber, sha256: existing.sha256, size: existing.size, etag: existing.etag };
  }
  let uploaded: R2UploadedPart;
  try {
    const multipart = bucket.resumeMultipartUpload(row.object_key, row.r2_upload_id);
    uploaded = await multipart.uploadPart(partNumber, body);
  } catch {
    return storageFailure();
  }
  if (!uploaded.etag || uploaded.partNumber !== partNumber) {
    throw new WorkerProtocolError(503, 'Upload storage returned an invalid part');
  }
  const timestamp = now();
  try {
    await db.batch([
      db.prepare(`INSERT OR IGNORE INTO worker_upload_parts(upload_id, part_number, sha256, size, etag, created_at)
        SELECT ?, ?, ?, ?, ?, ? WHERE EXISTS (
          SELECT 1 FROM worker_uploads u JOIN builds b ON b.id = u.build_id
          JOIN workers w ON w.id = u.worker_id
          WHERE u.id = ? AND u.build_id = ? AND u.worker_id = ? AND u.status = 'active' AND u.attempt = ? AND u.lease_token = ?
            AND b.status = 'leased' AND b.worker_id = ? AND b.lease_token = ? AND b.lease_expires_at > ? AND w.status = 'active'
            AND b.revision_id = (SELECT latest.id FROM revisions latest WHERE latest.request_id = (SELECT request_id FROM revisions current_revision WHERE current_revision.id = b.revision_id) ORDER BY latest.created_at DESC, latest.rowid DESC LIMIT 1)
            AND EXISTS (SELECT 1 FROM approvals a WHERE a.revision_id = b.revision_id AND a.kind = 'area' AND a.manifest_sha256 = (SELECT manifest_sha256 FROM revisions WHERE id = b.revision_id) AND a.revoked_at IS NULL)
            AND EXISTS (SELECT 1 FROM approvals a WHERE a.revision_id = b.revision_id AND a.kind = 'security' AND a.manifest_sha256 = (SELECT manifest_sha256 FROM revisions WHERE id = b.revision_id) AND a.revoked_at IS NULL))`)
        .bind(uploadId, partNumber, digest, body.byteLength, uploaded.etag, timestamp, uploadId, buildId, worker.id, build.attempt, leaseToken,
          worker.id, leaseToken, timestamp),
      db.prepare(`INSERT INTO audit_events(actor, action, target, detail, created_at)
        SELECT ?, 'worker.upload_part', ?, ?, ? WHERE changes() = 1`)
        .bind(`worker:${worker.id}`, buildId, JSON.stringify({ uploadId, partNumber, size: body.byteLength, sha256: digest }), timestamp)
    ]);
  } catch (cause) {
    await abortR2(bucket, row);
    await markFailed(db, row, { reason: 'part metadata commit failed' });
    return databaseFailure();
  }
  const saved = (await getParts(db, uploadId)).find((part) => part.part_number === partNumber);
  if (!saved) throw new WorkerProtocolError(409, 'Upload lease is fenced');
  if (saved.sha256 !== digest || saved.size !== body.byteLength) {
    await abortR2(bucket, row);
    await markFailed(db, row, { reason: 'conflicting part bytes' });
    throw new WorkerProtocolError(409, 'Upload part already contains different bytes');
  }
  return { partNumber, sha256: saved.sha256, size: saved.size, etag: saved.etag };
}

async function hashObject(bucket: R2Bucket, key: string): Promise<{ sha256: string; size: number }> {
  let object: R2ObjectBody | null;
  try {
    object = await bucket.get(key) as R2ObjectBody | null;
  } catch {
    return storageFailure();
  }
  if (!object?.body) throw new WorkerProtocolError(409, 'Completed upload is missing');
  const hash = createHash('sha256');
  const reader = object.body.getReader();
  let size = 0;
  try {
    while (true) {
      const next = await reader.read();
      if (next.done) break;
      size += next.value.byteLength;
      if (size > MAX_UPLOAD_SIZE) {
        await reader.cancel();
        throw new WorkerProtocolError(409, 'Completed upload is too large');
      }
      hash.update(next.value as Uint8Array);
    }
  } finally {
    reader.releaseLock();
  }
  return { sha256: hash.digest('hex'), size };
}

async function markFailed(db: D1Database, row: UploadRow, detail: Record<string, unknown>): Promise<void> {
  const timestamp = now();
  try {
    await db.batch([
      db.prepare("UPDATE worker_uploads SET status = 'failed', actual_size = ?, actual_sha256 = ?, completed_at = ? WHERE id = ? AND status = 'active'")
        .bind(detail.actualSize ?? null, detail.actualSha256 ?? null, timestamp, row.id),
      db.prepare(`INSERT INTO audit_events(actor, action, target, detail, created_at)
        SELECT 'worker-upload', 'worker.upload_failed', ?, ?, ? WHERE changes() = 1`)
        .bind(row.build_id, JSON.stringify({ uploadId: row.id, ...detail }), timestamp)
    ]);
  } catch {
    databaseFailure();
  }
}

async function abortR2(bucket: R2Bucket, row: UploadRow): Promise<void> {
  try {
    await bucket.resumeMultipartUpload(row.object_key, row.r2_upload_id).abort();
  } catch {
    await bucket.delete(row.object_key).catch(() => undefined);
  }
}

export async function completeMultipartUpload(
  db: D1Database,
  bucket: R2Bucket,
  worker: Worker,
  buildId: string,
  uploadId: string,
  value: unknown
): Promise<ArtifactReference> {
  const leaseToken = parseLeaseInput(value);
  const existing = await getUpload(db, buildId, uploadId, worker.id);
  if (!existing || existing.lease_token !== leaseToken) throw new WorkerProtocolError(409, 'Upload lease is fenced');
  const build = await requireWorkerLease(db, worker, buildId, leaseToken);
  if (existing.status === 'completed') return uploadArtifactReference(existing);
  if (existing.status !== 'active') throw new WorkerProtocolError(409, 'Upload is no longer active');
  assertActiveUpload(existing, worker, build, leaseToken);
  const parts = await getParts(db, uploadId);
  const expected = partSize(existing.expected_size, Math.ceil(existing.expected_size / UPLOAD_PART_SIZE));
  if (parts.length !== expected.totalParts || parts.some((part, index) => part.part_number !== index + 1)) {
    await abortR2(bucket, existing);
    await markFailed(db, existing, { reason: 'missing or non-contiguous parts' });
    throw new WorkerProtocolError(409, 'Upload is missing parts');
  }
  if (parts.some((part) => part.size !== partSize(existing.expected_size, part.part_number).size)) {
    await abortR2(bucket, existing);
    await markFailed(db, existing, { reason: 'part size mismatch' });
    throw new WorkerProtocolError(409, 'Upload part sizes do not match declaration');
  }
  try {
    const multipart = bucket.resumeMultipartUpload(existing.object_key, existing.r2_upload_id);
    await multipart.complete(parts.map((part) => ({ partNumber: part.part_number, etag: part.etag })));
  } catch {
    await abortR2(bucket, existing);
    await markFailed(db, existing, { reason: 'multipart completion failed' });
    return storageFailure();
  }
  let actual: { sha256: string; size: number };
  try {
    actual = await hashObject(bucket, existing.object_key);
  } catch (cause) {
    await bucket.delete(existing.object_key).catch(() => undefined);
    await markFailed(db, existing, { reason: cause instanceof WorkerProtocolError ? cause.message : 'object hashing failed' });
    throw cause;
  }
  if (actual.sha256 !== existing.expected_sha256 || actual.size !== existing.expected_size) {
    await bucket.delete(existing.object_key).catch(() => undefined);
    await markFailed(db, existing, { reason: 'whole-object digest mismatch', actualSha256: actual.sha256, actualSize: actual.size });
    throw new WorkerProtocolError(409, 'Uploaded bytes do not match declaration');
  }
  const timestamp = now();
  try {
    await db.batch([
      db.prepare(`UPDATE builds SET artifact_key = ?, artifact_sha256 = ?, artifact_size = ?, artifact_filename = ?
        WHERE id = ? AND worker_id = ? AND lease_token = ? AND status = 'leased' AND lease_expires_at > ? AND artifact_key IS NULL
          AND EXISTS (SELECT 1 FROM workers WHERE id = ? AND status = 'active')
          AND revision_id = (SELECT latest.id FROM revisions latest WHERE latest.request_id = (SELECT request_id FROM revisions current_revision WHERE current_revision.id = builds.revision_id) ORDER BY latest.created_at DESC, latest.rowid DESC LIMIT 1)
          AND EXISTS (SELECT 1 FROM approvals a WHERE a.revision_id = builds.revision_id AND a.kind = 'area' AND a.manifest_sha256 = (SELECT manifest_sha256 FROM revisions WHERE id = builds.revision_id) AND a.revoked_at IS NULL)
          AND EXISTS (SELECT 1 FROM approvals a WHERE a.revision_id = builds.revision_id AND a.kind = 'security' AND a.manifest_sha256 = (SELECT manifest_sha256 FROM revisions WHERE id = builds.revision_id) AND a.revoked_at IS NULL)
          AND EXISTS (SELECT 1 FROM worker_uploads u WHERE u.id = ? AND u.status = 'active' AND u.lease_token = ?)`)
        .bind(existing.object_key, actual.sha256, actual.size, existing.filename, buildId, worker.id, leaseToken, timestamp, worker.id, uploadId, leaseToken),
      db.prepare(`UPDATE worker_uploads SET status = 'completed', actual_sha256 = ?, actual_size = ?, completed_at = ?
        WHERE id = ? AND status = 'active' AND changes() = 1`).bind(actual.sha256, actual.size, timestamp, uploadId),
      db.prepare(`INSERT INTO audit_events(actor, action, target, detail, created_at)
        SELECT ?, 'worker.upload_completed', ?, ?, ? WHERE changes() = 1`)
        .bind(`worker:${worker.id}`, buildId, JSON.stringify({ uploadId, sha256: actual.sha256, size: actual.size, filename: existing.filename }), timestamp)
    ]);
  } catch {
    await bucket.delete(existing.object_key).catch(() => undefined);
    await markFailed(db, existing, { reason: 'artifact metadata commit failed' });
    return databaseFailure();
  }
  const completed = await getUpload(db, buildId, uploadId, worker.id);
  if (!completed || completed.status !== 'completed') {
    await bucket.delete(existing.object_key).catch(() => undefined);
    await markFailed(db, existing, { reason: 'artifact metadata commit was fenced' });
    throw new WorkerProtocolError(409, 'Upload lease is fenced');
  }
  return uploadArtifactReference(completed);
}

export async function abortMultipartUpload(
  db: D1Database,
  bucket: R2Bucket,
  worker: Worker,
  buildId: string,
  uploadId: string,
  value: unknown
): Promise<{ ok: true }> {
  const leaseToken = parseLeaseInput(value);
  const build = await requireWorkerLease(db, worker, buildId, leaseToken);
  const row = await getUpload(db, buildId, uploadId, worker.id);
  if (!row) throw new WorkerProtocolError(404, 'Upload not found');
  assertActiveUpload(row, worker, build, leaseToken);
  try {
    await bucket.resumeMultipartUpload(row.object_key, row.r2_upload_id).abort();
  } catch {
    return storageFailure();
  }
  const timestamp = now();
  try {
    await db.batch([
      db.prepare("UPDATE worker_uploads SET status = 'aborted', completed_at = ? WHERE id = ? AND status = 'active' AND lease_token = ?")
        .bind(timestamp, uploadId, leaseToken),
      db.prepare(`INSERT INTO audit_events(actor, action, target, detail, created_at)
        SELECT ?, 'worker.upload_aborted', ?, ?, ? WHERE changes() = 1`)
        .bind(`worker:${worker.id}`, buildId, JSON.stringify({ uploadId }), timestamp)
    ]);
  } catch {
    return databaseFailure();
  }
  return { ok: true };
}

export function parseUploadStart(value: unknown): StartInput {
  return parseStartInput(value);
}
