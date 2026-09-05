import { error } from '@sveltejs/kit';
import type { Actor, Architecture, Build, Revision, Source, Worker } from '../model';
import { audit, id, now, sha256 } from './db';
import { PolicyError, requireMaintainer, revisionImage } from './policy';
import { archRelationCovers, parsePackageMetadata } from './arch';
import { dependencyPlansEqual, parseDependencyPlan, planDependencies, type DependencyPlan } from './dependency-plan';

export const CLOCK_SKEW_SECONDS = 60;
export const LEASE_SECONDS = 180;
export const ENROLLMENT_TTL_SECONDS = 15 * 60;
export const MAX_JSON_BODY_BYTES = 1024 * 1024;
export const MAX_LOG_BYTES = 64 * 1024;
export const MAX_ARTIFACT_BYTES = 4 * 1024 * 1024 * 1024;
export const MAX_DIRECT_ARTIFACT_BYTES = 100 * 1024 * 1024;
export const MAX_RECIPE_BYTES = 2 * 1024 * 1024;

const sha256Pattern = /^[0-9a-f]{64}$/;
const imageDigestPattern = /^sha256:[0-9a-f]{64}$/;
const noncePattern = /^[0-9a-f]{32}$/;
const safeFilenamePattern = /^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}\.pkg\.tar\.zst$/;

export class WorkerProtocolError extends Error {
  constructor(
    readonly status: number,
    message: string
  ) {
    super(message);
    this.name = 'WorkerProtocolError';
  }
}

export const WORKER_CAPABILITIES = ['offline-oci', 'multipart-upload', 'registry-pull'] as const;
export type WorkerCapability = (typeof WORKER_CAPABILITIES)[number];
const workerVersionPattern = /^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$/;

export interface WorkerMetadata {
  version: string;
  runtime: 'podman' | 'docker';
  capabilities: WorkerCapability[];
}

export interface AuthenticatedWorker {
  worker: Worker;
  timestamp: number;
  nonce: string;
}

export interface EnrollmentInput {
  token: string;
  name: string;
  architecture: Architecture;
  publicKey: string;
  version?: string;
  runtime?: 'podman' | 'docker';
  capabilities?: WorkerCapability[];
}

export interface EnrollmentResult {
  id: string;
  architecture: Architecture;
}

export interface EnrollmentToken {
  token: string;
  expiresAt: number;
}

export interface WorkerJob {
  id: string;
  leaseToken: string;
  leaseExpiresAt: string;
  revisionId: string;
  packageName: string;
  version: string;
  pkgrel?: number;
  architecture: Architecture;
  recipe: string;
  recipeSha256: string;
  sourceDateEpoch: number;
  imageRef: string;
  imageDigest: string;
  sources: Source[];
  dependencies: string[];
  runtimeDependencies?: string[];
  makeDependencies?: string[];
  dependencyPlan?: DependencyPlan;
  smokeCommands: string[];
  surface: 'binary' | 'recipe';
}

export interface CompleteInput {
  leaseToken: string;
  status: 'succeeded' | 'failed';
  installedSize?: number;
  error?: string;
  artifact?: ArtifactReference;
  provenance?: string;
  provenanceSignature?: string;
  smokePassed: boolean;
}

export interface ArtifactReference {
  key: string;
  sha256: string;
  size: number;
  filename: string;
}

export interface WorkerLease extends Build {
  revision_name: string;
  revision_version: string;
  revision_recipe: string;
  revision_recipe_sha256: string;
  revision_manifest_sha256: string;
  revision_sources_json: string;
  revision_dependencies_json: string;
  revision_make_dependencies_json: string | null;
  revision_smoke_commands_json: string;
  revision_architectures_json: string;
  revision_build_images_json: string | null;
  revision_pkgrel: number | null;
  dependency_plan_json: string | null;
  revision_source_date_epoch: number;
  revision_image_digest: string;
  revision_surface: 'binary' | 'recipe';
}

interface CandidateBuild extends WorkerLease {
  revision_request_id: string;
  revision_license: string;
  revision_sbom_json: string;
}

const textEncoder = new TextEncoder();

function leaseExpiryValue(timestamp: number): string {
  return new Date(timestamp * 1000).toISOString();
}

function selectedImage(revision: Pick<Revision, 'build_images_json' | 'image_digest'>, architecture: Architecture): { imageRef: string; imageDigest: string } {
  let imageRef: string;
  try {
    imageRef = revisionImage(revision, architecture);
  } catch {
    throw new WorkerProtocolError(500, 'Reviewed builder image is invalid');
  }
  const imageDigest = imageRef.match(/@(sha256:[0-9a-f]{64})$/)?.[1];
  if (!imageDigest || !imageDigestPattern.test(imageDigest)) throw new WorkerProtocolError(500, 'Reviewed builder image digest is invalid');
  return { imageRef, imageDigest };
}

export function workerImage(build: Pick<WorkerLease, 'revision_build_images_json' | 'revision_image_digest' | 'architecture'>): { imageRef: string; imageDigest: string } {
  return selectedImage({ build_images_json: build.revision_build_images_json, image_digest: build.revision_image_digest }, build.architecture);
}

function storedCapabilities(value: string | null | undefined): WorkerCapability[] {
  if (!value) return [];
  try {
    const parsed: unknown = JSON.parse(value);
    if (!Array.isArray(parsed)) return [];
    return WORKER_CAPABILITIES.filter((capability) => parsed.includes(capability));
  } catch {
    return [];
  }
}

function workerMetadataChanged(worker: Worker, metadata: WorkerMetadata): boolean {
  return worker.daemon_version !== metadata.version || worker.runtime !== metadata.runtime ||
    JSON.stringify(storedCapabilities(worker.capabilities_json)) !== JSON.stringify(metadata.capabilities);
}

async function refreshWorkerMetadata(db: D1Database, worker: Worker, metadata: WorkerMetadata | null, timestamp: number): Promise<void> {
  if (!metadata) return;
  const changed = workerMetadataChanged(worker, metadata);
  try {
    await db.batch([
      db.prepare(`UPDATE workers SET last_seen_at=?,daemon_version=?,runtime=?,capabilities_json=?
        WHERE id=? AND status='active'`)
        .bind(timestamp, metadata.version, metadata.runtime, JSON.stringify(metadata.capabilities), worker.id),
      db.prepare(`INSERT INTO audit_events(actor,action,target,detail,created_at)
        SELECT ?, 'worker.metadata_updated', ?, ?, ? WHERE changes()=1 AND ?=1`)
        .bind(`worker:${worker.id}`, worker.id, JSON.stringify({ version: metadata.version, runtime: metadata.runtime, capabilities: metadata.capabilities }), timestamp, Number(changed))
    ]);
  } catch (cause) {
    return databaseFailure(cause);
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function hasControlCharacters(value: string): boolean {
  return /[\u0000-\u001f\u007f]/.test(value);
}

function requireString(value: unknown, field: string, maxLength: number): string {
  if (typeof value !== 'string' || value.length === 0 || value.length > maxLength || hasControlCharacters(value)) {
    throw new WorkerProtocolError(400, `Invalid ${field}`);
  }
  return value;
}

export function parseWorkerMetadata(value: unknown): WorkerMetadata | null {
  if (!isRecord(value)) throw new WorkerProtocolError(400, 'Invalid worker metadata');
  const fields = ['version', 'runtime', 'capabilities'] as const;
  const present = fields.filter((field) => Object.prototype.hasOwnProperty.call(value, field));
  if (!present.length) return null;
  if (present.length !== fields.length) throw new WorkerProtocolError(400, 'Worker metadata fields must be supplied together');
  if (typeof value.version !== 'string' || !workerVersionPattern.test(value.version)) {
    throw new WorkerProtocolError(400, 'Invalid worker version');
  }
  if (value.runtime !== 'podman' && value.runtime !== 'docker') throw new WorkerProtocolError(400, 'Invalid worker runtime');
  if (!Array.isArray(value.capabilities) || value.capabilities.length > WORKER_CAPABILITIES.length) {
    throw new WorkerProtocolError(400, 'Invalid worker capabilities');
  }
  const capabilities = value.capabilities.map((capability) => {
    if (typeof capability !== 'string' || !WORKER_CAPABILITIES.includes(capability as WorkerCapability)) {
      throw new WorkerProtocolError(400, 'Invalid worker capability');
    }
    return capability as WorkerCapability;
  });
  if (new Set(capabilities).size !== capabilities.length) throw new WorkerProtocolError(400, 'Duplicate worker capability');
  return {
    version: value.version,
    runtime: value.runtime,
    capabilities: WORKER_CAPABILITIES.filter((capability) => capabilities.includes(capability))
  };
}

function requireText(value: unknown, field: string, maxLength: number): string {
  if (typeof value !== 'string' || value.length === 0 || value.length > maxLength || value.includes('\u0000')) {
    throw new WorkerProtocolError(400, `Invalid ${field}`);
  }
  return value;
}

function requireArchitecture(value: unknown): Architecture {
  if (value !== 'x86_64' && value !== 'aarch64') throw new WorkerProtocolError(400, 'Invalid architecture');
  return value;
}

function requireLeaseToken(value: unknown): string {
  return requireString(value, 'leaseToken', 128);
}

function decodeBase64(value: unknown, field: string): Uint8Array {
  if (typeof value !== 'string' || value.length === 0 || value.length % 4 === 1 || !/^[A-Za-z0-9+/]*={0,2}$/.test(value)) {
    throw new WorkerProtocolError(400, `Invalid ${field}`);
  }
  try {
    const decoded = atob(value);
    return Uint8Array.from(decoded, (character) => character.charCodeAt(0));
  } catch {
    throw new WorkerProtocolError(400, `Invalid ${field}`);
  }
}

function encodeBase64(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function randomHex(byteLength = 32): string {
  const bytes = new Uint8Array(byteLength);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

function parseJsonBytes(bytes: Uint8Array): unknown {
  try {
    return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
  } catch {
    throw new WorkerProtocolError(400, 'Invalid JSON');
  }
}

function requireObject(value: unknown): Record<string, unknown> {
  if (!isRecord(value)) throw new WorkerProtocolError(400, 'JSON body must be an object');
  return value;
}

function requireExactKeys(value: Record<string, unknown>, allowed: readonly string[]): void {
  const allowedSet = new Set(allowed);
  if (Object.keys(value).some((key) => !allowedSet.has(key))) throw new WorkerProtocolError(400, 'Unexpected request field');
}

function requireKeys(value: Record<string, unknown>, required: readonly string[]): void {
  if (required.some((key) => !Object.prototype.hasOwnProperty.call(value, key))) throw new WorkerProtocolError(400, 'Missing request field');
}

function isUniqueConstraint(cause: unknown): boolean {
  return cause instanceof Error && /unique|primary key|constraint/i.test(cause.message);
}

function databaseFailure(cause: unknown): never {
  if (cause instanceof WorkerProtocolError) throw cause;
  throw new WorkerProtocolError(500, 'Worker protocol storage failure');
}

function canonical(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonical);
  if (isRecord(value)) {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonical(value[key])]));
  }
  return value;
}

function sameJson(left: unknown, right: unknown): boolean {
  return JSON.stringify(canonical(left)) === JSON.stringify(canonical(right));
}

function parseJsonColumn(value: string, field: string): unknown {
  try {
    return JSON.parse(value);
  } catch {
    throw new WorkerProtocolError(500, `Reviewed ${field} is invalid`);
  }
}

function parseSources(value: string): Source[] {
  const parsed = parseJsonColumn(value, 'sources');
  if (!Array.isArray(parsed) || parsed.length === 0) throw new WorkerProtocolError(500, 'Reviewed sources are invalid');
  return parsed.map((source) => {
    if (!isRecord(source)) throw new WorkerProtocolError(500, 'Reviewed source is invalid');
    const name = requireString(source.name, 'source name', 256);
    const url = requireString(source.url, 'source URL', 2048);
    try {
      if (new URL(url).protocol !== 'https:') throw new Error('not https');
    } catch {
      throw new WorkerProtocolError(500, 'Reviewed source URL is not HTTPS');
    }
    const digest = source.sha256;
    if (typeof digest !== 'string' || !sha256Pattern.test(digest)) {
      throw new WorkerProtocolError(500, 'Reviewed source checksum is invalid');
    }
    return { name, url, sha256: digest };
  });
}

function parseStringArray(value: string, field: string, maxItemLength: number): string[] {
  const parsed = parseJsonColumn(value, field);
  if (!Array.isArray(parsed)) throw new WorkerProtocolError(500, `Reviewed ${field} are invalid`);
  return parsed.map((item) => requireString(item, field.slice(0, -1), maxItemLength));
}

function parseArchitectures(value: string): Architecture[] {
  const parsed = parseJsonColumn(value, 'architectures');
  if (!Array.isArray(parsed) || parsed.length === 0) throw new WorkerProtocolError(500, 'Reviewed architectures are invalid');
  return parsed.map(requireArchitecture);
}

function parseRevisionForJob(revision: CandidateBuild): {
  sources: Source[];
  dependencies: string[];
  runtimeDependencies: string[];
  makeDependencies: string[];
  smokeCommands: string[];
  architectures: Architecture[];
} {
  if (revision.revision_recipe.length === 0 || revision.revision_recipe.length > MAX_RECIPE_BYTES) {
    throw new WorkerProtocolError(500, 'Reviewed recipe is invalid');
  }
  if (!sha256Pattern.test(revision.revision_recipe_sha256)) throw new WorkerProtocolError(500, 'Reviewed recipe checksum is invalid');
  const runtimeDependencies = parseStringArray(revision.revision_dependencies_json, 'dependencies', 256);
  const makeDependencies = parseStringArray(revision.revision_make_dependencies_json ?? '[]', 'build dependencies', 256);
  return {
    sources: parseSources(revision.revision_sources_json),
    dependencies: [...new Set([...runtimeDependencies, ...makeDependencies])],
    runtimeDependencies,
    makeDependencies,
    smokeCommands: parseStringArray(revision.revision_smoke_commands_json, 'smoke commands', 16 * 1024),
    architectures: parseArchitectures(revision.revision_architectures_json)
  };
}

async function verifyRecipeHash(recipe: string, expected: string): Promise<void> {
  if ((await sha256(recipe)) !== expected) throw new WorkerProtocolError(500, 'Reviewed recipe checksum does not match');
}

async function verifyEd25519(publicKeyBytes: Uint8Array, message: Uint8Array, signatureBytes: Uint8Array): Promise<boolean> {
  if (publicKeyBytes.byteLength !== 32 || signatureBytes.byteLength !== 64) return false;
  try {
    const key = await crypto.subtle.importKey('raw', publicKeyBytes as BufferSource, { name: 'Ed25519' }, false, ['verify']);
    return await crypto.subtle.verify({ name: 'Ed25519' }, key, signatureBytes as BufferSource, message as BufferSource);
  } catch {
    return false;
  }
}

function signatureMessage(method: string, pathAndQuery: string, timestamp: string, nonce: string, bodyHash: string): Uint8Array {
  return textEncoder.encode(`${method.toUpperCase()}\n${pathAndQuery}\n${timestamp}\n${nonce}\n${bodyHash}`);
}

/** Read a request body without allocating beyond its protocol limit. */
export async function readBody(request: Request, limit: number): Promise<Uint8Array> {
  const contentLength = request.headers.get('content-length');
  if (contentLength !== null) {
    if (!/^\d+$/.test(contentLength) || Number(contentLength) > limit) throw new WorkerProtocolError(413, 'Request body too large');
  }
  if (!request.body) return new Uint8Array();
  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (true) {
      const result = await reader.read();
      if (result.done) break;
      total += result.value.byteLength;
      if (total > limit) {
        await reader.cancel();
        throw new WorkerProtocolError(413, 'Request body too large');
      }
      chunks.push(result.value);
    }
  } finally {
    reader.releaseLock();
  }
  const body = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return body;
}

export function requireJsonContentType(request: Request): void {
  const contentType = request.headers.get('content-type')?.split(';', 1)[0].trim().toLowerCase();
  if (contentType !== 'application/json') throw new WorkerProtocolError(415, 'Content-Type must be application/json');
}

export function parseJsonRequest(bytes: Uint8Array): Record<string, unknown> {
  return requireObject(parseJsonBytes(bytes));
}

export async function authenticateWorker(
  db: D1Database,
  request: Request,
  pathAndQuery: string,
  body: Uint8Array
): Promise<AuthenticatedWorker> {
  const workerId = request.headers.get('X-OPR-Worker');
  const timestampHeader = request.headers.get('X-OPR-Timestamp');
  const nonce = request.headers.get('X-OPR-Nonce');
  const signatureHeader = request.headers.get('X-OPR-Signature');
  if (!workerId || !timestampHeader || !nonce || !signatureHeader || !/^\d+$/.test(timestampHeader) || !noncePattern.test(nonce)) {
    throw new WorkerProtocolError(401, 'Invalid worker authentication');
  }
  const timestamp = Number(timestampHeader);
  if (!Number.isSafeInteger(timestamp) || Math.abs(now() - timestamp) > CLOCK_SKEW_SECONDS) {
    throw new WorkerProtocolError(401, 'Invalid worker timestamp');
  }
  let worker: Worker | null;
  try {
    worker = await db.prepare('SELECT id, name, architecture, public_key, status, enrolled_at, last_seen_at, daemon_version, runtime, capabilities_json, accepting_jobs, paused_at, removed_at FROM workers WHERE id = ?')
      .bind(workerId).first<Worker>();
  } catch (cause) {
    return databaseFailure(cause);
  }
  if (!worker) throw new WorkerProtocolError(401, 'Invalid worker authentication');
  if (worker.status !== 'active') throw new WorkerProtocolError(403, 'Worker is revoked');
  const publicKey = decodeBase64(worker.public_key, 'worker public key');
  const signature = decodeBase64(signatureHeader, 'worker signature');
  const bodyHash = await sha256(body);
  const valid = await verifyEd25519(publicKey, signatureMessage(request.method, pathAndQuery, timestampHeader, nonce, bodyHash), signature);
  if (!valid) throw new WorkerProtocolError(401, 'Invalid worker signature');
  try {
    await db.batch([
      db.prepare('DELETE FROM worker_nonces WHERE created_at < ?').bind(now() - CLOCK_SKEW_SECONDS * 2),
      db.prepare('INSERT INTO worker_nonces(worker_id, nonce, created_at) VALUES(?,?,?)').bind(worker.id, nonce, now())
    ]);
  } catch (cause) {
    if (isUniqueConstraint(cause)) throw new WorkerProtocolError(409, 'Worker request replayed');
    return databaseFailure(cause);
  }
  return { worker, timestamp, nonce };
}

export async function enrollWorker(db: D1Database, input: unknown): Promise<EnrollmentResult> {
  const enrollment = requireObject(input);
  requireExactKeys(enrollment, ['token', 'name', 'architecture', 'publicKey', 'version', 'runtime', 'capabilities']);
  requireKeys(enrollment, ['token', 'name', 'architecture', 'publicKey']);
  const token = requireString(enrollment.token, 'token', 256);
  const name = requireString(enrollment.name, 'name', 128);
  const architecture = requireArchitecture(enrollment.architecture);
  const publicKeyBytes = decodeBase64(enrollment.publicKey, 'publicKey');
  if (publicKeyBytes.byteLength !== 32) throw new WorkerProtocolError(400, 'publicKey must be a raw Ed25519 key');
  const metadata = parseWorkerMetadata(enrollment);
  const publicKey = encodeBase64(publicKeyBytes);
  const tokenHash = await sha256(token);
  const workerId = id();
  const enrolledAt = now();
  try {
    await db.batch([
      db.prepare('UPDATE enrollment_tokens SET used_at = ?, worker_id = ? WHERE token_hash = ? AND used_at IS NULL AND expires_at > ? AND architecture = ?')
        .bind(enrolledAt, workerId, tokenHash, enrolledAt, architecture),
      db.prepare(`INSERT INTO workers(id, name, architecture, public_key, status, enrolled_at, last_seen_at, daemon_version, runtime, capabilities_json)
        SELECT ?, ?, ?, ?, 'active', ?, ?, ?, ?, ? WHERE changes() = 1`)
        .bind(workerId, name, architecture, publicKey, enrolledAt, enrolledAt, metadata?.version ?? null, metadata?.runtime ?? null, metadata ? JSON.stringify(metadata.capabilities) : null),
      db.prepare(`INSERT INTO audit_events(actor, action, target, detail, created_at)
        SELECT 'worker-enrollment', 'worker.enrolled', ?, ?, ? WHERE changes() = 1`)
        .bind(workerId, JSON.stringify({ architecture, name, ...(metadata ? { version: metadata.version, runtime: metadata.runtime, capabilities: metadata.capabilities } : {}) }), enrolledAt)
    ]);
  } catch (cause) {
    if (isUniqueConstraint(cause)) throw new WorkerProtocolError(409, 'Worker key is already enrolled');
    return databaseFailure(cause);
  }
  let worker: Worker | null;
  try {
    worker = await db.prepare('SELECT id, architecture FROM workers WHERE id = ?').bind(workerId).first<Worker>();
  } catch (cause) {
    return databaseFailure(cause);
  }
  if (!worker) throw new WorkerProtocolError(401, 'Invalid or expired enrollment token');
  return { id: worker.id, architecture: worker.architecture };
}

export async function createEnrollmentToken(
  db: D1Database,
  createdBy: string,
  architecture: Architecture,
  ttlSeconds = ENROLLMENT_TTL_SECONDS
): Promise<EnrollmentToken> {
  const actor = requireString(createdBy, 'createdBy', 256);
  requireArchitecture(architecture);
  if (!Number.isSafeInteger(ttlSeconds) || ttlSeconds < 60 || ttlSeconds > 24 * 60 * 60) {
    throw new WorkerProtocolError(400, 'Invalid enrollment token lifetime');
  }
  const token = randomHex();
  const tokenHash = await sha256(token);
  const expiresAt = now() + ttlSeconds;
  try {
    await db.batch([
      db.prepare('INSERT INTO enrollment_tokens(token_hash, architecture, created_by, expires_at) VALUES(?,?,?,?)')
        .bind(tokenHash, architecture, actor, expiresAt),
      audit(db, actor, 'worker.enrollment_token_created', `enrollment-token:${tokenHash}`, { architecture, expiresAt })
    ]);
  } catch (cause) {
    return databaseFailure(cause);
  }
  return { token, expiresAt };
}

export async function revokeWorker(db: D1Database, actor: string, workerId: string): Promise<Worker> {
  const auditActor = requireString(actor, 'actor', 256);
  const target = requireString(workerId, 'workerId', 128);
  let worker: Worker | null;
  try {
    worker = await db.prepare('SELECT id, name, architecture, public_key, status, enrolled_at, last_seen_at, daemon_version, runtime, capabilities_json, accepting_jobs, paused_at, removed_at FROM workers WHERE id = ?')
      .bind(target).first<Worker>();
  } catch (cause) {
    return databaseFailure(cause);
  }
  if (!worker) throw new WorkerProtocolError(404, 'Worker not found');
  if (worker.status === 'revoked') return worker;
  const timestamp = now();
  try {
    await db.batch([
      db.prepare("UPDATE workers SET status = 'revoked', accepting_jobs=0 WHERE id = ? AND status = 'active'").bind(target),
      db.prepare(`INSERT INTO audit_events(actor, action, target, detail, created_at)
        SELECT ?, 'worker.revoked', ?, ?, ? WHERE changes() = 1`)
        .bind(auditActor, target, JSON.stringify({ workerId: target }), timestamp),
      db.prepare("UPDATE builds SET status = 'queued', worker_id = NULL, lease_token = NULL, lease_expires_at = NULL, error = 'worker revoked', artifact_key = NULL, artifact_sha256 = NULL, artifact_size = NULL, artifact_filename = NULL, installed_size = NULL, dependency_plan_json = NULL, provenance = NULL, provenance_signature = NULL, smoke_passed = 0 WHERE worker_id = ? AND status = 'leased'")
        .bind(target),
      db.prepare(`INSERT INTO audit_events(actor, action, target, detail, created_at)
        SELECT ?, 'worker.leases_requeued', ?, ?, ? WHERE changes() > 0`)
        .bind(auditActor, target, JSON.stringify({ reason: 'worker revoked' }), timestamp)
    ]);
  } catch (cause) {
    return databaseFailure(cause);
  }
  try {
    worker = await db.prepare('SELECT id, name, architecture, public_key, status, enrolled_at, last_seen_at, daemon_version, runtime, capabilities_json, accepting_jobs, paused_at, removed_at FROM workers WHERE id = ?')
      .bind(target).first<Worker>();
  } catch (cause) {
    return databaseFailure(cause);
  }
  if (!worker) throw new WorkerProtocolError(404, 'Worker not found');
  return worker;
}

export async function pauseWorker(db: D1Database, actor: string, workerId: string): Promise<Worker> {
  const auditActor = requireString(actor, 'actor', 256);
  const target = requireString(workerId, 'workerId', 128);
  let worker: Worker | null;
  try {
    worker = await db.prepare('SELECT id, name, architecture, public_key, status, enrolled_at, last_seen_at, daemon_version, runtime, capabilities_json, accepting_jobs, paused_at, removed_at FROM workers WHERE id = ?')
      .bind(target).first<Worker>();
  } catch (cause) {
    return databaseFailure(cause);
  }
  if (!worker) throw new WorkerProtocolError(404, 'Worker not found');
  if (worker.status !== 'active') throw new WorkerProtocolError(409, 'Revoked workers cannot be paused');
  if (worker.accepting_jobs === 0) return worker;
  const timestamp = now();
  try {
    await db.batch([
      db.prepare("UPDATE workers SET accepting_jobs=0,paused_at=? WHERE id=? AND status='active' AND accepting_jobs=1")
        .bind(timestamp, target),
      db.prepare(`INSERT INTO audit_events(actor,action,target,detail,created_at)
        SELECT ?, 'worker.paused', ?, ?, ? WHERE changes()=1`)
        .bind(auditActor, target, JSON.stringify({ acceptingJobs: false, pausedAt: timestamp }), timestamp)
    ]);
  } catch (cause) {
    return databaseFailure(cause);
  }
  try {
    worker = await db.prepare('SELECT id, name, architecture, public_key, status, enrolled_at, last_seen_at, daemon_version, runtime, capabilities_json, accepting_jobs, paused_at, removed_at FROM workers WHERE id = ?')
      .bind(target).first<Worker>();
  } catch (cause) {
    return databaseFailure(cause);
  }
  if (!worker) throw new WorkerProtocolError(404, 'Worker not found');
  return worker;
}

export async function resumeWorker(db: D1Database, actor: string, workerId: string): Promise<Worker> {
  const auditActor = requireString(actor, 'actor', 256);
  const target = requireString(workerId, 'workerId', 128);
  let worker: Worker | null;
  try {
    worker = await db.prepare('SELECT id, name, architecture, public_key, status, enrolled_at, last_seen_at, daemon_version, runtime, capabilities_json, accepting_jobs, paused_at, removed_at FROM workers WHERE id = ?')
      .bind(target).first<Worker>();
  } catch (cause) {
    return databaseFailure(cause);
  }
  if (!worker) throw new WorkerProtocolError(404, 'Worker not found');
  if (worker.status !== 'active') throw new WorkerProtocolError(409, 'Revoked workers cannot resume');
  if (worker.accepting_jobs === 1) return worker;
  const timestamp = now();
  try {
    await db.batch([
      db.prepare("UPDATE workers SET accepting_jobs=1,paused_at=NULL WHERE id=? AND status='active' AND accepting_jobs=0")
        .bind(target),
      db.prepare(`INSERT INTO audit_events(actor,action,target,detail,created_at)
        SELECT ?, 'worker.resumed', ?, ?, ? WHERE changes()=1`)
        .bind(auditActor, target, JSON.stringify({ acceptingJobs: true, resumedAt: timestamp }), timestamp)
    ]);
  } catch (cause) {
    return databaseFailure(cause);
  }
  try {
    worker = await db.prepare('SELECT id, name, architecture, public_key, status, enrolled_at, last_seen_at, daemon_version, runtime, capabilities_json, accepting_jobs, paused_at, removed_at FROM workers WHERE id = ?')
      .bind(target).first<Worker>();
  } catch (cause) {
    return databaseFailure(cause);
  }
  if (!worker) throw new WorkerProtocolError(404, 'Worker not found');
  return worker;
}

export async function archiveWorker(db: D1Database, actor: string, workerId: string): Promise<Worker> {
  const auditActor = requireString(actor, 'actor', 256);
  const target = requireString(workerId, 'workerId', 128);
  let worker: Worker | null;
  try {
    worker = await db.prepare('SELECT id, name, architecture, public_key, status, enrolled_at, last_seen_at, daemon_version, runtime, capabilities_json, accepting_jobs, paused_at, removed_at FROM workers WHERE id = ?')
      .bind(target).first<Worker>();
  } catch (cause) {
    return databaseFailure(cause);
  }
  if (!worker) throw new WorkerProtocolError(404, 'Worker not found');
  if (worker.status !== 'revoked') throw new WorkerProtocolError(409, 'Only revoked workers can be archived');
  if (worker.removed_at !== null) return worker;
  try {
    const activeLease = await db.prepare("SELECT 1 FROM builds WHERE worker_id=? AND status='leased' LIMIT 1").bind(target).first();
    if (activeLease) throw new WorkerProtocolError(409, 'Worker still has an active lease');
  } catch (cause) {
    if (cause instanceof WorkerProtocolError) throw cause;
    return databaseFailure(cause);
  }
  const timestamp = now();
  try {
    await db.batch([
      db.prepare("UPDATE workers SET removed_at=?,accepting_jobs=0 WHERE id=? AND status='revoked' AND removed_at IS NULL")
        .bind(timestamp, target),
      db.prepare(`INSERT INTO audit_events(actor,action,target,detail,created_at)
        SELECT ?, 'worker.archived', ?, ?, ? WHERE changes()=1`)
        .bind(auditActor, target, JSON.stringify({ removedAt: timestamp }), timestamp)
    ]);
  } catch (cause) {
    return databaseFailure(cause);
  }
  try {
    worker = await db.prepare('SELECT id, name, architecture, public_key, status, enrolled_at, last_seen_at, daemon_version, runtime, capabilities_json, accepting_jobs, paused_at, removed_at FROM workers WHERE id = ?')
      .bind(target).first<Worker>();
  } catch (cause) {
    return databaseFailure(cause);
  }
  if (!worker) throw new WorkerProtocolError(404, 'Worker not found');
  return worker;
}

type RetryBuildRow = {
  build_id: string;
  revision_id: string;
  build_status: Build['status'];
  attempt: number;
  request_id: string;
  request_status: string;
  area: string;
  latest_revision_id: string | null;
  area_approved: number;
  security_approved: number;
};

export async function retryBuild(db: D1Database, actor: Actor | null, buildId: string, reason: string): Promise<void> {
  if (typeof buildId !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/.test(buildId)) throw new PolicyError(400, 'Invalid build ID.');
  if (typeof reason !== 'string') throw new PolicyError(400, 'Provide a retry reason, up to 2,000 characters.');
  const cleanReason = reason.replace(/[\u0000\r\n]+/g, ' ').trim();
  if (!cleanReason || cleanReason.length > 2_000) throw new PolicyError(400, 'Provide a retry reason, up to 2,000 characters.');
  const caller = requireMaintainer(actor);
  let row: RetryBuildRow | null;
  try {
    row = await db.prepare(`
      SELECT b.id AS build_id, b.revision_id, b.status AS build_status, b.attempt,
        q.id AS request_id, q.status AS request_status, q.area,
        (SELECT latest.id FROM revisions latest WHERE latest.request_id=r.request_id ORDER BY latest.created_at DESC, latest.rowid DESC LIMIT 1) AS latest_revision_id,
        EXISTS (SELECT 1 FROM approvals a WHERE a.revision_id=r.id AND a.kind='area' AND a.manifest_sha256=r.manifest_sha256 AND a.revoked_at IS NULL) AS area_approved,
        EXISTS (SELECT 1 FROM approvals a WHERE a.revision_id=r.id AND a.kind='security' AND a.manifest_sha256=r.manifest_sha256 AND a.revoked_at IS NULL) AS security_approved
      FROM builds b JOIN revisions r ON r.id=b.revision_id JOIN requests q ON q.id=r.request_id
      WHERE b.id=?`).bind(buildId).first<RetryBuildRow>();
  } catch (cause) {
    return databaseFailure(cause);
  }
  if (!row) throw new PolicyError(404, 'Build not found.');
  requireMaintainer(caller, row.area);
  if (row.build_status !== 'failed' || !['queued', 'building', 'failed'].includes(row.request_status)) throw new PolicyError(409, 'Only a failed build on its current request can be retried.');
  if (row.latest_revision_id !== row.revision_id) throw new PolicyError(409, 'Only the current reviewed revision can be retried.');
  if (row.area_approved !== 1 || row.security_approved !== 1) throw new PolicyError(409, 'Current area and security approvals are required before retry.');
  const timestamp = now();
  try {
    const result = await db.batch([
      db.prepare(`UPDATE requests SET status=CASE WHEN EXISTS (SELECT 1 FROM builds sibling WHERE sibling.revision_id=? AND sibling.id<>? AND sibling.status='leased') THEN 'building' ELSE 'queued' END,updated_at=? WHERE id=? AND status IN ('queued','building','failed')
        AND ?=(SELECT latest.id FROM revisions latest WHERE latest.request_id=? ORDER BY latest.created_at DESC,latest.rowid DESC LIMIT 1)
        AND EXISTS (SELECT 1 FROM builds target WHERE target.id=? AND target.revision_id=? AND target.status='failed')
        AND EXISTS (SELECT 1 FROM approvals a WHERE a.revision_id=? AND a.kind='area' AND a.manifest_sha256=(SELECT manifest_sha256 FROM revisions WHERE id=?) AND a.revoked_at IS NULL)
        AND EXISTS (SELECT 1 FROM approvals a WHERE a.revision_id=? AND a.kind='security' AND a.manifest_sha256=(SELECT manifest_sha256 FROM revisions WHERE id=?) AND a.revoked_at IS NULL)`)
        .bind(row.revision_id, row.build_id, timestamp, row.request_id, row.revision_id, row.request_id, row.build_id, row.revision_id, row.revision_id, row.revision_id, row.revision_id, row.revision_id),
      db.prepare(`UPDATE builds SET status='queued',worker_id=NULL,lease_token=NULL,lease_expires_at=NULL,
          error=NULL,artifact_key=NULL,artifact_sha256=NULL,artifact_size=NULL,artifact_filename=NULL,
          installed_size=NULL,dependency_plan_json=NULL,provenance=NULL,provenance_signature=NULL,
          smoke_passed=0,started_at=NULL,finished_at=NULL
        WHERE changes()=1 AND id=? AND revision_id=? AND status='failed'
          AND EXISTS (SELECT 1 FROM requests q WHERE q.id=? AND q.status IN ('queued','building'))
          AND revision_id=(SELECT latest.id FROM revisions latest WHERE latest.request_id=(SELECT request_id FROM revisions current WHERE current.id=builds.revision_id)
            ORDER BY latest.created_at DESC,latest.rowid DESC LIMIT 1)
          AND EXISTS (SELECT 1 FROM approvals a WHERE a.revision_id=? AND a.kind='area' AND a.manifest_sha256=(SELECT manifest_sha256 FROM revisions WHERE id=?) AND a.revoked_at IS NULL)
          AND EXISTS (SELECT 1 FROM approvals a WHERE a.revision_id=? AND a.kind='security' AND a.manifest_sha256=(SELECT manifest_sha256 FROM revisions WHERE id=?) AND a.revoked_at IS NULL)`)
        .bind(row.build_id, row.revision_id, row.request_id, row.revision_id, row.revision_id, row.revision_id, row.revision_id),
      db.prepare(`INSERT INTO audit_events(actor,action,target,detail,created_at)
        SELECT ?, 'build.retry_requested', ?, ?, ? WHERE changes()=1`)
        .bind(caller.id, row.build_id, JSON.stringify({ requestId: row.request_id, revisionId: row.revision_id, attempt: row.attempt, reason: cleanReason }), timestamp),
    ]);
    if (!result[0]?.meta.changes || !result[1]?.meta.changes) throw new PolicyError(409, 'Build or request changed. Refresh and retry.');
  } catch (cause) {
    if (cause instanceof PolicyError) throw cause;
    return databaseFailure(cause);
  }
}

async function reviewedCandidate(db: D1Database, architecture: Architecture, timestamp: number): Promise<CandidateBuild | null> {
  try {
    return await db.prepare(`
      SELECT b.id, b.revision_id, b.architecture, b.status, b.worker_id, b.lease_token, b.lease_expires_at,
        b.attempt, b.artifact_key, b.artifact_sha256, b.artifact_size, b.artifact_filename, b.installed_size, b.dependency_plan_json,
        b.provenance, b.provenance_signature, b.smoke_passed, b.error, b.created_at, b.started_at, b.finished_at,
        q.name AS revision_name, r.request_id AS revision_request_id, r.version AS revision_version, r.recipe AS revision_recipe,
        r.recipe_sha256 AS revision_recipe_sha256, r.manifest_sha256 AS revision_manifest_sha256,
        r.sources_json AS revision_sources_json, r.dependencies_json AS revision_dependencies_json, r.make_dependencies_json AS revision_make_dependencies_json,
        r.smoke_commands_json AS revision_smoke_commands_json, r.architectures_json AS revision_architectures_json,
        r.build_images_json AS revision_build_images_json, r.pkgrel AS revision_pkgrel, r.source_date_epoch AS revision_source_date_epoch,
        r.image_digest AS revision_image_digest,
        r.surface AS revision_surface, r.license AS revision_license, r.sbom_json AS revision_sbom_json
      FROM builds b
      JOIN revisions r ON r.id = b.revision_id
      JOIN requests q ON q.id = r.request_id
      WHERE b.architecture = ?
        AND q.status IN ('queued', 'building')
        AND r.pr_url IS NOT NULL AND r.commit_sha IS NOT NULL AND length(r.image_digest) > 0
        AND (b.status = 'queued' OR (b.status = 'leased' AND b.lease_expires_at IS NOT NULL AND b.lease_expires_at < ?))
        AND r.id = (SELECT latest.id FROM revisions latest WHERE latest.request_id = r.request_id ORDER BY latest.created_at DESC, latest.rowid DESC LIMIT 1)
        AND EXISTS (SELECT 1 FROM approvals a WHERE a.revision_id = r.id AND a.kind = 'area' AND a.manifest_sha256 = r.manifest_sha256 AND a.revoked_at IS NULL)
        AND EXISTS (SELECT 1 FROM approvals a WHERE a.revision_id = r.id AND a.kind = 'security' AND a.manifest_sha256 = r.manifest_sha256 AND a.revoked_at IS NULL)
      ORDER BY b.created_at ASC, b.id ASC
      LIMIT 1`).bind(architecture, timestamp).first<CandidateBuild>();
  } catch (cause) {
    return databaseFailure(cause);
  }
}

export async function claimJob(
  db: D1Database,
  worker: Worker,
  metadata: WorkerMetadata | null = null,
  dependencyContext?: { ARTIFACTS: R2Bucket; PUBLIC_ORIGIN: string; PACKAGE_SIGNING_FINGERPRINT?: string; SIGNING_FINGERPRINT?: string },
): Promise<WorkerJob | null> {
  const timestamp = now();
  await refreshWorkerMetadata(db, worker, metadata, timestamp);
  const candidate = await reviewedCandidate(db, worker.architecture, timestamp);
  if (!candidate) return null;
  const revision = parseRevisionForJob(candidate);
  await verifyRecipeHash(candidate.revision_recipe, candidate.revision_recipe_sha256);
  const { imageRef, imageDigest } = workerImage(candidate);
  if (!revision.architectures.includes(worker.architecture)) return null;
  if (!sha256Pattern.test(candidate.revision_manifest_sha256)) throw new WorkerProtocolError(500, 'Reviewed manifest checksum is invalid');
  if (candidate.revision_surface !== 'binary' && candidate.revision_surface !== 'recipe') {
    throw new WorkerProtocolError(500, 'Reviewed surface is invalid');
  }
  let dependencyPlan: DependencyPlan | null = null;
  let planDigest: string | null = null;
  let dependencyReleaseIds: string[] = [];
  if (dependencyContext) {
    try {
      const planned = await planDependencies({ DB: db, ...dependencyContext }, {
        architecture: worker.architecture,
        dependencies: revision.runtimeDependencies,
        makeDependencies: revision.makeDependencies,
      });
      dependencyPlan = planned.plan;
      planDigest = planned.digest;
      dependencyReleaseIds = planned.releaseIds;
    } catch (cause) {
      throw new WorkerProtocolError(409, cause instanceof Error ? cause.message : 'OPR dependency plan could not be created');
    }
  }
  const dependencyPlanJSON = dependencyPlan ? JSON.stringify(dependencyPlan) : null;
  const leaseToken = randomHex();
  const leaseExpiresAt = timestamp + LEASE_SECONDS;
  try {
    await db.batch([
      db.prepare(`UPDATE builds AS b SET status = 'leased', worker_id = ?, lease_token = ?, lease_expires_at = ?,
        attempt = attempt + 1, started_at = ?, finished_at = NULL, error = NULL,
        artifact_key = NULL, artifact_sha256 = NULL, artifact_size = NULL, artifact_filename = NULL, installed_size = NULL, dependency_plan_json = ?,
        provenance = NULL, provenance_signature = NULL, smoke_passed = 0
        WHERE id = ? AND architecture = ?
          AND (status = 'queued' OR (status = 'leased' AND lease_expires_at IS NOT NULL AND lease_expires_at < ?))
          AND revision_id = (SELECT latest.id FROM revisions latest WHERE latest.request_id = (SELECT request_id FROM revisions current_revision WHERE current_revision.id = b.revision_id) ORDER BY latest.created_at DESC, latest.rowid DESC LIMIT 1)
          AND EXISTS (SELECT 1 FROM approvals a WHERE a.revision_id = b.revision_id AND a.kind = 'area' AND a.manifest_sha256 = ? AND a.revoked_at IS NULL)
          AND EXISTS (SELECT 1 FROM approvals a WHERE a.revision_id = b.revision_id AND a.kind = 'security' AND a.manifest_sha256 = ? AND a.revoked_at IS NULL)
          AND EXISTS (SELECT 1 FROM revisions r WHERE r.id = b.revision_id AND r.pr_url IS NOT NULL AND r.commit_sha IS NOT NULL AND length(r.image_digest) > 0)
          AND EXISTS (SELECT 1 FROM requests q WHERE q.id = (SELECT request_id FROM revisions WHERE id = b.revision_id) AND q.status IN ('queued', 'building'))
          AND EXISTS (SELECT 1 FROM workers w WHERE w.id = ? AND w.status = 'active' AND w.accepting_jobs = 1 AND w.removed_at IS NULL)`)
        .bind(worker.id, leaseToken, leaseExpiresAt, timestamp, dependencyPlanJSON, candidate.id, worker.architecture, timestamp,
          candidate.revision_manifest_sha256, candidate.revision_manifest_sha256, worker.id),
      db.prepare(`INSERT INTO audit_events(actor, action, target, detail, created_at)
        SELECT ?, 'worker.job_claimed', ?, ?, ? WHERE changes() = 1`)
        .bind(`worker:${worker.id}`, candidate.id, JSON.stringify({
          requestId: candidate.revision_request_id, architecture: worker.architecture, attempt: candidate.attempt + 1, revisionId: candidate.revision_id,
          dependencyPlanSha256: planDigest, dependencyReleaseIds,
          dependencyPlanRefs: dependencyPlan?.packages.map((item) => ({ releaseId: item.releaseId, url: item.url, signatureUrl: item.signatureUrl, sha256: item.sha256, size: item.size })) ?? [],
        }), timestamp),
      db.prepare(`UPDATE requests SET status='building',updated_at=? WHERE id=? AND status='queued'
        AND ?=(SELECT latest.id FROM revisions latest WHERE latest.request_id=requests.id ORDER BY latest.created_at DESC,latest.rowid DESC LIMIT 1)
        AND EXISTS (SELECT 1 FROM builds claimed WHERE claimed.id=? AND claimed.revision_id=? AND claimed.status='leased' AND claimed.worker_id=? AND claimed.lease_token=?)`)
        .bind(timestamp, candidate.revision_request_id, candidate.revision_id, candidate.id, candidate.revision_id, worker.id, leaseToken),
      db.prepare(`INSERT INTO audit_events(actor,action,target,detail,created_at)
        SELECT ?, 'request.building', ?, ?, ? WHERE changes()=1`)
        .bind(`worker:${worker.id}`, candidate.revision_request_id, JSON.stringify({ buildId: candidate.id, revisionId: candidate.revision_id, architecture: worker.architecture, attempt: candidate.attempt + 1 }), timestamp)
    ]);
  } catch (cause) {
    return databaseFailure(cause);
  }
  let claimed: WorkerLease | null;
  try {
      claimed = await db.prepare(`
      SELECT b.id, b.revision_id, b.architecture, b.status, b.worker_id, b.lease_token, b.lease_expires_at,
        b.attempt, b.artifact_key, b.artifact_sha256, b.artifact_size, b.artifact_filename, b.installed_size, b.dependency_plan_json,
        b.provenance, b.provenance_signature, b.smoke_passed, b.error, b.created_at, b.started_at, b.finished_at,
        q.name AS revision_name, r.version AS revision_version, r.recipe AS revision_recipe,
        r.recipe_sha256 AS revision_recipe_sha256, r.manifest_sha256 AS revision_manifest_sha256,
        r.sources_json AS revision_sources_json, r.dependencies_json AS revision_dependencies_json, r.make_dependencies_json AS revision_make_dependencies_json,
        r.smoke_commands_json AS revision_smoke_commands_json, r.architectures_json AS revision_architectures_json,
        r.build_images_json AS revision_build_images_json, r.pkgrel AS revision_pkgrel, r.source_date_epoch AS revision_source_date_epoch,
        r.image_digest AS revision_image_digest,
        r.surface AS revision_surface
      FROM builds b JOIN revisions r ON r.id = b.revision_id JOIN requests q ON q.id = r.request_id
      WHERE b.id = ? AND b.worker_id = ? AND b.lease_token = ? AND b.status = 'leased'
        AND r.id = (SELECT latest.id FROM revisions latest WHERE latest.request_id = r.request_id ORDER BY latest.created_at DESC, latest.rowid DESC LIMIT 1)
        AND EXISTS (SELECT 1 FROM approvals a WHERE a.revision_id = r.id AND a.kind = 'area' AND a.manifest_sha256 = r.manifest_sha256 AND a.revoked_at IS NULL)
        AND EXISTS (SELECT 1 FROM approvals a WHERE a.revision_id = r.id AND a.kind = 'security' AND a.manifest_sha256 = r.manifest_sha256 AND a.revoked_at IS NULL)`).bind(candidate.id, worker.id, leaseToken).first<WorkerLease>();
  } catch (cause) {
    return databaseFailure(cause);
  }
  if (!claimed || !claimed.lease_expires_at) return null;
  let claimedDependencyPlan: DependencyPlan | null = null;
  if (claimed.dependency_plan_json !== null) {
    try { claimedDependencyPlan = parseDependencyPlan(JSON.parse(claimed.dependency_plan_json)); }
    catch { claimedDependencyPlan = null; }
    if (!claimedDependencyPlan) throw new WorkerProtocolError(500, 'Stored OPR dependency plan is invalid');
  }
  return {
    id: claimed.id,
    leaseToken,
    leaseExpiresAt: leaseExpiryValue(claimed.lease_expires_at),
    revisionId: claimed.revision_id,
    packageName: claimed.revision_name,
    version: claimed.revision_version,
    pkgrel: claimed.revision_pkgrel ?? 1,
    architecture: claimed.architecture,
    recipe: claimed.revision_recipe,
    recipeSha256: claimed.revision_recipe_sha256,
    sourceDateEpoch: claimed.revision_source_date_epoch,
    imageRef,
    imageDigest,
    sources: revision.sources,
    dependencies: revision.dependencies,
    runtimeDependencies: revision.runtimeDependencies,
    makeDependencies: revision.makeDependencies,
    ...(claimedDependencyPlan ? { dependencyPlan: claimedDependencyPlan } : {}),
    smokeCommands: revision.smokeCommands,
    surface: claimed.revision_surface
  };
}

async function getBuildForWorker(db: D1Database, buildId: string, workerId: string): Promise<WorkerLease | null> {
  try {
    return await db.prepare(`
      SELECT b.id, b.revision_id, b.architecture, b.status, b.worker_id, b.lease_token, b.lease_expires_at,
        b.attempt, b.artifact_key, b.artifact_sha256, b.artifact_size, b.artifact_filename, b.installed_size, b.dependency_plan_json,
        b.provenance, b.provenance_signature, b.smoke_passed, b.error, b.created_at, b.started_at, b.finished_at,
        q.name AS revision_name, r.version AS revision_version, r.recipe AS revision_recipe,
        r.recipe_sha256 AS revision_recipe_sha256, r.manifest_sha256 AS revision_manifest_sha256,
        r.sources_json AS revision_sources_json, r.dependencies_json AS revision_dependencies_json, r.make_dependencies_json AS revision_make_dependencies_json,
        r.smoke_commands_json AS revision_smoke_commands_json, r.architectures_json AS revision_architectures_json,
        r.build_images_json AS revision_build_images_json, r.pkgrel AS revision_pkgrel, r.source_date_epoch AS revision_source_date_epoch,
        r.image_digest AS revision_image_digest,
        r.surface AS revision_surface
      FROM builds b JOIN revisions r ON r.id = b.revision_id JOIN requests q ON q.id = r.request_id
      WHERE b.id = ? AND b.worker_id = ?
        AND r.id = (SELECT latest.id FROM revisions latest WHERE latest.request_id = r.request_id ORDER BY latest.created_at DESC, latest.rowid DESC LIMIT 1)
        AND EXISTS (SELECT 1 FROM approvals a WHERE a.revision_id = r.id AND a.kind = 'area' AND a.manifest_sha256 = r.manifest_sha256 AND a.revoked_at IS NULL)
        AND EXISTS (SELECT 1 FROM approvals a WHERE a.revision_id = r.id AND a.kind = 'security' AND a.manifest_sha256 = r.manifest_sha256 AND a.revoked_at IS NULL)`).bind(buildId, workerId).first<WorkerLease>();
  } catch (cause) {
    return databaseFailure(cause);
  }
}

async function requireLease(db: D1Database, buildId: string, workerId: string, leaseToken: string): Promise<WorkerLease> {
  const build = await getBuildForWorker(db, buildId, workerId);
  if (!build || build.lease_token !== leaseToken) throw new WorkerProtocolError(409, 'Worker lease is fenced');
  if (build.status !== 'leased' || build.lease_expires_at === null || build.lease_expires_at <= now()) {
    throw new WorkerProtocolError(409, 'Worker lease is expired');
  }
  return build;
}

export async function requireWorkerLease(db: D1Database, worker: Worker, buildId: string, leaseToken: string): Promise<WorkerLease> {
  return requireLease(db, buildId, worker.id, requireLeaseToken(leaseToken));
}

export async function heartbeatJob(
  db: D1Database,
  worker: Worker,
  buildId: string,
  leaseTokenValue: unknown,
  metadata: WorkerMetadata | null = null
): Promise<{ leaseExpiresAt: string | null; cancel: boolean }> {
  const token = requireLeaseToken(leaseTokenValue);
  const build = await getBuildForWorker(db, buildId, worker.id);
  if (!build || build.lease_token !== token) throw new WorkerProtocolError(409, 'Worker lease is fenced');
  if (build.status === 'cancelled') return { leaseExpiresAt: null, cancel: true };
  if (build.status !== 'leased' || build.lease_expires_at === null || build.lease_expires_at <= now()) {
    throw new WorkerProtocolError(409, 'Worker lease is expired');
  }
  const timestamp = now();
  const expiresAt = timestamp + LEASE_SECONDS;
  const metadataChanged = metadata ? workerMetadataChanged(worker, metadata) : false;
  try {
    await db.batch([
      db.prepare(`UPDATE builds SET lease_expires_at = ? WHERE id = ? AND worker_id = ? AND lease_token = ?
        AND status = 'leased' AND lease_expires_at > ?
        AND EXISTS (SELECT 1 FROM workers WHERE id = ? AND status = 'active')`)
        .bind(expiresAt, build.id, worker.id, token, timestamp, worker.id),
      metadata
        ? db.prepare(`UPDATE workers SET last_seen_at=?,daemon_version=?,runtime=?,capabilities_json=?
            WHERE id=? AND status='active' AND changes()=1`)
          .bind(timestamp, metadata.version, metadata.runtime, JSON.stringify(metadata.capabilities), worker.id)
        : db.prepare(`UPDATE workers SET last_seen_at = ? WHERE id = ? AND status = 'active' AND changes() = 1`).bind(timestamp, worker.id),
      db.prepare(`INSERT INTO audit_events(actor, action, target, detail, created_at)
        SELECT ?, 'worker.job_heartbeat', ?, ?, ? WHERE changes() = 1`)
        .bind(`worker:${worker.id}`, build.id, JSON.stringify({ leaseExpiresAt: expiresAt, ...(metadata ? { version: metadata.version, runtime: metadata.runtime, capabilities: metadata.capabilities } : {}) }), timestamp),
      ...(metadata ? [db.prepare(`INSERT INTO audit_events(actor,action,target,detail,created_at)
        SELECT ?, 'worker.metadata_updated', ?, ?, ? WHERE changes()=1 AND ?=1`)
        .bind(`worker:${worker.id}`, worker.id, JSON.stringify({ version: metadata.version, runtime: metadata.runtime, capabilities: metadata.capabilities }), timestamp, Number(metadataChanged))] : [])
    ]);
  } catch (cause) {
    return databaseFailure(cause);
  }
  return { leaseExpiresAt: leaseExpiryValue(expiresAt), cancel: false };
}

export async function appendJobLog(
  db: D1Database,
  worker: Worker,
  buildId: string,
  inputValue: unknown
): Promise<{ sequence: number; duplicate: boolean }> {
  const input = requireObject(inputValue);
  requireExactKeys(input, ['leaseToken', 'sequence', 'text']);
  requireKeys(input, ['leaseToken', 'sequence', 'text']);
  const token = requireLeaseToken(input.leaseToken);
  if (!Number.isSafeInteger(input.sequence) || (input.sequence as number) < 0 || (input.sequence as number) > 0x7fffffff) {
    throw new WorkerProtocolError(400, 'Invalid log sequence');
  }
  const sequence = input.sequence as number;
  const text = requireText(input.text, 'log text', MAX_LOG_BYTES);
  const build = await requireLease(db, buildId, worker.id, token);
  const timestamp = now();
  let inserted = false;
  try {
    const results = await db.batch([
      db.prepare(`INSERT OR IGNORE INTO build_logs(build_id, attempt, sequence, text, created_at)
        SELECT ?, ?, ?, ?, ? WHERE EXISTS (SELECT 1 FROM workers WHERE id = ? AND status = 'active')`)
        .bind(build.id, build.attempt, sequence, text, timestamp, worker.id),
      db.prepare(`INSERT INTO audit_events(actor, action, target, detail, created_at)
        SELECT ?, 'worker.job_log', ?, ?, ? WHERE changes() = 1`)
        .bind(`worker:${worker.id}`, build.id, JSON.stringify({ attempt: build.attempt, sequence }), timestamp)
    ]);
    inserted = Number((results[0] as { meta?: { changes?: number } } | undefined)?.meta?.changes ?? 0) > 0;
  } catch (cause) {
    return databaseFailure(cause);
  }
  let existing: { text: string } | null;
  try {
    existing = await db.prepare('SELECT text FROM build_logs WHERE build_id = ? AND attempt = ? AND sequence = ?')
      .bind(build.id, build.attempt, sequence).first<{ text: string }>();
  } catch (cause) {
    return databaseFailure(cause);
  }
  if (!existing) throw new WorkerProtocolError(500, 'Log append was not persisted');
  if (existing.text !== text) throw new WorkerProtocolError(409, 'Log sequence already contains different text');
  return { sequence, duplicate: !inserted };
}

function requireSafeFilename(value: unknown): string {
  if (typeof value !== 'string' || !safeFilenamePattern.test(value) || value.includes('/') || value.includes('\\')) {
    throw new WorkerProtocolError(400, 'Invalid artifact filename');
  }
  return value;
}

export function validateArtifactFilename(value: unknown): string {
  return requireSafeFilename(value);
}

function artifactMatches(left: ArtifactReference | null, right: ArtifactReference | null): boolean {
  if (!left || !right) return left === right;
  return left.key === right.key && left.sha256 === right.sha256 && left.size === right.size && left.filename === right.filename;
}

export async function uploadArtifact(
  db: D1Database,
  bucket: R2Bucket,
  worker: Worker,
  buildId: string,
  leaseToken: string,
  filenameInput: string,
  body: Uint8Array
): Promise<ArtifactReference> {
  const filename = requireSafeFilename(filenameInput);
  if (body.byteLength > MAX_DIRECT_ARTIFACT_BYTES) throw new WorkerProtocolError(413, 'Artifact too large; use multipart upload');
  const token = requireLeaseToken(leaseToken);
  const build = await requireLease(db, buildId, worker.id, token);
  if (build.revision_surface !== 'binary') throw new WorkerProtocolError(409, 'Recipe builds cannot upload artifacts');
  const digest = await sha256(body);
  const reference: ArtifactReference = {
    key: `private/builds/${build.id}/attempt-${build.attempt}/${digest}-${filename}`,
    sha256: digest,
    size: body.byteLength,
    filename
  };
  const existing = build.artifact_key && build.artifact_sha256 !== null && build.artifact_size !== null && build.artifact_filename
    ? { key: build.artifact_key, sha256: build.artifact_sha256, size: build.artifact_size, filename: build.artifact_filename }
    : null;
  if (existing) {
    if (!artifactMatches(existing, reference)) throw new WorkerProtocolError(409, 'Build already has a different artifact');
    return existing;
  }
  try {
    await bucket.put(reference.key, body, { customMetadata: { buildId: build.id, sha256: digest } });
  } catch {
    throw new WorkerProtocolError(503, 'Artifact storage unavailable');
  }
  const timestamp = now();
  try {
    await db.batch([
      db.prepare(`UPDATE builds SET artifact_key = ?, artifact_sha256 = ?, artifact_size = ?, artifact_filename = ?
        WHERE id = ? AND worker_id = ? AND lease_token = ? AND status = 'leased' AND lease_expires_at > ?
          AND artifact_key IS NULL AND EXISTS (SELECT 1 FROM workers WHERE id = ? AND status = 'active')`)
        .bind(reference.key, reference.sha256, reference.size, reference.filename, build.id, worker.id, token, timestamp, worker.id),
      db.prepare(`INSERT INTO audit_events(actor, action, target, detail, created_at)
        SELECT ?, 'worker.artifact_uploaded', ?, ?, ? WHERE changes() = 1`)
        .bind(`worker:${worker.id}`, build.id, JSON.stringify({ attempt: build.attempt, sha256: digest, size: body.byteLength }), timestamp)
    ]);
  } catch (cause) {
    await bucket.delete(reference.key).catch(() => undefined);
    return databaseFailure(cause);
  }
  const updated = await getBuildForWorker(db, build.id, worker.id);
  const uploaded = updated && updated.artifact_key && updated.artifact_sha256 !== null && updated.artifact_size !== null && updated.artifact_filename
    ? { key: updated.artifact_key, sha256: updated.artifact_sha256, size: updated.artifact_size, filename: updated.artifact_filename }
    : null;
  if (!uploaded) {
    await bucket.delete(reference.key).catch(() => undefined);
    throw new WorkerProtocolError(409, 'Worker lease is fenced');
  }
  if (!artifactMatches(uploaded, reference)) {
    await bucket.delete(reference.key).catch(() => undefined);
    throw new WorkerProtocolError(409, 'Build already has a different artifact');
  }
  return uploaded;
}

function parseArtifactReference(value: unknown): ArtifactReference {
  const object = requireObject(value);
  requireExactKeys(object, ['key', 'sha256', 'size', 'filename']);
  const key = requireString(object.key, 'artifact key', 512);
  const digest = object.sha256;
  if (typeof digest !== 'string' || !sha256Pattern.test(digest)) throw new WorkerProtocolError(400, 'Invalid artifact checksum');
  if (!Number.isSafeInteger(object.size) || (object.size as number) < 0 || (object.size as number) > MAX_ARTIFACT_BYTES) {
    throw new WorkerProtocolError(400, 'Invalid artifact size');
  }
  const filename = requireSafeFilename(object.filename);
  return { key, sha256: digest, size: object.size as number, filename };
}

function parseInstalledSize(value: unknown): number {
  if (!Number.isSafeInteger(value) || (value as number) < 0) throw new WorkerProtocolError(400, 'Invalid installedSize');
  return value as number;
}

function parseCompleteInput(value: unknown): CompleteInput {
  const object = requireObject(value);
  requireExactKeys(object, ['leaseToken', 'status', 'installedSize', 'error', 'artifact', 'provenance', 'provenanceSignature', 'smokePassed']);
  const leaseToken = requireLeaseToken(object.leaseToken);
  if (object.status !== 'succeeded' && object.status !== 'failed') throw new WorkerProtocolError(400, 'Invalid completion status');
  if (typeof object.smokePassed !== 'boolean') throw new WorkerProtocolError(400, 'Invalid smokePassed');
  const result: CompleteInput = { leaseToken, status: object.status, smokePassed: object.smokePassed };
  if (object.installedSize !== undefined) result.installedSize = parseInstalledSize(object.installedSize);
  if (object.error !== undefined && object.error !== null) result.error = requireString(object.error, 'error', 16 * 1024);
  if (object.artifact !== undefined && object.artifact !== null) result.artifact = parseArtifactReference(object.artifact);
  if (object.provenance !== undefined && object.provenance !== null) result.provenance = requireString(object.provenance, 'provenance', 512 * 1024);
  if (object.provenanceSignature !== undefined && object.provenanceSignature !== null) {
    const signature = decodeBase64(object.provenanceSignature, 'provenanceSignature');
    if (signature.byteLength !== 64) throw new WorkerProtocolError(400, 'Invalid provenance signature');
    result.provenanceSignature = object.provenanceSignature as string;
  }
  return result;
}

function parseProvenance(value: string): Record<string, unknown> {
  const parsed = parseJsonBytes(textEncoder.encode(value));
  const object = requireObject(parsed);
  const required = ['buildId', 'revisionId', 'workerId', 'recipeSha256', 'artifactSha256', 'architecture', 'imageDigest', 'sourceDateEpoch', 'sources', 'network', 'startedAt', 'finishedAt'];
  requireExactKeys(object, [...required, 'pkgrel', 'installedSize', 'packageMetadata', 'dependencyPlan']);
  requireKeys(object, required);
  if (object.pkgrel !== undefined && (!Number.isSafeInteger(object.pkgrel) || (object.pkgrel as number) < 1 || (object.pkgrel as number) > 9_999)) {
    throw new WorkerProtocolError(400, 'Invalid provenance pkgrel');
  }
  if (object.installedSize !== undefined) parseInstalledSize(object.installedSize);
  return object;
}

function provenanceTime(value: unknown): number {
  if (typeof value === 'number' && Number.isFinite(value)) return value;
  if (typeof value === 'string') {
    const parsed = Date.parse(value);
    if (!Number.isNaN(parsed)) return parsed;
  }
  throw new WorkerProtocolError(400, 'Invalid provenance timestamp');
}

async function verifyProvenance(
  worker: Worker,
  build: WorkerLease,
  artifact: ArtifactReference | null,
  provenance: string,
  provenanceSignature: string,
  installedSize: number | undefined
): Promise<void> {
  const object = parseProvenance(provenance);
  if (object.buildId !== build.id || object.revisionId !== build.revision_id || object.workerId !== worker.id) {
    throw new WorkerProtocolError(409, 'Provenance does not match worker lease');
  }
  const { imageDigest } = workerImage(build);
  if (object.recipeSha256 !== build.revision_recipe_sha256 || object.architecture !== build.architecture ||
      object.imageDigest !== imageDigest || object.sourceDateEpoch !== build.revision_source_date_epoch || object.network !== 'disabled') {
    throw new WorkerProtocolError(409, 'Provenance does not match reviewed inputs');
  }
  if (object.pkgrel !== undefined && object.pkgrel !== (build.revision_pkgrel ?? 1)) {
    throw new WorkerProtocolError(409, 'Provenance pkgrel does not match reviewed inputs');
  }
  if (object.installedSize !== installedSize) {
    throw new WorkerProtocolError(409, 'Provenance installed size does not match completion');
  }
  if (build.revision_surface === 'binary' || object.packageMetadata !== undefined) {
    const metadata = parsePackageMetadata(object.packageMetadata);
    if (!metadata || metadata.name !== build.revision_name ||
        metadata.fullVersion !== `${build.revision_version}-${build.revision_pkgrel ?? 1}` ||
        metadata.architecture !== build.architecture || metadata.installedSize !== installedSize) {
      throw new WorkerProtocolError(409, 'Package metadata does not match reviewed build');
    }
    const reviewedDependencies = parseStringArray(build.revision_dependencies_json, 'dependencies', 256);
    if (reviewedDependencies.some((reviewed) => !metadata.depends.some((native) => archRelationCovers(native, reviewed)))) {
      throw new WorkerProtocolError(409, 'Package metadata does not contain reviewed dependencies');
    }
  }
  let expectedDependencyPlan: DependencyPlan | null = null;
  if (build.dependency_plan_json !== null) {
    try { expectedDependencyPlan = parseDependencyPlan(JSON.parse(build.dependency_plan_json)); }
    catch { expectedDependencyPlan = null; }
    if (!expectedDependencyPlan) throw new WorkerProtocolError(500, 'Stored OPR dependency plan is invalid');
  }
  let actualDependencyPlan: DependencyPlan | null = null;
  if (object.dependencyPlan !== undefined && object.dependencyPlan !== null) {
    actualDependencyPlan = parseDependencyPlan(object.dependencyPlan);
    if (!actualDependencyPlan) throw new WorkerProtocolError(409, 'Provenance dependency plan is invalid');
  }
  if (!dependencyPlansEqual(expectedDependencyPlan, actualDependencyPlan)) {
    throw new WorkerProtocolError(409, 'Provenance dependency plan does not match lease');
  }
  const sources = parseSources(build.revision_sources_json);
  if (!sameJson(object.sources, sources)) throw new WorkerProtocolError(409, 'Provenance sources do not match reviewed inputs');
  const artifactSha256 = object.artifactSha256;
  if (artifact) {
    if (artifactSha256 !== artifact.sha256) throw new WorkerProtocolError(409, 'Provenance artifact does not match upload');
  } else if (build.revision_surface === 'binary') {
    throw new WorkerProtocolError(409, 'Provenance is missing the uploaded artifact');
  } else if (artifactSha256 !== null && artifactSha256 !== '' && (typeof artifactSha256 !== 'string' || !sha256Pattern.test(artifactSha256))) {
    throw new WorkerProtocolError(409, 'Recipe provenance artifact checksum is invalid');
  }
  if (provenanceTime(object.finishedAt) < provenanceTime(object.startedAt)) {
    throw new WorkerProtocolError(400, 'Invalid provenance time range');
  }
  const publicKey = decodeBase64(worker.public_key, 'worker public key');
  const signature = decodeBase64(provenanceSignature, 'provenance signature');
  if (!(await verifyEd25519(publicKey, textEncoder.encode(provenance), signature))) {
    throw new WorkerProtocolError(401, 'Invalid provenance signature');
  }
}

function storedArtifact(build: WorkerLease): ArtifactReference | null {
  if (!build.artifact_key && build.artifact_sha256 === null && build.artifact_size === null && !build.artifact_filename) return null;
  if (!build.artifact_key || !build.artifact_sha256 || build.artifact_size === null || !build.artifact_filename) {
    throw new WorkerProtocolError(500, 'Stored artifact metadata is incomplete');
  }
  return { key: build.artifact_key, sha256: build.artifact_sha256, size: build.artifact_size, filename: build.artifact_filename };
}

async function verifyStoredArtifact(bucket: R2Bucket, artifact: ArtifactReference): Promise<void> {
  let object: R2Object | null;
  try {
    object = await bucket.head(artifact.key);
  } catch {
    throw new WorkerProtocolError(503, 'Artifact storage unavailable');
  }
  if (!object || object.size !== artifact.size || object.customMetadata?.sha256 !== artifact.sha256) {
    throw new WorkerProtocolError(409, 'Uploaded artifact is unavailable');
  }
}

function terminalCompletionMatches(build: WorkerLease, input: CompleteInput, stored: ArtifactReference | null): boolean {
  if (build.status !== input.status || build.lease_token !== input.leaseToken) return false;
  if (input.status === 'failed') {
    return input.installedSize === undefined && !input.artifact && !input.provenance && !input.provenanceSignature &&
      !input.smokePassed && (build.error ?? undefined) === input.error;
  }
  return input.smokePassed && input.installedSize === (build.installed_size ?? undefined) && artifactMatches(input.artifact ?? null, stored) && build.provenance === input.provenance && build.provenance_signature === input.provenanceSignature;
}

export async function completeJob(
  db: D1Database,
  bucket: R2Bucket,
  worker: Worker,
  buildId: string,
  inputValue: unknown
): Promise<{ status: 'succeeded' | 'failed'; idempotent: boolean }> {
  const input = parseCompleteInput(inputValue);
  if (input.status === 'failed' && (input.installedSize !== undefined || input.artifact || input.provenance || input.provenanceSignature || input.smokePassed)) {
    throw new WorkerProtocolError(400, 'Failed completion contains success evidence');
  }
  const current = await getBuildForWorker(db, buildId, worker.id);
  if (!current || current.lease_token !== input.leaseToken) throw new WorkerProtocolError(409, 'Worker lease is fenced');
  const currentArtifact = storedArtifact(current);
  if (current.status === 'succeeded' || current.status === 'failed') {
    if (terminalCompletionMatches(current, input, currentArtifact)) return { status: current.status, idempotent: true };
    throw new WorkerProtocolError(409, 'Build already completed');
  }
  const build = await requireLease(db, buildId, worker.id, input.leaseToken);
  const artifact = storedArtifact(build);
  if (input.status === 'succeeded') {
    if (!input.smokePassed) throw new WorkerProtocolError(400, 'Successful completion requires smokePassed');
    if (build.revision_surface === 'binary' && input.installedSize === undefined) {
      throw new WorkerProtocolError(400, 'Successful binary completion requires installedSize');
    }
    if (build.revision_surface === 'binary') {
      if (!artifact || !input.artifact || !artifactMatches(input.artifact, artifact)) throw new WorkerProtocolError(409, 'Completion artifact does not match upload');
      await verifyStoredArtifact(bucket, artifact);
    } else if (artifact || input.artifact) {
      throw new WorkerProtocolError(409, 'Recipe completion cannot contain an artifact');
    }
    if (!input.provenance || !input.provenanceSignature) throw new WorkerProtocolError(400, 'Successful completion requires provenance');
    await verifyProvenance(worker, build, artifact, input.provenance, input.provenanceSignature, input.installedSize);
  } else if (input.installedSize !== undefined || input.smokePassed || input.artifact || input.provenance || input.provenanceSignature) {
    throw new WorkerProtocolError(400, 'Failed completion contains success evidence');
  }
  const timestamp = now();
  try {
    const updates = input.status === 'succeeded'
      ? db.prepare(`UPDATE builds SET status = 'succeeded', installed_size = ?, provenance = ?, provenance_signature = ?, smoke_passed = 1,
          finished_at = ?, lease_expires_at = ?
          WHERE id = ? AND worker_id = ? AND lease_token = ? AND status = 'leased' AND lease_expires_at > ?
            AND EXISTS (SELECT 1 FROM workers WHERE id = ? AND status = 'active')`)
          .bind(input.installedSize ?? null, input.provenance, input.provenanceSignature, timestamp, timestamp, build.id, worker.id, input.leaseToken, timestamp, worker.id)
      : db.prepare(`UPDATE builds SET status = 'failed', error = ?, smoke_passed = 0, finished_at = ?, lease_expires_at = ?
          WHERE id = ? AND worker_id = ? AND lease_token = ? AND status = 'leased' AND lease_expires_at > ?
            AND EXISTS (SELECT 1 FROM workers WHERE id = ? AND status = 'active')`)
          .bind(input.error ?? null, timestamp, timestamp, build.id, worker.id, input.leaseToken, timestamp, worker.id);
    const statements: D1PreparedStatement[] = [
      updates,
      db.prepare(`INSERT INTO audit_events(actor, action, target, detail, created_at)
        SELECT ?, ?, ?, ?, ? WHERE changes() = 1`)
        .bind(`worker:${worker.id}`, `worker.job_${input.status}`, build.id, JSON.stringify({ attempt: build.attempt, artifactSha256: artifact?.sha256 ?? null, installedSize: input.installedSize ?? null, smokePassed: input.smokePassed }), timestamp)
    ];
    statements.push(
      db.prepare(`UPDATE requests SET status='failed',updated_at=? WHERE id=(SELECT request_id FROM revisions WHERE id=?)
        AND status IN ('queued','building')
        AND ?=(SELECT latest.id FROM revisions latest WHERE latest.request_id=requests.id ORDER BY latest.created_at DESC,latest.rowid DESC LIMIT 1)
        AND EXISTS (SELECT 1 FROM builds failed WHERE failed.revision_id=? AND failed.status='failed')
        AND NOT EXISTS (SELECT 1 FROM builds active WHERE active.revision_id=? AND active.status IN ('queued','leased'))`)
        .bind(timestamp, build.revision_id, build.revision_id, build.revision_id, build.revision_id),
      db.prepare(`INSERT INTO audit_events(actor,action,target,detail,created_at)
        SELECT ?, 'request.failed', (SELECT request_id FROM revisions WHERE id=?), ?, ? WHERE changes()=1`)
        .bind(`worker:${worker.id}`, build.revision_id, JSON.stringify({ buildId: build.id, revisionId: build.revision_id, attempt: build.attempt, reason: 'build failed' }), timestamp),
    );
    await db.batch(statements);
  } catch (cause) {
    return databaseFailure(cause);
  }
  const completed = await getBuildForWorker(db, build.id, worker.id);
  if (completed && completed.status === input.status && completed.lease_token === input.leaseToken) {
    return { status: input.status, idempotent: false };
  }
  throw new WorkerProtocolError(409, 'Worker lease is fenced');
}

export function workerRouteFailure(cause: unknown): never {
  if (cause instanceof WorkerProtocolError) throw error(cause.status, cause.message);
  throw error(500, 'Worker protocol failure');
}
