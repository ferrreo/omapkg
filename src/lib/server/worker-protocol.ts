import type { Worker, Architecture, Source, Build, Revision } from '../model';
import type { DependencyPlan } from './dependency-plan';
import { revisionImage } from './policy';
import { sha256, now } from './db';
import { error } from '@sveltejs/kit';

export const CLOCK_SKEW_SECONDS = 60;

export const LEASE_SECONDS = 180;

export const ENROLLMENT_TTL_SECONDS = 15 * 60;

export const MAX_JSON_BODY_BYTES = 1024 * 1024;

export const MAX_LOG_BYTES = 64 * 1024;

export const MAX_ARTIFACT_BYTES = 4 * 1024 * 1024 * 1024;

export const MAX_DIRECT_ARTIFACT_BYTES = 100 * 1024 * 1024;

export const MAX_RECIPE_BYTES = 2 * 1024 * 1024;

export const sha256Pattern = /^[0-9a-f]{64}$/;

const imageDigestPattern = /^sha256:[0-9a-f]{64}$/;

const noncePattern = /^[0-9a-f]{32}$/;

export const safeFilenamePattern = /^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}\.pkg\.tar\.zst$/;

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

export interface CandidateBuild extends WorkerLease {
  revision_request_id: string;
  revision_license: string;
  revision_sbom_json: string;
}

export const textEncoder = new TextEncoder();

export function leaseExpiryValue(timestamp: number): string {
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

export function workerMetadataChanged(worker: Worker, metadata: WorkerMetadata): boolean {
  return worker.daemon_version !== metadata.version || worker.runtime !== metadata.runtime ||
    JSON.stringify(storedCapabilities(worker.capabilities_json)) !== JSON.stringify(metadata.capabilities);
}

export async function refreshWorkerMetadata(db: D1Database, worker: Worker, metadata: WorkerMetadata | null, timestamp: number): Promise<void> {
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

export function requireString(value: unknown, field: string, maxLength: number): string {
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

export function requireText(value: unknown, field: string, maxLength: number): string {
  if (typeof value !== 'string' || value.length === 0 || value.length > maxLength || value.includes('\u0000')) {
    throw new WorkerProtocolError(400, `Invalid ${field}`);
  }
  return value;
}

export function requireArchitecture(value: unknown): Architecture {
  if (value !== 'x86_64' && value !== 'aarch64') throw new WorkerProtocolError(400, 'Invalid architecture');
  return value;
}

export function requireLeaseToken(value: unknown): string {
  return requireString(value, 'leaseToken', 128);
}

export function decodeBase64(value: unknown, field: string): Uint8Array {
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

export function encodeBase64(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

export function randomHex(byteLength = 32): string {
  const bytes = new Uint8Array(byteLength);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

export function parseJsonBytes(bytes: Uint8Array): unknown {
  try {
    return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
  } catch {
    throw new WorkerProtocolError(400, 'Invalid JSON');
  }
}

export function requireObject(value: unknown): Record<string, unknown> {
  if (!isRecord(value)) throw new WorkerProtocolError(400, 'JSON body must be an object');
  return value;
}

export function requireExactKeys(value: Record<string, unknown>, allowed: readonly string[]): void {
  const allowedSet = new Set(allowed);
  if (Object.keys(value).some((key) => !allowedSet.has(key))) throw new WorkerProtocolError(400, 'Unexpected request field');
}

export function requireKeys(value: Record<string, unknown>, required: readonly string[]): void {
  if (required.some((key) => !Object.prototype.hasOwnProperty.call(value, key))) throw new WorkerProtocolError(400, 'Missing request field');
}

export function isUniqueConstraint(cause: unknown): boolean {
  return cause instanceof Error && /unique|primary key|constraint/i.test(cause.message);
}

export function databaseFailure(cause: unknown): never {
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

export function sameJson(left: unknown, right: unknown): boolean {
  return JSON.stringify(canonical(left)) === JSON.stringify(canonical(right));
}

function parseJsonColumn(value: string, field: string): unknown {
  try {
    return JSON.parse(value);
  } catch {
    throw new WorkerProtocolError(500, `Reviewed ${field} is invalid`);
  }
}

export function parseSources(value: string): Source[] {
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

export function parseStringArray(value: string, field: string, maxItemLength: number): string[] {
  const parsed = parseJsonColumn(value, field);
  if (!Array.isArray(parsed)) throw new WorkerProtocolError(500, `Reviewed ${field} are invalid`);
  return parsed.map((item) => requireString(item, field.slice(0, -1), maxItemLength));
}

function parseArchitectures(value: string): Architecture[] {
  const parsed = parseJsonColumn(value, 'architectures');
  if (!Array.isArray(parsed) || parsed.length === 0) throw new WorkerProtocolError(500, 'Reviewed architectures are invalid');
  return parsed.map(requireArchitecture);
}

export function parseRevisionForJob(revision: CandidateBuild): {
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

export async function verifyRecipeHash(recipe: string, expected: string): Promise<void> {
  if ((await sha256(recipe)) !== expected) throw new WorkerProtocolError(500, 'Reviewed recipe checksum does not match');
}

export async function verifyEd25519(publicKeyBytes: Uint8Array, message: Uint8Array, signatureBytes: Uint8Array): Promise<boolean> {
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

export async function getBuildForWorker(db: D1Database, buildId: string, workerId: string): Promise<WorkerLease | null> {
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

export async function requireLease(db: D1Database, buildId: string, workerId: string, leaseToken: string): Promise<WorkerLease> {
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

export function workerRouteFailure(cause: unknown): never {
  if (cause instanceof WorkerProtocolError) throw error(cause.status, cause.message);
  throw error(500, 'Worker protocol failure');
}
