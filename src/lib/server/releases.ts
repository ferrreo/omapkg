import { createHash } from 'node:crypto';
import type { Actor, Architecture, Build, Release, Revision } from '../model';
import type { Env } from './env';
import { audit, id, now, query, sha256 } from './db';
import { PolicyError, requireMaintainer, revisionImage, validateRevision } from './policy';
import {
  archRelationCovers,
  isArchPkgver,
  parseArchDependency,
  parseArchRelation,
  parsePackageMetadata,
  satisfiesArchRelation,
  type PackageMetadata,
} from './arch';
import { dependencyPlansEqual, parseDependencyPlan, type DependencyPlan } from './dependency-plan';
import { finalDescription } from './descriptions';

type JoinedBuild = {
  build_id: string;
  build_status: Build['status'];
  build_architecture: Architecture;
  worker_id: string | null;
  artifact_key: string | null;
  artifact_sha256: string | null;
  artifact_size: number | null;
  installed_size: number | null;
  dependency_plan_json: string | null;
  artifact_filename: string | null;
  provenance: string | null;
  package_metadata?: PackageMetadata;
  provenance_signature: string | null;
  smoke_passed: number;
  revision_id: string;
  request_id: string;
  request_name: string;
  request_status: string;
  area: string;
  revision_version: string;
  recipe: string;
  recipe_sha256: string;
  public_recipe?: string | null;
  public_recipe_sha256?: string | null;
  manifest_sha256: string;
  sources_json: string;
  dependencies_json: string;
  make_dependencies_json?: string | null;
  smoke_commands_json: string;
  architectures_json: string;
  build_images_json?: string | null;
  pkgrel?: number | null;
  source_date_epoch: number;
  image_digest: string;
  license: string;
  surface: Revision['surface'];
  description?: string | null;
  explanation: string;
  sbom_json: string;
  lint_json: string;
  upstream_commit: string | null;
  pr_url: string | null;
  commit_sha: string | null;
  upstream_url: string;
};

type RepoRelease = {
  release_id: string;
  build_id: string;
  revision_id: string;
  manifest_sha256: string;
  name: string;
  version: string;
  recipe_sha256: string;
  source_date_epoch: number;
  architecture: Architecture;
  surface: Revision['surface'];
  artifact_key: string;
  artifact_sha256: string;
  artifact_size: number;
  installed_size: number | null;
  artifact_filename: string;
  signature_key: string;
  license: string;
  description?: string | null;
  recipe?: string;
  explanation: string;
  dependencies_json: string;
  upstream_url: string;
  published_at: number;
  provenance: string | null;
  package_metadata?: PackageMetadata;
};

type SignatureResult = { signatureKey: string; signatureSha256: string };
type RepositorySnapshot = { id: string; architecture: Architecture; channel: 'stable' | 'dev'; dbKey: string; dbSignatureKey: string; dbSha256: string; batchId: string };

const PACKAGE_FILENAME = /^[A-Za-z0-9][A-Za-z0-9._+:-]{0,220}\.pkg\.tar\.zst$/;
const SHA256 = /^[a-f0-9]{64}$/;
const BASE64 = /^[A-Za-z0-9+/]+={0,2}$/;
const SAFE_KEY = /^(?!\/)(?!.*(?:^|\/)\.\.(?:\/|$))[\x21-\x7e]{1,1024}$/;
const MCP_RELEASE_ID = /^[A-Za-z0-9_-]{1,128}$/;
const DEFAULT_QUARANTINE_HOURS = 48;
const MAX_PACKAGE_BYTES = 4 * 1024 * 1024 * 1024;

function fail(status: number, message: string): never {
  throw new PolicyError(status, message);
}

function requireReleaseMaintainer(actor: Actor | null): Actor {
  return requireMaintainer(actor);
}

function cleanReason(reason: string): string {
  if (typeof reason !== 'string') fail(400, 'Provide a release reason.');
  const value = reason.replace(/[\u0000\r\n]/g, ' ').trim();
  if (!value || value.length > 2_000) fail(400, 'Provide a reason, up to 2,000 characters.');
  return value;
}

function safeKey(value: string, label = 'object key'): string {
  if (!SAFE_KEY.test(value)) fail(409, `Invalid ${label}.`);
  return value;
}

function safeId(value: string, label = 'release ID'): string {
  if (typeof value !== 'string' || !MCP_RELEASE_ID.test(value)) fail(400, `Invalid ${label}.`);
  return value;
}

function jsonObject(value: string, label: string): Record<string, unknown> {
  try {
    const parsed: unknown = JSON.parse(value);
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) fail(409, `${label} must be a JSON object.`);
    return parsed as Record<string, unknown>;
  } catch (cause) {
    if (cause instanceof PolicyError) throw cause;
    fail(409, `${label} is invalid.`);
  }
}

function jsonArray(value: string, label: string): unknown[] {
  try {
    const parsed: unknown = JSON.parse(value);
    if (!Array.isArray(parsed)) fail(409, `${label} must be a JSON array.`);
    return parsed;
  } catch (cause) {
    if (cause instanceof PolicyError) throw cause;
    fail(409, `${label} is invalid.`);
  }
}

function segment(value: string): string {
  return encodeURIComponent(value).replaceAll('%2F', '%252F');
}

function packageKey(architecture: Architecture, filename: string): string {
  return `packages/${architecture}/${filename}`;
}

function recipeKey(name: string, version: string, architecture: Architecture): string {
  return `recipes/${segment(name)}/${segment(version)}/${architecture}/PKGBUILD`;
}

function recipeAssignment(recipe: string, name: 'pkgname' | 'pkgver' | 'pkgrel'): string {
  const match = recipe.match(new RegExp(`^${name}=([^\\r\\n]+)$`, 'm'));
  if (!match) fail(409, `Reviewed recipe is missing ${name}.`);
  const value = match[1].trim();
  if ((value.startsWith("'") && value.endsWith("'")) || (value.startsWith('"') && value.endsWith('"'))) return value.slice(1, -1);
  return value;
}

function packageVersion(build: JoinedBuild, filename: string | null): string {
  const pkgname = recipeAssignment(build.recipe, 'pkgname');
  const pkgver = recipeAssignment(build.recipe, 'pkgver');
  const pkgrel = recipeAssignment(build.recipe, 'pkgrel');
  const reviewedPkgrel = build.pkgrel ?? Number(pkgrel);
  if (pkgname !== build.request_name || pkgver !== build.revision_version ||
      !Number.isSafeInteger(reviewedPkgrel) || reviewedPkgrel < 1 || reviewedPkgrel > 9_999 || Number(pkgrel) !== reviewedPkgrel ||
      !isArchPkgver(pkgver)) {
    fail(409, 'Reviewed package version metadata does not match the revision.');
  }
  const version = `${pkgver}-${reviewedPkgrel}`;
  if (filename && filename !== `${pkgname}-${version}-${build.build_architecture}.pkg.tar.zst`) {
    fail(409, 'Package filename does not match reviewed pkgname, pkgver, pkgrel and architecture.');
  }
  return version;
}

function fullPackageVersion(version: string, pkgrel: number | null | undefined): string {
  const release = pkgrel ?? 1;
  return version.endsWith(`-${release}`) ? version : `${version}-${release}`;
}

function packageMetadataFromValue(
  value: unknown,
  expected: { name: string; version: string; architecture: Architecture; installedSize: number | null },
): PackageMetadata {
  const metadata = parsePackageMetadata(value);
  if (!metadata || metadata.name !== expected.name || metadata.fullVersion !== expected.version ||
      metadata.architecture !== expected.architecture || expected.installedSize === null || metadata.installedSize !== expected.installedSize) {
    fail(409, 'Native package metadata does not match reviewed build.');
  }
  return metadata;
}

function packageMetadataFromProvenance(
  provenance: string | null,
  expected: { name: string; version: string; architecture: Architecture; installedSize: number | null },
): PackageMetadata {
  if (!provenance) fail(409, 'Build provenance is missing native package metadata.');
  return packageMetadataFromValue(jsonObject(provenance, 'Build provenance').packageMetadata, expected);
}

function storedDependencyPlan(value: string | null | undefined): DependencyPlan | null {
  if (value === null || value === undefined) return null;
  try {
    const plan = parseDependencyPlan(JSON.parse(value));
    if (!plan) fail(409, 'Stored OPR dependency plan is invalid.');
    return plan;
  } catch (cause) {
    if (cause instanceof PolicyError) throw cause;
    fail(409, 'Stored OPR dependency plan is invalid.');
  }
}

function hasPrivateSource(env: Env, sourcesJSON: string): boolean {
  let origin: URL;
  try { origin = new URL(env.PUBLIC_ORIGIN); }
  catch { return false; }
  try {
    return jsonArray(sourcesJSON, 'Source manifest').some((value) => {
      if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
      const url = (value as { url?: unknown }).url;
      if (typeof url !== 'string') return false;
      try {
        const source = new URL(url);
        return source.origin === origin.origin && /^\/sources\/[a-f0-9]{64}\.tar$/.test(source.pathname) && !source.search && !source.hash;
      } catch { return false; }
    });
  } catch { return false; }
}

function hasPrivateSourceReference(env: Env, recipe: string): boolean {
  try {
    const origin = new URL(env.PUBLIC_ORIGIN).origin;
    return recipe.includes(`${origin}/sources/`);
  } catch { return false; }
}

function metadataKey(releaseId: string, type: 'sbom' | 'provenance'): string {
  return `metadata/releases/${releaseId}/${type}.json`;
}

function rollbackKey(releaseId: string): string {
  return `rollback/${releaseId}.json`;
}

function publicOrigin(env: Env): string {
  let value: URL;
  try { value = new URL(env.PUBLIC_ORIGIN); }
  catch { fail(503, 'A public HTTPS origin is required for rollback instructions.'); }
  const local = ['localhost', '127.0.0.1', '[::1]'].includes(value.hostname);
  if ((!local && value.protocol !== 'https:') || (local && value.protocol !== 'https:' && value.protocol !== 'http:') || value.username || value.password || value.search || value.hash) {
    fail(503, 'A public HTTPS origin is required for rollback instructions.');
  }
  return value.toString().replace(/\/$/, '');
}

function textValue(value: unknown, fallback = ''): string {
  return typeof value === 'string' ? value.replace(/[\u0000\r\n]+/g, ' ').trim() : fallback;
}

function base64(value: ArrayBuffer | Uint8Array): string {
  const bytes = value instanceof Uint8Array ? value : new Uint8Array(value);
  let output = '';
  for (let offset = 0; offset < bytes.length; offset += 0x8000) {
    output += String.fromCharCode(...bytes.subarray(offset, offset + 0x8000));
  }
  return btoa(output);
}

function decodeBase64(value: string, expectedBytes: number, label: string): Uint8Array {
  if (!BASE64.test(value) || value.length % 4 === 1) fail(409, `${label} is invalid.`);
  try {
    const bytes = Uint8Array.from(atob(value), (character) => character.charCodeAt(0));
    if (bytes.byteLength !== expectedBytes) fail(409, `${label} has an invalid length.`);
    return bytes;
  } catch {
    fail(409, `${label} is invalid.`);
  }
}

async function recordDenied(env: Env, actor: Actor | null, action: string, target: string, cause: unknown) {
  const detail = { reason: cause instanceof PolicyError ? cause.message : 'request rejected' };
  try {
    await audit(env.DB, actor?.id ?? 'anonymous', action, target, detail).run();
  } catch {
    throw new PolicyError(503, 'Denied action could not be recorded.');
  }
}

async function immutableText(env: Env, key: string, text: string, contentType: string): Promise<string> {
  const bytes = new TextEncoder().encode(text);
  const digest = await sha256(bytes);
  await immutableBytes(env, key, bytes, digest, contentType);
  return key;
}

async function immutableBytes(env: Env, key: string, bytes: Uint8Array, digest: string, contentType: string) {
  safeKey(key);
  if (!SHA256.test(digest)) fail(409, 'Immutable object digest is invalid.');
  const existing = await env.ARTIFACTS.head(key);
  if (existing) {
    await verifyHead(env, key, existing, digest, bytes.byteLength);
    return;
  }
  const result = await env.ARTIFACTS.put(key, bytes, {
    onlyIf: { etagDoesNotMatch: '*' },
    httpMetadata: { contentType, cacheControl: 'public, max-age=31536000, immutable' },
    customMetadata: { sha256: digest },
  });
  if (!result) {
    const raced = await env.ARTIFACTS.head(key);
    if (!raced) fail(503, 'Immutable object publication raced and could not be verified.');
    await verifyHead(env, key, raced, digest, bytes.byteLength);
  }
}

async function verifyHead(env: Env, key: string, object: R2Object, digest: string, size: number) {
  if (object.size !== size) fail(409, `Immutable object ${key} does not match expected size.`);
  const current = await env.ARTIFACTS.get(key);
  if (!current) fail(503, `Immutable object ${key} disappeared during verification.`);
  const bytes = new Uint8Array(await current.arrayBuffer());
  if (bytes.byteLength !== size || await sha256(bytes) !== digest) fail(409, `Immutable object ${key} does not match expected digest.`);
}

async function hashR2Body(body: ReadableStream<Uint8Array>, key: string, maxSize = MAX_PACKAGE_BYTES): Promise<{ sha256: string; size: number }> {
  const hash = createHash('sha256');
  const reader = body.getReader();
  let size = 0;
  try {
    while (true) {
      const next = await reader.read();
      if (next.done) break;
      size += next.value.byteLength;
      if (size > maxSize) {
        await reader.cancel();
        fail(409, `Immutable object ${key} is too large.`);
      }
      hash.update(next.value);
    }
  } finally {
    reader.releaseLock();
  }
  return { sha256: hash.digest('hex'), size };
}

async function verifyR2Object(env: Env, key: string, digest: string, size: number): Promise<void> {
  safeKey(key);
  if (!SHA256.test(digest) || !Number.isSafeInteger(size) || size <= 0 || size > MAX_PACKAGE_BYTES) {
    fail(409, 'Build artifact metadata is invalid.');
  }
  const object = await env.ARTIFACTS.get(key);
  if (!object?.body) fail(409, 'Build artifact is missing from immutable storage.');
  const actual = await hashR2Body(object.body, key);
  if (actual.size !== size) fail(409, 'Build artifact size does not match its attestation.');
  if (actual.sha256 !== digest) fail(409, 'Build artifact digest does not match its attestation.');
}

async function verifySignatureObject(env: Env, key: string): Promise<void> {
  safeKey(key);
  const object = await env.ARTIFACTS.get(key);
  if (!object?.body) fail(409, 'Package signature is missing from immutable storage.');
  const actual = await hashR2Body(object.body, key, 16 * 1024);
  if (actual.size === 0) fail(409, 'Package signature is empty.');
}

async function copyVerifiedObject(env: Env, sourceKey: string, targetKey: string, digest: string, size: number, contentType: string): Promise<void> {
  const sourceHead = await env.ARTIFACTS.head(sourceKey);
  if (!sourceHead) fail(409, 'Build artifact is missing from immutable storage.');
  await verifyR2Object(env, sourceKey, digest, size);
  safeKey(targetKey);
  const existing = await env.ARTIFACTS.head(targetKey);
  if (existing) {
    await verifyR2Object(env, targetKey, digest, size);
    return;
  }
  const source = await env.ARTIFACTS.get(sourceKey, { onlyIf: { etagMatches: sourceHead.etag } });
  if (!source || !('body' in source) || !source.body) fail(409, 'Build artifact disappeared during publication.');
  const result = await env.ARTIFACTS.put(targetKey, source.body, {
    onlyIf: { etagDoesNotMatch: '*' },
    sha256: digest,
    httpMetadata: { contentType, cacheControl: 'public, max-age=31536000, immutable' },
    customMetadata: { sha256: digest },
  });
  if (!result) {
    const raced = await env.ARTIFACTS.head(targetKey);
    if (!raced) fail(503, 'Immutable object publication raced and could not be verified.');
  }
  await verifyR2Object(env, targetKey, digest, size);
}

async function joinedBuild(env: Env, buildId: string): Promise<JoinedBuild> {
  const row = await env.DB.prepare(`
    SELECT b.id AS build_id, b.status AS build_status, b.architecture AS build_architecture,
      b.worker_id, b.artifact_key, b.artifact_sha256, b.artifact_size, b.installed_size, b.dependency_plan_json, b.artifact_filename,
      b.provenance, b.provenance_signature, b.smoke_passed,
      v.*, v.id AS revision_id, v.version AS revision_version,
      v.manifest_sha256, v.sources_json, v.dependencies_json, v.smoke_commands_json,
      v.architectures_json, v.source_date_epoch, v.image_digest, v.license, v.surface,
      v.sbom_json, v.lint_json, v.upstream_commit, v.pr_url, v.commit_sha,
      q.name AS request_name, q.status AS request_status, q.area, q.upstream_url
    FROM builds b
    JOIN revisions v ON v.id = b.revision_id
    JOIN requests q ON q.id = v.request_id
    WHERE b.id=?`).bind(buildId).first<JoinedBuild>();
  if (!row) fail(404, 'Build not found.');
  return row;
}

async function assertAttestation(build: JoinedBuild, env: Env) {
  if (!build.provenance || !build.provenance_signature || !BASE64.test(build.provenance_signature)) {
    fail(409, 'A worker-signed provenance attestation is required.');
  }
  if (!build.worker_id) fail(409, 'A registered worker attestation is required.');
  const worker = await env.DB.prepare('SELECT public_key,status FROM workers WHERE id=?').bind(build.worker_id).first<{ public_key: string; status: 'active' | 'revoked' }>();
  if (!worker || worker.status !== 'active') fail(409, 'The build worker is no longer active.');
  const publicKey = decodeBase64(worker.public_key, 32, 'Worker public key');
  const signature = decodeBase64(build.provenance_signature, 64, 'Provenance signature');
  const provenance = jsonObject(build.provenance, 'Build provenance');
  if (build.surface === 'binary') {
    const metadata = packageMetadataFromValue(provenance.packageMetadata, {
      name: build.request_name,
      version: fullPackageVersion(build.revision_version, build.pkgrel),
      architecture: build.build_architecture,
      installedSize: build.installed_size,
    });
    const reviewedDependencies = jsonArray(build.dependencies_json, 'Dependency manifest');
    if (reviewedDependencies.some((reviewed) => typeof reviewed !== 'string' || !metadata.depends.some((native) => archRelationCovers(native, reviewed)))) {
      fail(409, 'Native package metadata does not contain reviewed dependencies.');
    }
  }
  let imageDigest: string;
  try {
    imageDigest = revisionImage(build, build.build_architecture).split('@').at(-1) ?? build.image_digest;
  } catch (cause) {
    if (cause instanceof PolicyError) throw cause;
    fail(409, 'Builder image is invalid for this architecture.');
  }
  const expected: Array<[string, unknown]> = [
    ['buildId', build.build_id], ['revisionId', build.revision_id], ['workerId', build.worker_id], ['architecture', build.build_architecture],
    ['recipeSha256', build.recipe_sha256], ['imageDigest', imageDigest],
    ['sourceDateEpoch', build.source_date_epoch], ['network', 'disabled'],
  ];
  for (const [field, value] of expected) if (provenance[field] !== value) fail(409, `Build provenance field ${field} does not match reviewed inputs.`);
  if (provenance.pkgrel !== undefined && provenance.pkgrel !== (build.pkgrel ?? 1)) fail(409, 'Build provenance field pkgrel does not match reviewed inputs.');
  if (provenance.artifactSha256 !== build.artifact_sha256 && build.surface === 'binary') {
    fail(409, 'Build provenance artifact digest does not match uploaded bytes.');
  }
  if (build.surface === 'recipe' && provenance.artifactSha256 !== null && typeof provenance.artifactSha256 !== 'string') {
    fail(409, 'Build provenance recipe artifact digest is invalid.');
  }
  let actualDependencyPlan: DependencyPlan | null = null;
  if (provenance.dependencyPlan !== undefined && provenance.dependencyPlan !== null) {
    actualDependencyPlan = parseDependencyPlan(provenance.dependencyPlan);
    if (!actualDependencyPlan) fail(409, 'Build provenance dependency plan is invalid.');
  }
  if (!dependencyPlansEqual(storedDependencyPlan(build.dependency_plan_json), actualDependencyPlan)) {
    fail(409, 'Build provenance dependency plan does not match the lease.');
  }
  const sources = jsonArray(build.sources_json, 'Source manifest');
  if (JSON.stringify(provenance.sources) !== JSON.stringify(sources)) fail(409, 'Build provenance source manifest does not match reviewed inputs.');
  try {
    const key = await crypto.subtle.importKey('raw', publicKey as BufferSource, { name: 'Ed25519' }, false, ['verify']);
    if (!await crypto.subtle.verify('Ed25519', key, signature as BufferSource, new TextEncoder().encode(build.provenance) as BufferSource)) {
      fail(409, 'Worker provenance signature is invalid.');
    }
  } catch (cause) {
    if (cause instanceof PolicyError) throw cause;
    fail(409, 'Worker provenance signature is invalid.');
  }
}

async function assertReviewed(build: JoinedBuild, env: Env) {
  try {
    await validateRevision({
      id: build.revision_id, request_id: build.request_id, version: build.revision_version, recipe: build.recipe,
      recipe_sha256: build.recipe_sha256, public_recipe: build.public_recipe, public_recipe_sha256: build.public_recipe_sha256,
      manifest_sha256: build.manifest_sha256, sources_json: build.sources_json,
      dependencies_json: build.dependencies_json, make_dependencies_json: build.make_dependencies_json, smoke_commands_json: build.smoke_commands_json,
      architectures_json: build.architectures_json, build_images_json: build.build_images_json, pkgrel: build.pkgrel, source_date_epoch: build.source_date_epoch,
      image_digest: build.image_digest, license: build.license, surface: build.surface,
      description: build.description, explanation: '', sbom_json: build.sbom_json, lint_json: build.lint_json,
      upstream_commit: build.upstream_commit, pr_url: build.pr_url, commit_sha: build.commit_sha, created_at: 0,
    });
  } catch (cause) {
    if (cause instanceof PolicyError) throw cause;
    fail(409, 'Reviewed revision integrity check failed.');
  }
  const approvals = await query<{ kind: 'area' | 'security'; manifest_sha256: string }>(
    env.DB, 'SELECT kind,manifest_sha256 FROM approvals WHERE revision_id=? AND revoked_at IS NULL', build.revision_id,
  );
  const kinds = new Set(approvals.filter((approval) => approval.manifest_sha256 === build.manifest_sha256).map((approval) => approval.kind));
  if (!kinds.has('area') || !kinds.has('security')) fail(409, 'Current area and security approvals are required before publication.');
}

async function assertCurrentApprovals(env: Env, revisionId: string, manifestSha256: string) {
  const approvals = await query<{ kind: 'area' | 'security' }>(
    env.DB, 'SELECT kind FROM approvals WHERE revision_id=? AND manifest_sha256=? AND revoked_at IS NULL', revisionId, manifestSha256,
  );
  const kinds = new Set(approvals.map((approval) => approval.kind));
  if (!kinds.has('area') || !kinds.has('security')) fail(409, 'Release revision approvals were revoked; generate a new review.');
}

async function signingRequest(env: Env, input: {
  buildId: string;
  revisionId: string;
  manifestSha256: string;
  objectKey: string;
  objectKind: 'package' | 'database';
  artifactSha256: string;
  artifactSize: number;
  artifactFilename: string;
}): Promise<SignatureResult> {
  if (!env.SIGNER && !env.SIGNER_URL) fail(503, 'Package signing service is not configured; binary publication is blocked.');
  const configured = env as Env & { PACKAGE_SIGNING_FINGERPRINT?: string; SIGNING_FINGERPRINT?: string };
  const intentId = id();
  const createdAt = now();
  const expiresAt = createdAt + 3_600;
  await env.DB.prepare(`INSERT INTO signing_intents
    (id,build_id,revision_id,object_key,object_kind,artifact_sha256,artifact_filename,manifest_sha256,created_at,expires_at,artifact_size,key_fingerprint)
    VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`).bind(
    intentId, input.buildId, input.revisionId, safeKey(input.objectKey), input.objectKind,
    input.artifactSha256, input.artifactFilename, input.manifestSha256, createdAt, expiresAt, input.artifactSize,
    (configured.PACKAGE_SIGNING_FINGERPRINT ?? configured.SIGNING_FINGERPRINT ?? null)?.toLowerCase() ?? null,
  ).run();
  const headers = new Headers({ 'Content-Type': 'application/json' });
  if (env.SIGNER_TOKEN) headers.set('Authorization', `Bearer ${env.SIGNER_TOKEN}`);
  const request = new Request(env.SIGNER_URL ? new URL('/v1/sign', env.SIGNER_URL).toString() : 'https://signer.internal/v1/sign', {
    method: 'POST', headers, body: JSON.stringify({ intentId, ...input }),
  });
  let response: Response;
  try {
    response = env.SIGNER ? await env.SIGNER.fetch(request) : await fetch(request);
  } catch {
    await env.DB.prepare("UPDATE signing_intents SET status='failed' WHERE id=? AND status='pending'").bind(intentId).run();
    fail(503, 'Package signing service could not be reached.');
  }
  if (!response.ok) {
    await env.DB.prepare("UPDATE signing_intents SET status='failed' WHERE id=? AND status='pending'").bind(intentId).run();
    fail(503, `Package signing service rejected request (${response.status}).`);
  }
  let result: Record<string, unknown>;
  try {
    const parsed: unknown = await response.json();
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error('invalid signer response');
    result = parsed as Record<string, unknown>;
  } catch {
    await env.DB.prepare("UPDATE signing_intents SET status='failed' WHERE id=? AND status='pending'").bind(intentId).run();
    fail(503, 'Package signing service returned invalid evidence.');
  }
  const signatureObject = result.signature && typeof result.signature === 'object' && !Array.isArray(result.signature)
    ? result.signature as Record<string, unknown>
    : null;
  const signatureKey = typeof result.signatureKey === 'string' ? result.signatureKey
    : typeof result.signature_key === 'string' ? result.signature_key
    : typeof signatureObject?.key === 'string' ? signatureObject.key : '';
  const signatureSha256 = typeof result.signatureSha256 === 'string' ? result.signatureSha256
    : typeof result.signature_sha256 === 'string' ? result.signature_sha256
    : typeof signatureObject?.sha256 === 'string' ? signatureObject.sha256 : null;
  if (!signatureKey || !SAFE_KEY.test(signatureKey) || !signatureSha256 || !SHA256.test(signatureSha256)) {
    await env.DB.prepare("UPDATE signing_intents SET status='failed' WHERE id=? AND status='pending'").bind(intentId).run();
    fail(503, 'Package signing service returned no immutable signature object.');
  }
  const signature = await env.ARTIFACTS.head(signatureKey);
  if (!signature || (signature.customMetadata?.sha256 !== signatureSha256 && signature.customMetadata?.signatureSha256 !== signatureSha256)) {
    await env.DB.prepare("UPDATE signing_intents SET status='failed' WHERE id=? AND status='pending'").bind(intentId).run();
    fail(503, 'Package signing service did not publish a verifiable signature object.');
  }
  await env.DB.prepare(`UPDATE signing_intents SET status='signed',signature_key=?,signature_sha256=?,consumed_at=?
    WHERE id=? AND status='pending'`).bind(signatureKey, signatureSha256, now(), intentId).run();
  return { signatureKey, signatureSha256 };
}

function signingConfigured(env: Env): boolean {
  return Boolean(env.SIGNER || env.SIGNER_URL);
}

async function loadReleaseByBuild(env: Env, buildId: string): Promise<Release | null> {
  return env.DB.prepare('SELECT * FROM releases WHERE build_id=?').bind(buildId).first<Release>();
}

async function publishBuildInner(env: Env, actor: Actor, buildId: string): Promise<Release> {
  const existing = await loadReleaseByBuild(env, buildId);
  if (existing) return existing;
  const build = await joinedBuild(env, safeId(buildId, 'build ID'));
  if (build.build_status !== 'succeeded' || build.smoke_passed !== 1) fail(409, 'Only a successful build with passing smoke tests can enter quarantine.');
  if (build.surface === 'binary' && !signingConfigured(env)) fail(503, 'Package signing service is not configured; binary publication is blocked.');
  if (!['queued', 'building', 'built'].includes(build.request_status)) fail(409, 'The package request is no longer publishable.');
  await assertReviewed(build, env);
  await assertAttestation(build, env);
  const releaseId = id();
  const publicationBatchId = id();
  const architecture = build.build_architecture;
  let artifact: { key: string; sha256: string; size: number; filename: string } | null = null;
  let signatureKey: string | null = null;
  let releaseVersion: string;
  if (build.surface === 'binary') {
    if (!build.artifact_key || !build.artifact_sha256 || !SHA256.test(build.artifact_sha256) || !build.artifact_size || !build.artifact_filename || !PACKAGE_FILENAME.test(build.artifact_filename)) {
      fail(409, 'A valid immutable package artifact is required for Surface A.');
    }
    releaseVersion = packageVersion(build, build.artifact_filename);
    const publishedKey = packageKey(architecture, build.artifact_filename);
    await copyVerifiedObject(env, build.artifact_key, publishedKey, build.artifact_sha256, build.artifact_size, 'application/octet-stream');
    artifact = { key: publishedKey, sha256: build.artifact_sha256, size: build.artifact_size, filename: build.artifact_filename };
    const signed = await signingRequest(env, {
      buildId: build.build_id, revisionId: build.revision_id, manifestSha256: build.manifest_sha256,
      objectKey: publishedKey, objectKind: 'package', artifactSha256: build.artifact_sha256, artifactSize: build.artifact_size, artifactFilename: build.artifact_filename,
    });
    signatureKey = signed.signatureKey;
  } else if (build.artifact_key || build.artifact_sha256 || build.artifact_size !== null || build.artifact_filename) {
    fail(409, 'Surface B builds must never publish or retain a binary artifact.');
  } else {
    releaseVersion = packageVersion(build, null);
  }

  const releaseRecipe = build.surface === 'recipe' ? build.public_recipe ?? build.recipe : build.recipe;
  if (build.surface === 'recipe' && hasPrivateSource(env, build.sources_json) && !build.public_recipe) {
    fail(409, 'A public recipe is required when reviewed sources use private sealed storage.');
  }
  if (build.surface === 'recipe' && hasPrivateSourceReference(env, releaseRecipe)) {
    fail(409, 'Published recipe cannot reference private sealed storage.');
  }

  const publishedAt = now();
  const recipe = recipeKey(build.request_name, releaseVersion, architecture);
  const sbom = metadataKey(releaseId, 'sbom');
  const provenance = metadataKey(releaseId, 'provenance');
  await immutableText(env, recipe, releaseRecipe, 'text/plain; charset=utf-8');
  await immutableText(env, sbom, build.sbom_json, 'application/json');
  await immutableText(env, provenance, build.provenance!, 'application/json');
  const release: Release = {
    id: releaseId, build_id: build.build_id, name: build.request_name, version: releaseVersion,
    architecture, surface: build.surface, channel: 'dev', artifact_key: artifact?.key ?? null,
    signature_key: signatureKey, recipe_key: recipe, sbom_key: sbom, provenance_key: provenance,
    published_at: publishedAt, stable_at: null, batch_id: null, previous_release_id: null,
  };
  let devCurrent: RepoRelease[] = [];
  const devSnapshot = artifact ? await (async () => {
    const current = await currentDev(env);
    devCurrent = current;
      const candidate: RepoRelease = {
      release_id: release.id, build_id: build.build_id, revision_id: build.revision_id,
      manifest_sha256: build.manifest_sha256, name: build.request_name, version: releaseVersion,
      recipe_sha256: build.recipe_sha256, source_date_epoch: build.source_date_epoch, architecture,
      surface: 'binary', artifact_key: artifact.key, artifact_sha256: artifact.sha256, artifact_size: artifact.size,
      installed_size: build.installed_size,
      artifact_filename: artifact.filename, signature_key: signatureKey!, license: build.license,
      description: finalDescription({ description: build.description, recipe: build.recipe, explanation: build.explanation }, build.request_name),
      explanation: build.explanation, dependencies_json: build.dependencies_json, upstream_url: build.upstream_url,
      published_at: publishedAt, provenance: build.provenance,
      package_metadata: packageMetadataFromProvenance(build.provenance, {
        name: build.request_name, version: releaseVersion, architecture, installedSize: build.installed_size,
      }),
    };
    return snapshot(env, finalDev(current, [candidate]), architecture, candidate, publicationBatchId, 'dev');
  })() : null;
  const statements: D1PreparedStatement[] = [
    env.DB.prepare(`INSERT INTO releases
      (id,build_id,name,version,architecture,surface,channel,artifact_key,signature_key,recipe_key,sbom_key,provenance_key,published_at)
      VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`).bind(
      release.id, release.build_id, release.name, release.version, release.architecture, release.surface,
      release.channel, release.artifact_key, release.signature_key, release.recipe_key, release.sbom_key,
      release.provenance_key, release.published_at,
    ),
    env.DB.prepare(`UPDATE requests SET status=CASE
        WHEN EXISTS (SELECT 1 FROM builds active WHERE active.revision_id=? AND active.status='leased') THEN 'building'
        WHEN EXISTS (SELECT 1 FROM builds queued WHERE queued.revision_id=? AND queued.status='queued') THEN 'queued'
        WHEN EXISTS (SELECT 1 FROM builds failed WHERE failed.revision_id=? AND failed.status='failed') THEN 'failed'
        WHEN EXISTS (
          SELECT 1 FROM json_each((SELECT architectures_json FROM revisions WHERE id=?)) architecture
          WHERE NOT EXISTS (
            SELECT 1 FROM builds complete JOIN releases published ON published.build_id=complete.id
            WHERE complete.revision_id=? AND complete.architecture=architecture.value AND complete.status='succeeded'
          )
        ) THEN 'building'
        ELSE 'built'
      END,updated_at=?
      WHERE id=? AND status IN ('queued','building','built','failed')
        AND ?=(SELECT latest.id FROM revisions latest WHERE latest.request_id=requests.id ORDER BY latest.created_at DESC,latest.rowid DESC LIMIT 1)`)
      .bind(build.revision_id, build.revision_id, build.revision_id, build.revision_id, build.revision_id, publishedAt, build.request_id, build.revision_id),
    env.DB.prepare('INSERT INTO distribution_assertions(expected,actual) SELECT 1,changes()'),
  ];
  if (devSnapshot) {
    statements.push(env.DB.prepare("UPDATE repository_snapshots SET active=0 WHERE channel='dev' AND architecture=? AND active=1").bind(architecture));
    statements.push(env.DB.prepare(`INSERT INTO repository_snapshots
      (id,architecture,channel,db_key,db_signature_key,batch_id,created_at,active) VALUES(?,?,?,?,?,?,?,1)`)
      .bind(devSnapshot.id, devSnapshot.architecture, devSnapshot.channel, devSnapshot.dbKey, devSnapshot.dbSignatureKey, devSnapshot.batchId, now()));
    statements.push(env.DB.prepare("INSERT INTO distribution_assertions(expected,actual) SELECT 1,COUNT(*) FROM repository_snapshots WHERE id=? AND channel='dev' AND architecture=? AND active=1")
      .bind(devSnapshot.id, architecture));
    for (const row of devCurrent) {
      if (row.name !== release.name || row.architecture !== release.architecture) {
        statements.push(env.DB.prepare("INSERT INTO distribution_assertions(expected,actual) SELECT 1,COUNT(*) FROM releases WHERE id=? AND channel='dev'").bind(row.release_id));
      }
    }
    const existingForPackage = devCurrent.filter((row) => row.name === release.name && row.architecture === release.architecture).length;
    statements.push(env.DB.prepare("INSERT INTO distribution_assertions(expected,actual) SELECT ?,COUNT(*) FROM releases WHERE name=? AND architecture=? AND channel='dev'")
      .bind(existingForPackage + 1, release.name, release.architecture));
    statements.push(env.DB.prepare("INSERT INTO distribution_assertions(expected,actual) SELECT ?,COUNT(*) FROM releases WHERE channel='dev' AND surface='binary'")
      .bind(devCurrent.length + 1));
  }
  statements.push(env.DB.prepare('DELETE FROM distribution_assertions'));
  statements.push(audit(env.DB, actor.id, 'release.published_dev', release.id, {
    buildId: build.build_id, surface: build.surface, artifactSha256: artifact?.sha256 ?? null,
    manifestSha256: build.manifest_sha256, channel: 'dev', devSnapshot: devSnapshot ? { id: devSnapshot.id, sha256: devSnapshot.dbSha256 } : null,
  }));
  await env.DB.batch(statements);
  return release;
}

export async function publishBuild(env: Env, actor: Actor | null, buildId: string): Promise<Release> {
  try {
    return await publishBuildInner(env, requireReleaseMaintainer(actor), buildId);
  } catch (cause) {
    if (cause instanceof PolicyError) await recordDenied(env, actor, 'release.publish_denied', buildId, cause);
    throw cause;
  }
}

async function repoRows(env: Env, where: string, ...values: unknown[]): Promise<RepoRelease[]> {
  return query<RepoRelease>(env.DB, `SELECT r.id AS release_id, r.build_id, r.architecture, r.surface, r.name, r.version,
    v.recipe_sha256, v.source_date_epoch,
    r.artifact_key, r.signature_key, b.artifact_sha256, b.artifact_size, b.installed_size, b.artifact_filename,
    b.provenance, b.revision_id, v.manifest_sha256, v.recipe, v.description, v.license, v.explanation, v.dependencies_json, q.upstream_url, r.published_at
    FROM releases r JOIN builds b ON b.id=r.build_id JOIN revisions v ON v.id=b.revision_id JOIN requests q ON q.id=v.request_id
    WHERE ${where}`, ...values);
}

type ReleasePackage = { row: RepoRelease; metadata: PackageMetadata };

function releasePackage(row: RepoRelease): ReleasePackage {
  const metadata = row.package_metadata ?? packageMetadataFromProvenance(row.provenance, {
    name: row.name, version: row.version, architecture: row.architecture, installedSize: row.installed_size,
  });
  return { row, metadata };
}

function relationText(value: unknown, label: string): string {
  if (typeof value !== 'string') fail(409, `${label} contains a non-string relation.`);
  return value;
}

function assertDependencyGraph(candidates: RepoRelease[], current: RepoRelease[], final: RepoRelease[]) {
  const finalPackages = final.filter((row) => row.surface === 'binary').map(releasePackage);
  const knownPackages = [...current, ...candidates].filter((row) => row.surface === 'binary').map(releasePackage);
  const knownNames = new Set<string>();
  for (const { row, metadata } of knownPackages) {
    knownNames.add(row.name);
    for (const value of metadata.provides) {
      const relation = parseArchRelation(value);
      if (relation) knownNames.add(relation.name);
    }
  }
  const providersFor = (architecture: Architecture) => finalPackages.filter((item) => item.row.architecture === architecture);
  const checkDependency = (owner: ReleasePackage, value: unknown, label: string) => {
    const text = relationText(value, label);
    const dependency = parseArchRelation(text);
    if (!dependency) {
      if (label === 'dependency manifest') fail(409, `Invalid Arch dependency constraint ${text}.`);
      fail(409, `Invalid Arch ${label.toLowerCase()} ${text}.`);
    }
    const providers = providersFor(owner.row.architecture);
    if (providers.some((provider) => satisfiesArchRelation(dependency, provider.metadata))) return;
    // Unknown names are supplied by Arch core/extra or another configured base
    // repository. Only fail when OPR previously advertised this capability.
    if (knownNames.has(dependency.name)) {
      const available = providers.flatMap((provider) => {
        if (provider.metadata.name === dependency.name) return [provider.metadata.fullVersion];
        return provider.metadata.provides.flatMap((value) => {
          const provided = parseArchRelation(value);
          return provided?.name === dependency.name ? [provided.version ?? provider.metadata.fullVersion] : [];
        });
      })[0] ?? 'the final package set';
      fail(409, `Dependency ${text} is not satisfied by ${available} for ${owner.row.name} on ${owner.row.architecture}.`);
    }
  };

  for (const owner of finalPackages) {
    for (const value of owner.metadata.depends) checkDependency(owner, value, 'package dependency');
    for (const value of owner.metadata.conflicts) {
      const text = relationText(value, 'Package conflict');
      const conflict = parseArchDependency(text);
      if (!conflict) fail(409, `Invalid Arch package conflict ${text}.`);
      if (providersFor(owner.row.architecture).some((provider) => provider.row.release_id !== owner.row.release_id && satisfiesArchRelation(conflict, provider.metadata))) {
        fail(409, `Package ${owner.row.name} conflicts with ${text} on ${owner.row.architecture}.`);
      }
    }
  }

  for (const candidate of candidates.filter((row) => row.surface === 'binary')) {
    const owner = finalPackages.find((item) => item.row.release_id === candidate.release_id);
    if (!owner) continue;
    for (const value of jsonArray(candidate.dependencies_json, 'Dependency manifest')) {
      const text = relationText(value, 'Dependency manifest');
      checkDependency(owner, text, 'dependency manifest');
      if (!owner.metadata.depends.some((native) => archRelationCovers(native, text))) {
        fail(409, `Native package metadata does not contain reviewed dependency ${text}.`);
      }
    }
    for (const value of owner.metadata.replaces) {
      if (!parseArchDependency(relationText(value, 'Package replacement'))) fail(409, `Invalid Arch package replacement ${String(value)}.`);
    }
  }
}

function octal(value: number, width: number): string {
  return Math.max(0, value).toString(8).padStart(width - 1, '0') + '\0';
}

function checksum(value: number): string {
  return Math.max(0, value).toString(8).padStart(6, '0') + '\0 ';
}

function ascii(target: Uint8Array, offset: number, width: number, value: string) {
  const bytes = new TextEncoder().encode(value);
  if (bytes.length > width) throw new Error('tar field too long');
  target.set(bytes, offset);
}

function tarHeader(path: string, size: number): Uint8Array {
  const header = new Uint8Array(512);
  const split = path.lastIndexOf('/');
  const prefix = split > 0 ? path.slice(0, split) : '';
  const name = split > 0 ? path.slice(split + 1) : path;
  if (name.length > 100 || prefix.length > 155) throw new Error('repository entry path too long');
  ascii(header, 0, 100, name);
  ascii(header, 100, 8, octal(0o644, 8));
  ascii(header, 108, 8, octal(0, 8));
  ascii(header, 116, 8, octal(0, 8));
  ascii(header, 124, 12, octal(size, 12));
  ascii(header, 136, 12, octal(0, 12));
  header.fill(0x20, 148, 156);
  header[156] = 0x30;
  ascii(header, 257, 6, 'ustar\0');
  ascii(header, 263, 2, '00');
  ascii(header, 345, 155, prefix);
  let sum = 0;
  for (const byte of header) sum += byte;
  ascii(header, 148, 8, checksum(sum));
  return header;
}

function tar(entries: Array<{ path: string; body: Uint8Array }>): Uint8Array {
  const size = entries.reduce((total, entry) => total + 512 + Math.ceil(entry.body.length / 512) * 512, 1024);
  const result = new Uint8Array(size);
  let offset = 0;
  for (const entry of entries) {
    result.set(tarHeader(entry.path, entry.body.length), offset);
    offset += 512;
    result.set(entry.body, offset);
    offset += Math.ceil(entry.body.length / 512) * 512;
  }
  return result;
}

async function gzip(bytes: Uint8Array): Promise<Uint8Array> {
  const stream = new CompressionStream('gzip');
  const writer = stream.writable.getWriter();
  await writer.write(bytes as unknown as BufferSource);
  await writer.close();
  return new Uint8Array(await new Response(stream.readable).arrayBuffer());
}

function field(name: string, values: string | string[]): string {
  const list = Array.isArray(values) ? values : [values];
  return `%${name}%\n${list.filter(Boolean).join('\n')}\n\n`;
}

async function repositoryDatabase(env: Env, rows: RepoRelease[]): Promise<Uint8Array> {
  const entries: Array<{ path: string; body: Uint8Array }> = [];
  for (const row of [...rows].sort((a, b) => `${a.name}-${a.version}-${a.architecture}`.localeCompare(`${b.name}-${b.version}-${b.architecture}`))) {
    if (!row.artifact_filename || !PACKAGE_FILENAME.test(row.artifact_filename) || !SHA256.test(row.artifact_sha256) || !Number.isSafeInteger(row.artifact_size) || row.artifact_size < 1) {
      fail(409, `Release ${row.release_id} has incomplete artifact metadata.`);
    }
    const signature = await env.ARTIFACTS.get(row.signature_key);
    if (!signature) fail(409, `Release ${row.release_id} has no package signature.`);
    const signatureBytes = new Uint8Array(await signature.arrayBuffer());
    if (!signatureBytes.length || signatureBytes.length > 16_384) fail(409, `Release ${row.release_id} has invalid package signature.`);
    if (row.installed_size !== null && (!Number.isSafeInteger(row.installed_size) || row.installed_size < 1)) {
      fail(409, `Release ${row.release_id} has invalid installed package size.`);
    }
    const packageDir = `${row.name}-${row.version}`;
    const metadata = row.package_metadata ?? packageMetadataFromProvenance(row.provenance, {
      name: row.name, version: row.version, architecture: row.architecture, installedSize: row.installed_size,
    });
    const desc = [
      field('FILENAME', row.artifact_filename), field('NAME', row.name), field('BASE', row.name), field('VERSION', row.version),
      field('DESC', finalDescription(row, row.name)), field('CSIZE', String(row.artifact_size)),
      row.installed_size === null ? '' : field('ISIZE', String(row.installed_size)),
      field('SHA256SUM', row.artifact_sha256), field('PGPSIG', base64(signatureBytes)), field('URL', row.upstream_url),
      field('LICENSE', textValue(row.license, 'unknown')), field('ARCH', row.architecture), field('BUILDDATE', String(row.source_date_epoch)),
      field('PACKAGER', 'omapkg'), metadata.depends.length ? field('DEPENDS', metadata.depends) : '',
      metadata.provides.length ? field('PROVIDES', metadata.provides) : '',
      metadata.conflicts.length ? field('CONFLICTS', metadata.conflicts) : '',
      metadata.replaces.length ? field('REPLACES', metadata.replaces) : '',
    ].join('');
    entries.push({ path: `${packageDir}/desc`, body: new TextEncoder().encode(desc) });
  }
  return gzip(tar(entries));
}

async function currentStable(env: Env): Promise<RepoRelease[]> {
  return repoRows(env, "r.channel='stable' AND r.surface='binary'");
}

async function currentDev(env: Env): Promise<RepoRelease[]> {
  return repoRows(env, "r.channel='dev' AND r.surface='binary'");
}

function finalStable(current: RepoRelease[], candidates: RepoRelease[]): RepoRelease[] {
  const replaced = new Set(candidates.map((row) => `${row.name}:${row.architecture}`));
  return [...current.filter((row) => !replaced.has(`${row.name}:${row.architecture}`)), ...candidates.filter((row) => row.artifact_key !== null)];
}

function latestPerPackage(rows: RepoRelease[]): RepoRelease[] {
  const latest = new Map<string, RepoRelease>();
  for (const row of [...rows].sort((left, right) => left.published_at - right.published_at || left.release_id.localeCompare(right.release_id))) {
    latest.set(`${row.name}:${row.architecture}`, row);
  }
  return [...latest.values()];
}

function finalDev(current: RepoRelease[], candidates: RepoRelease[]): RepoRelease[] {
  const replaced = new Set(candidates.map((row) => `${row.name}:${row.architecture}`));
  return [
    ...latestPerPackage(current.filter((row) => !replaced.has(`${row.name}:${row.architecture}`))),
    ...candidates.filter((row) => row.artifact_key !== null),
  ];
}

async function snapshot(env: Env, rows: RepoRelease[], architecture: Architecture, context: RepoRelease, batchId: string, channel: 'stable' | 'dev' = 'stable') {
  const database = await repositoryDatabase(env, rows.filter((row) => row.architecture === architecture));
  const digest = await sha256(database);
  const dbKey = `repo/${channel}/${architecture}/${batchId}/opr.db.tar.gz`;
  await immutableBytes(env, dbKey, database, digest, 'application/gzip');
  const signed = await signingRequest(env, {
    buildId: context.build_id, revisionId: context.revision_id, manifestSha256: context.manifest_sha256,
    objectKey: dbKey, objectKind: 'database', artifactSha256: digest, artifactSize: database.byteLength, artifactFilename: 'opr.db.tar.gz',
  });
  return { id: id(), architecture, channel, dbKey, dbSignatureKey: signed.signatureKey, dbSha256: digest, batchId };
}

async function promoteBatchInner(env: Env, actor: Actor, releaseIds: string[], reason: string) {
  const clean = cleanReason(reason);
  const ids = [...new Set(releaseIds.map((value) => safeId(value)))];
  if (!ids.length || ids.length > 100) fail(400, 'Select between one and 100 releases.');
  const placeholders = ids.map(() => '?').join(',');
  const candidateRows = await query<RepoRelease & { channel: string; surface: string; smoke_passed: number; build_status: string; dependencies_json: string; request_status: string; latest_revision_id: string | null }>(
    env.DB, `SELECT r.id AS release_id, r.build_id, r.name, r.version, r.architecture, r.surface, r.channel,
      b.status AS build_status, b.smoke_passed, r.artifact_key, r.signature_key, b.artifact_sha256, b.artifact_size, b.installed_size,
      b.artifact_filename, b.provenance, b.revision_id, v.manifest_sha256, v.recipe, v.description, v.recipe_sha256, v.source_date_epoch, v.license, v.explanation, v.dependencies_json, q.upstream_url,
      q.status AS request_status,
      (SELECT latest.id FROM revisions latest WHERE latest.request_id=v.request_id ORDER BY latest.created_at DESC, latest.rowid DESC LIMIT 1) AS latest_revision_id,
      r.published_at
      FROM releases r JOIN builds b ON b.id=r.build_id JOIN revisions v ON v.id=b.revision_id JOIN requests q ON q.id=v.request_id
      WHERE r.id IN (${placeholders})`, ...ids,
  );
  if (candidateRows.length !== ids.length) fail(404, 'One or more releases were not found.');
  const seen = new Set<string>();
  for (const row of candidateRows) {
    if (row.channel !== 'dev') fail(409, `Release ${row.release_id} is not in quarantine.`);
    if (!['queued', 'building', 'built'].includes(row.request_status) || row.latest_revision_id !== row.revision_id) fail(409, `Release ${row.release_id} is no longer the current reviewed revision.`);
    await assertCurrentApprovals(env, row.revision_id, row.manifest_sha256);
    if (row.surface === 'recipe') {
      const evidence = await joinedBuild(env, row.build_id);
      if (evidence.revision_id !== row.revision_id) fail(409, `Release ${row.release_id} build evidence changed.`);
      await assertAttestation(evidence, env);
    }
    const key = `${row.name}:${row.architecture}`;
    if (seen.has(key)) fail(409, `Batch contains multiple versions of ${row.name} for ${row.architecture}.`);
    seen.add(key);
    if (row.build_status !== 'succeeded' || row.smoke_passed !== 1) fail(409, `Release ${row.release_id} has not passed build and smoke gates.`);
    const quarantineHours = Number((env as Env & { QUARANTINE_HOURS?: string }).QUARANTINE_HOURS ?? DEFAULT_QUARANTINE_HOURS);
    const hours = Number.isFinite(quarantineHours) && quarantineHours >= 0 ? quarantineHours : DEFAULT_QUARANTINE_HOURS;
    if (row.published_at + Math.floor(hours * 3_600) > now()) fail(409, `Release ${row.release_id} is still in quarantine.`);
    const crash = await env.DB.prepare('SELECT COUNT(*) AS count FROM crash_reports WHERE release_id=? AND resolved_at IS NULL').bind(row.release_id).first<{ count: number }>();
    if ((crash?.count ?? 0) > 0) fail(409, `Release ${row.release_id} has unresolved crash reports.`);
    if (row.surface === 'binary' && (!row.artifact_key || !row.signature_key)) fail(409, `Release ${row.release_id} has no package signature.`);
    if (row.surface === 'recipe' && (row.artifact_key || row.signature_key)) fail(409, `Surface B release ${row.release_id} contains a binary artifact.`);
  }
  const current = await currentStable(env);
  const batchId = id();
  const candidates = candidateRows as RepoRelease[];
  const final = finalStable(current, candidates);
  assertDependencyGraph(candidates, current, final);
  const candidateKeys = new Set(candidates.map((row) => `${row.name}:${row.architecture}`));
  const architectures = [...new Set([
    ...candidates.filter((row) => row.surface === 'binary').map((row) => row.architecture),
    ...current.filter((row) => candidateKeys.has(`${row.name}:${row.architecture}`)).map((row) => row.architecture),
  ])] as Architecture[];
  const snapshots = [];
  for (const architecture of architectures) {
    const context = final.find((row) => row.architecture === architecture)
      ?? current.find((row) => row.architecture === architecture)
      ?? candidates.find((row) => row.surface === 'binary' && row.architecture === architecture);
    if (!context) fail(409, `No signed repository context for ${architecture}.`);
    snapshots.push(await snapshot(env, final, architecture, context, batchId));
  }
  const devCurrent = await currentDev(env);
  const devFinal = latestPerPackage(devCurrent.filter((row) => !candidateKeys.has(`${row.name}:${row.architecture}`)));
  const devArchitectures = [...new Set([
    ...candidates.filter((row) => row.surface === 'binary').map((row) => row.architecture),
    ...devCurrent.filter((row) => candidateKeys.has(`${row.name}:${row.architecture}`)).map((row) => row.architecture),
    ...current.filter((row) => candidateKeys.has(`${row.name}:${row.architecture}`)).map((row) => row.architecture),
  ])] as Architecture[];
  const devSnapshots = [];
  for (const architecture of devArchitectures) {
    const context = devFinal.find((row) => row.architecture === architecture)
      ?? candidates.find((row) => row.surface === 'binary' && row.architecture === architecture)
      ?? devCurrent.find((row) => row.architecture === architecture)
      ?? current.find((row) => row.architecture === architecture);
    if (!context) fail(409, `No signed development repository context for ${architecture}.`);
    devSnapshots.push(await snapshot(env, devFinal, architecture, context, batchId, 'dev'));
  }
  const statements: D1PreparedStatement[] = [];
  for (const row of candidateRows) {
    const previous = current.find((item) => item.name === row.name && item.architecture === row.architecture);
    if (previous) {
      statements.push(env.DB.prepare("UPDATE releases SET channel='withdrawn',batch_id=? WHERE id=? AND channel='stable'").bind(batchId, previous.release_id));
      statements.push(env.DB.prepare('INSERT INTO distribution_assertions(expected,actual) SELECT 1,changes()'));
    }
    statements.push(env.DB.prepare("UPDATE releases SET channel='stable',stable_at=?,batch_id=?,previous_release_id=? WHERE id=? AND channel='dev'")
      .bind(now(), batchId, previous?.release_id ?? null, row.release_id));
    statements.push(env.DB.prepare('INSERT INTO distribution_assertions(expected,actual) SELECT 1,changes()'));
  }
  for (const item of snapshots) {
    statements.push(env.DB.prepare("UPDATE repository_snapshots SET active=0 WHERE channel='stable' AND architecture=? AND active=1").bind(item.architecture));
    statements.push(env.DB.prepare(`INSERT INTO repository_snapshots
      (id,architecture,channel,db_key,db_signature_key,batch_id,created_at,active) VALUES(?,?,?,?,?,?,?,1)`)
      .bind(item.id, item.architecture, item.channel, item.dbKey, item.dbSignatureKey, item.batchId, now()));
  }
  for (const item of devSnapshots) {
    statements.push(env.DB.prepare("UPDATE repository_snapshots SET active=0 WHERE channel='dev' AND architecture=? AND active=1").bind(item.architecture));
    statements.push(env.DB.prepare(`INSERT INTO repository_snapshots
      (id,architecture,channel,db_key,db_signature_key,batch_id,created_at,active) VALUES(?,?,?,?,?,?,?,1)`)
      .bind(item.id, item.architecture, item.channel, item.dbKey, item.dbSignatureKey, item.batchId, now()));
    statements.push(env.DB.prepare("INSERT INTO distribution_assertions(expected,actual) SELECT 1,COUNT(*) FROM repository_snapshots WHERE id=? AND channel='dev' AND architecture=? AND active=1")
      .bind(item.id, item.architecture));
  }
  statements.push(env.DB.prepare('INSERT INTO promotion_batches(id,actor,release_ids_json,reason,created_at) VALUES(?,?,?,?,?)')
    .bind(batchId, actor.id, JSON.stringify(ids), clean, now()));
  statements.push(env.DB.prepare(`INSERT INTO distribution_assertions(expected,actual)
    SELECT ?,COUNT(*) FROM releases WHERE id IN (${placeholders}) AND channel='stable' AND batch_id=?`)
    .bind(candidateRows.length, ...ids, batchId));
  for (const row of current) {
    if (!candidateKeys.has(`${row.name}:${row.architecture}`)) {
      statements.push(env.DB.prepare("INSERT INTO distribution_assertions(expected,actual) SELECT 1,COUNT(*) FROM releases WHERE id=? AND channel='stable'").bind(row.release_id));
    }
  }
  for (const row of candidates) {
    statements.push(env.DB.prepare("INSERT INTO distribution_assertions(expected,actual) SELECT 1,COUNT(*) FROM releases WHERE id=? AND channel='stable' AND batch_id=?")
      .bind(row.release_id, batchId));
  }
  for (const row of candidates) {
    statements.push(env.DB.prepare("INSERT INTO distribution_assertions(expected,actual) SELECT 0,COUNT(*) FROM releases WHERE id=? AND channel='dev'").bind(row.release_id));
  }
  for (const row of devCurrent) {
    if (!candidateKeys.has(`${row.name}:${row.architecture}`)) {
      statements.push(env.DB.prepare("INSERT INTO distribution_assertions(expected,actual) SELECT 1,COUNT(*) FROM releases WHERE id=? AND channel='dev'").bind(row.release_id));
    }
  }
  const replacedCount = current.filter((row) => candidateKeys.has(`${row.name}:${row.architecture}`)).length;
  const binaryCount = candidates.filter((row) => row.surface === 'binary').length;
  statements.push(env.DB.prepare(`INSERT INTO distribution_assertions(expected,actual)
    SELECT ?,COUNT(*) FROM releases WHERE channel='stable' AND surface='binary'`)
    .bind(current.length - replacedCount + binaryCount));
  const devReplacedCount = devCurrent.filter((row) => candidateKeys.has(`${row.name}:${row.architecture}`)).length;
  statements.push(env.DB.prepare(`INSERT INTO distribution_assertions(expected,actual)
    SELECT ?,COUNT(*) FROM releases WHERE channel='dev' AND surface='binary'`)
    .bind(devCurrent.length - devReplacedCount));
  statements.push(env.DB.prepare('DELETE FROM distribution_assertions'));
  statements.push(audit(env.DB, actor.id, 'release.batch_promoted', batchId, {
    releaseIds: ids, reason: clean,
    snapshots: snapshots.map((item) => ({ id: item.id, sha256: item.dbSha256 })),
    devSnapshots: devSnapshots.map((item) => ({ id: item.id, sha256: item.dbSha256 })),
  }));
  const result = await env.DB.batch(statements);
  if (!result.length) fail(503, 'Release batch transaction returned no result.');
  return { batchId, releaseIds: ids, snapshots };
}

export async function promoteBatch(env: Env, actor: Actor | null, releaseIds: string[], reason: string) {
  try {
    return await promoteBatchInner(env, requireReleaseMaintainer(actor), releaseIds, reason);
  } catch (cause) {
    if (cause instanceof PolicyError) await recordDenied(env, actor, 'release.batch_promote_denied', 'batch', cause);
    throw cause;
  }
}

async function rollbackInner(env: Env, actor: Actor, releaseId: string, reason: string) {
  const clean = cleanReason(reason);
  const target = await env.DB.prepare(`SELECT r.*, b.id AS build_id, b.artifact_sha256, b.artifact_size, b.installed_size, b.artifact_filename, b.provenance,
    v.id AS revision_id, v.manifest_sha256, v.recipe, v.description, v.recipe_sha256, v.dependencies_json, v.license, v.explanation, q.upstream_url
    FROM releases r JOIN builds b ON b.id=r.build_id JOIN revisions v ON v.id=b.revision_id JOIN requests q ON q.id=v.request_id
    WHERE r.id=?`).bind(safeId(releaseId)).first<Release & RepoRelease>();
  if (!target) fail(404, 'Release not found.');
  if (target.channel !== 'stable') fail(409, 'Only stable releases can be rolled back.');
  const previous = target.previous_release_id
    ? await env.DB.prepare(`SELECT r.*, b.id AS build_id, b.artifact_sha256, b.artifact_size, b.installed_size, b.artifact_filename, b.provenance,
      v.id AS revision_id, v.manifest_sha256, v.recipe, v.description, v.recipe_sha256, v.dependencies_json, v.license, v.explanation, q.upstream_url
      FROM releases r JOIN builds b ON b.id=r.build_id JOIN revisions v ON v.id=b.revision_id JOIN requests q ON q.id=v.request_id WHERE r.id=?`).bind(target.previous_release_id).first<Release & RepoRelease>()
    : await env.DB.prepare(`SELECT r.*, b.id AS build_id, b.artifact_sha256, b.artifact_size, b.installed_size, b.artifact_filename, b.provenance,
      v.id AS revision_id, v.manifest_sha256, v.recipe, v.description, v.recipe_sha256, v.dependencies_json, v.license, v.explanation, q.upstream_url
      FROM releases r JOIN builds b ON b.id=r.build_id JOIN revisions v ON v.id=b.revision_id JOIN requests q ON q.id=v.request_id
      WHERE r.name=? AND r.architecture=? AND r.channel='withdrawn' AND r.published_at<? ORDER BY r.published_at DESC LIMIT 1`)
      .bind(target.name, target.architecture, target.published_at).first<Release & RepoRelease>();
  if (!previous || previous.name !== target.name || previous.architecture !== target.architecture || previous.surface !== target.surface) {
    fail(409, 'No compatible previous release is available for downgrade.');
  }
  if (previous.channel !== 'withdrawn') fail(409, 'Previous release is not available for downgrade.');
  await assertCurrentApprovals(env, previous.revision_id, previous.manifest_sha256);
  if (target.surface === 'binary' && (!previous.artifact_key || !previous.signature_key || !previous.artifact_sha256 || !previous.artifact_filename)) {
    fail(409, 'Previous binary release is missing immutable package evidence.');
  }
  if (target.surface === 'binary' && previous.artifact_key !== packageKey(previous.architecture, previous.artifact_filename)) {
    fail(409, 'Previous binary release is outside the published package namespace.');
  }
  const current = await currentStable(env);
  const final = finalStable(current.filter((row) => row.release_id !== target.id), previous.surface === 'binary' ? [previous as RepoRelease] : []);
  if (target.surface === 'binary') {
    await verifyR2Object(env, previous.artifact_key, previous.artifact_sha256, previous.artifact_size);
    await verifySignatureObject(env, previous.signature_key);
    assertDependencyGraph([], current, final);
  }
  const batchId = id();
  const origin = publicOrigin(env);
  const publicBase = `${origin}/repo/${target.architecture}`;
  const previousRecipeUrl = `${origin}/repo/recipes/${segment(previous.name)}/${segment(previous.version)}/${previous.architecture}/PKGBUILD`;
  const manifest = {
    schemaVersion: 1,
    kind: 'opr-downgrade',
    clientUrl: `${origin}/repo/rollback/client.sh`,
    publicKeyUrl: `${origin}/repo/key.asc`,
    package: { name: target.name, architecture: target.architecture },
    from: { releaseId: target.id, version: target.version },
    to: { releaseId: previous.id, version: previous.version },
    reason: clean,
    issuedAt: now(),
    command: target.surface === 'binary'
      ? `sudo pacman -U '${publicBase}/${previous.artifact_filename}'`
      : `curl --fail --location --proto '=https' --proto-redir '=https' --output PKGBUILD '${previousRecipeUrl}' && makepkg -si -f`,
    artifact: target.surface === 'binary' ? {
      url: `${publicBase}/${previous.artifact_filename}`, signatureUrl: `${publicBase}/${previous.artifact_filename}.sig`, sha256: previous.artifact_sha256,
    } : null,
    recipe: target.surface === 'recipe' ? { url: previousRecipeUrl, sha256: previous.recipe_sha256 } : null,
  };
  const manifestBytes = new TextEncoder().encode(JSON.stringify(manifest));
  const manifestPath = rollbackKey(target.id);
  await immutableBytes(env, manifestPath, manifestBytes, await sha256(manifestBytes), 'application/json');
  const snapshots = target.surface === 'binary' ? [await snapshot(env, final, target.architecture, previous as RepoRelease, batchId)] : [];
  const statements: D1PreparedStatement[] = [
    env.DB.prepare("UPDATE releases SET channel='withdrawn',batch_id=? WHERE id=? AND channel='stable'").bind(batchId, target.id),
    env.DB.prepare('INSERT INTO distribution_assertions(expected,actual) SELECT 1,changes()'),
    env.DB.prepare("UPDATE releases SET channel='stable',stable_at=?,batch_id=? WHERE id=? AND channel='withdrawn'").bind(now(), batchId, previous.id),
    env.DB.prepare('INSERT INTO distribution_assertions(expected,actual) SELECT 1,changes()'),
    env.DB.prepare('INSERT INTO release_rollbacks(release_id,previous_release_id,manifest_key,created_at) VALUES(?,?,?,?)')
      .bind(target.id, previous.id, manifestPath, now()),
  ];
  for (const item of snapshots) {
    statements.push(env.DB.prepare("UPDATE repository_snapshots SET active=0 WHERE channel='stable' AND architecture=? AND active=1").bind(item.architecture));
    statements.push(env.DB.prepare(`INSERT INTO repository_snapshots
      (id,architecture,channel,db_key,db_signature_key,batch_id,created_at,active) VALUES(?,?,?,?,?,?,?,1)`)
      .bind(item.id, item.architecture, item.channel, item.dbKey, item.dbSignatureKey, item.batchId, now()));
  }
  statements.push(env.DB.prepare(`INSERT INTO distribution_assertions(expected,actual)
    SELECT 2,COUNT(*) FROM releases WHERE id IN (?,?) AND batch_id=? AND ((id=? AND channel='withdrawn') OR (id=? AND channel='stable'))`)
    .bind(target.id, previous.id, batchId, target.id, previous.id));
  for (const row of current) {
    if (row.release_id !== target.id) {
      statements.push(env.DB.prepare("INSERT INTO distribution_assertions(expected,actual) SELECT 1,COUNT(*) FROM releases WHERE id=? AND channel='stable'").bind(row.release_id));
    }
  }
  statements.push(env.DB.prepare(`INSERT INTO distribution_assertions(expected,actual)
    SELECT ?,COUNT(*) FROM releases WHERE channel='stable' AND surface='binary'`)
    .bind(current.length));
  statements.push(env.DB.prepare('DELETE FROM distribution_assertions'));
  statements.push(audit(env.DB, actor.id, 'release.rolled_back', target.id, {
    previousReleaseId: previous.id, reason: clean, manifestKey: manifestPath, batchId,
    snapshots: snapshots.map((item) => ({ id: item.id, sha256: item.dbSha256 })),
  }));
  const result = await env.DB.batch(statements);
  if (!result[0].meta.changes || !result[1].meta.changes) fail(409, 'Release changed while rollback was being prepared; retry after refreshing.');
  return { releaseId: target.id, previousReleaseId: previous.id, manifestKey: manifestPath, batchId, snapshots };
}

export async function rollbackRelease(env: Env, actor: Actor | null, releaseId: string, reason: string) {
  try {
    return await rollbackInner(env, requireReleaseMaintainer(actor), releaseId, reason);
  } catch (cause) {
    if (cause instanceof PolicyError) await recordDenied(env, actor, 'release.rollback_denied', releaseId, cause);
    throw cause;
  }
}

/** Move a stable release back to quarantine after a policy-defined crash signal. */
export async function quarantineRelease(env: Env, releaseId: string, reason: string, minimumConfirmedCrashes?: number) {
  const target = await env.DB.prepare(`SELECT r.*,b.id AS build_id,b.artifact_sha256,b.artifact_size,b.installed_size,b.artifact_filename,b.provenance,
    v.id AS revision_id,v.manifest_sha256,v.recipe,v.description,v.dependencies_json,v.license,v.explanation,q.upstream_url
    FROM releases r JOIN builds b ON b.id=r.build_id JOIN revisions v ON v.id=b.revision_id JOIN requests q ON q.id=v.request_id
    WHERE r.id=?`).bind(safeId(releaseId)).first<Release & RepoRelease>();
  if (!target || target.channel !== 'stable') return false;
  const clean = cleanReason(reason);
  const batchId = id();
  const current = await currentStable(env);
  const final = current.filter((row) => row.release_id !== target.id);
  let snapshots: RepositorySnapshot[] = [];
  if (target.surface === 'binary') {
    assertDependencyGraph([], current, final);
    const context = final.find((row) => row.architecture === target.architecture) ?? target as RepoRelease;
    await assertCurrentApprovals(env, context.revision_id, context.manifest_sha256);
    snapshots = [await snapshot(env, final, target.architecture, context, batchId)];
  }
  const devCurrent = await currentDev(env);
  const devFinal = target.surface === 'binary' ? finalDev(devCurrent, [target as RepoRelease]) : latestPerPackage(devCurrent);
  const devSnapshots = target.surface === 'binary'
    ? [await snapshot(env, devFinal, target.architecture, (snapshots[0] && final.find((row) => row.architecture === target.architecture)) ?? target as RepoRelease, batchId, 'dev')]
    : [];
  const statements: D1PreparedStatement[] = [
    env.DB.prepare(`UPDATE releases SET channel='dev',batch_id=? WHERE id=? AND channel='stable'
      AND (? IS NULL OR (SELECT COUNT(*) FROM crash_reports WHERE release_id=? AND confirmed_at IS NOT NULL AND resolved_at IS NULL)>=?)`)
      .bind(batchId, target.id, minimumConfirmedCrashes ?? null, target.id, minimumConfirmedCrashes ?? null),
    env.DB.prepare('INSERT INTO distribution_assertions(expected,actual) SELECT 1,changes()'),
  ];
  for (const item of snapshots) {
    statements.push(env.DB.prepare("UPDATE repository_snapshots SET active=0 WHERE channel='stable' AND architecture=? AND active=1").bind(item.architecture));
    statements.push(env.DB.prepare(`INSERT INTO repository_snapshots
      (id,architecture,channel,db_key,db_signature_key,batch_id,created_at,active) VALUES(?,?,?,?,?,?,?,1)`)
      .bind(item.id, item.architecture, item.channel, item.dbKey, item.dbSignatureKey, item.batchId, now()));
  }
  for (const item of devSnapshots) {
    statements.push(env.DB.prepare("UPDATE repository_snapshots SET active=0 WHERE channel='dev' AND architecture=? AND active=1").bind(item.architecture));
    statements.push(env.DB.prepare(`INSERT INTO repository_snapshots
      (id,architecture,channel,db_key,db_signature_key,batch_id,created_at,active) VALUES(?,?,?,?,?,?,?,1)`)
      .bind(item.id, item.architecture, item.channel, item.dbKey, item.dbSignatureKey, item.batchId, now()));
    statements.push(env.DB.prepare("INSERT INTO distribution_assertions(expected,actual) SELECT 1,COUNT(*) FROM repository_snapshots WHERE id=? AND channel='dev' AND architecture=? AND active=1")
      .bind(item.id, item.architecture));
  }
  for (const row of current) {
    if (row.release_id !== target.id) {
      statements.push(env.DB.prepare("INSERT INTO distribution_assertions(expected,actual) SELECT 1,COUNT(*) FROM releases WHERE id=? AND channel='stable'").bind(row.release_id));
    }
  }
  for (const row of devCurrent) {
    if (row.name !== target.name || row.architecture !== target.architecture) {
      statements.push(env.DB.prepare("INSERT INTO distribution_assertions(expected,actual) SELECT 1,COUNT(*) FROM releases WHERE id=? AND channel='dev'").bind(row.release_id));
    }
  }
  statements.push(env.DB.prepare(`INSERT INTO distribution_assertions(expected,actual)
    SELECT 1,COUNT(*) FROM releases WHERE id=? AND channel='dev' AND batch_id=?`).bind(target.id, batchId));
  statements.push(env.DB.prepare(`INSERT INTO distribution_assertions(expected,actual)
    SELECT ?,COUNT(*) FROM releases WHERE channel='stable' AND surface='binary'`)
    .bind(current.length - (target.surface === 'binary' ? 1 : 0)));
  const devReplacedCount = devCurrent.filter((row) => row.name === target.name && row.architecture === target.architecture).length;
  statements.push(env.DB.prepare(`INSERT INTO distribution_assertions(expected,actual)
    SELECT ?,COUNT(*) FROM releases WHERE channel='dev' AND surface='binary'`)
    .bind(devCurrent.length - devReplacedCount + (target.surface === 'binary' ? 1 : 0)));
  statements.push(env.DB.prepare('DELETE FROM distribution_assertions'));
  statements.push(audit(env.DB, 'system', 'release.quarantined', target.id, {
    reason: clean, batchId,
    snapshots: snapshots.map((item) => ({ id: item.id, sha256: item.dbSha256 })),
    devSnapshots: devSnapshots.map((item) => ({ id: item.id, sha256: item.dbSha256 })),
  }));
  await env.DB.batch(statements);
  return true;
}

export type PublicRelease = {
  id: string;
  name: string;
  version: string;
  architecture: Architecture;
  surface: 'binary' | 'recipe';
  channel: 'stable' | 'withdrawn' | 'dev';
  publishedAt: number;
  stableAt: number | null;
  artifact: { url: string; filename: string; sha256: string; size: number; signatureUrl: string } | null;
  recipeUrl: string;
  sbomUrl: string;
  provenanceUrl: string;
  rollbackUrl: string;
  rollbackClientUrl: string;
};

export function publicRelease(release: Release & { artifact_filename?: string | null; artifact_sha256?: string | null; artifact_size?: number | null }, origin = '', includeDev = false): PublicRelease | null {
  if (release.channel !== 'stable' && release.channel !== 'withdrawn' && !(includeDev && release.channel === 'dev')) return null;
  const base = origin.replace(/\/$/, '');
  const routeBase = release.channel === 'dev' ? `${base}/repo/dev` : `${base}/repo`;
  const artifact = release.surface === 'binary' && release.artifact_key && release.signature_key && release.artifact_filename && release.artifact_sha256 && release.artifact_size
    ? {
        url: `${routeBase}/${release.architecture}/${encodeURIComponent(release.artifact_filename)}`,
        filename: release.artifact_filename, sha256: release.artifact_sha256, size: release.artifact_size,
        signatureUrl: `${routeBase}/${release.architecture}/${encodeURIComponent(release.artifact_filename)}.sig`,
      }
    : null;
  return {
    id: release.id, name: release.name, version: release.version, architecture: release.architecture,
    surface: release.surface, channel: release.channel, publishedAt: release.published_at, stableAt: release.stable_at,
    artifact, recipeUrl: `${routeBase}/recipes/${segment(release.name)}/${segment(release.version)}/${release.architecture}/PKGBUILD`,
    sbomUrl: `${base}/repo/metadata/${release.id}/sbom.json`, provenanceUrl: `${base}/repo/metadata/${release.id}/provenance.json`,
    rollbackUrl: `${base}/repo/rollback/${release.id}.json`, rollbackClientUrl: `${base}/repo/rollback/client.sh`,
  };
}

export function isReleaseId(value: string): boolean {
  return MCP_RELEASE_ID.test(value);
}
