import type { Architecture, Revision } from '../model';
import type { Env } from './env';
import { audit, now, sha256 } from './db';
import { PolicyError, revisionImage, validateRevision } from './policy';
import { archRelationCovers, parsePackageMetadata } from './arch';
import { dependencyPlansEqual, parseDependencyPlan, type DependencyPlan } from './dependency-plan';

export type SigningControlEnv = Pick<Env, 'DB' | 'ARTIFACTS'> & {
  CONTROL_TOKEN?: string;
  PACKAGE_SIGNING_FINGERPRINT?: string;
  SIGNING_FINGERPRINT?: string;
  PACKAGE_SIGNING_PUBLIC_KEY_R2_KEY?: string;
  SIGNING_KEY_ID?: string;
};

export const SIGNING_INTENT_TTL_SECONDS = 60 * 60;
export const SIGNING_CLAIM_TTL_SECONDS = 15 * 60;
export const MAX_SIGNING_ARTIFACT_BYTES = 4 * 1024 * 1024 * 1024;
const MAX_PROVENANCE_BYTES = 256 * 1024;
const MAX_SIGNATURE_BYTES = 1 * 1024 * 1024;
const ID = /^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/;
const SHA256 = /^[a-f0-9]{64}$/;
const BASE64 = /^[A-Za-z0-9+/]+={0,2}$/;
const FINGERPRINT = /^[a-f0-9]{40}$/;
const SAFE_KEY = /^(?!\/)(?!.*(?:^|\/)\.\.(?:\/|$))[\x21-\x7e]{1,1024}$/;
const FILENAME = /^[A-Za-z0-9][A-Za-z0-9._+:-]{0,220}$/;
const DATABASE_SUFFIXES = [
  '.db', '.files',
  '.db.tar.zst', '.db.tar.xz', '.db.tar.gz', '.db.tar.bz2',
  '.files.tar.zst', '.files.tar.xz', '.files.tar.gz', '.files.tar.bz2',
];

export class SigningControlError extends Error {
  constructor(readonly status: number, message: string) {
    super(message);
    this.name = 'SigningControlError';
  }
}

export interface SigningIntentResponse {
  id: string;
  status: 'ready' | 'signed';
  kind: 'package' | 'database';
  expiresAt: number;
  keyFingerprint: string;
  artifact: { key: string; sha256: string; size: number; filename: string };
  build: {
    id: string;
    revisionId: string;
    status: 'succeeded';
    surface: 'binary';
    architecture: Architecture;
    workerId: string;
    smokePassed: true;
  };
  review: { manifestSha256: string; areaApproved: boolean; securityApproved: boolean };
  attestation: { provenance: string; provenanceSignature: string; workerPublicKey: string };
  signature?: { key: string; sha256: string; filename: string };
}

export interface SigningEventInput {
  action: 'signing.completed';
  intentId: string;
  kind: 'package' | 'database';
  buildId: string;
  revisionId: string;
  artifactKey: string;
  artifactSha256: string;
  signatureKey: string;
  signatureSha256: string;
  signatureFilename: string;
  publicKeyKey: string;
  fingerprint: string;
  keyId: string;
  mode: 'cloudflare-worker-secret' | 'managed-kms';
}

interface IntentRow extends Revision {
  intent_id: string;
  intent_status: 'pending' | 'signed' | 'failed' | 'expired';
  object_key: string;
  object_kind: 'package' | 'database';
  intent_artifact_sha256: string;
  intent_artifact_filename: string;
  intent_manifest_sha256: string;
  intent_artifact_size: number | null;
  intent_expires_at: number | null;
  claimed_at: number | null;
  claim_expires_at: number | null;
  intent_key_fingerprint: string | null;
  signature_key: string | null;
  signature_sha256: string | null;
  intent_created_at: number;
  revision_id: string;
  build_id: string;
  build_revision_id: string;
  build_status: string;
  build_worker_id: string | null;
  build_architecture: Architecture;
  build_artifact_key: string | null;
  build_artifact_sha256: string | null;
  build_artifact_size: number | null;
  build_installed_size: number | null;
  build_dependency_plan_json: string | null;
  build_artifact_filename: string | null;
  build_provenance: string | null;
  build_provenance_signature: string | null;
  build_smoke_passed: number;
  request_status: string;
  request_name: string;
  latest_revision_id: string | null;
  worker_public_key: string | null;
  worker_status: string | null;
  area_approved: number;
  security_approved: number;
}

const INTENT_QUERY = `
  SELECT
    i.id AS intent_id, i.status AS intent_status, i.object_key, i.object_kind,
    i.artifact_sha256 AS intent_artifact_sha256, i.artifact_filename AS intent_artifact_filename,
    i.manifest_sha256 AS intent_manifest_sha256, i.artifact_size AS intent_artifact_size,
    i.expires_at AS intent_expires_at, i.claimed_at, i.claim_expires_at,
    i.key_fingerprint AS intent_key_fingerprint, i.signature_key, i.signature_sha256,
    i.created_at AS intent_created_at,
    b.id AS build_id, b.revision_id AS build_revision_id, b.status AS build_status,
    b.worker_id AS build_worker_id, b.architecture AS build_architecture,
    b.artifact_key AS build_artifact_key, b.artifact_sha256 AS build_artifact_sha256,
    b.artifact_size AS build_artifact_size, b.installed_size AS build_installed_size, b.dependency_plan_json AS build_dependency_plan_json, b.artifact_filename AS build_artifact_filename,
    b.provenance AS build_provenance, b.provenance_signature AS build_provenance_signature,
    b.smoke_passed AS build_smoke_passed,
    r.id, r.id AS revision_id, r.request_id, r.version, r.recipe, r.recipe_sha256, r.public_recipe, r.public_recipe_sha256, r.manifest_sha256,
    r.sources_json, r.dependencies_json, r.make_dependencies_json, r.smoke_commands_json, r.architectures_json, r.build_images_json,
    r.pkgrel, r.source_date_epoch, r.image_digest, r.license, r.surface, r.description, r.explanation,
    r.sbom_json, r.lint_json, r.upstream_commit, r.pr_url, r.commit_sha, r.created_at,
    q.status AS request_status, q.name AS request_name,
    (SELECT latest.id FROM revisions latest WHERE latest.request_id=r.request_id
      ORDER BY latest.created_at DESC, latest.rowid DESC LIMIT 1) AS latest_revision_id,
    w.public_key AS worker_public_key, w.status AS worker_status,
    EXISTS (SELECT 1 FROM approvals a WHERE a.revision_id=r.id AND a.kind='area'
      AND a.manifest_sha256=r.manifest_sha256 AND a.revoked_at IS NULL) AS area_approved,
    EXISTS (SELECT 1 FROM approvals a WHERE a.revision_id=r.id AND a.kind='security'
      AND a.manifest_sha256=r.manifest_sha256 AND a.revoked_at IS NULL) AS security_approved
  FROM signing_intents i
  JOIN builds b ON b.id=i.build_id AND b.revision_id=i.revision_id
  JOIN revisions r ON r.id=i.revision_id
  JOIN requests q ON q.id=r.request_id
  LEFT JOIN workers w ON w.id=b.worker_id
  WHERE i.id=?`;

function fail(status: number, message: string): never {
  throw new SigningControlError(status, message);
}

function text(value: unknown, max: number, label: string): string {
  if (typeof value !== 'string' || value.length === 0 || value.length > max || /[\u0000\r\n]/.test(value)) {
    fail(400, `${label} is invalid.`);
  }
  return value;
}

function jsonValue(value: string, label: string): unknown {
  if (value.length > MAX_PROVENANCE_BYTES) fail(409, `${label} is too large.`);
  try { return JSON.parse(value); }
  catch { fail(409, `${label} is invalid.`); }
}

function jsonObject(value: string, label: string): Record<string, unknown> {
  const parsed = jsonValue(value, label);
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) fail(409, `${label} must be an object.`);
  return parsed as Record<string, unknown>;
}

function jsonArray(value: string, label: string): unknown[] {
  const parsed = jsonValue(value, label);
  if (!Array.isArray(parsed)) fail(409, `${label} must be an array.`);
  return parsed;
}

function bytesFromBase64(value: string, label: string, expected: number): Uint8Array {
  if (!BASE64.test(value)) fail(409, `${label} is invalid.`);
  try {
    const bytes = Uint8Array.from(atob(value), (character) => character.charCodeAt(0));
    if (bytes.byteLength !== expected) fail(409, `${label} has an invalid length.`);
    return bytes;
  } catch { fail(409, `${label} is invalid.`); }
}

function configuredFingerprint(env: SigningControlEnv): string {
  const value = (env.PACKAGE_SIGNING_FINGERPRINT ?? env.SIGNING_FINGERPRINT ?? '').toLowerCase();
  if (!FINGERPRINT.test(value)) fail(503, 'Signing fingerprint is not configured.');
  return value;
}

function publicKeyKey(env: SigningControlEnv): string {
  const key = env.PACKAGE_SIGNING_PUBLIC_KEY_R2_KEY ?? 'keys/opr-package-signing.asc';
  if (!SAFE_KEY.test(key)) fail(503, 'Signing public-key object key is invalid.');
  return key;
}

function expiry(row: IntentRow): number {
  const value = row.intent_expires_at ?? row.intent_created_at + SIGNING_INTENT_TTL_SECONDS;
  if (!Number.isSafeInteger(value) || value <= row.intent_created_at) fail(409, 'Signing intent expiry is invalid.');
  return value;
}

function revision(row: IntentRow): Revision {
  return {
    id: row.id, request_id: row.request_id, version: row.version, recipe: row.recipe,
    recipe_sha256: row.recipe_sha256, public_recipe: row.public_recipe, public_recipe_sha256: row.public_recipe_sha256, manifest_sha256: row.manifest_sha256,
    sources_json: row.sources_json, dependencies_json: row.dependencies_json, make_dependencies_json: row.make_dependencies_json,
    smoke_commands_json: row.smoke_commands_json, architectures_json: row.architectures_json, build_images_json: row.build_images_json,
    pkgrel: row.pkgrel, source_date_epoch: row.source_date_epoch, image_digest: row.image_digest,
    license: row.license, surface: row.surface, description: row.description, explanation: row.explanation,
    sbom_json: row.sbom_json, lint_json: row.lint_json, upstream_commit: row.upstream_commit,
    pr_url: row.pr_url, commit_sha: row.commit_sha, created_at: row.created_at,
  };
}

async function load(env: SigningControlEnv, intentId: string): Promise<IntentRow> {
  const row = await env.DB.prepare(INTENT_QUERY).bind(intentId).first<IntentRow>();
  if (!row) fail(404, 'Signing intent not found.');
  return row;
}

async function validateEvidence(
  env: SigningControlEnv,
  row: IntentRow,
  fingerprint: string,
  artifactSize: number,
  requireCurrentReview: boolean,
): Promise<void> {
  if (row.intent_key_fingerprint && row.intent_key_fingerprint.toLowerCase() !== fingerprint) {
    fail(409, 'Signing key fingerprint changed.');
  }
  if (row.intent_artifact_sha256 !== row.intent_artifact_sha256.toLowerCase() || !SHA256.test(row.intent_artifact_sha256)) {
    fail(409, 'Signing artifact digest is invalid.');
  }
  if (!SAFE_KEY.test(row.object_key) || row.object_key.split('/').some((part) => part === '..')) fail(409, 'Signing artifact key is invalid.');
  if (!FILENAME.test(row.intent_artifact_filename) || row.intent_artifact_filename.includes('/')) fail(409, 'Signing artifact filename is invalid.');
  if (row.object_key.split('/').at(-1) !== row.intent_artifact_filename) fail(409, 'Signing artifact filename does not match its key.');
  if (row.object_kind === 'package') {
    if (!row.intent_artifact_filename.endsWith('.pkg.tar.zst') || !row.object_key.startsWith(`packages/${row.build_architecture}/`)) {
      fail(409, 'Package signing object is outside the package namespace.');
    }
    if (row.build_artifact_sha256 !== row.intent_artifact_sha256 || row.build_artifact_filename !== row.intent_artifact_filename || row.build_artifact_size !== artifactSize) {
      fail(409, 'Package signing object does not match build evidence.');
    }
  } else {
    if (!DATABASE_SUFFIXES.some((suffix) => row.intent_artifact_filename.endsWith(suffix)) ||
        !new RegExp(`^repo/(?:stable|dev)/${row.build_architecture}/`).test(row.object_key)) {
      fail(409, 'Database signing object is outside the repository namespace.');
    }
  }
  if (!Number.isSafeInteger(artifactSize) || artifactSize <= 0 || artifactSize > MAX_SIGNING_ARTIFACT_BYTES) fail(409, 'Signing artifact size is invalid.');
  if (row.build_revision_id !== row.revision_id || row.build_status !== 'succeeded' || row.build_smoke_passed !== 1 || row.build_worker_id === null || row.worker_public_key === null) {
    fail(409, 'Build attestation is not ready.');
  }
  if (row.build_architecture !== 'x86_64' && row.build_architecture !== 'aarch64') fail(409, 'Build architecture is invalid.');
  if (row.surface !== 'binary' || !['queued', 'building', 'built'].includes(row.request_status)) fail(409, 'Only a successful binary build can be signed.');
  if (row.latest_revision_id !== row.revision_id || row.intent_manifest_sha256 !== row.manifest_sha256) fail(409, 'Signing revision is no longer current.');
  if (requireCurrentReview && (row.worker_status !== 'active' || row.area_approved !== 1 || row.security_approved !== 1)) {
    fail(409, 'Current build review approvals are incomplete.');
  }
  try { await validateRevision(revision(row)); }
  catch (cause) { fail(cause instanceof PolicyError ? cause.status : 409, cause instanceof Error ? cause.message : 'Reviewed revision is invalid.'); }

  const workerPublicKey = row.worker_public_key;
  const provenanceSignature = row.build_provenance_signature;
  if (!workerPublicKey || !provenanceSignature || !BASE64.test(provenanceSignature)) fail(409, 'Build provenance signature is invalid.');
  const workerPublicKeyBytes = bytesFromBase64(workerPublicKey, 'Worker public key', 32);
  const provenanceSignatureBytes = bytesFromBase64(provenanceSignature, 'Build provenance signature', 64);
  if (!row.build_provenance) fail(409, 'Build provenance is missing.');
  let provenanceSignatureValid = false;
  try {
    const key = await crypto.subtle.importKey('raw', workerPublicKeyBytes as unknown as BufferSource, { name: 'Ed25519' }, false, ['verify']);
    provenanceSignatureValid = await crypto.subtle.verify(
      'Ed25519', key, provenanceSignatureBytes as unknown as BufferSource,
      new TextEncoder().encode(row.build_provenance) as unknown as BufferSource,
    );
  } catch {
    fail(409, 'Build provenance signature is invalid.');
  }
  if (!provenanceSignatureValid) fail(409, 'Build provenance signature is invalid.');
  const provenance = jsonObject(row.build_provenance, 'Build provenance');
  let expectedDependencyPlan: DependencyPlan | null = null;
  if (row.build_dependency_plan_json !== null) {
    try { expectedDependencyPlan = parseDependencyPlan(JSON.parse(row.build_dependency_plan_json)); }
    catch { expectedDependencyPlan = null; }
    if (!expectedDependencyPlan) fail(409, 'Stored OPR dependency plan is invalid.');
  }
  let actualDependencyPlan: DependencyPlan | null = null;
  if (provenance.dependencyPlan !== undefined && provenance.dependencyPlan !== null) {
    actualDependencyPlan = parseDependencyPlan(provenance.dependencyPlan);
    if (!actualDependencyPlan) fail(409, 'Build provenance dependency plan is invalid.');
  }
  if (!dependencyPlansEqual(expectedDependencyPlan, actualDependencyPlan)) fail(409, 'Build provenance dependency plan does not match lease.');
  const metadata = parsePackageMetadata(provenance.packageMetadata);
  if (!metadata || metadata.name !== row.request_name || metadata.fullVersion !== `${row.version}-${row.pkgrel ?? 1}` ||
      metadata.architecture !== row.build_architecture || metadata.installedSize !== row.build_installed_size ||
      metadata.installedSize !== provenance.installedSize) {
    fail(409, 'Package metadata does not match reviewed build.');
  }
  const reviewedDependencies = jsonArray(row.dependencies_json, 'Dependency manifest');
  if (reviewedDependencies.some((reviewed) => typeof reviewed !== 'string' || !metadata.depends.some((native) => archRelationCovers(native, reviewed)))) {
    fail(409, 'Package metadata does not contain reviewed dependencies.');
  }
  let expectedImageDigest: string | undefined;
  try { expectedImageDigest = revisionImage(revision(row), row.build_architecture).split('@').at(-1); }
  catch (cause) { fail(409, cause instanceof PolicyError ? cause.message : 'Builder image is invalid for this architecture.'); }
  const sources = jsonArray(row.sources_json, 'Source manifest');
  if (provenance.buildId !== row.build_id || provenance.revisionId !== row.revision_id || provenance.workerId !== row.build_worker_id ||
      provenance.recipeSha256 !== row.recipe_sha256 || provenance.architecture !== row.build_architecture ||
      provenance.imageDigest !== expectedImageDigest || provenance.sourceDateEpoch !== row.source_date_epoch || provenance.network !== 'disabled' ||
      JSON.stringify(provenance.sources) !== JSON.stringify(sources) || !Number.isSafeInteger(provenance.sourceDateEpoch) ||
      !Number.isFinite(Date.parse(String(provenance.startedAt))) || !Number.isFinite(Date.parse(String(provenance.finishedAt)))) {
    fail(409, 'Build provenance does not match reviewed inputs.');
  }
  if (typeof provenance.artifactSha256 !== 'string' || !SHA256.test(provenance.artifactSha256)) fail(409, 'Build provenance artifact digest is invalid.');
  if (row.object_kind === 'package' && provenance.artifactSha256 !== row.intent_artifact_sha256) fail(409, 'Build provenance artifact digest does not match package bytes.');
  if (row.object_kind === 'database' && provenance.artifactSha256 !== row.build_artifact_sha256) fail(409, 'Database signing context is not tied to an attested package build.');
}

async function artifactSize(env: SigningControlEnv, row: IntentRow): Promise<number> {
  const object = await env.ARTIFACTS.head(row.object_key);
  if (!object) fail(409, 'Signing artifact is unavailable.');
  if (row.intent_artifact_size !== null && object.size !== row.intent_artifact_size) fail(409, 'Signing artifact size changed.');
  const metadataDigest = object.customMetadata?.sha256 ?? object.customMetadata?.artifactSha256;
  if (metadataDigest && metadataDigest !== row.intent_artifact_sha256) fail(409, 'Signing artifact metadata digest changed.');
  return object.size;
}

function response(row: IntentRow, fingerprint: string, size: number): SigningIntentResponse {
  const result: SigningIntentResponse = {
    id: row.intent_id, status: row.intent_status === 'signed' ? 'signed' : 'ready', kind: row.object_kind,
    expiresAt: expiry(row), keyFingerprint: fingerprint,
    artifact: { key: row.object_key, sha256: row.intent_artifact_sha256, size, filename: row.intent_artifact_filename },
    build: { id: row.build_id, revisionId: row.revision_id, status: 'succeeded', surface: 'binary', architecture: row.build_architecture, workerId: row.build_worker_id!, smokePassed: true },
    review: { manifestSha256: row.manifest_sha256, areaApproved: row.area_approved === 1, securityApproved: row.security_approved === 1 },
    attestation: { provenance: row.build_provenance!, provenanceSignature: row.build_provenance_signature!, workerPublicKey: row.worker_public_key! },
  };
  if (row.intent_status === 'signed') {
    if (!row.signature_key || !row.signature_sha256 || !SHA256.test(row.signature_sha256) || row.signature_key !== `${row.object_key}.sig`) {
      fail(409, 'Signed intent has incomplete signature evidence.');
    }
    result.signature = { key: row.signature_key, sha256: row.signature_sha256, filename: `${row.intent_artifact_filename}.sig` };
  }
  return result;
}

async function markExpired(env: SigningControlEnv, intentId: string): Promise<void> {
  await env.DB.batch([
    env.DB.prepare("UPDATE signing_intents SET status='expired' WHERE id=? AND status='pending'").bind(intentId),
    env.DB.prepare(`INSERT INTO audit_events(actor,action,target,detail,created_at)
      SELECT 'system','signing.intent_expired',?,?,? WHERE changes()=1`).bind(intentId, '{}', now()),
  ]);
}

async function resetFailed(env: SigningControlEnv, intentId: string, expiresAt: number, timestamp: number): Promise<void> {
  await env.DB.batch([
    env.DB.prepare(`UPDATE signing_intents SET status='pending',claimed_at=NULL,claim_expires_at=NULL
      WHERE id=? AND status='failed' AND signature_key IS NULL AND COALESCE(expires_at,created_at+?)>?`).bind(intentId, SIGNING_INTENT_TTL_SECONDS, timestamp),
    env.DB.prepare(`INSERT INTO audit_events(actor,action,target,detail,created_at)
      SELECT 'system','signing.intent_retry',?,?,? WHERE changes()=1`).bind(intentId, JSON.stringify({ expiresAt }), timestamp),
  ]);
}

export async function claimSigningIntent(env: SigningControlEnv, intentId: string): Promise<SigningIntentResponse> {
  if (!ID.test(intentId)) fail(400, 'Invalid intent ID.');
  const fingerprint = configuredFingerprint(env);
  let row = await load(env, intentId);
  const timestamp = now();
  const expiresAt = expiry(row);
  if (row.intent_status === 'expired') fail(409, 'Signing intent has expired.');
  if (row.intent_status === 'failed') {
    if (expiresAt <= timestamp) { await markExpired(env, intentId); fail(409, 'Signing intent has expired.'); }
    await resetFailed(env, intentId, expiresAt, timestamp);
    row = await load(env, intentId);
  }
  if (row.intent_status === 'signed') {
    const size = await artifactSize(env, row);
    await validateEvidence(env, row, fingerprint, size, false);
    return response(row, fingerprint, size);
  }
  if (expiresAt <= timestamp) { await markExpired(env, intentId); fail(409, 'Signing intent has expired.'); }
  const size = await artifactSize(env, row);
  await validateEvidence(env, row, fingerprint, size, true);
  if (row.claim_expires_at === null || row.claim_expires_at <= timestamp) {
    await env.DB.batch([
      env.DB.prepare(`UPDATE signing_intents SET expires_at=COALESCE(expires_at,created_at+?),artifact_size=?,
          claimed_at=?,claim_expires_at=?,key_fingerprint=?
        WHERE id=? AND status='pending' AND COALESCE(expires_at,created_at+?)>? AND
          (claim_expires_at IS NULL OR claim_expires_at<=?)`).bind(
        SIGNING_INTENT_TTL_SECONDS, size, timestamp, timestamp + SIGNING_CLAIM_TTL_SECONDS, fingerprint,
        intentId, SIGNING_INTENT_TTL_SECONDS, timestamp, timestamp,
      ),
      env.DB.prepare(`INSERT INTO audit_events(actor,action,target,detail,created_at)
        SELECT 'system','signing.intent_claimed',?,?,? WHERE changes()=1`).bind(intentId, JSON.stringify({ expiresAt, claimExpiresAt: timestamp + SIGNING_CLAIM_TTL_SECONDS }), timestamp),
    ]);
    row = await load(env, intentId);
  }
  if (row.intent_status !== 'pending') {
    if (row.intent_status === 'signed') {
      const signedSize = await artifactSize(env, row);
      await validateEvidence(env, row, fingerprint, signedSize, false);
      return response(row, fingerprint, signedSize);
    }
    fail(409, 'Signing intent is no longer active.');
  }
  const claimedSize = await artifactSize(env, row);
  await validateEvidence(env, row, fingerprint, claimedSize, true);
  return response(row, fingerprint, claimedSize);
}

function parseEvent(value: unknown): SigningEventInput {
  if (!value || typeof value !== 'object' || Array.isArray(value)) fail(400, 'Signing event must be an object.');
  const input = value as Record<string, unknown>;
  const action = input.action === 'signing.completed' ? input.action : null;
  const kind = input.kind === 'package' || input.kind === 'database' ? input.kind : null;
  const mode = input.mode === 'cloudflare-worker-secret' || input.mode === 'managed-kms' ? input.mode : null;
  const result = {
    action, kind, mode,
    intentId: text(input.intentId, 128, 'Intent ID'), buildId: text(input.buildId, 128, 'Build ID'), revisionId: text(input.revisionId, 128, 'Revision ID'),
    artifactKey: text(input.artifactKey, 1024, 'Artifact key'), artifactSha256: text(input.artifactSha256, 64, 'Artifact digest'),
    signatureKey: text(input.signatureKey, 1024, 'Signature key'), signatureSha256: text(input.signatureSha256, 64, 'Signature digest'),
    signatureFilename: text(input.signatureFilename, 256, 'Signature filename'), publicKeyKey: text(input.publicKeyKey, 1024, 'Public key object key'),
    fingerprint: text(input.fingerprint, 64, 'Signing fingerprint'), keyId: text(input.keyId, 128, 'Signing key ID'),
  };
  if (!action || !kind || !mode || !ID.test(result.intentId) || !ID.test(result.buildId) || !ID.test(result.revisionId) ||
      !SHA256.test(result.artifactSha256) || !SHA256.test(result.signatureSha256) || !FINGERPRINT.test(result.fingerprint.toLowerCase()) ||
      !SAFE_KEY.test(result.artifactKey) || !SAFE_KEY.test(result.signatureKey) || !SAFE_KEY.test(result.publicKeyKey) ||
      !result.signatureKey.endsWith('.sig') || result.signatureFilename !== `${result.signatureFilename.replace(/\.sig$/, '')}.sig` ||
      /[\/]/.test(result.signatureFilename) || !FILENAME.test(result.signatureFilename)) {
    fail(400, 'Signing event evidence is invalid.');
  }
  return { ...result, action, kind, mode, fingerprint: result.fingerprint.toLowerCase() };
}

async function verifySignatureObject(env: SigningControlEnv, key: string, expected: string): Promise<void> {
  const object = await env.ARTIFACTS.get(key);
  if (!object) fail(409, 'Signature object is unavailable.');
  if (object.size <= 0 || object.size > MAX_SIGNATURE_BYTES) fail(409, 'Signature object size is invalid.');
  const bytes = new Uint8Array(await object.arrayBuffer());
  if (bytes.byteLength > MAX_SIGNATURE_BYTES || await sha256(bytes) !== expected) fail(409, 'Signature object digest does not match event.');
}

export async function completeSigningIntent(env: SigningControlEnv, input: SigningEventInput): Promise<{ idempotent: boolean }> {
  const fingerprint = configuredFingerprint(env);
  if (input.fingerprint !== fingerprint) fail(409, 'Signing key fingerprint mismatch.');
  if (env.SIGNING_KEY_ID && input.keyId !== env.SIGNING_KEY_ID) fail(409, 'Signing key ID mismatch.');
  if (input.publicKeyKey !== publicKeyKey(env)) fail(409, 'Public key object mismatch.');
  const row = await load(env, input.intentId);
  if (row.build_id !== input.buildId || row.revision_id !== input.revisionId || row.object_kind !== input.kind ||
      row.object_key !== input.artifactKey || row.intent_artifact_sha256 !== input.artifactSha256 ||
      input.signatureKey !== `${row.object_key}.sig` || input.signatureFilename !== `${row.intent_artifact_filename}.sig`) {
    fail(409, 'Signing event does not match intent.');
  }
  if (row.intent_status === 'signed') {
    if (row.signature_key === input.signatureKey && row.signature_sha256 === input.signatureSha256) {
      await verifySignatureObject(env, input.signatureKey, input.signatureSha256);
      return { idempotent: true };
    }
    fail(409, 'Signing intent already has different signature evidence.');
  }
  if (row.intent_status !== 'pending' && row.intent_status !== 'failed') fail(409, 'Signing intent is no longer active.');
  if (expiry(row) <= now()) { await markExpired(env, input.intentId); fail(409, 'Signing intent has expired.'); }
  const size = await artifactSize(env, row);
  await validateEvidence(env, row, fingerprint, size, true);
  await verifySignatureObject(env, input.signatureKey, input.signatureSha256);
  const timestamp = now();
  const result = await env.DB.batch([
    env.DB.prepare(`UPDATE signing_intents SET status='signed',signature_key=?,signature_sha256=?,consumed_at=?,
        key_fingerprint=?,claim_expires_at=NULL
      WHERE id=? AND status IN ('pending','failed') AND COALESCE(expires_at,created_at+?)>?`).bind(
      input.signatureKey, input.signatureSha256, timestamp, fingerprint, input.intentId, SIGNING_INTENT_TTL_SECONDS, timestamp,
    ),
    env.DB.prepare(`INSERT INTO audit_events(actor,action,target,detail,created_at)
      SELECT 'signer','signing.completed',?,?,? WHERE changes()=1`).bind(input.buildId, JSON.stringify(input), timestamp),
  ]);
  if (!result[0] || !(result[0] as { meta?: { changes?: number } }).meta?.changes) {
    const current = await load(env, input.intentId);
    if (current.intent_status === 'signed' && current.signature_key === input.signatureKey && current.signature_sha256 === input.signatureSha256) return { idempotent: true };
    fail(409, 'Signing intent changed during completion.');
  }
  return { idempotent: false };
}

export async function authorizeControlRequest(request: Request, env: SigningControlEnv): Promise<void> {
  if (!env.CONTROL_TOKEN) fail(503, 'Signing control is unavailable.');
  const header = request.headers.get('authorization') ?? '';
  if (!header.startsWith('Bearer ')) fail(401, 'Unauthorized.');
  const [left, right] = await Promise.all([
    crypto.subtle.digest('SHA-256', new TextEncoder().encode(header.slice(7))),
    crypto.subtle.digest('SHA-256', new TextEncoder().encode(env.CONTROL_TOKEN)),
  ]);
  const a = new Uint8Array(left);
  const b = new Uint8Array(right);
  let difference = 0;
  for (let index = 0; index < a.length; index += 1) difference |= a[index] ^ b[index];
  if (difference !== 0) fail(401, 'Unauthorized.');
}

export { parseEvent as parseSigningEvent };
