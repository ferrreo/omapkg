import type { Actor, Architecture } from '../model';
import type { Env } from './env';
import { audit, id, now, query } from './db';
import { PolicyError } from './policy';
import { getFactoryAttempt, reuseSuccessfulFactoryArtifact } from './factory-runs';

export const mirrors = ['stable', 'rc', 'edge', 'custom'] as const;

export type BuildImageMirror = (typeof mirrors)[number];

export interface BuildImage {
  id: string;
  label: string;
  image_ref: string;
  architecture: Architecture;
  mirror: BuildImageMirror;
  enabled: number;
  is_default: number;
  created_actor: string;
  created_at: number;
  origin?: 'legacy' | 'factory';
  factory_run_id?: string | null;
  factory_attempt?: number | null;
  factory_input_sha256?: string | null;
  factory_output_sha256?: string | null;
  factory_output_size?: number | null;
  factory_artifact_key?: string | null;
  factory_evidence_sha256?: string | null;
}

export interface RegisterBuildImageInput {
  label: string;
  image_ref: string;
  architecture: Architecture;
  mirror: BuildImageMirror;
}

export type BuildImageEnvironment = Pick<Env, 'DB'>;

export type DefaultBuildImages = Partial<Record<Architecture, string>>;

export interface RegisterFactoryBuildImageInput {
  runId: string;
  label: string;
  mirror: BuildImageMirror;
}

const IMAGE_REF = /^(?=.{1,512}$)[a-z0-9][a-z0-9.-]*(?::[0-9]{1,5})?(?:\/[a-z0-9][a-z0-9._-]*)+(?::[a-z0-9][a-z0-9._-]{0,127})?@sha256:[a-f0-9]{64}$/;

const IMAGE_ID = /^[A-Za-z0-9_-]{1,128}$/;

const CONTROL_CHARACTERS = /[\u0000-\u001f\u007f]/;

export function requireAdmin(actor: Actor | null): Actor {
  if (!actor || actor.role !== 'admin') throw new PolicyError(403, 'Administrator access is required to change build images.');

  return actor;
}

function text(value: unknown, label: string, maxLength: number): string {
  const article = /^[aeiou]/i.test(label) ? 'an' : 'a';

  if (typeof value !== 'string') throw new PolicyError(400, `Provide ${article} ${label}.`);
  const normalized = value.trim();

  if (!normalized || normalized.length > maxLength || CONTROL_CHARACTERS.test(normalized)) {
    throw new PolicyError(400, `Provide ${article} ${label} up to ${maxLength} characters.`);
  }

  return normalized;
}

function architecture(value: unknown): Architecture {
  if (value !== 'x86_64' && value !== 'aarch64') throw new PolicyError(400, 'Choose x86_64 or aarch64.');

  return value;
}

function mirror(value: unknown): BuildImageMirror {
  if (typeof value !== 'string' || !mirrors.includes(value as BuildImageMirror)) {
    throw new PolicyError(400, 'Choose a stable, rc, edge or custom mirror.');
  }

  return value as BuildImageMirror;
}

function imageId(value: unknown): string {
  if (typeof value !== 'string' || !IMAGE_ID.test(value)) throw new PolicyError(400, 'Build image ID is invalid.');

  return value;
}

function registerInput(input: unknown): RegisterBuildImageInput {
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw new PolicyError(400, 'Build image details are required.');
  const value = input as Partial<RegisterBuildImageInput>;
  const allowed = new Set(['label', 'image_ref', 'architecture', 'mirror']);

  if (Object.keys(value).some((key) => !allowed.has(key))) throw new PolicyError(400, 'Build image input contains an unsupported field.');
  const imageRef = text(value.image_ref, 'full registry image reference', 512);

  if (!IMAGE_REF.test(imageRef)) {
    throw new PolicyError(400, 'Use a lowercase registry/repository image reference pinned with @sha256: followed by 64 hex characters.');
  }

  return {
    label: text(value.label, 'image label', 120),
    image_ref: imageRef,
    architecture: architecture(value.architecture),
    mirror: mirror(value.mirror),
  };
}

function constraintFailure(cause: unknown): PolicyError | null {
  if (cause instanceof Error && /unique|constraint/i.test(cause.message)) {
    return new PolicyError(409, 'That image digest and architecture are already registered.');
  }

  return null;
}

export async function getBuildImages(env: BuildImageEnvironment): Promise<BuildImage[]> {
  try {
    return await query<BuildImage>(env.DB, `SELECT id,label,image_ref,architecture,mirror,enabled,is_default,created_actor,created_at,origin,
      factory_run_id,factory_attempt,factory_input_sha256,factory_output_sha256,factory_output_size,factory_artifact_key,factory_evidence_sha256
      FROM build_images ORDER BY architecture,is_default DESC,enabled DESC,created_at DESC`);
  } catch (cause) {
    const nested = cause instanceof Error && cause.cause instanceof Error ? cause.cause.message : '';
    if (!(cause instanceof Error) || !/no such column/i.test(`${cause.message} ${nested}`)) throw cause;
    const rows = await query<BuildImage>(env.DB, `SELECT id,label,image_ref,architecture,mirror,enabled,is_default,created_actor,created_at
      FROM build_images ORDER BY architecture,is_default DESC,enabled DESC,created_at DESC`);
    return rows.map((row) => ({ ...row, origin: 'legacy' as const }));
  }
}

export async function getDefaultBuildImages(env: BuildImageEnvironment): Promise<DefaultBuildImages> {
  const rows = await query<Pick<BuildImage, 'architecture' | 'image_ref'>>(env.DB,
    'SELECT architecture,image_ref FROM build_images WHERE enabled=1 AND is_default=1');

  return Object.fromEntries(rows.map((row) => [row.architecture, row.image_ref])) as DefaultBuildImages;
}

export async function registerBuildImage(env: BuildImageEnvironment, actor: Actor | null, input: unknown): Promise<{ id: string }> {
  const admin = requireAdmin(actor);
  const value = registerInput(input);
  const imageIdValue = id();

  try {
    await env.DB.batch([
      env.DB.prepare(`INSERT INTO build_images
        (id,label,image_ref,architecture,mirror,enabled,is_default,created_actor,created_at)
        VALUES(?,?,?,?,?,0,0,?,?)`).bind(
        imageIdValue, value.label, value.image_ref, value.architecture, value.mirror, admin.id, now(),
      ),
      audit(env.DB, admin.id, 'build_image.registered', imageIdValue, {
        label: value.label, imageRef: value.image_ref, architecture: value.architecture, mirror: value.mirror,
      }),
    ]);
  } catch (cause) {
    const failure = constraintFailure(cause);

    if (failure) throw failure;
    throw cause;
  }

  return { id: imageIdValue };
}

function activationRecord(value: unknown): { artifact: { key: string; sha256: string; size: number; filename: string }; evidence: Record<string, unknown>; evidenceSha256: string } {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new PolicyError(409, 'Factory image output evidence is missing.');
  const object = value as { artifact?: unknown; evidence?: unknown; evidenceSha256?: unknown };
  if (!object.artifact || typeof object.artifact !== 'object' || Array.isArray(object.artifact) || !object.evidence || typeof object.evidence !== 'object' || Array.isArray(object.evidence) || typeof object.evidenceSha256 !== 'string' || !/^[a-f0-9]{64}$/.test(object.evidenceSha256)) throw new PolicyError(409, 'Factory image output evidence is incomplete.');
  const artifact = object.artifact as Record<string, unknown>;
  if (typeof artifact.key !== 'string' || typeof artifact.sha256 !== 'string' || !/^[a-f0-9]{64}$/.test(artifact.sha256) || !Number.isSafeInteger(artifact.size) || (artifact.size as number) <= 0 || typeof artifact.filename !== 'string') throw new PolicyError(409, 'Factory image artifact evidence is invalid.');
  return { artifact: { key: artifact.key, sha256: artifact.sha256, size: artifact.size as number, filename: artifact.filename }, evidence: object.evidence as Record<string, unknown>, evidenceSha256: object.evidenceSha256 };
}

async function assertFactoryImageContract(db: D1Database, image: Pick<BuildImage, 'origin' | 'factory_run_id' | 'factory_attempt' | 'factory_input_sha256' | 'factory_output_sha256' | 'factory_output_size' | 'factory_artifact_key' | 'factory_evidence_sha256' | 'image_ref' | 'architecture'>): Promise<void> {
  if (image.origin !== 'factory') return;
  if (!image.factory_run_id || image.factory_attempt === null || image.factory_attempt === undefined || !image.factory_input_sha256 || !image.factory_output_sha256 || !image.factory_output_size || !image.factory_artifact_key || !image.factory_evidence_sha256) throw new PolicyError(409, 'Factory image activation contract is incomplete.');
  const artifact = await reuseSuccessfulFactoryArtifact(db, image.factory_run_id, { inputSha256: image.factory_input_sha256 });
  if (!artifact || artifact.attempt !== image.factory_attempt) throw new PolicyError(409, 'Factory image activation requires a successful exact run attempt.');
  const saved = activationRecord(artifact.artifact);
  if (saved.artifact.key !== image.factory_artifact_key || saved.artifact.sha256 !== image.factory_output_sha256 || saved.artifact.size !== image.factory_output_size || saved.evidenceSha256 !== image.factory_evidence_sha256) throw new PolicyError(409, 'Factory image output or evidence changed after registration.');
  const imageRef = saved.evidence.imageRef;
  if (typeof imageRef !== 'string' || imageRef !== image.image_ref || saved.evidence.architecture !== image.architecture || saved.evidence.imageKind !== 'oci') throw new PolicyError(409, 'Factory image evidence does not bind this OCI image.');
}

async function buildImageForControl(db: D1Database, imageIdValue: string): Promise<BuildImage | null> {
  try {
    return await db.prepare('SELECT id,architecture,enabled,is_default,origin,factory_run_id,factory_attempt,factory_input_sha256,factory_output_sha256,factory_output_size,factory_artifact_key,factory_evidence_sha256,image_ref FROM build_images WHERE id=?').bind(imageIdValue).first<BuildImage>();
  } catch (cause) {
    if (!(cause instanceof Error) || !/no such column/i.test(cause.message)) throw cause;
    return db.prepare('SELECT id,architecture,enabled,is_default,image_ref FROM build_images WHERE id=?').bind(imageIdValue).first<BuildImage>();
  }
}

/** Register an OCI image only from a successful signed private factory run. */
export async function registerFactoryBuildImage(env: BuildImageEnvironment, actor: Actor | null, input: RegisterFactoryBuildImageInput): Promise<{ id: string }> {
  const admin = requireAdmin(actor);
  const runId = text(input.runId, 'factory run ID', 256);
  const runArtifact = await reuseSuccessfulFactoryArtifact(env.DB, runId);
  if (!runArtifact) throw new PolicyError(409, 'Factory image registration requires a successful private run.');
  const saved = activationRecord(runArtifact.artifact);
  const imageRef = saved.evidence.imageRef;
  if (saved.evidence.imageKind !== 'oci' || typeof imageRef !== 'string' || !IMAGE_REF.test(imageRef)) throw new PolicyError(409, 'Successful factory run does not contain a pinned OCI image contract.');
  const arch = saved.evidence.architecture;
  if (arch !== 'x86_64' && arch !== 'aarch64') throw new PolicyError(409, 'Factory image evidence architecture is invalid.');
  const attempt = await getFactoryAttempt(env.DB, runId, runArtifact.attempt);
  if (!attempt || attempt.status !== 'succeeded' || attempt.inputSha256 !== saved.evidence.inputSha256) throw new PolicyError(409, 'Factory image attempt evidence is stale or incomplete.');
  const value = { label: text(input.label, 'image label', 120), image_ref: imageRef, architecture: arch as Architecture, mirror: mirror(input.mirror) };
  const imageIdValue = id();
  try {
    await env.DB.batch([
      env.DB.prepare(`INSERT INTO build_images(id,label,image_ref,architecture,mirror,enabled,is_default,created_actor,created_at,origin,factory_run_id,factory_attempt,factory_input_sha256,factory_output_sha256,factory_output_size,factory_artifact_key,factory_evidence_sha256)
        VALUES(?,?,?,?,?,0,0,?,?,?,?,?,?,?,?,?,?)`).bind(imageIdValue, value.label, value.image_ref, value.architecture, value.mirror, admin.id, now(), 'factory', runId, runArtifact.attempt, attempt.inputSha256, saved.artifact.sha256, saved.artifact.size, saved.artifact.key, saved.evidenceSha256),
      audit(env.DB, admin.id, 'build_image.factory_registered', imageIdValue, { runId, attempt: runArtifact.attempt, imageRef, inputSha256: attempt.inputSha256, outputSha256: saved.artifact.sha256, evidenceSha256: saved.evidenceSha256 }),
    ]);
  } catch (cause) { const failure = constraintFailure(cause); if (failure) throw failure; throw cause; }
  return { id: imageIdValue };
}

export async function setBuildImageEnabled(env: BuildImageEnvironment, actor: Actor | null, value: unknown, enabled: boolean): Promise<void> {
  const admin = requireAdmin(actor);
  const imageIdValue = imageId(value);
  const existing = await buildImageForControl(env.DB, imageIdValue);

  if (!existing) throw new PolicyError(404, 'Build image not found.');
  try { await assertFactoryImageContract(env.DB, existing); } catch (cause) { if (existing.origin === 'factory') throw cause; }
  await env.DB.batch([
    env.DB.prepare(`UPDATE build_images SET enabled=?,is_default=CASE WHEN ?=0 THEN 0 ELSE is_default END WHERE id=?`)
      .bind(enabled ? 1 : 0, enabled ? 1 : 0, imageIdValue),
    audit(env.DB, admin.id, enabled ? 'build_image.enabled' : 'build_image.disabled', imageIdValue, { enabled }),
  ]);
}

export async function setDefaultBuildImage(env: BuildImageEnvironment, actor: Actor | null, value: unknown): Promise<void> {
  const admin = requireAdmin(actor);
  const imageIdValue = imageId(value);

  const image = await buildImageForControl(env.DB, imageIdValue);

  if (!image) throw new PolicyError(404, 'Build image not found.');

  if (image.enabled !== 1) throw new PolicyError(409, 'Enable this image before choosing it as the default.');
  try { await assertFactoryImageContract(env.DB, image); } catch (cause) { if (image.origin === 'factory') throw cause; }

  try {
    await env.DB.batch([
      env.DB.prepare('UPDATE build_images SET is_default=0 WHERE architecture=? AND is_default=1').bind(image.architecture),
      env.DB.prepare('UPDATE build_images SET is_default=1 WHERE id=? AND enabled=1').bind(imageIdValue),
      audit(env.DB, admin.id, 'build_image.default_changed', imageIdValue, { architecture: image.architecture }),
    ]);
  } catch (cause) {
    const failure = constraintFailure(cause);

    if (failure) throw failure;
    throw cause;
  }
}
