import type { Actor, Architecture } from '../model';
import type { Env } from './env';
import { audit, id, now, query } from './db';
import { PolicyError } from './policy';

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
}

export interface RegisterBuildImageInput {
  label: string;
  image_ref: string;
  architecture: Architecture;
  mirror: BuildImageMirror;
}

export type BuildImageEnvironment = Pick<Env, 'DB'>;
export type DefaultBuildImages = Partial<Record<Architecture, string>>;

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
  return query<BuildImage>(env.DB, `SELECT id,label,image_ref,architecture,mirror,enabled,is_default,created_actor,created_at
    FROM build_images ORDER BY architecture,is_default DESC,enabled DESC,created_at DESC`);
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

export async function setBuildImageEnabled(env: BuildImageEnvironment, actor: Actor | null, value: unknown, enabled: boolean): Promise<void> {
  const admin = requireAdmin(actor);
  const imageIdValue = imageId(value);
  const existing = await env.DB.prepare('SELECT id FROM build_images WHERE id=?').bind(imageIdValue).first<{ id: string }>();
  if (!existing) throw new PolicyError(404, 'Build image not found.');
  await env.DB.batch([
    env.DB.prepare(`UPDATE build_images SET enabled=?,is_default=CASE WHEN ?=0 THEN 0 ELSE is_default END WHERE id=?`)
      .bind(enabled ? 1 : 0, enabled ? 1 : 0, imageIdValue),
    audit(env.DB, admin.id, enabled ? 'build_image.enabled' : 'build_image.disabled', imageIdValue, { enabled }),
  ]);
}

export async function setDefaultBuildImage(env: BuildImageEnvironment, actor: Actor | null, value: unknown): Promise<void> {
  const admin = requireAdmin(actor);
  const imageIdValue = imageId(value);
  const image = await env.DB.prepare('SELECT id,architecture,enabled FROM build_images WHERE id=?')
    .bind(imageIdValue).first<Pick<BuildImage, 'id' | 'architecture' | 'enabled'>>();
  if (!image) throw new PolicyError(404, 'Build image not found.');
  if (image.enabled !== 1) throw new PolicyError(409, 'Enable this image before choosing it as the default.');
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
