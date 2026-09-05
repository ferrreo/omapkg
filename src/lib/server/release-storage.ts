import { PolicyError } from './policy';
import type { Architecture } from '../model';
import type { Env } from './env';
import { sha256 } from './db';
import { createHash } from 'node:crypto';

export const SHA256 = /^[a-f0-9]{64}$/;

export const BASE64 = /^[A-Za-z0-9+/]+={0,2}$/;

export const SAFE_KEY = /^(?!\/)(?!.*(?:^|\/)\.\.(?:\/|$))[\x21-\x7e]{1,1024}$/;

const MCP_RELEASE_ID = /^[A-Za-z0-9_-]{1,128}$/;

const MAX_PACKAGE_BYTES = 4 * 1024 * 1024 * 1024;

export function fail(status: number, message: string): never {
  throw new PolicyError(status, message);
}

export function safeKey(value: string, label = 'object key'): string {
  if (!SAFE_KEY.test(value)) fail(409, `Invalid ${label}.`);
  return value;
}

export function safeId(value: string, label = 'release ID'): string {
  if (typeof value !== 'string' || !MCP_RELEASE_ID.test(value)) fail(400, `Invalid ${label}.`);
  return value;
}

export function jsonObject(value: string, label: string): Record<string, unknown> {
  try {
    const parsed: unknown = JSON.parse(value);
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) fail(409, `${label} must be a JSON object.`);
    return parsed as Record<string, unknown>;
  } catch (cause) {
    if (cause instanceof PolicyError) throw cause;
    fail(409, `${label} is invalid.`);
  }
}

export function jsonArray(value: string, label: string): unknown[] {
  try {
    const parsed: unknown = JSON.parse(value);
    if (!Array.isArray(parsed)) fail(409, `${label} must be a JSON array.`);
    return parsed;
  } catch (cause) {
    if (cause instanceof PolicyError) throw cause;
    fail(409, `${label} is invalid.`);
  }
}

export function segment(value: string): string {
  return encodeURIComponent(value).replaceAll('%2F', '%252F');
}

export function packageKey(architecture: Architecture, filename: string): string {
  return `packages/${architecture}/${filename}`;
}

export function recipeKey(name: string, version: string, architecture: Architecture): string {
  return `recipes/${segment(name)}/${segment(version)}/${architecture}/PKGBUILD`;
}

export function metadataKey(releaseId: string, type: 'sbom' | 'provenance'): string {
  return `metadata/releases/${releaseId}/${type}.json`;
}

export function publicOrigin(env: Env): string {
  let value: URL;
  try { value = new URL(env.PUBLIC_ORIGIN); }
  catch { fail(503, 'A public HTTPS origin is required for rollback instructions.'); }
  const local = ['localhost', '127.0.0.1', '[::1]'].includes(value.hostname);
  if ((!local && value.protocol !== 'https:') || (local && value.protocol !== 'https:' && value.protocol !== 'http:') || value.username || value.password || value.search || value.hash) {
    fail(503, 'A public HTTPS origin is required for rollback instructions.');
  }
  return value.toString().replace(/\/$/, '');
}

export function base64(value: ArrayBuffer | Uint8Array): string {
  const bytes = value instanceof Uint8Array ? value : new Uint8Array(value);
  let output = '';
  for (let offset = 0; offset < bytes.length; offset += 0x8000) {
    output += String.fromCharCode(...bytes.subarray(offset, offset + 0x8000));
  }
  return btoa(output);
}

export function decodeBase64(value: string, expectedBytes: number, label: string): Uint8Array {
  if (!BASE64.test(value) || value.length % 4 === 1) fail(409, `${label} is invalid.`);
  try {
    const bytes = Uint8Array.from(atob(value), (character) => character.charCodeAt(0));
    if (bytes.byteLength !== expectedBytes) fail(409, `${label} has an invalid length.`);
    return bytes;
  } catch {
    fail(409, `${label} is invalid.`);
  }
}

export async function immutableText(env: Env, key: string, text: string, contentType: string): Promise<string> {
  const bytes = new TextEncoder().encode(text);
  const digest = await sha256(bytes);
  await immutableBytes(env, key, bytes, digest, contentType);
  return key;
}

export async function immutableBytes(env: Env, key: string, bytes: Uint8Array, digest: string, contentType: string) {
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

export async function verifyR2Object(env: Env, key: string, digest: string, size: number): Promise<void> {
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

export async function verifySignatureObject(env: Env, key: string): Promise<void> {
  safeKey(key);
  const object = await env.ARTIFACTS.get(key);
  if (!object?.body) fail(409, 'Package signature is missing from immutable storage.');
  const actual = await hashR2Body(object.body, key, 16 * 1024);
  if (actual.size === 0) fail(409, 'Package signature is empty.');
}

export async function copyVerifiedObject(env: Env, sourceKey: string, targetKey: string, digest: string, size: number, contentType: string): Promise<void> {
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
