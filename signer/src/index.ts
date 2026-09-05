import { signingURL } from '../../src/lib/signing-url';
import * as openpgp from 'openpgp';
import { createHash } from 'node:crypto';

const MAX_INTENT_BYTES = 8 * 1024;
const DEFAULT_MAX_ARTIFACT_BYTES = 4 * 1024 * 1024 * 1024;
const SHA256 = /^[0-9a-f]{64}$/;
const ID = /^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/;
const FILENAME = /^[A-Za-z0-9][A-Za-z0-9._+@%=-]{0,254}$/;
const DATABASE_SUFFIXES = [
  '.db', '.files',
  '.db.tar.zst', '.db.tar.xz', '.db.tar.gz', '.db.tar.bz2',
  '.files.tar.zst', '.files.tar.xz', '.files.tar.gz', '.files.tar.bz2',
];

export interface Env {
  ARTIFACTS: R2Bucket;
  CONTROL_ORIGIN: string;
  PUBLIC_ORIGIN: string;
  KEY_ID: string;
  SIGNING_MODE?: string;
  KMS_SIGNER_URL?: string;
  KMS_SIGNER_TOKEN?: string;
  PUBLIC_KEY_KEY?: string;
  MAX_ARTIFACT_BYTES?: string;
  SIGNER_TOKEN: string;
  CONTROL_TOKEN: string;
  OPR_SIGNING_PRIVATE_KEY_B64: string;
  OPR_SIGNING_FINGERPRINT?: string;
}

type SignKind = 'package' | 'database';

interface SignIntent {
  id: string;
  status: 'ready' | 'signed';
  kind: SignKind;
  expiresAt: number;
  keyFingerprint?: string;
  artifact: {
    key: string;
    sha256: string;
    size: number;
    filename: string;
  };
  build: {
    id: string;
    revisionId: string;
    status: string;
    surface: string;
    architecture: string;
    workerId?: string;
    smokePassed: boolean;
  };
  review: {
    manifestSha256: string;
    areaApproved: boolean;
    securityApproved: boolean;
  };
  attestation: {
    provenance: string;
    provenanceSignature: string;
    workerPublicKey: string;
  };
  signature?: { key: string; sha256: string; filename: string };
}

interface Provenance {
  buildId: string;
  revisionId: string;
  workerId: string;
  recipeSha256: string;
  artifactSha256: string;
  architecture: string;
  imageDigest: string;
  sourceDateEpoch: number;
  network: string;
  startedAt: string;
  finishedAt: string;
}

interface SignRequest { intentId: string }

interface Identity {
  privateKey?: openpgp.PrivateKey;
  publicKey: openpgp.PublicKey;
  armored: string;
  fingerprint: string;
  mode: 'cloudflare-worker-secret' | 'managed-kms';
}

let identityPromise: Promise<Identity> | undefined;
let identityCacheKey: string | undefined;

function json(data: unknown, status = 200, headers: HeadersInit = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8', ...headers },
  });
}

function errorResponse(status: number, message: string) {
  return json({ error: message }, status);
}

async function fetchNoRedirect(input: RequestInfo | URL, init: RequestInit = {}): Promise<Response> {
  const response = await fetch(input, { ...init, redirect: 'manual' });
  if (response.status >= 300 && response.status < 400) throw new Error('redirect rejected');
  return response;
}

function decodeBase64(value: string, field: string): Uint8Array {
  let binary: string;
  try { binary = atob(value); }
  catch { throw new Error(`${field} is not valid base64`); }
  const bytes = Uint8Array.from(binary, (char) => char.charCodeAt(0));
  return bytes;
}

function hex(bytes: ArrayBuffer | Uint8Array): string {
  return Array.from(new Uint8Array(bytes), (byte) => byte.toString(16).padStart(2, '0')).join('');
}

function maxArtifactBytes(env: Env): number {
  const value = Number(env.MAX_ARTIFACT_BYTES ?? DEFAULT_MAX_ARTIFACT_BYTES);
  if (!Number.isSafeInteger(value) || value <= 0) throw new Error('MAX_ARTIFACT_BYTES must be a positive integer');
  return value;
}

function signingMode(env: Env): 'cloudflare-worker-secret' | 'managed-kms' {
  if (env.SIGNING_MODE === 'managed-kms' || env.SIGNING_MODE === 'managedKMS') return 'managed-kms';
  if (env.SIGNING_MODE && env.SIGNING_MODE !== 'cloudflare-worker-secret') throw new Error('SIGNING_MODE is invalid');
  return 'cloudflare-worker-secret';
}

async function constantTimeEqual(left: string, right: string): Promise<boolean> {
  const [a, b] = await Promise.all([
    crypto.subtle.digest('SHA-256', new TextEncoder().encode(left)),
    crypto.subtle.digest('SHA-256', new TextEncoder().encode(right)),
  ]);
  const aa = new Uint8Array(a);
  const bb = new Uint8Array(b);
  let difference = 0;
  for (let index = 0; index < aa.length; index += 1) difference |= aa[index] ^ bb[index];
  return difference === 0;
}

async function authorized(request: Request, env: Env): Promise<boolean> {
  const header = request.headers.get('authorization') ?? '';
  if (!header.startsWith('Bearer ')) return false;
  return constantTimeEqual(header.slice('Bearer '.length), env.SIGNER_TOKEN);
}

async function getIdentity(env: Env): Promise<Identity> {
  const mode = signingMode(env);
  let privateKey: openpgp.PrivateKey | undefined;
  let publicKey: openpgp.PublicKey;
  let armored: string;
  if (mode === 'managed-kms') {
    if (!env.KMS_SIGNER_TOKEN) throw new Error('managed KMS signer token is not configured');
    const response = await fetchNoRedirect(signingURL(env.KMS_SIGNER_URL, 'KMS_SIGNER_URL', '/v1/public-key'), {
      headers: { authorization: `Bearer ${env.KMS_SIGNER_TOKEN}`, accept: 'application/json' },
    });
    if (!response.ok) throw new Error(`managed KMS signer returned ${response.status}`);
    const body = await response.arrayBuffer();
    if (body.byteLength > 128 * 1024) throw new Error('managed KMS public key response is too large');
    let result: { publicKey?: unknown; fingerprint?: unknown };
    try { result = JSON.parse(new TextDecoder().decode(body)) as { publicKey?: unknown; fingerprint?: unknown }; }
    catch { throw new Error('managed KMS public key response is invalid'); }
    if (typeof result.publicKey !== 'string' || typeof result.fingerprint !== 'string') throw new Error('managed KMS public key evidence is incomplete');
    armored = result.publicKey;
    publicKey = await openpgp.readKey({ armoredKey: armored });
    if (publicKey.getFingerprint().toLowerCase() !== result.fingerprint.toLowerCase()) throw new Error('managed KMS public key fingerprint mismatch');
  } else {
    if (!env.OPR_SIGNING_PRIVATE_KEY_B64) throw new Error('signing key is not configured');
    armored = new TextDecoder().decode(decodeBase64(env.OPR_SIGNING_PRIVATE_KEY_B64, 'OPR_SIGNING_PRIVATE_KEY_B64'));
    privateKey = await openpgp.readPrivateKey({ armoredKey: armored });
    publicKey = privateKey.toPublic();
  }
  const fingerprint = publicKey.getFingerprint().toLowerCase();
  if (!/^[0-9a-f]{40}$/.test(fingerprint)) throw new Error('signing key must be an OpenPGP v4 key');
  if (env.OPR_SIGNING_FINGERPRINT && env.OPR_SIGNING_FINGERPRINT.toLowerCase() !== fingerprint) {
    throw new Error('configured signing fingerprint does not match private key');
  }
  const primary = publicKey.toPacketList()[0] as { version?: number; algorithm?: number };
  if (primary.version !== 4 || primary.algorithm !== openpgp.enums.publicKey.rsaEncryptSign) {
    throw new Error('signing key must be an RSA v4 key');
  }
  return { privateKey, publicKey, armored: mode === 'managed-kms' ? armored : publicKey.armor(), fingerprint, mode };
}

function getIdentityCached(env: Env): Promise<Identity> {
  const key = `${signingMode(env)}|${env.KMS_SIGNER_URL ?? ''}|${env.OPR_SIGNING_FINGERPRINT ?? ''}|${env.OPR_SIGNING_PRIVATE_KEY_B64?.slice(0, 32) ?? ''}`;
  if (!identityPromise || identityCacheKey !== key) {
    identityCacheKey = key;
    identityPromise = getIdentity(env);
  }
  return identityPromise;
}

function assertIntentShape(intent: SignIntent, now: number, maxBytes: number, identity: Identity): void {
  if (!intent || intent.id === undefined || !ID.test(intent.id)) throw new Error('invalid signing intent identity');
  if (intent.status !== 'ready' && intent.status !== 'signed') throw new Error('signing intent is not active');
  if (intent.status === 'ready' && (!Number.isSafeInteger(intent.expiresAt) || intent.expiresAt <= now)) throw new Error('signing intent expired');
  if (intent.kind !== 'package' && intent.kind !== 'database') throw new Error('invalid signing object kind');
  if (!intent.keyFingerprint || intent.keyFingerprint.toLowerCase() !== identity.fingerprint) {
    throw new Error('signing key fingerprint mismatch');
  }
  const artifact = intent.artifact;
  if (!artifact || !artifact.key || artifact.key.length > 512 || artifact.key.startsWith('/') || artifact.key.includes('\u0000') || artifact.key.split('/').some((part) => part === '..')) {
    throw new Error('invalid artifact key');
  }
  if (!SHA256.test(artifact.sha256) || !Number.isSafeInteger(artifact.size) || artifact.size <= 0 || artifact.size > maxBytes) {
    throw new Error('invalid artifact digest or size');
  }
  if (!FILENAME.test(artifact.filename) || artifact.filename.includes('/') || artifact.filename === '.' || artifact.filename === '..') {
    throw new Error('invalid artifact filename');
  }
  if (intent.kind === 'package' && !artifact.filename.endsWith('.pkg.tar.zst')) throw new Error('package signature requires a .pkg.tar.zst file');
  if (intent.kind === 'database' && !DATABASE_SUFFIXES.some((suffix) => artifact.filename.endsWith(suffix))) {
    throw new Error('database signature requires an Arch repository database filename');
  }
  const build = intent.build;
  if (!build || !ID.test(build.id) || !build.revisionId || build.status !== 'succeeded' || build.surface !== 'binary' || build.smokePassed !== true) {
    throw new Error('build is not an attested successful binary build');
  }
  if (build.architecture !== 'x86_64' && build.architecture !== 'aarch64') throw new Error('invalid build architecture');
  if (intent.status === 'signed') {
    if (!intent.signature || !SHA256.test(intent.signature.sha256) || intent.signature.key !== `${artifact.key}.sig` || intent.signature.filename !== `${artifact.filename}.sig`) {
      throw new Error('signed intent has incomplete signature evidence');
    }
    return;
  }
  if (!intent.review || !SHA256.test(intent.review.manifestSha256) || intent.review.areaApproved !== true || intent.review.securityApproved !== true) {
    throw new Error('build review gates are incomplete');
  }
  const attestation = intent.attestation;
  if (!attestation?.provenance || !attestation.provenanceSignature || !attestation.workerPublicKey) throw new Error('build attestation is missing');
  let provenance: Provenance;
  try { provenance = JSON.parse(attestation.provenance) as Provenance; }
  catch { throw new Error('build provenance is not valid JSON'); }
  if (provenance.buildId !== build.id || provenance.revisionId !== build.revisionId ||
      provenance.architecture !== build.architecture || provenance.network !== 'disabled' || !provenance.workerId ||
      !SHA256.test(provenance.recipeSha256) || !/^sha256:[0-9a-f]{64}$/.test(provenance.imageDigest) ||
      !Number.isSafeInteger(provenance.sourceDateEpoch) || provenance.sourceDateEpoch < 0 ||
      !Number.isFinite(Date.parse(provenance.startedAt)) || !Number.isFinite(Date.parse(provenance.finishedAt))) {
    throw new Error('build provenance does not match reviewed inputs');
  }
  if (!SHA256.test(provenance.artifactSha256) || (intent.kind === 'package' && provenance.artifactSha256 !== artifact.sha256)) {
    throw new Error('build provenance artifact digest does not match reviewed inputs');
  }
  if (build.workerId && build.workerId !== provenance.workerId) throw new Error('build worker does not match provenance');
}

async function verifyAttestation(intent: SignIntent): Promise<void> {
  const publicKey = decodeBase64(intent.attestation.workerPublicKey, 'workerPublicKey');
  const signature = decodeBase64(intent.attestation.provenanceSignature, 'provenanceSignature');
  if (publicKey.byteLength !== 32 || signature.byteLength !== 64) throw new Error('invalid worker attestation key or signature');
  const key = await crypto.subtle.importKey('raw', publicKey as unknown as BufferSource, { name: 'Ed25519' }, false, ['verify']);
  const valid = await crypto.subtle.verify('Ed25519', key, signature as unknown as BufferSource, new TextEncoder().encode(intent.attestation.provenance) as unknown as BufferSource);
  if (!valid) throw new Error('worker provenance signature is invalid');
}

async function drainReader(body: ReadableStream<Uint8Array>): Promise<void> {
  const reader = body.getReader();
  try {
    while (!(await reader.read()).done) { /* consume stream without buffering artifact bytes */ }
  } finally {
    reader.releaseLock();
  }
}

async function fetchIntent(request: Request, env: Env, intentId: string): Promise<SignIntent> {
  const url = signingURL(env.CONTROL_ORIGIN, 'CONTROL_ORIGIN', `/api/internal/signing-intents/${encodeURIComponent(intentId)}`);
  const response = await fetchNoRedirect(url, {
    headers: { authorization: `Bearer ${env.CONTROL_TOKEN}`, accept: 'application/json' },
    signal: request.signal,
  });
  if (!response.ok) throw new Error(`control plane returned ${response.status}`);
  const body = await response.arrayBuffer();
  if (body.byteLength > 1 << 20) throw new Error('control response is too large');
  try { return JSON.parse(new TextDecoder().decode(body)) as SignIntent; }
  catch { throw new Error('control response is not valid JSON'); }
}

function boundedBody(body: ReadableStream<Uint8Array>, maximum: number, count: { value: number }): ReadableStream<Uint8Array> {
  return body.pipeThrough(new TransformStream<Uint8Array, Uint8Array>({
    transform(chunk, controller) {
      count.value += chunk.byteLength;
      if (count.value > maximum) {
        controller.error(new Error('artifact exceeds configured size limit'));
        return;
      }
      controller.enqueue(chunk);
    },
  }));
}

async function streamDigest(body: ReadableStream<Uint8Array>): Promise<string> {
  const hash = createHash('sha256');
  const reader = body.getReader();
  try {
    while (true) {
      const next = await reader.read();
      if (next.done) break;
      hash.update(next.value);
    }
  } finally {
    reader.releaseLock();
  }
  return hash.digest('hex');
}

interface DigestedBody {
  body: ReadableStream<Uint8Array>;
  digest: Promise<string>;
  cancel: (reason: unknown) => Promise<void>;
}

function digestAndForward(body: ReadableStream<Uint8Array>): DigestedBody {
  const hash = createHash('sha256');
  const reader = body.getReader();
  let resolveDigest!: (value: string | PromiseLike<string>) => void;
  let rejectDigest!: (reason?: unknown) => void;
  const digest = new Promise<string>((resolve, reject) => {
    resolveDigest = resolve;
    rejectDigest = reject;
  });
  let complete = false;
  let outputController: ReadableStreamDefaultController<Uint8Array> | undefined;

  async function fail(cause: unknown): Promise<void> {
    if (complete) return;
    complete = true;
    try { await reader.cancel(cause); } catch { /* stream is already closed */ }
    reader.releaseLock();
    rejectDigest(cause);
    outputController?.error(cause);
  }

  const forwarded = new ReadableStream<Uint8Array>({
    start(controller) {
      outputController = controller;
    },
    async pull(controller) {
      try {
        const next = await reader.read();
        if (complete) return;
        if (next.done) {
          reader.releaseLock();
          const value = hash.digest('hex');
          complete = true;
          resolveDigest(value);
          controller.close();
          return;
        }
        hash.update(next.value);
        controller.enqueue(next.value);
      } catch (cause) {
        await fail(cause);
        controller.error(cause);
      }
    },
    async cancel(reason) {
      await fail(reason);
    },
  });
  return { body: forwarded, digest, cancel: fail };
}

async function cancelDigestedBody(body: DigestedBody, reason: unknown): Promise<void> {
  await body.cancel(reason).catch(() => undefined);
  await body.digest.catch(() => undefined);
}

async function readSignatureStream(value: Uint8Array | ReadableStream<Uint8Array>): Promise<Uint8Array> {
  if (value instanceof Uint8Array) return value;
  return new Uint8Array(await new Response(value).arrayBuffer());
}

async function signArtifact(env: Env, intent: SignIntent, identity: Identity): Promise<{ bytes: Uint8Array; artifactSha256: string; artifactSize: number }> {
  if (!identity.privateKey) throw new Error('local signing key is not configured');
  const object = await env.ARTIFACTS.get(intent.artifact.key);
  if (!object) throw new Error('artifact was not found');
  if (object.size !== intent.artifact.size) throw new Error('artifact size changed');
  const count = { value: 0 };
  const bounded = boundedBody(object.body, maxArtifactBytes(env), count);
  const digested = digestAndForward(bounded);
  try {
    const message = await openpgp.createMessage({ binary: digested.body });
    const signatureTask = openpgp.sign({
      message,
      signingKeys: identity.privateKey,
      detached: true,
      format: 'binary',
      config: { v6Keys: false, preferredHashAlgorithm: openpgp.enums.hash.sha256 },
    });
    const [artifactSha256, signature] = await Promise.all([digested.digest, signatureTask]);
    if (count.value !== intent.artifact.size || artifactSha256 !== intent.artifact.sha256) throw new Error('artifact hash changed');
    const bytes = await readSignatureStream(signature);
    if (!bytes.byteLength || bytes.byteLength > 1 << 20) throw new Error('generated signature has invalid size');
    return { bytes, artifactSha256, artifactSize: count.value };
  } catch (cause) {
    await cancelDigestedBody(digested, cause);
    throw cause;
  }
}

interface ManagedSignatureResponse {
  mode?: unknown;
  artifactSha256?: unknown;
  artifactSize?: unknown;
  signatureBase64?: unknown;
  signatureSha256?: unknown;
  publicKey?: unknown;
  fingerprint?: unknown;
}

async function signArtifactManaged(request: Request, env: Env, intent: SignIntent, identity: Identity): Promise<{ bytes: Uint8Array; artifactSha256: string; artifactSize: number }> {
  if (!env.KMS_SIGNER_TOKEN) throw new Error('managed KMS signer token is not configured');
  const object = await env.ARTIFACTS.get(intent.artifact.key);
  if (!object) throw new Error('artifact was not found');
  if (object.size !== intent.artifact.size) throw new Error('artifact size changed');
  const count = { value: 0 };
  const bounded = boundedBody(object.body, maxArtifactBytes(env), count);
  const digested = digestAndForward(bounded);
  let response: Response;
  try {
    response = await fetchNoRedirect(signingURL(env.KMS_SIGNER_URL, 'KMS_SIGNER_URL', '/v1/sign'), {
      method: 'POST',
      headers: { authorization: `Bearer ${env.KMS_SIGNER_TOKEN}`, 'content-type': 'application/octet-stream' },
      body: digested.body,
      signal: request.signal,
    });
  } catch (cause) {
    await cancelDigestedBody(digested, cause);
    throw cause;
  }
  if (!response.ok) {
    const cause = new Error(`managed KMS signer returned ${response.status}`);
    await cancelDigestedBody(digested, cause);
    throw cause;
  }
  let artifactSha256: string;
  try {
    artifactSha256 = await digested.digest;
  } catch (cause) {
    await cancelDigestedBody(digested, cause);
    throw cause;
  }
  const body = await response.arrayBuffer();
  if (body.byteLength > 128 * 1024) throw new Error('managed KMS signature response is too large');
  let result: ManagedSignatureResponse;
  try { result = JSON.parse(new TextDecoder().decode(body)) as ManagedSignatureResponse; }
  catch { throw new Error('managed KMS signature response is invalid'); }
  if (result.mode !== 'managed-kms' || result.artifactSha256 !== artifactSha256 || result.artifactSize !== count.value ||
      typeof result.signatureBase64 !== 'string' || typeof result.signatureSha256 !== 'string' || typeof result.publicKey !== 'string' ||
      typeof result.fingerprint !== 'string' || result.fingerprint.toLowerCase() !== identity.fingerprint || result.publicKey !== identity.armored) {
    throw new Error('managed KMS signature evidence does not match artifact or key');
  }
  const bytes = decodeBase64(result.signatureBase64, 'managed KMS signature');
  if (!bytes.byteLength || bytes.byteLength > 1 << 20 || !SHA256.test(result.signatureSha256) || hex(await crypto.subtle.digest('SHA-256', bytes as unknown as BufferSource)) !== result.signatureSha256) {
    throw new Error('managed KMS signature digest is invalid');
  }
  if (artifactSha256 !== intent.artifact.sha256 || count.value !== intent.artifact.size) throw new Error('artifact hash changed');
  return { bytes, artifactSha256, artifactSize: count.value };
}

async function verifySignature(env: Env, intent: SignIntent, identity: Identity, signature: Uint8Array): Promise<void> {
  const object = await env.ARTIFACTS.get(intent.artifact.key);
  if (!object) throw new Error('artifact disappeared during verification');
  if (object.size !== intent.artifact.size) throw new Error('artifact size changed during verification');
  const count = { value: 0 };
  const message = await openpgp.createMessage({ binary: boundedBody(object.body, maxArtifactBytes(env), count) });
  const parsed = await openpgp.readSignature({ binarySignature: signature });
  const result = await openpgp.verify({ message, signature: parsed, verificationKeys: identity.publicKey });
  if (!result.signatures.length) throw new Error('signature has no signer');
  if (result.data instanceof ReadableStream) await drainReader(result.data);
  await result.signatures[0].verified;
  if (count.value !== intent.artifact.size) throw new Error('artifact size changed during verification');
  await verifyArtifactHash(env, intent);
}

async function verifyArtifactHash(env: Env, intent: SignIntent): Promise<void> {
  const object = await env.ARTIFACTS.get(intent.artifact.key);
  if (!object || object.size !== intent.artifact.size) throw new Error('artifact size changed during verification');
  const count = { value: 0 };
  const digest = await streamDigest(boundedBody(object.body, maxArtifactBytes(env), count));
  if (count.value !== intent.artifact.size || digest !== intent.artifact.sha256) throw new Error('artifact hash changed during verification');
}

interface ExistingSignature {
  bytes: Uint8Array;
  sha256: string;
}

async function readExistingSignatureObject(env: Env, intent: SignIntent): Promise<ExistingSignature | null> {
  const key = `${intent.artifact.key}.sig`;
  const existing = await env.ARTIFACTS.head(key);
  if (!existing) return null;
  if (existing.customMetadata?.artifactSha256 && existing.customMetadata.artifactSha256 !== intent.artifact.sha256) {
    throw new Error('signature object already exists for different artifact bytes');
  }
  const object = await env.ARTIFACTS.get(key);
  if (!object || object.size <= 0 || object.size > 1 << 20) throw new Error('persisted signature is unavailable');
  const bytes = new Uint8Array(await object.arrayBuffer());
  const signatureSha256 = hex(await crypto.subtle.digest('SHA-256', bytes as unknown as BufferSource));
  const recorded = existing.customMetadata?.signatureSha256 ?? existing.customMetadata?.sha256;
  if (recorded && recorded !== signatureSha256) throw new Error('persisted signature digest changed');
  return { bytes, sha256: signatureSha256 };
}

async function readPersistedSignature(env: Env, intent: SignIntent): Promise<Uint8Array> {
  if (!intent.signature || intent.signature.key !== `${intent.artifact.key}.sig`) throw new Error('signed intent has no signature evidence');
  const persisted = await readExistingSignatureObject(env, intent);
  if (!persisted || persisted.sha256 !== intent.signature.sha256) throw new Error('persisted signature digest changed');
  return persisted.bytes;
}

function base64(bytes: Uint8Array): string {
  let value = '';
  for (let offset = 0; offset < bytes.length; offset += 0x8000) value += String.fromCharCode(...bytes.subarray(offset, offset + 0x8000));
  return btoa(value);
}

async function persistPublicKey(env: Env, identity: Identity): Promise<string> {
  const key = env.PUBLIC_KEY_KEY ?? 'keys/opr-package-signing.asc';
  const existing = await env.ARTIFACTS.head(key);
  if (existing) {
    if (existing.customMetadata?.fingerprint !== identity.fingerprint) throw new Error('public key object fingerprint mismatch');
    return key;
  }
  await env.ARTIFACTS.put(key, identity.armored, {
    httpMetadata: { contentType: 'application/pgp-keys; charset=utf-8', cacheControl: 'public, max-age=31536000, immutable' },
    customMetadata: { fingerprint: identity.fingerprint, keyId: env.KEY_ID },
  });
  return key;
}

async function persistSignature(env: Env, intent: SignIntent, identity: Identity, bytes: Uint8Array): Promise<{ key: string; sha256: string; filename: string }> {
  const key = `${intent.artifact.key}.sig`;
  const signatureSha256 = hex(await crypto.subtle.digest('SHA-256', bytes as unknown as BufferSource));
  const existing = await env.ARTIFACTS.head(key);
  if (existing) {
    const persisted = await readExistingSignatureObject(env, intent);
    if (!persisted) throw new Error('signature object disappeared during verification');
    await verifySignature(env, intent, identity, persisted.bytes);
    return { key, sha256: persisted.sha256, filename: `${intent.artifact.filename}.sig` };
  } else {
    await env.ARTIFACTS.put(key, bytes, {
      httpMetadata: { contentType: 'application/octet-stream', cacheControl: 'public, max-age=31536000, immutable' },
      customMetadata: {
        intentId: intent.id,
        artifactSha256: intent.artifact.sha256,
        sha256: signatureSha256,
        signatureSha256,
        fingerprint: identity.fingerprint,
        keyId: env.KEY_ID,
      },
    });
  }
  return { key, sha256: signatureSha256, filename: `${intent.artifact.filename}.sig` };
}

async function recordAudit(env: Env, intent: SignIntent, identity: Identity, signature: { key: string; sha256: string; filename: string }, publicKeyKey: string): Promise<void> {
  const url = signingURL(env.CONTROL_ORIGIN, 'CONTROL_ORIGIN', '/api/internal/signing-events');
  const response = await fetchNoRedirect(url, {
    method: 'POST',
    headers: { authorization: `Bearer ${env.CONTROL_TOKEN}`, 'content-type': 'application/json' },
    body: JSON.stringify({
      action: 'signing.completed',
      intentId: intent.id,
      kind: intent.kind,
      buildId: intent.build.id,
      revisionId: intent.build.revisionId,
      artifactKey: intent.artifact.key,
      artifactSha256: intent.artifact.sha256,
      signatureKey: signature.key,
      signatureSha256: signature.sha256,
      signatureFilename: signature.filename,
      publicKeyKey,
      fingerprint: identity.fingerprint,
      keyId: env.KEY_ID,
      mode: identity.mode,
    }),
  });
  if (!response.ok) throw new Error(`audit write returned ${response.status}`);
}

async function handlePublicKey(env: Env): Promise<Response> {
  const identity = await getIdentityCached(env);
  const key = await persistPublicKey(env, identity);
  return new Response(identity.armored, {
    headers: {
      'content-type': 'application/pgp-keys; charset=utf-8',
      'cache-control': 'public, max-age=31536000, immutable',
      'x-opr-public-key-key': key,
      'x-opr-key-fingerprint': identity.fingerprint,
    },
  });
}

async function handleSign(request: Request, env: Env): Promise<Response> {
  if (!(await authorized(request, env))) return errorResponse(401, 'unauthorized');
  const length = Number(request.headers.get('content-length') ?? 0);
  if (length > MAX_INTENT_BYTES) return errorResponse(413, 'request too large');
  let input: SignRequest;
  try {
    const body = await request.arrayBuffer();
    if (body.byteLength > MAX_INTENT_BYTES) return errorResponse(413, 'request too large');
    input = JSON.parse(new TextDecoder().decode(body)) as SignRequest;
  } catch { return errorResponse(400, 'request must be valid JSON'); }
  if (!input || typeof input.intentId !== 'string' || !ID.test(input.intentId)) return errorResponse(400, 'intentId is required');

  try {
    const identity = await getIdentityCached(env);
    const intent = await fetchIntent(request, env, input.intentId);
    if (intent.id !== input.intentId) throw new Error('control plane returned a different intent');
    assertIntentShape(intent, Math.floor(Date.now() / 1000), maxArtifactBytes(env), identity);
    const publicKeyKey = await persistPublicKey(env, identity);
    if (intent.status === 'signed') {
      const bytes = await readPersistedSignature(env, intent);
      await verifySignature(env, intent, identity, bytes);
      const signature = { ...intent.signature!, base64: base64(bytes) };
      return json({
        intentId: intent.id,
        kind: intent.kind,
        artifact: intent.artifact,
        signatureKey: signature.key,
        signatureSha256: signature.sha256,
        signature,
        publicKey: { key: publicKeyKey, armored: identity.armored, fingerprint: identity.fingerprint },
        mode: identity.mode,
      }, 200, { 'cache-control': 'no-store' });
    }
    await verifyAttestation(intent);
    const existing = await readExistingSignatureObject(env, intent);
    const signed = existing
      ? { bytes: existing.bytes, artifactSha256: intent.artifact.sha256, artifactSize: intent.artifact.size }
      : identity.mode === 'managed-kms'
        ? await signArtifactManaged(request, env, intent, identity)
        : await signArtifact(env, intent, identity);
    await verifySignature(env, intent, identity, signed.bytes);
    const signature = await persistSignature(env, intent, identity, signed.bytes);
    await recordAudit(env, intent, identity, signature, publicKeyKey);
    return json({
      intentId: intent.id,
      kind: intent.kind,
      artifact: { key: intent.artifact.key, filename: intent.artifact.filename, sha256: signed.artifactSha256, size: signed.artifactSize },
      signatureKey: signature.key,
      signatureSha256: signature.sha256,
      signature: { ...signature, base64: base64(signed.bytes) },
      publicKey: { key: publicKeyKey, armored: identity.armored, fingerprint: identity.fingerprint },
      mode: identity.mode,
    }, 200, { 'cache-control': 'no-store' });
  } catch (cause) {
    console.error('signing request failed', cause instanceof Error ? cause.message : 'unknown error');
    return errorResponse(409, cause instanceof Error ? cause.message : 'signing request rejected');
  }
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    try {
      const url = new URL(request.url);
      if (request.method === 'GET' && url.pathname === '/healthz') return json({ ok: true });
      if (request.method === 'GET' && url.pathname === '/v1/public-key') return handlePublicKey(env);
      if (request.method === 'POST' && url.pathname === '/v1/sign') return handleSign(request, env);
      return errorResponse(404, 'not found');
    } catch (cause) {
      console.error('signer request failed', cause instanceof Error ? cause.message : 'unknown error');
      return errorResponse(503, 'signer is not configured');
    }
  },
} satisfies ExportedHandler<Env>;
