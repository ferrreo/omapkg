import { mkdtemp, mkdir, readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { expect, test } from 'bun:test';
import * as openpgp from 'openpgp';
import signer from './index';

const generatedKey = await openpgp.generateKey({
  type: 'rsa',
  rsaBits: 2048,
  userIDs: [{ name: 'omarpkg', email: 'packages@example.com' }],
  format: 'armored',
  config: { v6Keys: false, preferredHashAlgorithm: openpgp.enums.hash.sha256 },
});

function stream(bytes: Uint8Array): ReadableStream<Uint8Array> {
  return new ReadableStream({ start(controller) { controller.enqueue(bytes); controller.close(); } });
}

function artifactChunk(offset: number, size: number): Uint8Array {
  const bytes = new Uint8Array(size);
  for (let index = 0; index < size; index += 1) bytes[index] = (offset + index) % 251;
  return bytes;
}

function generatedArtifactStream(size: number): ReadableStream<Uint8Array> {
  const chunkSize = 1024 * 1024;
  let offset = 0;
  return new ReadableStream({
    pull(controller) {
      if (offset >= size) { controller.close(); return; }
      const length = Math.min(chunkSize, size - offset);
      controller.enqueue(artifactChunk(offset, length));
      offset += length;
    },
  });
}

function generatedArtifactSha256(size: number): string {
  const hash = createHash('sha256');
  const chunkSize = 1024 * 1024;
  for (let offset = 0; offset < size; offset += chunkSize) hash.update(artifactChunk(offset, Math.min(chunkSize, size - offset)));
  return hash.digest('hex');
}

function encode(bytes: Uint8Array): string {
  let value = '';
  for (const byte of bytes) value += String.fromCharCode(byte);
  return btoa(value);
}

async function sha256(bytes: Uint8Array): Promise<string> {
  return Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes as unknown as BufferSource)), (byte) => byte.toString(16).padStart(2, '0')).join('');
}

async function drain(value: ReadableStream<Uint8Array>): Promise<void> {
  const reader = value.getReader();
  try { while (!(await reader.read()).done) { /* consume stream */ } }
  finally { reader.releaseLock(); }
}

async function runGPG(args: string[], home: string): Promise<{ status: number; stderr: string }> {
  const process = Bun.spawn(['gpg', '--batch', '--homedir', home, ...args], { stdout: 'pipe', stderr: 'pipe' });
  return { status: await process.exited, stderr: await new Response(process.stderr).text() };
}

test('signs package bytes and produces a GnuPG-verifiable detached signature', async () => {
  const generated = generatedKey;
  const privateKey = await openpgp.readPrivateKey({ armoredKey: generated.privateKey });
  const fingerprint = privateKey.getFingerprint().toLowerCase();
  const workerKeys = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
  const workerPublic = new Uint8Array(await crypto.subtle.exportKey('raw', workerKeys.publicKey));
  const artifact = new TextEncoder().encode('package bytes\x00\n');
  const artifactSha256 = await sha256(artifact);
  const provenance = JSON.stringify({
    buildId: 'build-1', revisionId: 'revision-1', workerId: 'worker-1',
    recipeSha256: 'a'.repeat(64), artifactSha256, architecture: 'x86_64',
    imageDigest: 'sha256:' + 'b'.repeat(64), sourceDateEpoch: 1,
    network: 'disabled', startedAt: new Date().toISOString(), finishedAt: new Date().toISOString(),
  });
  const provenanceSignature = new Uint8Array(await crypto.subtle.sign('Ed25519', workerKeys.privateKey, new TextEncoder().encode(provenance)));
  const intent = {
    id: 'intent-1', status: 'ready', kind: 'package', expiresAt: Math.floor(Date.now() / 1000) + 600,
    keyFingerprint: fingerprint,
    artifact: { key: 'builds/build-1/foo-1-1-x86_64.pkg.tar.zst', sha256: artifactSha256, size: artifact.byteLength, filename: 'foo-1-1-x86_64.pkg.tar.zst' },
    build: { id: 'build-1', revisionId: 'revision-1', status: 'succeeded', surface: 'binary', architecture: 'x86_64', workerId: 'worker-1', smokePassed: true },
    review: { manifestSha256: 'c'.repeat(64), areaApproved: true, securityApproved: true },
    attestation: { provenance, provenanceSignature: encode(provenanceSignature), workerPublicKey: encode(workerPublic) },
  };
  let controlIntent: any = intent;
  const objects = new Map<string, Uint8Array>([[intent.artifact.key, artifact]]);
  const metadata = new Map<string, Record<string, string>>();
  const events: unknown[] = [];
  const bucket = {
    async get(key: string) { const bytes = objects.get(key); return bytes ? { size: bytes.byteLength, body: stream(bytes), arrayBuffer: async () => bytes.slice().buffer } : null; },
    async head(key: string) { const bytes = objects.get(key); return bytes ? { size: bytes.byteLength, customMetadata: metadata.get(key) ?? {} } : null; },
    async put(key: string, value: Uint8Array | string, options: { customMetadata?: Record<string, string> }) {
      objects.set(key, typeof value === 'string' ? new TextEncoder().encode(value) : new Uint8Array(value));
      metadata.set(key, options.customMetadata ?? {});
    },
  };
  const originalFetch = globalThis.fetch;
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(input.toString());
    if (url.pathname === '/api/internal/signing-intents/intent-1') return new Response(JSON.stringify(controlIntent));
    if (url.pathname === '/api/internal/signing-events') {
      events.push(JSON.parse(String(init?.body ?? '{}')));
      return new Response('{}', { status: 201 });
    }
    throw new Error(`unexpected fetch ${url}`);
  }) as typeof fetch;
  try {
    const env = {
      ARTIFACTS: bucket,
      CONTROL_ORIGIN: 'https://control.example.test', PUBLIC_ORIGIN: 'https://packages.example.test', KEY_ID: 'test-v1',
      SIGNER_TOKEN: 'signer-token', CONTROL_TOKEN: 'control-token', OPR_SIGNING_PRIVATE_KEY_B64: btoa(generated.privateKey), OPR_SIGNING_FINGERPRINT: fingerprint,
    } as any;
    const response = await signer.fetch(new Request('https://signer/v1/sign', {
      method: 'POST', headers: { authorization: 'Bearer signer-token', 'content-type': 'application/json' }, body: JSON.stringify({ intentId: 'intent-1' }),
    }), env);
    expect(response.status).toBe(200);
    const result = await response.json() as any;
    expect(result.signature.filename).toBe(`${intent.artifact.filename}.sig`);
    expect(result.publicKey.fingerprint).toBe(fingerprint);
    expect(events).toHaveLength(1);

    controlIntent = {
      ...intent,
      status: 'signed',
      signature: { key: result.signature.key, sha256: result.signature.sha256, filename: result.signature.filename },
    };
    const retry = await signer.fetch(new Request('https://signer/v1/sign', {
      method: 'POST', headers: { authorization: 'Bearer signer-token', 'content-type': 'application/json' }, body: JSON.stringify({ intentId: 'intent-1' }),
    }), env);
    expect(retry.status).toBe(200);
    expect((await retry.json() as any).signatureSha256).toBe(result.signature.sha256);
    expect(events).toHaveLength(1);

    const testHome = await mkdtemp(join(tmpdir(), 'opr-signer-gpg-'));
    await mkdir(testHome, { recursive: true, mode: 0o700 });
    const packagePath = join(testHome, intent.artifact.filename);
    const signaturePath = join(testHome, result.signature.filename);
    const publicPath = join(testHome, 'opr-key.asc');
    await Bun.write(packagePath, artifact);
    await Bun.write(signaturePath, new Uint8Array(await (async () => {
      const binary = atob(result.signature.base64);
      return Uint8Array.from(binary, (character) => character.charCodeAt(0));
    })()));
    await Bun.write(publicPath, result.publicKey.armored);
    expect((await runGPG(['--import', publicPath], testHome)).status).toBe(0);
    const verified = await runGPG(['--verify', signaturePath, packagePath], testHome);
    expect(verified.status).toBe(0);
    expect(verified.stderr).toContain('Good signature');
    await readFile(signaturePath);
  } finally {
    globalThis.fetch = originalFetch;
  }
}, { timeout: 30_000 });

test('signs and verifies a streamed artifact larger than 128 MiB without reading arrayBuffer', async () => {
  const generated = generatedKey;
  const privateKey = await openpgp.readPrivateKey({ armoredKey: generated.privateKey });
  const fingerprint = privateKey.getFingerprint().toLowerCase();
  const workerKeys = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
  const workerPublic = new Uint8Array(await crypto.subtle.exportKey('raw', workerKeys.publicKey));
  const artifactSize = 128 * 1024 * 1024 + 8193;
  const artifactSha256 = generatedArtifactSha256(artifactSize);
  const provenance = JSON.stringify({
    buildId: 'build-large', revisionId: 'revision-large', workerId: 'worker-large',
    recipeSha256: 'a'.repeat(64), artifactSha256, architecture: 'x86_64',
    imageDigest: 'sha256:' + 'b'.repeat(64), sourceDateEpoch: 1,
    network: 'disabled', startedAt: new Date().toISOString(), finishedAt: new Date().toISOString(),
  });
  const provenanceSignature = new Uint8Array(await crypto.subtle.sign('Ed25519', workerKeys.privateKey, new TextEncoder().encode(provenance)));
  const intent = {
    id: 'intent-large', status: 'ready', kind: 'package', expiresAt: Math.floor(Date.now() / 1000) + 600,
    keyFingerprint: fingerprint,
    artifact: { key: 'builds/build-large/foo-1-1-x86_64.pkg.tar.zst', sha256: artifactSha256, size: artifactSize, filename: 'foo-1-1-x86_64.pkg.tar.zst' },
    build: { id: 'build-large', revisionId: 'revision-large', status: 'succeeded', surface: 'binary', architecture: 'x86_64', workerId: 'worker-large', smokePassed: true },
    review: { manifestSha256: 'c'.repeat(64), areaApproved: true, securityApproved: true },
    attestation: { provenance, provenanceSignature: encode(provenanceSignature), workerPublicKey: encode(workerPublic) },
  };
  const signatureKey = `${intent.artifact.key}.sig`;
  const objects = new Map<string, Uint8Array>();
  let artifactArrayBufferCalls = 0;
  const bucket = {
    async get(key: string) {
      if (key === intent.artifact.key) {
        return {
          size: artifactSize,
          body: generatedArtifactStream(artifactSize),
          arrayBuffer: async () => { artifactArrayBufferCalls += 1; throw new Error('artifact arrayBuffer must not be used'); },
        };
      }
      const bytes = objects.get(key);
      return bytes ? { size: bytes.byteLength, body: stream(bytes), arrayBuffer: async () => bytes.slice().buffer } : null;
    },
    async head(key: string) {
      const bytes = objects.get(key);
      return bytes ? { size: bytes.byteLength, customMetadata: {} } : null;
    },
    async put(key: string, value: Uint8Array | string) {
      objects.set(key, typeof value === 'string' ? new TextEncoder().encode(value) : new Uint8Array(value));
    },
  };
  const events: unknown[] = [];
  const originalFetch = globalThis.fetch;
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(input.toString());
    if (url.pathname === '/api/internal/signing-intents/intent-large') return new Response(JSON.stringify(intent));
    if (url.pathname === '/api/internal/signing-events') {
      events.push(JSON.parse(String(init?.body ?? '{}')));
      return new Response('{}', { status: 201 });
    }
    throw new Error(`unexpected fetch ${url}`);
  }) as typeof fetch;
  try {
    const env = {
      ARTIFACTS: bucket,
      CONTROL_ORIGIN: 'https://control.example.test', PUBLIC_ORIGIN: 'https://packages.example.test', KEY_ID: 'test-v1',
      SIGNER_TOKEN: 'signer-token', CONTROL_TOKEN: 'control-token', OPR_SIGNING_PRIVATE_KEY_B64: btoa(generated.privateKey), OPR_SIGNING_FINGERPRINT: fingerprint,
    } as any;
    const response = await signer.fetch(new Request('https://signer/v1/sign', {
      method: 'POST', headers: { authorization: 'Bearer signer-token', 'content-type': 'application/json' }, body: JSON.stringify({ intentId: intent.id }),
    }), env);
    expect(response.status).toBe(200);
    const result = await response.json() as any;
    expect(result.artifact.sha256).toBe(artifactSha256);
    expect(result.artifact.size).toBe(artifactSize);
    expect(result.signatureKey).toBe(signatureKey);
    expect(events).toHaveLength(1);
    expect(artifactArrayBufferCalls).toBe(0);

    const publicKey = await openpgp.readKey({ armoredKey: result.publicKey.armored });
    const binary = atob(result.signature.base64);
    const signature = Uint8Array.from(binary, (character) => character.charCodeAt(0));
    const message = await openpgp.createMessage({ binary: generatedArtifactStream(artifactSize) });
    const verified = await openpgp.verify({
      message,
      signature: await openpgp.readSignature({ binarySignature: signature }),
      verificationKeys: publicKey,
    });
    if (verified.data instanceof ReadableStream) await drain(verified.data);
    await verified.signatures[0].verified;
  } finally {
    globalThis.fetch = originalFetch;
  }
}, { timeout: 120_000 });

test('rejects a reviewed intent when downloaded bytes do not match its digest', async () => {
  const generated = generatedKey;
  const privateKey = await openpgp.readPrivateKey({ armoredKey: generated.privateKey });
  const fingerprint = privateKey.getFingerprint().toLowerCase();
  const workerKeys = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
  const workerPublic = new Uint8Array(await crypto.subtle.exportKey('raw', workerKeys.publicKey));
  const expectedSha256 = 'd'.repeat(64);
  const provenance = JSON.stringify({
    buildId: 'build-2', revisionId: 'revision-2', workerId: 'worker-2',
    recipeSha256: 'a'.repeat(64), artifactSha256: expectedSha256, architecture: 'x86_64',
    imageDigest: 'sha256:' + 'b'.repeat(64), sourceDateEpoch: 1,
    network: 'disabled', startedAt: new Date().toISOString(), finishedAt: new Date().toISOString(),
  });
  const provenanceSignature = new Uint8Array(await crypto.subtle.sign('Ed25519', workerKeys.privateKey, new TextEncoder().encode(provenance)));
  const intent = {
    id: 'intent-2', status: 'ready', kind: 'package', expiresAt: Math.floor(Date.now() / 1000) + 600, keyFingerprint: fingerprint,
    artifact: { key: 'builds/build-2/foo-1-1-x86_64.pkg.tar.zst', sha256: expectedSha256, size: 3, filename: 'foo-1-1-x86_64.pkg.tar.zst' },
    build: { id: 'build-2', revisionId: 'revision-2', status: 'succeeded', surface: 'binary', architecture: 'x86_64', workerId: 'worker-2', smokePassed: true },
    review: { manifestSha256: 'e'.repeat(64), areaApproved: true, securityApproved: true },
    attestation: { provenance, provenanceSignature: encode(provenanceSignature), workerPublicKey: encode(workerPublic) },
  };
  const originalFetch = globalThis.fetch;
  globalThis.fetch = (async (input: RequestInfo | URL) => {
    const url = new URL(input.toString());
    if (url.pathname === '/api/internal/signing-intents/intent-2') return new Response(JSON.stringify(intent));
    throw new Error(`unexpected fetch ${url}`);
  }) as typeof fetch;
  try {
    const env = {
      ARTIFACTS: { async get() { return { size: 3, body: stream(new Uint8Array([1, 2, 3])) }; }, async head() { return null; }, async put() {} },
      CONTROL_ORIGIN: 'https://control.example.test', PUBLIC_ORIGIN: 'https://packages.example.test', KEY_ID: 'test-v1',
      SIGNER_TOKEN: 'signer-token', CONTROL_TOKEN: 'control-token', OPR_SIGNING_PRIVATE_KEY_B64: btoa(generated.privateKey), OPR_SIGNING_FINGERPRINT: fingerprint,
    } as any;
    const response = await signer.fetch(new Request('https://signer/v1/sign', {
      method: 'POST', headers: { authorization: 'Bearer signer-token', 'content-type': 'application/json' }, body: JSON.stringify({ intentId: 'intent-2' }),
    }), env);
    expect(response.status).toBe(409);
  } finally {
    globalThis.fetch = originalFetch;
  }
}, { timeout: 30_000 });

test('managed KMS mode forwards the artifact stream and returns a verified signature', async () => {
  const generated = generatedKey;
  const privateKey = await openpgp.readPrivateKey({ armoredKey: generated.privateKey });
  const publicKey = await openpgp.readKey({ armoredKey: generated.publicKey });
  const fingerprint = publicKey.getFingerprint().toLowerCase();
  const workerKeys = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
  const workerPublic = new Uint8Array(await crypto.subtle.exportKey('raw', workerKeys.publicKey));
  const artifact = new TextEncoder().encode('managed package bytes');
  const artifactSha256 = await sha256(artifact);
  const provenance = JSON.stringify({
    buildId: 'build-3', revisionId: 'revision-3', workerId: 'worker-3', recipeSha256: 'a'.repeat(64), artifactSha256,
    architecture: 'x86_64', imageDigest: 'sha256:' + 'b'.repeat(64), sourceDateEpoch: 1, network: 'disabled',
    startedAt: new Date().toISOString(), finishedAt: new Date().toISOString(),
  });
  const provenanceSignature = new Uint8Array(await crypto.subtle.sign('Ed25519', workerKeys.privateKey, new TextEncoder().encode(provenance)));
  const intent = {
    id: 'intent-3', status: 'ready', kind: 'package', expiresAt: Math.floor(Date.now() / 1000) + 600, keyFingerprint: fingerprint,
    artifact: { key: 'builds/build-3/foo-1-1-x86_64.pkg.tar.zst', sha256: artifactSha256, size: artifact.byteLength, filename: 'foo-1-1-x86_64.pkg.tar.zst' },
    build: { id: 'build-3', revisionId: 'revision-3', status: 'succeeded', surface: 'binary', architecture: 'x86_64', workerId: 'worker-3', smokePassed: true },
    review: { manifestSha256: 'c'.repeat(64), areaApproved: true, securityApproved: true },
    attestation: { provenance, provenanceSignature: encode(provenanceSignature), workerPublicKey: encode(workerPublic) },
  };
  const objects = new Map<string, Uint8Array>([[intent.artifact.key, artifact]]);
  const metadata = new Map<string, Record<string, string>>();
  const originalFetch = globalThis.fetch;
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(input.toString());
    if (url.pathname === '/v1/public-key') return new Response(JSON.stringify({ publicKey: generated.publicKey, fingerprint }));
    if (url.pathname === '/v1/sign') {
      const body = new Uint8Array(await new Response(init?.body as BodyInit).arrayBuffer());
      const message = await openpgp.createMessage({ binary: body });
      const signature = await openpgp.sign({ message, signingKeys: privateKey, detached: true, format: 'binary', config: { v6Keys: false, preferredHashAlgorithm: openpgp.enums.hash.sha256 } });
      const bytes = await readSignatureStreamForTest(signature);
      return new Response(JSON.stringify({ mode: 'managed-kms', artifactSha256: await sha256(body), artifactSize: body.byteLength, signatureBase64: encode(bytes), signatureSha256: await sha256(bytes), publicKey: generated.publicKey, fingerprint }));
    }
    if (url.pathname === '/api/internal/signing-intents/intent-3') return new Response(JSON.stringify(intent));
    if (url.pathname === '/api/internal/signing-events') return new Response('{}', { status: 201 });
    throw new Error(`unexpected fetch ${url}`);
  }) as typeof fetch;
  try {
    const env = {
      ARTIFACTS: {
        async get(key: string) { const bytes = objects.get(key); return bytes ? { size: bytes.byteLength, body: stream(bytes), arrayBuffer: async () => bytes.slice().buffer } : null; },
        async head(key: string) { const bytes = objects.get(key); return bytes ? { size: bytes.byteLength, customMetadata: metadata.get(key) ?? {} } : null; },
        async put(key: string, value: Uint8Array | string, options: { customMetadata?: Record<string, string> }) {
          objects.set(key, typeof value === 'string' ? new TextEncoder().encode(value) : new Uint8Array(value));
          metadata.set(key, options.customMetadata ?? {});
        },
      },
      CONTROL_ORIGIN: 'https://control.example.test', PUBLIC_ORIGIN: 'https://packages.example.test', KEY_ID: 'test-v1',
      SIGNING_MODE: 'managed-kms', KMS_SIGNER_URL: 'https://kms.example.test', KMS_SIGNER_TOKEN: 'kms-token',
      SIGNER_TOKEN: 'signer-token', CONTROL_TOKEN: 'control-token',
    } as any;
    const response = await signer.fetch(new Request('https://signer/v1/sign', {
      method: 'POST', headers: { authorization: 'Bearer signer-token', 'content-type': 'application/json' }, body: JSON.stringify({ intentId: 'intent-3' }),
    }), env);
    expect(response.status).toBe(200);
    const result = await response.json() as any;
    expect(result.mode).toBe('managed-kms');
    expect(result.signatureKey).toBe(`${intent.artifact.key}.sig`);
    expect(result.publicKey.fingerprint).toBe(fingerprint);
  } finally {
    globalThis.fetch = originalFetch;
  }
}, { timeout: 30_000 });

test('cancels a streamed artifact when managed KMS rejects before consuming it', async () => {
  const generated = generatedKey;
  const publicKey = await openpgp.readKey({ armoredKey: generated.publicKey });
  const fingerprint = publicKey.getFingerprint().toLowerCase();
  const workerKeys = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
  const workerPublic = new Uint8Array(await crypto.subtle.exportKey('raw', workerKeys.publicKey));
  const artifact = new TextEncoder().encode('managed failure bytes');
  const artifactSha256 = await sha256(artifact);
  const provenance = JSON.stringify({
    buildId: 'build-managed-failure', revisionId: 'revision-managed-failure', workerId: 'worker-managed-failure',
    recipeSha256: 'a'.repeat(64), artifactSha256, architecture: 'x86_64',
    imageDigest: 'sha256:' + 'b'.repeat(64), sourceDateEpoch: 1,
    network: 'disabled', startedAt: new Date().toISOString(), finishedAt: new Date().toISOString(),
  });
  const provenanceSignature = new Uint8Array(await crypto.subtle.sign('Ed25519', workerKeys.privateKey, new TextEncoder().encode(provenance)));
  const intent = {
    id: 'intent-managed-failure', status: 'ready', kind: 'package', expiresAt: Math.floor(Date.now() / 1000) + 600,
    keyFingerprint: fingerprint,
    artifact: { key: 'builds/build-managed-failure/foo-1-1-x86_64.pkg.tar.zst', sha256: artifactSha256, size: artifact.byteLength, filename: 'foo-1-1-x86_64.pkg.tar.zst' },
    build: { id: 'build-managed-failure', revisionId: 'revision-managed-failure', status: 'succeeded', surface: 'binary', architecture: 'x86_64', workerId: 'worker-managed-failure', smokePassed: true },
    review: { manifestSha256: 'c'.repeat(64), areaApproved: true, securityApproved: true },
    attestation: { provenance, provenanceSignature: encode(provenanceSignature), workerPublicKey: encode(workerPublic) },
  };
  const objects = new Map<string, Uint8Array>();
  let cancelCalls = 0;
  let signCalls = 0;
  const bucket = {
    async get(key: string) {
      if (key !== intent.artifact.key) return null;
      return {
        size: artifact.byteLength,
        body: new ReadableStream<Uint8Array>({
          pull() { /* KMS rejects before this stream is read. */ },
          cancel() { cancelCalls += 1; },
        }),
        arrayBuffer: async () => { throw new Error('artifact arrayBuffer must not be used'); },
      };
    },
    async head(key: string) {
      const bytes = objects.get(key);
      return bytes ? { size: bytes.byteLength, customMetadata: {} } : null;
    },
    async put(key: string, value: Uint8Array | string) {
      objects.set(key, typeof value === 'string' ? new TextEncoder().encode(value) : new Uint8Array(value));
    },
  };
  const originalFetch = globalThis.fetch;
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(input.toString());
    if (url.pathname === '/v1/public-key') return new Response(JSON.stringify({ publicKey: generated.publicKey, fingerprint }));
    if (url.pathname === '/api/internal/signing-intents/intent-managed-failure') return new Response(JSON.stringify(intent));
    if (url.pathname === '/v1/sign') {
      signCalls += 1;
      return new Response(null, { status: 503 });
    }
    throw new Error(`unexpected fetch ${url}`);
  }) as typeof fetch;
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    const env = {
      ARTIFACTS: bucket,
      CONTROL_ORIGIN: 'https://control.example.test', PUBLIC_ORIGIN: 'https://packages.example.test', KEY_ID: 'test-v1',
      SIGNING_MODE: 'managed-kms', KMS_SIGNER_URL: 'https://kms.example.test', KMS_SIGNER_TOKEN: 'kms-token',
      SIGNER_TOKEN: 'signer-token', CONTROL_TOKEN: 'control-token',
    } as any;
    const response = await Promise.race([
      signer.fetch(new Request('https://signer/v1/sign', {
        method: 'POST', headers: { authorization: 'Bearer signer-token', 'content-type': 'application/json' }, body: JSON.stringify({ intentId: intent.id }),
      }), env),
      new Promise<never>((_, reject) => { timer = setTimeout(() => reject(new Error('managed KMS rejection did not settle')), 1_000); }),
    ]);
    expect(response.status).toBe(409);
    expect(await response.json() as any).toEqual({ error: 'managed KMS signer returned 503' });
    expect(signCalls).toBe(1);
    expect(cancelCalls).toBe(1);
  } finally {
    if (timer) clearTimeout(timer);
    globalThis.fetch = originalFetch;
  }
}, { timeout: 30_000 });

test('rejects a control-plane redirect without following it or forwarding credentials', async () => {
  const privateKey = await openpgp.readPrivateKey({ armoredKey: generatedKey.privateKey });
  const fingerprint = privateKey.getFingerprint().toLowerCase();
  const calls: Array<{ url: string; authorization: string | null }> = [];
  const originalFetch = globalThis.fetch;
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    calls.push({ url: input.toString(), authorization: new Headers(init?.headers).get('authorization') });
    return new Response(null, { status: 302, headers: { location: 'https://evil.example.test/collect' } });
  }) as typeof fetch;
  try {
    const env = {
      ARTIFACTS: {} as R2Bucket,
      CONTROL_ORIGIN: 'https://control.example.test', PUBLIC_ORIGIN: 'https://packages.example.test', KEY_ID: 'test-v1',
      SIGNER_TOKEN: 'signer-token', CONTROL_TOKEN: 'control-token', OPR_SIGNING_PRIVATE_KEY_B64: btoa(generatedKey.privateKey), OPR_SIGNING_FINGERPRINT: fingerprint,
    } as any;
    const response = await signer.fetch(new Request('https://signer/v1/sign', {
      method: 'POST', headers: { authorization: 'Bearer signer-token', 'content-type': 'application/json' }, body: JSON.stringify({ intentId: 'intent-redirect' }),
    }), env);
    expect(response.status).toBe(409);
    expect(calls).toEqual([{ url: 'https://control.example.test/api/internal/signing-intents/intent-redirect', authorization: 'Bearer control-token' }]);
  } finally {
    globalThis.fetch = originalFetch;
  }
}, { timeout: 30_000 });

async function readSignatureStreamForTest(value: Uint8Array | ReadableStream<Uint8Array>): Promise<Uint8Array> {
  return value instanceof Uint8Array ? value : new Uint8Array(await new Response(value).arrayBuffer());
}

test('reuses an existing valid signature after a transient audit failure', async () => {
  const privateKey = await openpgp.readPrivateKey({ armoredKey: generatedKey.privateKey });
  const fingerprint = privateKey.getFingerprint().toLowerCase();
  const workerKeys = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
  const workerPublic = new Uint8Array(await crypto.subtle.exportKey('raw', workerKeys.publicKey));
  const artifact = new TextEncoder().encode('retry package bytes');
  const artifactSha256 = await sha256(artifact);
  const provenance = JSON.stringify({
    buildId: 'build-4', revisionId: 'revision-4', workerId: 'worker-4', recipeSha256: 'a'.repeat(64), artifactSha256,
    architecture: 'x86_64', imageDigest: 'sha256:' + 'b'.repeat(64), sourceDateEpoch: 1, network: 'disabled',
    startedAt: new Date().toISOString(), finishedAt: new Date().toISOString(),
  });
  const provenanceSignature = encode(new Uint8Array(await crypto.subtle.sign('Ed25519', workerKeys.privateKey, new TextEncoder().encode(provenance))));
  const makeIntent = (id: string) => ({
    id, status: 'ready', kind: 'package', expiresAt: Math.floor(Date.now() / 1000) + 600, keyFingerprint: fingerprint,
    artifact: { key: 'builds/build-4/foo-1-1-x86_64.pkg.tar.zst', sha256: artifactSha256, size: artifact.byteLength, filename: 'foo-1-1-x86_64.pkg.tar.zst' },
    build: { id: 'build-4', revisionId: 'revision-4', status: 'succeeded', surface: 'binary', architecture: 'x86_64', workerId: 'worker-4', smokePassed: true },
    review: { manifestSha256: 'c'.repeat(64), areaApproved: true, securityApproved: true },
    attestation: { provenance, provenanceSignature, workerPublicKey: encode(workerPublic) },
  });
  let controlIntent: any = makeIntent('intent-4a');
  const objects = new Map<string, Uint8Array>([[controlIntent.artifact.key, artifact]]);
  const metadata = new Map<string, Record<string, string>>();
  let auditCalls = 0;
  const originalFetch = globalThis.fetch;
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(input.toString());
    if (url.pathname.startsWith('/api/internal/signing-intents/')) return new Response(JSON.stringify(controlIntent));
    if (url.pathname === '/api/internal/signing-events') {
      auditCalls += 1;
      return new Response('{}', { status: auditCalls === 1 ? 503 : 201 });
    }
    throw new Error(`unexpected fetch ${url}`);
  }) as typeof fetch;
  const bucket = {
    async get(key: string) { const bytes = objects.get(key); return bytes ? { size: bytes.byteLength, body: stream(bytes), arrayBuffer: async () => bytes.slice().buffer } : null; },
    async head(key: string) { const bytes = objects.get(key); return bytes ? { size: bytes.byteLength, customMetadata: metadata.get(key) ?? {} } : null; },
    async put(key: string, value: Uint8Array | string, options: { customMetadata?: Record<string, string> }) {
      objects.set(key, typeof value === 'string' ? new TextEncoder().encode(value) : new Uint8Array(value));
      metadata.set(key, options.customMetadata ?? {});
    },
  };
  const env = {
    ARTIFACTS: bucket, CONTROL_ORIGIN: 'https://control.example.test', PUBLIC_ORIGIN: 'https://packages.example.test', KEY_ID: 'test-v1',
    SIGNER_TOKEN: 'signer-token', CONTROL_TOKEN: 'control-token', OPR_SIGNING_PRIVATE_KEY_B64: btoa(generatedKey.privateKey), OPR_SIGNING_FINGERPRINT: fingerprint,
  } as any;
  try {
    const request = () => new Request('https://signer/v1/sign', {
      method: 'POST', headers: { authorization: 'Bearer signer-token', 'content-type': 'application/json' }, body: JSON.stringify({ intentId: controlIntent.id }),
    });
    const first = await signer.fetch(request(), env);
    expect(first.status).toBe(409);
    const signatureKey = `${controlIntent.artifact.key}.sig`;
    const firstSignature = objects.get(signatureKey);
    expect(firstSignature?.byteLength).toBeGreaterThan(0);
    const firstBytes = firstSignature!.slice();
    controlIntent = makeIntent('intent-4b');
    const second = await signer.fetch(request(), env);
    expect(second.status).toBe(200);
    expect(Array.from(objects.get(signatureKey) ?? [])).toEqual(Array.from(firstBytes));
    expect(auditCalls).toBe(2);
  } finally {
    globalThis.fetch = originalFetch;
  }
}, { timeout: 30_000 });

test('signing transports reject nonlocal HTTP and allow HTTPS or loopback development', async () => {
  const originalFetch = globalThis.fetch;
  const request = () => new Request('https://signer.internal/v1/sign', {
    method: 'POST', headers: { authorization: 'Bearer review-test-token', 'content-type': 'application/json' },
    body: JSON.stringify({ intentId: 'intent-transport' }),
  });
  const observed: Array<{ url: string; authorization: string | null }> = [];
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    observed.push({ url: String(input), authorization: new Headers(init?.headers).get('authorization') });
    return new Response('stubbed service unavailable', { status: 503 });
  }) as typeof fetch;
  try {
    for (const origin of ['http://control.example', 'https://control.example', 'http://localhost:5173', 'http://127.0.0.1:5173', 'http://[::1]:5173']) {
      observed.length = 0;
      await signer.fetch(request(), {
        ARTIFACTS: {} as R2Bucket, SIGNER_TOKEN: 'review-test-token', CONTROL_TOKEN: 'dummy-control-token',
        CONTROL_ORIGIN: origin, PUBLIC_ORIGIN: 'https://omapkg.example', KEY_ID: 'test',
        OPR_SIGNING_PRIVATE_KEY_B64: btoa(generatedKey.privateKey),
      });
      expect(observed).toEqual(origin === 'http://control.example' ? [] : [{
        url: `${origin}/api/internal/signing-intents/intent-transport`, authorization: 'Bearer dummy-control-token',
      }]);
    }
    observed.length = 0;
    await signer.fetch(request(), {
      ARTIFACTS: {} as R2Bucket, SIGNER_TOKEN: 'review-test-token', CONTROL_TOKEN: 'dummy-control-token',
      CONTROL_ORIGIN: 'https://control.example', PUBLIC_ORIGIN: 'https://omapkg.example', KEY_ID: 'test',
      OPR_SIGNING_PRIVATE_KEY_B64: '', SIGNING_MODE: 'managed-kms',
      KMS_SIGNER_URL: 'http://kms.example', KMS_SIGNER_TOKEN: 'dummy-kms-token',
    });
    expect(observed).toHaveLength(0);
  } finally { globalThis.fetch = originalFetch; }
});
