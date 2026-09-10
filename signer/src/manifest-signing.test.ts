import { expect, test } from 'bun:test';
import * as openpgp from 'openpgp';
import signer from './index';
import { verifyDistributionManifest } from './verify-release';
import { canonicalJson } from '../../src/lib/canonical-json';

function stream(bytes: Uint8Array): ReadableStream<Uint8Array> {
  return new ReadableStream({ start(controller) { controller.enqueue(bytes); controller.close(); } });
}

async function sha256(bytes: Uint8Array): Promise<string> {
  return Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes as BufferSource)), (byte) => byte.toString(16).padStart(2, '0')).join('');
}

function base64(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes));
}

test('signs an exact distribution manifest through the shared signer contract', async () => {
  const generated = await openpgp.generateKey({ type: 'rsa', rsaBits: 2048, userIDs: [{ name: 'omapkg', email: 'packages@example.com' }], format: 'armored', config: { v6Keys: false, preferredHashAlgorithm: openpgp.enums.hash.sha256 } });
  const privateKey = await openpgp.readPrivateKey({ armoredKey: generated.privateKey });
  const fingerprint = privateKey.getFingerprint().toLowerCase();
  const manifest = new TextEncoder().encode(canonicalJson({
    schemaVersion: 1, kind: 'system', lane: 'system', channel: 'stable', identity: { version: '4.0.3', generation: null }, releaseId: '4.0.3',
    parent: { digest: null, sequence: null }, createdAt: 1_700_000_000, expiresAt: 1_800_000_000, sequence: 1,
    architectures: ['aarch64', 'x86_64'], sourceRefs: [], repositories: [], packageChunks: [], packageCount: 0,
    compatibility: { systemManifestDigest: null, systemSnapshotDigests: [], oprManifestDigest: null }, systemManifest: null, oprManifest: null,
    changelog: { url: 'https://repo.example/changelog.json', sha256: 'a'.repeat(64), size: 1, approvedBy: 'github:1', cohortDigests: [] },
    approvals: { releaseTeam: ['github:1'], baseOwners: [] }, recovery: { fromDigest: null, target: null, authorized: false, reason: null, constraints: [] },
    policy: { schemaVersion: 1, version: 'distribution-release-v1' },
  }));
  const manifestSha256 = await sha256(manifest);
  const intent = {
    id: 'manifest-intent-1', status: 'ready', kind: 'manifest', expiresAt: Math.floor(Date.now() / 1000) + 600, keyFingerprint: fingerprint,
    artifact: { key: 'distribution/releases/system/4.0.3/manifest.json', sha256: manifestSha256, size: manifest.byteLength, filename: 'manifest.json' },
    build: { id: 'candidate-1', revisionId: 'candidate-1', status: 'succeeded', surface: 'recipe', architecture: 'x86_64', workerId: 'distribution', smokePassed: true },
    manifest: { candidateId: 'candidate-1', manifestSha256 },
  };
  const objects = new Map([[intent.artifact.key, manifest]]);
  const metadata = new Map<string, Record<string, string>>();
  let control: any = intent;
  const events: any[] = [];
  const bucket = {
    async get(key: string) { const bytes = objects.get(key); return bytes ? { size: bytes.byteLength, body: stream(bytes), arrayBuffer: async () => bytes.slice().buffer } : null; },
    async head(key: string) { const bytes = objects.get(key); return bytes ? { size: bytes.byteLength, customMetadata: metadata.get(key) ?? {} } : null; },
    async put(key: string, value: Uint8Array | string, options?: { customMetadata?: Record<string, string> }) { objects.set(key, typeof value === 'string' ? new TextEncoder().encode(value) : new Uint8Array(value)); metadata.set(key, options?.customMetadata ?? {}); },
  };
  const originalFetch = globalThis.fetch;
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(input.toString());
    if (url.pathname === '/api/internal/signing-intents/manifest-intent-1') return new Response(JSON.stringify(control));
    if (url.pathname === '/api/internal/signing-events') { events.push(JSON.parse(String(init?.body ?? '{}'))); return new Response('{}', { status: 201 }); }
    throw new Error(`unexpected fetch ${url}`);
  }) as typeof fetch;
  try {
    const env = { ARTIFACTS: bucket, CONTROL_ORIGIN: 'https://control.example.test', PUBLIC_ORIGIN: 'https://repo.example', KEY_ID: 'test-v1', SIGNER_TOKEN: 'signer-token', CONTROL_TOKEN: 'control-token', OPR_SIGNING_PRIVATE_KEY_B64: btoa(generated.privateKey), OPR_SIGNING_FINGERPRINT: fingerprint } as any;
    const response = await signer.fetch(new Request('https://signer/v1/sign', { method: 'POST', headers: { authorization: 'Bearer signer-token', 'content-type': 'application/json' }, body: JSON.stringify({ intentId: intent.id }) }), env);
    expect(response.status).toBe(200);
    const result = await response.json() as any;
    expect(result.kind).toBe('manifest');
    expect(result.artifact.sha256).toBe(manifestSha256);
    expect(events[0].candidateId).toBe('candidate-1');
    const signatureBytes = Uint8Array.from(atob(result.signature.base64), (character) => character.charCodeAt(0));
    const verified = await verifyDistributionManifest({ manifest, signature: signatureBytes, trustedPublicKey: result.publicKey.armored, trustedFingerprint: fingerprint });
    expect(verified.digest).toBe(manifestSha256);
    control = { ...intent, status: 'signed', signature: { key: result.signatureKey, sha256: result.signatureSha256, filename: 'manifest.json.sig' } };
    const retry = await signer.fetch(new Request('https://signer/v1/sign', { method: 'POST', headers: { authorization: 'Bearer signer-token', 'content-type': 'application/json' }, body: JSON.stringify({ intentId: intent.id }) }), env);
    expect(retry.status).toBe(200);
  } finally { globalThis.fetch = originalFetch; }
});

test('signs a native schema v2 core database with reviewed output context', async () => {
  const generated = await openpgp.generateKey({ type: 'rsa', rsaBits: 2048, userIDs: [{ name: 'omapkg', email: 'packages@example.com' }], format: 'armored', config: { v6Keys: false, preferredHashAlgorithm: openpgp.enums.hash.sha256 } });
  const signingKey = await openpgp.readPrivateKey({ armoredKey: generated.privateKey });
  const fingerprint = signingKey.getFingerprint().toLowerCase();
  const workerKeys = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
  const workerPublicKey = base64(new Uint8Array(await crypto.subtle.exportKey('raw', workerKeys.publicKey)));
  const outputContract = { schemaVersion: 2, cohort: { id: 'cohort-db', revision: 1, manifestSha256: 'a'.repeat(64) },
    outputs: [{ name: 'demo', fullVersion: '1.0-1', architecture: 'x86_64' }], runtimeGroups: [['demo']] };
  const runtimeAnalysis = { schemaVersion: 2, tool: 'go-native-analysis', toolVersion: 'go1.26', elf: [], nativeCode: [], payloadSha256: 'b'.repeat(64),
    findings: [], runtimeClosureComplete: false, unknowns: ['unexercised dlopen'], exceptions: [] };
  const buildEnvironment = { baseImage: `registry.example/builder@sha256:${'c'.repeat(64)}`, preparedImage: `sha256:${'d'.repeat(64)}`, packages: ['base 1.0'] };
  const runtimeEnvironment = { baseImage: `registry.example/runtime@sha256:${'e'.repeat(64)}`, preparedImage: `sha256:${'f'.repeat(64)}`, packages: ['base 1.0'] };
  const packageDigest = '1'.repeat(64);
  const provenance = JSON.stringify({ schemaVersion: 2, attempt: 1, outputContract, buildId: 'build-db', revisionId: 'revision-db', workerId: 'worker-db',
    recipeSha256: '2'.repeat(64), architecture: 'x86_64', imageDigest: `sha256:${'c'.repeat(64)}`, sourceDateEpoch: 1, sources: [], network: 'disabled',
    startedAt: '2026-09-10T00:00:00.000Z', finishedAt: '2026-09-10T00:01:00.000Z', buildEnvironment, runtimeTests: [{ outputs: ['demo'], environment: runtimeEnvironment, smokePassed: true,
      analyses: [{ name: 'demo', runtimeAnalysis }] }], outputs: [{ pkgbase: 'demo', filename: 'demo-1.0-1-x86_64.pkg.tar.zst', artifactSha256: packageDigest,
      packageMetadata: { name: 'demo', fullVersion: '1.0-1', architecture: 'x86_64', installedSize: 0, depends: [], provides: [], conflicts: [], replaces: [] } }] });
  const provenanceSignature = base64(new Uint8Array(await crypto.subtle.sign('Ed25519', workerKeys.privateKey, new TextEncoder().encode(provenance))));
  const database = new TextEncoder().encode('native owned core database bytes');
  const databaseSha256 = await sha256(database);
  const intent = {
    id: 'database-intent-1', status: 'ready', kind: 'database', expiresAt: Math.floor(Date.now() / 1000) + 600, keyFingerprint: fingerprint,
    artifact: { key: 'repo/stable/x86_64/core.db.tar.gz', sha256: databaseSha256, size: database.byteLength, filename: 'core.db.tar.gz' },
    build: { id: 'build-db', revisionId: 'revision-db', status: 'succeeded', surface: 'binary', architecture: 'x86_64', workerId: 'worker-db', smokePassed: true, attempt: 1 },
    review: { manifestSha256: 'a'.repeat(64), areaApproved: true, securityApproved: true, runtimeExceptions: [], outputContract, inputLockSha256: undefined },
    attestation: { provenance, provenanceSignature, workerPublicKey },
  };
  const objects = new Map([[intent.artifact.key, database]]); const metadata = new Map<string, Record<string, string>>(); let control: any = intent; const events: any[] = [];
  const bucket = {
    async get(key: string) { const bytes = objects.get(key); return bytes ? { size: bytes.byteLength, body: stream(bytes), arrayBuffer: async () => bytes.slice().buffer } : null; },
    async head(key: string) { const bytes = objects.get(key); return bytes ? { size: bytes.byteLength, customMetadata: metadata.get(key) ?? {} } : null; },
    async put(key: string, value: Uint8Array | string, options?: { customMetadata?: Record<string, string> }) { objects.set(key, typeof value === 'string' ? new TextEncoder().encode(value) : new Uint8Array(value)); metadata.set(key, options?.customMetadata ?? {}); },
  };
  const originalFetch = globalThis.fetch;
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(input.toString());
    if (url.pathname === '/api/internal/signing-intents/database-intent-1') return new Response(JSON.stringify(control));
    if (url.pathname === '/api/internal/signing-events') { events.push(JSON.parse(String(init?.body ?? '{}'))); return new Response('{}', { status: 201 }); }
    throw new Error(`unexpected fetch ${url}`);
  }) as typeof fetch;
  try {
    const env = { ARTIFACTS: bucket, CONTROL_ORIGIN: 'https://control.example.test', PUBLIC_ORIGIN: 'https://repo.example', KEY_ID: 'test-v1', SIGNER_TOKEN: 'signer-token', CONTROL_TOKEN: 'control-token', OPR_SIGNING_PRIVATE_KEY_B64: btoa(generated.privateKey), OPR_SIGNING_FINGERPRINT: fingerprint } as any;
    const response = await signer.fetch(new Request('https://signer/v1/sign', { method: 'POST', headers: { authorization: 'Bearer signer-token', 'content-type': 'application/json' }, body: JSON.stringify({ intentId: intent.id }) }), env);
    expect(response.status).toBe(200);
    const result = await response.json() as any;
    expect(result.kind).toBe('database');
    expect(result.artifact.sha256).toBe(databaseSha256);
    expect(events[0].kind).toBe('database');
    const signatureBytes = Uint8Array.from(atob(result.signature.base64), (character) => character.charCodeAt(0));
    const publicKey = await openpgp.readKey({ armoredKey: result.publicKey.armored });
    const verified = await openpgp.verify({ message: await openpgp.createMessage({ binary: database }), signature: await openpgp.readSignature({ binarySignature: signatureBytes }), verificationKeys: publicKey });
    await verified.signatures[0].verified;
    control = { ...intent, status: 'signed', signature: { key: result.signatureKey, sha256: result.signatureSha256, filename: 'core.db.tar.gz.sig' } };
    const retry = await signer.fetch(new Request('https://signer/v1/sign', { method: 'POST', headers: { authorization: 'Bearer signer-token', 'content-type': 'application/json' }, body: JSON.stringify({ intentId: intent.id }) }), env);
    expect(retry.status).toBe(200);
  } finally { globalThis.fetch = originalFetch; }
});
