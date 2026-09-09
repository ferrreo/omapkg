import { test, expect } from 'bun:test';
import * as openpgp from 'openpgp';
import signer, { type Env } from './index';
import { verifyReleaseEvidence } from './verify-release';
import { releaseAttestation } from '../../src/lib/server/release-attestation';
import { sha256 } from '../../src/lib/server/db';
import { packageFilename } from '../../src/lib/output-contract';
import { runtimeEvidence } from '../../tests/runtime-fixtures';

test('native output signing and offline verification bind every output, runtime group and exact attempt', async () => {
  const key = await openpgp.generateKey({ type: 'rsa', rsaBits: 2048, userIDs: [{ name: 'Native signing test' }], format: 'armored', config: { v6Keys: false } });
  const privateKey = await openpgp.readPrivateKey({ armoredKey: key.privateKey });
  const fingerprint = privateKey.getFingerprint();
  const workerKey = await crypto.subtle.generateKey('Ed25519', true, ['sign', 'verify']);
  const workerPublicKey = Buffer.from(await crypto.subtle.exportKey('raw', workerKey.publicKey)).toString('base64');
  const encode = (value: string) => new TextEncoder().encode(value);
  const imageDigest = `sha256:${'a'.repeat(64)}`;
  const runtime = runtimeEvidence(imageDigest);
  const outputContract = { schemaVersion: 2, cohort: { id: 'native-cohort', revision: 1, manifestSha256: 'b'.repeat(64) },
    outputs: [{ name: 'native@demo', fullVersion: '2:1-3.1', architecture: 'x86_64' as const }, { name: 'native-docs', fullVersion: '2:1-3.1', architecture: 'any' as const }],
    runtimeGroups: [['native@demo'], ['native-docs']] };
  const artifact = encode('native fixture bytes'); const artifactSha256 = await sha256(artifact);
  const report = { schemaVersion: 2, attempt: 2, outputContract, buildId: 'build-1', revisionId: 'revision-1', workerId: 'worker-1',
    recipeSha256: 'c'.repeat(64), imageDigest, architecture: 'x86_64', sourceDateEpoch: 1, network: 'disabled',
    sources: [{ name: 'source.tar', url: 'https://example.org/source.tar', sha256: 'd'.repeat(64) }], startedAt: '2026-09-09T00:00:00Z', finishedAt: '2026-09-09T00:01:00Z',
    buildEnvironment: runtime.buildEnvironment, outputs: outputContract.outputs.map((output) => ({ pkgbase: 'native', filename: packageFilename(output), artifactSha256,
      packageMetadata: { ...output, installedSize: 10, depends: [], provides: [], conflicts: [], replaces: [] } })),
    runtimeTests: outputContract.runtimeGroups.map((outputs) => ({ outputs, environment: runtime.runtimeEnvironment, smokePassed: true,
      analyses: outputs.map((name) => ({ name, runtimeAnalysis: { ...runtime.runtimeAnalysis, nativeCode: [] as string[], payloadSha256: 'e'.repeat(64) } })) })) };
  const provenance = JSON.stringify(report);
  const provenanceSignature = Buffer.from(await crypto.subtle.sign('Ed25519', workerKey.privateKey, encode(provenance))).toString('base64');
  const statement = await releaseAttestation({ buildId: report.buildId, revisionId: report.revisionId, surface: 'binary', artifactFilename: null, artifactSha256: null,
    recipe: 'pkgname=native', recipeSha256: report.recipeSha256, manifestSha256: 'f'.repeat(64), sbom: '{}', provenance, provenanceSignature, workerPublicKey });
  const statementKey = 'metadata/builds/build-1/attempts/2/attestation.json';
  const filename = report.outputs[0].filename;
  const artifactKey = `builds/build-1/attempt-2/upload-fixture/${artifactSha256}-${filename}`;
  const objects = new Map<string, Uint8Array>([[artifactKey, artifact], [statementKey, encode(statement)]]);
  const metadata = new Map<string, Record<string, string>>();
  const bucket = {
    async get(key: string) { const bytes = objects.get(key); return bytes ? { size: bytes.byteLength, body: new Response(bytes.slice().buffer as ArrayBuffer).body, arrayBuffer: async () => bytes.slice().buffer } : null; },
    async head(key: string) { const bytes = objects.get(key); return bytes ? { size: bytes.byteLength, customMetadata: metadata.get(key) ?? {} } : null; },
    async put(key: string, value: string | Uint8Array, options: { customMetadata?: Record<string, string> }) { objects.set(key, typeof value === 'string' ? encode(value) : value); metadata.set(key, options.customMetadata ?? {}); },
  };
  const base = { id: 'native-intent', status: 'ready', expiresAt: Math.floor(Date.now() / 1000) + 600, keyFingerprint: fingerprint,
    build: { id: report.buildId, revisionId: report.revisionId, status: 'succeeded', surface: 'binary', architecture: 'x86_64', workerId: report.workerId, smokePassed: true, attempt: 2 },
    review: { manifestSha256: 'f'.repeat(64), areaApproved: true, securityApproved: true, outputContract }, attestation: { provenance, provenanceSignature, workerPublicKey } };
  let control: Record<string, unknown> = { ...base, kind: 'package', artifact: { key: artifactKey, filename, sha256: artifactSha256, size: artifact.length } };
  const originalFetch = globalThis.fetch;
  globalThis.fetch = (async (input: RequestInfo | URL) => {
    const path = new URL(String(input)).pathname;
    if (path === '/api/internal/signing-intents/native-intent') return Response.json(control);
    if (path === '/api/internal/signing-events') return Response.json({});
    throw new Error(`Unexpected test fetch ${path}`);
  }) as typeof fetch;
  const env = { ARTIFACTS: bucket, CONTROL_ORIGIN: 'https://control.example.org', PUBLIC_ORIGIN: 'https://example.org', KEY_ID: 'native-test',
    SIGNER_TOKEN: 'test-signer', CONTROL_TOKEN: 'test-control', OPR_SIGNING_PRIVATE_KEY_B64: btoa(key.privateKey), OPR_SIGNING_FINGERPRINT: fingerprint } as unknown as Env;
  const sign = () => signer.fetch(new Request('https://signer/v1/sign', { method: 'POST', headers: { authorization: 'Bearer test-signer' }, body: JSON.stringify({ intentId: base.id }) }), env);
  try {
    const response = await sign(); expect(response.status).toBe(200);
    const signed = await response.json() as { signatureSha256: string };
    expect(await sha256(objects.get(`${artifactKey}.sig`)!)).toBe(signed.signatureSha256);
    const verified = await openpgp.verify({ message: await openpgp.createMessage({ binary: artifact }), signature: await openpgp.readSignature({ binarySignature: objects.get(`${artifactKey}.sig`)! }), verificationKeys: await openpgp.readKey({ armoredKey: key.publicKey }) });
    await verified.signatures[0].verified;
    control = { ...control, build: { ...base.build, attempt: 1 } };
    expect((await sign()).status).toBe(409);
    control = { ...base, kind: 'attestation', statement, artifact: { key: statementKey, filename: 'attestation.json', sha256: await sha256(statement), size: encode(statement).length } };
    expect((await sign()).status).toBe(200);
    const evidence = { statement: encode(statement), signature: objects.get(`${statementKey}.sig`)!, trustedPublicKey: key.publicKey, trustedFingerprint: fingerprint,
      subjectName: filename, subjectSha256: artifactSha256, sbomSha256: await sha256('{}') };
    for (const output of report.outputs) expect((await verifyReleaseEvidence({ ...evidence, subjectName: output.filename })).buildId).toBe('build-1');
    const centralSign = async (text: string) => await openpgp.sign({ message: await openpgp.createMessage({ binary: encode(text) }), signingKeys: privateKey, detached: true, format: 'binary' }) as Uint8Array;
    for (const edit of [
      (value: any) => value.subject.pop(),
      (value: any) => value.predicate.buildDefinition.externalParameters.attempt++,
      (value: any) => value.predicate.buildDefinition.resolvedDependencies.pop(),
      (value: any) => value.predicate.buildDefinition.externalParameters.inputPolicy = 'owned',
    ]) {
      const changed = JSON.parse(statement); edit(changed); const text = JSON.stringify(changed);
      await expect(verifyReleaseEvidence({ ...evidence, statement: encode(text), signature: await centralSign(text) })).rejects.toThrow();
    }
    const bad = structuredClone(report); bad.runtimeTests[1].analyses[0].runtimeAnalysis.nativeCode.push('usr/lib/hidden.a');
    const badRaw = JSON.stringify(bad);
    control = { ...base, kind: 'package', artifact: { key: artifactKey, filename, sha256: artifactSha256, size: artifact.length },
      attestation: { ...base.attestation, provenance: badRaw, provenanceSignature: Buffer.from(await crypto.subtle.sign('Ed25519', workerKey.privateKey, encode(badRaw))).toString('base64') } };
    expect((await sign()).status).toBe(409);
  } finally { globalThis.fetch = originalFetch; }
});
