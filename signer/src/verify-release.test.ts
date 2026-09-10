import { runtimeEvidence } from '../../tests/runtime-fixtures';
import { expect, test } from 'bun:test';
import * as openpgp from 'openpgp';
import { releaseAttestation } from '../../src/lib/server/release-attestation';
import { sha256 } from '../../src/lib/server/db';
import { verifyReleaseEvidence } from './verify-release';

test('public evidence verifies both subjects and rejects tampering, substitution, and untrusted keys', async () => {
  const generated = await openpgp.generateKey({ type: 'rsa', rsaBits: 2048, userIDs: [{ name: 'Test release key' }], format: 'armored', config: { v6Keys: false } });
  const privateKey = await openpgp.readPrivateKey({ armoredKey: generated.privateKey });
  const workerKey = await crypto.subtle.generateKey('Ed25519', true, ['sign', 'verify']);
  const bytes = (value: string) => new TextEncoder().encode(value);
  const encode = (value: ArrayBuffer) => Buffer.from(value).toString('base64');
  const workerPublicKey = encode(await crypto.subtle.exportKey('raw', workerKey.publicKey));
  const recipe = 'pkgname=hello\n';

  const provenance = JSON.stringify({
    buildId: 'build-1', revisionId: 'revision-1', workerId: 'worker-1',
    recipeSha256: await sha256(recipe), artifactSha256: await sha256('package'),
    sources: [{ name: 'source.tar', url: 'https://example.org/source.tar', sha256: 'a'.repeat(64) }],
    imageDigest: `sha256:${'b'.repeat(64)}`, network: 'disabled', ...runtimeEvidence(`sha256:${'b'.repeat(64)}`),
    startedAt: '2026-09-09T10:00:00Z', finishedAt: '2026-09-09T10:01:00Z',
  });

  const input = {
    buildId: 'build-1', revisionId: 'revision-1', surface: 'binary' as const,
    artifactFilename: 'hello.pkg.tar.zst', artifactSha256: await sha256('package'),
    recipe, recipeSha256: await sha256(recipe), manifestSha256: 'c'.repeat(64), sbom: '{}',
    provenance, provenanceSignature: encode(await crypto.subtle.sign('Ed25519', workerKey.privateKey, bytes(provenance))), workerPublicKey,
  };

  const statement = bytes(await releaseAttestation(input));
  expect(statement).toEqual(bytes(await releaseAttestation(input)));

  async function sign(statement: Uint8Array) {
    return await openpgp.sign({ message: await openpgp.createMessage({ binary: statement }), signingKeys: privateKey, detached: true, format: 'binary' }) as Uint8Array;
  }

  const evidence = {
    statement, signature: await sign(statement), trustedPublicKey: generated.publicKey,
    trustedFingerprint: privateKey.getFingerprint(), subjectSha256: input.artifactSha256,
    subjectName: input.artifactFilename, sbomSha256: await sha256('{}'),
  };

  expect(await verifyReleaseEvidence(evidence)).toEqual({ buildId: 'build-1', surface: 'binary', workerId: 'worker-1' });
  await expect(verifyReleaseEvidence({ ...evidence, subjectSha256: await sha256('modified package') })).rejects.toThrow('subject');
  await expect(verifyReleaseEvidence({ ...evidence, trustedFingerprint: 'd'.repeat(40) })).rejects.toThrow('trusted fingerprint');
  await expect(verifyReleaseEvidence({ ...evidence, statement: bytes(new TextDecoder().decode(statement).replace('revision-1', 'revision-2')) })).rejects.toThrow();
  await expect(verifyReleaseEvidence({ ...evidence, sbomSha256: 'e'.repeat(64) })).rejects.toThrow('SBOM');

  const swapped = JSON.parse(new TextDecoder().decode(statement));
  swapped.predicate.runDetails.metadata.invocationId = 'another-build';
  const swappedBytes = bytes(JSON.stringify(swapped));
  await expect(verifyReleaseEvidence({ ...evidence, statement: swappedBytes, signature: await sign(swappedBytes) })).rejects.toThrow('different build');

  const publicRecipe = recipe + '# public source recipe\n';
  const recipeStatement = bytes(await releaseAttestation({ ...input, surface: 'recipe', artifactFilename: null, artifactSha256: null, recipe: publicRecipe }));
  const recipeEvidence = { ...evidence, statement: recipeStatement, signature: await sign(recipeStatement), subjectName: 'PKGBUILD', subjectSha256: await sha256(publicRecipe) };
  expect((await verifyReleaseEvidence(recipeEvidence)).surface).toBe('recipe');
  await expect(verifyReleaseEvidence({ ...recipeEvidence, subjectSha256: await sha256(recipe) })).rejects.toThrow('subject');
});
