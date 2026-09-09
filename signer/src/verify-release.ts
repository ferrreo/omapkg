import * as openpgp from 'openpgp';
import { createHash } from 'node:crypto';
import { assertRuntimeEvidence, runtimeExceptions } from '../../src/lib/server/runtime-evidence';
import { assertOutputEvidence, outputResolvedDependencies } from '../../src/lib/server/output-evidence';
import { canonicalJson } from '../../src/lib/canonical-json';

const digest = (bytes: Uint8Array | string) => createHash('sha256').update(bytes).digest('hex');

export async function verifyReleaseEvidence(input: {
  statement: Uint8Array;
  signature: Uint8Array;
  trustedPublicKey: string;
  trustedFingerprint: string;
  subjectSha256: string;
  subjectName: string;
  sbomSha256?: string;
}): Promise<{ buildId: string; surface: 'binary' | 'recipe'; workerId: string }> {
  if (input.statement.byteLength > 1024 * 1024 || input.signature.byteLength > 1024 * 1024) throw new Error('Evidence exceeds size limit');
  const key = await openpgp.readKey({ armoredKey: input.trustedPublicKey });
  if (!/^[a-f0-9]{40}$/i.test(input.trustedFingerprint) || key.getFingerprint() !== input.trustedFingerprint.toLowerCase()) {
    throw new Error('Release key does not match independently trusted fingerprint');
  }
  const verified = await openpgp.verify({
    message: await openpgp.createMessage({ binary: input.statement }),
    signature: await openpgp.readSignature({ binarySignature: input.signature }), verificationKeys: key,
  });
  if (verified.signatures.length !== 1) throw new Error('Expected one release signature');
  await verified.signatures[0].verified;
  return verifyStatementEvidence(input);
}

export async function verifyStatementEvidence(input: {
  statement: Uint8Array; subjectName: string; subjectSha256: string; sbomSha256?: string;
}): Promise<{ buildId: string; surface: 'binary' | 'recipe'; workerId: string }> {
  const statement = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(input.statement));
  const predicate = statement.predicate;
  const parameters = predicate?.buildDefinition?.externalParameters;
  const v2 = predicate?.buildDefinition?.buildType === 'https://github.com/ferrreo/omapkg/blob/main/docs/build-type-v2.md';
  if (statement._type !== 'https://in-toto.io/Statement/v1' || statement.predicateType !== 'https://slsa.dev/provenance/v1' ||
      (!v2 && predicate?.buildDefinition?.buildType !== 'https://github.com/ferrreo/omapkg/blob/main/docs/build-type-v1.md') ||
      !['binary', 'recipe'].includes(parameters?.surface) || !/^[a-f0-9]{64}$/.test(parameters?.manifestSha256) ||
      !Array.isArray(statement.subject) || (!v2 && statement.subject.length !== 1) ||
      !statement.subject.some((item: { name: string; digest?: { sha256?: string } }) => item.name === input.subjectName && item.digest?.sha256 === input.subjectSha256)) {
    throw new Error('Release statement does not match expected subject or build type');
  }
  const byproducts = predicate.runDetails?.byproducts;
  const reports = Array.isArray(byproducts) ? byproducts.filter((item) => item.name === 'worker-provenance.json') : [];
  if (reports.length !== 1) throw new Error('Worker evidence is missing or ambiguous');
  const report = reports[0];
  const raw = Uint8Array.from(atob(report.content), (character) => character.charCodeAt(0));
  const publicKey = Uint8Array.from(atob(report.annotations.publicKey), (character) => character.charCodeAt(0));
  const signature = Uint8Array.from(atob(report.annotations.signature), (character) => character.charCodeAt(0));
  if (report.annotations.algorithm !== 'Ed25519' || publicKey.length !== 32 || signature.length !== 64 ||
      report.digest?.sha256 !== digest(raw) || predicate.runDetails.builder?.id !== `urn:omapkg:worker-key:${digest(report.annotations.publicKey)}`) {
    throw new Error('Worker identity or evidence digest mismatch');
  }
  const workerKey = await crypto.subtle.importKey('raw', publicKey, 'Ed25519', false, ['verify']);
  if (!await crypto.subtle.verify('Ed25519', workerKey, signature, raw)) throw new Error('Invalid worker signature');
  const worker = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(raw));
  if (v2) {
    const report = await assertOutputEvidence(worker, runtimeExceptions(parameters.runtimeExceptions));
    const subjects = [...report.outputs].sort((a, b) => a.filename < b.filename ? -1 : a.filename > b.filename ? 1 : 0)
      .map((output) => ({ name: output.filename, digest: { sha256: output.artifactSha256 } }));
    if (parameters.surface !== 'binary' || parameters.inputPolicy !== 'shadow' || parameters.attempt !== report.attempt ||
        canonicalJson(parameters.outputContract) !== canonicalJson(report.outputContract) || canonicalJson(subjects) !== canonicalJson(statement.subject)) {
      throw new Error('V2 statement does not bind the complete reviewed output set');
    }
    if (canonicalJson(predicate.buildDefinition.resolvedDependencies) !== canonicalJson(outputResolvedDependencies(report))) throw new Error('Resolved inputs differ from worker evidence');
  } else {
    if (worker.schemaVersion === 2) throw new Error('V2 worker evidence requires the v2 build type');
    await assertRuntimeEvidence(worker, worker.imageDigest, runtimeExceptions(parameters.runtimeExceptions));
  }
  if (worker.buildId !== predicate.runDetails.metadata?.invocationId || worker.revisionId !== parameters.revisionId ||
      worker.recipeSha256 !== parameters.recipeSha256 || worker.network !== 'disabled' ||
      worker.startedAt !== predicate.runDetails.metadata.startedOn || worker.finishedAt !== predicate.runDetails.metadata.finishedOn ||
      (!v2 && parameters.surface === 'binary' && worker.artifactSha256 !== input.subjectSha256) ||
      (parameters.surface === 'recipe' && parameters.publishedRecipeSha256 !== input.subjectSha256)) {
    throw new Error('Worker evidence belongs to a different build or subject');
  }
  const dependencies = predicate.buildDefinition.resolvedDependencies;
  if (!v2 && (!Array.isArray(dependencies) || !Array.isArray(worker.sources) || dependencies.length !== worker.sources.length + 1 ||
      worker.sources.some((source: { name: string; url: string; sha256: string }, index: number) =>
        source.name !== dependencies[index]?.name || source.url !== dependencies[index]?.uri || source.sha256 !== dependencies[index]?.digest?.sha256) ||
      dependencies.at(-1)?.digest?.sha256 !== worker.imageDigest?.replace(/^sha256:/, ''))) {
    throw new Error('Resolved inputs differ from worker evidence');
  }
  if (input.sbomSha256) {
    const sboms = byproducts.filter((item: { name: string }) => item.name === 'sbom.json');
    if (sboms.length !== 1 || sboms[0].digest?.sha256 !== input.sbomSha256) throw new Error('SBOM digest mismatch');
  }
  return { buildId: worker.buildId, surface: parameters.surface, workerId: worker.workerId };
}
