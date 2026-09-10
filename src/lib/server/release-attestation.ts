import { readOprEvidence } from './sbom';
import { sha256 } from './db';
import { assertOutputEvidence, outputResolvedDependencies } from './output-evidence';
import { reviewedRuntimeExceptions } from './runtime-evidence';

export const RELEASE_BUILD_TYPE = 'https://github.com/ferrreo/omapkg/blob/main/docs/build-type-v1.md';

export const OUTPUT_BUILD_TYPE = 'https://github.com/ferrreo/omapkg/blob/main/docs/build-type-v2.md';

export interface ReleaseAttestationInput {
  buildId: string;
  revisionId: string;
  surface: 'binary' | 'recipe';
  artifactFilename: string | null;
  artifactSha256: string | null;
  recipe: string;
  recipeSha256: string;
  manifestSha256: string;
  sbom: string;
  provenance: string;
  provenanceSignature: string;
  workerPublicKey: string;
}

function base64(text: string): string {
  let binary = '';
  for (const byte of new TextEncoder().encode(text)) binary += String.fromCharCode(byte);
  return btoa(binary);
}

// Call only after validating the worker signature and the current reviewed build.
// No publication timestamp: retries must produce the same bytes.
export async function releaseAttestation(input: ReleaseAttestationInput): Promise<string> {
  const provenance = JSON.parse(input.provenance);
  const outputs = provenance.schemaVersion === 2 ? await assertOutputEvidence(provenance, reviewedRuntimeExceptions(input.sbom)) : null;
  if (outputs && input.surface !== 'binary') throw new Error('V2 output attestation requires a binary build');
  const publishedRecipeSha256 = await sha256(input.recipe);
  if (input.surface === 'binary' && !outputs && (!input.artifactFilename || !input.artifactSha256)) {
    throw new Error('Binary attestation requires an artifact subject');
  }
  return JSON.stringify({
    _type: 'https://in-toto.io/Statement/v1',
    subject: outputs ? [...outputs.outputs].sort((a, b) => a.filename < b.filename ? -1 : a.filename > b.filename ? 1 : 0).map((output) => ({ name: output.filename, digest: { sha256: output.artifactSha256 } })) : [{
      name: input.surface === 'binary' ? input.artifactFilename : 'PKGBUILD',
      digest: { sha256: input.surface === 'binary' ? input.artifactSha256 : publishedRecipeSha256 },
    }],
    predicateType: 'https://slsa.dev/provenance/v1',
    predicate: {
      buildDefinition: {
        buildType: outputs ? OUTPUT_BUILD_TYPE : RELEASE_BUILD_TYPE,
        externalParameters: {
          revisionId: input.revisionId,
          ...(outputs ? { attempt: outputs.attempt, outputContract: outputs.outputContract, inputPolicy: outputs.frozenInputs?.manifest.purpose ?? 'shadow' } : {}),
          surface: input.surface,
          manifestSha256: input.manifestSha256,
          recipeSha256: input.recipeSha256,
          publishedRecipeSha256,
          runtimeExceptions: reviewedRuntimeExceptions(input.sbom),
          recipePolicy: readOprEvidence(JSON.parse(input.sbom))?.recipePolicy ?? { mode: 'custom-shell', recorded: false },
        },
        resolvedDependencies: outputs ? outputResolvedDependencies(outputs) : [
          ...provenance.sources.map((source: { name: string; url: string; sha256: string }) => ({
            name: source.name, uri: source.url, digest: { sha256: source.sha256 },
          })),
          { name: 'builder-image', digest: { sha256: provenance.imageDigest.replace(/^sha256:/, '') } },
        ],
      },
      runDetails: {
        builder: { id: `urn:omapkg:worker-key:${await sha256(input.workerPublicKey)}` },
        metadata: { invocationId: input.buildId, startedOn: provenance.startedAt, finishedOn: provenance.finishedAt },
        byproducts: [
          {
            name: 'worker-provenance.json', mediaType: 'application/json',
            digest: { sha256: await sha256(input.provenance) }, content: base64(input.provenance),
            annotations: { signature: input.provenanceSignature, publicKey: input.workerPublicKey, algorithm: 'Ed25519' },
          },
          { name: 'sbom.json', mediaType: 'application/spdx+json', digest: { sha256: await sha256(input.sbom) } },
        ],
      },
    },
  });
}

export function attestationKey(buildId: string, attempt?: number): string {
  return `metadata/builds/${buildId}/${attempt === undefined ? '' : `attempts/${attempt}/`}attestation.json`;
}
