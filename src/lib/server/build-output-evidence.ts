import type { Worker } from '../model';
import { archRelationCovers } from './arch';
import { packageFilename, parseOutputMetadata, storedOutputContract } from './build-outputs';
import { parseDependencyPlan, dependencyPlansEqual } from './dependency-plan';
import { assertRuntimeEvidence, reviewedRuntimeExceptions } from './runtime-evidence';
import { WorkerProtocolError, decodeBase64, parseSources, parseStringArray, requireExactKeys, requireObject, sameJson, verifyEd25519, workerImage,
  type ArtifactReference, type WorkerLease } from './worker-protocol';

export async function verifyOutputProvenance(worker: Pick<Worker, 'id' | 'public_key' | 'architecture'>, build: WorkerLease,
  artifacts: ArtifactReference[], provenance: string, signature: string, installedSize: number | undefined): Promise<void> {
  const contract = storedOutputContract(build);
  if (!contract || worker.architecture !== build.architecture) throw new WorkerProtocolError(409, 'Native output contract is required');
  const report = requireObject(JSON.parse(provenance));
  const keys = ['schemaVersion', 'attempt', 'outputContract', 'buildId', 'revisionId', 'workerId', 'recipeSha256', 'architecture', 'imageDigest',
    'sourceDateEpoch', 'sources', 'network', 'startedAt', 'finishedAt', 'buildEnvironment', 'runtimeTests', 'outputs'];
  requireExactKeys(report, [...keys, 'dependencyPlan']);
  if (keys.some((key) => !Object.hasOwn(report, key))) throw new WorkerProtocolError(409, 'Incomplete v2 build evidence');
  const { imageDigest } = workerImage(build);
  if (report.schemaVersion !== 2 || report.attempt !== build.attempt || !sameJson(report.outputContract, contract) || report.buildId !== build.id ||
      report.revisionId !== build.revision_id || report.workerId !== worker.id || report.recipeSha256 !== build.revision_recipe_sha256 ||
      report.architecture !== build.architecture || report.imageDigest !== imageDigest || report.network !== 'disabled' ||
      report.sourceDateEpoch !== build.revision_source_date_epoch || !sameJson(report.sources, parseSources(build.revision_sources_json))) {
    throw new WorkerProtocolError(409, 'V2 provenance does not match leased inputs');
  }
  if (typeof report.startedAt !== 'string' || typeof report.finishedAt !== 'string' || !Number.isFinite(Date.parse(report.startedAt)) ||
      !Number.isFinite(Date.parse(report.finishedAt)) || Date.parse(report.finishedAt) < Date.parse(report.startedAt)) throw new WorkerProtocolError(409, 'Invalid build evidence timestamps');
  const expectedPlan = build.dependency_plan_json ? parseDependencyPlan(JSON.parse(build.dependency_plan_json)) : null;
  const actualPlan = report.dependencyPlan ? parseDependencyPlan(report.dependencyPlan) : null;
  if ((build.dependency_plan_json && !expectedPlan) || (report.dependencyPlan && !actualPlan) || !dependencyPlansEqual(expectedPlan, actualPlan)) {
    throw new WorkerProtocolError(409, 'V2 dependency plan differs from lease');
  }
  if (!Array.isArray(report.outputs) || report.outputs.length !== contract.outputs.length || artifacts.length !== contract.outputs.length) {
    throw new WorkerProtocolError(409, 'Build output set is incomplete');
  }
  const seen = new Set<string>();
  const relations: string[] = [];
  const metadataByName = new Map<string, NonNullable<ReturnType<typeof parseOutputMetadata>>>();
  let total = 0;
  for (const value of report.outputs) {
    const output = requireObject(value);
    requireExactKeys(output, ['pkgbase', 'filename', 'artifactSha256', 'packageMetadata']);
    const metadata = parseOutputMetadata(output.packageMetadata);
    const expected = contract.outputs.find((item) => item.name === metadata?.name);
    const artifact = artifacts.find((item) => item.filename === output.filename);
    if (output.pkgbase !== build.revision_name || !metadata || !expected || seen.has(metadata.name) || metadata.fullVersion !== expected.fullVersion || metadata.architecture !== expected.architecture ||
        output.filename !== packageFilename(expected) || artifact?.sha256 !== output.artifactSha256 || !artifact) {
      throw new WorkerProtocolError(409, 'Package output differs from reviewed identity or uploaded bytes');
    }
    seen.add(metadata.name);
    total += metadata.installedSize;
    relations.push(...metadata.depends);
    metadataByName.set(metadata.name, metadata);
  }
  if (!Array.isArray(report.runtimeTests) || report.runtimeTests.length !== contract.runtimeGroups.length) throw new WorkerProtocolError(409, 'Native installation test matrix is incomplete');
  const payloads = new Map<string, string>();
  for (const [index, value] of report.runtimeTests.entries()) {
    const test = requireObject(value);
    requireExactKeys(test, ['outputs', 'environment', 'analyses', 'smokePassed']);
    const group = contract.runtimeGroups[index];
    if (!sameJson(test.outputs, group) || test.smokePassed !== true || !Array.isArray(test.analyses) || test.analyses.length !== group.length) throw new WorkerProtocolError(409, 'Native installation group differs from reviewed matrix');
    const checked = new Set<string>();
    for (const value of test.analyses) {
      const item = requireObject(value);
      requireExactKeys(item, ['name', 'runtimeAnalysis']);
      if (typeof item.name !== 'string' || !group.includes(item.name) || checked.has(item.name)) throw new WorkerProtocolError(409, 'Output analysis is missing or duplicated');
      checked.add(item.name);
      const metadata = metadataByName.get(item.name)!;
      try {
        await assertRuntimeEvidence({ buildEnvironment: report.buildEnvironment, runtimeEnvironment: test.environment, runtimeAnalysis: item.runtimeAnalysis }, imageDigest, reviewedRuntimeExceptions(build.revision_sbom_json));
        const analysis = item.runtimeAnalysis as { elf: { machine: string }[]; nativeCode: string[]; payloadSha256: string };
        if (!/^[a-f0-9]{64}$/.test(analysis.payloadSha256) || (payloads.has(item.name) && payloads.get(item.name) !== analysis.payloadSha256)) throw new Error('Package payload comparison digest is missing or inconsistent');
        payloads.set(item.name, analysis.payloadSha256);
        if (!Array.isArray(analysis.nativeCode) || analysis.nativeCode.length > 4096 || analysis.nativeCode.some((path) => typeof path !== 'string' || !path || path.length > 4096)) throw new Error('Native code inspection is missing or invalid');
        if (metadata.architecture === 'any' && (analysis.elf.length || analysis.nativeCode.length)) throw new Error('Architecture-independent output contains native code');
        if (analysis.elf.some((elf) => !(build.architecture === 'aarch64' ? ['EM_AARCH64'] : ['EM_X86_64', 'EM_386']).includes(elf.machine))) throw new Error('Output ELF architecture differs from native target');
      } catch (cause) { throw new WorkerProtocolError(409, cause instanceof Error ? cause.message : 'Invalid output runtime evidence'); }
    }
  }

  if (!Number.isSafeInteger(total) || total !== installedSize) throw new WorkerProtocolError(409, 'Output installed size does not match completion');
  if (parseStringArray(build.revision_dependencies_json, 'dependencies', 256).some((reviewed) => !relations.some((native) => archRelationCovers(native, reviewed)))) {
    throw new WorkerProtocolError(409, 'Output metadata omits reviewed runtime dependencies');
  }
  if (!await verifyEd25519(decodeBase64(worker.public_key, 'worker public key'), new TextEncoder().encode(provenance), decodeBase64(signature, 'provenance signature'))) {
    throw new WorkerProtocolError(401, 'Invalid v2 provenance signature');
  }
}
