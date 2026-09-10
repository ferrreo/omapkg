import type { Architecture, Source } from '../model';
import { canonicalJson } from '../canonical-json';
import { packageFilename, parseOutputContract, parseOutputMetadata, type OutputContract, type OutputMetadata } from '../output-contract';
import { assertRuntimeEvidence, assertRuntimeAnalysis, preparedEnvironment, type RuntimeException } from './runtime-evidence';
import { assertFrozenEvidence, type FrozenEvidence } from '../frozen-inputs';
import { parseDependencyPlan, type DependencyPlan } from './dependency-plan';
import { parsePreservedBuildInputs, type PreservedBuildInputs } from '../preserved-recipe';
import { parseAbiReference } from '../abi-inventory';
import type { InputObject } from '../frozen-inputs';
import { sha256 } from './db';

export interface ReproducibilityContract {
  schemaVersion: 1;
  status: 'reproducibility-contract-verified';
  mode: 'single-build';
  target: Architecture;
  execution?: { runId: string; attempt: number; inputSha256: string };
  inputs: { recipeSha256: string; sourceManifestSha256: string; inputLockSha256: string; dependencyPlanSha256: string; imageDigest: string; sourceDateEpoch: number };
  controls: { network: 'disabled'; locale: 'C'; timezone: 'UTC'; umask: '022'; hostSecrets: 'excluded'; writableCaches: 'excluded'; nativeTarget: Architecture; archivePathsChecked: true; archiveMetadataChecked: true; timestampOwnershipOrderChecked: true };
  outputs: { setSha256: string; files: { filename: string; size: number; sha256: string }[]; unexpected: string[]; prohibitedPaths: string[] };
  limitations: string[];
}

export interface OutputEvidence {
  schemaVersion: 2; attempt: number; outputContract: OutputContract;
  buildId: string; revisionId: string; workerId: string; recipeSha256: string; architecture: Architecture;
  factoryRunId?: string; factoryAttempt?: number; factoryInputSha256?: string;
  imageDigest: string; sourceDateEpoch: number; sources: Source[]; network: 'disabled'; startedAt: string; finishedAt: string;
  dependencyPlan?: DependencyPlan | null; frozenInputs?: FrozenEvidence; preservedRecipe?: PreservedBuildInputs; buildEnvironment: unknown;
  reproducibility?: ReproducibilityContract;
  outputs: { pkgbase: string; filename: string; artifactSha256: string; packageMetadata: OutputMetadata }[];
  runtimeTests: { outputs: string[]; environment: { baseImage: string; preparedImage: string }; smokePassed: true;
    analyses: { name: string; runtimeAnalysis: { elf: { machine: string }[]; nativeCode: string[]; payloadSha256: string; abiInventory?: InputObject } }[] }[];
}

const hash = /^[a-f0-9]{64}$/;

function keys(value: unknown, required: string[], optional: string[] = []): void {
  if (!value || typeof value !== 'object' || Array.isArray(value) || required.some((key) => !Object.hasOwn(value, key)) ||
      Object.keys(value).some((key) => !required.includes(key) && !optional.includes(key))) throw new Error('Incomplete or unexpected v2 evidence fields');
}

// Shared by ingestion, the isolated signer and the offline verifier; no database authority is inferred here.
export async function assertOutputEvidence(value: unknown, exceptions: RuntimeException[]): Promise<OutputEvidence> {
  keys(value, ['schemaVersion', 'attempt', 'outputContract', 'buildId', 'revisionId', 'workerId', 'recipeSha256', 'architecture', 'imageDigest',
    'sourceDateEpoch', 'sources', 'network', 'startedAt', 'finishedAt', 'buildEnvironment', 'runtimeTests', 'outputs'], ['dependencyPlan', 'frozenInputs', 'preservedRecipe', 'reproducibility', 'factoryRunId', 'factoryAttempt', 'factoryInputSha256']);
  const report = value as OutputEvidence;

  if (report.schemaVersion !== 2 || !Number.isSafeInteger(report.attempt) || report.attempt < 1 ||
      !['x86_64', 'aarch64'].includes(report.architecture) || !hash.test(report.recipeSha256) || !/^sha256:[a-f0-9]{64}$/.test(report.imageDigest) ||
      [report.buildId, report.revisionId, report.workerId].some((id) => typeof id !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/.test(id)) ||
      report.network !== 'disabled' || !Number.isSafeInteger(report.sourceDateEpoch) || report.sourceDateEpoch < 0 ||
      !Array.isArray(report.sources) || report.sources.length > 64 || report.sources.some((source) => !source || typeof source.name !== 'string' ||
        !source.name || typeof source.url !== 'string' || !source.url.startsWith('https://') || !hash.test(source.sha256))) throw new Error('Invalid v2 build identity or inputs');

  if (typeof report.startedAt !== 'string' || typeof report.finishedAt !== 'string' || !Number.isFinite(Date.parse(report.startedAt)) ||
      !Number.isFinite(Date.parse(report.finishedAt)) || Date.parse(report.finishedAt) < Date.parse(report.startedAt)) throw new Error('Invalid build evidence timestamps');

  if (report.dependencyPlan !== undefined && report.dependencyPlan !== null && !parseDependencyPlan(report.dependencyPlan)) throw new Error('Invalid v2 dependency plan');
  const contract = parseOutputContract(report.outputContract, report.architecture);
  if (report.reproducibility !== undefined) await assertReproducibilityContract(report.reproducibility, report, contract);

  if (report.preservedRecipe !== undefined) {
    parsePreservedBuildInputs(report.preservedRecipe);

    if (!report.frozenInputs || report.sources.length || report.dependencyPlan) throw new Error('Preserved recipes require frozen inputs and retained source bundles');
  }

  if (!Array.isArray(report.outputs) || report.outputs.length !== contract.outputs.length) throw new Error('Build output set is incomplete');
  const metadataByName = new Map<string, OutputMetadata>();
  const pkgbases = new Set<string>();
  let installedSize = 0;

  for (const output of report.outputs) {
    keys(output, ['pkgbase', 'filename', 'artifactSha256', 'packageMetadata']);
    const metadata = parseOutputMetadata(output.packageMetadata);
    const expected = contract.outputs.find((item) => item.name === metadata?.name);

    if (!metadata || !expected || metadataByName.has(metadata.name) || metadata.fullVersion !== expected.fullVersion || metadata.architecture !== expected.architecture ||
        output.filename !== packageFilename(expected) || !hash.test(output.artifactSha256) || typeof output.pkgbase !== 'string' ||
        !/^[a-z0-9][a-z0-9@._+-]{0,63}$/.test(output.pkgbase)) throw new Error('Package output differs from reviewed identity');
    metadataByName.set(metadata.name, metadata); pkgbases.add(output.pkgbase); installedSize += metadata.installedSize;
  }

  if (pkgbases.size !== 1 || !Number.isSafeInteger(installedSize)) throw new Error('Inconsistent output package base or size');

  if (!Array.isArray(report.runtimeTests) || report.runtimeTests.length !== contract.runtimeGroups.length) throw new Error('Native installation test matrix is incomplete');

  if (report.frozenInputs !== undefined) {
    if (report.dependencyPlan) throw new Error('Frozen inputs cannot include a live dependency plan');
    await assertFrozenEvidence(report.frozenInputs, { architecture: report.architecture, recipeSha256: report.recipeSha256,
      cohortSha256: contract.cohort.manifestSha256, sourceDateEpoch: report.sourceDateEpoch, imageDigest: report.imageDigest,
      environments: [preparedEnvironment(report.buildEnvironment), ...report.runtimeTests.map((test) => preparedEnvironment(test.environment))] });
  }

  const payloads = new Map<string, string>();
  const abi = new Map<string, string>();

  for (const [index, test] of report.runtimeTests.entries()) {
    keys(test, ['outputs', 'environment', 'analyses', 'smokePassed']);
    const group = contract.runtimeGroups[index];

    if (canonicalJson(test.outputs) !== canonicalJson(group) || test.smokePassed !== true || !Array.isArray(test.analyses) || test.analyses.length !== group.length) throw new Error('Native installation group differs from reviewed matrix');
    const checked = new Set<string>();

    for (const item of test.analyses) {
      keys(item, ['name', 'runtimeAnalysis']);

      if (typeof item.name !== 'string' || !group.includes(item.name) || checked.has(item.name)) throw new Error('Output analysis is missing or duplicated');
      checked.add(item.name);

      if (report.frozenInputs) await assertRuntimeAnalysis(item.runtimeAnalysis, exceptions);
      else await assertRuntimeEvidence({ buildEnvironment: report.buildEnvironment, runtimeEnvironment: test.environment, runtimeAnalysis: item.runtimeAnalysis }, report.imageDigest, exceptions);
      const analysis = item.runtimeAnalysis;

      if (analysis.abiInventory !== undefined) parseAbiReference(analysis.abiInventory);
      const ref = canonicalJson(analysis.abiInventory ?? null);

      if (abi.has(item.name) && abi.get(item.name) !== ref) throw new Error('ABI inventory differs between installation groups');
      abi.set(item.name, ref);

      if (!hash.test(analysis.payloadSha256) || (payloads.has(item.name) && payloads.get(item.name) !== analysis.payloadSha256)) throw new Error('Package payload comparison digest is missing or inconsistent');
      payloads.set(item.name, analysis.payloadSha256);

      if (!Array.isArray(analysis.nativeCode) || analysis.nativeCode.length > 4096 || analysis.nativeCode.some((path) => typeof path !== 'string' || !path || path.length > 4096)) throw new Error('Native code inspection is missing or invalid');

      if (metadataByName.get(item.name)!.architecture === 'any' && (analysis.elf.length || analysis.nativeCode.length)) throw new Error('Architecture-independent output contains native code');

      if (analysis.elf.some((elf) => !(report.architecture === 'aarch64' ? ['EM_AARCH64'] : ['EM_X86_64', 'EM_386']).includes(elf.machine))) throw new Error('Output ELF architecture differs from native target');
    }
  }

  return report;
}

export async function requireReproducibilityContract(report: OutputEvidence, contract = report.outputContract): Promise<ReproducibilityContract> {
  if (!report.reproducibility) throw new Error('Single-build reproducibility contract is missing');
  await assertReproducibilityContract(report.reproducibility, report, contract);
  return report.reproducibility;
}

type ReproducibilityExpectation = {
  architecture: Architecture; recipeSha256: string; imageDigest: string; sourceDateEpoch: number; sources: unknown;
  inputLockSha256: string; dependencyPlan?: unknown; factoryRunId?: string; factoryAttempt?: number; factoryInputSha256?: string;
};

async function validateReproducibilityContract(value: unknown, expected: ReproducibilityExpectation): Promise<{ contract: ReproducibilityContract; files: { filename: string; size: number; sha256: string }[] }> {
  const item = value as Record<string, unknown>;
  keys(item, ['schemaVersion', 'status', 'mode', 'target', 'inputs', 'controls', 'outputs', 'limitations'], ['execution']);
  if (item.schemaVersion !== 1 || item.status !== 'reproducibility-contract-verified' || item.mode !== 'single-build' || item.target !== expected.architecture) throw new Error('Single-build reproducibility contract is missing or invalid');
  if (expected.factoryRunId) {
    const execution = item.execution as Record<string, unknown>; keys(execution, ['runId', 'attempt', 'inputSha256']);
    if (execution.runId !== expected.factoryRunId || execution.attempt !== expected.factoryAttempt || execution.inputSha256 !== expected.factoryInputSha256) throw new Error('Factory execution identity differs from reproducibility evidence');
  }
  const inputs = item.inputs as Record<string, unknown>; keys(inputs, ['recipeSha256', 'sourceManifestSha256', 'inputLockSha256', 'dependencyPlanSha256', 'imageDigest', 'sourceDateEpoch']);
  const sourceManifestSha256 = await sha256(canonicalJson(expected.sources));
  const dependencyPlanSha256 = expected.dependencyPlan === undefined ? '' : await sha256(canonicalJson(expected.dependencyPlan));
  if (inputs.recipeSha256 !== expected.recipeSha256 || inputs.sourceManifestSha256 !== sourceManifestSha256 || inputs.inputLockSha256 !== expected.inputLockSha256 || inputs.dependencyPlanSha256 !== dependencyPlanSha256 || inputs.imageDigest !== expected.imageDigest || inputs.sourceDateEpoch !== expected.sourceDateEpoch) throw new Error('Single-build reproducibility inputs do not match provenance');
  const controls = item.controls as Record<string, unknown>; keys(controls, ['network', 'locale', 'timezone', 'umask', 'hostSecrets', 'writableCaches', 'nativeTarget', 'archivePathsChecked', 'archiveMetadataChecked', 'timestampOwnershipOrderChecked']);
  if (controls.network !== 'disabled' || controls.locale !== 'C' || controls.timezone !== 'UTC' || controls.umask !== '022' || controls.hostSecrets !== 'excluded' || controls.writableCaches !== 'excluded' || controls.nativeTarget !== expected.architecture || controls.archivePathsChecked !== true || controls.archiveMetadataChecked !== true || controls.timestampOwnershipOrderChecked !== true) throw new Error('Single-build reproducibility controls were not observed');
  const outputs = item.outputs as Record<string, unknown>; keys(outputs, ['setSha256', 'files', 'unexpected', 'prohibitedPaths']);
  if (!Array.isArray(outputs.unexpected) || outputs.unexpected.length || !Array.isArray(outputs.prohibitedPaths) || outputs.prohibitedPaths.length || !Array.isArray(outputs.files)) throw new Error('Single-build reproducibility output inspection is incomplete');
  const files = outputs.files.map((entry) => { const file = entry as Record<string, unknown>; keys(file, ['filename', 'size', 'sha256']); if (typeof file.filename !== 'string' || typeof file.size !== 'number' || !Number.isSafeInteger(file.size) || file.size <= 0 || typeof file.sha256 !== 'string' || !hash.test(file.sha256)) throw new Error('Invalid single-build reproducibility output'); return { filename: file.filename, size: file.size, sha256: file.sha256 }; }).sort((left, right) => left.filename.localeCompare(right.filename));
  if (typeof outputs.setSha256 !== 'string' || outputs.setSha256 !== await sha256(canonicalJson(files))) throw new Error('Single-build reproducibility output identity differs from provenance');
  if (!Array.isArray(item.limitations) || item.limitations.length < 1 || item.limitations.some((entry) => typeof entry !== 'string')) throw new Error('Single-build reproducibility limitations are missing');
  return { contract: value as ReproducibilityContract, files };
}

export async function assertStandaloneReproducibilityContract(value: unknown, expected: ReproducibilityExpectation & { output?: { filename: string; size: number; sha256: string } }): Promise<ReproducibilityContract> {
  const result = await validateReproducibilityContract(value, expected);
  if (expected.output && (result.files.length !== 1 || canonicalJson(result.files[0]) !== canonicalJson(expected.output))) throw new Error('Single-build reproducibility output identity differs from provenance');
  return result.contract;
}

async function assertReproducibilityContract(value: unknown, report: OutputEvidence, contract: OutputContract): Promise<void> {
  const result = await validateReproducibilityContract(value, { architecture: report.architecture, recipeSha256: report.recipeSha256, imageDigest: report.imageDigest,
    sourceDateEpoch: report.sourceDateEpoch, sources: report.sources, inputLockSha256: report.frozenInputs?.lock.sha256 ?? '', dependencyPlan: report.dependencyPlan,
    factoryRunId: report.factoryRunId, factoryAttempt: report.factoryAttempt, factoryInputSha256: report.factoryInputSha256 });
  const expected = report.outputs.map((output) => ({ filename: output.filename, sha256: output.artifactSha256 })).sort((left, right) => left.filename.localeCompare(right.filename));
  if (result.files.length !== expected.length || result.files.some((file, index) => file.filename !== expected[index].filename || file.sha256 !== expected[index].sha256) || result.files.some((file) => !contract.outputs.some((output) => packageFilename(output) === file.filename))) throw new Error('Single-build reproducibility output identity differs from provenance');
}

export function outputResolvedDependencies(report: OutputEvidence) {
  if (report.frozenInputs) {
    const { lock, manifest } = report.frozenInputs;

    return [
      ...report.sources.map((source) => ({ name: source.name, uri: source.url, digest: { sha256: source.sha256 } })),
      ...[...(report.preservedRecipe ? [{ name: 'recipe-capture', ...report.preservedRecipe.capture }, { name: 'recipe-source-bundle', ...report.preservedRecipe.sourceBundle }] : []),
        { name: 'input-lock', ...lock }, { name: 'helper-archive', ...manifest.helperArchive }, { name: 'makepkg-config', ...manifest.makepkgConfig },
        ...manifest.environments.flatMap((environment) => environment.chunks.map((ref, index) => ({ name: `${environment.name}-packages-${index}`, ...ref })))].map((ref) => ({
        name: ref.name, uri: `urn:sha256:${ref.sha256}`, digest: { sha256: ref.sha256 }, annotations: { size: String(ref.size) },
      })),
    ];
  }

  return [
    ...report.sources.map((source) => ({ name: source.name, uri: source.url, digest: { sha256: source.sha256 } })),
    { name: 'builder-image', digest: { sha256: report.imageDigest.replace(/^sha256:/, '') } },
    ...report.runtimeTests.map((test, index) => ({ name: `runtime-image-${index}`, uri: test.environment.baseImage,
      digest: { sha256: test.environment.baseImage.split('@sha256:')[1] } })),
    ...(report.dependencyPlan?.packages ?? []).map((item) => ({ name: item.filename, uri: item.url, digest: { sha256: item.sha256 },
      annotations: { releaseId: item.releaseId, signatureSha256: item.signatureSha256, keyFingerprint: report.dependencyPlan!.publicKeyFingerprint } })),
  ];
}
