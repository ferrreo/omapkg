import type { Architecture, Source } from '../model';
import { canonicalJson } from '../canonical-json';
import { packageFilename, parseOutputContract, parseOutputMetadata, type OutputContract, type OutputMetadata } from '../output-contract';
import { assertRuntimeEvidence, assertRuntimeAnalysis, preparedEnvironment, type RuntimeException } from './runtime-evidence';
import { assertFrozenEvidence, type FrozenEvidence } from '../frozen-inputs';
import { parseDependencyPlan, type DependencyPlan } from './dependency-plan';

export interface OutputEvidence {
  schemaVersion: 2; attempt: number; outputContract: OutputContract;
  buildId: string; revisionId: string; workerId: string; recipeSha256: string; architecture: Architecture;
  imageDigest: string; sourceDateEpoch: number; sources: Source[]; network: 'disabled'; startedAt: string; finishedAt: string;
  dependencyPlan?: DependencyPlan | null; frozenInputs?: FrozenEvidence; buildEnvironment: unknown;
  outputs: { pkgbase: string; filename: string; artifactSha256: string; packageMetadata: OutputMetadata }[];
  runtimeTests: { outputs: string[]; environment: { baseImage: string; preparedImage: string }; smokePassed: true;
    analyses: { name: string; runtimeAnalysis: { elf: { machine: string }[]; nativeCode: string[]; payloadSha256: string } }[] }[];
}

const hash = /^[a-f0-9]{64}$/;
function keys(value: unknown, required: string[], optional: string[] = []): void {
  if (!value || typeof value !== 'object' || Array.isArray(value) || required.some((key) => !Object.hasOwn(value, key)) ||
      Object.keys(value).some((key) => !required.includes(key) && !optional.includes(key))) throw new Error('Incomplete or unexpected v2 evidence fields');
}

// Shared by ingestion, the isolated signer and the offline verifier; no database authority is inferred here.
export async function assertOutputEvidence(value: unknown, exceptions: RuntimeException[]): Promise<OutputEvidence> {
  keys(value, ['schemaVersion', 'attempt', 'outputContract', 'buildId', 'revisionId', 'workerId', 'recipeSha256', 'architecture', 'imageDigest',
    'sourceDateEpoch', 'sources', 'network', 'startedAt', 'finishedAt', 'buildEnvironment', 'runtimeTests', 'outputs'], ['dependencyPlan', 'frozenInputs']);
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
      if (!hash.test(analysis.payloadSha256) || (payloads.has(item.name) && payloads.get(item.name) !== analysis.payloadSha256)) throw new Error('Package payload comparison digest is missing or inconsistent');
      payloads.set(item.name, analysis.payloadSha256);
      if (!Array.isArray(analysis.nativeCode) || analysis.nativeCode.length > 4096 || analysis.nativeCode.some((path) => typeof path !== 'string' || !path || path.length > 4096)) throw new Error('Native code inspection is missing or invalid');
      if (metadataByName.get(item.name)!.architecture === 'any' && (analysis.elf.length || analysis.nativeCode.length)) throw new Error('Architecture-independent output contains native code');
      if (analysis.elf.some((elf) => !(report.architecture === 'aarch64' ? ['EM_AARCH64'] : ['EM_X86_64', 'EM_386']).includes(elf.machine))) throw new Error('Output ELF architecture differs from native target');
    }
  }
  return report;
}

export function outputResolvedDependencies(report: OutputEvidence) {
  if (report.frozenInputs) {
    const { lock, manifest } = report.frozenInputs;
    return [
      ...report.sources.map((source) => ({ name: source.name, uri: source.url, digest: { sha256: source.sha256 } })),
      ...[{ name: 'input-lock', ...lock }, { name: 'helper-archive', ...manifest.helperArchive }, { name: 'makepkg-config', ...manifest.makepkgConfig },
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
