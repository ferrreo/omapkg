import type { Architecture } from './model';
import type { ArtifactArchitecture } from './distribution';
import { isArchPkgver, parsePackageMetadata, type PackageMetadata } from './server/arch';

export type OutputMetadata = Omit<PackageMetadata, 'architecture'> & { architecture: ArtifactArchitecture };

export type ExpectedOutput = { name: string; fullVersion: string; architecture: ArtifactArchitecture };

export type OutputContract = {
  schemaVersion: 2;
  cohort: { id: string; revision: number; manifestSha256: string };
  outputs: ExpectedOutput[];
  runtimeGroups: string[][];
};

export const MAX_BUILD_OUTPUTS = 256;

export function packageFilename(output: ExpectedOutput): string {
  return `${output.name}-${output.fullVersion}-${output.architecture}.pkg.tar.zst`;
}

export function parseOutputMetadata(value: unknown): OutputMetadata | null {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  const item = value as Record<string, unknown>;
  const native = parsePackageMetadata(item.architecture === 'any' ? { ...item, architecture: 'x86_64' } : item);

  return native ? { ...native, architecture: item.architecture as ArtifactArchitecture } : null;
}

export function parseOutputContract(value: unknown, target: Architecture): OutputContract {
  const item = value as OutputContract;

  if (!item || typeof item !== 'object' || Object.keys(item).sort().join(',') !== 'cohort,outputs,runtimeGroups,schemaVersion' || item.schemaVersion !== 2 ||
      !item.cohort || Object.keys(item.cohort).sort().join(',') !== 'id,manifestSha256,revision' ||
      !/^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/.test(item.cohort.id) || !Number.isSafeInteger(item.cohort.revision) || item.cohort.revision < 1 ||
      !/^[a-f0-9]{64}$/.test(item.cohort.manifestSha256) || !Array.isArray(item.outputs) || !item.outputs.length || item.outputs.length > MAX_BUILD_OUTPUTS) {
    throw new Error('Invalid build output contract');
  }

  for (const output of item.outputs) {
    const version = typeof output?.fullVersion === 'string' ? /^(?:([0-9]+):)?(.+)-([1-9]\d{0,3}(?:\.[1-9]\d{0,3})?)$/.exec(output.fullVersion) : null;

    if (!output || Object.keys(output).sort().join(',') !== 'architecture,fullVersion,name' ||
        !/^[a-z0-9][a-z0-9@._+-]{0,63}$/.test(output.name) || !version || output.fullVersion.length > 128 || !isArchPkgver(version[2]) ||
        (output.architecture !== target && output.architecture !== 'any')) throw new Error('Invalid expected package output');
  }

  if (new Set(item.outputs.map((output) => output.name)).size !== item.outputs.length) throw new Error('Duplicate expected package output');

  if (!Array.isArray(item.runtimeGroups) || !item.runtimeGroups.length || item.runtimeGroups.length > MAX_BUILD_OUTPUTS ||
      item.runtimeGroups.some((group) => !Array.isArray(group) || !group.length || group.length > MAX_BUILD_OUTPUTS || new Set(group).size !== group.length || group.some((name) => !item.outputs.some((output) => output.name === name))) ||
      new Set(item.runtimeGroups.flat()).size !== item.outputs.length || new Set(item.runtimeGroups.map((group) => [...group].sort().join(' '))).size !== item.runtimeGroups.length) {
    throw new Error('Native installation groups must cover every output without duplicate groups');
  }

  return item;
}
