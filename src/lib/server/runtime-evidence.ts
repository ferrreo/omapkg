import { sha256 } from './db';
import { readOprEvidence } from './sbom';
import { parseAbiReference } from '../abi-inventory';

export type RuntimeException = { findingSha256: string; reason: string };
const SHA256 = /^[a-f0-9]{64}$/;
const AMBIGUOUS = new Set(['library-no-package-associated', 'dependency-detected-but-optional', 'dependency-implicitly-satisfied-optional']);

export function reviewedRuntimeExceptions(sbom: string): RuntimeException[] {
  return runtimeExceptions(readOprEvidence(JSON.parse(sbom))?.runtimeExceptions);
}

export function runtimeExceptions(value: unknown): RuntimeException[] {
  if (value === undefined) return [];
  if (!Array.isArray(value) || value.length > 16) throw new Error('Runtime exceptions must be a list of at most 16 findings');
  const seen = new Set<string>();
  return value.map((item) => {
    if (!item || typeof item !== 'object' || Object.keys(item).some((key) => !['findingSha256', 'reason'].includes(key)) ||
        typeof item.findingSha256 !== 'string' || !SHA256.test(item.findingSha256) || seen.has(item.findingSha256) ||
        typeof item.reason !== 'string' || !item.reason.trim() || item.reason.length > 2000 || /[\u0000-\u001f]/.test(item.reason)) {
      throw new Error('Runtime exception must identify one finding and give a review reason');
    }
    seen.add(item.findingSha256);
    return { findingSha256: item.findingSha256, reason: item.reason };
  });
}

export function preparedEnvironment(value: unknown): { baseImage: string; preparedImage: string; packages: string[] } {
  const item = value as Record<string, unknown> | undefined;
  if (!item || typeof item.baseImage !== 'string' || item.baseImage.length > 1024 || !/^.+@sha256:[a-f0-9]{64}$/.test(item.baseImage) ||
      typeof item.preparedImage !== 'string' || !/^sha256:[a-f0-9]{64}$/.test(item.preparedImage) ||
      !Array.isArray(item.packages) || !item.packages.length || item.packages.length > 4096 ||
      item.packages.some((entry) => typeof entry !== 'string' || !/^[a-z0-9][a-z0-9@._+-]{0,63} [A-Za-z0-9][A-Za-z0-9@._+%~^:-]{0,127}$/.test(entry)) ||
      new Set(item.packages.map((entry: string) => entry.split(' ')[0])).size !== item.packages.length) {
    throw new Error('Exact prepared environment identity and package inventory are required');
  }
  return item as ReturnType<typeof preparedEnvironment>;
}

export async function assertRuntimeEvidence(provenance: Record<string, unknown>, imageDigest: string, exceptions: RuntimeException[]): Promise<void> {
  const build = preparedEnvironment(provenance.buildEnvironment);
  const runtime = preparedEnvironment(provenance.runtimeEnvironment);
  if (!build.baseImage.endsWith(`@${imageDigest}`) || runtime.baseImage === build.baseImage || runtime.preparedImage === build.preparedImage) {
    throw new Error('Runtime checks require a separate minimal image from the reviewed builder');
  }
  await assertRuntimeAnalysis(provenance.runtimeAnalysis, exceptions);
}

export async function assertRuntimeAnalysis(value: unknown, exceptions: RuntimeException[]): Promise<void> {
  const analysis = value as Record<string, unknown> | undefined;
  if (!analysis || !(analysis.schemaVersion === 1 && analysis.tool === 'namcap' || analysis.schemaVersion === 2 && analysis.tool === 'go-native-analysis') || typeof analysis.toolVersion !== 'string' || !analysis.toolVersion || analysis.toolVersion.length > 128 ||
      analysis.runtimeClosureComplete !== false || !Array.isArray(analysis.unknowns) || !analysis.unknowns.length || analysis.unknowns.length > 32 || analysis.unknowns.some((item) => typeof item !== 'string' || !item || item.length > 4096) ||
      !Array.isArray(analysis.elf) || analysis.elf.length > 4096 || !Array.isArray(analysis.findings) || analysis.findings.length > 1024 ||
      JSON.stringify(runtimeExceptions(analysis.exceptions)) !== JSON.stringify(exceptions)) {
    throw new Error('Bounded runtime evidence with explicit coverage and reviewed exceptions is required');
  }
  if (analysis.abiInventory !== undefined) parseAbiReference(analysis.abiInventory);
  for (const value of analysis.elf) {
    if (!value || typeof value.path !== 'string' || !value.path || value.path.length > 4096 || typeof value.machine !== 'string' ||
        !Array.isArray(value.needed) || !Array.isArray(value.searchPaths) || [...value.needed, ...value.searchPaths].some((item) => typeof item !== 'string' || item.length > 4096)) {
      throw new Error('ELF dependency evidence is invalid');
    }
  }
  for (const finding of analysis.findings) {
    if (!finding || typeof finding.code !== 'string' || !/^[a-z0-9-]{1,128}$/.test(finding.code) ||
        !['error', 'warning', 'info'].includes(finding.level) || typeof finding.detail !== 'string' || finding.detail.length > 4096 ||
        finding.sha256 !== await sha256(`${finding.level}\n${finding.code}\n${finding.detail}`)) {
      throw new Error('Runtime finding integrity is invalid');
    }
    if (finding.level === 'error' || AMBIGUOUS.has(finding.code)) {
      if (finding.level === 'error' || !AMBIGUOUS.has(finding.code) || !exceptions.some((item) => item.findingSha256 === finding.sha256)) {
        throw new Error(`Unresolved runtime dependency finding: ${finding.code}`);
      }
    }
  }
}
