import * as v from 'valibot';
import { sha256 } from './db';
import { readOprEvidence } from './sbom';
import { parseAbiReference } from '../abi-inventory';

export type RuntimeException = { findingSha256: string; reason: string };

const SHA256 = /^[a-f0-9]{64}$/;

const AMBIGUOUS = new Set(['library-no-package-associated', 'dependency-detected-but-optional', 'dependency-implicitly-satisfied-optional']);

const runtimeExceptionSchema = v.strictObject({
  findingSha256: v.pipe(v.string(), v.regex(SHA256)),
  reason: v.pipe(v.string(), v.trim(), v.minLength(1), v.maxLength(2000), v.check((value) => ![...value].some((character) => character <= '\u001f'), 'Control characters are not allowed.')),
});

const preparedEnvironmentSchema = v.strictObject({
  baseImage: v.pipe(v.string(), v.maxLength(1024), v.regex(/^.+@sha256:[a-f0-9]{64}$/)),
  preparedImage: v.pipe(v.string(), v.regex(/^sha256:[a-f0-9]{64}$/)),
  packages: v.pipe(v.array(v.pipe(v.string(), v.regex(/^[a-z0-9][a-z0-9@._+-]{0,63} [A-Za-z0-9][A-Za-z0-9@._+%~^:-]{0,127}$/))), v.minLength(1), v.maxLength(4096)),
});

const runtimeAnalysisSchema = v.object({
  schemaVersion: v.picklist([1, 2]),
  tool: v.picklist(['namcap', 'go-native-analysis']),
  toolVersion: v.pipe(v.string(), v.minLength(1), v.maxLength(128)),
  runtimeClosureComplete: v.literal(false),
  unknowns: v.pipe(v.array(v.pipe(v.string(), v.minLength(1), v.maxLength(4096))), v.minLength(1), v.maxLength(32)),
  elf: v.pipe(v.array(v.object({
    path: v.pipe(v.string(), v.minLength(1), v.maxLength(4096)),
    machine: v.string(),
    needed: v.array(v.pipe(v.string(), v.maxLength(4096))),
    searchPaths: v.array(v.pipe(v.string(), v.maxLength(4096))),
  })), v.maxLength(4096)),
  findings: v.pipe(v.array(v.object({
    code: v.pipe(v.string(), v.regex(/^[a-z0-9-]{1,128}$/)),
    level: v.picklist(['error', 'warning', 'info']),
    detail: v.pipe(v.string(), v.maxLength(4096)),
    sha256: v.string(),
  })), v.maxLength(1024)),
  exceptions: v.optional(v.unknown()),
  abiInventory: v.optional(v.unknown()),
});

export function reviewedRuntimeExceptions(sbom: string): RuntimeException[] {
  return runtimeExceptions(readOprEvidence(JSON.parse(sbom))?.runtimeExceptions);
}

export function runtimeExceptions(value: unknown): RuntimeException[] {
  if (value === undefined) return [];

  const parsed = v.safeParse(v.pipe(v.array(runtimeExceptionSchema), v.maxLength(16)), value);

  if (!parsed.success) throw new Error('Runtime exceptions must be a list of at most 16 findings');
  const seen = new Set<string>();

  return parsed.output.map((item) => {
    if (seen.has(item.findingSha256)) throw new Error('Runtime exception must identify one finding and give a review reason');
    seen.add(item.findingSha256);

    return { findingSha256: item.findingSha256, reason: item.reason };
  });
}

export function preparedEnvironment(value: unknown): { baseImage: string; preparedImage: string; packages: string[] } {
  const parsed = v.safeParse(preparedEnvironmentSchema, value);

  if (!parsed.success || new Set(parsed.output.packages.map((entry) => entry.split(' ')[0])).size !== parsed.output.packages.length) {
    throw new Error('Exact prepared environment identity and package inventory are required');
  }

  return parsed.output;
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
  const parsed = v.safeParse(runtimeAnalysisSchema, value);

  if (!parsed.success || (parsed.output.schemaVersion === 1 && parsed.output.tool !== 'namcap') ||
      (parsed.output.schemaVersion === 2 && parsed.output.tool !== 'go-native-analysis') ||
      JSON.stringify(runtimeExceptions(parsed.output.exceptions)) !== JSON.stringify(exceptions)) {
    throw new Error('Bounded runtime evidence with explicit coverage and reviewed exceptions is required');
  }

  const analysis = parsed.output;

  if (analysis.abiInventory !== undefined) parseAbiReference(analysis.abiInventory);

  for (const finding of analysis.findings) {
    if (finding.sha256 !== await sha256(`${finding.level}\n${finding.code}\n${finding.detail}`)) {
      throw new Error('Runtime finding integrity is invalid');
    }

    if (finding.level === 'error' || AMBIGUOUS.has(finding.code)) {
      if (finding.level === 'error' || !AMBIGUOUS.has(finding.code) || !exceptions.some((item) => item.findingSha256 === finding.sha256)) {
        throw new Error(`Unresolved runtime dependency finding: ${finding.code}`);
      }
    }
  }
}
