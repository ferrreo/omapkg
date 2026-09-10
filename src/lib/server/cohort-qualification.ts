import { createHash } from 'node:crypto';
import type { AbiFile, AbiRecord, AbiSymbol } from '../abi-inventory';
import { parseAbiReference, type AbiInventory } from '../abi-inventory';
import { canonicalJson } from '../canonical-json';
import type { ArtifactArchitecture } from '../distribution';
import type { Architecture, Build } from '../model';
import type { InputObject } from '../frozen-inputs';
import { parseArchRelation, satisfiesArchRelation, type PackageMetadata } from './arch';
import { buildArtifacts } from './build-outputs';
import { type CohortBlocker, type CohortRow } from '../cohorts';
import { now, query, sha256 } from './db';
import type { Env } from './env';
import { PolicyError } from './policy';
import { assertRetainedAbiEvidence, readAbiChunk, retainedAbiInventory } from './build-abi-evidence';
import { verifyOutputProvenance } from './build-output-evidence';
import { getBuildForWorker } from './worker-protocol';
import type { Worker } from '../model';
import { ownedRepositoryUniversePages } from './owned-repository';

const MAX_FINDINGS = 256;
const MAX_PACKAGES = 100_000;
const MAX_INDEX_RECORDS = 1_000_000;
const MAX_QUERY_RECORDS = 32_768;
const SHA256 = /^[a-f0-9]{64}$/;

export type QualificationKind = 'dependency' | 'abi';
type PackageRelations = Omit<PackageMetadata, 'architecture'>;

export interface QualificationAbi {
  inventorySha256?: string;
  artifactSha256: string;
  typeAbi: AbiInventory['typeAbi'];
  records: AbiRecord[];
}

export interface QualificationPackage {
  pkgbase: string;
  name: string;
  fullVersion: string;
  architecture: ArtifactArchitecture;
  artifactSha256: string;
  artifactSize: number;
  metadata: PackageRelations;
  abi: QualificationAbi | null;
  origin: 'candidate' | 'owned';
  rebuildOn: string[];
  buildId: string | null;
  attempt: number | null;
  inputLockSha256?: string | null;
}

export interface QualificationFinding {
  kind: QualificationKind;
  code: string;
  pkgbase: string;
  packageName: string;
  architecture: Architecture;
  relatedPkgbase: string | null;
  relation: string | null;
  reason: string;
}

export interface QualificationReport {
  schemaVersion: 1;
  cohortId: string;
  revision: number;
  manifestSha256: string;
  architecture: Architecture;
  universeSha256: string;
  packageCount: number;
  candidatePackageCount: number;
  findings: QualificationFinding[];
  truncated: boolean;
  createdAt: number;
}

export interface QualificationResult {
  report: QualificationReport;
  digest: string;
  inputSha256: string;
  fences: D1PreparedStatement[];
}

export type QualificationBuild = Pick<Build, 'id' | 'revision_id' | 'architecture' | 'status' | 'attempt' | 'artifact_sha256' | 'artifact_size' | 'artifact_filename' | 'installed_size' | 'provenance' | 'provenance_signature' | 'input_lock_sha256' | 'worker_id' | 'output_contract_json'> & {
  pkgbase: string; rebuild_on: string; surface?: 'binary' | 'recipe'; worker_status?: string | null;
};
type StoredBuild = QualificationBuild;

type OutputRecord = {
  pkgbase: string; filename: string; name: string; fullVersion: string; architecture: ArtifactArchitecture;
  artifactSha256: string; artifactSize: number; metadata: PackageMetadata & { architecture: ArtifactArchitecture }; abiRef: InputObject | null;
};
export type QualificationOutput = OutputRecord;
export type QualificationAbiIndexBudget = { used: number; max: number };
export type QualificationAbiIndexContext = { cohortId: string; revision: number; architecture: Architecture; retainRecords?: boolean; budget?: QualificationAbiIndexBudget };

function finding(
  kind: QualificationKind, code: string, owner: QualificationPackage, reason: string,
  related: QualificationPackage | null = null, relation: string | null = null,
): QualificationFinding {
  return { kind, code, pkgbase: owner.pkgbase, packageName: owner.name, architecture: owner.architecture === 'any' ? 'x86_64' : owner.architecture,
    relatedPkgbase: related?.pkgbase ?? null, relation, reason };
}

function targetPackage(value: QualificationPackage, architecture: Architecture): boolean {
  return value.architecture === 'any' || value.architecture === architecture;
}

function elfFiles(item: QualificationPackage): AbiFile[] {
  return item.abi?.records.filter((record): record is AbiFile => record.kind === 'file' && record.nativeKind === 'elf') ?? [];
}

function symbols(item: QualificationPackage): AbiSymbol[] {
  return item.abi?.records.filter((record): record is AbiSymbol => record.kind === 'symbol') ?? [];
}

function sonames(item: QualificationPackage): string[] {
  return elfFiles(item).flatMap((file) => file.elf?.soname ? [file.elf.soname] : []);
}

function recordKey(record: AbiSymbol): string {
  return [record.path, record.table, record.dynamic ? 'dynamic' : 'static', record.name, record.version ?? '', record.versionFile ?? ''].join('\u0000');
}

function dynamicDefined(item: QualificationPackage): AbiSymbol[] {
  return symbols(item).filter((symbol) => symbol.dynamic && symbol.defined && !/hidden|internal/i.test(symbol.visibility));
}

function dynamicImported(item: QualificationPackage): AbiSymbol[] {
  // GNU copy relocations are represented as defined dynamic symbols in the
  // consumer.  Their versionFile still names the provider they must bind to.
  return symbols(item).filter((symbol) => symbol.dynamic && (!symbol.defined || symbol.versionFile !== null) && !/hidden|internal/i.test(symbol.visibility));
}

function importedSymbolMatches(imported: AbiSymbol, exported: AbiSymbol): boolean {
  if (imported.name !== exported.name) return false;
  if (imported.version !== null) {
    // versionFile is the GNU verneed library on imports and is normally null
    // on provider verdef exports.  Provider selection checks that file name;
    // symbol matching only needs exact version equality.  An explicit import
    // may name a non-default (@) definition, so do not compare hidden bits.
    if (exported.version !== imported.version) return false;
  } else if (exported.version !== null && exported.versionHidden) return false;
  const importType = imported.type.replace(/^STT_/, ''); const exportType = exported.type.replace(/^STT_/, '');
  if (importType !== 'NOTYPE' && importType !== exportType) return false;
  if (importType === 'OBJECT' && imported.size > 0 && imported.size !== exported.size) return false;
  return true;
}

function packageIdentityNames(item: QualificationPackage): Set<string> {
  return new Set([item.name, ...item.metadata.provides.map((value) => parseArchRelation(value)?.name).filter((value): value is string => Boolean(value)), ...sonames(item)]);
}

function sameElfClass(left: AbiFile | null, right: AbiFile | null): boolean {
  if (!left?.elf || !right?.elf) return true;
  return left.elf.bits === right.elf.bits && left.elf.machine === right.elf.machine;
}

function elfFileForSymbol(item: QualificationPackage, symbol: AbiSymbol): AbiFile | null {
  return elfFiles(item).find((file) => file.path === symbol.path) ?? null;
}

function providerNeededByConsumer(consumer: QualificationPackage, provider: QualificationPackage, universe: QualificationPackage[], previous?: QualificationPackage): boolean {
  const targetFiles = [...elfFiles(provider), ...(previous ? elfFiles(previous) : [])];
  const providerSonames = new Set(targetFiles.flatMap((file) => file.elf?.soname ? [file.elf.soname] : []));
  if (!providerSonames.size) return false;
  const consumerFiles = elfFiles(consumer);
  if (!consumerFiles.length) {
    const providerNames = packageIdentityNames(provider);
    return consumer.metadata.depends.some((value) => {
      const relation = parseArchRelation(value);
      return relation !== null && providerNames.has(relation.name);
    });
  }
  const bySoname = new Map<string, Array<{ owner: QualificationPackage; file: AbiFile }>>();
  const addFiles = (owner: QualificationPackage, files: AbiFile[]) => {
    for (const file of files) if (file.elf?.soname) bySoname.set(file.elf.soname, [...(bySoname.get(file.elf.soname) ?? []), { owner, file }]);
  };
  for (const item of universe) addFiles(item, elfFiles(item));
  addFiles(provider, elfFiles(provider));
  if (previous) addFiles(previous, elfFiles(previous));
  const queue = consumerFiles.flatMap((file) => file.elf?.needed?.map((soname) => ({ soname, consumerFile: file })) ?? []);
  const seen = new Set<string>();
  while (queue.length) {
    const needed = queue.shift()!;
    const key = `${needed.soname}\u0000${needed.consumerFile.elf?.machine ?? ''}\u0000${needed.consumerFile.elf?.bits ?? ''}`;
    if (seen.has(key)) continue;
    seen.add(key);
    for (const match of bySoname.get(needed.soname) ?? []) {
      if (!sameElfClass(needed.consumerFile, match.file)) continue;
      if (providerSonames.has(needed.soname) && (match.owner === provider || match.owner === previous)) return true;
      for (const soname of match.file.elf?.needed ?? []) queue.push({ soname, consumerFile: match.file });
    }
  }
  return false;
}

function unresolvedImportedSymbols(provider: QualificationPackage, consumer: QualificationPackage, previous: QualificationPackage | undefined, universe: QualificationPackage[]): AbiSymbol[] {
  if (!providerNeededByConsumer(consumer, provider, universe, previous)) return [];
  const exports = new Map<string, AbiSymbol[]>();
  for (const exported of dynamicDefined(provider)) exports.set(exported.name, [...(exports.get(exported.name) ?? []), exported]);
  const oldExports = new Map<string, AbiSymbol[]>();
  for (const exported of previous ? dynamicDefined(previous) : []) oldExports.set(exported.name, [...(oldExports.get(exported.name) ?? []), exported]);
  const providerFiles = [...elfFiles(provider), ...(previous ? elfFiles(previous) : [])];
  return dynamicImported(consumer).filter((imported) => {
    if (/WEAK/i.test(imported.binding)) return false;
    const consumerFile = elfFileForSymbol(consumer, imported);
    if (imported.versionFile !== null && !providerFiles.some((file) => file.elf?.soname === imported.versionFile && sameElfClass(consumerFile, file))) return false;
    // An unversioned import is attributed to this provider only when the old
    // provider exported a matching default symbol.  This avoids comparing
    // every Qt/glibc import against every changed provider in the closure.
    if (imported.version === null && previous && !(oldExports.get(imported.name) ?? []).some((exported) =>
      sameElfClass(consumerFile, elfFileForSymbol(previous, exported)) && importedSymbolMatches(imported, exported))) return false;
    return !(exports.get(imported.name) ?? []).some((exported) =>
      sameElfClass(consumerFile, elfFileForSymbol(provider, exported)) && importedSymbolMatches(imported, exported));
  });
}

function packageKey(item: Pick<QualificationPackage, 'name' | 'architecture'>, architecture: Architecture): string {
  return `${item.name}:${architecture}`;
}

function pushFinding(findings: QualificationFinding[], value: QualificationFinding): boolean {
  const key = canonicalJson(value);
  if (findings.some((item) => canonicalJson(item) === key)) return false;
  if (findings.length >= MAX_FINDINGS) return true;
  findings.push(value);
  return false;
}

type ReverseIndex = { capability: Map<string, QualificationPackage[]>; soname: Map<string, QualificationPackage[]>; identity: Map<string, QualificationPackage[]> };

function reverseIndex(packages: QualificationPackage[], architecture: Architecture): ReverseIndex {
  const index: ReverseIndex = { capability: new Map(), soname: new Map(), identity: new Map() };
  for (const item of packages) {
    if (!targetPackage(item, architecture)) continue;
    for (const relation of item.metadata.depends.map((value) => parseArchRelation(value)).filter((value): value is NonNullable<typeof value> => Boolean(value))) {
      index.capability.set(relation.name, [...(index.capability.get(relation.name) ?? []), item]);
    }
    for (const file of elfFiles(item)) for (const needed of file.elf?.needed ?? []) index.soname.set(needed, [...(index.soname.get(needed) ?? []), item]);
    for (const trigger of item.rebuildOn) index.identity.set(trigger, [...(index.identity.get(trigger) ?? []), item]);
  }
  return index;
}

function reverseConsumers(index: ReverseIndex, provider: QualificationPackage, baseline: QualificationPackage | undefined): QualificationPackage[] {
  const names = new Set([provider.name, ...(provider.metadata.provides ?? []).flatMap((value) => {
    const relation = parseArchRelation(value); return relation ? [relation.name] : [];
  }), ...sonames(provider)]);
  const oldNames = baseline ? new Set([baseline.name, ...(baseline.metadata.provides ?? []).flatMap((value) => {
    const relation = parseArchRelation(value); return relation ? [relation.name] : [];
  }), ...sonames(baseline)]) : names;
  const consumers = new Set<QualificationPackage>();
  for (const name of [...names, ...oldNames]) for (const item of index.capability.get(name) ?? []) consumers.add(item);
  for (const name of [...names, ...oldNames]) for (const item of index.soname.get(name) ?? []) consumers.add(item);
  for (const name of [provider.pkgbase, provider.name]) for (const item of index.identity.get(name) ?? []) consumers.add(item);
  return [...consumers].filter((item) => item.name !== provider.name);
}

function abiDiff(baseline: QualificationPackage, candidate: QualificationPackage): { removedSonames: string[]; changedSymbols: string[]; changedStatic: boolean; changedElf: boolean } {
  const oldSonames = new Set(sonames(baseline)); const newSonames = new Set(sonames(candidate));
  const removedSonames = [...oldSonames].filter((value) => !newSonames.has(value)).sort();
  const oldSymbols = new Map(dynamicDefined(baseline).map((value) => [recordKey(value), value]));
  const newSymbols = new Map(dynamicDefined(candidate).map((value) => [recordKey(value), value]));
  const changedSymbols = [...oldSymbols.values()].filter((old) => {
    const sameName = [...newSymbols.values()].find((value) => value.path === old.path && value.name === old.name);
    if (!sameName) return true;
    return sameName.type !== old.type || sameName.size !== old.size || sameName.version !== old.version || sameName.versionFile !== old.versionFile;
  }).map((value) => `${value.name}${value.version ? `@${value.version}` : ''}`).sort();
  const staticHashes = (item: QualificationPackage) => item.abi?.records.filter((record): record is AbiFile => record.kind === 'file' && (record.nativeKind === 'static-archive' || record.nativeKind === 'thin-archive'))
    .map((record) => `${record.path}:${record.sha256 ?? ''}`).sort() ?? [];
  const elfIdentity = (item: QualificationPackage) => elfFiles(item).map((record) => [record.path, record.elf?.machine, record.elf?.type, record.elf?.bits, record.elf?.byteOrder, record.elf?.interpreter,
    ...(record.elf?.rpath ?? []), ...(record.elf?.runpath ?? [])]).sort();
  return { removedSonames, changedSymbols, changedStatic: canonicalJson(staticHashes(baseline)) !== canonicalJson(staticHashes(candidate)),
    changedElf: canonicalJson(elfIdentity(baseline)) !== canonicalJson(elfIdentity(candidate)) };
}

/**
 * Compare one exact candidate universe against its predecessor. The input is
 * already bounded by the candidate manifest; this function never trusts a
 * worker-supplied pass/fail flag.
 */
export function qualifyCandidateUniverse(input: {
  cohortId: string; revision: number; manifestSha256: string; architecture: Architecture;
  candidate: QualificationPackage[]; baseline?: QualificationPackage[];
}): QualificationReport {
  const candidate = input.candidate.filter((item) => targetPackage(item, input.architecture));
  const baseline = (input.baseline ?? []).filter((item) => targetPackage(item, input.architecture));
  const baselineByName = new Map(baseline.map((item) => [packageKey(item, input.architecture), item]));
  const findings: QualificationFinding[] = [];
  let truncated = false;
  const add = (value: QualificationFinding) => { if (pushFinding(findings, { ...value, architecture: input.architecture })) truncated = true; };
  const identities = new Map<string, QualificationPackage>();
  for (const item of candidate) {
    const key = packageKey(item, input.architecture);
    const previous = identities.get(key);
    if (previous) add(finding('dependency', 'duplicate-package-authority', item, `Final universe contains more than one authority for ${item.name}.`, previous));
    else identities.set(key, item);
  }
  const byCapability = new Map<string, QualificationPackage[]>();
  for (const item of candidate) for (const relation of [item.name, ...item.metadata.provides].map((value) => parseArchRelation(value)).filter((value): value is NonNullable<typeof value> => Boolean(value))) {
    byCapability.set(relation.name, [...(byCapability.get(relation.name) ?? []), item]);
  }
  const reverse = reverseIndex(candidate, input.architecture);
  for (const owner of candidate) {
    for (const relation of owner.metadata.depends) {
      const dependency = parseArchRelation(relation);
      const matches = dependency ? (byCapability.get(dependency.name) ?? []).filter((item) => targetPackage(item, input.architecture) && satisfiesArchRelation(dependency, {
        name: item.name, fullVersion: item.fullVersion, provides: item.metadata.provides,
      })) : [];
      if (!dependency || !matches.length) {
        add(finding('dependency', 'unresolved-dependency', owner, `No owned final-universe provider satisfies ${relation}.`, null, relation));
      }
    }
  }
  const sonameProviders = new Map<string, QualificationPackage[]>();
  for (const item of candidate) for (const soname of sonames(item)) sonameProviders.set(soname, [...(sonameProviders.get(soname) ?? []), item]);
  for (const owner of candidate) {
    if (!owner.abi && owner.origin === 'candidate' && owner.architecture !== 'any') add(finding('abi', 'abi-coverage', owner, 'Native candidate output has no retained ABI inventory.'));
    for (const file of elfFiles(owner)) for (const needed of file.elf?.needed ?? []) {
      if (!sonameProviders.has(needed)) add(finding('abi', 'unresolved-elf-needed', owner, `ELF dependency ${needed} has no exact SONAME provider.`, null, needed));
    }
  }
  for (const candidateProvider of candidate) {
    const oldProvider = baselineByName.get(packageKey(candidateProvider, input.architecture));
    if (!oldProvider || oldProvider.artifactSha256 === candidateProvider.artifactSha256) continue;
    if (!candidateProvider.abi) {
      add(finding('abi', 'abi-coverage', candidateProvider, 'Changed candidate provider has no retained ABI inventory.'));
      continue;
    }
    const diff = oldProvider.abi ? abiDiff(oldProvider, candidateProvider) : { removedSonames: [], changedSymbols: ['unknown baseline ABI'], changedStatic: false, changedElf: true };
    const consumers = reverseConsumers(reverse, candidateProvider, oldProvider);
    if (diff.removedSonames.length || diff.changedSymbols.length || diff.changedStatic || diff.changedElf || candidateProvider.abi.typeAbi === 'not-checked') {
      for (const consumer of consumers) {
        if (!consumer.abi && consumer.architecture !== 'any') {
          add(finding('abi', 'abi-coverage', consumer, `Reverse consumer of changed provider ${candidateProvider.name} lacks ABI inventory.`, candidateProvider));
        }
        if (consumer.origin !== 'candidate') {
          add(finding('abi', 'reverse-rebuild-required', candidateProvider, `Changed provider ${candidateProvider.name} requires rebuilding consumer ${consumer.name}; stable SONAME is not a compatibility proof.`, consumer));
        } else if (consumer.abi) {
          for (const imported of unresolvedImportedSymbols(candidateProvider, consumer, oldProvider, candidate)) {
            add(finding('abi', 'imported-symbol-unresolved', consumer, `Consumer ${consumer.name} imports ${imported.name}${imported.version ? `@${imported.version}` : ''}, which the final provider ${candidateProvider.name} does not export with matching version/type semantics.`, candidateProvider));
          }
        }
      }
      if (!consumers.length && diff.changedStatic) add(finding('abi', 'static-rebuild-unknown', candidateProvider, `Static archive ${candidateProvider.name} changed without a measured reverse-consumer closure.`));
      if (!consumers.length && candidateProvider.abi.typeAbi === 'not-checked' && dynamicDefined(candidateProvider).length) {
        add(finding('abi', 'reverse-rebuild-unknown', candidateProvider, `Provider ${candidateProvider.name} has native symbols but no measured reverse-consumer closure; unknown C/C++ ABI requires conservative rebuild scope.`));
      }
      if (!consumers.length && diff.changedSymbols.length && oldProvider.abi === null) add(finding('abi', 'abi-baseline-unknown', candidateProvider, `Provider ${candidateProvider.name} changed but its previous ABI inventory is unavailable.`));
    }
  }
  return { schemaVersion: 1, cohortId: input.cohortId, revision: input.revision, manifestSha256: input.manifestSha256,
    architecture: input.architecture, universeSha256: qualificationUniverseDigest(candidate), packageCount: candidate.length,
    candidatePackageCount: candidate.filter((item) => item.origin === 'candidate').length, findings, truncated, createdAt: 0 };
}

export async function finalProviderInputFindings(db: D1Database, candidate: QualificationPackage[], baseline: QualificationPackage[], architecture: Architecture): Promise<QualificationFinding[]> {
  const findings: QualificationFinding[] = [];
  const byCapability = new Map<string, QualificationPackage[]>();
  const bySoname = new Map<string, QualificationPackage[]>();
  const byIdentity = new Map<string, QualificationPackage[]>();
  for (const provider of candidate) {
    byIdentity.set(provider.pkgbase, [...(byIdentity.get(provider.pkgbase) ?? []), provider]);
    byIdentity.set(provider.name, [...(byIdentity.get(provider.name) ?? []), provider]);
    for (const relation of [provider.name, ...provider.metadata.provides].map((value) => parseArchRelation(value)).filter((value): value is NonNullable<typeof value> => Boolean(value))) {
      byCapability.set(relation.name, [...(byCapability.get(relation.name) ?? []), provider]);
    }
    for (const soname of sonames(provider)) bySoname.set(soname, [...(bySoname.get(soname) ?? []), provider]);
  }
  const bound = async (consumer: QualificationPackage, provider: QualificationPackage) => {
      const lock = consumer.inputLockSha256;
      const present = lock ? await db.prepare(`SELECT 1 FROM input_lock_packages
        WHERE lock_sha256=? AND json_extract(package_json,'$.name')=? AND json_extract(package_json,'$.version')=?
          AND json_extract(package_json,'$.package.sha256')=?
          AND json_extract(package_json,'$.origin')='owned-build'
          AND (json_extract(package_json,'$.architecture')=? OR json_extract(package_json,'$.architecture')='any')`)
        .bind(lock, provider.name, provider.fullVersion, provider.artifactSha256, architecture).first() : null;
      if (!present) findings.push(finding('abi', 'stale-provider-input', consumer, `Consumer ${consumer.name} was rebuilt without the final provider bytes for ${provider.name}.`, provider));
  };
  for (const consumer of candidate.filter((item) => item.origin === 'candidate')) {
    const providersForConsumer = new Set<QualificationPackage>();
    for (const relation of consumer.metadata.depends) {
      const parsed = parseArchRelation(relation);
      for (const provider of (parsed ? byCapability.get(parsed.name) ?? [] : [])) if (targetPackage(provider, architecture) && satisfiesArchRelation(parsed!, { name: provider.name, fullVersion: provider.fullVersion, provides: provider.metadata.provides })) providersForConsumer.add(provider);
    }
    for (const file of elfFiles(consumer)) for (const needed of file.elf?.needed ?? []) for (const provider of bySoname.get(needed) ?? []) providersForConsumer.add(provider);
    for (const trigger of consumer.rebuildOn) for (const provider of byIdentity.get(trigger) ?? []) providersForConsumer.add(provider);
    for (const provider of providersForConsumer) await bound(consumer, provider);
  }
  const lockIds = [...new Set([...candidate, ...baseline].map((item) => item.inputLockSha256).filter((value): value is string => Boolean(value)))];
  const inputEdges = new Map<string, QualificationPackage[]>();
  const consumersByLock = new Map<string, QualificationPackage[]>();
  for (const consumer of [...candidate, ...baseline]) if (consumer.inputLockSha256) consumersByLock.set(consumer.inputLockSha256, [...(consumersByLock.get(consumer.inputLockSha256) ?? []), consumer]);
  for (let offset = 0; offset < lockIds.length; offset += 128) {
    const rows = await query<{ lock_sha256: string; package_json: string }>(db,
      'SELECT lock_sha256,package_json FROM input_lock_packages WHERE lock_sha256 IN (SELECT value FROM json_each(?))', JSON.stringify(lockIds.slice(offset, offset + 128)));
    for (const row of rows) {
      let packageJson: { package?: { sha256?: string } };
      try { packageJson = JSON.parse(row.package_json) as typeof packageJson; } catch { continue; }
      const digest = packageJson.package?.sha256; if (!digest) continue;
      const consumers = consumersByLock.get(row.lock_sha256) ?? [];
      inputEdges.set(digest, [...(inputEdges.get(digest) ?? []), ...consumers]);
    }
  }
  const baselineByName = new Map(baseline.map((item) => [packageKey(item, architecture), item]));
  for (const provider of candidate.filter((item) => item.origin === 'candidate')) {
    const previous = baselineByName.get(packageKey(provider, architecture));
    const providerDigests = new Set([provider.artifactSha256, ...(previous ? [previous.artifactSha256] : [])]);
    for (const digest of providerDigests) for (const consumer of new Set(inputEdges.get(digest) ?? [])) {
      if (consumer.name === provider.name) continue;
      if (digest !== provider.artifactSha256 && consumer.origin !== 'candidate') findings.push(finding('abi', 'reverse-rebuild-required', provider, `Static/build consumer ${consumer.name} uses changed provider bytes and must be rebuilt.`, consumer));
      else if (digest !== provider.artifactSha256 && consumer.origin === 'candidate') findings.push(finding('abi', 'stale-provider-input', consumer, `Consumer ${consumer.name} was rebuilt from stale provider bytes for ${provider.name}.`, provider));
    }
  }
  return findings;
}

function createDigest(value: string): string { return createHash('sha256').update(value).digest('hex'); }

export function qualificationUniverseDigest(packages: QualificationPackage[]): string {
  const summary = packages.map((item) => ({
    pkgbase: item.pkgbase, name: item.name, fullVersion: item.fullVersion, architecture: item.architecture,
    artifactSha256: item.artifactSha256, artifactSize: item.artifactSize, metadata: item.metadata, rebuildOn: [...item.rebuildOn].sort(),
    abi: item.abi ? { inventorySha256: item.abi.inventorySha256 ?? null, artifactSha256: item.abi.artifactSha256, typeAbi: item.abi.typeAbi,
      recordsSha256: createDigest(canonicalJson(item.abi.records)) } : null,
  })).sort((a, b) => `${a.name}:${a.architecture}`.localeCompare(`${b.name}:${b.architecture}`));
  return createDigest(canonicalJson(summary));
}

async function digest(value: unknown): Promise<string> { return sha256(canonicalJson(value)); }

export async function persistQualificationAbiRecords(db: D1Database, context: QualificationAbiIndexContext, artifactSha256: string, inventorySha256: string, start: number, records: AbiRecord[]): Promise<void> {
  if (!records.length) return;
  const rows = canonicalJson(records);
  await db.prepare(`INSERT OR IGNORE INTO cohort_qualification_abi_records
    (cohort_id,revision,architecture,artifact_sha256,inventory_sha256,ordinal,record_kind,path,table_name,symbol_index,symbol_name,dynamic,defined,version,version_file,version_hidden,binding,symbol_type,visibility,symbol_size,native_kind,soname,needed_json,rpath_json,runpath_json,file_sha256,record_json)
    SELECT ?,?,?,?,?,CAST(key AS INTEGER)+?,json_extract(value,'$.kind'),json_extract(value,'$.path'),json_extract(value,'$.table'),json_extract(value,'$.index'),json_extract(value,'$.name'),json_extract(value,'$.dynamic'),json_extract(value,'$.defined'),json_extract(value,'$.version'),json_extract(value,'$.versionFile'),json_extract(value,'$.versionHidden'),json_extract(value,'$.binding'),json_extract(value,'$.type'),json_extract(value,'$.visibility'),json_extract(value,'$.size'),json_extract(value,'$.nativeKind'),json_extract(value,'$.elf.soname'),json_extract(value,'$.elf.needed'),json_extract(value,'$.elf.rpath'),json_extract(value,'$.elf.runpath'),json_extract(value,'$.sha256'),value FROM json_each(?)`)
    .bind(context.cohortId, context.revision, context.architecture, artifactSha256, inventorySha256, start, rows).run();
}

export async function indexedQualificationAbiRecords(db: D1Database, context: QualificationAbiIndexContext, artifactSha256: string, inventorySha256?: string): Promise<AbiRecord[]> {
  const where = inventorySha256 ? 'AND inventory_sha256=?' : '';
  const values = inventorySha256 ? [context.cohortId, context.revision, context.architecture, artifactSha256, inventorySha256] : [context.cohortId, context.revision, context.architecture, artifactSha256];
  const rows = await query<{ record_json: string }>(db, `SELECT record_json FROM cohort_qualification_abi_records
    WHERE cohort_id=? AND revision=? AND architecture=? AND artifact_sha256=? ${where} ORDER BY ordinal`, ...values);
  return rows.map((row) => JSON.parse(row.record_json) as AbiRecord);
}

async function indexedRecordCount(db: D1Database, context: QualificationAbiIndexContext, artifactSha256: string, inventorySha256?: string): Promise<number> {
  const where = inventorySha256 ? 'AND inventory_sha256=?' : '';
  const values = inventorySha256 ? [context.cohortId, context.revision, context.architecture, artifactSha256, inventorySha256] : [context.cohortId, context.revision, context.architecture, artifactSha256];
  return Number((await db.prepare(`SELECT COUNT(*) AS count FROM cohort_qualification_abi_records WHERE cohort_id=? AND revision=? AND architecture=? AND artifact_sha256=? ${where}`).bind(...values).first<{ count: number }>())?.count ?? 0);
}

async function indexedSymbolsMissing(db: D1Database, context: QualificationAbiIndexContext, consumer: QualificationPackage, provider: QualificationPackage, previous?: QualificationPackage): Promise<AbiSymbol[]> {
  const providerInventory = provider.abi?.inventorySha256 ?? '';
  const consumerInventory = consumer.abi?.inventorySha256 ?? '';
  const previousInventory = previous?.abi?.inventorySha256 ?? '';
  const previousKnown = Boolean(previous?.abi?.inventorySha256);
  const oldProviderFilesCte = previousKnown ? `, old_provider_files AS (
    SELECT path,soname,json_extract(record_json,'$.elf.machine') AS machine,json_extract(record_json,'$.elf.bits') AS bits
    FROM cohort_qualification_abi_records
    WHERE cohort_id=? AND revision=? AND architecture=? AND artifact_sha256=? AND inventory_sha256=?
      AND record_kind='file' AND native_kind='elf'
  )` : '';
  const providerFilesCte = `, provider_files AS (SELECT * FROM current_provider_files${previousKnown ? ' UNION ALL SELECT * FROM old_provider_files' : ''})`;
  const oldExportsCte = previousKnown ? `, old_exports AS (
    SELECT path,symbol_name,version,version_hidden,symbol_type,symbol_size FROM cohort_qualification_abi_records
    WHERE cohort_id=? AND revision=? AND architecture=? AND artifact_sha256=? AND inventory_sha256=?
      AND record_kind='symbol' AND dynamic=1 AND defined=1
  )` : '';
  const previousPredicate = previousKnown ? `AND (i.version IS NOT NULL OR EXISTS (SELECT 1 FROM old_exports oe
    WHERE oe.symbol_name=i.symbol_name AND (oe.version IS NULL OR oe.version_hidden=0)
      AND (REPLACE(i.symbol_type,'STT_','')='NOTYPE' OR REPLACE(oe.symbol_type,'STT_','')=REPLACE(i.symbol_type,'STT_',''))
      AND (REPLACE(i.symbol_type,'STT_','')!='OBJECT' OR i.symbol_size=0 OR i.symbol_size=oe.symbol_size)
      AND (NOT EXISTS (SELECT 1 FROM consumer_files cf WHERE cf.path=i.path)
        OR EXISTS (SELECT 1 FROM consumer_files cf JOIN old_provider_files ofile ON ofile.path=oe.path
          WHERE cf.path=i.path AND cf.machine=ofile.machine AND cf.bits=ofile.bits))))` : '';
  const rows = await query<{ record_json: string }>(db, `WITH current_provider_files AS (
    SELECT path,soname,json_extract(record_json,'$.elf.machine') AS machine,json_extract(record_json,'$.elf.bits') AS bits
    FROM cohort_qualification_abi_records
    WHERE cohort_id=? AND revision=? AND architecture=? AND artifact_sha256=? AND inventory_sha256=?
      AND record_kind='file' AND native_kind='elf'
  )${oldProviderFilesCte}${providerFilesCte}, consumer_files AS (
    SELECT path,json_extract(record_json,'$.elf.machine') AS machine,json_extract(record_json,'$.elf.bits') AS bits FROM cohort_qualification_abi_records
    WHERE cohort_id=? AND revision=? AND architecture=? AND artifact_sha256=? AND inventory_sha256=?
      AND record_kind='file' AND native_kind='elf'
  ), consumer_needed AS (
    SELECT wanted.value AS soname,json_extract(cf.record_json,'$.elf.machine') AS machine,json_extract(cf.record_json,'$.elf.bits') AS bits
      FROM cohort_qualification_abi_records cf JOIN json_each(cf.needed_json) wanted
    WHERE cf.cohort_id=? AND cf.revision=? AND cf.architecture=? AND cf.artifact_sha256=? AND cf.inventory_sha256=?
      AND cf.record_kind='file' AND cf.native_kind='elf'
  )${oldExportsCte}
  SELECT i.record_json FROM cohort_qualification_abi_records i
    WHERE i.cohort_id=? AND i.revision=? AND i.architecture=? AND i.artifact_sha256=? AND i.inventory_sha256=?
      AND i.record_kind='symbol' AND i.dynamic=1 AND (i.defined=0 OR i.version_file IS NOT NULL)
      AND UPPER(COALESCE(i.binding,'')) NOT LIKE '%WEAK%'
      AND (
        (i.version_file IS NOT NULL AND EXISTS (SELECT 1 FROM provider_files pf
          WHERE pf.soname=i.version_file AND (NOT EXISTS (SELECT 1 FROM consumer_files cf WHERE cf.path=i.path)
            OR EXISTS (SELECT 1 FROM consumer_files cf WHERE cf.path=i.path AND cf.machine=pf.machine AND cf.bits=pf.bits))))
        OR (i.version_file IS NULL AND
          (NOT EXISTS (SELECT 1 FROM consumer_files cf WHERE cf.path=i.path)
           OR EXISTS (SELECT 1 FROM consumer_needed cn JOIN provider_files pf ON pf.soname=cn.soname
             WHERE cn.machine=pf.machine AND cn.bits=pf.bits))
          ${previousPredicate})
      )
      AND NOT EXISTS (SELECT 1 FROM cohort_qualification_abi_records e WHERE e.cohort_id=i.cohort_id AND e.revision=i.revision AND e.architecture=i.architecture
        AND e.artifact_sha256=? AND e.inventory_sha256=? AND e.record_kind='symbol' AND e.dynamic=1 AND e.defined=1 AND e.symbol_name=i.symbol_name
        AND ((i.version IS NOT NULL AND e.version=i.version)
          OR (i.version IS NULL AND (e.version IS NULL OR e.version_hidden=0)))
        AND (REPLACE(i.symbol_type,'STT_','')='NOTYPE' OR REPLACE(i.symbol_type,'STT_','')=REPLACE(e.symbol_type,'STT_',''))
        AND (REPLACE(i.symbol_type,'STT_','')!='OBJECT' OR i.symbol_size=0 OR i.symbol_size=e.symbol_size)
        AND (NOT EXISTS (SELECT 1 FROM consumer_files cf WHERE cf.path=i.path)
          OR EXISTS (SELECT 1 FROM consumer_files cf JOIN current_provider_files pf ON pf.path=e.path
            WHERE cf.path=i.path AND cf.machine=pf.machine AND cf.bits=pf.bits))) ORDER BY i.ordinal LIMIT ?`,
    context.cohortId, context.revision, context.architecture, provider.artifactSha256, providerInventory,
    ...(previousKnown ? [context.cohortId, context.revision, context.architecture, previous!.artifactSha256, previousInventory] : []),
    context.cohortId, context.revision, context.architecture, consumer.artifactSha256, consumerInventory,
    context.cohortId, context.revision, context.architecture, consumer.artifactSha256, consumerInventory,
    ...(previousKnown ? [context.cohortId, context.revision, context.architecture, previous!.artifactSha256, previousInventory] : []),
    context.cohortId, context.revision, context.architecture, consumer.artifactSha256, consumerInventory,
    provider.artifactSha256, providerInventory, MAX_FINDINGS);
  return rows.map((row) => JSON.parse(row.record_json) as AbiSymbol);
}

async function indexedProviderDiff(db: D1Database, context: QualificationAbiIndexContext, oldProvider: QualificationPackage | undefined, provider: QualificationPackage) {
  const oldSonames = oldProvider ? new Set((await query<{ soname: string }>(db, `SELECT DISTINCT soname FROM cohort_qualification_abi_records WHERE cohort_id=? AND revision=? AND architecture=? AND artifact_sha256=? AND inventory_sha256=? AND record_kind='file' AND soname IS NOT NULL`, context.cohortId, context.revision, context.architecture, oldProvider.artifactSha256, oldProvider.abi?.inventorySha256 ?? '')).map((row) => row.soname)) : new Set<string>();
  const newSonames = new Set((await query<{ soname: string }>(db, `SELECT DISTINCT soname FROM cohort_qualification_abi_records WHERE cohort_id=? AND revision=? AND architecture=? AND artifact_sha256=? AND inventory_sha256=? AND record_kind='file' AND soname IS NOT NULL`, context.cohortId, context.revision, context.architecture, provider.artifactSha256, provider.abi?.inventorySha256 ?? '')).map((row) => row.soname));
  const changedSymbols: string[] = [];
  if (oldProvider) {
    const rows = await query<{ symbol_name: string; version: string | null }>(db, `SELECT o.symbol_name,o.version FROM cohort_qualification_abi_records o
      WHERE o.cohort_id=? AND o.revision=? AND o.architecture=? AND o.artifact_sha256=? AND o.inventory_sha256=? AND o.record_kind='symbol' AND o.dynamic=1 AND o.defined=1
          AND NOT EXISTS (SELECT 1 FROM cohort_qualification_abi_records n WHERE n.cohort_id=o.cohort_id AND n.revision=o.revision AND n.architecture=o.architecture
          AND n.artifact_sha256=? AND n.inventory_sha256=? AND n.record_kind='symbol' AND n.dynamic=1 AND n.defined=1 AND n.path=o.path AND n.symbol_name=o.symbol_name
          AND REPLACE(n.symbol_type,'STT_','')=REPLACE(o.symbol_type,'STT_','') AND n.symbol_size=o.symbol_size AND n.version IS o.version AND n.version_file IS o.version_file AND n.version_hidden=o.version_hidden)
      LIMIT ?`, context.cohortId, context.revision, context.architecture, oldProvider.artifactSha256, oldProvider.abi?.inventorySha256 ?? '', provider.artifactSha256, provider.abi?.inventorySha256 ?? '', MAX_FINDINGS);
    for (const row of rows) changedSymbols.push(`${row.symbol_name}${row.version ? `@${row.version}` : ''}`);
  }
  const staticOld = oldProvider ? canonicalJson(await query(db, `SELECT path,file_sha256 FROM cohort_qualification_abi_records WHERE cohort_id=? AND revision=? AND architecture=? AND artifact_sha256=? AND inventory_sha256=? AND native_kind IN ('static-archive','thin-archive') ORDER BY path`, context.cohortId, context.revision, context.architecture, oldProvider.artifactSha256, oldProvider.abi?.inventorySha256 ?? '')) : '[]';
  const staticNew = canonicalJson(await query(db, `SELECT path,file_sha256 FROM cohort_qualification_abi_records WHERE cohort_id=? AND revision=? AND architecture=? AND artifact_sha256=? AND inventory_sha256=? AND native_kind IN ('static-archive','thin-archive') ORDER BY path`, context.cohortId, context.revision, context.architecture, provider.artifactSha256, provider.abi?.inventorySha256 ?? ''));
  const elfOld = oldProvider ? canonicalJson(await query(db, `SELECT path,soname,needed_json,rpath_json,runpath_json FROM cohort_qualification_abi_records WHERE cohort_id=? AND revision=? AND architecture=? AND artifact_sha256=? AND inventory_sha256=? AND native_kind='elf' ORDER BY path`, context.cohortId, context.revision, context.architecture, oldProvider.artifactSha256, oldProvider.abi?.inventorySha256 ?? '')) : '[]';
  const elfNew = canonicalJson(await query(db, `SELECT path,soname,needed_json,rpath_json,runpath_json FROM cohort_qualification_abi_records WHERE cohort_id=? AND revision=? AND architecture=? AND artifact_sha256=? AND inventory_sha256=? AND native_kind='elf' ORDER BY path`, context.cohortId, context.revision, context.architecture, provider.artifactSha256, provider.abi?.inventorySha256 ?? ''));
  return { oldSonames: [...oldSonames], newSonames: [...newSonames], removedSonames: [...oldSonames].filter((value) => !newSonames.has(value)), changedSymbols, changedStatic: staticOld !== staticNew, changedElf: elfOld !== elfNew, dynamic: Number((await db.prepare(`SELECT COUNT(*) AS count FROM cohort_qualification_abi_records WHERE cohort_id=? AND revision=? AND architecture=? AND artifact_sha256=? AND inventory_sha256=? AND record_kind='symbol' AND dynamic=1 AND defined=1`).bind(context.cohortId, context.revision, context.architecture, provider.artifactSha256, provider.abi?.inventorySha256 ?? '').first<{ count: number }>())?.count ?? 0) > 0 };
}

async function indexedNeededConsumers(db: D1Database, context: QualificationAbiIndexContext, packages: QualificationPackage[]): Promise<Map<string, QualificationPackage[]>> {
  const result = new Map<string, QualificationPackage[]>();
  const byArtifact = new Map(packages.map((item) => [item.artifactSha256, item]));
  const hashes = [...byArtifact.keys()].filter((hash) => byArtifact.get(hash)?.abi?.inventorySha256);
  for (let offset = 0; offset < hashes.length; offset += 512) {
    const rows = await query<{ artifact_sha256: string; record_json: string }>(db, `SELECT r.artifact_sha256,r.record_json
      FROM cohort_qualification_abi_records r JOIN json_each(?) wanted ON wanted.key=r.artifact_sha256 AND wanted.value=r.inventory_sha256
      WHERE r.cohort_id=? AND r.revision=? AND r.architecture=? AND r.record_kind='file' AND r.native_kind='elf'`,
      JSON.stringify(Object.fromEntries(hashes.slice(offset, offset + 512).map((hash) => [hash, byArtifact.get(hash)!.abi!.inventorySha256]))), context.cohortId, context.revision, context.architecture);
    for (const row of rows) {
      const record = JSON.parse(row.record_json) as AbiFile; const owner = byArtifact.get(row.artifact_sha256);
      if (!owner) continue;
      for (const needed of record.elf?.needed ?? []) result.set(needed, [...(result.get(needed) ?? []), owner]);
    }
  }
  return result;
}

async function indexedAbiFindings(db: D1Database, context: QualificationAbiIndexContext, candidate: QualificationPackage[], baseline: QualificationPackage[], architecture: Architecture): Promise<QualificationFinding[]> {
  const findings: QualificationFinding[] = []; const add = (value: QualificationFinding) => { if (findings.length < MAX_FINDINGS) findings.push(value); }; const baselineByName = new Map(baseline.map((item) => [packageKey(item, architecture), item]));
  const reverse = reverseIndex(candidate, architecture); const needed = await indexedNeededConsumers(db, context, candidate);
  const sonameMap = new Map<string, QualificationPackage[]>();
  const byArtifact = new Map(candidate.map((item) => [item.artifactSha256, item])); const hashes = [...byArtifact.keys()].filter((hash) => byArtifact.get(hash)?.abi?.inventorySha256);
  for (let offset = 0; offset < hashes.length; offset += 512) {
    const rows = await query<{ artifact_sha256: string; soname: string }>(db, `SELECT r.artifact_sha256,r.soname
      FROM cohort_qualification_abi_records r JOIN json_each(?) wanted ON wanted.key=r.artifact_sha256 AND wanted.value=r.inventory_sha256
      WHERE r.cohort_id=? AND r.revision=? AND r.architecture=? AND r.record_kind='file' AND r.native_kind='elf' AND r.soname IS NOT NULL`,
      JSON.stringify(Object.fromEntries(hashes.slice(offset, offset + 512).map((hash) => [hash, byArtifact.get(hash)!.abi!.inventorySha256]))), context.cohortId, context.revision, context.architecture);
    for (const row of rows) { const item = byArtifact.get(row.artifact_sha256); if (item) sonameMap.set(row.soname, [...(sonameMap.get(row.soname) ?? []), item]); }
  }
  for (const [neededName, consumers] of needed) if (!sonameMap.has(neededName)) for (const consumer of consumers) add(finding('abi', 'unresolved-elf-needed', consumer, `ELF dependency ${neededName} has no exact SONAME provider.`, null, neededName));
  for (const provider of candidate.filter((item) => item.origin === 'candidate')) {
    const previous = baselineByName.get(packageKey(provider, architecture));
    if (previous && previous.artifactSha256 === provider.artifactSha256) continue;
    const providerCount = await indexedRecordCount(db, context, provider.artifactSha256, provider.abi?.inventorySha256);
    const indexedLarge = providerCount > MAX_QUERY_RECORDS;
    const providerRecords = indexedLarge ? [] : await indexedQualificationAbiRecords(db, context, provider.artifactSha256, provider.abi?.inventorySha256);
    const providerAbi = providerRecords.length || indexedLarge ? { inventorySha256: provider.abi?.inventorySha256, artifactSha256: provider.artifactSha256, typeAbi: provider.abi?.typeAbi ?? 'not-checked' as const, records: providerRecords } : null;
    if (!providerAbi) { add(finding('abi', 'abi-coverage', provider, 'Changed candidate provider has no indexed ABI inventory.')); continue; }
    const oldCount = previous ? await indexedRecordCount(db, context, previous.artifactSha256, previous.abi?.inventorySha256) : 0;
    const oldRecords = previous && oldCount <= MAX_QUERY_RECORDS ? await indexedQualificationAbiRecords(db, context, previous.artifactSha256, previous.abi?.inventorySha256) : [];
    const oldAbi = previous ? { inventorySha256: previous.abi?.inventorySha256, artifactSha256: previous.artifactSha256, typeAbi: previous.abi?.typeAbi ?? 'not-checked' as const, records: oldRecords } : null;
    const providerView = { ...provider, abi: providerAbi }; const oldView = previous ? { ...previous, abi: oldAbi } : undefined;
    const indexedDiff = indexedLarge || oldCount > MAX_QUERY_RECORDS ? await indexedProviderDiff(db, context, previous, provider) : null;
    const names = new Set([provider.name, ...provider.metadata.provides.map((value) => parseArchRelation(value)?.name).filter((value): value is string => Boolean(value)), ...sonames(providerView), ...(indexedDiff?.newSonames ?? []), ...(indexedDiff?.oldSonames ?? [])]);
    const consumers = new Set([...reverseConsumers(reverse, providerView, oldView), ...[...names].flatMap((name) => needed.get(name) ?? [])]);
    const diff = indexedDiff ?? (oldView?.abi ? abiDiff(oldView, providerView) : { removedSonames: [], changedSymbols: ['unknown baseline ABI'], changedStatic: false, changedElf: true, dynamic: true });
    for (const consumer of consumers) {
      if (consumer === provider) continue;
      const consumerCount = consumer.origin === 'candidate' ? await indexedRecordCount(db, context, consumer.artifactSha256, consumer.abi?.inventorySha256) : 0;
      const consumerRecords = consumer.origin === 'candidate' && consumerCount <= MAX_QUERY_RECORDS ? await indexedQualificationAbiRecords(db, context, consumer.artifactSha256, consumer.abi?.inventorySha256) : [];
      const consumerAbi = consumer.origin === 'candidate' && consumerCount <= MAX_QUERY_RECORDS && consumerRecords.length ? { inventorySha256: consumer.abi?.inventorySha256, artifactSha256: consumer.artifactSha256, typeAbi: consumer.abi?.typeAbi ?? 'not-checked' as const, records: consumerRecords } : null;
      if (consumer.origin !== 'candidate') add(finding('abi', 'reverse-rebuild-required', provider, `Changed provider ${provider.name} requires rebuilding consumer ${consumer.name}; final SONAME alone is not compatibility proof.`, consumer));
      else if (indexedLarge || consumerCount > MAX_QUERY_RECORDS) for (const imported of await indexedSymbolsMissing(db, context, consumer, provider, previous)) add(finding('abi', 'imported-symbol-unresolved', consumer, `Consumer ${consumer.name} imports ${imported.name}, which final provider ${provider.name} does not export with matching version/type semantics.`, provider));
      else if (!consumerAbi) add(finding('abi', 'abi-coverage', consumer, `Reverse consumer ${consumer.name} lacks indexed ABI inventory.`, provider));
      else for (const imported of unresolvedImportedSymbols(providerView, { ...consumer, abi: consumerAbi }, oldView, candidate)) add(finding('abi', 'imported-symbol-unresolved', consumer, `Consumer ${consumer.name} imports ${imported.name}, which final provider ${provider.name} does not export with matching version/type semantics.`, provider));
    }
    if (!consumers.size && (diff.changedStatic || (providerAbi.typeAbi === 'not-checked' && (indexedDiff?.dynamic || dynamicDefined(providerView).length)))) add(finding('abi', 'reverse-rebuild-unknown', provider, `Provider ${provider.name} changed without a measured reverse-consumer closure.`));
  }
  return findings;
}

export function qualificationIndexedAbiFindings(db: D1Database, context: QualificationAbiIndexContext, candidate: QualificationPackage[], baseline: QualificationPackage[], architecture: Architecture): Promise<QualificationFinding[]> {
  return indexedAbiFindings(db, context, candidate, baseline, architecture);
}

async function readAbi(env: Pick<Env, 'DB' | 'ARTIFACTS'>, ref: InputObject | null, artifactSha256: string, build: Pick<StoredBuild, 'id' | 'attempt'>, indexContext?: QualificationAbiIndexContext): Promise<QualificationAbi | null> {
  if (!ref) return null;
  parseAbiReference(ref);
  if (!SHA256.test(ref.sha256)) throw new PolicyError(409, 'ABI inventory object is missing or changed.');
  const manifest = await retainedAbiInventory(env.DB, { id: build.id, attempt: build.attempt }, ref, artifactSha256);
  if (indexContext) {
    const indexed = await env.DB.prepare(`SELECT type_abi,record_count FROM cohort_qualification_abi_index_state
      WHERE cohort_id=? AND revision=? AND architecture=? AND artifact_sha256=? AND inventory_sha256=?`)
      .bind(indexContext.cohortId, indexContext.revision, indexContext.architecture, artifactSha256, ref.sha256).first<{ type_abi: string; record_count: number }>();
    if (indexed) return { inventorySha256: ref.sha256, artifactSha256, typeAbi: indexed.type_abi as AbiInventory['typeAbi'], records: [] };
  }
  const records: AbiRecord[] = [];
  let indexedCount = 0;
  const progress = indexContext ? await env.DB.prepare(`SELECT next_chunk FROM cohort_qualification_abi_progress
    WHERE cohort_id=? AND revision=? AND architecture=? AND artifact_sha256=? AND inventory_sha256=?`)
    .bind(indexContext.cohortId, indexContext.revision, indexContext.architecture, artifactSha256, ref.sha256).first<{ next_chunk: number }>() : null;
  const nextChunk = progress?.next_chunk ?? 0;
  // Keep only records used by dependency/ABI closure. Chunk bytes are verified
  // and released one at a time; package docs and local symbols never enter the
  // full-catalog in-memory index.
  for (const [chunkIndex, chunkRef] of manifest.chunks.entries()) {
    if (chunkIndex < nextChunk) continue;
    if (indexContext?.budget && indexContext.budget.used >= indexContext.budget.max) throw new PolicyError(409, 'ABI index continuation required; retry qualification to resume retained chunks.');
    if (indexContext?.budget) indexContext.budget.used += 1;
    const chunk = await readAbiChunk(env, { sha256: chunkRef.sha256, size: chunkRef.size }, artifactSha256);
    const relevantRecords = chunk.records.filter((record) => record.kind === 'file' && ['elf', 'static-archive', 'thin-archive'].includes(record.nativeKind ?? '') || record.kind === 'symbol' && record.dynamic);
    if (indexContext) await persistQualificationAbiRecords(env.DB, indexContext, artifactSha256, ref.sha256, chunk.start, relevantRecords);
    indexedCount += relevantRecords.length;
    for (const record of relevantRecords) {
    const relevant = record.kind === 'file' && ['elf', 'static-archive', 'thin-archive'].includes(record.nativeKind ?? '') || record.kind === 'symbol' && record.dynamic;
    if (relevant && indexContext?.retainRecords !== false) {
      if (records.length >= MAX_INDEX_RECORDS) throw new PolicyError(409, 'Candidate ABI index is unavailable within the bounded qualification memory budget.');
      records.push(record);
    }
    }
    if (indexContext) await env.DB.prepare(`INSERT INTO cohort_qualification_abi_progress
      (cohort_id,revision,architecture,artifact_sha256,inventory_sha256,next_chunk,updated_at) VALUES(?,?,?,?,?,?,?)
      ON CONFLICT(cohort_id,revision,architecture,artifact_sha256,inventory_sha256) DO UPDATE SET next_chunk=excluded.next_chunk,updated_at=excluded.updated_at`)
      .bind(indexContext.cohortId, indexContext.revision, indexContext.architecture, artifactSha256, ref.sha256, chunkIndex + 1, now()).run();
  }
  if (indexContext && nextChunk + (manifest.chunks.length - nextChunk) === manifest.chunks.length) {
    await env.DB.prepare(`INSERT INTO cohort_qualification_abi_index_state
      (cohort_id,revision,architecture,artifact_sha256,inventory_sha256,type_abi,record_count,created_at) VALUES(?,?,?,?,?,?,?,?)`)
      .bind(indexContext.cohortId, indexContext.revision, indexContext.architecture, artifactSha256, ref.sha256, manifest.typeAbi, indexedCount, now()).run();
    await env.DB.prepare(`DELETE FROM cohort_qualification_abi_progress WHERE cohort_id=? AND revision=? AND architecture=? AND artifact_sha256=? AND inventory_sha256=?`)
      .bind(indexContext.cohortId, indexContext.revision, indexContext.architecture, artifactSha256, ref.sha256).run();
  }
  return { inventorySha256: ref.sha256, artifactSha256, typeAbi: manifest.typeAbi, records };
}

function analysisRef(provenance: unknown, name: string): InputObject | null {
  const report = provenance as { runtimeTests?: Array<{ analyses?: Array<{ name?: string; runtimeAnalysis?: { abiInventory?: InputObject } }> }> };
  for (const test of report.runtimeTests ?? []) for (const item of test.analyses ?? []) if (item.name === name && item.runtimeAnalysis?.abiInventory) return item.runtimeAnalysis.abiInventory;
  return null;
}

async function outputRecords(env: Pick<Env, 'DB' | 'ARTIFACTS'>, build: StoredBuild): Promise<OutputRecord[]> {
  if (!build.provenance) return [];
  const provenance = JSON.parse(build.provenance) as { outputs?: Array<{ pkgbase: string; filename: string; artifactSha256: string; packageMetadata: PackageMetadata }>;
    packageMetadata?: PackageMetadata; artifactSha256?: string; artifactSize?: number; runtimeTests?: unknown[] };
  if (Array.isArray(provenance.outputs)) {
    const artifacts = await buildArtifacts(env.DB, build);
    if (artifacts.length !== provenance.outputs.length) throw new PolicyError(409, `Build ${build.id} has an incomplete registered output set.`);
    return Promise.all(provenance.outputs.map(async (output) => {
      const artifact = artifacts.find((item) => item.filename === output.filename);
      if (!artifact || artifact.sha256 !== output.artifactSha256) throw new PolicyError(409, `Build ${build.id} output bytes are missing or changed.`);
      const size = artifact.size;
      const metadata = output.packageMetadata;
      return { pkgbase: output.pkgbase, filename: output.filename, name: metadata.name, fullVersion: metadata.fullVersion, architecture: metadata.architecture,
        artifactSha256: output.artifactSha256, artifactSize: size, metadata, abiRef: analysisRef(provenance, metadata.name) };
    }));
  }
  if (!provenance.packageMetadata || !build.artifact_sha256 || build.artifact_size === null) return [];
  const metadata = provenance.packageMetadata;
  return [{ pkgbase: build.pkgbase, filename: build.artifact_filename ?? '', name: metadata.name, fullVersion: metadata.fullVersion, architecture: metadata.architecture,
    artifactSha256: provenance.artifactSha256 ?? build.artifact_sha256, artifactSize: provenance.artifactSha256 === build.artifact_sha256 ? build.artifact_size : 0,
    metadata, abiRef: analysisRef(provenance, metadata.name) }];
}

/** Testable v2 output reader; aggregate build artifact columns may be null. */
export function qualificationBuildOutputs(env: Pick<Env, 'DB' | 'ARTIFACTS'>, build: StoredBuild): Promise<QualificationOutput[]> {
  return outputRecords(env, build);
}

export function indexRetainedQualificationAbi(env: Pick<Env, 'DB' | 'ARTIFACTS'>, ref: InputObject, artifactSha256: string, build: Pick<StoredBuild, 'id' | 'attempt'>, context: QualificationAbiIndexContext): Promise<QualificationAbi | null> {
  return readAbi(env, ref, artifactSha256, build, context);
}

function outputPackage(value: OutputRecord, origin: QualificationPackage['origin'], rebuildOn: string[], buildId: string | null, attempt: number | null, inputLockSha256: string | null = null): QualificationPackage {
  const { architecture: _architecture, ...metadata } = value.metadata;
  return { pkgbase: value.pkgbase, name: value.name, fullVersion: value.fullVersion, architecture: value.architecture,
    artifactSha256: value.artifactSha256, artifactSize: value.artifactSize, metadata, abi: null,
    origin, rebuildOn, buildId, attempt, inputLockSha256 };
}

async function packageFromOutput(env: Pick<Env, 'DB' | 'ARTIFACTS'>, value: OutputRecord, origin: QualificationPackage['origin'], rebuildOn: string[], buildId: string | null, attempt: number | null, inputLockSha256: string | null = null, indexContext?: QualificationAbiIndexContext): Promise<QualificationPackage> {
  const item = outputPackage(value, origin, rebuildOn, buildId, attempt, inputLockSha256);
  if (value.abiRef && buildId && attempt !== null) item.abi = await readAbi(env, value.abiRef, value.artifactSha256, { id: buildId, attempt }, indexContext);
  return item;
}

async function catalogRebuildOn(db: D1Database, pkgbase: string): Promise<string[]> {
  const row = await db.prepare('SELECT manifest_json FROM catalog_revisions WHERE pkgbase=? AND revision=(SELECT current_revision FROM catalog_packages WHERE pkgbase=?)').bind(pkgbase, pkgbase).first<{ manifest_json: string }>();
  if (!row) return [];
  try { return JSON.parse(row.manifest_json).rebuildOn ?? []; } catch { return []; }
}

async function candidateBuilds(db: D1Database, current: CohortRow, architecture: Architecture): Promise<StoredBuild[]> {
  return query<StoredBuild>(db, `SELECT b.id,b.revision_id,b.architecture,b.status,b.attempt,b.artifact_sha256,b.artifact_size,b.artifact_filename,b.installed_size,b.provenance,b.provenance_signature,b.input_lock_sha256,b.worker_id,b.output_contract_json,r.surface,w.status AS worker_status,
    m.pkgbase,COALESCE(json_extract(catalog.manifest_json,'$.rebuildOn'),'[]') AS rebuild_on
    FROM builds b JOIN cohort_members m ON m.recipe_revision_id=b.revision_id AND m.cohort_id=? AND m.revision=? JOIN revisions r ON r.id=b.revision_id
    LEFT JOIN catalog_revisions catalog ON catalog.pkgbase=m.pkgbase AND catalog.revision=m.catalog_revision
    LEFT JOIN workers w ON w.id=b.worker_id
    WHERE b.architecture=? ORDER BY b.id`, current.id, current.current_revision, architecture);
}

type PinnedUniverse = { id: string; lane: 'system' | 'opr'; releaseId: string; rootSha256: string; packageCount: number };

async function pinnedUniverses(env: Pick<Env, 'DB'>, current: CohortRow): Promise<PinnedUniverse[]> {
  const manifest = JSON.parse(current.manifest_json) as { parentSnapshot?: string | null; compatibleSystems?: string[] };
  const refs = new Map<string, { lane: 'system' | 'opr'; releaseId: string }>();
  const addDirect = async (value: string) => {
    const rows = await query<PinnedUniverse>(env.DB, `SELECT id,lane,release_id AS releaseId,root_sha256 AS rootSha256,package_count AS packageCount
      FROM owned_repository_universes WHERE status IN ('prepared','published') AND (root_sha256=? OR release_id=?)`, value, value);
    for (const row of rows) refs.set(`${row.lane}:${row.releaseId}`, { lane: row.lane, releaseId: row.releaseId });
  };
  if (manifest.parentSnapshot) await addDirect(manifest.parentSnapshot);
  for (const systemDigest of manifest.compatibleSystems ?? []) {
    const release = await env.DB.prepare(`SELECT release_id,manifest_json FROM distribution_release_candidates
      WHERE kind='system' AND manifest_sha256=? AND status IN ('signed','active') ORDER BY sequence DESC LIMIT 1`).bind(systemDigest)
      .first<{ release_id: string; manifest_json: string }>();
    if (!release) throw new PolicyError(409, `Compatible system manifest ${systemDigest} is unavailable.`);
    refs.set(`system:${release.release_id}`, { lane: 'system', releaseId: release.release_id });
  }
  const universes: PinnedUniverse[] = [];
  for (const ref of refs.values()) {
    const row = await env.DB.prepare(`SELECT id,lane,release_id AS releaseId,root_sha256 AS rootSha256,package_count AS packageCount
      FROM owned_repository_universes WHERE lane=? AND release_id=? AND status IN ('prepared','published')`).bind(ref.lane, ref.releaseId).first<PinnedUniverse>();
    if (!row) throw new PolicyError(409, `Pinned owned ${ref.lane} universe ${ref.releaseId} is unavailable.`);
    universes.push(row);
  }
  if (!universes.length) throw new PolicyError(409, 'An immutable owned parent universe is required for candidate qualification.');
  return universes.sort((left, right) => left.lane.localeCompare(right.lane) || left.releaseId.localeCompare(right.releaseId));
}

async function ownedUniversePackages(env: Env, current: CohortRow, architecture: Architecture, budget?: QualificationAbiIndexBudget): Promise<QualificationPackage[]> {
  const universes = await pinnedUniverses(env, current);
  const packages = new Map<string, QualificationPackage>();
  for (const universe of universes) for await (const page of ownedRepositoryUniversePages(env, { lane: universe.lane, releaseId: universe.releaseId }, 256)) {
    const buildIds = [...new Set(page.map((item) => item.buildId))];
    const locks = new Map((await query<{ build_id: string; attempt: number; input_lock_sha256: string | null }>(env.DB,
      'SELECT build_id,attempt,input_lock_sha256 FROM build_attempts WHERE build_id IN (SELECT value FROM json_each(?))', JSON.stringify(buildIds)))
      .map((row) => [`${row.build_id}:${row.attempt}`, row.input_lock_sha256] as const));
    for (const value of page.filter((item) => item.targetArchitecture === architecture)) {
      const metadata: PackageRelations = { name: value.name, fullVersion: value.version, installedSize: 0, depends: value.depends,
        provides: value.provides, conflicts: value.conflicts, replaces: value.replaces };
      let abi: QualificationAbi | null = null;
      if (value.abiInventoryRef) {
        const ref = await env.DB.prepare('SELECT size FROM build_abi_evidence WHERE build_id=? AND attempt=? AND sha256=?')
          .bind(value.buildId, value.attempt, value.abiInventoryRef).first<{ size: number }>();
        if (!ref) throw new PolicyError(409, `Owned package ${value.name} ABI inventory is not retained.`);
        abi = await readAbi(env, { sha256: value.abiInventoryRef, size: ref.size }, value.artifactSha256, { id: value.buildId, attempt: value.attempt }, { cohortId: current.id, revision: current.current_revision, architecture, retainRecords: false, budget });
      }
      const item: QualificationPackage = { pkgbase: value.pkgbase, name: value.name, fullVersion: value.version, architecture: value.architecture,
        artifactSha256: value.artifactSha256, artifactSize: value.artifactSize, metadata, abi, origin: 'owned', rebuildOn: value.rebuildOn,
        buildId: value.buildId, attempt: value.attempt, inputLockSha256: locks.get(`${value.buildId}:${value.attempt}`) ?? null };
      packages.set(packageKey(item, architecture), item);
    }
  }
  if (!packages.size) throw new PolicyError(409, `Owned parent universe has no ${architecture} packages.`);
  return [...packages.values()];
}

async function verifyCandidateBuild(env: Env, build: StoredBuild): Promise<void> {
  if (!build.worker_id || !build.provenance || !build.provenance_signature) throw new PolicyError(409, `Build ${build.id} lacks signed native output evidence.`);
  const worker = await env.DB.prepare('SELECT * FROM workers WHERE id=?').bind(build.worker_id).first<Worker>();
  const lease = worker ? await getBuildForWorker(env.DB, build.id, worker.id) : null;
  if (!worker || worker.status !== 'active' || worker.architecture !== build.architecture || !lease) throw new PolicyError(409, `Build ${build.id} worker identity is no longer current.`);
  const artifacts = await buildArtifacts(env.DB, lease);
  await verifyOutputProvenance(worker, lease, artifacts, build.provenance, build.provenance_signature, build.installed_size ?? undefined);
  await assertRetainedAbiEvidence(env.DB, lease, JSON.parse(build.provenance));
}

async function loadPackages(env: Env, current: CohortRow, architecture: Architecture): Promise<{ candidate: QualificationPackage[]; baseline: QualificationPackage[]; fences: D1PreparedStatement[] }> {
  const abiBudget: QualificationAbiIndexBudget = { used: 0, max: 300 };
  const baseline = await ownedUniversePackages(env, current, architecture, abiBudget);
  const candidateBuild = await candidateBuilds(env.DB, current, architecture);
  const candidate: QualificationPackage[] = [...baseline];
  const fences: D1PreparedStatement[] = [];
  for (const build of candidateBuild) {
    if (build.status !== 'succeeded') continue;
    if (build.surface === 'recipe') continue;
    if (!build.worker_id || build.worker_status !== 'active' || !build.provenance_signature || !build.output_contract_json) {
      throw new PolicyError(409, `Build ${build.id} lacks current signed native output evidence.`);
    }
    const contract = JSON.parse(build.output_contract_json) as { cohort?: { id?: string; revision?: number; manifestSha256?: string } };
    if (contract.cohort?.id !== current.id || contract.cohort.revision !== current.current_revision || contract.cohort.manifestSha256 !== current.manifest_sha256) {
      throw new PolicyError(409, `Build ${build.id} output contract is outside the current cohort.`);
    }
    const selected = build.input_lock_sha256 ? await env.DB.prepare(`SELECT 1 FROM build_input_selections s JOIN current_input_locks l ON l.sha256=s.lock_sha256
      WHERE s.recipe_revision_id=? AND s.architecture=? AND s.cohort_id=? AND s.cohort_revision=? AND s.lock_sha256=? AND l.purpose='owned'`)
      .bind(build.revision_id, architecture, current.id, current.current_revision, build.input_lock_sha256).first() : null;
    if (!selected) throw new PolicyError(409, `Build ${build.id} lacks the selected current owned input lock.`);
    await verifyCandidateBuild(env, build);
    for (const output of await outputRecords(env, build)) {
      const policy = await catalogRebuildOn(env.DB, build.pkgbase);
      const item = await packageFromOutput(env, output, 'candidate', policy, build.id, build.attempt, build.input_lock_sha256, { cohortId: current.id, revision: current.current_revision, architecture, retainRecords: false, budget: abiBudget });
      const key = packageKey(item, architecture);
      const index = candidate.findIndex((entry) => packageKey(entry, architecture) === key);
      if (index >= 0) candidate[index] = item; else candidate.push(item);
    }
    fences.push(env.DB.prepare(`INSERT INTO distribution_assertions(expected,actual) SELECT 1,COUNT(*) FROM builds
      WHERE id=? AND architecture=? AND status='succeeded' AND attempt=? AND artifact_sha256 IS ? AND artifact_size IS ? AND provenance IS ?`).bind(
      build.id, architecture, build.attempt, build.artifact_sha256, build.artifact_size, build.provenance));
  }
  if (candidate.length > MAX_PACKAGES) throw new PolicyError(409, 'Candidate dependency universe exceeds 100,000 packages.');
  const indexRecords = candidate.reduce((count, item) => count + (item.abi?.records.length ?? 0), 0);
  // ponytail: compact ABI index capped at 1M records; persist per-package summaries if measured catalog runs exceed this bound.
  if (indexRecords > MAX_INDEX_RECORDS) throw new PolicyError(409, 'Candidate ABI index is unavailable within the bounded qualification memory budget.');
  return { candidate, baseline, fences };
}

async function qualificationEpoch(db: D1Database, cohortId: string): Promise<string> {
  const row = await db.prepare(`SELECT e.version||':'||s.version AS version FROM cohort_evidence_epoch e JOIN cohort_scope_epochs s ON s.cohort_id=? WHERE e.id=1`).bind(cohortId).first<{ version: string }>();
  if (!row) throw new PolicyError(409, 'Candidate qualification epoch is unavailable.');
  return row.version;
}

async function qualificationInputDigest(env: Pick<Env, 'DB' | 'ARTIFACTS'>, current: CohortRow, architecture: Architecture, epoch: string): Promise<string> {
  const universes = await pinnedUniverses(env, current);
  const owned = await query<{ snapshot_id: string; db_sha256: string; status: string; artifact_id: string; artifact_sha256: string; build_id: string; build_attempt: number; provenance_signature: string | null }>(env.DB,
    `SELECT u.id AS snapshot_id,u.root_sha256 AS db_sha256,u.status,a.id AS artifact_id,a.artifact_sha256,a.build_id,a.build_attempt,r.provenance_signature
     FROM owned_repository_universes u JOIN owned_repository_universe_packages p ON p.universe_id=u.id
     JOIN owned_repository_artifacts a ON a.id=p.artifact_id LEFT JOIN build_attempts ba ON ba.build_id=a.build_id AND ba.attempt=a.build_attempt
     LEFT JOIN build_attempt_results r ON r.build_id=ba.build_id AND r.attempt=ba.attempt
     WHERE u.id IN (SELECT value FROM json_each(?)) AND p.target_architecture=? AND u.status IN ('prepared','published') ORDER BY u.id,p.ordinal`, JSON.stringify(universes.map((universe) => universe.id)), architecture);
  const builds = await query<Pick<StoredBuild, 'id' | 'revision_id' | 'status' | 'attempt' | 'worker_id' | 'worker_status' | 'artifact_sha256' | 'artifact_size' | 'installed_size' | 'provenance_signature' | 'output_contract_json' | 'input_lock_sha256' | 'surface'> & { pkgbase: string }>(env.DB,
    `SELECT b.id,b.revision_id,b.status,b.attempt,b.worker_id,w.status AS worker_status,b.artifact_sha256,b.artifact_size,b.installed_size,b.provenance_signature,b.output_contract_json,b.input_lock_sha256,m.pkgbase,r.surface
     FROM builds b JOIN cohort_members m ON m.recipe_revision_id=b.revision_id AND m.cohort_id=? AND m.revision=? JOIN revisions r ON r.id=b.revision_id LEFT JOIN workers w ON w.id=b.worker_id
     WHERE b.architecture=? ORDER BY b.id`, current.id, current.current_revision, architecture);
  return sha256(canonicalJson({ schemaVersion: 1, cohortId: current.id, revision: current.current_revision, manifestSha256: current.manifest_sha256,
    architecture, epoch, snapshots: owned,
    candidateBuilds: builds.map((row) => ({ id: row.id, revisionId: row.revision_id, status: row.status, attempt: row.attempt, workerId: row.worker_id,
      workerStatus: row.worker_status, surface: row.surface, artifactSha256: row.artifact_sha256, artifactSize: row.artifact_size,
      provenanceSignature: row.provenance_signature, outputContract: row.output_contract_json, inputLock: row.input_lock_sha256, pkgbase: row.pkgbase })) }));
}

async function qualifyCohortUncached(env: Env, current: CohortRow, architecture: Architecture): Promise<Omit<QualificationResult, 'inputSha256'>> {
  const loaded = await loadPackages(env, current, architecture);
  const baseReport = qualifyCandidateUniverse({ cohortId: current.id, revision: current.current_revision, manifestSha256: current.manifest_sha256,
    architecture, candidate: loaded.candidate, baseline: loaded.baseline });
  const indexedFindings = await indexedAbiFindings(env.DB, { cohortId: current.id, revision: current.current_revision, architecture }, loaded.candidate, loaded.baseline, architecture);
  let report = { ...baseReport, findings: [...baseReport.findings.filter((item) => item.kind === 'dependency'), ...indexedFindings].slice(0, MAX_FINDINGS), truncated: baseReport.truncated || baseReport.findings.length + indexedFindings.length > MAX_FINDINGS };
  const inputFindings = await finalProviderInputFindings(env.DB, loaded.candidate, loaded.baseline, architecture);
  if (inputFindings.length) report = { ...report, findings: [...report.findings, ...inputFindings].slice(0, MAX_FINDINGS), truncated: report.truncated || report.findings.length + inputFindings.length > MAX_FINDINGS };
  const digestValue = await digest(report);
  loaded.fences.push(env.DB.prepare(`INSERT INTO distribution_assertions(expected,actual) SELECT 1,COUNT(*) FROM cohort_revisions
    WHERE cohort_id=? AND revision=? AND manifest_sha256=?`).bind(current.id, current.current_revision, current.manifest_sha256));
  for (const item of loaded.candidate) if (item.abi?.inventorySha256) loaded.fences.push(env.DB.prepare('INSERT INTO distribution_assertions(expected,actual) SELECT 1,COUNT(*) FROM build_abi_evidence WHERE sha256=? AND artifact_sha256=?').bind(item.abi.inventorySha256, item.artifactSha256));
  return { report, digest: digestValue, fences: loaded.fences };
}

export async function qualifyCohort(env: Env, current: CohortRow, architecture: Architecture): Promise<QualificationResult> {
  const epoch = await qualificationEpoch(env.DB, current.id);
  const inputSha256 = await qualificationInputDigest(env, current, architecture, epoch);
  const saved = await qualificationRunForGateWithInput(env.DB, current, architecture, inputSha256);
  if (saved) return { report: saved.report, digest: saved.digest, inputSha256, fences: [env.DB.prepare(`INSERT INTO distribution_assertions(expected,actual) SELECT 1,COUNT(*) FROM cohort_qualification_runs
    WHERE cohort_id=? AND revision=? AND architecture=? AND input_sha256=? AND report_sha256=?`).bind(current.id, current.current_revision, architecture, inputSha256, saved.digest)] };
  const result = await qualifyCohortUncached(env, current, architecture);
  return { ...result, inputSha256 };
}

export async function qualificationRunForGate(env: Pick<Env, 'DB' | 'ARTIFACTS'>, current: CohortRow, architecture: Architecture): Promise<{ report: QualificationReport; digest: string; inputSha256: string } | null> {
  const epoch = await qualificationEpoch(env.DB, current.id);
  const inputSha256 = await qualificationInputDigest(env, current, architecture, epoch);
  return qualificationRunForGateWithInput(env.DB, current, architecture, inputSha256);
}

async function qualificationRunForGateWithInput(db: D1Database, current: CohortRow, architecture: Architecture, inputSha256: string) {
  const saved = await db.prepare(`SELECT report_json,report_sha256 FROM cohort_qualification_runs
    WHERE cohort_id=? AND revision=? AND architecture=? AND input_sha256=? ORDER BY created_at DESC LIMIT 1`)
    .bind(current.id, current.current_revision, architecture, inputSha256).first<{ report_json: string; report_sha256: string }>();
  if (!saved) return null;
  const report = JSON.parse(saved.report_json) as QualificationReport;
  if (report.cohortId !== current.id || report.revision !== current.current_revision || report.manifestSha256 !== current.manifest_sha256 || report.architecture !== architecture || await sha256(canonicalJson(report)) !== saved.report_sha256) {
    throw new PolicyError(409, 'Stored candidate qualification report is stale or corrupt.');
  }
  return { report, digest: saved.report_sha256, inputSha256 };
}

export function qualificationBlockers(result: QualificationResult, members: ReadonlySet<string>): CohortBlocker[] {
  const blockers: CohortBlocker[] = [];
  for (const item of result.report.findings) {
    const pkgbase = members.has(item.pkgbase) ? item.pkgbase : item.relatedPkgbase;
    blockers.push({ code: `candidate-${item.kind}`, reason: item.reason, pkgbase: pkgbase ?? null, architecture: item.architecture,
      href: pkgbase ? `/maintain/catalog/${encodeURIComponent(pkgbase)}` : null });
  }
  if (result.report.truncated && members.size) blockers.push({ code: 'candidate-qualification-budget', reason: 'Candidate qualification exceeded its bounded finding budget; qualification remains incomplete until its persistent index is extended.', pkgbase: null, architecture: null, href: null });
  return blockers;
}

export async function storeQualificationRun(db: D1Database, result: QualificationResult): Promise<void> {
  const json = canonicalJson(result.report);
  if (await sha256(json) !== result.digest) throw new PolicyError(409, 'Candidate qualification report digest changed.');
  await db.prepare(`INSERT INTO cohort_qualification_runs(cohort_id,revision,architecture,input_sha256,universe_sha256,report_sha256,report_json,created_at)
    VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(cohort_id,revision,architecture,input_sha256,universe_sha256) DO NOTHING`)
    .bind(result.report.cohortId, result.report.revision, result.report.architecture, result.inputSha256, result.report.universeSha256, result.digest, json, now()).run();
}
