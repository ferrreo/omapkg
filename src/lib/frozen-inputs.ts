import type { Architecture } from './model';
import { canonicalJson } from './canonical-json';
import { sha256 } from './server/db';

export type InputObject = { sha256: string; size: number };
export type FrozenPackage = {
  name: string; version: string; architecture: Architecture | 'any'; filename: string;
  package: InputObject; signature: InputObject; publicKey: InputObject; fingerprint: string;
  origin: 'external-bootstrap' | 'owned-build'; originEvidence: string;
};
export type FrozenEnvironment = {
  name: string; packageCount: number; totalBytes: number; inventorySha256: string; chunks: InputObject[];
};
export type FrozenManifest = {
  schemaVersion: 1; purpose: 'bootstrap' | 'owned'; architecture: Architecture;
  recipeSha256: string; cohortSha256: string; sourceDateEpoch: number; helperImage: string;
  helperArchive: InputObject; makepkgConfig: InputObject; transferLimitBytes: number; environments: FrozenEnvironment[];
};
export type FrozenEvidence = {
  lock: InputObject; manifest: FrozenManifest;
  host: { architecture: Architecture; kernel: string; cpuInfoSha256: string; cpuModel: string;
    runtime: 'podman' | 'docker'; runtimeVersion: string; goVersion: string };
};
export const MAX_INPUT_OBJECT = 32 * 1024 ** 3;
export const MAX_INPUT_TRANSFER = 256 * 1024 ** 3;
export const MAX_INPUT_METADATA = 4 * 1024 * 1024;
export const INPUT_HASH = /^[a-f0-9]{64}$/;

function exact(value: unknown, fields: string): void {
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).sort().join(',') !== fields.split(',').sort().join(',')) {
    throw new Error('Frozen input has missing or unexpected fields');
  }
}
function integer(value: unknown, min: number, max: number): boolean {
  return Number.isSafeInteger(value) && (value as number) >= min && (value as number) <= max;
}
export function parseInputObject(value: unknown, max = MAX_INPUT_OBJECT): InputObject {
  exact(value, 'sha256,size');
  const ref = value as InputObject;
  if (typeof ref.sha256 !== 'string' || !INPUT_HASH.test(ref.sha256) || !integer(ref.size, 1, max)) throw new Error('Invalid frozen object reference');
  return ref;
}
export function parseFrozenManifest(value: unknown): FrozenManifest {
  exact(value, 'schemaVersion,purpose,architecture,recipeSha256,cohortSha256,sourceDateEpoch,helperImage,helperArchive,makepkgConfig,transferLimitBytes,environments');
  const m = value as FrozenManifest;
  if (m.schemaVersion !== 1 || !['bootstrap', 'owned'].includes(m.purpose) || !['x86_64', 'aarch64'].includes(m.architecture) ||
      !INPUT_HASH.test(m.recipeSha256) || !INPUT_HASH.test(m.cohortSha256) || !integer(m.sourceDateEpoch, 0, Number.MAX_SAFE_INTEGER) ||
      typeof m.helperImage !== 'string' || m.helperImage.length > 1024 || !/^[^\s\x00-\x1f]+@sha256:[a-f0-9]{64}$/.test(m.helperImage) ||
      !integer(m.transferLimitBytes, 1, MAX_INPUT_TRANSFER) || !Array.isArray(m.environments) || !m.environments.length || m.environments.length > 257) {
    throw new Error('Invalid frozen manifest identity or budget');
  }
  parseInputObject(m.helperArchive); parseInputObject(m.makepkgConfig, 64 * 1024);
  let pages = 0;
  for (const [index, environment] of m.environments.entries()) {
    exact(environment, 'name,packageCount,totalBytes,inventorySha256,chunks');
    if (environment.name !== (index ? `runtime-${index - 1}` : 'build') || !integer(environment.packageCount, 1, 4096) ||
        !integer(environment.totalBytes, 1, m.transferLimitBytes) || !INPUT_HASH.test(environment.inventorySha256) ||
        !Array.isArray(environment.chunks) || !environment.chunks.length || environment.chunks.length > 64) throw new Error('Invalid frozen environment');
    for (const chunk of environment.chunks) parseInputObject(chunk, 1024 * 1024);
    pages += environment.chunks.length;
  }
  if (pages > 1024 || new TextEncoder().encode(canonicalJson(m)).byteLength > 128 * 1024) throw new Error('Frozen manifest exceeds page or document budget');
  return m;
}
export function parseFrozenPage(value: unknown, manifest: FrozenManifest): FrozenPackage[] {
  if (!Array.isArray(value) || !value.length || value.length > 64) throw new Error('Frozen pages require 1 to 64 packages');
  for (const item of value as FrozenPackage[]) {
    exact(item, 'name,version,architecture,filename,package,signature,publicKey,fingerprint,origin,originEvidence');
    if (typeof item.name !== 'string' || !/^[a-z0-9][a-z0-9@._+-]{0,63}$/.test(item.name) || typeof item.version !== 'string' ||
        !/^(?:[0-9]+:)?[A-Za-z0-9][A-Za-z0-9@._+%~^-]{0,127}$/.test(item.version) ||
        ![manifest.architecture, 'any'].includes(item.architecture) || typeof item.filename !== 'string' || item.filename.length > 256 ||
        ![item.version, item.version.replace(/^[0-9]+:/, '')].some((version) => item.filename === `${item.name}-${version}-${item.architecture}.pkg.tar.zst`) ||
        !/^[A-F0-9]{40}$/.test(item.fingerprint) || !INPUT_HASH.test(item.originEvidence) ||
        !['external-bootstrap', 'owned-build'].includes(item.origin) || (manifest.purpose === 'owned' && item.origin !== 'owned-build')) {
      throw new Error('Invalid frozen package identity or origin');
    }
    parseInputObject(item.package, 4 * 1024 ** 3); parseInputObject(item.signature, 1024 * 1024); parseInputObject(item.publicKey, 1024 * 1024);
  }
  return value as FrozenPackage[];
}

// The page reader must verify retained bytes. This validates the complete closure,
// including deduplicated transfer costs, before any large object is downloaded.
export async function inspectFrozenInputs(lock: InputObject, value: unknown, readPage: (ref: InputObject) => Promise<unknown>) {
  parseInputObject(lock, 128 * 1024);
  const manifest = parseFrozenManifest(value);
  const json = canonicalJson(manifest);
  if (lock.sha256 !== await sha256(json) || lock.size !== new TextEncoder().encode(json).byteLength) throw new Error('Frozen manifest checksum differs from root reference');
  const objects = new Map<string, InputObject>();
  const origins = new Set<string>();
  const uniquePackages = new Map<string, string>();
  const environments: { name: string; packages: FrozenPackage[] }[] = [];
  const pages = new Map<string, FrozenPackage[]>();
  let metadataBytes = 0;
  let size = 0;
  function add(ref: InputObject) {
    const previous = objects.get(ref.sha256);
    if (previous && previous.size !== ref.size) throw new Error('Frozen object has conflicting sizes');
    if (!previous) { objects.set(ref.sha256, ref); size += ref.size; }
    if (size > manifest.transferLimitBytes) throw new Error('Frozen inputs exceed reviewed transfer budget');
  }
  add(lock); add(manifest.helperArchive); add(manifest.makepkgConfig);
  for (const environment of manifest.environments) {
    const packages: FrozenPackage[] = [];
    for (const chunk of environment.chunks) {
      add(chunk);
      if (!pages.has(chunk.sha256)) {
        metadataBytes += chunk.size;
        if (metadataBytes > MAX_INPUT_METADATA) throw new Error('Frozen package pages exceed metadata budget');
        pages.set(chunk.sha256, parseFrozenPage(await readPage(chunk), manifest));
      }
      for (const pkg of pages.get(chunk.sha256)!) {
        const identity = `${pkg.name} ${pkg.version} ${pkg.architecture}`;
        if (uniquePackages.has(pkg.package.sha256) && uniquePackages.get(pkg.package.sha256) !== identity) throw new Error('One frozen package checksum has conflicting identities');
        packages.push(pkg); uniquePackages.set(pkg.package.sha256, identity); origins.add(pkg.originEvidence);
        add(pkg.package); add(pkg.signature); add(pkg.publicKey);
      }
    }
    const inventory = packages.map((pkg) => `${pkg.name} ${pkg.version}`).sort().join('\n') + '\n';
    if (uniquePackages.size > 4096 || packages.length !== environment.packageCount || new Set(packages.map((pkg) => pkg.name)).size !== packages.length ||
        packages.reduce((total, pkg) => total + pkg.package.size, 0) !== environment.totalBytes || await sha256(inventory) !== environment.inventorySha256) {
      throw new Error('Frozen package count, size or inventory differs from lock');
    }
    environments.push({ name: environment.name, packages });
  }
  return { manifest, objects: [...objects.values()], origins: [...origins], environments, transferBytes: size };
}

export async function assertFrozenEvidence(value: unknown, expected: { architecture: Architecture; recipeSha256: string; cohortSha256: string;
  sourceDateEpoch: number; imageDigest: string; environments: { baseImage: string; preparedImage: string; packages: string[] }[] }): Promise<FrozenEvidence> {
  exact(value, 'lock,manifest,host');
  const evidence = value as FrozenEvidence;
  const m = parseFrozenManifest(evidence.manifest); const ref = parseInputObject(evidence.lock, 128 * 1024);
  const json = canonicalJson(m);
  if (ref.sha256 !== await sha256(json) || ref.size !== new TextEncoder().encode(json).byteLength ||
      m.architecture !== expected.architecture || m.recipeSha256 !== expected.recipeSha256 || m.cohortSha256 !== expected.cohortSha256 ||
      m.sourceDateEpoch !== expected.sourceDateEpoch || !m.helperImage.endsWith(`@${expected.imageDigest}`) || m.environments.length !== expected.environments.length) {
    throw new Error('Frozen input evidence differs from native build');
  }
  assertNativeHost(evidence.host, expected.architecture);
  for (const [index, environment] of expected.environments.entries()) {
    if (environment.baseImage !== m.helperImage || !/^sha256:[a-f0-9]{64}$/.test(environment.preparedImage) ||
        !Array.isArray(environment.packages) || environment.packages.length !== m.environments[index].packageCount ||
        await sha256([...environment.packages].sort().join('\n') + '\n') !== m.environments[index].inventorySha256) throw new Error('Prepared environment differs from frozen inventory');
  }
  return evidence;
}

export function assertNativeHost(value: unknown, architecture: Architecture): FrozenEvidence['host'] {
  exact(value, 'architecture,kernel,cpuInfoSha256,cpuModel,runtime,runtimeVersion,goVersion');
  const host = value as FrozenEvidence['host'];
  if (host.architecture !== architecture || !INPUT_HASH.test(host.cpuInfoSha256) || !['podman', 'docker'].includes(host.runtime) ||
      [host.kernel, host.cpuModel, host.runtimeVersion, host.goVersion].some((value) => typeof value !== 'string' || !value || value.length > 4096 || /[\x00-\x1f\x7f]/.test(value))) {
    throw new Error('Native host evidence is missing or invalid');
  }
  return host;
}
