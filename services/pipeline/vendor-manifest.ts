import type { Architecture } from '../../src/lib/model';
import { validateArchivePath, resolveArchiveLinkTarget, resolveCanonicalArchivePath } from './archive-safety';

export const MAX_VENDOR_SOURCE_BYTES = 2 * 1024 * 1024 * 1024;

export const MAX_VENDOR_HEADER_BYTES = 1 * 1024 * 1024;

export const MAX_VENDOR_ENTRIES = 20_000;

export const MAX_VENDOR_PATH_BYTES = 4_096;

export const MAX_VENDOR_EXPANDED_BYTES = 4 * 1024 * 1024 * 1024;

export const MAX_VENDOR_MANIFEST_BYTES = 8 * 1024 * 1024;

export const MAX_VENDOR_INVENTORY_ENTRIES = 200;

export const MAX_VENDOR_READ_BYTES = 32 * 1024;

export type VendorArtifactFormat = 'deb' | 'rpm' | 'appimage1' | 'appimage2' | 'run';

export type VendorArtifactSurface = 'binary' | 'recipe';

export interface VendorArtifactEntry {
  path: string;
  kind: 'file' | 'directory' | 'symlink' | 'hardlink';
  size: number;
  target: string | null;
}

export interface VendorArtifactManifest {
  schemaVersion: 1;
  format: VendorArtifactFormat;
  surface: VendorArtifactSurface;
  sourcePath: string;
  sourceSize: number;
  sourceSha256: string;
  payloadPath: string | null;
  entriesPath: string | null;
  controlPath?: string | null;
  controlEntriesPath?: string | null;
  appimageOffset?: number | null;
  metadata: Record<string, string>;
  entries?: VendorArtifactEntry[];
  inventory?: string[];
  controlInventory?: string[];
}

export interface VendorArtifactCommandOptions {
  workspaceRoot?: string;
  sourcePath?: string;
  /** Optional source filename hint; header/package metadata remains authoritative. */
  sourceName?: string;
  workPath?: string;
  manifestPath?: string;
  payloadPath?: string;
  entriesPath?: string;
  maxBytes?: number;
  maxEntries?: number;
}

export interface OfflineVendorExtractOptions {
  sourcePath?: string;
  destination?: string;
  sha256: string;
  appimageOffset?: number;
}

const formats: readonly VendorArtifactFormat[] = ['deb', 'rpm', 'appimage1', 'appimage2', 'run'];

export const sha256Pattern = /^[0-9a-f]{64}$/;

const squashfsMagic = ['hsqs', 'sqsh', 'shsq', 'qshs'];

const vendorArchitectures: readonly Architecture[] = ['x86_64', 'aarch64'];

function ascii(bytes: Uint8Array, offset: number, length: number): string {
  if (offset < 0 || offset + length > bytes.byteLength) return '';
  return String.fromCharCode(...bytes.subarray(offset, offset + length));
}

function readUInt(bytes: Uint8Array, offset: number, width: 2 | 4 | 8, little: boolean): number | null {
  if (offset < 0 || offset + width > bytes.byteLength) return null;
  let value = 0;
  for (let index = 0; index < width; index += 1) {
    const at = little ? offset + index : offset + width - index - 1;
    value += bytes[at] * 2 ** (8 * index);
  }
  return Number.isSafeInteger(value) ? value : null;
}

function elfFileEnd(bytes: Uint8Array): number | null {
  if (ascii(bytes, 0, 4) !== '\x7fELF' || bytes[4] === 0 || bytes[5] < 1 || bytes[5] > 2) return null;
  const is64 = bytes[4] === 2;
  const little = bytes[5] === 1;
  const phoff = readUInt(bytes, is64 ? 32 : 28, is64 ? 8 : 4, little);
  const shoff = readUInt(bytes, is64 ? 40 : 32, is64 ? 8 : 4, little);
  const phentsize = readUInt(bytes, is64 ? 54 : 42, 2, little);
  const phnum = readUInt(bytes, is64 ? 56 : 44, 2, little);
  const shentsize = readUInt(bytes, is64 ? 58 : 46, 2, little);
  const shnum = readUInt(bytes, is64 ? 60 : 48, 2, little);
  let end = readUInt(bytes, is64 ? 52 : 40, 2, little) ?? 0;
  if (phoff !== null && phentsize && phnum && phnum <= 256) {
    for (let index = 0; index < phnum; index += 1) {
      const header = phoff + index * phentsize;
      const offset = readUInt(bytes, header + (is64 ? 8 : 4), is64 ? 8 : 4, little);
      const size = readUInt(bytes, header + (is64 ? 32 : 16), is64 ? 8 : 4, little);
      if (offset !== null && size !== null) end = Math.max(end, offset + size);
    }
  }
  if (shoff !== null && shentsize && shnum && shnum <= 65_536) {
    for (let index = 0; index < shnum; index += 1) {
      const header = shoff + index * shentsize;
      const type = readUInt(bytes, header + 4, 4, little);
      const offset = readUInt(bytes, header + (is64 ? 24 : 16), is64 ? 8 : 4, little);
      const size = readUInt(bytes, header + (is64 ? 32 : 20), is64 ? 8 : 4, little);
      if (type !== 8 && offset !== null && size !== null) end = Math.max(end, offset + size);
    }
  }
  return end > 0 && end <= bytes.byteLength ? end : null;
}

export function elfMachineArchitecture(bytes: Uint8Array): Architecture | null {
  if (ascii(bytes, 0, 4) !== '\x7fELF' || bytes[5] < 1 || bytes[5] > 2) return null;
  const machine = readUInt(bytes, 18, 2, bytes[5] === 1);
  if (machine === 62) return 'x86_64';
  if (machine === 183) return 'aarch64';
  return null;
}

export function appImageSquashfsOffset(bytes: Uint8Array): number | null {
  const start = elfFileEnd(bytes);
  if (start === null) return null;
  const limit = Math.min(bytes.byteLength - 4, start + 16 * 1024 * 1024);
  for (let offset = start; offset <= limit; offset += 1) {
    if (squashfsMagic.includes(ascii(bytes, offset, 4))) return offset;
  }
  return null;
}

function runHeader(bytes: Uint8Array): boolean {
  if (ascii(bytes, 0, 2) !== '#!') return false;
  const header = new TextDecoder().decode(bytes.subarray(0, Math.min(bytes.byteLength, MAX_VENDOR_HEADER_BYTES)));
  return /(?:makeself|nvidia-linux|self[- ]extracting)/i.test(header);
}

export function detectVendorBinaryFormat(bytes: Uint8Array): VendorArtifactFormat | null {
  if (ascii(bytes, 0, 8) === '!<arch>\n') return 'deb';
  if (ascii(bytes, 0, 4) === '\xed\xab\xee\xdb') return 'rpm';
  if (ascii(bytes, 0, 4) === '\x7fELF' && ascii(bytes, 8, 3) === 'AI\x02' && appImageSquashfsOffset(bytes) !== null) return 'appimage2';
  if (ascii(bytes, 0, 4) === '\x7fELF' && ascii(bytes, 8, 3) === 'AI\x01' && ascii(bytes, 32_769, 5) === 'CD001') return 'appimage1';
  if (runHeader(bytes)) return 'run';
  return null;
}

function architectureEvidence(value: string, format: VendorArtifactFormat): Architecture[] {
  const normalized = value.trim().toLowerCase();
  if (normalized === 'all' || normalized === 'noarch') {
    if (format === 'appimage1' || format === 'appimage2' || format === 'run') throw new Error(`unsupported ${format} architecture evidence`);
    return [...vendorArchitectures];
  }
  if (normalized === 'amd64' || normalized === 'x86_64' || normalized === 'x86-64') return ['x86_64'];
  if (normalized === 'arm64' || normalized === 'aarch64') return ['aarch64'];
  throw new Error(`unsupported ${format} architecture evidence`);
}

export function vendorArtifactArchitectures(manifest: Pick<VendorArtifactManifest, 'format' | 'metadata'>): Architecture[] {
  const value = manifest.metadata?.architecture;
  if (typeof value !== 'string' || !value.trim()) throw new Error(`vendor ${manifest.format} architecture evidence is missing`);
  return architectureEvidence(value, manifest.format);
}

export function constrainVendorArtifactArchitectures(
  requested: readonly Architecture[],
  manifest: Pick<VendorArtifactManifest, 'format' | 'metadata'>,
): Architecture[] {
  const supported = vendorArtifactArchitectures(manifest);
  const candidates = [...new Set(requested)];
  const constrained = candidates.filter((architecture) => supported.includes(architecture));
  if (!constrained.length) throw new Error(`vendor ${manifest.format} architecture does not match requested architectures`);
  return constrained;
}

export const assertVendorArtifactArchitectures = constrainVendorArtifactArchitectures;

export function validateArchiveEntries(paths: readonly string[], maxEntries = MAX_VENDOR_ENTRIES): string[] {
  if (paths.length > maxEntries) throw new Error('vendor archive contains too many entries');
  const normalized = paths.map(validateArchivePath);
  if (new Set(normalized).size !== normalized.length) throw new Error('vendor archive contains duplicate entries');
  return normalized;
}

function normalizeVendorEntryPath(value: string): string {
  return validateArchivePath(value.replace(/\/$/, ''), MAX_VENDOR_PATH_BYTES);
}

function resolveVendorLinkTarget(path: string, target: string): string {
  if (typeof target !== 'string' || target.length === 0 || target.length > MAX_VENDOR_PATH_BYTES || /[\u0000-\u001f\u007f\\]/.test(target)) {
    throw new Error('vendor archive link target is unsafe');
  }
  if (target.startsWith('/')) return normalizeVendorEntryPath(target.slice(1));
  return resolveArchiveLinkTarget(path, target, MAX_VENDOR_PATH_BYTES);
}

export function validateVendorArtifactEntries(
  rawEntries: readonly VendorArtifactEntry[],
  maxEntries = MAX_VENDOR_ENTRIES,
  maxExpandedBytes = MAX_VENDOR_EXPANDED_BYTES,
): VendorArtifactEntry[] {
  if (!Number.isSafeInteger(maxEntries) || maxEntries <= 0 || maxEntries > MAX_VENDOR_ENTRIES) throw new Error('vendor entry limit is invalid');
  if (!Number.isSafeInteger(maxExpandedBytes) || maxExpandedBytes <= 0 || maxExpandedBytes > MAX_VENDOR_EXPANDED_BYTES) throw new Error('vendor expansion limit is invalid');
  if (!rawEntries.length) throw new Error('vendor archive is empty');
  if (rawEntries.length > maxEntries) throw new Error('vendor archive contains too many entries');
  const entries = rawEntries.map((entry) => {
    if (!entry || !['file', 'directory', 'symlink', 'hardlink'].includes(entry.kind) ||
      !Number.isSafeInteger(entry.size) || entry.size < 0 || entry.size > maxExpandedBytes) {
      throw new Error('vendor archive entry is invalid');
    }
    const path = normalizeVendorEntryPath(entry.path);
    let target: string | null = null;
    if (entry.kind === 'symlink') {
      target = entry.target;
      resolveVendorLinkTarget(path, target ?? '');
    } else if (entry.kind === 'hardlink') {
      target = normalizeVendorEntryPath(entry.target ?? '');
    } else if (entry.target !== null && entry.target !== undefined && entry.target !== '') {
      throw new Error('vendor archive regular entry has a link target');
    }
    return { path, kind: entry.kind, size: entry.size, target };
  });
  const byPath = new Map(entries.map((entry) => [entry.path, entry]));
  if (byPath.size !== entries.length) throw new Error('vendor archive contains duplicate entries');
  let expandedSize = 0;
  for (const entry of entries) {
    if (expandedSize > maxExpandedBytes - entry.size) throw new Error('vendor archive exceeds the expansion limit');
    expandedSize += entry.size;
    let parent = entry.path;
    while (parent.includes('/')) {
      parent = parent.slice(0, parent.lastIndexOf('/'));
      const parentEntry = byPath.get(parent);
      if (parentEntry && parentEntry.kind !== 'directory') throw new Error('vendor archive has a non-directory parent');
    }
    if (entry.kind === 'hardlink') {
      const target = byPath.get(entry.target ?? '');
      if (!target || target.kind !== 'file') throw new Error('vendor archive hardlink target is missing or not a regular file');
    }
  }
  for (const entry of entries) {
    if (entry.kind === 'symlink') {
      const absolute = (entry.target ?? '').startsWith('/');
      const parent = absolute ? '' : entry.path.includes('/') ? entry.path.slice(0, entry.path.lastIndexOf('/')) : '';
      resolveCanonicalArchivePath(parent, absolute ? (entry.target ?? '').slice(1) : entry.target ?? '', byPath);
    }
  }
  return entries;
}

export function vendorArtifactInventory(
  entries: readonly VendorArtifactEntry[],
  limit = MAX_VENDOR_INVENTORY_ENTRIES,
): string[] {
  if (!Number.isSafeInteger(limit) || limit <= 0 || limit > MAX_VENDOR_INVENTORY_ENTRIES) throw new Error('vendor inventory limit is invalid');
  if (!entries.length) return [];
  const priority = (path: string): number => {
    const basename = path.slice(path.lastIndexOf('/') + 1);
    if (/^(?:control|AppRun|.*\.desktop)$/i.test(basename)) return 0;
    if (/^(?:license|copying|notice|readme)(?:[._ -].*)?$/i.test(basename)) return 1;
    return path.includes('/') ? 3 : 2;
  };
  return validateVendorArtifactEntries(entries)
    .filter((entry) => entry.kind !== 'directory' && vendorInspectionPath(entry.path))
    .map((entry) => entry.path)
    .sort((left, right) => priority(left) - priority(right) || left.localeCompare(right))
    .slice(0, limit);
}

function vendorInspectionPath(path: string): boolean {
  const basename = path.slice(path.lastIndexOf('/') + 1);
  return basename === 'AppRun' || basename === 'control' || basename === 'postinst' ||
    /\.desktop$/i.test(basename) || /^(?:license|copying|notice|readme)(?:[._ -].*)?$/i.test(basename);
}

export function assertVendorArtifactReadPaths(
  entries: readonly VendorArtifactEntry[],
  rawPaths: readonly string[],
): string[] {
  const validated = validateVendorArtifactEntries(entries);
  const allowed = new Set(validated.filter((entry) => entry.kind !== 'directory').map((entry) => entry.path));
  const paths = [...new Set(rawPaths.map((path) => normalizeVendorEntryPath(path)))];
  if (paths.length > 12 || paths.some((path) => !allowed.has(path) || !vendorInspectionPath(path))) {
    throw new Error('vendor file is not an approved text inspection path');
  }
  return paths;
}

export function vendorArtifactLogicalReadPath(
  entries: readonly VendorArtifactEntry[],
  path: string,
): string {
  const validated = validateVendorArtifactEntries(entries);
  const normalized = normalizeVendorEntryPath(path);
  const byPath = new Map(validated.map((entry) => [entry.path, entry]));
  const entry = byPath.get(normalized);
  if (!entry || entry.kind === 'directory') throw new Error('vendor file is not an approved text inspection path');
  if (entry.kind === 'hardlink') return entry.target ?? '';
  if (entry.kind === 'symlink') {
    const absolute = (entry.target ?? '').startsWith('/');
    const parent = absolute ? '' : normalized.includes('/') ? normalized.slice(0, normalized.lastIndexOf('/')) : '';
    return resolveCanonicalArchivePath(parent, absolute ? (entry.target ?? '').slice(1) : entry.target ?? '', byPath);
  }
  return normalized;
}

export function workspaceRoot(value = '/workspace'): string {
  if (typeof value !== 'string' || !value.startsWith('/') || value.length > 512 || !/^[A-Za-z0-9._+@%/-]+$/.test(value) || value.split('/').includes('..') || value.endsWith('/')) {
    throw new Error('vendor workspace root is invalid');
  }
  return value;
}

export function sandboxPath(value: string, label: string, root = '/workspace'): string {
  const base = workspaceRoot(root);
  if (typeof value !== 'string' || !value.startsWith(`${base}/`) || value.length > 512 || !/^[A-Za-z0-9._+@%/-]+$/.test(value) || value.split('/').includes('..')) {
    throw new Error(`${label} must be an absolute workspace path`);
  }
  return value;
}

function manifestPath(value: unknown, label: string, root = '/workspace'): string {
  return sandboxPath(typeof value === 'string' ? value : '', label, root);
}

export function parseVendorArtifactManifest(raw: string, entriesRaw?: string, root = '/workspace'): VendorArtifactManifest {
  let value: unknown;
  try { value = JSON.parse(raw); } catch { throw new Error('vendor artifact manifest is invalid JSON'); }
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('vendor artifact manifest must be an object');
  const manifest = value as Record<string, unknown>;
  if (manifest.schemaVersion !== 1 || !formats.includes(manifest.format as VendorArtifactFormat)) throw new Error('vendor artifact manifest version or format is invalid');
  if (manifest.surface !== 'binary' && manifest.surface !== 'recipe') throw new Error('vendor artifact surface is invalid');
  if (typeof manifest.sourcePath !== 'string') throw new Error('vendor artifact source path is missing');
  const sourcePath = sandboxPath(manifest.sourcePath, 'vendor source path', root);
  if (!Number.isSafeInteger(manifest.sourceSize) || (manifest.sourceSize as number) < 0 || (manifest.sourceSize as number) > MAX_VENDOR_SOURCE_BYTES) throw new Error('vendor source size is invalid');
  if (typeof manifest.sourceSha256 !== 'string' || !sha256Pattern.test(manifest.sourceSha256)) throw new Error('vendor source digest is invalid');
  const payloadPath = manifest.payloadPath === undefined || manifest.payloadPath === null ? null : manifestPath(manifest.payloadPath, 'vendor payload path', root);
  const entriesPath = manifest.entriesPath === undefined || manifest.entriesPath === null ? null : manifestPath(manifest.entriesPath, 'vendor entries path', root);
  const controlPath = manifest.controlPath === undefined || manifest.controlPath === null ? manifest.controlPath ?? null : manifestPath(manifest.controlPath, 'vendor control path', root);
  const controlEntriesPath = manifest.controlEntriesPath === undefined || manifest.controlEntriesPath === null ? manifest.controlEntriesPath ?? null : manifestPath(manifest.controlEntriesPath, 'vendor control entries path', root);
  let appimageOffset: number | null | undefined = manifest.appimageOffset as number | null | undefined;
  if (appimageOffset !== undefined && appimageOffset !== null && (!Number.isSafeInteger(appimageOffset) || appimageOffset < 0 || appimageOffset > MAX_VENDOR_SOURCE_BYTES)) throw new Error('AppImage filesystem offset is invalid');
  const metadataValue = manifest.metadata;
  if (!metadataValue || typeof metadataValue !== 'object' || Array.isArray(metadataValue)) throw new Error('vendor metadata is invalid');
  const metadata: Record<string, string> = {};
  for (const [key, item] of Object.entries(metadataValue as Record<string, unknown>)) {
    if (!/^[A-Za-z][A-Za-z0-9_]{0,63}$/.test(key) || typeof item !== 'string' || item.length > 512 || /[\u0000\r\n]/.test(item)) throw new Error('vendor metadata field is invalid');
    metadata[key] = item;
  }
  if (manifest.format === 'run' && payloadPath !== null) throw new Error('self-extracting installers do not produce an online payload');
  if (manifest.format === 'run' && entriesPath !== null) throw new Error('self-extracting installers do not produce an online entry manifest');
  if (manifest.format === 'run' && controlEntriesPath !== null) throw new Error('self-extracting installers do not produce control entries');
  if (manifest.format !== 'run' && (payloadPath === null || entriesPath === null)) throw new Error('vendor archive payload manifest is incomplete');
  if (manifest.format === 'appimage2' && (appimageOffset === undefined || appimageOffset === null)) throw new Error('Type 2 AppImage filesystem offset is missing');
  if (manifest.format !== 'appimage2' && appimageOffset !== undefined && appimageOffset !== null) throw new Error('AppImage filesystem offset is only valid for Type 2 images');
  const result: VendorArtifactManifest = {
    schemaVersion: 1,
    format: manifest.format as VendorArtifactFormat,
    surface: manifest.surface,
    sourcePath,
    sourceSize: manifest.sourceSize as number,
    sourceSha256: manifest.sourceSha256,
    payloadPath,
    entriesPath,
    controlPath,
    controlEntriesPath,
    appimageOffset,
    metadata,
  };
  vendorArtifactArchitectures(result);
  if (entriesRaw !== undefined) {
    if (new TextEncoder().encode(entriesRaw).byteLength > MAX_VENDOR_MANIFEST_BYTES) throw new Error('vendor entry manifest is too large');
    result.entries = parseVendorArtifactManifestEntries(entriesRaw);
  }
  return result;
}

export function parseVendorArtifactManifestEntries(raw: string): VendorArtifactEntry[] {
  const entries: VendorArtifactEntry[] = [];
  for (const line of raw.split('\n')) {
    if (!line) continue;
    const [kind, path, size, target] = line.split('\t');
    if (!kind || !path || !/^\d+$/.test(size ?? '') || !['file', 'directory', 'symlink', 'hardlink'].includes(kind)) throw new Error('vendor entry manifest is invalid');
    entries.push({ path, kind: kind as VendorArtifactEntry['kind'], size: Number(size), target: target || null });
  }
  return validateVendorArtifactEntries(entries);
}

export function vendorSurface(redistributionEvidence?: string): VendorArtifactSurface {
  return redistributionEvidence?.trim() ? 'binary' : 'recipe';
}

export const detectVendorBinary = detectVendorBinaryFormat;
