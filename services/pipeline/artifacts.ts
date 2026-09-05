import type { Sandbox } from '@flue/runtime';
import type { Architecture } from '../../src/lib/model';
import {
  resolveArchiveLinkTarget,
  resolveCanonicalArchivePath,
  validateArchivePath,
} from './archive-safety';
export { validateArchivePath } from './archive-safety';

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
const sha256Pattern = /^[0-9a-f]{64}$/;
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

export interface VendorArtifactReadCommandOptions {
  workspaceRoot?: string;
  rootPath?: string;
  maxBytes?: number;
}

export function vendorArtifactReadCommand(
  entries: readonly VendorArtifactEntry[],
  paths: readonly string[],
  options: VendorArtifactReadCommandOptions = {},
): string {
  const validated = validateVendorArtifactEntries(entries);
  const selected = assertVendorArtifactReadPaths(validated, paths);
  const physicalPaths = selected.map((path) => ({ display: path, path: vendorArtifactLogicalReadPath(validated, path) }));
  const root = workspaceRoot(options.workspaceRoot);
  const rootPath = sandboxPath(options.rootPath ?? `${root}/vendor-artifact/payload-root`, 'vendor payload root', root);
  const maxBytes = options.maxBytes ?? MAX_VENDOR_READ_BYTES;
  if (!Number.isSafeInteger(maxBytes) || maxBytes <= 0 || maxBytes > MAX_VENDOR_READ_BYTES) throw new Error('vendor read limit is invalid');
  const q = shellQuote;
  return `#!/usr/bin/env bash
set -eu
root=${q(rootPath)}
command -v realpath >/dev/null 2>&1 || exit 65
for specification in ${physicalPaths.map(({ display, path }) => q(`${display}\t${path}`)).join(' ')}; do
  IFS=$'\t' read -r relative physical <<< "$specification"
  file="$root/$physical"
  test -f "$file"
  resolved=$(realpath -m -- "$file")
  case "$resolved" in "$root"/*) ;; *) exit 65 ;; esac
  size=$(stat -c '%s' "$file")
  [[ "$size" =~ ^[0-9]+$ ]] && (( size <= ${maxBytes} )) || exit 65
  printf '\\n--- %s ---\\n' "$relative"
  LC_ALL=C sed -n '1,240p' "$file" | head -c ${maxBytes} | LC_ALL=C tr -cd '\\11\\12\\15\\40-\\176'
done
`;
}

function workspaceRoot(value = '/workspace'): string {
  if (typeof value !== 'string' || !value.startsWith('/') || value.length > 512 || !/^[A-Za-z0-9._+@%/-]+$/.test(value) || value.split('/').includes('..') || value.endsWith('/')) {
    throw new Error('vendor workspace root is invalid');
  }
  return value;
}

function sandboxPath(value: string, label: string, root = '/workspace'): string {
  const base = workspaceRoot(root);
  if (typeof value !== 'string' || !value.startsWith(`${base}/`) || value.length > 512 || !/^[A-Za-z0-9._+@%/-]+$/.test(value) || value.split('/').includes('..')) {
    throw new Error(`${label} must be an absolute workspace path`);
  }
  return value;
}

function shellQuote(value: string): string {
  return `'${value.replaceAll("'", "'\\''")}'`;
}

function shellRecipePath(value: string, label: string): string {
  if (typeof value !== 'string' || value.length > 512 || /[\u0000\r\n]/.test(value) || value.split('/').some((part) => part === '..')) {
    throw new Error(`${label} is unsafe`);
  }
  if (/^(?:\/|\.\/|\$srcdir\/|\$\{srcdir\}\/)[A-Za-z0-9._+@%=-]+(?:\/[A-Za-z0-9._+@%=-]+)*$/.test(value)) {
    return value.startsWith('$srcdir') || value.startsWith('${srcdir}') ? `"${value}"` : shellQuote(value);
  }
  throw new Error(`${label} is unsafe`);
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

async function readBoundedVendorFile(sandbox: Sandbox, path: string): Promise<string> {
  const guard = await sandbox.exec([
    'set -eu',
    `test -f ${shellQuote(path)}`,
    `size=$(stat -c '%s' ${shellQuote(path)})`,
    `test "$size" -ge 0 -a "$size" -le ${MAX_VENDOR_MANIFEST_BYTES}`,
  ].join('\n'), { timeoutMs: 60_000 });
  if (guard.exitCode !== 0) throw new Error('vendor manifest exceeds the bounded read limit');
  const bytes = await sandbox.readFileBuffer(path);
  if (bytes.byteLength > MAX_VENDOR_MANIFEST_BYTES) throw new Error('vendor manifest exceeds the bounded read limit');
  return new TextDecoder().decode(bytes);
}

export async function inspectVendorArtifact(sandbox: Sandbox, options: VendorArtifactCommandOptions = {}): Promise<VendorArtifactManifest> {
  const root = workspaceRoot(options.workspaceRoot);
  const manifestPath = manifestPathValue(options.manifestPath, root);
  const result = await sandbox.exec(vendorArtifactCommand(options), { timeoutMs: 15 * 60 * 1_000 });
  if (result.exitCode !== 0) throw new Error(`vendor artifact inspection failed: ${result.stderr.slice(0, 1_000)}`);
  const raw = await readBoundedVendorFile(sandbox, manifestPath);
  const parsed = parseVendorArtifactManifest(raw, undefined, root);
  if (parsed.entriesPath) parsed.entries = parseVendorArtifactManifestEntries(await readBoundedVendorFile(sandbox, parsed.entriesPath));
  return parsed;
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

function manifestPathValue(value: string | undefined, root = '/workspace'): string {
  const base = workspaceRoot(root);
  return sandboxPath(value ?? `${base}/vendor-artifact.json`, 'vendor manifest path', base);
}

export function vendorArtifactCommand(options: VendorArtifactCommandOptions = {}): string {
  const root = workspaceRoot(options.workspaceRoot);
  const source = sandboxPath(options.sourcePath ?? `${root}/source.bundle`, 'vendor source path', root);
  const work = sandboxPath(options.workPath ?? `${root}/vendor-artifact`, 'vendor work path', root);
  const manifest = manifestPathValue(options.manifestPath, root);
  const payload = sandboxPath(options.payloadPath ?? `${work}/payload.tar`, 'vendor payload path', root);
  const entries = sandboxPath(options.entriesPath ?? `${work}/entries.tsv`, 'vendor entries path', root);
  const maxBytes = options.maxBytes ?? MAX_VENDOR_SOURCE_BYTES;
  const maxEntries = options.maxEntries ?? MAX_VENDOR_ENTRIES;
  if (!Number.isSafeInteger(maxBytes) || maxBytes <= 0 || maxBytes > MAX_VENDOR_SOURCE_BYTES) throw new Error('vendor source limit is invalid');
  if (!Number.isSafeInteger(maxEntries) || maxEntries <= 0 || maxEntries > MAX_VENDOR_ENTRIES) throw new Error('vendor entry limit is invalid');
  if (options.sourceName !== undefined && !/^[A-Za-z0-9][A-Za-z0-9._+%=-]{0,254}$/.test(options.sourceName)) throw new Error('vendor source name hint is invalid');
  const sourceName = options.sourceName ?? '';
  const q = shellQuote;
  return `#!/usr/bin/env bash
set -euo pipefail
source=${q(source)}
source_name=${q(sourceName)}
work=${q(work)}
manifest=${q(manifest)}
payload=${q(payload)}
entries=${q(entries)}
max_bytes=${maxBytes}
max_entries=${maxEntries}
max_expanded=${MAX_VENDOR_EXPANDED_BYTES}
fail() { printf '%s\\n' "$1" >&2; exit 65; }
elf_architecture() {
  local machine
  machine=$(LC_ALL=C readelf -h "$source" | awk -F: '$1 ~ /^[[:space:]]*Machine[[:space:]]*$/ { value=$2; gsub(/^[[:space:]]+|[[:space:]]+$/, "", value); print value; exit }')
  case "$machine" in
    'Advanced Micro Devices X86-64') printf 'x86_64' ;;
    AArch64) printf 'aarch64' ;;
    *) fail 'AppImage ELF architecture is unsupported' ;;
  esac
}
command -v sha256sum >/dev/null 2>&1 || fail 'sha256sum is required'
command -v stat >/dev/null 2>&1 || fail 'stat is required'
command -v timeout >/dev/null 2>&1 || fail 'timeout is required'
test -f "$source" || fail 'vendor source is missing'
source_size=$(stat -c '%s' "$source")
[[ "$source_size" =~ ^[0-9]+$ ]] && (( source_size <= max_bytes )) || fail 'vendor source exceeds the inspection limit'
source_sha256=$(sha256sum "$source" | awk '{print $1}')
[[ "$source_sha256" =~ ^[0-9a-f]{64}$ ]] || fail 'vendor source digest is invalid'
rm -rf "$work"
mkdir -p "$work" "$work/control" "$work/payload-root"
validate_archive_relationships() {
  local list="$1"
  awk -F '\\t' '
  function fail(message) { print message > "/dev/stderr"; exit 65 }
  function non_directory(value) { return value == "file" || value == "symlink" || value == "hardlink" }
  {
    if (NF != 4) fail("vendor archive entry manifest is invalid")
    paths[++count] = $2
    kind[$2] = $1
    target[$2] = $4
  }
  END {
    for (i = 1; i <= count; i++) {
      path = paths[i]
      parent = path
      while (index(parent, "/")) {
        sub(/\\/[^\\/]*$/, "", parent)
        if (non_directory(kind[parent])) fail("vendor archive has a non-directory parent")
      }
      if (kind[path] == "hardlink" && kind[target[path]] != "file") fail("vendor archive hardlink target is missing or not a regular file")
    }
  }
  ' "$list" || fail 'vendor archive relationship validation failed'
}
validate_archive_listing() {
  local archive="$1" list="$2"
  local normalized="$list.normalized"
  timeout 900 bsdtar --numeric-owner -tvf "$archive" | awk -v limit="$max_entries" -v max_path="${MAX_VENDOR_PATH_BYTES}" -v max_expanded="$max_expanded" '
  function fail(message) { print message > "/dev/stderr"; exit 65 }
  function strip_token(value) { sub(/^[^[:space:]]+[[:space:]]+/, "", value); return value }
  function normalized_path(value) { sub(/^\\.\\//, "", value); sub(/\\/$/, "", value); return value }
  function valid_path(value) {
    return value != "" && value != "." && length(value) <= max_path && value !~ /^\\// &&
      value !~ /(^|\\/)\\.\\.($|\\/)/ && value !~ /(^|\\/)\\.($|\\/)/ && value !~ /\\/\\// &&
      value !~ /[[:cntrl:]]/ && index(value, "\\\\") == 0
  }
  function link_inside(path, target, parent, count, i, part, depth, pieces) {
    if (target == "" || length(target) > max_path || target ~ /[[:cntrl:]]/ || index(target, "\\\\") != 0 || target ~ /\\/\\//) return 0
    parent = path
    if (target ~ /^\\//) { if (target ~ /^\\/\\//) return 0; target = substr(target, 2); parent = "" }
    else if (index(parent, "/")) sub(/\\/[^\\/]*$/, "", parent)
    else parent = ""
    count = split(parent "/" target, pieces, "/")
    depth = 0
    for (i = 1; i <= count; i++) {
      part = pieces[i]
      if (part == "" || part == ".") continue
      if (part == "..") { if (depth == 0) return 0; depth--; continue }
      pieces[++depth] = part
    }
    return depth > 0
  }
  {
    mode = substr($0, 1, 1)
    if (mode !~ /^[dlh-]$/) fail("vendor archive contains a link, device or special file")
    if (NF < 8 || $5 !~ /^[0-9]+$/) fail("vendor archive listing is invalid")
    size = $5 + 0
    line = $0
    for (i = 1; i <= 8; i++) line = strip_token(line)
    path = line
    target = ""
    if (mode == "l") { marker = index(path, " -> "); if (!marker) fail("vendor archive symlink listing is invalid"); target = substr(path, marker + 4); path = substr(path, 1, marker - 1) }
    else if (mode == "h") { marker = index(path, " link to "); if (!marker) fail("vendor archive hardlink listing is invalid"); target = normalized_path(substr(path, marker + 9)); path = substr(path, 1, marker - 1) }
    path = normalized_path(path)
    if (path == "" || path == ".") next
    if (!valid_path(path)) fail("vendor archive path is unsafe")
    if (size > max_expanded || total > max_expanded - size) fail("vendor archive exceeds the expansion limit")
    if (seen[path]++) fail("vendor archive contains duplicate entries")
    if (entry_count++ >= limit) fail("vendor archive contains too many entries")
    if (mode == "l" && !link_inside(path, target)) fail("vendor archive symlink target escapes extraction root")
    if (mode == "h" && !valid_path(target)) fail("vendor archive hardlink target is unsafe")
    kind = mode == "d" ? "directory" : mode == "l" ? "symlink" : mode == "h" ? "hardlink" : "file"
    printf "%s\\t%s\\t%s\\t%s\\n", kind, path, size, target
    total += size
  }
  END { if (entry_count == 0) fail("vendor archive is empty") }
  ' > "$normalized" || fail 'vendor archive member validation failed'
  mv "$normalized" "$list"
  validate_archive_relationships "$list"
}
extract_archive() {
  local archive="$1" root="$2" list="$3"
  validate_archive_listing "$archive" "$list"
  rm -rf "$root"
  mkdir -p "$root"
  timeout 900 bsdtar --safe-writes --no-same-owner --no-same-permissions --no-acls --no-xattrs --no-fflags -xf "$archive" -C "$root" || fail 'vendor archive extraction failed'
  validate_tree "$root" "$list"
}
validate_tree() {
  local root="$1" list="$2" actual="$work/$(basename "$list").actual"
  command -v realpath >/dev/null 2>&1 || fail 'realpath is required'
  if ! find "$root" -xdev -type l -print0 | while IFS= read -r -d '' path; do
    target=$(readlink -- "$path") || exit 65
    candidate="$path"
    if [[ "$target" == /* ]]; then candidate="$root$target"; fi
    resolved=$(realpath -m -- "$candidate") || exit 65
    case "$resolved" in "$root"/*) ;; *) exit 65 ;; esac
  done; then fail 'vendor archive symlink resolves outside extraction root'; fi
  find "$root" -xdev -mindepth 1 -printf '%y\\t%P\\t%s\\n' | LC_ALL=C sort > "$actual" || fail 'vendor payload tree listing failed'
  awk -F '\\t' '
  function fail(message) { print message > "/dev/stderr"; exit 65 }
  function expected_type(value) { return value == "directory" ? "d" : value == "symlink" ? "l" : "f" }
  function has_descendant(path, i) { for (i = 1; i <= expected_count; i++) if (index(expected_paths[i], path "/") == 1) return 1; return 0 }
  NR == FNR { expected_paths[++expected_count] = $2; expected_kind[$2] = expected_type($1); expected_size[$2] = $3; expected_archive_kind[$2] = $1; next }
  { actual_kind[$2] = $1; actual_size[$2] = $3 }
  END {
    for (i = 1; i <= expected_count; i++) {
      path = expected_paths[i]
      if (!(path in actual_kind) || actual_kind[path] != expected_kind[path]) fail("vendor extracted tree does not match the verified archive")
      if (expected_kind[path] == "f" && expected_archive_kind[path] == "file" && actual_size[path] != expected_size[path]) fail("vendor extracted file size does not match the verified archive")
    }
    for (path in actual_kind) if (!(path in expected_kind) && (actual_kind[path] != "d" || !has_descendant(path))) fail("vendor extracted tree contains an unverified path")
  }
  ' "$list" "$actual" || fail 'vendor extracted tree validation failed'
  local expanded
  expanded=$(awk -F '\\t' '$1 == "f" { total += $3 } END { printf "%.0f\\n", total + 0 }' "$actual")
  [[ "$expanded" =~ ^[0-9]+$ ]] && (( expanded <= max_expanded )) || fail 'vendor payload exceeds the expansion limit'
}
write_entries() {
  local list="$1"
  cp "$list" "$entries"
}
detected=
header_hex=$(dd if="$source" bs=1 count=8 2>/dev/null | od -An -tx1 | tr -d ' \\n')
app_magic=$(dd if="$source" bs=1 skip=8 count=3 2>/dev/null | od -An -tx1 | tr -d ' \\n')
iso_magic=$(dd if="$source" bs=1 skip=32769 count=5 2>/dev/null | od -An -tx1 | tr -d ' \\n')
head -c ${MAX_VENDOR_HEADER_BYTES} "$source" > "$work/header.sample"
if [[ "$header_hex" == 213c617263683e0a ]]; then detected=deb
elif [[ "$header_hex" == edabeedb* ]]; then detected=rpm
elif [[ "$header_hex" == 7f454c46* && "$app_magic" == 414902 ]]; then detected=appimage2
elif [[ "$header_hex" == 7f454c46* && "$app_magic" == 414901 && "$iso_magic" == 4344303031 ]]; then detected=appimage1
elif [[ "$header_hex" == 2321* ]] && grep -aEq 'Makeself|NVIDIA-Linux|self[- ]extracting' "$work/header.sample"; then detected=run
fi
[[ -n "$detected" ]] || fail 'unsupported vendor binary format'
metadata='{}'
control_path=
control_entries_path=
payload_path=
entries_path=
appimage_offset=null
payload_json=null
entries_json=null
control_json=null
control_entries_json=null
case "$detected" in
  deb)
    command -v ar >/dev/null 2>&1 || fail 'ar is required for Debian packages'
    command -v bsdtar >/dev/null 2>&1 || fail 'bsdtar is required for Debian packages'
    members="$work/deb.members"
    ar t "$source" > "$members" || fail 'Debian archive listing failed'
    debian_binary=$(awk '$0 == "debian-binary" { count++; value=$0 } END { if (count != 1) exit 65; print value }' "$members") || fail 'Debian package header is invalid'
    ar p "$source" "$debian_binary" | tr -d '\\r\\n' | grep -qx '2.0' || fail 'Debian package version is unsupported'
    control_member=$(awk '/^control[.]tar([.]|$)/ { count++; value=$0 } END { if (count != 1) exit 65; print value }' "$members") || fail 'Debian control archive is missing'
    data_member=$(awk '/^data[.]tar([.]|$)/ { count++; value=$0 } END { if (count != 1) exit 65; print value }' "$members") || fail 'Debian data archive is missing'
    ar p "$source" "$control_member" > "$work/control.tar"
    ar p "$source" "$data_member" > "$work/data.tar"
    control_entries="$work/control.entries"
    extract_archive "$work/control.tar" "$work/control" "$control_entries"
    control_file=$(awk -F '\\t' '$2 == "control" || $2 ~ /\\/control$/ { print $2; exit }' "$control_entries")
    [[ -n "$control_file" ]] || fail 'Debian control file is missing'
    bsdtar -xOf "$work/control.tar" "$control_file" > "$work/control.txt"
    field() { awk -F': *' -v key="$1" '$1 == key { sub(/^[^:]*:[[:space:]]*/, "", $0); print; exit }' "$work/control.txt"; }
    package=$(field Package); version=$(field Version); architecture=$(field Architecture)
    [[ "$package" =~ ^[A-Za-z0-9][A-Za-z0-9._+:%~/-]{0,255}$ && "$version" =~ ^[A-Za-z0-9][A-Za-z0-9._+:%~/-]{0,255}$ && "$architecture" =~ ^[A-Za-z0-9][A-Za-z0-9._+:%~/-]{1,63}$ ]] || fail 'Debian control metadata is invalid'
    extract_archive "$work/data.tar" "$work/payload-root" "$work/data.entries"
    write_entries "$work/data.entries"
    tar --sort=name --mtime='UTC 1970-01-01' --owner=0 --group=0 --numeric-owner --format=gnu -cf "$payload" -C "$work/payload-root" .
    metadata=$(printf '{"package":"%s","version":"%s","architecture":"%s"}' "$package" "$version" "$architecture")
    control_path="$work/control.tar"; control_entries_path="$control_entries"; payload_path="$payload"; entries_path="$entries"
    ;;
  rpm)
    command -v bsdtar >/dev/null 2>&1 || fail 'bsdtar is required for RPM packages'
    if command -v rpm >/dev/null 2>&1; then
      mapfile -t rpm_fields < <(rpm -qp --queryformat '%{NAME}\\n%{VERSION}\\n%{RELEASE}\\n%{ARCH}\\n' "$source")
    else
      fail 'rpm is required for RPM metadata inspection'
    fi
    [[ \${#rpm_fields[@]} -eq 4 ]] || fail 'RPM metadata is incomplete'
    package=\${rpm_fields[0]}; version=\${rpm_fields[1]}-\${rpm_fields[2]}; architecture=\${rpm_fields[3]}
    [[ "$package" =~ ^[A-Za-z0-9][A-Za-z0-9._+:%~/-]{0,255}$ && "$version" =~ ^[A-Za-z0-9][A-Za-z0-9._+:%~/-]{0,255}$ && "$architecture" =~ ^[A-Za-z0-9][A-Za-z0-9._+:%~/-]{1,63}$ ]] || fail 'RPM metadata is invalid'
    if command -v rpm2cpio >/dev/null 2>&1; then
      rpm2cpio "$source" | head -c "$((max_expanded + 1))" > "$work/payload.cpio" || fail 'RPM payload exceeds the expansion limit'
      [[ "$(stat -c '%s' "$work/payload.cpio")" -lt "$((max_expanded + 1))" ]] || fail 'RPM payload exceeds the expansion limit'
    elif command -v 7z >/dev/null 2>&1; then
      7z x -so "$source" | head -c "$((max_expanded + 1))" > "$work/payload.cpio" || fail 'RPM payload exceeds the expansion limit'
      [[ "$(stat -c '%s' "$work/payload.cpio")" -lt "$((max_expanded + 1))" ]] || fail 'RPM payload exceeds the expansion limit'
    else
      fail 'rpm2cpio or 7z is required for RPM payload inspection'
    fi
    extract_archive "$work/payload.cpio" "$work/payload-root" "$work/data.entries"
    write_entries "$work/data.entries"
    tar --sort=name --mtime='UTC 1970-01-01' --owner=0 --group=0 --numeric-owner --format=gnu -cf "$payload" -C "$work/payload-root" .
    metadata=$(printf '{"package":"%s","version":"%s","architecture":"%s"}' "$package" "$version" "$architecture")
    payload_path="$payload"; entries_path="$entries"
    ;;
  appimage2)
    command -v readelf >/dev/null 2>&1 || fail 'readelf is required for Type 2 AppImage inspection'
    command -v unsquashfs >/dev/null 2>&1 || fail 'unsquashfs is required for Type 2 AppImage inspection'
    elf_end=$(readelf -SW "$source" | awk '$1 == "[" && $3 != "" && $6 ~ /^[0-9A-Fa-f]+$/ && $7 ~ /^[0-9A-Fa-f]+$/ { end=("0x" $6)+("0x" $7); if (end > max) max=end } END { print max+0 }')
    [[ "$elf_end" =~ ^[0-9]+$ ]] || fail 'Type 2 AppImage ELF layout is invalid'
    offset=$(grep -aobE 'hsqs|sqsh|shsq|qshs' "$source" | awk -F: -v min="$elf_end" -v max="$((elf_end + 16 * 1024 * 1024))" '$1 >= min && $1 <= max && !found { print $1; found=1 }')
    [[ "$offset" =~ ^[0-9]+$ ]] || fail 'Type 2 AppImage SquashFS offset is invalid'
    [[ "$(dd if="$source" bs=1 skip="$offset" count=4 2>/dev/null)" =~ ^(hsqs|sqsh|shsq|qshs)$ ]] || fail 'Type 2 AppImage SquashFS magic is invalid'
    timeout 900 unsquashfs -ll -no-progress -offset "$offset" "$source" | awk -v limit="$max_entries" -v max_path="${MAX_VENDOR_PATH_BYTES}" -v max_expanded="$max_expanded" '
    function fail(message) { print message > "/dev/stderr"; exit 65 }
    function strip_token(value) { sub(/^[^[:space:]]+[[:space:]]+/, "", value); return value }
    function normalized_path(value) { sub(/^squashfs-root\\/?/, "", value); sub(/^\\.\\//, "", value); sub(/\\/$/, "", value); return value }
    function valid_path(value) {
      return value != "" && value != "." && length(value) <= max_path && value !~ /^\\// && value !~ /(^|\\/)\\.\\.($|\\/)/ && value !~ /(^|\\/)\\.($|\\/)/ && value !~ /\\/\\// && value !~ /[[:cntrl:]]/ && index(value, "\\\\") == 0
    }
    function link_inside(path, target, parent, count, i, part, depth, pieces) {
      if (target == "" || length(target) > max_path || target ~ /[[:cntrl:]]/ || index(target, "\\\\") != 0 || target ~ /\\/\\//) return 0
      parent = path; if (target ~ /^\\//) { if (target ~ /^\\/\\//) return 0; target = substr(target, 2); parent = "" } else if (index(parent, "/")) sub(/\\/[^\\/]*$/, "", parent); else parent = ""
      count = split(parent "/" target, pieces, "/"); depth = 0
      for (i = 1; i <= count; i++) { part = pieces[i]; if (part == "" || part == ".") continue; if (part == "..") { if (depth == 0) return 0; depth--; continue } pieces[++depth] = part }
      return depth > 0
    }
    {
      mode = substr($0, 1, 1); if (mode !~ /^[dlh-]$/) fail("AppImage contains a link, device or special file")
      if (NF < 6 || $3 !~ /^[0-9]+$/) fail("Type 2 AppImage listing is invalid")
      size = $3 + 0; line = $0; for (i = 1; i <= 5; i++) line = strip_token(line); path = normalized_path(line); target = ""
      if (mode == "l") { marker = index(path, " -> "); if (!marker) fail("Type 2 AppImage symlink listing is invalid"); target = substr(path, marker + 4); path = substr(path, 1, marker - 1) }
      if (path == "" || path == ".") next
      if (!valid_path(path)) fail("Type 2 AppImage path is unsafe")
      if (size > max_expanded || total > max_expanded - size) fail("Type 2 AppImage exceeds the expansion limit")
      if (seen[path]++) fail("Type 2 AppImage contains duplicate entries")
      if (count++ >= limit) fail("Type 2 AppImage contains too many entries")
      if (mode == "l" && !link_inside(path, target)) fail("Type 2 AppImage symlink target escapes extraction root")
      kind = mode == "d" ? "directory" : mode == "l" ? "symlink" : "file"
      printf "%s\\t%s\\t%s\\t%s\\n", kind, path, size, target; total += size
    }
    END { if (count == 0) fail("Type 2 AppImage is empty") }
    ' > "$work/squash.entries" || fail 'Type 2 AppImage path validation failed'
    validate_archive_relationships "$work/squash.entries"
    timeout 900 unsquashfs -no-progress -no-xattrs -offset "$offset" -d "$work/payload-root" "$source" >/dev/null || fail 'Type 2 AppImage extraction failed'
    test -f "$work/payload-root/AppRun" || fail 'AppImage AppRun entrypoint is missing'
    validate_tree "$work/payload-root" "$work/squash.entries"
    write_entries "$work/squash.entries"
    tar --sort=name --mtime='UTC 1970-01-01' --owner=0 --group=0 --numeric-owner --format=gnu -cf "$payload" -C "$work/payload-root" .
    architecture=$(elf_architecture)
    metadata=$(printf '{"entrypoint":"AppRun","architecture":"%s"}' "$architecture"); payload_path="$payload"; entries_path="$entries"; appimage_offset="$offset"
    ;;
  appimage1)
    command -v readelf >/dev/null 2>&1 || fail 'readelf is required for Type 1 AppImage inspection'
    command -v bsdtar >/dev/null 2>&1 || fail 'bsdtar is required for Type 1 AppImage inspection'
    extract_archive "$source" "$work/payload-root" "$work/iso.entries"
    test -f "$work/payload-root/AppRun" || fail 'AppImage AppRun entrypoint is missing'
    write_entries "$work/iso.entries"
    tar --sort=name --mtime='UTC 1970-01-01' --owner=0 --group=0 --numeric-owner --format=gnu -cf "$payload" -C "$work/payload-root" .
    architecture=$(elf_architecture)
    metadata=$(printf '{"entrypoint":"AppRun","architecture":"%s"}' "$architecture"); payload_path="$payload"; entries_path="$entries"
    ;;
  run)
    header_sha256=$(head -c ${MAX_VENDOR_HEADER_BYTES} "$source" | sha256sum | awk '{print $1}')
    [[ "$header_sha256" =~ ^[0-9a-f]{64}$ ]] || fail 'self-extracting installer header digest is invalid'
    run_architectures=$( {
      head -c ${MAX_VENDOR_HEADER_BYTES} "$source"
    } | grep -aEo 'x86_64|amd64|x86-64|aarch64|arm64' | awk '{
      if ($0 == "x86_64" || $0 == "amd64" || $0 == "x86-64") print "x86_64";
      else print "aarch64";
    }' | sort -u || true )
    run_architecture_count=$(printf '%s\\n' "$run_architectures" | sed '/^$/d' | wc -l)
    [[ "$run_architecture_count" == 1 ]] || fail 'self-extracting installer architecture is unknown or ambiguous'
    run_architecture=$(printf '%s\\n' "$run_architectures")
    if [[ -n "$source_name" ]]; then
      filename_architectures=$(printf '%s\\n' "$source_name" | grep -aEo 'x86_64|amd64|x86-64|aarch64|arm64' | awk '{
        if ($0 == "x86_64" || $0 == "amd64" || $0 == "x86-64") print "x86_64";
        else print "aarch64";
      }' | sort -u || true)
      filename_architecture_count=$(printf '%s\\n' "$filename_architectures" | sed '/^$/d' | wc -l)
      if [[ "$filename_architecture_count" -gt 1 || ( "$filename_architecture_count" == 1 && "$filename_architectures" != "$run_architecture" ) ]]; then
        fail 'self-extracting installer filename architecture disagrees with header'
      fi
    fi
    metadata=$(printf '{"headerSha256":"%s","architecture":"%s"}' "$header_sha256" "$run_architecture")
    ;;
esac
if [[ -n "$payload_path" ]]; then payload_json=$(printf '"%s"' "$payload_path"); fi
if [[ -n "$entries_path" ]]; then entries_json=$(printf '"%s"' "$entries_path"); fi
if [[ -n "$control_path" ]]; then control_json=$(printf '"%s"' "$control_path"); fi
if [[ -n "$control_entries_path" ]]; then control_entries_json=$(printf '"%s"' "$control_entries_path"); fi
printf '{"schemaVersion":1,"format":"%s","surface":"recipe","sourcePath":"%s","sourceSize":%s,"sourceSha256":"%s","payloadPath":%s,"entriesPath":%s,"controlPath":%s,"controlEntriesPath":%s,"appimageOffset":%s,"metadata":%s}\\n' \
  "$detected" "$source" "$source_size" "$source_sha256" \
  "$payload_json" "$entries_json" "$control_json" "$control_entries_json" "$appimage_offset" "$metadata" > "$manifest"
[[ -s "$manifest" ]] || fail 'vendor artifact manifest was not written'
`;
}

export function vendorSurface(redistributionEvidence?: string): VendorArtifactSurface {
  return redistributionEvidence?.trim() ? 'binary' : 'recipe';
}

export function offlineVendorExtractCommand(format: VendorArtifactFormat, options: OfflineVendorExtractOptions): string {
  if (!sha256Pattern.test(options.sha256)) throw new Error('vendor source checksum is invalid');
  const source = shellRecipePath(options.sourcePath ?? '$srcdir/vendor-source', 'vendor source path');
  const destination = shellRecipePath(options.destination ?? '$srcdir/vendor-root', 'vendor destination');
  const checksum = shellQuote(options.sha256);
  const common = `set -eu\nsource=${source}\ndestination=${destination}\nprintf '%s  %s\\n' ${checksum} "$source" | sha256sum -c -\nrm -rf "$destination"`;
  const prepared = format === 'run' ? common : `${common}\nmkdir -p "$destination"`;
  if (format === 'deb') return `${prepared}\ndata_member=$(ar t "$source" | awk '/^data[.]tar([.]|$)/ { print; exit }')\ntest -n "$data_member"\nar p "$source" "$data_member" | bsdtar -xmf - -C "$destination"`;
  if (format === 'rpm') return `${prepared}\nrpm2cpio "$source" | bsdtar -xmf - -C "$destination"`;
  if (format === 'appimage1') return `${prepared}\nbsdtar -xmf "$source" -C "$destination"`;
  if (format === 'appimage2') {
    if (!Number.isSafeInteger(options.appimageOffset) || (options.appimageOffset as number) < 0 || (options.appimageOffset as number) > MAX_VENDOR_SOURCE_BYTES) throw new Error('AppImage filesystem offset is required');
    return `${prepared}\nunsquashfs -no-progress -no-xattrs -offset ${options.appimageOffset} -d "$destination" "$source"`;
  }
  return `${prepared}\nsh "$source" --extract-only --target "$destination"`;
}

export const detectVendorBinary = detectVendorBinaryFormat;
