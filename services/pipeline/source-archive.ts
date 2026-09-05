import {
  resolveArchiveLinkTarget,
  resolveCanonicalArchivePath,
  validateArchivePath,
} from './archive-safety';

export const MAX_SOURCE_ARCHIVE_BYTES = 2 * 1024 * 1024 * 1024;
export const MAX_SOURCE_ARCHIVE_ENTRIES = 20_000;
export const MAX_SOURCE_ARCHIVE_PATH_BYTES = 4_096;
export const MAX_SOURCE_ARCHIVE_EXPANDED_BYTES = 4 * 1024 * 1024 * 1024;
export const MAX_SOURCE_ARCHIVE_MANIFEST_BYTES = 8 * 1024 * 1024;
export const MAX_SOURCE_ARCHIVE_INVENTORY_ENTRIES = 200;
export const SOURCE_ARCHIVE_TIMEOUT_SECONDS = 180;

export type SourceArchiveFormat = 'tar' | 'zip';
export type SourceArchiveEntryKind = 'file' | 'directory' | 'symlink' | 'hardlink';

export interface SourceArchiveEntry {
  path: string;
  kind: SourceArchiveEntryKind;
  size: number;
  target: string | null;
}

export interface SourceArchiveManifest {
  schemaVersion: 1;
  format: SourceArchiveFormat;
  sourcePath: string;
  sourceSize: number;
  sourceSha256: string;
  expandedSize: number;
  entries: SourceArchiveEntry[];
}

export interface SourceArchiveCommandOptions {
  workspaceRoot?: string;
  sourcePath?: string;
  destination?: string;
  entriesPath?: string;
  metadataPath?: string;
  maxBytes?: number;
  maxEntries?: number;
  maxExpandedBytes?: number;
  timeoutSeconds?: number;
}

const SHA256 = /^[0-9a-f]{64}$/;
const formats: readonly SourceArchiveFormat[] = ['tar', 'zip'];
const kinds: readonly SourceArchiveEntryKind[] = ['file', 'directory', 'symlink', 'hardlink'];

function workspaceRoot(value = '/workspace'): string {
  if (typeof value !== 'string' || !value.startsWith('/') || value.length > 512 ||
    !/^[A-Za-z0-9._+@%/-]+$/.test(value) || value.split('/').includes('..') || value.endsWith('/')) {
    throw new Error('source archive workspace root is invalid');
  }
  return value;
}

function sandboxPath(value: string, label: string, root: string): string {
  if (typeof value !== 'string' || !value.startsWith(`${root}/`) || value.length > 512 ||
    !/^[A-Za-z0-9._+@%/-]+$/.test(value) || value.endsWith('/') || value.includes('//') || value.split('/').includes('..')) {
    throw new Error(`${label} must be an absolute workspace path`);
  }
  return value;
}

function shellQuote(value: string): string {
  return `'${value.replaceAll("'", "'\\''")}'`;
}

function assertLimit(value: number, maximum: number, label: string): number {
  if (!Number.isSafeInteger(value) || value <= 0 || value > maximum) throw new Error(`${label} is invalid`);
  return value;
}

function normalizePath(value: string): string {
  return validateArchivePath(value.replace(/\/$/, ''));
}

function normalizeHardlinkTarget(target: string): string {
  return normalizePath(target);
}

export function validateSourceArchiveEntries(
  rawEntries: readonly SourceArchiveEntry[],
  limits: Pick<SourceArchiveCommandOptions, 'maxEntries' | 'maxExpandedBytes'> = {},
): SourceArchiveEntry[] {
  const maxEntries = limits.maxEntries ?? MAX_SOURCE_ARCHIVE_ENTRIES;
  const maxExpandedBytes = limits.maxExpandedBytes ?? MAX_SOURCE_ARCHIVE_EXPANDED_BYTES;
  assertLimit(maxEntries, MAX_SOURCE_ARCHIVE_ENTRIES, 'source archive entry limit');
  assertLimit(maxExpandedBytes, MAX_SOURCE_ARCHIVE_EXPANDED_BYTES, 'source archive expansion limit');
  if (rawEntries.length === 0) throw new Error('source archive is empty');
  if (rawEntries.length > maxEntries) throw new Error('source archive contains too many entries');

  const entries = rawEntries.map((entry) => {
    if (!entry || !kinds.includes(entry.kind) || !Number.isSafeInteger(entry.size) || entry.size < 0 || entry.size > maxExpandedBytes) {
      throw new Error('source archive entry is invalid');
    }
    const path = normalizePath(entry.path);
    let target: string | null = null;
    if (entry.kind === 'symlink') {
      target = entry.target;
      resolveArchiveLinkTarget(path, target ?? '', MAX_SOURCE_ARCHIVE_PATH_BYTES);
    } else if (entry.kind === 'hardlink') {
      target = normalizeHardlinkTarget(entry.target ?? '');
    } else if (entry.target !== null && entry.target !== undefined && entry.target !== '') {
      throw new Error('source archive regular entry has a link target');
    }
    return { path, kind: entry.kind, size: entry.size, target };
  });

  const byPath = new Map(entries.map((entry) => [entry.path, entry]));
  if (byPath.size !== entries.length) throw new Error('source archive contains duplicate entries');
  let expandedSize = 0;
  for (const entry of entries) {
    if (expandedSize > maxExpandedBytes - entry.size) throw new Error('source archive exceeds the expansion limit');
    expandedSize += entry.size;
    let parent = entry.path;
    while (parent.includes('/')) {
      parent = parent.slice(0, parent.lastIndexOf('/'));
      const parentEntry = byPath.get(parent);
      if (parentEntry && parentEntry.kind !== 'directory') throw new Error('source archive has a non-directory parent');
    }
    if (entry.kind === 'hardlink') {
      const target = byPath.get(entry.target ?? '');
      if (!target || target.kind !== 'file') {
        throw new Error('source archive hardlink target is missing or not a regular file');
      }
    }
  }
  for (const entry of entries) {
    if (entry.kind === 'symlink') {
      const parent = entry.path.includes('/') ? entry.path.slice(0, entry.path.lastIndexOf('/')) : '';
      resolveCanonicalArchivePath(parent, entry.target ?? '', byPath);
    }
  }
  return entries;
}

function parseMetadata(raw: string): Map<string, string> {
  if (typeof raw !== 'string' || raw.length > 32 * 1024) throw new Error('source archive metadata is too large');
  const values = new Map<string, string>();
  for (const line of raw.split('\n')) {
    if (!line) continue;
    const separator = line.indexOf('=');
    if (separator <= 0) throw new Error('source archive metadata is invalid');
    const key = line.slice(0, separator);
    const value = line.slice(separator + 1);
    if (!/^[A-Za-z][A-Za-z0-9_]{0,63}$/.test(key) || /[\u0000\r\n\t]/.test(value) || values.has(key)) {
      throw new Error('source archive metadata is invalid');
    }
    values.set(key, value);
  }
  return values;
}

function metadataInteger(values: Map<string, string>, key: string, maximum: number): number {
  const value = values.get(key) ?? '';
  if (!/^\d+$/.test(value)) throw new Error(`source archive ${key} is invalid`);
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 0 || parsed > maximum) throw new Error(`source archive ${key} is invalid`);
  return parsed;
}

export function parseSourceArchiveManifest(
  metadataRaw: string,
  entriesRaw: string,
  root = '/workspace',
): SourceArchiveManifest {
  const base = workspaceRoot(root);
  if (typeof entriesRaw !== 'string' || entriesRaw.length > MAX_SOURCE_ARCHIVE_MANIFEST_BYTES) {
    throw new Error('source archive entry manifest is too large');
  }
  const values = parseMetadata(metadataRaw);
  if (values.get('schemaVersion') !== '1' || !formats.includes(values.get('format') as SourceArchiveFormat)) {
    throw new Error('source archive metadata version or format is invalid');
  }
  const sourcePath = sandboxPath(values.get('sourcePath') ?? '', 'source archive path', base);
  const sourceSize = metadataInteger(values, 'sourceSize', MAX_SOURCE_ARCHIVE_BYTES);
  const expandedSize = metadataInteger(values, 'expandedSize', MAX_SOURCE_ARCHIVE_EXPANDED_BYTES);
  const sourceSha256 = values.get('sourceSha256') ?? '';
  if (!SHA256.test(sourceSha256)) throw new Error('source archive digest is invalid');
  const entries: SourceArchiveEntry[] = [];
  for (const line of entriesRaw.split('\n')) {
    if (!line) continue;
    const fields = line.split('\t');
    if (fields.length !== 4 || !/^(?:file|directory|symlink|hardlink)$/.test(fields[0] ?? '') || !/^\d+$/.test(fields[2] ?? '')) {
      throw new Error('source archive entry manifest is invalid');
    }
    entries.push({
      kind: fields[0] as SourceArchiveEntryKind,
      path: fields[1] ?? '',
      size: Number(fields[2]),
      target: fields[3] || null,
    });
  }
  const validated = validateSourceArchiveEntries(entries);
  const calculatedSize = validated.reduce((total, entry) => total + entry.size, 0);
  if (calculatedSize !== expandedSize) throw new Error('source archive expansion total does not match metadata');
  return {
    schemaVersion: 1,
    format: values.get('format') as SourceArchiveFormat,
    sourcePath,
    sourceSize,
    sourceSha256,
    expandedSize,
    entries: validated,
  };
}

export function sourceArchivePaths(manifest: SourceArchiveManifest): string[] {
  return manifest.entries.map((entry) => entry.path);
}

export function sourceArchiveReadablePaths(manifest: SourceArchiveManifest): string[] {
  return manifest.entries.filter((entry) => entry.kind !== 'directory').map((entry) => entry.path);
}

function inventoryPriority(path: string): number {
  const basename = path.slice(path.lastIndexOf('/') + 1);
  if (/^(?:PKGBUILD|Makefile|GNUmakefile|CMakeLists\.txt|meson\.build|configure|go\.mod|Cargo\.toml|package\.json)$/i.test(basename)) return 0;
  if (/^(?:license|copying|notice|readme)(?:[._ -].*)?$/i.test(basename)) return 1;
  return path.includes('/') ? 3 : 2;
}

export function sourceArchiveInventory(
  manifest: SourceArchiveManifest,
  limit = MAX_SOURCE_ARCHIVE_INVENTORY_ENTRIES,
): string[] {
  if (!Number.isSafeInteger(limit) || limit <= 0 || limit > MAX_SOURCE_ARCHIVE_INVENTORY_ENTRIES) {
    throw new Error('source archive inventory limit is invalid');
  }
  return sourceArchiveReadablePaths(manifest)
    .sort((left, right) => inventoryPriority(left) - inventoryPriority(right) || left.localeCompare(right))
    .slice(0, limit);
}

export function assertSourceArchiveReadPaths(
  manifest: SourceArchiveManifest,
  rawPaths: readonly string[],
): string[] {
  const paths = [...new Set(rawPaths.map(normalizePath))];
  const allowed = new Set(sourceArchiveReadablePaths(manifest));
  if (paths.some((path) => !allowed.has(path))) throw new Error('source file was not listed by archive inspection');
  return paths;
}

export function sourceArchiveManifestSizeCheckCommand(options: SourceArchiveCommandOptions = {}): string {
  const root = workspaceRoot(options.workspaceRoot);
  const entries = sandboxPath(options.entriesPath ?? `${root}/source-archive.entries`, 'source archive entries path', root);
  const metadata = sandboxPath(options.metadataPath ?? `${root}/source-archive.meta`, 'source archive metadata path', root);
  const q = shellQuote;
  return String.raw`#!/usr/bin/env bash
set -eu
for path in ${q(entries)} ${q(metadata)}; do
  test -f "$path"
  size=$(stat -c '%s' "$path")
  [[ "$size" =~ ^[0-9]+$ ]] && (( size <= ${MAX_SOURCE_ARCHIVE_MANIFEST_BYTES} )) || exit 65
done
`;
}

function sourceArchiveScript(options: SourceArchiveCommandOptions, materialize: boolean): string {
  const root = workspaceRoot(options.workspaceRoot);
  const source = sandboxPath(options.sourcePath ?? `${root}/source.bundle`, 'source archive path', root);
  const destination = sandboxPath(options.destination ?? `${root}/source`, 'source archive destination', root);
  const entries = sandboxPath(options.entriesPath ?? `${root}/source-archive.entries`, 'source archive entries path', root);
  const metadata = sandboxPath(options.metadataPath ?? `${root}/source-archive.meta`, 'source archive metadata path', root);
  if (new Set([source, destination, entries, metadata]).size !== 4) throw new Error('source archive paths must be distinct');
  const maxBytes = assertLimit(options.maxBytes ?? MAX_SOURCE_ARCHIVE_BYTES, MAX_SOURCE_ARCHIVE_BYTES, 'source archive size limit');
  const maxEntries = assertLimit(options.maxEntries ?? MAX_SOURCE_ARCHIVE_ENTRIES, MAX_SOURCE_ARCHIVE_ENTRIES, 'source archive entry limit');
  const maxExpandedBytes = assertLimit(options.maxExpandedBytes ?? MAX_SOURCE_ARCHIVE_EXPANDED_BYTES, MAX_SOURCE_ARCHIVE_EXPANDED_BYTES, 'source archive expansion limit');
  const timeoutSeconds = assertLimit(options.timeoutSeconds ?? SOURCE_ARCHIVE_TIMEOUT_SECONDS, 900, 'source archive timeout');
  const q = shellQuote;
  const actual = `${root}/.source-archive.actual`;
  const entriesTmp = `${entries}.tmp`;
  const archiveScript = String.raw`
awk -v max_entries=${maxEntries} -v max_path=${MAX_SOURCE_ARCHIVE_PATH_BYTES} -v max_expanded=${maxExpandedBytes} '
function fail(message) { print message > "/dev/stderr"; exit 65 }
function strip_token(value) { sub(/^[^[:space:]]+[[:space:]]+/, "", value); return value }
function normalized(value) { sub(/^\.\//, "", value); sub(/\/$/, "", value); return value }
function valid_path(value) {
  return value != "" && value != "." && length(value) <= max_path && value !~ /^\// &&
    value !~ /(^|\/)\.\.($|\/)/ && value !~ /(^|\/)\.($|\/)/ && value !~ /\/\// &&
    value !~ /[[:cntrl:]]/ && index(value, "\\") == 0
}
function link_inside(path, target, parent, count, i, part, depth, pieces) {
  if (target == "" || length(target) > max_path || target ~ /^\// || target ~ /[[:cntrl:]]/ || index(target, "\\") != 0 || target ~ /\/\//) return 0
  parent = path
  if (index(parent, "/")) sub(/\/[^\/]*$/, "", parent)
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
  if (mode !~ /^[dlh-]$/) fail("source archive contains a link, device or special file")
  if (NF < 8 || $5 !~ /^[0-9]+$/) fail("source archive listing is invalid")
  size = $5 + 0
  line = $0
  for (i = 1; i <= 8; i++) line = strip_token(line)
  path = line
  target = ""
  if (mode == "l") { marker = index(path, " -> "); if (!marker) fail("source archive symlink listing is invalid"); target = substr(path, marker + 4); path = substr(path, 1, marker - 1) }
  else if (mode == "h") { marker = index(path, " link to "); if (!marker) fail("source archive hardlink listing is invalid"); target = normalized(substr(path, marker + 9)); path = substr(path, 1, marker - 1) }
  path = normalized(path)
  if (path == "" || path == ".") next
  if (!valid_path(path)) fail("source archive path is unsafe")
  if (size > max_expanded || total > max_expanded - size) fail("source archive exceeds the expansion limit")
  if (seen[path]++) fail("source archive contains duplicate entries")
  if (count++ >= max_entries) fail("source archive contains too many entries")
  if (mode == "l" && !link_inside(path, target)) fail("source archive symlink target escapes extraction root")
  if (mode == "h" && !valid_path(target)) fail("source archive hardlink target is unsafe")
  kind = mode == "d" ? "directory" : mode == "l" ? "symlink" : mode == "h" ? "hardlink" : "file"
  printf "%s\t%s\t%s\t%s\n", kind, path, size, target
  total += size
}
END { if (count == 0) fail("source archive is empty") }
'
`;
  const relationshipScript = String.raw`
awk -F '\t' '
function fail(message) { print message > "/dev/stderr"; exit 65 }
function non_directory(value) { return value == "file" || value == "symlink" || value == "hardlink" }
{
  if (NF != 4) fail("source archive entry manifest is invalid")
  paths[++count] = $2
  kind[$2] = $1
  target[$2] = $4
}
END {
  for (i = 1; i <= count; i++) {
    path = paths[i]
    parent = path
    while (index(parent, "/")) {
      sub(/\/[^\/]*$/, "", parent)
      if (non_directory(kind[parent])) fail("source archive has a non-directory parent")
    }
    if (kind[path] == "hardlink" && kind[target[path]] != "file") fail("source archive hardlink target is missing or not a regular file")
  }
}
'
`;
const extraction = materialize ? String.raw`
rm -rf ${q(destination)}
mkdir -p ${q(destination)}
command -v realpath >/dev/null 2>&1 || fail 'realpath is required'
timeout --signal=KILL ${timeoutSeconds} bsdtar --safe-writes --no-same-owner --no-same-permissions --no-acls --no-xattrs --no-fflags -xf ${q(source)} -C ${q(destination)} || fail 'source archive extraction failed'
if ! find ${q(destination)} -xdev -type l -print0 | while IFS= read -r -d '' path; do
  resolved=$(realpath -m -- "$path") || exit 65
  case "$resolved" in "$destination"/*) ;; *) exit 65 ;; esac
done; then fail 'source archive symlink resolves outside extraction root'; fi
find ${q(destination)} -xdev -mindepth 1 -printf '%y\t%P\t%s\n' | LC_ALL=C sort > ${q(actual)} || fail 'source archive tree listing failed'
awk -F '\t' '
function fail(message) { print message > "/dev/stderr"; exit 65 }
function expected_type(value) { return value == "directory" ? "d" : value == "symlink" ? "l" : "f" }
function has_descendant(path, i) { for (i = 1; i <= expected_count; i++) if (index(expected_paths[i], path "/") == 1) return 1; return 0 }
NR == FNR { expected_paths[++expected_count] = $2; expected_kind[$2] = expected_type($1); expected_size[$2] = $3; expected_archive_kind[$2] = $1; next }
{ actual_kind[$2] = $1; actual_size[$2] = $3 }
END {
  for (i = 1; i <= expected_count; i++) {
    path = expected_paths[i]
    if (!(path in actual_kind) || actual_kind[path] != expected_kind[path]) fail("extracted tree does not match the verified archive")
    if (expected_kind[path] == "f" && expected_archive_kind[path] == "file" && actual_size[path] != expected_size[path]) fail("extracted file size does not match the verified archive")
  }
  for (path in actual_kind) if (!(path in expected_kind) && (actual_kind[path] != "d" || !has_descendant(path))) fail("extracted tree contains an unverified path")
}
' ${q(entries)} ${q(actual)} || fail 'extracted tree validation failed'
expanded_size=$(awk -F '\t' '$1 == "f" { total += $3 } END { printf "%.0f\n", total + 0 }' ${q(actual)})
[[ "$expanded_size" =~ ^[0-9]+$ ]] && (( expanded_size <= max_expanded )) || fail 'extracted tree exceeds the expansion limit'
` : '';
  return String.raw`#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C
source=${q(source)}
destination=${q(destination)}
entries=${q(entries)}
metadata=${q(metadata)}
actual=${q(actual)}
max_bytes=${maxBytes}
max_expanded=${maxExpandedBytes}
fail() { printf '%s\n' "$1" >&2; exit 65; }
command -v bsdtar >/dev/null 2>&1 || fail 'bsdtar is required'
command -v timeout >/dev/null 2>&1 || fail 'timeout is required'
test -f "$source" || fail 'source archive is missing'
source_size=$(stat -c '%s' "$source")
[[ "$source_size" =~ ^[0-9]+$ ]] && (( source_size <= max_bytes )) || fail 'source archive exceeds the size limit'
source_sha256=$(timeout --signal=KILL ${timeoutSeconds} sha256sum "$source" | awk '{print $1}')
[[ "$source_sha256" =~ ^[0-9a-f]{64}$ ]] || fail 'source archive digest is invalid'
magic=$(head -c 6 "$source" | od -An -tx1 | tr -d ' \n')
case "$magic" in
  504b0304*|504b0506*|504b0708*) format=zip ;;
  1f8b*|425a68*|fd377a585a00*|28b52ffd*|04224d18*|5d000080*|1f9d*|4c5a4950*) format=tar ;;
  *) tar_magic=$(dd if="$source" bs=1 skip=257 count=5 2>/dev/null | od -An -tx1 | tr -d ' \n'); [[ "$tar_magic" == 7573746172 ]] || fail 'source is not a tar or zip archive'; format=tar ;;
esac
rm -f "$entries" "$metadata" ${q(entriesTmp)} "$actual"
timeout --signal=KILL ${timeoutSeconds} bsdtar -tf "$source" >/dev/null || fail 'source archive listing failed'
if ! timeout --signal=KILL ${timeoutSeconds} bsdtar --numeric-owner -tvf "$source" | ${archiveScript.trim()} > ${q(entriesTmp)}; then fail 'source archive member validation failed'; fi
mv ${q(entriesTmp)} "$entries"
${relationshipScript.trim()} "$entries" || fail 'source archive relationship validation failed'
expanded_size=$(awk -F '\t' '{ total += $3 } END { printf "%.0f\n", total + 0 }' "$entries")
[[ "$expanded_size" =~ ^[0-9]+$ ]] && (( expanded_size <= max_expanded )) || fail 'source archive exceeds the expansion limit'
printf 'schemaVersion=1\nformat=%s\nsourcePath=%s\nsourceSize=%s\nsourceSha256=%s\nexpandedSize=%s\n' "$format" "$source" "$source_size" "$source_sha256" "$expanded_size" > "$metadata"
${extraction}`;
}

export function inspectSourceArchiveCommand(options: SourceArchiveCommandOptions = {}): string {
  return sourceArchiveScript(options, false);
}

export function materializeSourceArchiveCommand(options: SourceArchiveCommandOptions = {}): string {
  return sourceArchiveScript(options, true);
}
