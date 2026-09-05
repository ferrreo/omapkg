import {
  MAX_SOURCE_ARCHIVE_ENTRIES,
  MAX_SOURCE_ARCHIVE_EXPANDED_BYTES,
  MAX_SOURCE_ARCHIVE_MANIFEST_BYTES,
  MAX_SOURCE_ARCHIVE_PATH_BYTES,
} from './source-archive';
import { resolveArchiveLinkTarget, resolveCanonicalArchivePath, validateArchivePath } from './archive-safety';

export const MAX_GIT_SOURCE_ENTRIES = MAX_SOURCE_ARCHIVE_ENTRIES;
export const MAX_GIT_SOURCE_PATH_BYTES = MAX_SOURCE_ARCHIVE_PATH_BYTES;
export const MAX_GIT_SOURCE_EXPANDED_BYTES = MAX_SOURCE_ARCHIVE_EXPANDED_BYTES;
export const MAX_GIT_SYMLINK_BYTES = MAX_SOURCE_ARCHIVE_PATH_BYTES;
export const MAX_GIT_ATTRIBUTES_BYTES = 1 * 1024 * 1024;
export const MAX_GIT_SOURCE_INVENTORY_ENTRIES = 200;
export const GIT_SOURCE_POLICY_TIMEOUT_SECONDS = 180;

export type GitSourceEntryKind = 'file' | 'symlink';

export interface GitSourceTreeEntry {
  path: string;
  kind: GitSourceEntryKind;
  size: number;
  target: string | null;
  objectId?: string;
  mode?: string;
  type?: string;
}

export interface GitSourcePolicyOptions {
  workspaceRoot?: string;
  sourcePath?: string;
  entriesPath?: string;
  metadataPath?: string;
  maxEntries?: number;
  maxExpandedBytes?: number;
  timeoutSeconds?: number;
}

const SHA = /^[0-9a-f]{40}(?:[0-9a-f]{24})?$/;
const entryKinds: readonly GitSourceEntryKind[] = ['file', 'symlink'];

function workspaceRoot(value = '/workspace'): string {
  if (typeof value !== 'string' || !value.startsWith('/') || value.length > 512 ||
    !/^[A-Za-z0-9._+@%/-]+$/.test(value) || value.split('/').includes('..') || value.endsWith('/')) {
    throw new Error('Git source workspace root is invalid');
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

function normalizePath(value: string): string {
  return validateArchivePath(value);
}

function isGitMetadataPath(path: string): boolean {
  return path === '.gitmodules' || path.endsWith('/.gitmodules') || path.split('/').includes('.git');
}

export function validateGitSourceEntries(
  rawEntries: readonly GitSourceTreeEntry[],
  limits: Pick<GitSourcePolicyOptions, 'maxEntries' | 'maxExpandedBytes'> = {},
): GitSourceTreeEntry[] {
  const maxEntries = limits.maxEntries ?? MAX_GIT_SOURCE_ENTRIES;
  const maxExpandedBytes = limits.maxExpandedBytes ?? MAX_GIT_SOURCE_EXPANDED_BYTES;
  if (!Number.isSafeInteger(maxEntries) || maxEntries <= 0 || maxEntries > MAX_GIT_SOURCE_ENTRIES) throw new Error('Git source entry limit is invalid');
  if (!Number.isSafeInteger(maxExpandedBytes) || maxExpandedBytes <= 0 || maxExpandedBytes > MAX_GIT_SOURCE_EXPANDED_BYTES) throw new Error('Git source expansion limit is invalid');
  if (rawEntries.length === 0) throw new Error('Git source tree is empty');
  if (rawEntries.length > maxEntries) throw new Error('Git source tree contains too many entries');

  const entries = rawEntries.map((entry) => {
    if (!entry || !entryKinds.includes(entry.kind) || !Number.isSafeInteger(entry.size) || entry.size < 0 || entry.size > maxExpandedBytes) {
      throw new Error('Git source tree entry is invalid');
    }
    if (entry.type === 'commit' || entry.mode === '160000') throw new Error('Git source submodules are unsupported');
    if (entry.type !== undefined && entry.type !== 'blob') throw new Error('Git source tree entry type is unsupported');
    const path = normalizePath(entry.path);
    if (isGitMetadataPath(path)) throw new Error('Git source metadata paths are unsupported');
    let target: string | null = null;
    if (entry.kind === 'symlink') {
      target = entry.target;
      resolveArchiveLinkTarget(path, target ?? '', MAX_GIT_SYMLINK_BYTES);
    } else if (entry.target !== null && entry.target !== undefined && entry.target !== '') {
      throw new Error('Git source regular entry has a symlink target');
    }
    if (entry.objectId !== undefined && !SHA.test(entry.objectId)) throw new Error('Git source object ID is invalid');
    return { ...entry, path, target };
  });
  const byPath = new Map(entries.map((entry) => [entry.path, entry]));
  if (byPath.size !== entries.length) throw new Error('Git source tree contains duplicate entries');
  let expandedSize = 0;
  for (const entry of entries) {
    if (expandedSize > maxExpandedBytes - entry.size) throw new Error('Git source tree exceeds the expansion limit');
    expandedSize += entry.size;
    let parent = entry.path;
    while (parent.includes('/')) {
      parent = parent.slice(0, parent.lastIndexOf('/'));
      if (byPath.has(parent)) throw new Error('Git source tree has a non-directory parent');
    }
  }
  for (const entry of entries) {
    if (entry.kind === 'symlink') {
      const parent = entry.path.includes('/') ? entry.path.slice(0, entry.path.lastIndexOf('/')) : '';
      resolveCanonicalArchivePath(parent, entry.target ?? '', byPath, () => false, (entry) => entry.kind === 'symlink');
    }
  }
  return entries;
}

export function parseGitSourceEntries(raw: string): GitSourceTreeEntry[] {
  if (typeof raw !== 'string' || raw.length > MAX_SOURCE_ARCHIVE_MANIFEST_BYTES) throw new Error('Git source entry manifest is too large');
  const entries: GitSourceTreeEntry[] = [];
  for (const line of raw.split('\n')) {
    if (!line) continue;
    const fields = line.split('\t');
    if ((fields.length !== 4 && fields.length !== 5) || !entryKinds.includes(fields[0] as GitSourceEntryKind) || !/^\d+$/.test(fields[2] ?? '')) {
      throw new Error('Git source entry manifest is invalid');
    }
    entries.push({
      kind: fields[0] as GitSourceEntryKind,
      path: fields[1] ?? '',
      size: Number(fields[2]),
      target: fields[3] && fields[3] !== '-' ? fields[3] : null,
      objectId: fields[4] || undefined,
      type: 'blob',
    });
  }
  return validateGitSourceEntries(entries);
}

function inventoryPriority(path: string): number {
  const basename = path.slice(path.lastIndexOf('/') + 1);
  if (/^(?:PKGBUILD|Makefile|GNUmakefile|CMakeLists\.txt|meson\.build|configure|go\.mod|Cargo\.toml|package\.json)$/i.test(basename)) return 0;
  if (/^(?:license|copying|notice|readme)(?:[._ -].*)?$/i.test(basename)) return 1;
  return path.includes('/') ? 3 : 2;
}

export function gitSourceInventory(
  entries: readonly GitSourceTreeEntry[],
  limit = MAX_GIT_SOURCE_INVENTORY_ENTRIES,
): string[] {
  if (!Number.isSafeInteger(limit) || limit <= 0 || limit > MAX_GIT_SOURCE_INVENTORY_ENTRIES) {
    throw new Error('Git source inventory limit is invalid');
  }
  return validateGitSourceEntries(entries)
    .map((entry) => entry.path)
    .sort((left, right) => inventoryPriority(left) - inventoryPriority(right) || left.localeCompare(right))
    .slice(0, limit);
}

export function gitSourcePolicyCommand(options: GitSourcePolicyOptions = {}): string {
  const root = workspaceRoot(options.workspaceRoot);
  const source = sandboxPath(options.sourcePath ?? `${root}/source`, 'Git source path', root);
  const entries = sandboxPath(options.entriesPath ?? `${root}/git-source.entries`, 'Git source entries path', root);
  const metadata = sandboxPath(options.metadataPath ?? `${root}/git-source.meta`, 'Git source metadata path', root);
  const scratch = `${entries}.scratch`;
  if (new Set([source, entries, metadata, scratch]).size !== 4) throw new Error('Git source paths must be distinct');
  const maxEntries = options.maxEntries ?? MAX_GIT_SOURCE_ENTRIES;
  const maxExpandedBytes = options.maxExpandedBytes ?? MAX_GIT_SOURCE_EXPANDED_BYTES;
  const timeoutSeconds = options.timeoutSeconds ?? GIT_SOURCE_POLICY_TIMEOUT_SECONDS;
  if (!Number.isSafeInteger(maxEntries) || maxEntries <= 0 || maxEntries > MAX_GIT_SOURCE_ENTRIES) throw new Error('Git source entry limit is invalid');
  if (!Number.isSafeInteger(maxExpandedBytes) || maxExpandedBytes <= 0 || maxExpandedBytes > MAX_GIT_SOURCE_EXPANDED_BYTES) throw new Error('Git source expansion limit is invalid');
  if (!Number.isSafeInteger(timeoutSeconds) || timeoutSeconds <= 0 || timeoutSeconds > 900) throw new Error('Git source timeout is invalid');
  const q = shellQuote;
  const entriesTmp = `${entries}.tmp`;
  const rawEntries = `${entries}.raw`;
  const listingScript = String.raw`
awk -v max_entries=${maxEntries} -v max_path=${MAX_GIT_SOURCE_PATH_BYTES} -v max_expanded=${maxExpandedBytes} '
BEGIN { RS = "\0" }
function fail(message) { print message > "/dev/stderr"; exit 65 }
function valid_path(value) {
  return value != "" && value != "." && length(value) <= max_path && value !~ /^\// &&
    value !~ /(^|\/)\.\.($|\/)/ && value !~ /(^|\/)\.($|\/)/ && value !~ /\/\// &&
    value !~ /[[:cntrl:]]/ && index(value, "\\") == 0 && value !~ /(^|\/)\.git($|\/)/
}
{
  tab = index($0, "\t")
  if (!tab) fail("Git source tree listing is invalid")
  header = substr($0, 1, tab - 1)
  path = substr($0, tab + 1)
  field_count = split(header, fields, /[[:space:]]+/)
  if (field_count < 4) fail("Git source tree listing is invalid")
  mode = fields[1]
  type = fields[2]
  object = fields[3]
  size = fields[4]
  if (mode == "160000" || type == "commit") fail("Git source submodules are unsupported")
  if (type != "blob" || (mode != "100644" && mode != "100755" && mode != "120000")) fail("Git source tree entry type is unsupported")
  if (object !~ /^[0-9a-f][0-9a-f]*$/ || (length(object) != 40 && length(object) != 64) || size !~ /^[0-9][0-9]*$/) fail("Git source tree listing is invalid")
  if (!valid_path(path) || path == ".gitmodules" || path ~ /\/\.gitmodules$/) fail("Git source metadata path is unsupported")
  if (mode == "120000" && size > ${MAX_GIT_SYMLINK_BYTES}) fail("Git source symlink is too large")
  if (size > max_expanded || total > max_expanded - size) fail("Git source tree exceeds the expansion limit")
  if (seen[path]++) fail("Git source tree contains duplicate entries")
  if (entry_count++ >= max_entries) fail("Git source tree contains too many entries")
  kind = mode == "120000" ? "symlink" : "file"
  printf "%s\t%s\t%s\t-\t%s\n", kind, path, size, object
  total += size
}
END { if (entry_count == 0) fail("Git source tree is empty") }
'
`;
  return String.raw`#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C
export GIT_CONFIG_NOSYSTEM=1
export GIT_CONFIG_GLOBAL=/dev/null
source=${q(source)}
entries=${q(entries)}
rawEntries=${q(rawEntries)}
metadata=${q(metadata)}
scratch=${q(scratch)}
max_expanded=${maxExpandedBytes}
fail() { printf '%s\n' "$1" >&2; exit 65; }
command -v git >/dev/null 2>&1 || fail 'git is required'
command -v realpath >/dev/null 2>&1 || fail 'realpath is required'
command -v timeout >/dev/null 2>&1 || fail 'timeout is required'
test -d "$source/.git" || fail 'Git source checkout is missing'
git -C "$source" rev-parse --is-inside-work-tree | grep -qx true || fail 'Git source checkout is invalid'
hooks=$(git -C "$source" config --local --get core.hooksPath || true)
[[ -z "$hooks" || "$hooks" == '/dev/null' ]] || fail 'Git hooks are not permitted'
if git -C "$source" config --local --get-regexp '^submodule\.' >/dev/null 2>&1; then fail 'Git submodules are not permitted'; fi
rm -f "$entries" "$metadata" ${q(entriesTmp)} ${q(rawEntries)} "$scratch"
if ! timeout --signal=KILL ${timeoutSeconds} git -C "$source" -c core.hooksPath=/dev/null -c protocol.file.allow=never -c submodule.recurse=false ls-tree --full-tree -r -l -z HEAD | ${listingScript.trim()} > ${q(entriesTmp)}; then fail 'Git source tree policy validation failed'; fi
mv ${q(entriesTmp)} ${q(rawEntries)}
: > ${q(entriesTmp)}
while IFS=$'\t' read -r kind path size target object; do
  [[ -n "$path" && "$size" =~ ^[0-9]+$ && "$object" =~ ^[0-9a-f]{40}([0-9a-f]{24})?$ ]] || fail 'Git source entry manifest is invalid'
  if [[ "$kind" == 'symlink' ]]; then
    (( size <= ${MAX_GIT_SYMLINK_BYTES} )) || fail 'Git source symlink is too large'
    timeout --signal=KILL ${timeoutSeconds} git -C "$source" cat-file blob "$object" > "$scratch" || fail 'Git symlink blob could not be read'
    [[ "$(wc -c < "$scratch")" == "$size" ]] || fail 'Git symlink size changed during inspection'
    if LC_ALL=C grep -aEq '[[:cntrl:]]' "$scratch"; then fail 'Git symlink target contains control characters'; fi
    target=$(<"$scratch")
    [[ -n "$target" && "$target" != /* && "$target" != *'//' && "$target" != *'\'* && "$target" != *$'\t'* && "$target" != *$'\n'* ]] || fail 'Git symlink target is unsafe'
    resolved=$(realpath -m -- "$source/$path") || fail 'Git symlink could not be resolved'
    case "$resolved" in "$source"/*) ;; *) fail 'Git symlink resolves outside checkout' ;; esac
    case "$resolved" in "$source/.git"|"$source/.git/"*) fail 'Git symlink resolves into repository metadata' ;; esac
    printf 'symlink\t%s\t%s\t%s\t%s\n' "$path" "$size" "$target" "$object" >> ${q(entriesTmp)}
  else
    git -C "$source" cat-file -e "$object^{blob}" || fail 'Git source object is missing'
    set +e
    set +o pipefail
    timeout --signal=KILL ${timeoutSeconds} git -C "$source" cat-file blob "$object" | head -c 256 > "$scratch"
    git_status=$PIPESTATUS
    set -o pipefail
    set -e
    [[ "$git_status" == 0 || "$git_status" == 141 ]] || fail 'Git source blob inspection timed out or failed'
    if grep -aEq '^version https://git-lfs.github.com/spec/v1[[:space:]]*$' "$scratch"; then fail 'Git LFS pointer is unsupported'; fi
    printf 'file\t%s\t%s\t-\t%s\n' "$path" "$size" "$object" >> ${q(entriesTmp)}
  fi
  if [[ "$(basename "$path")" == '.gitattributes' ]]; then
    (( size <= ${MAX_GIT_ATTRIBUTES_BYTES} )) || fail 'Git attributes file is too large to inspect'
    timeout --signal=KILL ${timeoutSeconds} git -C "$source" cat-file blob "$object" > "$scratch" || fail 'Git attributes blob could not be read'
    if grep -aEq '(^|[[:space:]])filter=lfs([[:space:]]|$)' "$scratch"; then fail 'Git LFS attributes are unsupported'; fi
  fi
done < "$rawEntries"
rm -f "$rawEntries"
mv ${q(entriesTmp)} "$entries"
rm -f "$scratch"
commit=$(git -C "$source" rev-parse HEAD) || fail 'Git source commit is missing'
[[ "$commit" =~ ^[0-9a-f]{40}([0-9a-f]{24})?$ ]] || fail 'Git source commit is invalid'
expanded_size=$(awk -F '\t' '{ total += $3 } END { printf "%.0f\n", total + 0 }' "$entries")
[[ "$expanded_size" =~ ^[0-9]+$ ]] && (( expanded_size <= max_expanded )) || fail 'Git source tree exceeds the expansion limit'
printf 'schemaVersion=1\ncommit=%s\nexpandedSize=%s\n' "$commit" "$expanded_size" > "$metadata"
`;
}
