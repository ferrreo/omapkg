export const DEFAULT_ARCHIVE_PATH_BYTES = 4_096;

export interface ArchiveEntryLike {
  path: string;
  kind: string;
  target: string | null;
}

export function validateArchivePath(value: string, maxBytes = DEFAULT_ARCHIVE_PATH_BYTES): string {
  if (typeof value !== 'string' || value.length === 0 || value.length > maxBytes || /[\u0000-\u001f\u007f\t\\]/.test(value)) {
    throw new Error('archive path is invalid');
  }
  const normalized = value.replace(/^\.\//, '');
  if (!normalized || normalized === '.' || normalized.startsWith('/') || normalized.split('/').some((part) => part === '..' || part === '.' || part === '')) {
    throw new Error('archive path escapes extraction root');
  }
  return normalized;
}

export function resolveArchiveLinkTarget(path: string, target: string, maxBytes = DEFAULT_ARCHIVE_PATH_BYTES): string {
  if (typeof target !== 'string' || target.length === 0 || target.length > maxBytes ||
    target.startsWith('/') || target.includes('//') || /[\u0000-\u001f\u007f\\]/.test(target)) {
    throw new Error('archive link target is unsafe');
  }
  const stack = path.split('/');
  stack.pop();
  for (const part of target.split('/')) {
    if (!part || part === '.') continue;
    if (part === '..') {
      if (!stack.length) throw new Error('archive link target escapes extraction root');
      stack.pop();
      continue;
    }
    stack.push(part);
  }
  if (!stack.length) throw new Error('archive link target is empty');
  return validateArchivePath(stack.join('/'), maxBytes);
}

export function resolveCanonicalArchivePath<T extends ArchiveEntryLike>(
  start: string,
  input: string,
  byPath: Map<string, T>,
  isDirectory: (entry: T) => boolean = (entry) => entry.kind === 'directory',
  isSymlink: (entry: T) => boolean = (entry) => entry.kind === 'symlink',
): string {
  const stack = start ? start.split('/') : [];
  const pending = input.split('/');
  const followed = new Set<string>();
  while (pending.length) {
    const part = pending.shift();
    if (!part || part === '.') continue;
    if (part === '..') {
      if (!stack.length) throw new Error('archive link target escapes extraction root');
      stack.pop();
      continue;
    }
    stack.push(part);
    const path = stack.join('/');
    const entry = byPath.get(path);
    if (entry && isSymlink(entry)) {
      if (followed.has(path)) throw new Error('archive symlink cycle detected');
      followed.add(path);
      stack.pop();
      pending.unshift(...(entry.target ?? '').split('/'));
    } else if (entry && !isDirectory(entry) && pending.length) {
      throw new Error('archive link target traverses a non-directory');
    }
  }
  if (!stack.length) throw new Error('archive link target is empty');
  return validateArchivePath(stack.join('/'));
}
