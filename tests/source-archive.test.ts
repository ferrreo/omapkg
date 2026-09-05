import { describe, expect, test } from 'bun:test';
import { execFileSync } from 'node:child_process';
import { existsSync, linkSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  inspectSourceArchiveCommand,
  MAX_SOURCE_ARCHIVE_MANIFEST_BYTES,
  materializeSourceArchiveCommand,
  parseSourceArchiveManifest,
  assertSourceArchiveReadPaths,
  sourceArchiveManifestSizeCheckCommand,
  sourceArchiveInventory,
  validateSourceArchiveEntries,
} from '../services/pipeline/source-archive';

function scriptResult(script: string): { status: number; stderr: string } {
  try {
    execFileSync('bash', ['-c', script], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
    return { status: 0, stderr: '' };
  } catch (cause) {
    const error = cause as { status?: number; stderr?: Buffer | string };
    return { status: error.status ?? 1, stderr: String(error.stderr ?? '') };
  }
}

function workspaceFor(archive: string, root: string, name = 'workspace'): string {
  const workspace = join(root, name);
  mkdirSync(workspace);
  writeFileSync(join(workspace, 'source.bundle'), readFileSync(archive));
  return workspace;
}

function tarArchive(root: string, name = 'source.tar'): string {
  const input = join(root, 'input');
  mkdirSync(join(input, 'src', 'bin'), { recursive: true });
  writeFileSync(join(input, 'src', 'README.md'), 'source archive\n');
  writeFileSync(join(input, 'src', 'space name.txt'), 'space\n');
  writeFileSync(join(input, 'src', 'bin', 'tool'), '#!/bin/sh\nprintf tool\n');
  symlinkSync('tool', join(input, 'src', 'bin', 'current'));
  linkSync(join(input, 'src', 'bin', 'tool'), join(input, 'src', 'bin', 'copy'));
  const archive = join(root, name);
  execFileSync('tar', ['-cf', archive, '-C', input, 'src']);
  return archive;
}

describe('source archive boundary', () => {
  test('can inspect without materializing the archive', () => {
    const root = mkdtempSync(join(tmpdir(), 'omapkg-source-inspect-'));
    try {
      const workspace = workspaceFor(tarArchive(root), root);
      expect(scriptResult(inspectSourceArchiveCommand({ workspaceRoot: workspace })).status).toBe(0);
      expect(scriptResult(sourceArchiveManifestSizeCheckCommand({ workspaceRoot: workspace })).status).toBe(0);
      expect(existsSync(join(workspace, 'source'))).toBe(false);
      const manifest = parseSourceArchiveManifest(
        readFileSync(join(workspace, 'source-archive.meta'), 'utf8'),
        readFileSync(join(workspace, 'source-archive.entries'), 'utf8'),
        workspace,
      );
      expect(manifest.entries.length).toBeGreaterThan(0);
      writeFileSync(join(workspace, 'source-archive.entries'), Buffer.alloc(MAX_SOURCE_ARCHIVE_MANIFEST_BYTES + 1));
      expect(scriptResult(sourceArchiveManifestSizeCheckCommand({ workspaceRoot: workspace })).status).not.toBe(0);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  test('validates and materializes tar members, including safe links', () => {
    const root = mkdtempSync(join(tmpdir(), 'omapkg-source-tar-'));
    try {
      const workspace = workspaceFor(tarArchive(root), root);
      const result = scriptResult(materializeSourceArchiveCommand({ workspaceRoot: workspace, maxExpandedBytes: 10_000 }));
      expect(result.status).toBe(0);
      const manifest = parseSourceArchiveManifest(
        readFileSync(join(workspace, 'source-archive.meta'), 'utf8'),
        readFileSync(join(workspace, 'source-archive.entries'), 'utf8'),
        workspace,
      );
      expect(manifest.format).toBe('tar');
      expect(manifest.entries.some((entry) => entry.kind === 'symlink' && entry.target === 'tool')).toBe(true);
      expect(manifest.entries.some((entry) => entry.kind === 'hardlink')).toBe(true);
      expect(manifest.entries.some((entry) => entry.path === 'src/space name.txt')).toBe(true);
      expect(assertSourceArchiveReadPaths(manifest, ['src/README.md', './src/README.md'])).toEqual(['src/README.md']);
      expect(() => assertSourceArchiveReadPaths(manifest, ['src'])).toThrow();
      expect(readFileSync(join(workspace, 'source', 'src', 'README.md'), 'utf8')).toBe('source archive\n');
      expect(readFileSync(join(workspace, 'source', 'src', 'bin', 'current'), 'utf8')).toContain('tool');
      expect(existsSync(join(workspace, 'source', 'src', 'bin', 'copy'))).toBe(true);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  test('validates and materializes zip members', () => {
    const root = mkdtempSync(join(tmpdir(), 'omapkg-source-zip-'));
    try {
      const input = join(root, 'input');
      mkdirSync(join(input, 'src'), { recursive: true });
      writeFileSync(join(input, 'src', 'README.md'), 'zip source\n');
      const archive = join(root, 'source.zip');
      execFileSync('zip', ['-q', '-r', archive, 'src'], { cwd: input });
      const workspace = workspaceFor(archive, root);
      const result = scriptResult(materializeSourceArchiveCommand({ workspaceRoot: workspace }));
      expect(result.status).toBe(0);
      const manifest = parseSourceArchiveManifest(
        readFileSync(join(workspace, 'source-archive.meta'), 'utf8'),
        readFileSync(join(workspace, 'source-archive.entries'), 'utf8'),
        workspace,
      );
      expect(manifest.format).toBe('zip');
      expect(readFileSync(join(workspace, 'source', 'src', 'README.md'), 'utf8')).toBe('zip source\n');
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  test('rejects unsafe links, special files, duplicate members, and expansion overflow before extraction', () => {
    const root = mkdtempSync(join(tmpdir(), 'omapkg-source-reject-'));
    try {
      const unsafeInput = join(root, 'unsafe-input');
      mkdirSync(join(unsafeInput, 'src'), { recursive: true });
      symlinkSync('../../outside', join(unsafeInput, 'src', 'escape'));
      const unsafeArchive = join(root, 'unsafe.tar');
      execFileSync('tar', ['-cf', unsafeArchive, '-C', unsafeInput, 'src']);
      const unsafeWorkspace = workspaceFor(unsafeArchive, root);
      const unsafe = scriptResult(materializeSourceArchiveCommand({ workspaceRoot: unsafeWorkspace }));
      expect(unsafe.status).not.toBe(0);
      expect(existsSync(join(unsafeWorkspace, 'source-archive.meta'))).toBe(false);

      const absoluteInput = join(root, 'absolute-input');
      mkdirSync(join(absoluteInput, 'src'), { recursive: true });
      symlinkSync('/etc/passwd', join(absoluteInput, 'src', 'absolute'));
      const absoluteArchive = join(root, 'absolute.tar');
      execFileSync('tar', ['-cf', absoluteArchive, '-C', absoluteInput, 'src']);
      const absoluteWorkspace = workspaceFor(absoluteArchive, root, 'absolute-workspace');
      expect(scriptResult(materializeSourceArchiveCommand({ workspaceRoot: absoluteWorkspace })).status).not.toBe(0);

      const rootLinkInput = join(root, 'root-link-input');
      mkdirSync(rootLinkInput);
      symlinkSync('../outside', join(rootLinkInput, 'link'));
      const rootLinkArchive = join(root, 'root-link.tar');
      execFileSync('tar', ['-cf', rootLinkArchive, '-C', rootLinkInput, 'link']);
      const rootLinkWorkspace = workspaceFor(rootLinkArchive, root, 'root-link-workspace');
      expect(scriptResult(materializeSourceArchiveCommand({ workspaceRoot: rootLinkWorkspace })).status).not.toBe(0);

      const chainInput = join(root, 'chain-input');
      mkdirSync(join(chainInput, 'src', 'a', 'b'), { recursive: true });
      symlinkSync('../../c', join(chainInput, 'src', 'a', 'b', 'link'));
      symlinkSync('a/b/link/../../../outside', join(chainInput, 'src', 'x'));
      const chainArchive = join(root, 'chain.tar');
      execFileSync('tar', ['-cf', chainArchive, '-C', chainInput, 'src']);
      const chainWorkspace = workspaceFor(chainArchive, root, 'chain-workspace');
      expect(scriptResult(materializeSourceArchiveCommand({ workspaceRoot: chainWorkspace })).status).not.toBe(0);

      const fifoInput = join(root, 'fifo-input');
      mkdirSync(join(fifoInput, 'src'), { recursive: true });
      execFileSync('mkfifo', [join(fifoInput, 'src', 'pipe')]);
      const fifoArchive = join(root, 'fifo.tar');
      execFileSync('tar', ['-cf', fifoArchive, '-C', fifoInput, 'src']);
      const fifoWorkspace = workspaceFor(fifoArchive, root, 'fifo-workspace');
      expect(scriptResult(materializeSourceArchiveCommand({ workspaceRoot: fifoWorkspace })).status).not.toBe(0);

      const duplicateInput = join(root, 'duplicate-input');
      mkdirSync(join(duplicateInput, 'src'), { recursive: true });
      writeFileSync(join(duplicateInput, 'src', 'file'), 'duplicate\n');
      const duplicateArchive = join(root, 'duplicate.tar');
      execFileSync('tar', ['-cf', duplicateArchive, '-C', duplicateInput, 'src/file']);
      execFileSync('tar', ['-rf', duplicateArchive, '-C', duplicateInput, 'src/file']);
      const duplicateWorkspace = workspaceFor(duplicateArchive, root, 'duplicate-workspace');
      expect(scriptResult(materializeSourceArchiveCommand({ workspaceRoot: duplicateWorkspace })).status).not.toBe(0);

      const overflowArchive = join(root, 'overflow.tar');
      execFileSync('tar', ['-cf', overflowArchive, '-C', duplicateInput, 'src/file']);
      const overflowWorkspace = workspaceFor(overflowArchive, root, 'overflow-workspace');
      expect(scriptResult(materializeSourceArchiveCommand({ workspaceRoot: overflowWorkspace, maxExpandedBytes: 1 })).status).not.toBe(0);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  test('validates normalized paths, hardlink targets, and manifest totals', () => {
    const valid = validateSourceArchiveEntries([
      { path: './src/file', kind: 'file', size: 3, target: null },
      { path: 'src/copy', kind: 'hardlink', size: 0, target: './src/file' },
      { path: 'src/link', kind: 'symlink', size: 0, target: '../file' },
    ]);
    expect(valid[0]?.path).toBe('src/file');
    expect(valid[1]?.target).toBe('src/file');
    expect(() => validateSourceArchiveEntries([{ path: '../escape', kind: 'file', size: 1, target: null }])).toThrow();
    expect(() => validateSourceArchiveEntries([{ path: 'a', kind: 'file', size: 1, target: null }, { path: 'a/b', kind: 'file', size: 1, target: null }])).toThrow();
    expect(() => validateSourceArchiveEntries([{ path: 'a/link', kind: 'symlink', size: 0, target: '../../escape' }])).toThrow();
    expect(() => validateSourceArchiveEntries([
      { path: 'a/b/link', kind: 'symlink', size: 0, target: '../../c' },
      { path: 'x', kind: 'symlink', size: 0, target: 'a/b/link/../../../outside' },
    ])).toThrow();
    expect(() => validateSourceArchiveEntries([{ path: 'a/link', kind: 'hardlink', size: 0, target: 'missing' }])).toThrow();
    expect(() => parseSourceArchiveManifest(
      'schemaVersion=1\nformat=tar\nsourcePath=/workspace/source.bundle\nsourceSize=10\nsourceSha256=' + 'a'.repeat(64) + '\nexpandedSize=2\n',
      'file\tsrc/file\t1\t\n',
    )).toThrow();
    const inventory = {
      schemaVersion: 1 as const,
      format: 'tar' as const,
      sourcePath: '/workspace/source.bundle',
      sourceSize: 10,
      sourceSha256: 'a'.repeat(64),
      expandedSize: 3,
      entries: [
        { path: 'docs/LICENSE', kind: 'file' as const, size: 1, target: null },
        { path: 'src/PKGBUILD', kind: 'file' as const, size: 1, target: null },
        { path: 'README.md', kind: 'file' as const, size: 1, target: null },
      ],
    };
    expect(sourceArchiveInventory(inventory)).toEqual(['src/PKGBUILD', 'docs/LICENSE', 'README.md']);
    expect(sourceArchiveInventory(inventory, 2)).toHaveLength(2);
  });
});
