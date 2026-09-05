import { describe, expect, test } from 'bun:test';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, mkdtempSync, symlinkSync, writeFileSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  gitSourcePolicyCommand,
  gitSourceInventory,
  parseGitSourceEntries,
  validateGitSourceEntries,
} from '../services/pipeline/git-source';
import { materializeSourceArchiveCommand, parseSourceArchiveManifest } from '../services/pipeline/source-archive';
import { gitInspectCommand, shellQuote } from '../services/pipeline/security';

function result(command: string, prependPath?: string): number {
  try {
    execFileSync('bash', ['-c', command], {
      stdio: ['ignore', 'pipe', 'pipe'],
      env: prependPath ? { ...process.env, PATH: `${prependPath}:${process.env.PATH ?? ''}` } : process.env,
    });
    return 0;
  } catch (cause) {
    return (cause as { status?: number }).status ?? 1;
  }
}

function gitRepository(workspace: string, setup?: (source: string) => void): string {
  const source = join(workspace, 'source');
  mkdirSync(source, { recursive: true });
  execFileSync('git', ['init', '-q', source]);
  execFileSync('git', ['-C', source, 'config', 'user.email', 'test@example.com']);
  execFileSync('git', ['-C', source, 'config', 'user.name', 'Test']);
  writeFileSync(join(source, 'README.md'), 'source\n');
  setup?.(source);
  execFileSync('git', ['-C', source, 'add', '.']);
  execFileSync('git', ['-C', source, 'commit', '-qm', 'test']);
  return source;
}

function policy(workspace: string): string {
  return gitSourcePolicyCommand({ workspaceRoot: workspace });
}

describe('Git source policy boundary', () => {
  test('complete inspection seals Git before replacing checkout with verified archive bytes', () => {
    const root = mkdtempSync(join(tmpdir(), 'omapkg-git-inspect-'));
    try {
      const repository = gitRepository(join(root, 'upstream'), (path) => {
        writeFileSync(join(path, '.gitattributes'), 'ignored.txt export-ignore\nVERSION export-subst\n');
        writeFileSync(join(path, 'ignored.txt'), 'excluded\n');
        writeFileSync(join(path, 'VERSION'), '$Format:%H$\n');
      });
      const commit = execFileSync('git', ['-C', repository, 'rev-parse', 'HEAD'], { encoding: 'utf8' }).trim();
      const nativeGit = execFileSync('which', ['git'], { encoding: 'utf8' }).trim();
      const bin = join(root, 'bin');
      mkdirSync(bin);
      // Substitute local transport only; execute every inspection command with real Git and tar.
      writeFileSync(join(bin, 'git'), `#!/usr/bin/env bash
args=()
for argument in "$@"; do
  case "$argument" in
    https://example.com/source.git) args+=(${shellQuote(repository)});;
    protocol.file.allow=never) args+=(protocol.file.allow=always);;
    *) args+=("$argument");;
  esac
done
exec ${shellQuote(nativeGit)} "\${args[@]}"
`, { mode: 0o700 });
      for (const requestedCommit of [undefined, commit]) {
        const workspace = join(root, requestedCommit ? 'pinned' : 'default');
        mkdirSync(workspace);
        const command = gitInspectCommand('https://example.com/source.git', '/workspace/source', requestedCommit).replaceAll('/workspace', workspace);
        const output = execFileSync('sh', ['-c', command], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], env: { ...process.env, PATH: `${bin}:${process.env.PATH}` } });
        expect(output).toContain(`commit=${commit}`);
        expect(readFileSync(join(workspace, 'source', 'VERSION'), 'utf8').trim()).toBe(commit);
        expect(existsSync(join(workspace, 'source', '.git'))).toBe(false);
        expect(existsSync(join(workspace, 'source', 'ignored.txt'))).toBe(false);
        const manifest = parseSourceArchiveManifest(readFileSync(join(workspace, 'source-archive.meta'), 'utf8'), readFileSync(join(workspace, 'source-archive.entries'), 'utf8'), workspace);
        expect(manifest.sourceSha256).toBe(createHash('sha256').update(readFileSync(join(workspace, 'source.tar'))).digest('hex'));
      }
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  test('records a bounded tree and permits safe symlinks', () => {
    const root = mkdtempSync(join(tmpdir(), 'omapkg-git-safe-'));
    try {
      const source = gitRepository(join(root, 'workspace'), (path) => {
        mkdirSync(join(path, 'src'));
        writeFileSync(join(path, 'src', 'main'), 'main\n');
        symlinkSync('main', join(path, 'src', 'current'));
      });
      const workspace = join(root, 'workspace');
      expect(result(policy(workspace))).toBe(0);
      const entries = parseGitSourceEntries(readFileSync(join(workspace, 'git-source.entries'), 'utf8'));
      expect(entries.some((entry) => entry.path === 'src/current' && entry.kind === 'symlink' && entry.target === 'main')).toBe(true);
      expect(entries.some((entry) => entry.path === 'README.md')).toBe(true);
      expect(readFileSync(join(source, 'src', 'current'), 'utf8')).toBe('main\n');
      expect(readFileSync(join(workspace, 'git-source.meta'), 'utf8')).toContain('expandedSize=');
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  test('accepts a real source tree with the Sandbox image awk implementation', () => {
    if (!existsSync('/usr/bin/mawk')) return;
    const root = mkdtempSync(join(tmpdir(), 'omapkg-git-mawk-'));
    try {
      const workspace = join(root, 'workspace');
      gitRepository(workspace);
      const bin = join(root, 'bin');
      mkdirSync(bin);
      symlinkSync('/usr/bin/mawk', join(bin, 'awk'));
      expect(result(policy(workspace), bin)).toBe(0);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  test('rejects root and chained symlinks that resolve outside checkout', () => {
    const root = mkdtempSync(join(tmpdir(), 'omapkg-git-links-'));
    try {
      const rootWorkspace = join(root, 'root-workspace');
      gitRepository(rootWorkspace, (source) => symlinkSync('../outside', join(source, 'escape')));
      expect(result(policy(rootWorkspace))).not.toBe(0);

      const chainWorkspace = join(root, 'chain-workspace');
      gitRepository(chainWorkspace, (source) => {
        mkdirSync(join(source, 'a', 'b'), { recursive: true });
        symlinkSync('../../c', join(source, 'a', 'b', 'link'));
        symlinkSync('a/b/link/../../../outside', join(source, 'x'));
      });
      expect(result(policy(chainWorkspace))).not.toBe(0);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  test('rejects submodules, Git metadata, LFS pointers, attributes, and custom hooks', () => {
    expect(() => validateGitSourceEntries([{ path: 'vendor', kind: 'file', size: 0, target: null, mode: '160000', type: 'commit' }])).toThrow();
    expect(() => validateGitSourceEntries([{ path: '.gitmodules', kind: 'file', size: 1, target: null }])).toThrow();

    const root = mkdtempSync(join(tmpdir(), 'omapkg-git-reject-'));
    try {
      const lfsWorkspace = join(root, 'lfs-workspace');
      gitRepository(lfsWorkspace, (source) => {
        writeFileSync(join(source, '.gitattributes'), '*.bin filter=lfs\n');
        writeFileSync(join(source, 'payload.bin'), 'version https://git-lfs.github.com/spec/v1\noid sha256:' + 'a'.repeat(64) + '\nsize 1\n');
      });
      expect(result(policy(lfsWorkspace))).not.toBe(0);

      const hooksWorkspace = join(root, 'hooks-workspace');
      const source = gitRepository(hooksWorkspace);
      execFileSync('git', ['-C', source, 'config', 'core.hooksPath', 'hooks']);
      expect(result(policy(hooksWorkspace))).not.toBe(0);
      expect(existsSync(join(hooksWorkspace, 'git-source.entries'))).toBe(false);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  test('rejects lexical and graph escapes plus oversized trees', () => {
    expect(() => validateGitSourceEntries([{ path: 'link', kind: 'symlink', size: 0, target: '../outside' }])).toThrow();
    expect(() => validateGitSourceEntries([
      { path: 'a/b/link', kind: 'symlink', size: 0, target: '../../c' },
      { path: 'x', kind: 'symlink', size: 0, target: 'a/b/link/../../../outside' },
    ])).toThrow();
    expect(() => validateGitSourceEntries([
      { path: 'a', kind: 'file', size: 3, target: null },
      { path: 'b', kind: 'file', size: 3, target: null },
    ], { maxExpandedBytes: 5 })).toThrow();
    const parsed = parseGitSourceEntries('file\tREADME.md\t1\t-\t' + 'a'.repeat(40) + '\n');
    expect(parsed[0]?.objectId).toBe('a'.repeat(40));
    expect(gitSourceInventory([
      { path: 'docs/LICENSE', kind: 'file', size: 1, target: null },
      { path: 'src/PKGBUILD', kind: 'file', size: 1, target: null },
      { path: 'README.md', kind: 'file', size: 1, target: null },
    ])).toEqual(['src/PKGBUILD', 'docs/LICENSE', 'README.md']);
  });

  test('inspects the exact git archive bytes used by workers', () => {
    const root = mkdtempSync(join(tmpdir(), 'omapkg-git-archive-'));
    try {
      const workspace = join(root, 'workspace');
      const source = gitRepository(workspace, (path) => {
        writeFileSync(join(path, '.gitattributes'), 'ignored.txt export-ignore\nVERSION export-subst\n');
        writeFileSync(join(path, 'ignored.txt'), 'should not be archived\n');
        writeFileSync(join(path, 'VERSION'), '$Format:%H$\n');
      });
      expect(result(policy(workspace))).toBe(0);
      const commit = execFileSync('git', ['-C', source, 'rev-parse', 'HEAD'], { encoding: 'utf8' }).trim();
      const archive = join(workspace, 'source.tar');
      writeFileSync(archive, execFileSync('git', ['-C', source, 'archive', '--format=tar', 'HEAD']));
      execFileSync('bash', ['-c', materializeSourceArchiveCommand({ workspaceRoot: workspace, sourcePath: archive })], { stdio: 'pipe' });
      const manifest = parseSourceArchiveManifest(
        readFileSync(join(workspace, 'source-archive.meta'), 'utf8'),
        readFileSync(join(workspace, 'source-archive.entries'), 'utf8'),
        workspace,
      );
      const paths = manifest.entries.map((entry) => entry.path);
      expect(paths).toContain('VERSION');
      expect(paths).not.toContain('ignored.txt');
      expect(readFileSync(join(workspace, 'source', 'VERSION'), 'utf8')).toContain(commit);
      expect(manifest.sourceSha256).toBe(createHash('sha256').update(readFileSync(archive)).digest('hex'));
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
});
