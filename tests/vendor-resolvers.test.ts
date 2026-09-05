import { describe, expect, test } from 'bun:test';
import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { vendorKindForEvidence } from '../services/pipeline/tools';
import { vendorCommand } from '../services/pipeline/security';
import type { SourceEvidence } from '../services/pipeline/types';

const nativeNodeBin = process.env.OPR_NODE ? dirname(process.env.OPR_NODE) : undefined;

function resolverEnv() {
  return nativeNodeBin ? { ...process.env, PATH: `${nativeNodeBin}:${process.env.PATH ?? ''}` } : process.env;
}

function hasExecutable(name: string): boolean {
  try {
    execFileSync('sh', ['-c', `command -v ${name}`], { env: resolverEnv(), stdio: 'ignore' });
    return true;
  } catch {
    return false;
  }
}

function evidence(files: string[]): SourceEvidence {
  return {
    sourceKind: 'archive',
    upstreamUrl: 'https://example.test/source.tar.gz',
    normalizedUrl: 'https://example.test/source.tar.gz',
    sourceName: 'source.tar.gz',
    sourceSha256: 'a'.repeat(64),
    upstreamCommit: null,
    files,
    licenseFiles: [],
  };
}

function runResolver(kind: 'go' | 'rust' | 'npm', files: Record<string, string>): string {
  const root = mkdtempSync(join(tmpdir(), 'omapkg-vendor-resolver-'));
  const source = join(root, 'source');
  for (const [path, body] of Object.entries(files)) {
    const target = join(source, path);
    mkdirSync(dirname(target), { recursive: true });
    writeFileSync(target, body);
  }
  const command = vendorCommand(kind, 'archive').replaceAll('/workspace', root);
  execFileSync('bash', ['-c', command], { env: resolverEnv(), stdio: 'pipe' });
  return root;
}

function resolverStatus(kind: 'go' | 'rust' | 'npm', files: Record<string, string>): number {
  const root = mkdtempSync(join(tmpdir(), 'omapkg-vendor-resolver-fail-'));
  const source = join(root, 'source');
  try {
    for (const [path, body] of Object.entries(files)) {
      const target = join(source, path);
      mkdirSync(dirname(target), { recursive: true });
      writeFileSync(target, body);
    }
    const command = vendorCommand(kind, 'archive').replaceAll('/workspace', root);
    try {
      execFileSync('bash', ['-c', command], { env: resolverEnv(), stdio: 'pipe' });
      return 0;
    } catch (cause) {
      const status = (cause as { status?: unknown }).status;
      return typeof status === 'number' ? status : -1;
    }
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

describe('dependency vendor resolvers', () => {
  test('does not require optional lockfiles before inspecting dependency content', () => {
    expect(vendorKindForEvidence(evidence(['go.mod']))).toBe('go');
    expect(vendorKindForEvidence(evidence(['package.json']))).toBe('npm');
    expect(vendorKindForEvidence(evidence(['Cargo.toml', 'Cargo.lock']))).toBe('rust');
  });

  test('skips Go vendoring for a module with no requirements', () => {
    if (!hasExecutable('go')) return;
    const root = runResolver('go', {
      'go.mod': 'module example.com/stdonly\n\ngo 1.22\n',
    });
    try {
      expect(existsSync(join(root, 'vendor-empty'))).toBe(true);
      expect(existsSync(join(root, 'vendor.tar'))).toBe(false);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  test('skips Rust vendoring and ignores project Cargo executable hooks', () => {
    if (!hasExecutable('cargo') || !hasExecutable('rustc')) return;
    const root = mkdtempSync(join(tmpdir(), 'omapkg-vendor-rust-canary-'));
    const marker = join(root, 'hook-ran');
    try {
      const source = join(root, 'source');
      const wrapper = join(root, 'evil-wrapper');
      const credential = join(root, 'evil-credential');
      mkdirSync(join(source, 'src'), { recursive: true });
      mkdirSync(join(source, '.cargo'), { recursive: true });
      writeFileSync(join(source, 'Cargo.toml'), '[package]\nname="stdonly"\nversion="0.1.0"\nedition="2021"\n');
      writeFileSync(join(source, 'Cargo.lock'), 'version = 3\n\n[[package]]\nname = "stdonly"\nversion = "0.1.0"\n');
      writeFileSync(join(source, 'src', 'main.rs'), 'fn main() {}\n');
      writeFileSync(wrapper, `#!/bin/sh\nprintf ran > ${marker}\nexit 99\n`);
      writeFileSync(credential, `#!/bin/sh\nprintf ran > ${marker}\nexit 99\n`);
      execFileSync('chmod', ['+x', wrapper, credential]);
      writeFileSync(join(source, '.cargo', 'config.toml'), [
        '[build]',
        `rustc = "${wrapper}"`,
        `rustc-wrapper = "${wrapper}"`,
        `rustc-workspace-wrapper = "${wrapper}"`,
        '[registry]',
        `global-credential-providers = ["${credential}"]`,
        '[source.crates-io]',
        'replace-with = "evil"',
        '[source.evil]',
        'registry = "https://evil.invalid/index"',
      ].join('\n'));
      const command = vendorCommand('rust', 'archive').replaceAll('/workspace', root);
      execFileSync('bash', ['-c', command], { env: resolverEnv(), stdio: 'pipe' });
      expect(existsSync(join(root, 'vendor-empty'))).toBe(true);
      expect(existsSync(marker)).toBe(false);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  test('skips npm vendoring when package has no dependency fields or lockfile', () => {
    if (!hasExecutable('node')) return;
    const markerName = 'should-not-run';
    const root = runResolver('npm', {
      'package.json': JSON.stringify({ name: 'stdonly', version: '1.0.0', scripts: { preinstall: `touch ${markerName}` } }),
      '.npmrc': 'registry=https://evil.invalid/\nignore-scripts=false\n',
    });
    try {
      expect(existsSync(join(root, 'vendor-empty'))).toBe(true);
      expect(existsSync(join(root, markerName))).toBe(false);
      expect(existsSync(join(root, 'vendor.tar'))).toBe(false);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  test('keeps external dependency lock and registry checks in resolver commands', () => {
    const go = vendorCommand('go', 'archive');
    const rust = vendorCommand('rust', 'archive');
    const npm = vendorCommand('npm', 'archive');
    expect(go).toContain('pinned go.sum lockfile');
    expect(go).toContain('go mod download -json all');
    expect(rust).toContain('Cargo.lock');
    expect(rust).toContain('index.crates.io');
    expect(rust).toContain('global-credential-providers=[]');
    expect(rust).toContain('rustc-wrapper=\"\"');
    expect(npm).toContain('npm lockfile is required');
    expect(npm).toContain('registry.npmjs.org');
    expect(npm).toContain('--ignore-scripts');
  });

  test('rejects external dependencies without their verified lock data', () => {
    if (hasExecutable('go')) {
      expect(resolverStatus('go', {
        'go.mod': 'module example.com/needsdep\n\ngo 1.22\nrequire example.com/dep v1.0.0\n',
      })).toBe(64);
    }
    if (hasExecutable('node')) {
      expect(resolverStatus('npm', {
        'package.json': JSON.stringify({ name: 'needsdep', version: '1.0.0', dependencies: { 'left-pad': '1.3.0' } }),
      })).toBe(64);
    }
    if (hasExecutable('cargo') && hasExecutable('rustc')) {
      expect(resolverStatus('rust', {
        'Cargo.toml': '[package]\nname="needsdep"\nversion="0.1.0"\nedition="2021"\n',
        'Cargo.lock': 'version = 3\n\n[[package]]\nname = "evil"\nversion = "1.0.0"\nsource = "registry+https://evil.invalid/index"\n',
      })).toBe(65);
    }
  });
});
