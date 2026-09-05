import { describe, expect, test } from 'bun:test';
import { execFileSync } from 'node:child_process';
import { gzipSync } from 'node:zlib';
import {
  chmodSync,
  existsSync,
  linkSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, join } from 'node:path';
import {
  appImageSquashfsOffset,
  assertVendorArtifactReadPaths,
  constrainVendorArtifactArchitectures,
  detectVendorBinaryFormat,
  elfMachineArchitecture,
  offlineVendorExtractCommand,
  parseVendorArtifactManifest,
  parseVendorArtifactManifestEntries,
  validateArchiveEntries,
  vendorArtifactInventory,
  vendorArtifactReadCommand,
  vendorArtifactCommand,
  vendorSurface,
} from '../services/pipeline/artifacts';

function run(command: string, path?: string): void {
  execFileSync('bash', ['-c', command], { env: { ...process.env, ...(path ? { PATH: path } : {}) }, stdio: 'pipe' });
}

function align4(value: Buffer): Buffer {
  return Buffer.concat([value, Buffer.alloc((4 - (value.length % 4)) % 4)]);
}

function cpio(entries: Array<{ path: string; mode: number; body: Buffer }>): Buffer {
  const output: Buffer[] = [];
  let inode = 1;
  for (const entry of entries) {
    const name = Buffer.from(`${entry.path}\0`);
    const fields = [inode++, entry.mode, 0, 0, 1, 0, entry.body.length, 0, 0, 0, 0, name.length, 0];
    const header = Buffer.from(`070701${fields.map((field) => field.toString(16).padStart(8, '0')).join('')}`);
    output.push(align4(Buffer.concat([header, name])), align4(entry.body));
  }
  const trailer = Buffer.from('TRAILER!!!\0');
  const fields = [0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, trailer.length, 0];
  output.push(align4(Buffer.concat([Buffer.from(`070701${fields.map((field) => field.toString(16).padStart(8, '0')).join('')}`), trailer])));
  return Buffer.concat(output);
}

function rpmHeader(fields: Array<{ tag: number; value: string }>): Buffer {
  const store = Buffer.concat(fields.map((field) => Buffer.from(`${field.value}\0`)));
  const indexes = Buffer.alloc(fields.length * 16);
  let offset = 0;
  fields.forEach((field, index) => {
    indexes.writeUInt32BE(field.tag, index * 16);
    indexes.writeUInt32BE(6, index * 16 + 4);
    indexes.writeUInt32BE(offset, index * 16 + 8);
    indexes.writeUInt32BE(1, index * 16 + 12);
    offset += Buffer.byteLength(field.value) + 1;
  });
  const intro = Buffer.alloc(16);
  intro.set([0x8e, 0xad, 0xe8, 0x01], 0);
  intro.writeUInt32BE(fields.length, 8);
  intro.writeUInt32BE(store.length, 12);
  return Buffer.concat([intro, indexes, store]);
}

function rpmFixture(): Buffer {
  const lead = Buffer.alloc(96);
  lead.set([0xed, 0xab, 0xee, 0xdb], 0);
  lead[4] = 3;
  lead.writeUInt16BE(1, 8);
  lead.writeUInt16BE(1, 76);
  lead.writeUInt16BE(5, 78);
  const signature = Buffer.from([0x8e, 0xad, 0xe8, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
  const header = rpmHeader([
    { tag: 1000, value: 'vendor-demo' },
    { tag: 1001, value: '1.0' },
    { tag: 1002, value: '1' },
    { tag: 1022, value: 'x86_64' },
  ]);
  const payload = gzipSync(cpio([
    { path: 'usr', mode: 0o040755, body: Buffer.alloc(0) },
    { path: 'usr/share', mode: 0o040755, body: Buffer.alloc(0) },
    { path: 'usr/share/vendor-demo.txt', mode: 0o100644, body: Buffer.from('rpm payload\n') },
  ]));
  return Buffer.concat([lead, signature, header, payload]);
}

function appImageFixture(root: string, type: 1 | 2, escape = false): string {
  const app = join(root, `app-${type}`);
  mkdirSync(join(app, 'usr', 'bin'), { recursive: true });
  mkdirSync(join(app, 'usr', 'share', 'vendor-demo'), { recursive: true });
  writeFileSync(join(app, 'usr', 'bin', 'vendor-demo'), '#!/bin/sh\nprintf app\n');
  chmodSync(join(app, 'usr', 'bin', 'vendor-demo'), 0o755);
  symlinkSync('usr/bin/vendor-demo', join(app, 'AppRun'));
  if (escape) symlinkSync('../../outside', join(app, 'escape'));
  writeFileSync(join(app, 'vendor-demo.desktop'), '[Desktop Entry]\nName=Vendor Demo\nType=Application\nExec=AppRun\n');
  writeFileSync(join(app, 'usr', 'share', 'vendor-demo', 'payload.txt'), 'appimage payload\n');
  const squashfs = join(root, `app-${type}.squashfs`);
  execFileSync('mksquashfs', [app, squashfs, '-noappend', '-no-progress', '-all-root'], { stdio: 'pipe' });
  const runtime = join(root, `runtime-${type}`);
  execFileSync('gcc', ['-x', 'c', '-O2', '-o', runtime, '-'], { input: 'int main(void) { return 0; }', stdio: 'pipe' });
  if (type === 2) {
    const bytes = Buffer.concat([readFileSync(runtime), readFileSync(squashfs)]);
    bytes[8] = 0x41;
    bytes[9] = 0x49;
    bytes[10] = 0x02;
    const output = join(root, 'vendor-demo.AppImage');
    writeFileSync(output, bytes);
    return output;
  }
  const iso = join(root, 'vendor-demo.iso');
  execFileSync('xorriso', ['-as', 'mkisofs', '-R', '-J', '-o', iso, app], { stdio: 'pipe' });
  const bytes = readFileSync(iso);
  const output = Buffer.from(bytes);
  const runtimeBytes = readFileSync(runtime);
  Buffer.from(runtimeBytes).copy(output, 0);
  output[8] = 0x41;
  output[9] = 0x49;
  output[10] = 0x01;
  const result = join(root, 'vendor-demo-type1.AppImage');
  writeFileSync(result, output);
  return result;
}

function inspect(source: string, root: string, extraPath?: string) {
  mkdirSync(root, { recursive: true });
  writeFileSync(join(root, 'source.bundle'), readFileSync(source));
  run(vendorArtifactCommand({ workspaceRoot: root, sourceName: basename(source) }), extraPath);
  const manifestPath = join(root, 'vendor-artifact.json');
  const raw = readFileSync(manifestPath, 'utf8');
  const parsed = JSON.parse(raw) as { entriesPath?: string | null };
  const entries = parsed.entriesPath ? readFileSync(parsed.entriesPath, 'utf8') : undefined;
  return parseVendorArtifactManifest(raw, entries, root);
}

describe('vendor binary artifact boundary', () => {
  test('classifies by file magic when names are unhelpful', () => {
    expect(detectVendorBinaryFormat(gzipSync(Buffer.from('ordinary GNU tar payload')))).toBeNull();
    expect(detectVendorBinaryFormat(Buffer.from('!<arch>\n'))).toBe('deb');
  });

  test('constrains prebuilt artifacts to verified architecture evidence', () => {
    const manifest = (format: 'deb' | 'rpm' | 'appimage1' | 'appimage2' | 'run', architecture: string) => ({ format, metadata: { architecture } });
    expect(constrainVendorArtifactArchitectures(['x86_64', 'aarch64'], manifest('deb', 'amd64'))).toEqual(['x86_64']);
    expect(constrainVendorArtifactArchitectures(['x86_64', 'aarch64'], manifest('rpm', 'arm64'))).toEqual(['aarch64']);
    expect(constrainVendorArtifactArchitectures(['x86_64', 'aarch64'], manifest('deb', 'all'))).toEqual(['x86_64', 'aarch64']);
    expect(constrainVendorArtifactArchitectures(['x86_64', 'aarch64'], manifest('rpm', 'noarch'))).toEqual(['x86_64', 'aarch64']);
    expect(() => constrainVendorArtifactArchitectures(['aarch64'], manifest('run', 'x86_64'))).toThrow();
    expect(() => constrainVendorArtifactArchitectures(['x86_64'], manifest('run', 'unknown'))).toThrow(/unsupported/);
    expect(() => constrainVendorArtifactArchitectures(['x86_64'], manifest('appimage2', ''))).toThrow(/missing/);
    expect(() => constrainVendorArtifactArchitectures(['x86_64'], manifest('appimage2', 'all'))).toThrow(/unsupported/);
  });

  test('reads AppImage ELF machine from trusted header', () => {
    const x86 = new Uint8Array(20);
    x86.set([0x7f, 0x45, 0x4c, 0x46, 2, 1], 0);
    x86[18] = 0x3e;
    expect(elfMachineArchitecture(x86)).toBe('x86_64');
    const arm = new Uint8Array(x86);
    arm[18] = 0xb7;
    arm[19] = 0;
    expect(elfMachineArchitecture(arm)).toBe('aarch64');
    const unknown = new Uint8Array(x86);
    unknown[18] = 0;
    unknown[19] = 0;
    expect(elfMachineArchitecture(unknown)).toBeNull();
  });

  test('does not infer self-extracting installer architecture from filename alone', () => {
    const root = mkdtempSync(join(tmpdir(), 'omarpkg-run-unknown-'));
    try {
      writeFileSync(join(root, 'source.bundle'), '#!/bin/sh\n# Makeself self-extracting archive\n');
      expect(() => run(vendorArtifactCommand({ workspaceRoot: root, sourceName: 'NVIDIA-Linux-x86_64.run' }))).toThrow(/unknown or ambiguous/);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  test('detects and inspects a real Debian package without running postinst', () => {
    const root = mkdtempSync(join(tmpdir(), 'omarpkg-deb-'));
    const packageRoot = join(root, 'package');
    const marker = join(root, 'installed-marker');
    try {
      mkdirSync(join(packageRoot, 'DEBIAN'), { recursive: true });
      mkdirSync(join(packageRoot, 'usr', 'bin'), { recursive: true });
      mkdirSync(join(packageRoot, 'usr', 'share', 'vendor-demo'), { recursive: true });
      writeFileSync(join(packageRoot, 'DEBIAN', 'control'), 'Package: vendor-demo\nVersion: 1.2.3\nArchitecture: all\nDescription: test\n\n');
      writeFileSync(join(packageRoot, 'DEBIAN', 'postinst'), `#!/bin/sh\ntouch ${marker}\n`);
      chmodSync(join(packageRoot, 'DEBIAN', 'postinst'), 0o755);
      writeFileSync(join(packageRoot, 'usr', 'bin', 'vendor-demo'), '#!/bin/sh\nprintf deb\n');
      symlinkSync('vendor-demo', join(packageRoot, 'usr', 'bin', 'vendor-alias'));
      linkSync(join(packageRoot, 'usr', 'bin', 'vendor-demo'), join(packageRoot, 'usr', 'bin', 'vendor-copy'));
      mkdirSync(join(packageRoot, 'usr', 'share', 'applications'), { recursive: true });
      writeFileSync(join(packageRoot, 'usr', 'share', 'applications', 'vendor-demo.desktop'), '[Desktop Entry]\nName=Vendor Demo\nType=Application\n');
      mkdirSync(join(packageRoot, 'usr', 'share', 'doc', 'vendor-demo'), { recursive: true });
      writeFileSync(join(packageRoot, 'usr', 'share', 'doc', 'vendor-demo', 'LICENSE'), 'MIT\n');
      writeFileSync(join(packageRoot, 'usr', 'share', 'vendor-demo', 'payload.txt'), 'deb payload\n');
      const source = join(root, 'vendor-demo.deb');
      execFileSync('dpkg-deb', ['--build', packageRoot, source], { stdio: 'pipe' });
      const bytes = readFileSync(source);
      expect(detectVendorBinaryFormat(bytes)).toBe('deb');
      const manifest = inspect(source, join(root, 'workspace'));
      expect(manifest.format).toBe('deb');
      expect(manifest.surface).toBe('recipe');
      expect(manifest.metadata).toEqual({ package: 'vendor-demo', version: '1.2.3', architecture: 'all' });
      expect(manifest.entries?.some((entry) => entry.path === 'usr/share/vendor-demo/payload.txt')).toBe(true);
      expect(manifest.entries?.some((entry) => entry.kind === 'symlink' && entry.path === 'usr/bin/vendor-alias' && entry.target === 'vendor-demo')).toBe(true);
      expect(manifest.entries?.some((entry) => entry.kind === 'hardlink' && entry.path === 'usr/bin/vendor-demo' && entry.target === 'usr/bin/vendor-copy')).toBe(true);
      const payloadEntries = manifest.entries ?? [];
      expect(manifest.controlEntriesPath).toBe(join(root, 'workspace', 'vendor-artifact', 'control.entries'));
      const payloadListing = execFileSync('bsdtar', ['-tvf', join(root, 'workspace', 'vendor-artifact', 'payload.tar')], { encoding: 'utf8' });
      expect(payloadListing).toContain('vendor-alias -> vendor-demo');
      expect(payloadListing).toContain('vendor-demo link to ./usr/bin/vendor-copy');
      expect(vendorArtifactInventory(payloadEntries).slice(0, 2)).toEqual([
        'usr/share/applications/vendor-demo.desktop',
        'usr/share/doc/vendor-demo/LICENSE',
      ]);
      expect(assertVendorArtifactReadPaths(payloadEntries, [
        'usr/share/applications/vendor-demo.desktop',
        'usr/share/doc/vendor-demo/LICENSE',
      ])).toHaveLength(2);
      expect(() => assertVendorArtifactReadPaths(payloadEntries, ['usr/bin/vendor-demo'])).toThrow();
      const readOutput = execFileSync('bash', ['-c', vendorArtifactReadCommand(payloadEntries, [
        'usr/share/applications/vendor-demo.desktop',
        'usr/share/doc/vendor-demo/LICENSE',
      ], {
        workspaceRoot: join(root, 'workspace'),
        rootPath: join(root, 'workspace', 'vendor-artifact', 'payload-root'),
      })], { encoding: 'utf8' });
      expect(readOutput).toContain('Name=Vendor Demo');
      expect(readOutput).toContain('MIT');
      const controlEntries = parseVendorArtifactManifestEntries(readFileSync(join(root, 'workspace', 'vendor-artifact', 'control.entries'), 'utf8'));
      const controlOutput = execFileSync('bash', ['-c', vendorArtifactReadCommand(controlEntries, ['control', 'postinst'], {
        workspaceRoot: join(root, 'workspace'),
        rootPath: join(root, 'workspace', 'vendor-artifact', 'control'),
      })], { encoding: 'utf8' });
      expect(controlOutput).toContain('Package: vendor-demo');
      expect(controlOutput).toContain('touch');
      expect(existsSync(marker)).toBe(false);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  test('keeps self-extracting artifacts with no online payload inventory inspectable', () => {
    expect(vendorArtifactInventory([])).toEqual([]);
  });

  test('detects and inspects a real RPM payload through cpio without scriptlets', () => {
    const root = mkdtempSync(join(tmpdir(), 'omarpkg-rpm-'));
    try {
      const source = join(root, 'vendor-demo.rpm');
      writeFileSync(source, rpmFixture());
      const stubBin = join(root, 'bin');
      mkdirSync(stubBin);
      writeFileSync(join(stubBin, 'rpm'), '#!/bin/sh\ncase "$*" in *--queryformat*) printf "vendor-demo\\n1.0\\n1\\nx86_64\\n";; *) exit 1;; esac\n');
      chmodSync(join(stubBin, 'rpm'), 0o755);
      expect(detectVendorBinaryFormat(readFileSync(source))).toBe('rpm');
      const manifest = inspect(source, join(root, 'workspace'), `${stubBin}:${process.env.PATH ?? ''}`);
      expect(manifest.format).toBe('rpm');
      expect(manifest.metadata.package).toBe('vendor-demo');
      expect(manifest.entries?.some((entry) => entry.path === 'usr/share/vendor-demo.txt')).toBe(true);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  test('rejects a Debian payload symlink that escapes the extraction root', () => {
    const root = mkdtempSync(join(tmpdir(), 'omarpkg-deb-escape-'));
    const packageRoot = join(root, 'package');
    try {
      mkdirSync(join(packageRoot, 'DEBIAN'), { recursive: true });
      mkdirSync(join(packageRoot, 'usr', 'bin'), { recursive: true });
      writeFileSync(join(packageRoot, 'DEBIAN', 'control'), 'Package: vendor-escape\nVersion: 1\nArchitecture: all\nDescription: test\n\n');
      symlinkSync('../../../outside', join(packageRoot, 'usr', 'bin', 'escape'));
      const source = join(root, 'vendor-escape.deb');
      execFileSync('dpkg-deb', ['--build', packageRoot, source], { stdio: 'pipe' });
      expect(() => inspect(source, join(root, 'workspace'))).toThrow();

      const chainRoot = join(root, 'chain-package');
      mkdirSync(join(chainRoot, 'DEBIAN'), { recursive: true });
      mkdirSync(join(chainRoot, 'usr', 'bin'), { recursive: true });
      writeFileSync(join(chainRoot, 'DEBIAN', 'control'), 'Package: vendor-chain\nVersion: 1\nArchitecture: all\nDescription: test\n\n');
      symlinkSync('../../c', join(chainRoot, 'usr', 'bin', 'a'));
      symlinkSync('a/../../outside', join(chainRoot, 'usr', 'bin', 'x'));
      const chainSource = join(root, 'vendor-chain.deb');
      execFileSync('dpkg-deb', ['--build', chainRoot, chainSource], { stdio: 'pipe' });
      expect(() => inspect(chainSource, join(root, 'chain-workspace'))).toThrow();
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  test('detects both AppImage types from ELF and validated filesystem magic', () => {
    const root = mkdtempSync(join(tmpdir(), 'omarpkg-appimage-'));
    try {
      for (const type of [1, 2] as const) {
        const source = appImageFixture(root, type);
        const bytes = readFileSync(source);
        expect(detectVendorBinaryFormat(bytes)).toBe(type === 1 ? 'appimage1' : 'appimage2');
        if (type === 2) expect(appImageSquashfsOffset(bytes)).toBeGreaterThan(0);
        const manifest = inspect(source, join(root, `workspace-${type}`));
        expect(manifest.format).toBe(type === 1 ? 'appimage1' : 'appimage2');
        expect(manifest.metadata.entrypoint).toBe('AppRun');
        expect(manifest.metadata.architecture).toBe('x86_64');
        expect(manifest.entries?.some((entry) => entry.path === 'AppRun' && entry.kind === 'symlink')).toBe(true);
      }
      for (const type of [1, 2] as const) {
        const source = appImageFixture(join(root, 'escape'), type, true);
        expect(() => inspect(source, join(root, `escape-workspace-${type}`))).toThrow();
      }
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  test('inspects a self-extracting NVIDIA-style run file without executing it online', () => {
    const root = mkdtempSync(join(tmpdir(), 'omarpkg-run-'));
    const marker = join(root, 'installed-marker');
    try {
      const source = join(root, 'NVIDIA-Linux-x86_64.run');
      writeFileSync(source, `#!/bin/sh\n# NVIDIA-Linux-x86_64 Makeself self-extracting archive\nif [ "$1" = --extract-only ]; then test "$2" = --target; test ! -e "$3"; mkdir -p "$3"; printf extracted > "$3/payload.txt"; exit 0; fi\ntouch ${marker}\n`);
      chmodSync(source, 0o755);
      const manifest = inspect(source, join(root, 'workspace'));
      expect(manifest.format).toBe('run');
      expect(manifest.surface).toBe('recipe');
      expect(manifest.payloadPath).toBeNull();
      expect(manifest.metadata.architecture).toBe('x86_64');
      expect(existsSync(marker)).toBe(false);
      const checksum = execFileSync('sha256sum', [source], { encoding: 'utf8' }).trim().split(/\s+/, 1)[0];
      const destination = join(root, 'offline-root');
      run(offlineVendorExtractCommand('run', { sourcePath: source, destination, sha256: checksum }));
      expect(readFileSync(join(destination, 'payload.txt'), 'utf8')).toBe('extracted');
      expect(existsSync(marker)).toBe(false);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  test('rejects unsafe archive paths and defaults vendor artifacts to recipe surface', () => {
    expect(() => validateArchiveEntries(['safe/file', '../escape'])).toThrow();
    expect(() => validateArchiveEntries(['safe', 'safe'])).toThrow();
    expect(vendorSurface()).toBe('recipe');
    expect(vendorSurface('license grant: redistribute')).toBe('binary');
  });

  test('reads a logical absolute package link through its verified target without using host paths', () => {
    const root = mkdtempSync(join(tmpdir(), 'omarpkg-vendor-read-'));
    try {
      const payloadRoot = join(root, 'payload-root');
      mkdirSync(join(payloadRoot, 'opt', 'vendor'), { recursive: true });
      writeFileSync(join(payloadRoot, 'opt', 'vendor', 'app'), 'logical package target\n');
      symlinkSync('/opt/vendor/app', join(payloadRoot, 'AppRun'));
      const entries = [
        { path: 'opt', kind: 'directory' as const, size: 0, target: null },
        { path: 'opt/vendor', kind: 'directory' as const, size: 0, target: null },
        { path: 'opt/vendor/app', kind: 'file' as const, size: 22, target: null },
        { path: 'AppRun', kind: 'symlink' as const, size: 0, target: '/opt/vendor/app' },
      ];
      const output = execFileSync('bash', ['-c', vendorArtifactReadCommand(entries, ['AppRun'], {
        workspaceRoot: root,
        rootPath: payloadRoot,
      })], { encoding: 'utf8' });
      expect(output).toContain('logical package target');
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
});
