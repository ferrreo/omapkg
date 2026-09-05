import { describe, expect, test } from 'bun:test';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { lintRecipe, renderPublicRecipe, renderRecipe } from '../services/pipeline/recipe';
import { normalizeCandidate } from '../services/pipeline/revision';
import type { FactoryCandidate } from '../services/pipeline/types';
import { factoryCandidateInputSchema, makeReadSourceFilesTool, makeSourceMaterializer, makeSubmitCandidateTool } from '../services/pipeline/tools';

const image = `ghcr.io/opr/builder@sha256:${'a'.repeat(64)}`;

function candidate(overrides: Partial<FactoryCandidate> = {}): FactoryCandidate {
  return {
    request: {
      id: 'request-recipe', name: 'demo', upstreamUrl: 'https://example.test/demo-1.0.0.tar.gz',
      sourceKind: 'archive', area: 'development', declaredLicense: 'unknown',
    },
    version: '1.0.0',
    sources: [{ name: 'demo-1.0.0.tar.gz', url: 'https://example.test/demo-1.0.0.tar.gz', sha256: 'b'.repeat(64) }],
    sourceRoot: 'demo-1.0.0',
    dependencies: [],
    makeDependencies: [],
    smokeCommands: ['demo --version'],
    architectures: ['x86_64'],
    buildImages: { x86_64: image },
    pkgrel: 1,
    sourceDateEpoch: 1,
    imageDigest: image,
    license: 'MIT',
    surface: 'binary',
    description: 'A small demo package.',
    buildCommands: ['./configure --prefix=/usr', 'make'],
    packageCommands: ['make install DESTDIR="$pkgdir"'],
    explanation: 'Verified demo source.',
    ...overrides,
  };
}

describe('generated recipe source roots', () => {
  test('rejects missing builder architectures instead of silently dropping them', async () => {
    const value = candidate({ architectures: ['x86_64', 'aarch64'] });
    let emitted = false;
    const tool = makeSubmitCandidateTool(value.request, () => { emitted = true; }, () => ({
      sourceKind: 'archive', upstreamUrl: value.request.upstreamUrl, normalizedUrl: value.request.upstreamUrl,
      sourceName: value.sources[0].name, sourceSha256: value.sources[0].sha256,
      upstreamCommit: null, files: [], licenseFiles: [],
    }), { x86_64: image });
    await expect(tool.run({ data: value } as unknown as Parameters<typeof tool.run>[0])).rejects.toThrow('aarch64');
    expect(emitted).toBe(false);
  });

  test('enters wrapped archive root before build and package commands', () => {
    const recipe = renderRecipe(candidate());
    const buildRoot = recipe.indexOf('cd "$srcdir/demo-1.0.0"');
    const configure = recipe.indexOf('./configure');
    const packageRoot = recipe.lastIndexOf('cd "$srcdir/demo-1.0.0"');
    expect(buildRoot).toBeGreaterThan(-1);
    expect(buildRoot).toBeLessThan(configure);
    expect(packageRoot).toBeGreaterThan(configure);
    expect(lintRecipe(recipe).passed).toBe(true);
  });

  test('rejects package staging from build and source-root resets', () => {
    const invalid = renderRecipe(candidate({ buildCommands: ['make DESTDIR="$pkgdir"'] }));
    const lint = lintRecipe(invalid);
    expect(lint.passed).toBe(false);
    expect(lint.checks.find((check) => check.name === 'package staging only in package()')?.passed).toBe(false);
    expect(() => renderRecipe(candidate({ buildCommands: ['cd "$srcdir";', 'make'] }))).toThrow('commands must remain relative to the verified source root');
  });

  test('allows relative subdirectory changes inside verified root', () => {
    expect(() => renderRecipe(candidate({ buildCommands: ['cd src', 'make'] }))).not.toThrow();
  });

  test('ignores network words in metadata and filenames while rejecting network commands', () => {
    const metadata = candidate({
      request: { ...candidate().request, name: 'curl' },
      sources: [{ name: 'curl-1.0.tar.gz', url: 'https://example.test/curl-1.0.tar.gz', sha256: 'b'.repeat(64) }],
      sourceRoot: 'curl-1.0',
      description: 'A curl client package.',
      packageCommands: ['install -Dm755 build/sudo "$pkgdir/usr/bin/sudo"'],
    });
    expect(lintRecipe(renderRecipe(metadata)).passed).toBe(true);
    expect(lintRecipe(renderRecipe(candidate({ buildCommands: ['curl https://example.test/tool'] }))).passed).toBe(false);
  });

  test('allows dd used by an offline AppImage extraction prelude', () => {
    const recipe = renderRecipe(candidate({ buildCommands: ['dd if="$srcdir/app.AppImage" of="$srcdir/app.copy"'] }));
    expect(lintRecipe(recipe).passed).toBe(true);
  });

  test('reads vendor control and payload files through the bounded artifact reader', async () => {
    const payloadEntries = [{ path: 'usr/share/demo/README', kind: 'file' as const, size: 7, target: null }];
    const controlEntries = [{ path: 'control', kind: 'file' as const, size: 7, target: null }];
    const buffers: Record<string, Uint8Array> = {
      '/workspace/vendor-artifact/entries.tsv': new TextEncoder().encode('file\tusr/share/demo/README\t7\t\n'),
      '/workspace/vendor-artifact/control.entries': new TextEncoder().encode('file\tcontrol\t7\t\n'),
    };
    const commands: string[] = [];
    const sandbox = {
      exec: async (command: string) => {
        commands.push(command);
        if (command.startsWith('#!/usr/bin/env bash')) return {
          stdout: command.includes('/workspace/vendor-artifact/control') ? 'payload\ncontrol' : 'payload',
          stderr: '', exitCode: 0,
        };
        return { stdout: '', stderr: '', exitCode: 0 };
      },
      readFileBuffer: async (path: string) => buffers[path] ?? new Uint8Array(),
    };
    const evidence = {
      sourceKind: 'archive' as const, upstreamUrl: 'https://example.test/demo.deb', normalizedUrl: 'https://example.test/demo.deb',
      sourceName: 'demo.deb', sourceSha256: 'a'.repeat(64), upstreamCommit: null, files: [], licenseFiles: [],
      vendorArtifact: {
        schemaVersion: 1 as const, format: 'deb' as const, surface: 'recipe' as const,
        sourcePath: '/workspace/source.bundle', sourceSize: 1, sourceSha256: 'a'.repeat(64),
        payloadPath: '/workspace/vendor-artifact/payload.tar', entriesPath: '/workspace/vendor-artifact/entries.tsv',
        controlPath: '/workspace/vendor-artifact/control.tar', controlEntriesPath: '/workspace/vendor-artifact/control.entries',
        metadata: { package: 'demo', version: '1.0', architecture: 'all' }, entries: payloadEntries,
      },
    };
    const tool = makeReadSourceFilesTool(() => evidence);
    const result = await tool.run({ data: { paths: ['usr/share/demo/README', 'control'] }, harness: { sandbox }, signal: new AbortController().signal } as unknown as Parameters<typeof tool.run>[0]);
    expect(result.output.text).toContain('payload');
    expect(result.output.text).toContain('control');
    expect(commands.some((command) => command.includes('/workspace/vendor-artifact/payload-root'))).toBe(true);
    expect(commands.some((command) => command.includes('/workspace/vendor-artifact/control'))).toBe(true);
  });

  test('normalizes native Arch dependency constraints and rejects malformed pkgver', () => {
    const normalized = normalizeCandidate(candidate({ dependencies: ['libfoo>=2.0-1'], makeDependencies: ['base-devel=1:2.0'] }));
    expect(normalized.dependencies).toEqual(['libfoo>=2.0-1']);
    expect(normalized.makeDependencies).toEqual(['base-devel=1:2.0']);
    expect(() => normalizeCandidate(candidate({ dependencies: ['libfoo>>2'] }))).toThrow('invalid Arch dependency');
    expect(() => normalizeCandidate(candidate({ version: '1-rc1' }))).toThrow('invalid Arch pkgver');
  });

  test('rejects packaging variables from installed smoke commands', () => {
    for (const command of [
      '$pkgdir/usr/bin/hello --version',
      '${pkgdir}/usr/bin/hello --version',
      '$srcdir/hello --version',
      '${pkgname} --version',
      '$pkgver',
      '$pkgrel',
      '$CHOST',
      '${CARCH}',
    ]) {
      expect(() => normalizeCandidate(candidate({ smokeCommands: [command] }))).toThrow('smoke command must use installed paths');
    }
    expect(normalizeCandidate(candidate({ smokeCommands: ['/usr/bin/hello --version'] })).smokeCommands).toEqual(['/usr/bin/hello --version']);
  });

  test('rejects uncompressed makepkg man/info assertions but allows compressed paths and fallbacks', () => {
    expect(() => normalizeCandidate(candidate({ smokeCommands: ['test -f /usr/share/man/man1/hello.1'] }))).toThrow('compressed man/info paths');
    expect(() => normalizeCandidate(candidate({ smokeCommands: ['[ -f /usr/share/info/hello.info ]'] }))).toThrow('compressed man/info paths');
    expect(normalizeCandidate(candidate({ smokeCommands: ['test -f /usr/share/man/man1/hello.1.gz'] })).smokeCommands).toEqual(['test -f /usr/share/man/man1/hello.1.gz']);
    expect(normalizeCandidate(candidate({ smokeCommands: ['test -f /usr/share/man/man1/hello.1.gz || test -f /usr/share/man/man1/hello.1'] })).smokeCommands).toEqual(['test -f /usr/share/man/man1/hello.1.gz || test -f /usr/share/man/man1/hello.1']);
    expect(normalizeCandidate(candidate({ smokeCommands: ['man hello'] })).smokeCommands).toEqual(['man hello']);
    expect(normalizeCandidate(candidate({ smokeCommands: ['test -d /usr/share/man/man1'] })).smokeCommands).toEqual(['test -d /usr/share/man/man1']);
  });

  test('public Git recipe recreates and verifies the native sealed archive', () => {
    const root = mkdtempSync(join(tmpdir(), 'omapkg-public-git-'));
    try {
      execFileSync('git', ['init', root], { stdio: 'pipe' });
      execFileSync('git', ['-C', root, 'config', 'user.email', 'test@example.invalid'], { stdio: 'pipe' });
      execFileSync('git', ['-C', root, 'config', 'user.name', 'OPR test'], { stdio: 'pipe' });
      writeFileSync(join(root, 'README.md'), 'public source\n');
      execFileSync('git', ['-C', root, 'add', 'README.md'], { stdio: 'pipe' });
      execFileSync('git', ['-C', root, 'commit', '-m', 'initial'], {
        stdio: 'pipe',
        env: { ...process.env, GIT_AUTHOR_DATE: '2020-01-01T00:00:00Z', GIT_COMMITTER_DATE: '2020-01-01T00:00:00Z' },
      });
      const commit = execFileSync('git', ['-C', root, 'rev-parse', 'HEAD'], { encoding: 'utf8' }).trim();
      const archive = execFileSync('git', ['-C', root, 'archive', '--format=tar', 'HEAD']);
      const sourceSha256 = createHash('sha256').update(archive).digest('hex');
      const sourceName = `demo-${commit.slice(0, 12)}.tar`;
      const recipe = renderPublicRecipe(candidate({
        request: { ...candidate().request, sourceKind: 'git', upstreamUrl: 'https://example.org/demo.git' },
        surface: 'recipe', sourceRoot: undefined,
      }), {
        sourceKind: 'git', sourceUrl: 'https://example.org/demo.git', sourceName, sourceSha256, upstreamCommit: commit,
      });
      expect(recipe).toContain(`git+https://example.org/demo.git#commit=${commit}`);
      expect(recipe).toContain(`'${sourceSha256}'`);
      expect(recipe).not.toContain('/sources/');
      const prepare = recipe.match(/prepare\(\) \{([\s\S]*?)\n\}/)?.[1];
      if (!prepare) throw new Error('public Git recipe has no prepare function');
      const srcdir = join(root, 'srcdir');
      mkdirSync(srcdir);
      execFileSync('git', ['clone', root, join(srcdir, 'demo-git')], { stdio: 'pipe' });
      execFileSync('bash', ['-euc', prepare], { stdio: 'pipe', env: { ...process.env, srcdir } });
      expect(readFileSync(join(srcdir, 'README.md'), 'utf8')).toBe('public source\n');
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  test('public vendored recipe rebuilds locked dependencies in prepare without private URLs', () => {
    const publicRecipe = renderPublicRecipe(candidate({
      surface: 'recipe', sourceRoot: 'demo-1.0',
      sources: [
        { name: 'demo-1.0.tar.gz', url: 'https://example.org/demo-1.0.tar.gz', sha256: 'b'.repeat(64) },
        { name: 'opr-vendor-go.tar', url: `https://opr.example/sources/${'a'.repeat(64)}.tar`, sha256: 'a'.repeat(64) },
      ],
    }), {
      sourceKind: 'archive', sourceUrl: 'https://example.org/demo-1.0.tar.gz', sourceName: 'demo-1.0.tar.gz',
      sourceSha256: 'b'.repeat(64), sourceRoot: 'demo-1.0', vendorKind: 'go', vendorSha256: 'a'.repeat(64),
    });
    expect(publicRecipe).not.toContain('/sources/');
    expect(publicRecipe).toContain('go mod download');
    expect(publicRecipe).toContain('go mod verify');
    expect(publicRecipe).toContain('go mod vendor');
    expect(publicRecipe).toContain(`'${'a'.repeat(64)}'`);
    expect(publicRecipe.indexOf('prepare() {')).toBeLessThan(publicRecipe.indexOf('build() {'));
    expect(lintRecipe(publicRecipe).passed).toBe(true);
  });

  test('candidate submission binds the public Git recipe separately from worker recipe', async () => {
    const commit = 'c'.repeat(40);
    const sourceSha256 = 'd'.repeat(64);
    const value = candidate({
      request: { ...candidate().request, sourceKind: 'git', upstreamUrl: 'https://example.org/demo.git' },
      sourceRoot: undefined, surface: 'recipe', upstreamCommit: commit,
      sources: [{ name: 'demo-deadbeefdead.tar', url: `https://opr.example/sources/${sourceSha256}.tar`, sha256: sourceSha256 }],
    });
    let emitted: FactoryCandidate | undefined;
    const tool = makeSubmitCandidateTool(value.request, (next) => { emitted = next as FactoryCandidate; }, () => ({
      sourceKind: 'git', upstreamUrl: value.request.upstreamUrl, normalizedUrl: value.sources[0].url,
      sourceName: value.sources[0].name, sourceSha256, upstreamCommit: commit, files: [], licenseFiles: [],
    }), value.buildImages);
    const result = await tool.run({ data: value } as unknown as Parameters<typeof tool.run>[0]);
    expect(result.output.publicRecipeSha256).toMatch(/^[0-9a-f]{64}$/);
    expect(emitted?.publicRecipe).toContain(`git+${value.request.upstreamUrl}#commit=${commit}`);
    expect(emitted?.publicRecipe).not.toContain('/sources/');
    expect(emitted?.sources[0]?.url).toContain('/sources/');
  });

  test('candidate submission accepts the inspected source and verified vendor bundle', async () => {
    const vendorSha256 = 'c'.repeat(64);
    const vendorSource = { name: 'opr-vendor-go.tar', url: `https://opr.example/sources/${vendorSha256}.tar`, sha256: vendorSha256 };
    const value = candidate({ sources: [candidate().sources[0], vendorSource] });
    let emitted: FactoryCandidate | undefined;
    const tool = makeSubmitCandidateTool(value.request, (next) => { emitted = next as FactoryCandidate; }, () => ({
      sourceKind: 'archive', upstreamUrl: value.request.upstreamUrl, normalizedUrl: value.sources[0].url,
      sourceName: value.sources[0].name, sourceSha256: value.sources[0].sha256, upstreamCommit: null, files: [], licenseFiles: [],
      vendor: {
        kind: 'go', sourceName: vendorSource.name, sourceSha256: vendorSha256, sourceUrl: vendorSource.url,
        sourceKey: `sources/${vendorSha256}.tar`, components: [],
      },
    }), value.buildImages);
    await expect(tool.run({ data: value } as unknown as Parameters<typeof tool.run>[0])).resolves.toBeDefined();
    expect(emitted?.sources).toEqual(value.sources);
  });

  test('candidate tool omits internal vendor metadata and injects inspected evidence', async () => {
    expect((factoryCandidateInputSchema as unknown as { entries: Record<string, unknown> }).entries.vendorArtifact).toBeUndefined();
    const trustedArtifact = {
      schemaVersion: 1 as const, format: 'deb' as const, surface: 'recipe' as const,
      sourcePath: '/workspace/source.bundle', sourceSize: 1, sourceSha256: candidate().sources[0].sha256,
      payloadPath: null, entriesPath: null, controlPath: null, controlEntriesPath: null,
      metadata: { package: 'demo', version: '1.0.0', architecture: 'all' },
    };
    const value = candidate({ vendorArtifact: { ...trustedArtifact, schemaVersion: 2 as never } });
    let emitted: FactoryCandidate | undefined;
    const tool = makeSubmitCandidateTool(value.request, (next) => { emitted = next as FactoryCandidate; }, () => ({
      sourceKind: 'archive', upstreamUrl: value.request.upstreamUrl, normalizedUrl: value.sources[0].url,
      sourceName: value.sources[0].name, sourceSha256: value.sources[0].sha256, upstreamCommit: null, files: [], licenseFiles: [],
      vendorArtifact: trustedArtifact,
    }), value.buildImages);
    await expect(tool.run({ data: value } as unknown as Parameters<typeof tool.run>[0])).resolves.toBeDefined();
    expect(emitted?.vendorArtifact).toEqual(trustedArtifact);
  });

  test('candidate tool rejects duplicate .run extraction after renderer staging', async () => {
    const trustedArtifact = {
      schemaVersion: 1 as const, format: 'run' as const, surface: 'recipe' as const,
      sourcePath: '/workspace/source.bundle', sourceSize: 1, sourceSha256: candidate().sources[0].sha256,
      payloadPath: null, entriesPath: null, controlPath: null, controlEntriesPath: null,
      metadata: { architecture: 'x86_64' },
    };
    for (const commands of [
      { buildCommands: ['sh NVIDIA.run --extract-only --target "$srcdir/vendor-root"'] },
      { packageCommands: ['sh NVIDIA.run --extract-only --target "$srcdir/vendor-root"'] },
    ]) {
      const value = candidate({ ...commands, vendorArtifact: trustedArtifact });
      let emitted = false;
      const tool = makeSubmitCandidateTool(value.request, () => { emitted = true; }, () => ({
        sourceKind: 'archive', upstreamUrl: value.request.upstreamUrl, normalizedUrl: value.sources[0].url,
        sourceName: value.sources[0].name, sourceSha256: value.sources[0].sha256, upstreamCommit: null, files: [], licenseFiles: [],
        vendorArtifact: trustedArtifact,
      }), value.buildImages);
      await expect(tool.run({ data: value } as unknown as Parameters<typeof tool.run>[0])).rejects.toThrow(/already extracted.*vendor-root/);
      expect(emitted).toBe(false);
    }
  });

  test('candidate submission rejects extra sources that were not inspected', async () => {
    const value = candidate({ sources: [
      ...candidate().sources,
      { name: 'unreviewed.tar.gz', url: 'https://unreviewed.example/source.tar.gz', sha256: 'e'.repeat(64) },
    ] });
    let emitted = false;
    const tool = makeSubmitCandidateTool(value.request, () => { emitted = true; }, () => ({
      sourceKind: 'archive', upstreamUrl: value.request.upstreamUrl, normalizedUrl: value.sources[0].url,
      sourceName: value.sources[0].name, sourceSha256: value.sources[0].sha256, upstreamCommit: null, files: [], licenseFiles: [],
    }), value.buildImages);
    await expect(tool.run({ data: value } as unknown as Parameters<typeof tool.run>[0])).rejects.toThrow('unverified source');
    expect(emitted).toBe(false);
  });

  test('materializes Git source archives with a fixed-length, checksum-verified R2 body', async () => {
    const bytes = new TextEncoder().encode('hello');
    const sourceSha256 = createHash('sha256').update(bytes).digest('hex');
    const metadata = `schemaVersion=1\nformat=tar\nsourcePath=/workspace/source.tar\nsourceSize=${bytes.byteLength}\nsourceSha256=${sourceSha256}\nexpandedSize=${bytes.byteLength}\n`;
    const entries = 'file\tREADME.md\t5\t\n';
    const encoder = new TextEncoder();
    const readables = new Set<ReadableStream<Uint8Array>>();
    class TestFixedLengthStream {
      readonly readable: ReadableStream<Uint8Array>;
      readonly writable: WritableStream<Uint8Array>;
      constructor(expectedLength: number) {
        let written = 0;
        const stream = new TransformStream<Uint8Array, Uint8Array>({
          transform(chunk, controller) {
            written += chunk.byteLength;
            if (written > expectedLength) throw new Error('fixed stream received too many bytes');
            controller.enqueue(chunk);
          },
          flush() {
            if (written !== expectedLength) throw new Error('fixed stream received too few bytes');
          },
        });
        this.readable = stream.readable;
        this.writable = stream.writable;
        readables.add(this.readable);
      }
    }
    const previousFixedLengthStream = (globalThis as unknown as { FixedLengthStream?: unknown }).FixedLengthStream;
    (globalThis as unknown as { FixedLengthStream: unknown }).FixedLengthStream = TestFixedLengthStream;
    const puts: Array<{ key: string; value: ReadableStream<Uint8Array>; options: { sha256?: string } }> = [];
    let rejectPut = false;
    let cleanupCount = 0;
    const sandbox = {
      exec: async (command: string | string[]) => {
        const text = Array.isArray(command) ? command.join('\n') : command;
        if (text.includes('split -b 4194304')) return { stdout: `size=${bytes.byteLength}\nsha256=${sourceSha256}\nparts=1\n`, stderr: '', exitCode: 0 };
        if (text.includes('rm -f /workspace/.opr-vendor-part-*')) cleanupCount += 1;
        return { stdout: '', stderr: '', exitCode: 0 };
      },
      readFileBuffer: async (path: string) => {
        if (path.endsWith('source-archive.meta')) return encoder.encode(metadata);
        if (path.endsWith('source-archive.entries')) return encoder.encode(entries);
        if (path.endsWith('.opr-vendor-part-000000')) return bytes;
        throw new Error(`unexpected sandbox read: ${path}`);
      },
    };
    const artifacts = {
      head: async () => null,
      put: async (key: string, value: ReadableStream<Uint8Array>, options: { sha256?: string }) => {
        puts.push({ key, value, options });
        expect(readables.has(value)).toBe(true);
        expect(options.sha256).toBe(sourceSha256);
        if (rejectPut) {
          await value.cancel();
          throw new Error('r2 rejected before consuming body');
        }
        expect(new Uint8Array(await new Response(value).arrayBuffer())).toEqual(bytes);
        return null;
      },
    };
    const db = { prepare: () => ({ bind: () => ({}) }), batch: async () => [] };
    const materialize = makeSourceMaterializer({ DB: db as unknown as D1Database, ARTIFACTS: artifacts as unknown as R2Bucket, PUBLIC_ORIGIN: 'https://omapkg.example' });
    const request = {
      id: 'request-stream', name: 'demo', upstreamUrl: 'https://example.org/demo.git', sourceKind: 'git' as const, area: 'development' as const, declaredLicense: 'unknown',
    };
    const evidence = {
      sourceKind: 'git' as const, upstreamUrl: 'https://example.org/demo.git', normalizedUrl: 'https://example.org/demo.git',
      sourceName: 'demo-git.tar', sourceSha256, upstreamCommit: 'a'.repeat(40), files: [], licenseFiles: [],
    };
    const sandboxValue = sandbox as unknown as Parameters<ReturnType<typeof makeSourceMaterializer>>[2];
    try {
      await materialize(request, evidence, sandboxValue);
      expect(puts).toHaveLength(1);
      rejectPut = true;
      await expect(materialize(request, evidence, sandboxValue)).rejects.toThrow('r2 rejected before consuming body');
      expect(puts).toHaveLength(2);
      expect(cleanupCount).toBe(2);
    } finally {
      if (previousFixedLengthStream === undefined) delete (globalThis as unknown as { FixedLengthStream?: unknown }).FixedLengthStream;
      else (globalThis as unknown as { FixedLengthStream: unknown }).FixedLengthStream = previousFixedLengthStream;
    }
  });

  test('constrains prebuilt candidate architectures before revision generation', () => {
    const normalized = normalizeCandidate(candidate({
      architectures: ['x86_64', 'aarch64'],
      buildImages: { x86_64: image, aarch64: image },
      vendorArtifact: {
        schemaVersion: 1,
        format: 'deb',
        surface: 'recipe',
        sourcePath: '/workspace/source.bundle',
        sourceSize: 1,
        sourceSha256: 'b'.repeat(64),
        payloadPath: null,
        entriesPath: null,
        controlPath: null,
        metadata: { package: 'demo', version: '1.0.0', architecture: 'amd64' },
      },
    }));
    expect(normalized.architectures).toEqual(['x86_64']);
    expect(normalized.buildImages).toEqual({ x86_64: image });
    expect(() => normalizeCandidate(candidate({
      architectures: ['aarch64'],
      buildImages: { aarch64: image },
      vendorArtifact: {
        schemaVersion: 1,
        format: 'deb',
        surface: 'recipe',
        sourcePath: '/workspace/source.bundle',
        sourceSize: 1,
        sourceSha256: 'b'.repeat(64),
        payloadPath: null,
        entriesPath: null,
        controlPath: null,
        metadata: { package: 'demo', version: '1.0.0', architecture: 'amd64' },
      },
    }))).toThrow(/does not match/);
  });
});
