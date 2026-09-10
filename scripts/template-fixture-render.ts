import { createHash } from 'node:crypto';
import { renderRecipe } from '../services/pipeline/recipe';
import type { FactoryCandidate } from '../services/pipeline/types';
import type { TypedRecipeTemplate } from '../services/pipeline/typed-templates';

type Request = {
  id: string;
  sourceName: string;
  sourceSha256: string;
  architecture: 'x86_64' | 'aarch64';
  locks?: Array<{ name: string; sha256: string; kind: 'source' | 'vendor' | 'toolchain' | 'runtime' }>;
  appimageOffset?: number;
  plainInstallTarget?: string;
};

const imageDigest = `ghcr.io/opr/builder@sha256:${'a'.repeat(64)}`;

const hash = (value: string): string => createHash('sha256').update(value).digest('hex');

function runtimeDependencies(id: string, architecture: 'x86_64' | 'aarch64'): string[] {
  if (id.startsWith('node-')) return ['nodejs'];
  if (id === 'python-v1') return ['python', 'glibc', 'gcc-libs'];
  if (id === 'electron-v1') return [architecture === 'aarch64' ? 'electron43-arm-runtime' : 'electron43', 'bash'];
  if (id === 'script-data-v1') return ['bash'];
  return ['bash', 'glibc', 'gcc-libs'];
}

type TemplateFixture = { value: TypedRecipeTemplate; vendorArtifact?: FactoryCandidate['vendorArtifact'] };

function sourceRoot(name: string): string | undefined {
  return name.endsWith('.tar.gz') ? name.slice(0, -'.tar.gz'.length) : undefined;
}

function template(input: Request): TemplateFixture {
  const root = sourceRoot(input.sourceName);
  const binary = 'demo';
  const common = input.locks ? { inputs: input.locks } : {};

  switch (input.id) {
    case 'autotools-v1': case 'autotools-autoreconf-v1': return { value: { id: 'autotools-v1', binary, sourceMode: input.id === 'autotools-autoreconf-v1' ? 'autoreconf' : 'release-tarball', tests: true, ...common } };
    case 'plain-make-v1': return { value: { id: input.id, binary, buildTarget: 'all', checkTarget: 'test', installTarget: input.plainInstallTarget ?? 'install', ...common } };
    case 'cmake-v1': return { value: { id: input.id, binary, generator: 'ninja', buildType: 'none', tests: true, ...common } };
    case 'meson-v1': return { value: { id: input.id, binary, buildType: 'plain', tests: true, ...common } };
    case 'rust-v1': return { value: { id: input.id, binary: 'app', profile: 'release', tests: true, workspace: true, outputs: [{ name: 'app', source: 'target/release/app', destination: '/usr/bin/app', mode: '0755', architecture: 'target' }, { name: 'tool', source: 'target/release/tool', destination: '/usr/bin/tool', mode: '0755', architecture: 'target' }], ...common } };
    case 'python-v1': return { value: { id: input.id, wheel: `demo-1.0.0-cp314-cp314-linux_${input.architecture === 'aarch64' ? 'aarch64' : 'x86_64'}.whl`, backend: 'setuptools', nativeExtension: true, tests: false, bytecode: 'none', ...common } };
    case 'node-npm-v1': return { value: { id: input.id, binary, lockfile: 'package-lock.json', build: true, outputPath: 'index.js', outputs: [{ name: 'demo', source: 'index.js', destination: '/usr/share/demo/index.js', mode: '0644', architecture: 'target' }], ...common } };
    case 'node-pnpm-v1': return { value: { id: input.id, binary, lockfile: 'pnpm-lock.yaml', build: true, outputPath: 'index.js', outputs: [{ name: 'demo', source: 'index.js', destination: '/usr/share/demo/index.js', mode: '0644', architecture: 'target' }], ...common } };
    case 'node-yarn-v1': return { value: { id: input.id, binary, lockfile: 'yarn.lock', build: true, outputPath: 'index.js', outputs: [{ name: 'demo', source: 'index.js', destination: '/usr/share/demo/index.js', mode: '0644', architecture: 'target' }], ...common } };
    case 'electron-v1': return { value: { id: input.id, binary, appPath: 'app.js', desktopFile: 'demo.desktop', systemElectron: true, launchTest: true, outputs: [{ name: 'demo', source: 'app.js', destination: '/usr/lib/demo/app.js', mode: '0644', architecture: 'target' }], runtime: { kind: 'electron', path: '/usr/lib/demo/app.js', args: ['--no-sandbox', '--disable-gpu', '--disable-dev-shm-usage'] }, ...common } };
    case 'archive-v1': return { value: { id: input.id, binary, archivePath: input.sourceName, payloadPath: 'usr/bin/demo', ...common } };
    case 'script-data-v1': return { value: { id: input.id, sourcePath: `${root}/demo.txt`, destination: '/usr/share/demo/demo.txt', kind: 'data', runtime: { kind: 'file', path: '/usr/share/demo/demo.txt' }, ...common } };
    case 'go-v2': return { value: { id: input.id, binary, target: '.', profile: 'release', tests: true, workspace: true, cgo: true, ...common } };
    case 'deb-v1': case 'rpm-v1': case 'appimage-v1': case 'run-v1': {
      let format: 'deb' | 'rpm' | 'run' | 'appimage2' = 'appimage2';

      if (input.id === 'deb-v1') format = 'deb';
      else if (input.id === 'rpm-v1') format = 'rpm';
      else if (input.id === 'run-v1') format = 'run';
      const artifactArchitecture = input.architecture === 'aarch64' ? (format === 'deb' ? 'arm64' : 'aarch64') : (format === 'deb' ? 'amd64' : 'x86_64');

      return {
        value: { id: input.id, binary: 'payload', payloadPath: 'usr/share/demo/payload.txt', outputs: [{ name: 'demo', source: 'vendor-root/usr/share/demo/payload.txt', destination: '/usr/share/demo/payload.txt', mode: '0644', architecture: 'target' }], runtime: { kind: 'file', path: '/usr/share/demo/payload.txt' }, ...common },
        vendorArtifact: { schemaVersion: 1, format, surface: 'binary', sourcePath: '/workspace/source.bundle', sourceSize: 1, sourceSha256: input.sourceSha256, payloadPath: '/workspace/vendor-artifact/payload.tar', entriesPath: '/workspace/vendor-artifact/entries.tsv', controlPath: null, controlEntriesPath: null, appimageOffset: input.appimageOffset ?? null, metadata: { architecture: artifactArchitecture } },
      };
    }
  }
}

// SAFETY: stdin is the fixture contract consumed by this test-only renderer.
const input = JSON.parse(await Bun.stdin.text()) as Request;

const selected = template(input);

const source = { name: input.sourceName, url: `https://example.invalid/template/${input.sourceName}`, sha256: input.sourceSha256 };

const candidate: FactoryCandidate = {
  request: { id: `template-${input.id}`, name: `opr-template-${input.id}`, upstreamUrl: source.url, sourceKind: 'archive', area: 'development', declaredLicense: 'MIT' },
  version: '1.0.0', sources: [source], sourceRoot: sourceRoot(input.sourceName), dependencies: runtimeDependencies(input.id, input.architecture), makeDependencies: [], smokeCommands: [], architectures: [input.architecture], pkgrel: 1, sourceDateEpoch: 1_700_000_000, imageDigest, license: 'MIT', surface: 'binary', description: `typed ${input.id} fixture`, recipeMode: 'template', template: selected.value, vendorArtifact: selected.vendorArtifact, buildCommands: [], packageCommands: [], explanation: 'native template fixture',
};

const recipe = renderRecipe(candidate);

process.stdout.write(JSON.stringify({ sourceSha256: input.sourceSha256, recipeSha256: hash(recipe), recipe }));
