import * as v from 'valibot';
import { shellQuote } from './security';

/**
 * Typed family renderers are deliberately small. They produce the same
 * command arrays consumed by the existing recipe renderer; callers never
 * provide shell fragments or installer hooks.
 */

export const TYPED_TEMPLATE_IDS = [
  'autotools-v1', 'plain-make-v1', 'cmake-v1', 'meson-v1', 'rust-v1', 'python-v1',
  'node-npm-v1', 'node-pnpm-v1', 'node-yarn-v1', 'electron-v1', 'archive-v1',
  'deb-v1', 'rpm-v1', 'appimage-v1', 'run-v1', 'script-data-v1', 'go-v2',
] as const;

export type TypedTemplateId = (typeof TYPED_TEMPLATE_IDS)[number];

export type TemplateArchitecture = 'target' | 'any';

export type TemplateOutputMode = '0755' | '0644' | '0750' | '0555';

export interface PinnedTemplateInput {
  name: string;
  sha256: string;
  kind: 'source' | 'vendor' | 'toolchain' | 'runtime';
}

export interface TemplateOutputSpec {
  name: string;
  source: string;
  destination: string;
  mode: TemplateOutputMode;
  architecture: TemplateArchitecture;
}

export type TemplateRuntimeProbe =
  | { kind: 'executable'; path: string; args?: string[] }
  | { kind: 'file'; path: string }
  | { kind: 'directory'; path: string }
  | { kind: 'electron'; path: string; args?: string[] };

interface TypedTemplateBase {
  id: TypedTemplateId;
  binary?: string;
  inputs?: PinnedTemplateInput[];
  outputs?: TemplateOutputSpec[];
  runtime?: TemplateRuntimeProbe;
}

export type TypedRecipeTemplate =
  | (TypedTemplateBase & { id: 'autotools-v1'; sourceMode: 'release-tarball' | 'autoreconf'; tests: boolean })
  | (TypedTemplateBase & { id: 'plain-make-v1'; buildTarget: string; checkTarget?: string; installTarget: string })
  | (TypedTemplateBase & { id: 'cmake-v1'; generator: 'ninja' | 'make'; buildType: 'none' | 'debug' | 'release'; tests: boolean; buildTarget?: string })
  | (TypedTemplateBase & { id: 'meson-v1'; buildType: 'plain' | 'debugoptimized' | 'release'; tests: boolean })
  | (TypedTemplateBase & { id: 'rust-v1'; profile: 'debug' | 'release'; tests: boolean; workspace: boolean; package?: string })
  | (TypedTemplateBase & { id: 'python-v1'; wheel: string; backend: 'setuptools' | 'flit' | 'hatchling' | 'pdm' | 'poetry-core'; nativeExtension: boolean; tests: boolean; bytecode: 'none' | 'checked-hash' })
  | (TypedTemplateBase & { id: 'node-npm-v1' | 'node-pnpm-v1' | 'node-yarn-v1'; lockfile: 'package-lock.json' | 'pnpm-lock.yaml' | 'yarn.lock'; build: boolean; outputPath: string })
  | (TypedTemplateBase & { id: 'electron-v1'; appPath: string; desktopFile: string; iconPath?: string; systemElectron: boolean; launchTest: boolean })
  | (TypedTemplateBase & { id: 'archive-v1'; archivePath: string; payloadPath: string })
  | (TypedTemplateBase & { id: 'deb-v1' | 'rpm-v1' | 'appimage-v1' | 'run-v1'; payloadPath: string; desktopFile?: string; iconPath?: string })
  | (TypedTemplateBase & { id: 'script-data-v1'; sourcePath: string; destination: string; kind: 'script' | 'data'; interpreter?: 'sh' | 'python3' | 'perl' | 'ruby' | 'node' })
  | (TypedTemplateBase & { id: 'go-v2'; target: string; profile: 'debug' | 'release'; tests: boolean; workspace: boolean; cgo: boolean });

export interface TemplateCommands {
  build: string[];
  package: string[];
  smoke: string[];
}

export const TYPED_TEMPLATE_DEFINITIONS: Record<TypedTemplateId, { family: string; rendererVersion: 1; offline: true; vendorPreparation: 'none' | 'verified-artifact' | 'locked-input' }> = {
  'autotools-v1': { family: 'autotools', rendererVersion: 1, offline: true, vendorPreparation: 'locked-input' },
  'plain-make-v1': { family: 'plain-make', rendererVersion: 1, offline: true, vendorPreparation: 'locked-input' },
  'cmake-v1': { family: 'cmake', rendererVersion: 1, offline: true, vendorPreparation: 'locked-input' },
  'meson-v1': { family: 'meson-ninja', rendererVersion: 1, offline: true, vendorPreparation: 'locked-input' },
  'rust-v1': { family: 'rust-cargo', rendererVersion: 1, offline: true, vendorPreparation: 'locked-input' },
  'python-v1': { family: 'python-pep517', rendererVersion: 1, offline: true, vendorPreparation: 'locked-input' },
  'node-npm-v1': { family: 'node-npm', rendererVersion: 1, offline: true, vendorPreparation: 'locked-input' },
  'node-pnpm-v1': { family: 'node-pnpm', rendererVersion: 1, offline: true, vendorPreparation: 'locked-input' },
  'node-yarn-v1': { family: 'node-yarn', rendererVersion: 1, offline: true, vendorPreparation: 'locked-input' },
  'electron-v1': { family: 'electron', rendererVersion: 1, offline: true, vendorPreparation: 'locked-input' },
  'archive-v1': { family: 'prebuilt-archive', rendererVersion: 1, offline: true, vendorPreparation: 'locked-input' },
  'deb-v1': { family: 'debian-binary', rendererVersion: 1, offline: true, vendorPreparation: 'verified-artifact' },
  'rpm-v1': { family: 'rpm-binary', rendererVersion: 1, offline: true, vendorPreparation: 'verified-artifact' },
  'appimage-v1': { family: 'appimage', rendererVersion: 1, offline: true, vendorPreparation: 'verified-artifact' },
  'run-v1': { family: 'vendor-run', rendererVersion: 1, offline: true, vendorPreparation: 'verified-artifact' },
  'script-data-v1': { family: 'script-data', rendererVersion: 1, offline: true, vendorPreparation: 'locked-input' },
  'go-v2': { family: 'go', rendererVersion: 1, offline: true, vendorPreparation: 'locked-input' },
};

/** Stable, inspectable matrix used by diagnostics and fixture tests. */
export const TEMPLATE_FAMILY_MATRIX = TYPED_TEMPLATE_IDS.map((id) => ({ id, ...TYPED_TEMPLATE_DEFINITIONS[id] })) as readonly {
  id: TypedTemplateId;
  family: string;
  rendererVersion: 1;
  offline: true;
  vendorPreparation: 'none' | 'verified-artifact' | 'locked-input';
}[];

const idPattern = /^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$/;

const pathPattern = /^[A-Za-z0-9][A-Za-z0-9._+@%=-]*(?:\/[A-Za-z0-9][A-Za-z0-9._+@%=-]*)*$/;

const targetPattern = /^[A-Za-z0-9][A-Za-z0-9._+:-]{0,63}$/;

const sha256Pattern = /^[0-9a-f]{64}$/;

const installPathPattern = /^\/(?:usr|opt)\/[A-Za-z0-9][A-Za-z0-9._+@%=-]*(?:\/[A-Za-z0-9][A-Za-z0-9._+@%=-]*)*$/;

const argumentPattern = /^[-A-Za-z0-9._+/:=@%]+$/;

function record(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('template must be an object');

  return value as Record<string, unknown>;
}

function keys(value: Record<string, unknown>, allowed: readonly string[]): void {
  if (Object.keys(value).some((key) => !allowed.includes(key))) throw new Error('template contains unsupported parameters');
}

function text(value: unknown, name: string, pattern: RegExp = idPattern): string {
  if (typeof value !== 'string' || !pattern.test(value)) throw new Error(`template ${name} is invalid`);

  if (pattern === pathPattern && value.split('/').some((part) => part === '.' || part === '..')) throw new Error(`template ${name} is invalid`);

  return value;
}

function optionalText(value: unknown, name: string, pattern: RegExp = idPattern): string | undefined {
  return value === undefined ? undefined : text(value, name, pattern);
}

function bool(value: unknown, name: string): boolean {
  if (typeof value !== 'boolean') throw new Error(`template ${name} is invalid`);

  return value;
}

function literal<T extends string>(value: unknown, name: string, allowed: readonly T[]): T {
  if (typeof value !== 'string' || !allowed.includes(value as T)) throw new Error(`template ${name} is invalid`);

  return value as T;
}

function array(value: unknown, name: string, max = 64): unknown[] | undefined {
  if (value === undefined) return undefined;

  if (!Array.isArray(value) || value.length > max) throw new Error(`template ${name} is invalid`);

  return value;
}

function validateCommon(value: Record<string, unknown>, allowed: readonly string[]): void {
  keys(value, ['id', 'binary', 'inputs', 'outputs', 'runtime', ...allowed]);
  optionalText(value.binary, 'binary');
  const inputs = array(value.inputs, 'inputs');

  if (inputs) {
    const seen = new Set<string>();

    for (const item of inputs) {
      const input = record(item);
      keys(input, ['name', 'sha256', 'kind']);
      const name = text(input.name, 'input name', pathPattern);

      if (seen.has(name) || !sha256Pattern.test(String(input.sha256))) throw new Error('template input lock is invalid');
      seen.add(name);
      literal(input.kind, 'input kind', ['source', 'vendor', 'toolchain', 'runtime'] as const);
    }
  }

  const outputs = array(value.outputs, 'outputs');

  if (outputs) {
    const seen = new Set<string>();
    const destinations = new Set<string>();

    for (const item of outputs) {
      const output = record(item);
      keys(output, ['name', 'source', 'destination', 'mode', 'architecture']);
      const name = text(output.name, 'output name', /^[a-z0-9][a-z0-9@._+-]{0,63}$/);
      const source = text(output.source, 'output source', pathPattern);
      const destination = text(output.destination, 'output destination', installPathPattern);

      if (seen.has(name) || destinations.has(destination) || source.startsWith('.git/')) throw new Error('template outputs must be unique and safe');
      seen.add(name); destinations.add(destination);
      literal(output.mode, 'output mode', ['0755', '0644', '0750', '0555'] as const);
      literal(output.architecture, 'output architecture', ['target', 'any'] as const);
    }
  }

  if (value.runtime !== undefined) {
    const runtime = record(value.runtime);
    keys(runtime, ['kind', 'path', 'args']);
    literal(runtime.kind, 'runtime kind', ['executable', 'file', 'directory', 'electron'] as const);
    text(runtime.path, 'runtime path', installPathPattern);
    const args = array(runtime.args, 'runtime args', 16);

    if (args) args.forEach((arg) => text(arg, 'runtime argument', argumentPattern));

    if (runtime.kind !== 'executable' && runtime.kind !== 'electron' && runtime.args !== undefined) throw new Error('runtime args require executable check');
  }
}

function requireBinaryOrOutputs(value: Record<string, unknown>, family: string): void {
  if (value.binary === undefined && (!Array.isArray(value.outputs) || value.outputs.length === 0)) throw new Error(`${family} template requires binary or output mappings`);
}

function validateTemplateFamily(value: Record<string, unknown>): void {
  const id = value.id;

  if (typeof id !== 'string' || !(TYPED_TEMPLATE_IDS as readonly string[]).includes(id)) throw new Error('unknown typed template');

  switch (id as TypedTemplateId) {
    case 'autotools-v1':
      validateCommon(value, ['sourceMode', 'tests']); requireBinaryOrOutputs(value, 'autotools'); literal(value.sourceMode, 'sourceMode', ['release-tarball', 'autoreconf'] as const); bool(value.tests, 'tests'); break;
    case 'plain-make-v1':
      validateCommon(value, ['buildTarget', 'checkTarget', 'installTarget']); requireBinaryOrOutputs(value, 'plain make'); text(value.buildTarget, 'buildTarget', targetPattern); optionalText(value.checkTarget, 'checkTarget', targetPattern); text(value.installTarget, 'installTarget', targetPattern); break;
    case 'cmake-v1':
      validateCommon(value, ['generator', 'buildType', 'tests', 'buildTarget']); requireBinaryOrOutputs(value, 'CMake'); literal(value.generator, 'generator', ['ninja', 'make'] as const); literal(value.buildType, 'buildType', ['none', 'debug', 'release'] as const); bool(value.tests, 'tests'); optionalText(value.buildTarget, 'buildTarget', targetPattern); break;
    case 'meson-v1':
      validateCommon(value, ['buildType', 'tests']); requireBinaryOrOutputs(value, 'Meson'); literal(value.buildType, 'buildType', ['plain', 'debugoptimized', 'release'] as const); bool(value.tests, 'tests'); break;
    case 'rust-v1':
      validateCommon(value, ['profile', 'tests', 'workspace', 'package']); requireBinaryOrOutputs(value, 'Rust'); literal(value.profile, 'profile', ['debug', 'release'] as const); bool(value.tests, 'tests'); bool(value.workspace, 'workspace'); optionalText(value.package, 'package', targetPattern); break;
    case 'python-v1':
      validateCommon(value, ['wheel', 'backend', 'nativeExtension', 'tests', 'bytecode']); text(value.wheel, 'wheel', /^[A-Za-z0-9][A-Za-z0-9._+-]{0,200}\.whl$/); literal(value.backend, 'backend', ['setuptools', 'flit', 'hatchling', 'pdm', 'poetry-core'] as const); bool(value.nativeExtension, 'nativeExtension'); bool(value.tests, 'tests'); literal(value.bytecode, 'bytecode', ['none', 'checked-hash'] as const); break;
    case 'node-npm-v1': case 'node-pnpm-v1': case 'node-yarn-v1':
      validateCommon(value, ['lockfile', 'build', 'outputPath']); literal(value.lockfile, 'lockfile', ['package-lock.json', 'pnpm-lock.yaml', 'yarn.lock'] as const); lockfileFor(id as 'node-npm-v1' | 'node-pnpm-v1' | 'node-yarn-v1', value.lockfile as string); bool(value.build, 'build'); text(value.outputPath, 'outputPath', pathPattern); break;
    case 'electron-v1':
      validateCommon(value, ['appPath', 'desktopFile', 'iconPath', 'systemElectron', 'launchTest']); requireBinaryOrOutputs(value, 'Electron'); text(value.appPath, 'appPath', pathPattern); text(value.desktopFile, 'desktopFile', pathPattern); optionalText(value.iconPath, 'iconPath', pathPattern); bool(value.systemElectron, 'systemElectron'); bool(value.launchTest, 'launchTest'); break;
    case 'archive-v1':
      validateCommon(value, ['archivePath', 'payloadPath']); requireBinaryOrOutputs(value, 'archive'); text(value.archivePath, 'archivePath', pathPattern); text(value.payloadPath, 'payloadPath', pathPattern); break;
    case 'deb-v1': case 'rpm-v1': case 'appimage-v1': case 'run-v1':
      validateCommon(value, ['payloadPath', 'desktopFile', 'iconPath']); requireBinaryOrOutputs(value, 'vendor'); text(value.payloadPath, 'payloadPath', pathPattern); optionalText(value.desktopFile, 'desktopFile', pathPattern); optionalText(value.iconPath, 'iconPath', pathPattern); break;
    case 'script-data-v1':
      validateCommon(value, ['sourcePath', 'destination', 'kind', 'interpreter']); text(value.sourcePath, 'sourcePath', pathPattern); text(value.destination, 'destination', installPathPattern); literal(value.kind, 'kind', ['script', 'data'] as const);

 if (value.kind === 'script') literal(value.interpreter, 'interpreter', ['sh', 'python3', 'perl', 'ruby', 'node'] as const); else if (value.interpreter !== undefined) throw new Error('data template cannot declare interpreter'); break;
    case 'go-v2':
      validateCommon(value, ['target', 'profile', 'tests', 'workspace', 'cgo']); requireBinaryOrOutputs(value, 'Go'); text(value.target, 'target', /^\.?\/?[A-Za-z0-9._+@/-]{1,127}$/);

 if (String(value.target).split('/').includes('..')) throw new Error('template target escapes source root'); literal(value.profile, 'profile', ['debug', 'release'] as const); bool(value.tests, 'tests'); bool(value.workspace, 'workspace'); bool(value.cgo, 'cgo');

 if (value.cgo && !(Array.isArray(value.inputs) && value.inputs.some((input) => record(input).kind === 'toolchain' || record(input).kind === 'runtime'))) throw new Error('CGO template requires pinned native inputs'); break;
  }
}

export function validateTypedTemplate(value: unknown): asserts value is TypedRecipeTemplate {
  validateTemplateFamily(record(value));
}

/** Valibot boundary used by the model-facing candidate schema. */
export const typedTemplateSchema = v.custom<TypedRecipeTemplate>((value) => {
  try { validateTypedTemplate(value);

 return true; } catch { return false; }
}, 'Invalid typed recipe template');

function q(value: string): string { return shellQuote(value); }

function source(name: string): string { return `"$srcdir/${name}"`; }

function sourceRef(path: string): string { return path.startsWith('$srcdir/') ? `"${path}"` : q(path); }

function packagePath(path: string): string { return `"$pkgdir${path}"`; }

function inputChecks(inputs: readonly PinnedTemplateInput[] | undefined): string[] {
  return (inputs ?? []).flatMap((input) => [
    `test -f ${q(input.name)}`,
    `printf '%s  %s\\n' '${input.sha256}' ${q(input.name)} | sha256sum -c -`,
  ]);
}

function outputCommands(template: TypedRecipeTemplate, fallback: { source: string; destination: string; mode: TemplateOutputMode }): string[] {
  const outputs = template.outputs?.length ? template.outputs : [{ name: template.binary ?? 'payload', ...fallback, architecture: 'target' as const }];

  return outputs.flatMap((output) => [
    `test -f ${sourceRef(output.source)}`,
    `install -Dm${output.mode} ${sourceRef(output.source)} ${packagePath(output.destination)}`,
  ]);
}

export function typedTemplateOutputCommands(outputs: readonly TemplateOutputSpec[]): string[] {
  return outputs.flatMap((output) => [
    `test -f ${sourceRef(output.source)}`,
    `install -Dm${output.mode} ${sourceRef(output.source)} ${packagePath(output.destination)}`,
  ]);
}

export function typedTemplateOutputs(value: TypedRecipeTemplate): readonly TemplateOutputSpec[] {
  validateTypedTemplate(value);
  return value.outputs ?? [];
}

function smoke(template: TypedRecipeTemplate, fallbackBinary?: string): string[] {
  const runtime = template.runtime;

  if (!runtime) {
    if (!fallbackBinary) return ['test -d /usr/share'];

    return [`${q(`/usr/bin/${fallbackBinary}`)} --version`];
  }

  if (runtime.kind === 'file') return [`test -f ${q(runtime.path)}`];

  if (runtime.kind === 'directory') return [`test -d ${q(runtime.path)}`];
  const args = (runtime.args ?? ['--version']).map(q).join(' ');

  if (runtime.kind === 'electron') return [`xvfb-run --auto-servernum --server-args='-screen 0 1024x768x24' ${q(runtime.path)} ${args}`];

  return [`test -x ${q(runtime.path)}`, `${q(runtime.path)}${args ? ` ${args}` : ''}`];
}

function lockfileFor(id: 'node-npm-v1' | 'node-pnpm-v1' | 'node-yarn-v1', lockfile: string): void {
  const expected = id === 'node-npm-v1' ? 'package-lock.json' : id === 'node-pnpm-v1' ? 'pnpm-lock.yaml' : 'yarn.lock';

  if (lockfile !== expected) throw new Error(`${id} requires ${expected}`);
}

function vendorTemplate(id: TypedTemplateId): boolean {
  return id === 'deb-v1' || id === 'rpm-v1' || id === 'appimage-v1' || id === 'run-v1';
}

export function isVerifiedArtifactTemplate(value: unknown): boolean {
  try { validateTypedTemplate(value);

 return vendorTemplate((value as TypedRecipeTemplate).id); } catch { return false; }
}

export function typedTemplateCommands(value: TypedRecipeTemplate): TemplateCommands {
  validateTypedTemplate(value);
  const binary = value.binary;

  switch (value.id) {
    case 'autotools-v1': {
      const build = [...inputChecks(value.inputs)];

      if (value.sourceMode === 'autoreconf') build.push('autoreconf --force --install --no-recursive');
      build.push('./configure --prefix=/usr', 'make');

      if (value.tests) build.push('make check');

      return { build, package: ['make DESTDIR="$pkgdir" install'], smoke: smoke(value, binary) };
    }

    case 'plain-make-v1': {
      const build = [...inputChecks(value.inputs), `make PREFIX=/usr ${value.buildTarget}`];

      if (value.checkTarget) build.push(`make PREFIX=/usr ${value.checkTarget}`);

      return { build, package: [`make PREFIX=/usr DESTDIR="$pkgdir" ${value.installTarget}`], smoke: smoke(value, binary) };
    }

    case 'cmake-v1': {
      const generator = value.generator === 'ninja' ? 'Ninja' : 'Unix Makefiles';
      const build = [...inputChecks(value.inputs), `cmake -S . -B build -G ${q(generator)} -D CMAKE_BUILD_TYPE=${value.buildType === 'none' ? 'None' : value.buildType[0].toUpperCase() + value.buildType.slice(1)} -D CMAKE_INSTALL_PREFIX=/usr -D FETCHCONTENT_FULLY_DISCONNECTED=ON -D FETCHCONTENT_UPDATES_DISCONNECTED=ON`, `cmake --build build${value.buildTarget ? ` --target ${value.buildTarget}` : ''}`];

      if (value.tests) build.push('ctest --test-dir build --output-on-failure');

      return { build, package: ['DESTDIR="$pkgdir" cmake --install build'], smoke: smoke(value, binary) };
    }

    case 'meson-v1': {
      const build = [...inputChecks(value.inputs), `meson setup build --prefix=/usr --buildtype=${value.buildType} --wrap-mode=nodownload`, 'meson compile -C build'];

      if (value.tests) build.push('meson test -C build --print-errorlogs');

      return { build, package: ['DESTDIR="$pkgdir" meson install -C build'], smoke: smoke(value, binary) };
    }

    case 'rust-v1': {
      const flags = `${value.workspace ? ' --workspace' : ''}${value.package ? ` -p ${value.package}` : ''}`;
      const build = [...inputChecks(value.inputs), `CARGO_NET_OFFLINE=true cargo build --frozen --offline --locked${value.profile === 'release' ? ' --release' : ''}${flags}`];

      if (value.tests) build.push('CARGO_NET_OFFLINE=true cargo test --frozen --offline --locked' + (value.workspace ? ' --workspace' : ''));

      return { build, package: outputCommands(value, { source: `target/${value.profile}/${binary ?? 'BINARY'}`, destination: `/usr/bin/${binary ?? 'BINARY'}`, mode: '0755' }), smoke: smoke(value, binary) };
    }

    case 'python-v1': {
      const build = [...inputChecks(value.inputs), 'test -f pyproject.toml', 'python -m build --wheel --no-isolation --outdir dist', `test -f ${q(`dist/${value.wheel}`)}`];

      if (value.tests) build.push('python -m pytest -o addopts=""');

      if (value.bytecode === 'checked-hash') build.push('python -m compileall --invalidation-mode=checked-hash .');

      return { build, package: [`python -m installer --destdir="$pkgdir" ${q(`dist/${value.wheel}`)}`], smoke: smoke(value, binary) };
    }

    case 'node-npm-v1': case 'node-pnpm-v1': case 'node-yarn-v1': {
      lockfileFor(value.id, value.lockfile);
      const build = [...inputChecks(value.inputs), `test -f ${q(value.lockfile)}`];

      if (value.id === 'node-npm-v1') build.push('npm ci --offline --ignore-scripts --no-audit --no-fund --cache="$srcdir/.npm-cache"');
      else if (value.id === 'node-pnpm-v1') build.push('pnpm install --offline --frozen-lockfile --ignore-scripts');
      else build.push('yarn install --immutable --offline');

      if (value.build) build.push('npm run build --if-present');

      return { build, package: outputCommands(value, { source: value.outputPath, destination: `/usr/share/${binary ?? 'node-app'}`, mode: '0644' }), smoke: smoke(value, binary) };
    }

    case 'electron-v1': {
      const build = [...inputChecks(value.inputs), 'test -f package-lock.json', 'npm ci --offline --ignore-scripts --no-audit --no-fund --cache="$srcdir/.npm-cache"', 'npm run build --if-present', 'test -e ' + q(value.appPath)];

      return { build, package: [...outputCommands(value, { source: value.appPath, destination: `/usr/lib/${binary ?? 'electron-app'}`, mode: '0755' }), `install -Dm644 ${q(value.desktopFile)} ${packagePath(`/usr/share/applications/${value.desktopFile.split('/').pop()!}`)}`, ...(value.iconPath ? [`install -Dm644 ${q(value.iconPath)} ${packagePath(`/usr/share/icons/hicolor/256x256/apps/${binary ?? 'electron-app'}.png`)}`] : [])], smoke: value.launchTest ? smoke({ ...value, runtime: value.runtime ?? { kind: 'electron', path: `/usr/lib/${binary ?? 'electron-app'}` } }, binary) : [`test -f ${q(`/usr/share/applications/${value.desktopFile.split('/').pop()!}`)}`] };
    }

    case 'archive-v1':
      return { build: [...inputChecks(value.inputs), `test -f ${source(value.archivePath)}`, `mkdir -p "$srcdir/prebuilt"`, `bsdtar --extract --file ${source(value.archivePath)} --directory "$srcdir/prebuilt" --no-same-owner --no-same-permissions`, `test -e ${q(`prebuilt/${value.payloadPath}`)}`], package: outputCommands(value, { source: `$srcdir/prebuilt/${value.payloadPath}`, destination: `/usr/bin/${binary ?? 'payload'}`, mode: '0755' }), smoke: smoke(value, binary) };
    case 'deb-v1': case 'rpm-v1': case 'appimage-v1': case 'run-v1': {
      const root = 'vendor-root';
      const build = [...inputChecks(value.inputs), `test -d "$srcdir/${root}"`, `test -e ${q(`${root}/${value.payloadPath}`)}`];
      const packageCommands = outputCommands(value, { source: `$srcdir/${root}/${value.payloadPath}`, destination: `/usr/bin/${binary ?? 'payload'}`, mode: '0755' });

      if (value.desktopFile) packageCommands.push(`install -Dm644 "$srcdir/${root}/${value.desktopFile}" ${packagePath(`/usr/share/applications/${value.desktopFile.split('/').pop()!}`)}`);

      if (value.iconPath) packageCommands.push(`install -Dm644 "$srcdir/${root}/${value.iconPath}" ${packagePath(`/usr/share/icons/hicolor/256x256/apps/${binary ?? 'payload'}.png`)}`);

      return { build, package: packageCommands, smoke: smoke(value, binary) };
    }

    case 'script-data-v1': {
      const build = [...inputChecks(value.inputs), `test -f ${source(value.sourcePath)}`];
      const mode = value.kind === 'script' ? '0755' : '0644';
      const runtime = value.runtime ?? (value.kind === 'script' ? { kind: 'executable' as const, path: value.destination, args: [] } : { kind: 'file' as const, path: value.destination });

      return { build, package: [`install -Dm${mode} ${source(value.sourcePath)} ${packagePath(value.destination)}`], smoke: smoke({ ...value, runtime }, binary) };
    }

    case 'go-v2': {
      const flags = `${value.profile === 'release' ? ' -ldflags=-buildid= -trimpath' : ' -trimpath'}`;
      const workspace = value.workspace ? 'GOWORK="$PWD/go.work" ' : 'GOWORK=off ';
      const cgo = value.cgo ? 'CGO_ENABLED=1' : 'CGO_ENABLED=0';
      const build = [...inputChecks(value.inputs), 'test -f go.mod', ...(value.workspace ? ['test -f go.work'] : []), 'test -d vendor', `${cgo} ${workspace}GOTOOLCHAIN=local GOENV=off GOPROXY=off GOSUMDB=off go build -mod=vendor -trimpath -o build/${binary ?? 'BINARY'}${flags} ${q(value.target)}`];

      if (value.tests) build.push(`${cgo} ${workspace}GOTOOLCHAIN=local GOENV=off GOPROXY=off GOSUMDB=off go test -mod=vendor -trimpath ${value.workspace ? './...' : q(value.target)}`);

      return { build, package: outputCommands(value, { source: `build/${binary ?? 'BINARY'}`, destination: `/usr/bin/${binary ?? 'BINARY'}`, mode: '0755' }), smoke: smoke(value, binary) };
    }
  }
}
