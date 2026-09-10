import { describe, expect, test } from 'bun:test';
import {
  TYPED_TEMPLATE_IDS,
  typedTemplateCommands,
  typedTemplateSchema,
  validateTypedTemplate,
  type TypedRecipeTemplate,
} from '../services/pipeline/recipe-template';
import { safeParse } from 'valibot';
import { lintRecipe, renderRecipe } from '../services/pipeline/recipe';
import { createFactoryRevision } from '../services/pipeline/revision';
import { validateRecipePolicy } from '../services/pipeline/recipe-policy';
import type { FactoryCandidate } from '../services/pipeline/types';

const image = `ghcr.io/opr/builder@sha256:${'a'.repeat(64)}`;

const templates: TypedRecipeTemplate[] = [
  { id: 'autotools-v1', binary: 'demo', sourceMode: 'release-tarball', tests: true },
  { id: 'plain-make-v1', binary: 'demo', buildTarget: 'all', checkTarget: 'test', installTarget: 'install' },
  { id: 'cmake-v1', binary: 'demo', generator: 'ninja', buildType: 'none', tests: true },
  { id: 'meson-v1', binary: 'demo', buildType: 'plain', tests: true },
  { id: 'rust-v1', binary: 'demo', profile: 'release', tests: true, workspace: true },
  { id: 'python-v1', binary: 'demo', wheel: 'demo-1.0-py3-none-any.whl', backend: 'setuptools', nativeExtension: false, tests: true, bytecode: 'checked-hash' },
  { id: 'node-npm-v1', binary: 'demo', lockfile: 'package-lock.json', build: true, outputPath: 'dist/demo.js' },
  { id: 'node-pnpm-v1', binary: 'demo', lockfile: 'pnpm-lock.yaml', build: true, outputPath: 'dist/demo.js' },
  { id: 'node-yarn-v1', binary: 'demo', lockfile: 'yarn.lock', build: true, outputPath: 'dist/demo.js' },
  { id: 'electron-v1', binary: 'demo', appPath: 'dist/linux-unpacked', desktopFile: 'demo.desktop', systemElectron: true, launchTest: true },
  { id: 'archive-v1', binary: 'demo', archivePath: 'demo.tar.zst', payloadPath: 'bin/demo' },
  { id: 'deb-v1', binary: 'demo', payloadPath: 'usr/bin/demo' },
  { id: 'rpm-v1', binary: 'demo', payloadPath: 'usr/bin/demo' },
  { id: 'appimage-v1', binary: 'demo', payloadPath: 'usr/bin/demo', desktopFile: 'demo.desktop' },
  { id: 'run-v1', binary: 'demo', payloadPath: 'usr/bin/demo' },
  { id: 'script-data-v1', binary: 'demo', sourcePath: 'demo.sh', destination: '/usr/bin/demo', kind: 'script', interpreter: 'sh' },
  { id: 'go-v2', binary: 'demo', target: '.', profile: 'release', tests: true, workspace: true, cgo: true, inputs: [{ name: 'native-toolchain.tar', sha256: 'c'.repeat(64), kind: 'toolchain' }] },
];

function candidate(template: TypedRecipeTemplate): FactoryCandidate {
  return {
    request: { id: 'template-fixture', name: 'demo', upstreamUrl: 'https://example.test/demo.tar.gz', sourceKind: 'archive', area: 'development', declaredLicense: 'MIT' },
    version: '1.0.0', sources: [{ name: 'demo.tar.gz', url: 'https://example.test/demo.tar.gz', sha256: 'b'.repeat(64) }],
    dependencies: [], makeDependencies: template.id === 'go-v2' ? ['go'] : [], smokeCommands: [], architectures: ['x86_64'],
    buildImages: { x86_64: image }, pkgrel: 1, sourceDateEpoch: 1, imageDigest: image, license: 'MIT', surface: 'binary',
    description: 'typed template fixture', recipeMode: 'template', template, buildCommands: [], packageCommands: [], explanation: 'fixture',
  };
}

describe('typed recipe template matrix', () => {
  test('renders every required family with offline deterministic stages', () => {
    expect(templates.map((template) => template.id)).toEqual([...TYPED_TEMPLATE_IDS]);

    for (const template of templates) {
      validateTypedTemplate(template);
      const commands = typedTemplateCommands(template);
      expect(commands.build.length).toBeGreaterThan(0);
      expect(commands.package.length).toBeGreaterThan(0);
      expect(commands.smoke.length).toBeGreaterThan(0);
      expect(commands.build.join('\n')).not.toMatch(/(?:curl|wget|git\s+(?:clone|fetch)|--upload-pack)/);
    }
  });

  test('typed output and input locks become explicit staged checks', () => {
    const template: TypedRecipeTemplate = {
      id: 'archive-v1', binary: 'demo', archivePath: 'demo.tar.zst', payloadPath: 'bin/demo',
      inputs: [{ name: 'toolchain.tar', sha256: 'c'.repeat(64), kind: 'toolchain' }],
      outputs: [{ name: 'demo', source: 'prebuilt/bin/demo', destination: '/usr/bin/demo', mode: '0755', architecture: 'target' }],
    };

    const commands = typedTemplateCommands(template);
    expect(commands.build).toContain(`printf '%s  %s\\n' '${'c'.repeat(64)}' 'toolchain.tar' | sha256sum -c -`);
    expect(commands.package).toContain("install -Dm0755 'prebuilt/bin/demo' \"$pkgdir/usr/bin/demo\"");
  });

  test('typed parameters reject shell fragments, missing locks, and unsafe paths', () => {
    for (const template of templates) {
      expect(() => validateTypedTemplate({ ...template, binary: 'demo;id' })).toThrow();
    }

    for (const invalid of [
      { ...templates[1], buildTarget: 'all;id' },
      { ...templates[10], payloadPath: '../outside' },
      { ...templates[4], inputs: [{ name: 'vendor.tar', sha256: 'bad', kind: 'vendor' as const }] },
      { ...templates[0], runtime: { kind: 'executable' as const, path: '/usr/bin/demo', args: ['$(id)'] } },
      { ...templates[6], lockfile: 'pnpm-lock.yaml' as const },
    ]) {
      expect(() => validateTypedTemplate(invalid)).toThrow();
      expect(safeParse(typedTemplateSchema, invalid).success).toBe(false);
    }
  });

  test('typed templates pass existing recipe lint and do not opt into host/vendor installers', () => {
    for (const template of templates.filter((item) => !['deb-v1', 'rpm-v1', 'appimage-v1', 'run-v1'].includes(item.id))) {
      const recipe = renderRecipe(candidate(template));
      expect(lintRecipe(recipe).passed).toBe(true);
      expect(recipe).not.toContain('sudo ');
    }
  });

  test('typed template policy re-renders the same immutable recipe', async () => {
    const draft = await createFactoryRevision(candidate(templates[2]));
    await validateRecipePolicy(draft.revision);
    expect(draft.revision.recipe).toContain('cmake -S . -B build');
    expect(JSON.parse(draft.revision.smoke_commands_json)).toEqual(["'/usr/bin/demo' --version"]);
  });

  test('verified vendor preparation is retained in typed policy', async () => {
    const sourceSha256 = 'b'.repeat(64);

    const draft = await createFactoryRevision({
      ...candidate({ id: 'deb-v1', binary: 'demo', payloadPath: 'usr/bin/demo' }),
      sources: [{ name: 'demo.deb', url: 'https://example.test/demo.deb', sha256: sourceSha256 }],
      vendorArtifact: {
        schemaVersion: 1, format: 'deb', surface: 'recipe', sourcePath: '/workspace/source.bundle', sourceSize: 1, sourceSha256,
        payloadPath: '/workspace/vendor-artifact/payload.tar', entriesPath: '/workspace/vendor-artifact/entries.tsv', controlPath: null,
        controlEntriesPath: null, metadata: { architecture: 'all' },
      },
    });

    await validateRecipePolicy(draft.revision);
    expect(draft.revision.recipe).toContain('$srcdir/vendor-root');
  });
});
