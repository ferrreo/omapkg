/*
 * Adapted from adamhjk/omarchy-aur-factory at commit
 * 657d9c7c95e10573952d44cdb8a3c7ea6992ac0a.
 *
 * Source paths:
 * .claude/skills/arch-packaging/SKILL.md
 * .claude/skills/arch-packaging/references/{binary,c-cpp,go,nodejs,pkgbuild,python,rust,validation,vcs}.md
 *
 * Modified for omapkg: rules are bounded, immutable Flue guidance. Swamp
 * workflows, Claude CLI calls, host execution, and live dependency resolution
 * are intentionally omitted. See licenses/Apache-2.0-omarchy-aur-factory.txt.
 */

export const PACKAGING_GUIDANCE_VERSION = 1 as const;

export const PACKAGING_GUIDANCE_COMMIT = '657d9c7c95e10573952d44cdb8a3c7ea6992ac0a' as const;

export const PACKAGING_GUIDANCE_SOURCES = [
  '.claude/skills/arch-packaging/SKILL.md',
  '.claude/skills/arch-packaging/references/binary.md',
  '.claude/skills/arch-packaging/references/c-cpp.md',
  '.claude/skills/arch-packaging/references/go.md',
  '.claude/skills/arch-packaging/references/nodejs.md',
  '.claude/skills/arch-packaging/references/pkgbuild.md',
  '.claude/skills/arch-packaging/references/python.md',
  '.claude/skills/arch-packaging/references/rust.md',
  '.claude/skills/arch-packaging/references/validation.md',
  '.claude/skills/arch-packaging/references/vcs.md',
] as const;

export const PACKAGING_FAMILY_ORDER = [
  'autotools',
  'make',
  'cmake',
  'meson',
  'rust',
  'go',
  'python',
  'node-npm',
  'node-pnpm',
  'node-yarn',
  'electron',
  'prebuilt-archive',
  'debian',
  'rpm',
  'appimage',
  'self-extractor',
  'script-data',
  'vcs',
] as const;

export type PackagingFamily = (typeof PACKAGING_FAMILY_ORDER)[number];

export const PACKAGING_TEMPLATE_FAMILY = {
  'make-v1': 'make',
  'go-v1': 'go',
  'autotools-v1': 'autotools',
  'plain-make-v1': 'make',
  'cmake-v1': 'cmake',
  'meson-v1': 'meson',
  'rust-v1': 'rust',
  'python-v1': 'python',
  'node-npm-v1': 'node-npm',
  'node-pnpm-v1': 'node-pnpm',
  'node-yarn-v1': 'node-yarn',
  'electron-v1': 'electron',
  'archive-v1': 'prebuilt-archive',
  'deb-v1': 'debian',
  'rpm-v1': 'rpm',
  'appimage-v1': 'appimage',
  'run-v1': 'self-extractor',
  'script-data-v1': 'script-data',
  'go-v2': 'go',
} as const satisfies Record<string, PackagingFamily>;

export interface PackagingGuidance {
  readonly family: PackagingFamily;
  readonly inspect: readonly string[];
  readonly prepare: readonly string[];
  readonly build: readonly string[];
  readonly check: readonly string[];
  readonly install: readonly string[];
  readonly reject: readonly string[];
}

const commonReject = [
  'Reject live downloads, moving refs, shell-valued parameters, and implicit installer hooks.',
  'Reject host writes, inherited secrets, and commands that weaken required checks.',
] as const;

const guidance = {
  autotools: {
    family: 'autotools',
    inspect: ['Distinguish a release archive with configure from sources that require autoreconf and pinned autotools.'],
    prepare: ['Materialize every patch and tool input before the isolated build; keep autoreconf out of release archives.'],
    build: ['Configure with /usr prefix and an out-of-source or clean source tree, then compile with the worker toolchain.'],
    check: ['Run the project check target when present and record an actionable absence when no test target exists.'],
    install: ['Stage install through DESTDIR and verify library, CLI, split, license, and architecture outputs.'],
    reject: commonReject,
  },
  make: {
    family: 'make',
    inspect: ['Read the Makefile for supported build, check, PREFIX, DESTDIR, and nonstandard install targets; do not assume configure exists.'],
    prepare: ['Pin patches and generated inputs; preserve the worker CFLAGS and LDFLAGS unless the project documents a reviewed override.'],
    build: ['Invoke only the documented build target with explicit PREFIX and target-specific parameters.'],
    check: ['Run the documented check or test target; a missing target is evidence, not a passing check.'],
    install: ['Use DESTDIR when supported or map files explicitly into standard /usr paths.'],
    reject: commonReject,
  },
  cmake: {
    family: 'cmake',
    inspect: ['Read CMake options, install rules, tests, toolchain requirements, and any FetchContent or external project declarations.'],
    prepare: ['Pin generator, toolchain, and all fetched sources; configure disconnected source directories for dependencies.'],
    build: ['Use an out-of-tree build with /usr prefix and a neutral build type that preserves worker flags.'],
    check: ['Run CTest from the build tree with failure output enabled.'],
    install: ['Install with DESTDIR and inspect every split output, RPATH, library directory, and generated metadata.'],
    reject: commonReject,
  },
  meson: {
    family: 'meson',
    inspect: ['Read meson.build, project options, wrap files, subprojects, install rules, and test definitions.'],
    prepare: ['Pin Meson, Ninja, toolchain, wraps, and subproject inputs; missing offline subprojects fail preparation.'],
    build: ['Set /usr prefix and a plain or explicitly reviewed build type, then compile in a separate build directory.'],
    check: ['Run the project test suite through Meson and retain failed test names and logs.'],
    install: ['Stage the Meson install into the package root and verify permissions, paths, and split outputs.'],
    reject: commonReject,
  },
  rust: {
    family: 'rust',
    inspect: ['Require Cargo.toml and Cargo.lock; identify workspace members, binaries, build scripts, features, and native -sys dependencies.'],
    prepare: ['Use a retained vendored crate tree and pinned toolchain; missing locks or vendor checksums stop the candidate.'],
    build: ['Build frozen and offline with trimpath, the declared profile, and explicit workspace or binary outputs.'],
    check: ['Run frozen offline tests in a mode that keeps debug assertions useful.'],
    install: ['Install each declared binary or library output explicitly and include license text when required.'],
    reject: commonReject,
  },
  go: {
    family: 'go',
    inspect: ['Read go.mod, go.sum, vendor/modules.txt, workspace files, CGO requirements, and every requested output under cmd or package targets.'],
    prepare: ['Require a retained vendor tree or an equivalent locked module bundle; keep GOPATH and caches inside the isolated source area.'],
    build: ['Build offline with readonly or vendor module mode, trimpath, PIE, and explicit CGO flags; never resolve modules during build.'],
    check: ['Run the project tests for the selected workspace and record native dependency coverage.'],
    install: ['Install every declared binary or library output, with architecture labels matching actual native code.'],
    reject: commonReject,
  },
  python: {
    family: 'python',
    inspect: ['Identify the PEP 517 backend, pinned build requirements, runtime modules, native extensions, tests, and version-from-VCS behavior.'],
    prepare: ['Materialize backend wheels and test inputs; build without isolation and without pip or registry access.'],
    build: ['Build a wheel with the pinned backend and controlled bytecode and path settings.'],
    check: ['Run the project test suite against the built or staged package using only declared check dependencies.'],
    install: ['Install the wheel into DESTDIR with the package installer, classify pure Python as any only when no native code is present, and exclude tests from site-packages.'],
    reject: commonReject,
  },
  'node-npm': {
    family: 'node-npm',
    inspect: ['Require package.json plus an exact package-lock.json or npm-shrinkwrap; identify runtime dependencies and lifecycle scripts.'],
    prepare: ['Retain an npm cache or dependency store keyed by the lockfile; review scripts before allowing any lifecycle hook.'],
    build: ['Use npm ci or the local project build with offline cache settings and no registry access; keep caches under the source area.'],
    check: ['Run the declared test or CLI check against the staged package and record lifecycle-script decisions.'],
    install: ['Stage the package under standard Node paths, remove build-root metadata leaks, and verify bundled dependency licenses.'],
    reject: commonReject,
  },
  'node-pnpm': {
    family: 'node-pnpm',
    inspect: ['Require package.json plus an exact pnpm lockfile and store metadata; identify workspace packages and lifecycle scripts.'],
    prepare: ['Materialize the pnpm store before isolation and verify lockfile/store completeness; no registry resolution is allowed in build.'],
    build: ['Use frozen, offline pnpm commands with the pinned version and a source-local store.'],
    check: ['Run workspace tests and the built CLI or asset check without fetching dependencies.'],
    install: ['Map only declared runtime files into standard paths and audit symlinks and bundled license texts.'],
    reject: commonReject,
  },
  'node-yarn': {
    family: 'node-yarn',
    inspect: ['Require package.json plus an exact Yarn lockfile and configured cache; identify workspaces and lifecycle scripts.'],
    prepare: ['Materialize and verify the Yarn cache before the isolated build; reject lockfile/cache gaps instead of falling back online.'],
    build: ['Use the pinned Yarn adapter in immutable, offline mode with a source-local cache.'],
    check: ['Run declared workspace tests and a compiled-asset or CLI check.'],
    install: ['Stage only reviewed runtime files, normalize permissions, and verify bundled dependency licenses and symlinks.'],
    reject: commonReject,
  },
  electron: {
    family: 'electron',
    inspect: ['Identify the exact Electron/runtime and builder versions, native extensions, application root, desktop metadata, icons, and system integration.'],
    prepare: ['Pin Electron, builder, and application assets; make native modules match the selected system runtime before isolation.'],
    build: ['Build from the retained asset store without downloads and choose explicitly between a system Electron dependency and a bundled runtime.'],
    check: ['Launch in the approved isolated display profile and verify desktop entry, icons, runtime dependencies, and clean exit.'],
    install: ['Place application files under /usr/lib or /usr/share as appropriate and add a reviewed launcher with standard permissions.'],
    reject: commonReject,
  },
  'prebuilt-archive': {
    family: 'prebuilt-archive',
    inspect: ['Verify exact archive bytes, target architecture, payload inventory, shared-library dependencies, licenses, and archive path safety.'],
    prepare: ['Extract with a pinned archive tool into a disposable root; no executable installer or host write is permitted.'],
    build: ['Treat repackaging as an offline mapping stage; do not claim source-build reproducibility for vendor bytes.'],
    check: ['Run file-list, metadata, dependency, permissions, and installed runtime checks for every payload.'],
    install: ['Map files explicitly into standard paths and retain license text and architecture-specific labels.'],
    reject: commonReject,
  },
  debian: {
    family: 'debian',
    inspect: ['Verify the .deb bytes, control metadata, architecture, payload paths, dependencies, and license evidence.'],
    prepare: ['Extract control and data archives into disposable roots with a pinned tool; never execute maintainer scripts.'],
    build: ['Perform explicit Arch-layout mapping from the extracted payload; this is vendor repackaging, not a source build.'],
    check: ['Inspect metadata, payload paths, permissions, dependency mapping, licenses, and installed runtime behavior.'],
    install: ['Copy only reviewed payload paths into DESTDIR and reject unsafe paths, setuid surprises, and implicit script output.'],
    reject: commonReject,
  },
  rpm: {
    family: 'rpm',
    inspect: ['Verify RPM bytes, header metadata, architecture, payload paths, dependency relations, permissions, and licenses.'],
    prepare: ['Extract payload and metadata with a pinned tool into disposable roots; never run RPM scriptlets.'],
    build: ['Map the retained payload explicitly into Arch layout with no repository or scriptlet execution.'],
    check: ['Verify payload, modes, dependency mapping, license decision, and a clean installed runtime check.'],
    install: ['Install only reviewed files under DESTDIR and reject traversal, host paths, and unexpected generated output.'],
    reject: commonReject,
  },
  appimage: {
    family: 'appimage',
    inspect: ['Verify AppImage bytes, architecture, offset, extracted inventory, desktop metadata, icons, and bundled-versus-system runtime policy.'],
    prepare: ['Extract with a pinned tool into a disposable root; inspection must not execute the image or write to the host.'],
    build: ['Repackage the verified extracted tree deterministically or retain it as a reviewed vendor payload.'],
    check: ['Run the extracted application in the approved isolated runtime profile and verify desktop integration.'],
    install: ['Map application files and launchers explicitly, preserving permissions and license evidence.'],
    reject: commonReject,
  },
  'self-extractor': {
    family: 'self-extractor',
    inspect: ['Classify the format and redistribution terms; support extraction-only tools for known formats and escalate arbitrary installers.'],
    prepare: ['Use pinned extraction tooling in a disposable root with no host writes, prompts, or installer execution.'],
    build: ['Package only an explicitly mapped extracted payload; unsupported behavior remains a reviewed custom-shell candidate.'],
    check: ['Verify offline extraction, safe paths, permissions, architecture, redistribution decision, and recipe-only behavior when required.'],
    install: ['Stage mapped files and license text explicitly; never preserve an installer as an implicit post-install action.'],
    reject: commonReject,
  },
  'script-data': {
    family: 'script-data',
    inspect: ['Identify every installed file, mode, interpreter, data consumer, architecture dependence, and license.'],
    prepare: ['Pin interpreter and data inputs; reject generated files or hooks that are not in the declared output map.'],
    build: ['Run only deterministic preparation needed for the declared script or data payload.'],
    check: ['Execute a bounded script check or data-consumer check; do not assume every package supports --version.'],
    install: ['Use explicit mappings, standard modes, and arch any only when content is architecture independent.'],
    reject: commonReject,
  },
  vcs: {
    family: 'vcs',
    inspect: ['Treat VCS as a source mode: record the commit, submodules, LFS objects, and complete source bundle.'],
    prepare: ['Resolve the moving reference before the build and retain the resulting immutable bytes and provenance.'],
    build: ['Build from the pinned bundle; never resolve a branch, tag, submodule, or LFS object during isolated execution.'],
    check: ['Verify the recorded commit and every nested source input before family-specific checks run.'],
    install: ['Apply the selected build-family mapping; VCS does not create a second renderer or package family.'],
    reject: commonReject,
  },
} as const satisfies Record<PackagingFamily, PackagingGuidance>;

export const PACKAGING_GUIDANCE: Readonly<Record<PackagingFamily, PackagingGuidance>> = guidance;

export function packagingGuidanceFor(family: PackagingFamily): PackagingGuidance {
  const value = PACKAGING_GUIDANCE[family];

  if (!value) throw new Error(`Unknown packaging family: ${String(family)}`);

  return value;
}

export function packagingGuidanceForTemplate(templateId: string): PackagingGuidance | undefined {
  const family = PACKAGING_TEMPLATE_FAMILY[templateId as keyof typeof PACKAGING_TEMPLATE_FAMILY];

  return family ? packagingGuidanceFor(family) : undefined;
}

export function renderFluePackagingGuidance(families: readonly PackagingFamily[] = PACKAGING_FAMILY_ORDER): string {
  const selected = [...new Set(families)];

  if (!selected.length) throw new Error('At least one packaging family is required');

  if (selected.length > PACKAGING_FAMILY_ORDER.length) throw new Error('Too many packaging families');
  const unknown = selected.filter((family) => !PACKAGING_FAMILY_ORDER.includes(family));

  if (unknown.length) throw new Error(`Unknown packaging family: ${unknown[0]}`);
  const ordered = PACKAGING_FAMILY_ORDER.filter((family) => selected.includes(family));

  const sections = ordered.map((family) => {
    const item = packagingGuidanceFor(family);

    return [
      `## ${item.family}`,
      `Inspect: ${item.inspect.join(' ')}`,
      `Prepare: ${item.prepare.join(' ')}`,
      `Build: ${item.build.join(' ')}`,
      `Check: ${item.check.join(' ')}`,
      `Install: ${item.install.join(' ')}`,
      `Reject: ${item.reject.join(' ')}`,
    ].join('\n');
  });

  const result = [
    `Packaging guidance v${PACKAGING_GUIDANCE_VERSION} (upstream ${PACKAGING_GUIDANCE_COMMIT}).`,
    'Use as bounded authoring guidance only. Inspect evidence before choosing a family; the coordinator owns execution, review, signing, and publication.',
    'All preparation, build, check, and packaging stages consume retained inputs offline in the isolated worker. Missing locks, unsafe paths, failed checks, and unknown coverage stop the candidate.',
    ...sections,
  ].join('\n\n');

  if (result.length > 24_000) throw new Error('Packaging guidance exceeds bounded prompt size');

  return result;
}
