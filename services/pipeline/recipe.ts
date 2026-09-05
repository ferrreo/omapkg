import type { FactoryCandidate, RecipeLint, VendorKind } from './types';
import type { Source } from '../../src/lib/model';
import { offlineVendorExtractCommand } from './artifacts';
import {
  assertCommand,
  assertImageDigest,
  assertPackageName,
  assertRecipeLength,
  assertSha256,
  assertVersion,
  normalizeSourceUrl,
  shellQuote,
} from './security';

function quote(value: string): string {
  return shellQuote(value.replace(/[\r\n]/g, ' ').trim());
}

function quoteArray(values: string[]): string {
  return `(${values.map(quote).join(' ')})`;
}

function recipeCommands(commands: string[]): string {
  return commands.map((command) => `  ${command}`).join('\n');
}

export interface RecipeRenderOptions {
  sources?: Source[];
  checksums?: string[];
  prepareCommands?: string[];
  vendorKind?: VendorKind;
}

function functionBody(recipe: string, name: 'build' | 'package'): string {
  const start = recipe.indexOf(`${name}() {`);
  if (start < 0) return '';
  const end = recipe.indexOf('\n}', start);
  return recipe.slice(start, end < 0 ? recipe.length : end);
}

function unquoted(value: string): string {
  return value
    .replace(/'(?:[^'\\]|\\.)*'/g, ' ')
    .replace(/"(?:[^"\\]|\\.)*"/g, ' ');
}

function commandSegments(body: string): string[] {
  return unquoted(body)
    .split(/&&|\|\||[;|\n]/)
    .map((segment) => segment.trim())
    .filter(Boolean);
}

function commandName(segment: string): string {
  const withoutControl = segment.replace(/^(?:if|then|else|elif|while|until|do)\s+/, '');
  const withoutAssignments = withoutControl.replace(/^(?:[A-Za-z_][A-Za-z0-9_]*=\S*\s+)+/, '');
  return withoutAssignments.split(/\s+/, 1)[0]?.replace(/^.*\//, '') ?? '';
}

function hasNetworkCommand(recipe: string): boolean {
  return [functionBody(recipe, 'build'), functionBody(recipe, 'package')].some((body) => commandSegments(body).some((segment) => {
    const name = commandName(segment);
    if (name === 'git') return /\bgit\s+(?:clone|pull|fetch)\b/i.test(segment);
    if (name === 'npm') return /\bnpm\s+(?:install|ci|update)\b/i.test(segment);
    if (name === 'pnpm') return /\bpnpm\s+(?:install|update|add|fetch)\b/i.test(segment);
    if (name === 'yarn') return /\byarn\s+(?:install|upgrade|add)\b/i.test(segment);
    if (name === 'cargo') return /\bcargo\s+(?:fetch|add|install)\b/i.test(segment);
    if (name === 'go') return /\bgo\s+(?:get|install|mod\s+download)\b/i.test(segment);
    return ['curl', 'wget', 'fetch', 'pip'].includes(name);
  }));
}

function hasDangerousCommand(recipe: string): boolean {
  return [functionBody(recipe, 'build'), functionBody(recipe, 'package')].some((body) => body
    .split(/&&|\|\||[;|\n]/)
    .map((segment) => ({ raw: segment, parsed: unquoted(segment) }))
    .some(({ raw, parsed }) => {
    const name = commandName(parsed);
    if (/^(?:sudo|mkfs|eval)$/.test(name)) return true;
    if (name === 'rm' && /\brm\s+-rf\s+["']?\/["']?(?:\s|$)/i.test(raw)) return true;
    if (name === 'chmod' && /\bchmod\s+777\b/i.test(parsed)) return true;
    if (name === 'chown' && /\bchown\s+-R\s+["']?\/["']?(?:\s|$)/i.test(raw)) return true;
    return /\/dev\/tcp\//i.test(raw);
  }));
}

export function renderRecipe(candidate: FactoryCandidate, options: RecipeRenderOptions = {}): string {
  const pkgname = assertPackageName(candidate.request.name);
  const pkgver = assertVersion(candidate.version);
  const pkgrel = candidate.pkgrel ?? 1;
  if (!Number.isSafeInteger(pkgrel) || pkgrel < 1 || pkgrel > 9_999) throw new Error('pkgrel must be an integer between 1 and 9999');
  assertImageDigest(candidate.imageDigest);
  if (!candidate.sources.length) throw new Error('at least one source is required');
  if (!candidate.buildCommands.length || !candidate.packageCommands.length) {
    throw new Error('build and package commands are required');
  }
  const sourceRoot = candidate.sourceRoot?.trim() || undefined;
  if (sourceRoot && (candidate.request.sourceKind !== 'archive' || !/^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$/.test(sourceRoot))) {
    throw new Error('invalid archive source root');
  }
  if (sourceRoot && [...candidate.buildCommands, ...candidate.packageCommands].some((command) => /(?:^|[;&|])\s*cd\s+["']?\$\{?srcdir\}?["']?(?:\s|[;&|]|$)/.test(command))) {
    throw new Error('commands must remain relative to the verified source root');
  }

  const sources = options.sources ?? candidate.sources;
  const sourceUrls = sources.map((source) => {
    assertSha256(source.sha256);
    if (!source.name || /[\u0000\r\n/]/.test(source.name) || source.name === '.' || source.name === '..') {
      throw new Error('invalid source name');
    }
    return `${source.name}::${source.url}`;
  });
  const checksums = options.checksums ?? sources.map((source) => source.sha256);
  if (checksums.length !== sources.length || checksums.some((checksum) => checksum !== 'SKIP' && !/^[0-9a-f]{64}$/.test(checksum))) {
    throw new Error('source checksum list is invalid');
  }
  const arches = candidate.architectures.length ? candidate.architectures : ['x86_64'];
  const vendorSources = sources.filter((source) => /^opr-vendor-(?:go|rust|npm)\.tar$/.test(source.name));
  const vendorKind = options.vendorKind ?? vendorSources[0]?.name.match(/^opr-vendor-(go|rust|npm)\.tar$/)?.[1];
  const vendorDirectory = `$srcdir/${sourceRoot ? `${sourceRoot}/` : ''}vendor`;
  const vendorDestination = sourceRoot ? `$srcdir/${sourceRoot}` : '$srcdir';
  const artifactSource = candidate.vendorArtifact
    ? candidate.sources.find((source) => source.sha256 === candidate.vendorArtifact?.sourceSha256)
    : undefined;
  if (candidate.vendorArtifact && !artifactSource) throw new Error('vendor artifact source is missing from source manifest');
  const artifactExtraction = candidate.vendorArtifact && artifactSource
    ? offlineVendorExtractCommand(candidate.vendorArtifact.format, {
      sourcePath: `$srcdir/${artifactSource.name}`,
      destination: '$srcdir/vendor-root',
      sha256: candidate.vendorArtifact.sourceSha256,
      appimageOffset: candidate.vendorArtifact.appimageOffset ?? undefined,
    }).split('\n').map((line) => `  ${line}`)
    : [];
  const license = candidate.license.replace(/[\r\n]/g, ' ').trim();
  if (!license || license.length > 128) throw new Error('invalid license');

  for (const command of [...candidate.buildCommands, ...candidate.packageCommands]) {
    assertCommand(command, 'recipe command');
  }

  const description = candidate.description.replace(/[\r\n]/g, ' ').slice(0, 160);
  const recipe = [
    `# Generated by omapkg factory. Review before build.`,
    `pkgname=${quote(pkgname)}`,
    `pkgver=${quote(pkgver)}`,
    `pkgrel=${pkgrel}`,
    `pkgdesc=${quote(description)}`,
    `arch=${quoteArray([...arches])}`,
    `license=${quoteArray([license])}`,
    `depends=${quoteArray(candidate.dependencies)}`,
    `makedepends=${quoteArray(candidate.makeDependencies ?? [])}`,
    `source=${quoteArray(sourceUrls)}`,
    `sha256sums=${quoteArray(checksums)}`,
    ...(options.prepareCommands?.length ? ['', 'prepare() {', recipeCommands(options.prepareCommands), '}'] : []),
    '',
    'build() {',
    '  cd "$srcdir"',
    ...vendorSources.flatMap((source) => [
      `  test -f "$srcdir/${source.name}"`,
      `  tar --extract --file "$srcdir/${source.name}" --directory "${vendorDestination}" --no-same-owner --no-same-permissions`,
    ]),
    ...artifactExtraction,
    ...(vendorKind === 'go' ? ['  export GOFLAGS="${GOFLAGS:-} -mod=vendor"'] : []),
    ...(vendorKind === 'rust' ? [
      '  mkdir -p "$srcdir/.cargo"',
      '  cat > "$srcdir/.cargo/config.toml" <<EOF',
      '[source.crates-io]',
      'replace-with = "opr-vendor"',
      '[source.opr-vendor]',
      `directory = "${vendorDirectory}"`,
      '[net]',
      'offline = true',
      'EOF',
    ] : []),
    ...(sourceRoot ? [`  cd "$srcdir/${sourceRoot}"`] : []),
    recipeCommands(candidate.buildCommands),
    '}',
    '',
    'package() {',
    `  cd "$srcdir${sourceRoot ? `/${sourceRoot}` : ''}"`,
    recipeCommands(candidate.packageCommands),
    '}',
    '',
  ].join('\n');
  return assertRecipeLength(recipe);
}

type PublicRecipeOptions = {
  sourceKind: 'git' | 'archive';
  sourceUrl: string;
  sourceName: string;
  sourceSha256: string;
  sourceRoot?: string;
  upstreamCommit?: string | null;
  vendorKind?: VendorKind;
  vendorSha256?: string;
};

function sourcePath(name: string): string {
  return `"$srcdir/${name}"`;
}

function isPrivateSourceCache(value: string): boolean {
  try { return /^\/sources\/[a-f0-9]{64}\.tar$/.test(new URL(value).pathname); }
  catch { return false; }
}

function publicVendorCommands(options: PublicRecipeOptions): string[] {
  if (!options.vendorKind && !options.vendorSha256) return [];
  if (!options.vendorKind || !options.vendorSha256 || !/^[0-9a-f]{64}$/.test(options.vendorSha256)) {
    throw new Error('public recipe vendor evidence is incomplete');
  }
  const root = options.sourceRoot ? sourcePath(options.sourceRoot) : '"$srcdir"';
  const vendorTar = sourcePath('.opr-vendor.tar');
  const vendorDirectory = `$srcdir/${options.sourceRoot ? `${options.sourceRoot}/` : ''}vendor`;
  const commands = [
    `cd ${root}`,
    'rm -rf vendor node_modules',
  ];
  if (options.vendorKind === 'go') {
    commands.push(
      'test -f go.mod',
      'test -f go.sum',
      'command -v go >/dev/null 2>&1',
      'export GOTOOLCHAIN=local GOWORK=off GOENV=off GOPROXY=https://proxy.golang.org GOSUMDB=sum.golang.org GOPRIVATE= GONOSUMDB= GONOPROXY= GOINSECURE=',
      'mkdir -p "$srcdir/.opr-go-home" "$srcdir/.opr-go-mod-cache"',
      'HOME="$srcdir/.opr-go-home" GOMODCACHE="$srcdir/.opr-go-mod-cache" go mod download',
      'HOME="$srcdir/.opr-go-home" GOMODCACHE="$srcdir/.opr-go-mod-cache" go mod verify',
      'HOME="$srcdir/.opr-go-home" GOMODCACHE="$srcdir/.opr-go-mod-cache" go mod vendor',
      'find vendor -type l -print -quit | grep -q . && exit 65 || true',
      `tar --sort=name --mtime='UTC 1970-01-01' --owner=0 --group=0 --numeric-owner --format=gnu -cf ${vendorTar} vendor`,
    );
  } else if (options.vendorKind === 'rust') {
    commands.push(
      'test -f Cargo.toml',
      'test -f Cargo.lock',
      'command -v cargo >/dev/null 2>&1',
      'mkdir -p "$srcdir/.opr-cargo-home"',
      'CARGO_HOME="$srcdir/.opr-cargo-home" CARGO_NET_OFFLINE=false CARGO_REGISTRIES_CRATES_IO_PROTOCOL=sparse cargo --config \'build.rustc-wrapper=""\' --config \'build.rustc-workspace-wrapper=""\' --config \'registry.global-credential-providers=[]\' --config \'registries.crates-io.credential-provider=[]\' --config \'net.offline=false\' --config \'http.proxy=""\' vendor --locked --versioned-dirs vendor > "$srcdir/.opr-vendor-config"',
      'find vendor -type l -print -quit | grep -q . && exit 65 || true',
      `mkdir -p .cargo && cat > .cargo/config.toml <<EOF\n[source.crates-io]\nreplace-with = "opr-vendor"\n[source.opr-vendor]\ndirectory = "${vendorDirectory}"\n[net]\noffline = true\nEOF`,
      `tar --sort=name --mtime='UTC 1970-01-01' --owner=0 --group=0 --numeric-owner --format=gnu -cf ${vendorTar} vendor`,
    );
  } else {
    commands.push(
      'test -f package.json',
      'command -v npm >/dev/null 2>&1',
      'if test -f package-lock.json; then lockfile=package-lock.json; elif test -f npm-shrinkwrap.json; then lockfile=npm-shrinkwrap.json; else exit 64; fi',
      'mkdir -p "$srcdir/.opr-npm-cache"',
      'printf "%s\\n" "registry=https://registry.npmjs.org/" "ignore-scripts=true" "audit=false" "fund=false" > "$srcdir/.opr-npmrc"',
      'NPM_CONFIG_USERCONFIG="$srcdir/.opr-npmrc" NPM_CONFIG_REGISTRY=https://registry.npmjs.org/ npm ci --ignore-scripts --no-audit --no-fund --registry=https://registry.npmjs.org/ --cache="$srcdir/.opr-npm-cache"',
      'root="$(pwd)/node_modules"; find node_modules -type l -exec sh -c \'root="$1"; shift; for link do resolved="$(realpath -m "$link")"; case "$resolved" in "$root"/*) ;; *) exit 65;; esac; done\' sh "$root" {} +',
      `tar --dereference --sort=name --mtime='UTC 1970-01-01' --owner=0 --group=0 --numeric-owner --format=gnu -cf ${vendorTar} node_modules`,
    );
  }
  commands.push(
    `printf '%s  %s\\n' '${options.vendorSha256}' ${vendorTar} | sha256sum -c -`,
    'chmod -R u+w "$srcdir/.opr-go-home" "$srcdir/.opr-go-mod-cache" "$srcdir/.opr-cargo-home" "$srcdir/.opr-npm-cache" 2>/dev/null || true',
    'rm -rf "$srcdir/.opr-go-home" "$srcdir/.opr-go-mod-cache" "$srcdir/.opr-cargo-home" "$srcdir/.opr-npm-cache" "$srcdir/.opr-npmrc" "$srcdir/.opr-vendor-config" "$srcdir/.opr-vendor.tar"',
  );
  return commands;
}

export function renderPublicRecipe(candidate: FactoryCandidate, options: PublicRecipeOptions): string {
  if (candidate.surface !== 'recipe') throw new Error('public recipe is only available for Surface B');
  const sourceUrl = normalizeSourceUrl(options.sourceUrl).toString();
  if (options.sourceKind === 'git') {
    const commit = options.upstreamCommit?.toLowerCase() ?? '';
    if (!/^[0-9a-f]{40}(?:[0-9a-f]{24})?$/.test(commit)) throw new Error('public Git recipe requires an immutable commit');
    if (!/^[0-9a-f]{64}$/.test(options.sourceSha256)) throw new Error('public Git recipe source hash is invalid');
    const checkoutName = `${candidate.request.name}-git`;
    const archiveName = options.sourceName;
    const sources: Source[] = [{ name: checkoutName, url: `git+${sourceUrl}#commit=${commit}`, sha256: options.sourceSha256 }];
    const prepareCommands = [
      `git -C ${sourcePath(checkoutName)} archive --format=tar HEAD > ${sourcePath(archiveName)}`,
      `printf '%s  %s\\n' '${options.sourceSha256}' ${sourcePath(archiveName)} | sha256sum -c -`,
      `rm -rf ${sourcePath(checkoutName)}`,
      `bsdtar --extract --file ${sourcePath(archiveName)} --directory "$srcdir" --no-same-owner --no-same-permissions`,
      `rm -f ${sourcePath(archiveName)}`,
      ...publicVendorCommands(options),
    ];
    return renderRecipe(candidate, { sources, checksums: ['SKIP'], prepareCommands, vendorKind: options.vendorKind });
  }
  if (!/^[0-9a-f]{64}$/.test(options.sourceSha256)) throw new Error('public archive recipe source hash is invalid');
  const vendorNames = new Set(['opr-vendor-go.tar', 'opr-vendor-rust.tar', 'opr-vendor-npm.tar']);
  const sources = candidate.sources.filter((source) => !vendorNames.has(source.name));
  if (sources.length === candidate.sources.length) throw new Error('public archive recipe has no vendored source to recreate');
  if (sources.some((source) => isPrivateSourceCache(source.url))) throw new Error('public recipe source still references private sealed storage');
  if (!sources.some((source) => source.name === options.sourceName && source.sha256 === options.sourceSha256 && source.url === sourceUrl)) {
    throw new Error('public archive recipe source does not match reviewed evidence');
  }
  return renderRecipe(candidate, { sources, prepareCommands: publicVendorCommands(options), vendorKind: options.vendorKind });
}

export function lintRecipe(recipe: string, repairAttempts = 0): RecipeLint {
  const checks: RecipeLint['checks'] = [];
  const required = ['pkgname=', 'pkgver=', 'pkgrel=', 'arch=', 'license=', 'source=', 'sha256sums=', 'build() {', 'package() {'];
  for (const marker of required) {
    checks.push({
      name: `contains ${marker}`,
      passed: recipe.includes(marker),
      detail: recipe.includes(marker) ? 'present' : `missing ${marker}`,
    });
  }

  const network = hasNetworkCommand(recipe);
  checks.push({
    name: 'offline build commands',
    passed: !network,
    detail: network ? 'network or package-manager command found' : 'no network command found',
  });

  const dangerous = hasDangerousCommand(recipe);
  checks.push({
    name: 'no privileged or destructive command',
    passed: !dangerous,
    detail: dangerous ? 'privileged or destructive command found' : 'no privileged/destructive command found',
  });

  const buildBody = recipe.match(/build\(\) \{([\s\S]*?)\n\}/)?.[1] ?? '';
  const buildStagesPackage = /\$\{?pkgdir\}?\b/.test(buildBody);
  checks.push({
    name: 'package staging only in package()',
    passed: !buildStagesPackage,
    detail: buildStagesPackage ? '$pkgdir is referenced from build()' : 'build() does not reference $pkgdir',
  });

  const sourceCount = (recipe.match(/^source=/m)?.[0] ? (recipe.match(/source=\(([^)]*)\)/)?.[1].match(/'/g)?.length ?? 0) / 2 : 0);
  const checksumCount = (recipe.match(/sha256sums=\(([^)]*)\)/)?.[1].match(/'/g)?.length ?? 0) / 2;
  checks.push({
    name: 'source/checksum count',
    passed: sourceCount > 0 && sourceCount === checksumCount,
    detail: `${sourceCount} source(s), ${checksumCount} checksum(s)`,
  });

  return { passed: checks.every((check) => check.passed), checks, repairAttempts };
}
