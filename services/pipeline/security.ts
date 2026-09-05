import { gitSourcePolicyCommand } from './git-source';
import { materializeSourceArchiveCommand } from './source-archive';

const SHA256 = /^[0-9a-f]{64}$/;
const ARCH_PACKAGE_NAME = /^[a-z0-9][a-z0-9@._+:-]{0,63}$/;
const VERSION = /^[A-Za-z0-9][A-Za-z0-9@._+%]{0,127}$/;
const IMAGE_DIGEST = /^.+@sha256:[0-9a-f]{64}$/;
const MAX_URL_LENGTH = 2_048;
const MAX_DIRECT_SOURCE_BYTES = 2_147_483_648;
const MAX_RECIPE_LENGTH = 128 * 1024;
const MAX_COMMAND_LENGTH = 4_096;
const PACKAGING_VARIABLE = /\$(?:\{(?:pkgdir|srcdir|pkgname|pkgver|pkgrel|CHOST|CARCH)(?![A-Za-z0-9_])|(?:pkgdir|srcdir|pkgname|pkgver|pkgrel|CHOST|CARCH)(?![A-Za-z0-9_]))/;
const INSTALLED_PATH = /\/usr\/share\/(?:man|info)\/[^\s"'`;&|)\]]+/gi;
const MAN_PAGE_PATH = /\/usr\/share\/man\/(?:[^/]+\/)+[^/]+\.[0-9][A-Za-z]*$/i;
const INFO_PAGE_PATH = /\/usr\/share\/info\/[^/]+\.info(?:-[0-9]+)?$/i;
const COMPRESSED_DOC_PATH = /\.(?:gz|bz2|xz|zst|lz4|lz|Z)$/i;
const PRIVATE_HOSTS = new Set([
  'localhost',
  'localhost.localdomain',
  'metadata.google.internal',
  'metadata.google.internal.',
  'instance-data.ec2.internal',
]);

export const MAX_REPAIR_ATTEMPTS = 2;
export const MAX_SOURCE_REDIRECTS = 3;
export const VENDOR_REGISTRY_HOSTS = [
  'proxy.golang.org', 'sum.golang.org', 'storage.googleapis.com',
  'crates.io', 'index.crates.io', 'static.crates.io',
  'registry.npmjs.org',
] as const;

const SENSITIVE_QUERY_PARTS = new Set([
  'accesskey', 'apikey', 'auth', 'authorization', 'bearer', 'credential', 'credentials',
  'jwt', 'password', 'private', 'secret', 'sig', 'signature', 'token',
]);

function sensitiveQueryParameter(name: string): boolean {
  const parts = name.toLowerCase().split(/[^a-z0-9]+/).filter(Boolean);
  const compact = parts.join('');
  return parts.some((part) => SENSITIVE_QUERY_PARTS.has(part)) ||
    /(?:accesskey|accesskeyid|apikey|authorization|credential|password|secret|signature|token)$/.test(compact);
}

export function assertPackageName(value: string): string {
  if (!ARCH_PACKAGE_NAME.test(value)) throw new Error('invalid Arch package name');
  return value;
}

export function assertVersion(value: string): string {
  if (!VERSION.test(value)) throw new Error('invalid Arch pkgver; use letters, digits, @, ., _, +, % only; keep pkgrel separate');
  return value;
}

export function assertSha256(value: string, field = 'sha256'): string {
  if (!SHA256.test(value)) throw new Error(`invalid ${field}`);
  return value;
}

export function assertImageDigest(value: string): string {
  if (!IMAGE_DIGEST.test(value)) throw new Error('imageDigest must be a sha256 digest');
  return value;
}

export function assertCommand(value: string, field = 'command'): string {
  if (!value || value.length > MAX_COMMAND_LENGTH || /[\u0000\r]/.test(value)) {
    throw new Error(`invalid ${field}`);
  }
  return value;
}

export function assertSmokeCommand(value: string): string {
  assertCommand(value, 'smoke command');
  if (PACKAGING_VARIABLE.test(value)) {
    throw new Error('smoke command must use installed paths and cannot reference PKGBUILD variables');
  }
  const branches = value.split(/\|\|/).map((branch) => {
    let hasUncompressed = false;
    let hasCompressed = false;
    for (const segment of branch.split(/&&|[;|\n]/)) {
      const command = segment.trim().replace(/^(?:(?:if|then|else|elif|while|until|do)\s+|!\s+)+/, '');
      if (!/^(?:test|\[\[?)(?:\s|$)/.test(command)) continue;
      for (const match of command.matchAll(INSTALLED_PATH)) {
        const path = match[0];
        if (COMPRESSED_DOC_PATH.test(path)) {
          hasCompressed = true;
        } else if (MAN_PAGE_PATH.test(path) || INFO_PAGE_PATH.test(path)) {
          hasUncompressed = true;
        }
      }
    }
    return { hasUncompressed, hasCompressed };
  });
  for (let index = 0; index < branches.length; index += 1) {
    if (branches[index].hasUncompressed && !branches.some((branch, other) => other !== index && branch.hasCompressed)) {
      throw new Error('smoke command must prefer executable behavior or check compressed man/info paths');
    }
  }
  return value;
}

export function assertRecipeLength(value: string): string {
  if (!value || value.length > MAX_RECIPE_LENGTH || /\u0000/.test(value)) {
    throw new Error('invalid recipe size');
  }
  return value;
}

function isPrivateIpv4(host: string): boolean {
  const parts = host.split('.').map(Number);
  if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) return false;
  const [a, b] = parts;
  return a === 0 || a === 10 || a === 127 || (a === 100 && b >= 64 && b <= 127) ||
    (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) || a >= 224;
}

function isPrivateHost(host: string): boolean {
  const lower = host.toLowerCase().replace(/\.$/, '');
  if (PRIVATE_HOSTS.has(lower) || lower.endsWith('.localhost') || lower.endsWith('.internal')) return true;
  if (isPrivateIpv4(lower)) return true;
  if (lower.includes(':')) return true; // Reject IPv6 literals, including loopback/link-local forms.
  return false;
}

export function normalizeSourceUrl(raw: string): URL {
  if (typeof raw !== 'string' || raw.length === 0 || raw.length > MAX_URL_LENGTH) {
    throw new Error('source URL is required and must be <= 2048 bytes');
  }
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new Error('source URL is invalid');
  }
  if (url.protocol !== 'https:') throw new Error('source URL must use HTTPS');
  if (url.username || url.password || url.port || !url.hostname.includes('.') || url.hostname.endsWith('.') || [...url.searchParams.keys()].some(sensitiveQueryParameter)) {
    throw new Error('source URL must be a permanent HTTPS URL without credentials or signed query parameters');
  }
  if (isPrivateHost(url.hostname)) throw new Error('source URL host is not public');
  url.hash = '';
  return url;
}

export function normalizeRedirectSourceUrl(raw: string): URL {
  if (typeof raw !== 'string' || raw.length === 0 || raw.length > MAX_URL_LENGTH) {
    throw new Error('source redirect URL is invalid');
  }
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new Error('source redirect URL is invalid');
  }
  if (url.protocol !== 'https:' || url.username || url.password || url.port || !url.hostname.includes('.') || url.hostname.endsWith('.')) {
    throw new Error('source redirect must use a public HTTPS URL');
  }
  if (isPrivateHost(url.hostname)) throw new Error('source redirect host is not public');
  url.hash = '';
  return url;
}

export function classifySourceUrl(raw: string): 'git' | 'archive' {
  const url = normalizeSourceUrl(raw);
  const path = url.pathname.toLowerCase();
  if (/\.(?:git|git\/?)$/.test(path)) return 'git';
  if (/\.(?:zip|tar|tgz|tar\.gz|tar\.zst|tar\.xz|tar\.bz2|tar\.lz4|deb|rpm|appimage|run)(?:\/)?$/.test(path)) return 'archive';
  return 'git';
}

export function shellQuote(value: string): string {
  return `'${value.replaceAll("'", "'\\''")}'`;
}

export function sourceFetchCommand(raw: string, destination = '/workspace/source.bundle', options: { allowRedirectQuery?: boolean } = {}): string {
  const url = options.allowRedirectQuery ? normalizeRedirectSourceUrl(raw) : normalizeSourceUrl(raw);
  const headerPath = '/workspace/source.headers';
  const statusPath = '/workspace/source.status';
  return [
    'set -eu',
    `umask 077; rm -f ${shellQuote(destination)} ${shellQuote(headerPath)} ${shellQuote(statusPath)}; curl --silent --show-error --max-redirs 0 --proto '=https' --proto-redir '=https' --tlsv1.2 --max-time 180 --max-filesize ${MAX_DIRECT_SOURCE_BYTES} --dump-header ${shellQuote(headerPath)} --write-out '%{http_code}' ${shellQuote(url.toString())} --output ${shellQuote(destination)} > ${shellQuote(statusPath)}`,
    `http_status=$(cat ${shellQuote(statusPath)}); location=$(awk 'BEGIN { IGNORECASE=1 } tolower($1)=="location:" { sub(/^[^:]*:[[:space:]]*/, ""); print; exit }' ${shellQuote(headerPath)} | tr -d '\\r' | head -c ${MAX_URL_LENGTH}); printf 'http_status=%s\\nredirect_location=%s\\n' "$http_status" "$location"`,
    `case "$http_status" in 2??) test "$(wc -c < ${shellQuote(destination)})" -le ${MAX_DIRECT_SOURCE_BYTES};; 3??) rm -f ${shellQuote(destination)};; *) rm -f ${shellQuote(destination)}; printf 'source HTTP status %s\\n' "$http_status" >&2; exit 69;; esac`,
    `case "$http_status" in 2??) sha256sum ${shellQuote(destination)};; esac`,
    `case "$http_status" in 2??) artifact_magic="$(head -c 8 ${shellQuote(destination)} | od -An -tx1 | tr -d ' \\n')"; printf '\\nartifact_magic=%s' "$artifact_magic"; artifact_candidate=0; case "$artifact_magic" in 213c617263683e0a|edabeedb*|7f454c46*) artifact_candidate=1;; 2321*) if head -c 1048576 ${shellQuote(destination)} | grep -aEq 'Makeself|NVIDIA-Linux|self[- ]extracting'; then artifact_candidate=1; fi;; esac; printf '\\nartifact_candidate=%s' "$artifact_candidate";; esac`,
    `case "$http_status" in 2??) printf '\\nfiles=\\n'; if tar -tf ${shellQuote(destination)} >/dev/null 2>&1; then tar -tf ${shellQuote(destination)} | head -200; elif command -v unzip >/dev/null 2>&1; then unzip -Z1 ${shellQuote(destination)} 2>/dev/null | head -200; fi;; esac`,
  ].join('\n');
}

/**
 * Inspect remote metadata without materializing an upstream archive. The
 * range form is only a bounded fallback for servers that reject HEAD. A FIFO
 * sink reads one byte and closes, while curl's max-file-size guard handles
 * servers that advertise a larger response before sending its body.
 */
export function sourceMetadataCommand(raw: string, options: { allowRedirectQuery?: boolean; method?: 'head' | 'range' } = {}): string {
  const url = options.allowRedirectQuery ? normalizeRedirectSourceUrl(raw) : normalizeSourceUrl(raw);
  const headerPath = '/workspace/upstream.metadata.headers';
  const headerPipe = '/workspace/upstream.metadata.headers.pipe';
  const bodyPipe = '/workspace/upstream.metadata.body.pipe';
  const transfer = options.method === 'range' ? '--range 0-0 --max-filesize 1' : '--head';
  const script = [
    'set +e',
    `umask 077; rm -f ${shellQuote(headerPath)} ${shellQuote(headerPipe)} ${shellQuote(bodyPipe)}; mkfifo ${shellQuote(headerPipe)} ${shellQuote(bodyPipe)}`,
    `{ head -c 65536 ${shellQuote(headerPipe)} > ${shellQuote(headerPath)}; cat > /dev/null; } & header_reader=$!`,
    `head -c 1 ${shellQuote(bodyPipe)} > /dev/null & body_reader=$!`,
    `curl --silent --show-error --max-redirs 0 --proto '=https' --proto-redir '=https' --tlsv1.2 --connect-timeout 15 --max-time 45 ${transfer} --dump-header ${shellQuote(headerPipe)} --output ${shellQuote(bodyPipe)} ${shellQuote(url.toString())} & curl_pid=$!`,
    'wait "$curl_pid"; curl_status=$?',
    'for tick in 1 2 3 4 5; do kill -0 "$header_reader" 2>/dev/null || header_done=1; kill -0 "$body_reader" 2>/dev/null || body_done=1; test "${header_done:-0}" = 1 && test "${body_done:-0}" = 1 && break; sleep 0.1; done',
    'kill "$header_reader" "$body_reader" 2>/dev/null || true',
    'wait "$header_reader"; wait "$body_reader"',
    `http_status="$(awk 'BEGIN { status = "000" } toupper($1) ~ /^HTTP\\/[0-9]/ && $2 ~ /^[0-9][0-9][0-9]$/ { status = $2 } END { print status }' ${shellQuote(headerPath)} 2>/dev/null || printf '000')"`,
    `head -c 65536 ${shellQuote(headerPath)} 2>/dev/null || true; printf '\\nhttp_status=%s\\ncurl_status=%s\\n' "$http_status" "$curl_status"`,
    `rm -f ${shellQuote(headerPath)} ${shellQuote(headerPipe)} ${shellQuote(bodyPipe)}`,
    'exit 0',
  ].join('\n');
  return `bash -ceu ${shellQuote(script)}`;
}

export function gitInspectCommand(raw: string, destination = '/workspace/source', commit?: string): string {
  const url = normalizeSourceUrl(raw);
  if (commit !== undefined && !/^[0-9a-f]{40}(?:[0-9a-f]{24})?$/i.test(commit)) throw new Error('upstream ref must be a commit SHA');
  const bashScript = (script: string): string => `bash -ceu ${shellQuote(script)}`;
  const checkout = commit
    ? [
      `git init ${shellQuote(destination)}`,
      `git -C ${shellQuote(destination)} remote add origin ${shellQuote(url.toString())}`,
      `git -c core.hooksPath=/dev/null -c protocol.file.allow=never -c submodule.recurse=false -C ${shellQuote(destination)} fetch --depth 1 origin ${shellQuote(commit)}`,
      `git -c core.hooksPath=/dev/null -c protocol.file.allow=never -c submodule.recurse=false -C ${shellQuote(destination)} checkout --detach FETCH_HEAD`,
    ]
    : [`git -c core.hooksPath=/dev/null -c protocol.file.allow=never -c submodule.recurse=false clone --depth 1 --no-tags --no-recurse-submodules ${shellQuote(url.toString())} ${shellQuote(destination)}`];
  const script = [
    'set -eu',
    'export GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null',
    `rm -rf ${shellQuote(destination)}`,
    `rm -f ${shellQuote('/workspace/source.tar')}`,
    ...checkout,
    bashScript(gitSourcePolicyCommand({ sourcePath: destination })),
    `printf 'commit='; git -C ${shellQuote(destination)} rev-parse HEAD`,
    `git -c core.hooksPath=/dev/null -c protocol.file.allow=never -c submodule.recurse=false -C ${shellQuote(destination)} archive --format=tar HEAD > ${shellQuote('/workspace/source.tar')}`,
    `printf '\\nsha256='; sha256sum ${shellQuote('/workspace/source.tar')} | cut -d ' ' -f 1`,
    bashScript(materializeSourceArchiveCommand({ sourcePath: '/workspace/source.tar', destination: '/workspace/source' })),
    `printf '\\nfiles=\\n'; cut -f 2 ${shellQuote('/workspace/source-archive.entries')} | head -200`,
  ].join('\n');
  return `bash -ceu ${shellQuote(script)}`;
}

export function gitTagsCommand(raw: string): string {
  const url = normalizeSourceUrl(raw);
  return `set -eu; git ls-remote --tags --sort=-v:refname ${shellQuote(url.toString())} | head -200`;
}

export function materializeSourceTreeCommand(sourceKind: 'git' | 'archive'): string {
  if (sourceKind === 'git') return 'set -eu; test -d /workspace/source';
  return materializeSourceArchiveCommand();
}

export function sourceReadCommand(_sourceKind: 'git' | 'archive', paths: string[]): string {
  return [
    'set -eu',
    ...paths.map((path) => `printf '\\n--- %s ---\\n' ${shellQuote(path)}; file=${shellQuote(`/workspace/source/${path}`)}; if test -f "$file"; then sed -n '1,240p' "$file" | head -c 32768; else printf 'missing\\n'; fi`),
  ].join('\n');
}

export function vendorCommand(kind: 'go' | 'rust' | 'npm', _sourceKind: 'git' | 'archive', sourceRoot?: string): string {
  if (sourceRoot && !/^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$/.test(sourceRoot)) throw new Error('source archive root is unsafe');
  const sourcePath = sourceRoot ? `/workspace/source/${sourceRoot}` : '/workspace/source';
  const common = [
    'set -eu',
    'rm -rf /workspace/vendor.tar /workspace/vendor-components.json /workspace/vendor-component-sha256.tsv /workspace/vendor-config.txt /workspace/vendor-empty /workspace/vendor-work /workspace/cargo-home /workspace/go-home /workspace/go-mod-cache /workspace/npm-cache',
    `test -d ${shellQuote(sourcePath)}`,
    'mkdir -p /workspace/vendor-work',
    `cd ${shellQuote(sourcePath)}`,
  ];
  if (kind === 'go') {
    common.push(
      'test -f go.mod',
      'command -v go >/dev/null 2>&1',
      'export GOTOOLCHAIN=local GOWORK=off GOENV=off GOPROXY=https://proxy.golang.org GOSUMDB=sum.golang.org GOPRIVATE= GONOSUMDB= GONOPROXY= GOINSECURE=',
      'go_mod_json="$(go mod edit -json go.mod)"',
      "if printf '%s\\n' \"$go_mod_json\" | grep -Eq '\"Require\"[[:space:]]*:[[:space:]]*null'; then printf 'vendor_empty=1\\n' > /workspace/vendor-empty; exit 0; fi",
      "if ! test -f go.sum; then printf 'Go source requires a pinned go.sum lockfile\\n' >&2; exit 64; fi",
      "! grep -Eq '^[[:space:]]*replace([[:space:]]|\\()' go.mod",
      'rm -rf vendor',
      'mkdir -p /workspace/go-home /workspace/go-mod-cache',
      'export HOME=/workspace/go-home GOMODCACHE=/workspace/go-mod-cache',
      'go mod download',
      'go mod vendor',
      'find vendor -type l -print -quit | grep -q . && exit 65 || true',
      'go mod download -json all > /workspace/vendor-components.json',
      "tar --sort=name --mtime='UTC 1970-01-01' --owner=0 --group=0 --numeric-owner --format=gnu -cf /workspace/vendor.tar vendor",
      "tar -tf /workspace/vendor.tar | awk 'BEGIN { bad=0 } { if ($0 ~ /^\\// || $0 ~ /(^|\\/)\\.\\.(\\/|$)/) bad=1 } END { exit bad }'",
    );
  } else if (kind === 'rust') {
    common.push(
      'test -f Cargo.toml',
      'test -f Cargo.lock',
      `awk -F'"' '/^[[:space:]]*source[[:space:]]*=[[:space:]]*"/ { if ($2 != "registry+https:\/\/github.com\/rust-lang\/crates.io-index" && $2 != "sparse+https:\/\/index.crates.io\/") exit 65 }' Cargo.lock`,
      'command -v cargo >/dev/null 2>&1',
      'command -v rustc >/dev/null 2>&1',
      'rm -rf /workspace/vendor-work/vendor',
      'mkdir -p /workspace/cargo-home',
      'rustc_path="$(command -v rustc)"',
      'export CARGO_HOME=/workspace/cargo-home CARGO_NET_OFFLINE=false CARGO_REGISTRIES_CRATES_IO_PROTOCOL=sparse RUSTC="$rustc_path" RUSTC_WRAPPER= RUSTC_WORKSPACE_WRAPPER=',
      'unset CARGO_BUILD_RUSTC CARGO_BUILD_RUSTC_WRAPPER CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER CARGO_REGISTRY_GLOBAL_CREDENTIAL_PROVIDERS CARGO_REGISTRIES_CRATES_IO_CREDENTIAL_PROVIDER',
      `cd /workspace/vendor-work && cargo --config 'build.rustc-wrapper=\"\"' --config 'build.rustc-workspace-wrapper=\"\"' --config 'registry.global-credential-providers=[]' --config 'registries.crates-io.credential-provider=[]' --config 'net.offline=false' --config 'http.proxy=\"\"' vendor --manifest-path ${shellQuote(`${sourcePath}/Cargo.toml`)} --locked --versioned-dirs /workspace/vendor-work/vendor > /workspace/vendor-config.txt`,
      'if ! test -d /workspace/vendor-work/vendor; then printf \'vendor_empty=1\\n\' > /workspace/vendor-empty; exit 0; fi',
      'find /workspace/vendor-work/vendor -type l -print -quit | grep -q . && exit 65 || true',
      `cargo --config 'build.rustc-wrapper=\"\"' --config 'build.rustc-workspace-wrapper=\"\"' --config 'registry.global-credential-providers=[]' --config 'registries.crates-io.credential-provider=[]' --config 'net.offline=false' --config 'http.proxy=\"\"' metadata --manifest-path ${shellQuote(`${sourcePath}/Cargo.toml`)} --locked --format-version 1 > /workspace/vendor-components.json`,
      "find /workspace/vendor-work/vendor -mindepth 1 -maxdepth 1 -type d -printf '%f\\n' | sort | while IFS= read -r name; do tar --sort=name --mtime='UTC 1970-01-01' --owner=0 --group=0 --numeric-owner --format=gnu -cf - \"/workspace/vendor-work/vendor/$name\" | sha256sum | cut -d ' ' -f 1 | awk -v n=\"$name\" '{ print n \"\\t\" $1 }'; done > /workspace/vendor-component-sha256.tsv",
      "tar --sort=name --mtime='UTC 1970-01-01' --owner=0 --group=0 --numeric-owner --format=gnu -cf /workspace/vendor.tar -C /workspace/vendor-work vendor",
      "tar -tf /workspace/vendor.tar | awk 'BEGIN { bad=0 } { if ($0 ~ /^\\// || $0 ~ /(^|\\/)\\.\\.(\\/|$)/) bad=1 } END { exit bad }'",
    );
  } else {
    common.push(
      'test -f package.json',
      `dependency_state="$(node -e 'const fs=require("fs"); const p=JSON.parse(fs.readFileSync(process.argv[1],"utf8")); const keys=["dependencies","devDependencies","optionalDependencies","peerDependencies"]; let required=false; for (const key of keys) { const value=p[key]; if (value === undefined) continue; if (!value || typeof value !== "object" || Array.isArray(value)) process.exit(64); if (Object.keys(value).length) required=true; } process.stdout.write(required ? "required" : "empty");' package.json)"`,
      'if test "$dependency_state" = empty; then printf \'vendor_empty=1\\n\' > /workspace/vendor-empty; exit 0; fi',
      "if test -f package-lock.json; then lockfile=package-lock.json; elif test -f npm-shrinkwrap.json; then lockfile=npm-shrinkwrap.json; else printf 'npm lockfile is required\\n' >&2; exit 64; fi",
      'command -v npm >/dev/null 2>&1',
      `node -e 'const fs=require("fs"); const l=JSON.parse(fs.readFileSync(process.argv[1],"utf8")); if (typeof l.lockfileVersion !== "number" || l.lockfileVersion < 2 || !l.packages) process.exit(64); for (const [path,p] of Object.entries(l.packages)) { if (!path) continue; if (typeof p.resolved !== "string" || typeof p.integrity !== "string" || !/^sha(1|512)-[A-Za-z0-9+/=]+$/.test(p.integrity)) process.exit(64); const u=new URL(p.resolved); if (u.protocol !== "https:" || u.hostname !== "registry.npmjs.org" || u.username || u.password || u.port || u.search || u.hash || !u.pathname.startsWith("/")) process.exit(64); }' "$lockfile"`,
      'mkdir -p /workspace/npm-cache',
      "printf '%s\\n' 'registry=https://registry.npmjs.org/' 'ignore-scripts=true' 'audit=false' 'fund=false' > /workspace/npmrc",
      'NPM_CONFIG_USERCONFIG=/workspace/npmrc NPM_CONFIG_REGISTRY=https://registry.npmjs.org/ NPM_CONFIG_IGNORE_SCRIPTS=true npm ci --ignore-scripts --no-audit --no-fund --registry=https://registry.npmjs.org/ --cache=/workspace/npm-cache',
      'command -v realpath >/dev/null 2>&1',
      'root="$(pwd)/node_modules"; find node_modules -type l -exec sh -c \'root="$1"; shift; for link do resolved="$(realpath -m "$link")"; case "$resolved" in "$root"/*) ;; *) exit 65;; esac; done\' sh "$root" {} +',
      'cp "$lockfile" /workspace/vendor-components.json',
      "tar --dereference --sort=name --mtime='UTC 1970-01-01' --owner=0 --group=0 --numeric-owner --format=gnu -cf /workspace/vendor.tar node_modules",
      "tar -tf /workspace/vendor.tar | awk 'BEGIN { bad=0 } { if ($0 ~ /^\\// || $0 ~ /(^|\\/)\\.\\.(\\/|$)/) bad=1 } END { exit bad }'",
    );
  }
  return common.join('\n');
}

export function redactText(value: string): string {
  return value
    .replace(/https?:\/\/[^\s/@]+:[^\s/@]+@/gi, 'https://REDACTED@')
    .replace(/([?&](?:token|secret|password|signature|x-amz-[^=]+))=[^&\s]*/gi, '$1=REDACTED');
}

export function containsForbiddenBuildNetwork(value: string): boolean {
  return /\b(?:curl|wget|fetch|git\s+(?:clone|pull|fetch)|npm\s+(?:install|ci|update)|pnpm\s+(?:install|update|add|fetch)|yarn\s+(?:install|upgrade|add)|cargo\s+(?:fetch|add|install)|go\s+(?:get|install|mod\s+download)|pip\s+install|pacman\s+-S|ssh|scp|nc|netcat)\b/i.test(value);
}

export function isKnownSurface(value: string): value is 'binary' | 'recipe' {
  return value === 'binary' || value === 'recipe';
}
