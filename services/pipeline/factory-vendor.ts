import type { SourceEvidence, VendorKind, VendorComponent, FactoryRequest, FactoryEnv, VendorEvidence } from './types';
import type { Sandbox } from '@flue/runtime';
import { vendorCommand, redactText } from './security';
import { audit } from '../../src/lib/server/db';

export function vendorKindForEvidence(evidence: SourceEvidence, sourcePaths: readonly string[] = evidence.files): VendorKind | null {
  const files = new Set(sourcePaths);
  const has = (name: string) => files.has(evidence.sourceRoot ? `${evidence.sourceRoot}/${name}` : name);
  const unsupported = ['pnpm-lock.yaml', 'pnpm-lock.yml', 'yarn.lock'].filter(has);
  if (unsupported.length) throw new Error(`unsupported dependency lockfile: ${unsupported[0]}`);
  const kinds: VendorKind[] = [];
  if (has('go.mod')) {
    kinds.push('go');
  }
  if (has('Cargo.toml')) {
    if (!has('Cargo.lock')) throw new Error('Rust source requires a pinned Cargo.lock lockfile');
    kinds.push('rust');
  }
  if (has('package.json')) {
    kinds.push('npm');
  }
  if (kinds.length > 1) throw new Error(`multiple dependency ecosystems are not supported: ${kinds.join(', ')}`);
  return kinds[0] ?? null;
}

function parseJSONObjects(value: string): unknown[] {
  const result: unknown[] = [];
  let start = -1;
  let depth = 0;
  let quoted = false;
  let escaped = false;
  for (let index = 0; index < value.length; index++) {
    const character = value[index];
    if (quoted) {
      if (escaped) escaped = false;
      else if (character === '\\') escaped = true;
      else if (character === '"') quoted = false;
      continue;
    }
    if (character === '"') {
      quoted = true;
      continue;
    }
    if (character === '{') {
      if (depth === 0) start = index;
      depth++;
    } else if (character === '}' && depth > 0) {
      depth--;
      if (depth === 0 && start >= 0) {
        result.push(JSON.parse(value.slice(start, index + 1)) as unknown);
        start = -1;
      }
    }
  }
  if (depth !== 0 || quoted) throw new Error('vendor component manifest is incomplete');
  return result;
}

function componentText(value: unknown, label: string, maxLength = 512): string {
  if (typeof value !== 'string' || !value || value.length > maxLength || /[\u0000\r\n]/.test(value)) {
    throw new Error(`vendor component ${label} is invalid`);
  }
  return value;
}

function parseGoComponents(raw: string): VendorComponent[] {
  const components: VendorComponent[] = [];
  for (const value of parseJSONObjects(raw)) {
    if (!value || typeof value !== 'object') throw new Error('Go component manifest is invalid');
    const module = value as { Main?: boolean; Path?: unknown; Version?: unknown; Sum?: unknown; GoModSum?: unknown };
    if (module.Main) continue;
    const name = componentText(module.Path, 'name', 256);
    const version = componentText(module.Version, 'version', 128);
    const checksum = typeof module.Sum === 'string' && module.Sum ? module.Sum : module.GoModSum;
    if (typeof checksum !== 'string' || !checksum || checksum.length > 256) throw new Error(`Go component ${name} has no checksum`);
    const source = `https://proxy.golang.org/${name.split('/').map(encodeURIComponent).join('/')}/@v/${encodeURIComponent(version)}.zip`;
    components.push({ name, version, source, checksum, checksumAlgorithm: 'GO-H1', integrity: null, license: null });
  }
  if (!components.length) throw new Error('Go lockfile has no pinned modules');
  if (components.length > 2_048) throw new Error('Go dependency graph exceeds component limit');
  return components;
}

function parseRustComponents(metadataRaw: string, digestRaw: string): VendorComponent[] {
  let metadata: { packages?: Array<{ name?: unknown; version?: unknown; source?: unknown }> };
  try { metadata = JSON.parse(metadataRaw) as typeof metadata; }
  catch { throw new Error('Rust component manifest is invalid'); }
  if (!metadata || (metadata.packages !== undefined && !Array.isArray(metadata.packages))) throw new Error('Rust component manifest is invalid');
  const digests = new Map<string, string>();
  for (const line of digestRaw.split('\n').map((value) => value.trim()).filter(Boolean)) {
    const [name, checksum, ...extra] = line.split('\t');
    if (!name || !checksum || extra.length || !/^[0-9a-f]{64}$/.test(checksum)) throw new Error('Rust component checksum manifest is invalid');
    if (digests.has(name)) throw new Error('Rust component checksum manifest contains duplicates');
    digests.set(name, checksum);
  }
  const components: VendorComponent[] = [];
  for (const packageValue of metadata.packages ?? []) {
    if (!packageValue || typeof packageValue !== 'object' || Array.isArray(packageValue)) throw new Error('Rust component manifest is invalid');
    const name = componentText(packageValue.name, 'name', 256);
    const version = componentText(packageValue.version, 'version', 128);
    if (typeof packageValue.source !== 'string' || !packageValue.source) continue;
    if (!/^registry\+https:\/\/github\.com\/rust-lang\/crates\.io-index$|^sparse\+https:\/\/index\.crates\.io\/$/.test(packageValue.source)) {
      throw new Error(`Rust dependency ${name} uses an unsupported source`);
    }
    const checksum = digests.get(`${name}-${version}`);
    if (!checksum) throw new Error(`Rust component ${name} has no vendored checksum`);
    const license = typeof (packageValue as { license?: unknown }).license === 'string' ? (packageValue as { license: string }).license : null;
    components.push({ name, version, source: packageValue.source, checksum, checksumAlgorithm: 'SHA256', integrity: null, license });
  }
  if (!components.length) throw new Error('Rust lockfile has no registry crates');
  if (components.length > 2_048) throw new Error('Rust dependency graph exceeds component limit');
  return components;
}

function parseNpmComponents(raw: string): VendorComponent[] {
  let lock: { lockfileVersion?: unknown; packages?: Record<string, { name?: unknown; version?: unknown; resolved?: unknown; integrity?: unknown; license?: unknown }> };
  try { lock = JSON.parse(raw) as typeof lock; }
  catch { throw new Error('npm component manifest is invalid'); }
  if (typeof lock.lockfileVersion !== 'number' || lock.lockfileVersion < 2 || !lock.packages) {
    throw new Error('npm lockfile version 2 or newer is required');
  }
  const components: VendorComponent[] = [];
  for (const [path, packageValue] of Object.entries(lock.packages)) {
    if (!path) continue;
    if (!packageValue || typeof packageValue !== 'object' || Array.isArray(packageValue)) throw new Error('npm component manifest is invalid');
    const name = componentText(packageValue.name, 'name', 256);
    const version = componentText(packageValue.version, 'version', 128);
    const source = npmRegistrySource(packageValue.resolved);
    const integrity = componentText(packageValue.integrity, 'integrity', 512);
    if (!/^sha(1|512)-[A-Za-z0-9+/=]+$/.test(integrity)) {
      throw new Error(`npm component ${name} is not a registry package with integrity`);
    }
    const license = typeof packageValue.license === 'string' && packageValue.license.length <= 256 ? packageValue.license : null;
    components.push({ name, version, source, checksum: null, checksumAlgorithm: null, integrity, license });
  }
  if (!components.length) throw new Error('npm lockfile has no packages');
  if (components.length > 2_048) throw new Error('npm dependency graph exceeds component limit');
  return components;
}

function npmRegistrySource(value: unknown): string {
  const source = componentText(value, 'source', 2_048);
  let url: URL;
  try { url = new URL(source); }
  catch { throw new Error('npm component source is invalid'); }
  if (url.protocol !== 'https:' || url.hostname !== 'registry.npmjs.org' || url.username || url.password || url.port || url.search || url.hash || !url.pathname.startsWith('/')) {
    throw new Error('npm component source is not a public registry URL');
  }
  return url.toString();
}

export async function vendorEvidence(
  request: FactoryRequest,
  evidence: SourceEvidence,
  sandbox: Sandbox,
  origin: URL,
  env: Pick<FactoryEnv, 'DB' | 'ARTIFACTS'>,
  sourcePaths?: readonly string[],
): Promise<VendorEvidence | undefined> {
  const kind = vendorKindForEvidence(evidence, sourcePaths);
  if (!kind) return undefined;
  const command = vendorCommand(kind, evidence.sourceKind, evidence.sourceRoot);
  const result = await sandbox.exec(command, { timeoutMs: 900_000 });
  if (result.exitCode !== 0) throw new Error(`dependency vendoring failed: ${redactText(result.stderr).slice(0, 1_000)}`);
  const empty = await sandbox.exec('test -f /workspace/vendor-empty', { timeoutMs: 30_000 });
  if (empty.exitCode === 0) {
    await sandbox.exec('rm -f /workspace/vendor-empty', { timeoutMs: 30_000 });
    return undefined;
  }
  const bundle = await streamSealedSandboxFile(sandbox, '/workspace/vendor.tar', 536_870_912);
  const componentsFile = await sandbox.readFileBuffer('/workspace/vendor-components.json');
  if (componentsFile.byteLength === 0 || componentsFile.byteLength > 8 * 1024 * 1024) throw new Error('vendor component manifest is empty or too large');
  const componentsRaw = new TextDecoder().decode(componentsFile);
  let components: VendorComponent[];
  if (kind === 'go') components = parseGoComponents(componentsRaw);
  else if (kind === 'rust') {
    const digestFile = await sandbox.readFileBuffer('/workspace/vendor-component-sha256.tsv');
    if (digestFile.byteLength === 0 || digestFile.byteLength > 8 * 1024 * 1024) throw new Error('Rust component checksum manifest is empty or too large');
    components = parseRustComponents(componentsRaw, new TextDecoder().decode(digestFile));
  } else components = parseNpmComponents(componentsRaw);
  const digest = bundle.sha256;
  const key = `sources/${digest}.tar`;
  try {
    if (!await env.ARTIFACTS.head(key)) {
      bundle.start();
      await env.ARTIFACTS.put(key, bundle.body, {
        sha256: digest,
        httpMetadata: { contentType: 'application/octet-stream', cacheControl: 'public, max-age=31536000, immutable' },
        customMetadata: { requestId: request.id, sha256: digest, sourceKind: 'vendor', vendorKind: kind },
      });
      await bundle.wait();
    }
  } finally {
    await bundle.stop();
    await sandbox.exec('rm -f /workspace/.opr-vendor-part-*', { timeoutMs: 30_000 });
  }
  await env.DB.batch([audit(env.DB, 'factory', 'vendor.materialized', request.id, {
    sourceKey: key, sourceSha256: digest, vendorKind: kind, componentCount: components.length,
  })]);
  return {
    kind,
    sourceName: `opr-vendor-${kind}.tar`,
    sourceSha256: digest,
    sourceUrl: new URL(`/sources/${digest}.tar`, origin).toString(),
    sourceKey: key,
    components,
  };
}

export async function streamSealedSandboxFile(sandbox: Sandbox, path: string, maxBytes: number): Promise<{
  sha256: string;
  size: number;
  body: ReadableStream<Uint8Array>;
  start: () => void;
  stop: () => Promise<void>;
  wait: () => Promise<void>;
}> {
  const prefix = '/workspace/.opr-vendor-part-';
  const result = await sandbox.exec([
    'set -eu',
    `size=$(stat -c '%s' ${path})`,
    `test "$size" -gt 0 -a "$size" -le ${maxBytes}`,
    `digest=$(sha256sum ${path} | cut -d ' ' -f 1)`,
    `rm -f ${prefix}*`,
    `split -b 4194304 -d -a 6 ${path} ${prefix}`,
    `parts=$(find /workspace -maxdepth 1 -type f -name '.opr-vendor-part-*' | wc -l)`,
    `printf 'size=%s\\nsha256=%s\\nparts=%s\\n' "$size" "$digest" "$parts"`,
  ].join('\n'), { timeoutMs: 180_000 });
  if (result.exitCode !== 0) throw new Error(`vendor bundle sealing failed: ${redactText(result.stderr).slice(0, 1_000)}`);
  const fields = new Map(redactText(result.stdout).split('\n').map((line) => line.split('=', 2) as [string, string]));
  const size = Number(fields.get('size'));
  const parts = Number(fields.get('parts'));
  const digest = fields.get('sha256') ?? '';
  if (!Number.isSafeInteger(size) || size <= 0 || size > maxBytes || !Number.isSafeInteger(parts) || parts < 1 || parts > Math.ceil(maxBytes / 4_194_304) || !/^[0-9a-f]{64}$/.test(digest)) {
    throw new Error('vendor bundle seal is invalid');
  }
  const fixed = new FixedLengthStream(size);
  const writer = fixed.writable.getWriter();
  let started = false;
  let pump = Promise.resolve();
  const start = () => {
    if (started) return;
    started = true;
    pump = (async () => {
      let streamedSize = 0;
      try {
        for (let index = 0; index < parts; index += 1) {
          const suffix = String(index).padStart(6, '0');
          const chunk = await sandbox.readFileBuffer(`${prefix}${suffix}`);
          if (!chunk.byteLength || chunk.byteLength > 4_194_304) throw new Error('vendor bundle chunk is invalid');
          if (streamedSize > size - chunk.byteLength) throw new Error('vendor bundle size changed during streaming');
          streamedSize += chunk.byteLength;
          await writer.write(chunk);
        }
        if (streamedSize !== size) throw new Error('vendor bundle size changed during streaming');
        await writer.close();
      } catch (cause) {
        try {
          await writer.abort(cause);
        } catch {
          // The destination may already have cancelled the stream.
        }
        throw cause;
      }
    })();
    void pump.catch(() => undefined);
  };
  const stop = async () => {
    if (!started) return;
    try {
      await writer.abort(new Error('sealed bundle stream stopped'));
    } catch {
      // The stream may already be closed or cancelled.
    }
    await pump.catch(() => undefined);
  };
  return { sha256: digest, size, body: fixed.readable, start, stop, wait: () => pump };
}
