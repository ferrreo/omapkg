#!/usr/bin/env bun
import { execFileSync, spawnSync } from 'node:child_process';
import { createHash, generateKeyPairSync, sign, verify } from 'node:crypto';
import { accessSync, constants, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, statfsSync } from 'node:fs';
import { homedir, freemem, arch, platform, tmpdir } from 'node:os';
import { basename, dirname, join, resolve } from 'node:path';
import { parseArgs } from 'node:util';
import { canonicalJson } from '../src/lib/canonical-json';

export type DiagnosticStatus = 'passed' | 'failed' | 'skipped' | 'incomplete';

export interface DiagnosticCheck {
  name: string;
  required: boolean;
  status: DiagnosticStatus;
  detail: string;
  remediation?: string;
}

export interface DiagnosticReport {
  schemaVersion: 1;
  kind: 'factory-diagnostic';
  mode: 'readonly' | 'deep';
  namespace: string | null;
  evidencePath?: string;
  checks: DiagnosticCheck[];
  dossier?: { json: string; markdown: string; sha256: string };
}

export interface FactoryCheckOptions {
  deep: boolean;
  json: boolean;
  config?: string;
  workDir?: string;
  preserveFailures: boolean;
}

const digestPattern = /^sha256:[0-9a-f]{64}$/;

const workerIdPattern = /^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/;

const allowedConfigKeys = new Set(['origin', 'workerId', 'privateKey', 'image', 'imageDigest', 'runtimeImage', 'architecture', 'containerRuntime', 'stateDir', 'maxSourceBytes', 'sourceTimeoutSeconds']);

const requiredFreeBytes = Number(process.env.FACTORY_MIN_FREE_BYTES ?? 1_073_741_824);

const requiredFreeMemory = Number(process.env.FACTORY_MIN_FREE_MEMORY_BYTES ?? 536_870_912);
const pinnedHelloRecipeSha256 = 'b2ca6345f5190cc5dff9fba676e87996fb5e9d1ff47f0980270c3310658d6b95';

function check(name: string, required: boolean, status: DiagnosticStatus, detail: string, remediation?: string): DiagnosticCheck {
  return { name, required, status, detail: detail.replace(/[\r\n]+/g, ' ').slice(0, 1_000), ...(remediation ? { remediation } : {}) };
}

function command(name: string, args: string[] = [], timeout = 10_000): { ok: boolean; output: string; error: string } {
  try {
    const output = execFileSync(name, args, { encoding: 'utf8', timeout, stdio: ['ignore', 'pipe', 'pipe'], env: { PATH: process.env.PATH ?? '/usr/local/bin:/usr/bin:/bin' } });

    return { ok: true, output: output.trim().slice(0, 1_000), error: '' };
  } catch (cause) {
    const error = cause instanceof Error ? cause.message : String(cause);

    return { ok: false, output: '', error: error.replace(/[\r\n]+/g, ' ').slice(0, 300) };
  }
}

function safeOrigin(value: unknown): URL | null {
  if (typeof value !== 'string') return null;

  try {
    const url = new URL(value);

    if (url.username || url.password || url.search || url.hash || !url.host || (url.protocol !== 'https:' && !(url.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname)))) return null;

    return url;
  } catch { return null; }
}

function validPinnedImage(value: unknown): boolean {
  return typeof value === 'string' && value.length <= 2_048 && /^\S+@sha256:[0-9a-f]{64}$/.test(value);
}

function configPath(options: FactoryCheckOptions): { path: string | null; explicit: boolean } {
  if (options.config) return { path: resolve(options.config), explicit: true };

  if (process.env.OPR_WORKER_CONFIG) return { path: resolve(process.env.OPR_WORKER_CONFIG), explicit: true };

  return { path: join(process.env.OPR_WORKER_STATE_DIR ? resolve(process.env.OPR_WORKER_STATE_DIR) : join(homedir(), '.config', 'opr-worker'), 'config.json'), explicit: false };
}

export function validateWorkerConfig(filename: string): DiagnosticCheck {
  if (!existsSync(filename)) return check('worker-config', true, 'failed', 'Worker config is missing.', `Create an enrolled worker config at ${filename}; do not put credentials in shell arguments.`);
  let value: unknown;

  try { value = JSON.parse(readFileSync(filename, 'utf8')); } catch { return check('worker-config', true, 'failed', 'Worker config is not valid JSON.', `Repair ${filename} with a valid worker config or pass --config to a valid file.`); }

  if (!value || typeof value !== 'object' || Array.isArray(value)) return check('worker-config', true, 'failed', 'Worker config must be a JSON object.', 'Use the worker config schema from worker/protocol.go.');
  const config = value as Record<string, unknown>;
  const unknown = Object.keys(config).filter((key) => !allowedConfigKeys.has(key)).sort();

  if (unknown.length) return check('worker-config', true, 'failed', `Worker config contains unsupported fields: ${unknown.join(', ')}.`, 'Remove fields outside the permitted worker config schema.');
  let mode = 0o000;

  try { mode = statSync(filename).mode & 0o777; } catch { return check('worker-config', true, 'failed', 'Worker config cannot be inspected.', `Check permissions for ${filename}.`); }

  if (mode & 0o077) return check('worker-config', true, 'failed', 'Worker config is accessible by group or others.', `chmod 600 ${filename} and keep its parent directory private.`);
  const origin = safeOrigin(config.origin);

  if (!origin || typeof config.workerId !== 'string' || !workerIdPattern.test(config.workerId) || typeof config.privateKey !== 'string' || !config.privateKey || !['x86_64', 'aarch64'].includes(String(config.architecture)) || !['podman', 'docker'].includes(String(config.containerRuntime)) || typeof config.stateDir !== 'string' || !config.stateDir) {
    return check('worker-config', true, 'failed', 'Worker config has invalid required fields.', 'Use an HTTPS origin, safe worker ID, private key, x86_64/aarch64 architecture, podman/docker runtime, and stateDir.');
  }

  const pair = (config.image === undefined || config.image === '') && (config.imageDigest === undefined || config.imageDigest === '');

  if (!pair && (typeof config.image !== 'string' || !digestPattern.test(String(config.imageDigest)) || config.image !== `${config.image.split('@')[0]}@${String(config.imageDigest)}` || !validPinnedImage(config.image))) return check('worker-config', true, 'failed', 'Builder image and imageDigest must be a matching digest-pinned pair.', 'Set image to IMAGE@sha256:DIGEST and imageDigest to sha256:DIGEST.');

  if (config.runtimeImage !== undefined && config.runtimeImage !== '' && !validPinnedImage(config.runtimeImage)) return check('worker-config', true, 'failed', 'Runtime image must be digest pinned.', 'Set runtimeImage to IMAGE@sha256:DIGEST or omit it until approved.');

  if (resolve(String(config.stateDir)) !== dirname(resolve(filename))) return check('worker-config', true, 'failed', 'Worker stateDir must be the config file parent.', 'Place config.json directly inside stateDir.');

  return check('worker-config', true, 'passed', `Validated permitted worker config fields at ${filename}; credential values withheld.`);
}

function toolCheck(name: string, args: string[], required: boolean): DiagnosticCheck {
  const result = command(name, args);

  return result.ok ? check(`tool:${name}`, required, 'passed', result.output || `${name} is available.`) : check(`tool:${name}`, required, required ? 'failed' : 'skipped', `${name} is unavailable.`, required ? `Install ${name} through the host's approved image or worker provisioning process; this command never installs it.` : `Install ${name} only when the selected check requires it.`);
}

function configOrigin(filename: string): URL | null {
  try {
    const value = JSON.parse(readFileSync(filename, 'utf8')) as Record<string, unknown>;

    return safeOrigin(value.origin);
  } catch { return null; }
}

function workerExecutionPrerequisites(options: FactoryCheckOptions): { runtime: string | null; image: string | null; runtimeImage: string | null } {
  const selected = configPath(options);

  if (!selected.path || !existsSync(selected.path)) return { runtime: null, image: null, runtimeImage: null };

  try {
    const config = JSON.parse(readFileSync(selected.path, 'utf8')) as Record<string, unknown>;
    const runtime = config.containerRuntime === 'podman' || config.containerRuntime === 'docker' ? config.containerRuntime : null;
    const image = validPinnedImage(config.image) ? String(config.image) : null;
    const runtimeImage = validPinnedImage(config.runtimeImage) ? String(config.runtimeImage) : null;

    return { runtime, image, runtimeImage };
  } catch { return { runtime: null, image: null, runtimeImage: null }; }
}

async function connectivity(name: string, raw: string, required: boolean): Promise<DiagnosticCheck> {
  const url = safeOrigin(raw);

  if (!url) return check(`connectivity:${name}`, required, 'failed', 'Configured service URL is invalid or contains credentials.', 'Use an absolute HTTPS URL without query credentials.');
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 5_000);

  try {
    const response = await fetch(url, { method: 'HEAD', redirect: 'manual', signal: controller.signal });

    return check(`connectivity:${name}`, required, 'passed', `Connected to ${url.origin}; HTTP ${response.status}.`);
  } catch {
    return check(`connectivity:${name}`, required, required ? 'failed' : 'skipped', `Could not connect to ${url.origin}.`, `Verify service availability and outbound HTTPS from this host; no configuration was changed.`);
  } finally { clearTimeout(timer); }
}

function baseChecks(options: FactoryCheckOptions): DiagnosticCheck[] {
  const result: DiagnosticCheck[] = [
    check('native-architecture', true, 'passed', `${platform()} ${arch()} (${arch() === 'x64' ? 'x86_64' : arch() === 'arm64' ? 'aarch64' : 'unknown'}).`),
    toolCheck('bun', ['--version'], true),
    toolCheck('go', ['version'], true),
    toolCheck('git', ['--version'], true),
    toolCheck('jq', ['--version'], false),
  ];

  const runtime = process.env.OPR_CONTAINER_RUNTIME === 'docker' ? 'docker' : process.env.OPR_CONTAINER_RUNTIME === 'podman' ? 'podman' : ['podman', 'docker'].find((name) => command(name, ['--version']).ok) ?? null;
  result.push(runtime ? toolCheck(runtime, ['--version'], true) : check('container-isolation', true, 'failed', 'Neither podman nor docker is available.', 'Install and configure one rootless OCI runtime through worker provisioning; this command does not install host dependencies.'));

  if (runtime) {
    const info = command(runtime, ['info', '--format', '{{.Host.OS}}'], 15_000);
    result.push(info.ok ? check('container-isolation', true, 'passed', `${runtime} responds to read-only info.`) : check('container-isolation', true, 'failed', `${runtime} is installed but isolation info failed.`, `Start the rootless ${runtime} service and verify user namespaces without changing this service configuration.`));
  }

  const paths = configPath(options);
  const config = existsSync(paths.path ?? '') ? validateWorkerConfig(paths.path!) : paths.explicit ? validateWorkerConfig(paths.path!) : check('worker-config', false, 'skipped', 'No worker config was selected; local diagnostics remain read-only.', 'Pass --config or OPR_WORKER_CONFIG to validate a worker config.');
  result.push(config);
  const storage = paths.path && existsSync(paths.path) ? dirname(paths.path) : process.cwd();

  try {
    const stat = statfsSync(storage);
    const freeBytes = Number(stat.bavail) * Number(stat.bsize);
    result.push(check('storage-permissions', true, (() => { try { accessSync(storage, constants.R_OK | constants.X_OK);

 return 'passed'; } catch { return 'failed'; } })(), `Storage path ${storage} is readable; free bytes ${freeBytes.toLocaleString()}.`, `Grant the worker account read/execute access to ${storage} without broadening credential permissions.`));
    result.push(check('storage-capacity', true, freeBytes >= requiredFreeBytes ? 'passed' : 'failed', `Free storage: ${freeBytes.toLocaleString()} bytes.`, `Free at least ${requiredFreeBytes.toLocaleString()} bytes in the worker state filesystem.`));
  } catch { result.push(check('storage-permissions', true, 'failed', `Storage path ${storage} cannot be inspected.`, 'Choose an existing local worker state directory.')); }

  result.push(check('memory-capacity', true, freemem() >= requiredFreeMemory ? 'passed' : 'failed', `Free memory: ${freemem().toLocaleString()} bytes.`, `Free at least ${requiredFreeMemory.toLocaleString()} bytes before running deep checks.`));
  const origin = paths.path && existsSync(paths.path) ? configOrigin(paths.path) : null;

  if (origin) result.push({ name: 'connectivity:worker-origin', required: true, status: 'skipped', detail: `Configured origin ${origin.origin} will be checked asynchronously.` });
  else result.push(check('connectivity:worker-origin', false, 'skipped', 'No worker origin is configured.'));

  for (const [name, envName] of [['pipeline', 'PIPELINE_URL'], ['signer', 'SIGNER_URL']] as const) {
    const value = process.env[envName];
    result.push(value ? { name: `connectivity:${name}`, required: false, status: 'skipped', detail: `Configured ${name} URL will be checked asynchronously.` } : check(`connectivity:${name}`, false, 'skipped', `Optional ${name} service is not configured.`));
  }

  return result;
}

function fixtureDigest(filename: string): string {
  return createHash('sha256').update(readFileSync(filename)).digest('hex');
}

function runCommandCheck(name: string, cwd: string, args: string[], required: boolean, remediation: string, envRoot = cwd, extraEnv: NodeJS.ProcessEnv = {}, incompleteOnSkip = false): DiagnosticCheck {
  const result = spawnSync(name, args, { cwd, encoding: 'utf8', timeout: 120_000, stdio: ['ignore', 'pipe', 'pipe'], env: { ...fixtureEnvironment(envRoot), ...extraEnv } });
  const output = `${result.stdout || ''}\n${result.stderr || ''}`.trim().slice(-800);
  if (result.status === 3) return check(`deep:${basename(name)} ${args.join(' ')}`, required, 'incomplete', output || 'Prerequisites are unavailable.', remediation);
  if (result.status === 0) {
    const skipped = incompleteOnSkip && /(?:skip|incomplete|not set)/i.test(output);
    return check(`deep:${basename(name)} ${args.join(' ')}`, required, skipped ? 'incomplete' : 'passed', skipped ? output || 'Prerequisites are unavailable.' : output || 'Completed.', skipped ? remediation : undefined);
  }
  return check(`deep:${basename(name)} ${args.join(' ')}`, required, 'failed', output || 'Command failed', remediation);
}

function fixtureEnvironment(root: string): NodeJS.ProcessEnv {
  return { PATH: process.env.PATH ?? '/usr/local/bin:/usr/bin:/bin', HOME: root, TMPDIR: root, GOPROXY: 'off', GOSUMDB: 'off', GOTOOLCHAIN: 'local', CI: '1' };
}

function removeOwned(path: string): boolean {
  try { rmSync(path, { recursive: true, force: true }); return true; } catch { return false; }
}

export async function runDiagnostic(options: FactoryCheckOptions): Promise<DiagnosticReport> {
  const checks = baseChecks(options);

  for (const name of ['worker-origin'] as const) {
    const selected = configPath(options);

    if (selected.path && existsSync(selected.path)) {
      const origin = configOrigin(selected.path);

      if (origin) {
        const result = await connectivity(name, origin.toString(), true);
        const index = checks.findIndex((item) => item.name === `connectivity:${name}`);

        if (index >= 0) checks[index] = result;
      }
    }
  }

  for (const [name, envName] of [['pipeline', 'PIPELINE_URL'], ['signer', 'SIGNER_URL']] as const) {
    const value = process.env[envName];

    if (value) {
      const result = await connectivity(name, value, false);
      const index = checks.findIndex((item) => item.name === `connectivity:${name}`);

      if (index >= 0) checks[index] = result;
    }
  }

  return { schemaVersion: 1, kind: 'factory-diagnostic', mode: 'readonly', namespace: null, checks };
}

export async function runDeepCheck(options: FactoryCheckOptions): Promise<DiagnosticReport> {
  const readonly = await runDiagnostic(options);
  const root = options.workDir ? resolve(options.workDir) : mkdtempSync(join(tmpdir(), 'omapkg-factory-check-'));
  const namespace = `factory-check-${process.pid}-${Date.now().toString(36)}`;
  const owned = !options.workDir;
  const checks = [...readonly.checks];
  const execution = workerExecutionPrerequisites(options);
  let fixtureRoot = '';

  try {
    fixtureRoot = join(root, namespace);
    mkdirSync(fixtureRoot, { recursive: true, mode: 0o700 });
    const hello = resolve('worker/testdata/hello/PKGBUILD');

    if (!existsSync(hello)) checks.push(check('deep:source-verification', true, 'failed', 'Pinned hello fixture is missing.', 'Restore worker/testdata/hello/PKGBUILD.'));
    else {
      const sourceDigest = fixtureDigest(hello);
      checks.push(check('deep:source-verification', true, sourceDigest === pinnedHelloRecipeSha256 ? 'passed' : 'failed', sourceDigest === pinnedHelloRecipeSha256 ? `Verified pinned fixture PKGBUILD SHA-256 ${sourceDigest}.` : `PKGBUILD SHA-256 ${sourceDigest} differs from pinned fixture identity.`, 'Restore the reviewed worker/testdata/hello/PKGBUILD fixture or update its reviewed digest.'));
      const recipeRendering = runCommandCheck('bun', '.', ['test', 'tests/recipe-templates.test.ts'], true, 'Run the real typed recipe renderer fixtures.', fixtureRoot);
      checks.push({ ...recipeRendering, name: 'deep:recipe-rendering' });
      const systemPolicy = runCommandCheck('bash', '.', ['system-images/test.sh'], true, 'Run the system image policy self-check.', fixtureRoot);
      checks.push({ ...systemPolicy, name: 'deep:system-policy' });
      const oprPolicy = runCommandCheck('go', 'worker', ['test', '-run', '^TestRunner', '-count=1'], true, 'Run the worker runner fixture tests.', fixtureRoot);
      checks.push({ ...oprPolicy, name: 'deep:opr-policy' });
      const guidance = existsSync('services/pipeline/packaging-guidance.ts') ? readFileSync('services/pipeline/packaging-guidance.ts', 'utf8') : '';
      const families = ['autotools', 'plain-make', 'cmake', 'meson', 'rust', 'python', 'node', 'electron', 'archive', 'deb', 'rpm', 'appimage', 'run', 'script', 'go'];
      const missingFamilies = families.filter((family) => !guidance.includes(`'${family}`) && !guidance.includes(`"${family}`));
      checks.push(check('deep:template-guidance', true, missingFamilies.length ? 'incomplete' : 'passed', missingFamilies.length ? `Template guidance is missing families: ${missingFamilies.join(', ')}.` : `Template guidance covers ${families.length} required families.`, 'Add reviewed local guidance for every required template family.'));
      const repair = runCommandCheck('bun', '.', ['test', 'tests/factory-runs.test.ts', 'tests/workflow-retry.test.ts'], true, 'Run the durable factory repair fixtures.', fixtureRoot);
      checks.push({ ...repair, name: 'deep:repair-loop' });
      const dossierExportDir = join(fixtureRoot, 'dossier-export');
      const dossier = runCommandCheck('bun', '.', ['test', 'tests/factory-dossier.test.ts'], true, 'Run the real dossier render/export fixtures.', fixtureRoot, { FACTORY_DOSSIER_EXPORT_DIR: dossierExportDir });
      const exportedJson = join(dossierExportDir, 'dossier.json');
      const exportedMarkdown = join(dossierExportDir, 'dossier.md');
      let dossierExport = dossier.status;
      let dossierDetail = dossier.detail;
      if (dossier.status === 'passed') {
        try {
          const jsonText = readFileSync(exportedJson, 'utf8');
          const parsed = JSON.parse(jsonText) as Record<string, unknown>;
          if (!parsed || parsed.kind !== 'factory-package-dossier' || canonicalJson(parsed) !== jsonText.trimEnd() || !existsSync(exportedMarkdown) || statSync(exportedJson).size === 0 || statSync(exportedMarkdown).size === 0) throw new Error('dossier export files are incomplete or noncanonical');
          dossierDetail = `${dossier.detail} exported ${statSync(exportedJson).size} JSON bytes and ${statSync(exportedMarkdown).size} Markdown bytes.`;
        } catch (cause) {
          dossierExport = 'failed';
          dossierDetail = cause instanceof Error ? cause.message : String(cause);
        }
      }
      checks.push({ ...dossier, name: 'deep:dossier-export', status: dossierExport, detail: dossierDetail });
      const cohort = runCommandCheck('bun', '.', ['test', 'tests/rebuild-cohort.test.ts'], true, 'Run the real cohort fixture path.', fixtureRoot);
      checks.push({ ...cohort, name: 'deep:cohort' });
      const pair = runCommandCheck('go', 'worker', ['test', '-run', '^TestRunReproducibilityPair', '-count=1'], true, 'Run the shared RunReproducibilityPair harness.', fixtureRoot);
      checks.push({ ...pair, name: 'deep:reproducibility-pair-harness' });
      const reproEnv = execution.image && execution.runtimeImage ? {
        OPR_WORKER_REPRO_IMAGE: execution.image,
        OPR_WORKER_REPRO_RUNTIME_IMAGE: execution.runtimeImage,
        OPR_WORKER_REPRO_RUNTIME: execution.runtime ?? 'podman',
      } : {};
      const nativeRepro = runCommandCheck('go', 'worker', ['test', '-run', '^TestReproducibilityHarnessNativeOCI$', '-count=1', '-v'], true, 'Provide a local digest-pinned builder/runtime pair for real native A/B builds.', fixtureRoot, reproEnv, true);
      checks.push({ ...nativeRepro, name: 'deep:isolated-build' });
      checks.push({ ...nativeRepro, name: 'deep:clean-runtime' });
      checks.push({ ...nativeRepro, name: 'deep:single-build-reproducibility' });
      const matrixEnv = execution.image && execution.runtimeImage ? {
        OPR_WORKER_TEMPLATE_MATRIX_IMAGE: execution.image,
        OPR_WORKER_TEMPLATE_MATRIX_RUNTIME_IMAGE: execution.runtimeImage,
        OPR_WORKER_TEMPLATE_MATRIX_RUNTIME: execution.runtime ?? 'podman',
        OPR_WORKER_TEMPLATE_MATRIX_ARCH: arch() === 'arm64' ? 'aarch64' : 'x86_64',
      } : {};
      const matrix = runCommandCheck('go', 'worker', ['test', '-run', '^TestTemplateFamilyReproducibilityNativeOCI$', '-count=1', '-v'], true, 'Provide a local digest-pinned builder/runtime pair for the template matrix.', fixtureRoot, matrixEnv, true);
      checks.push({ ...matrix, name: 'deep:template-matrix' });
      const { privateKey, publicKey } = generateKeyPairSync('ed25519');
      const signingPayload = Buffer.from(`factory-self-check:${namespace}`);
      const signature = sign(null, signingPayload, privateKey);
      checks.push(check('deep:test-signing-identity', true, verify(null, signingPayload, publicKey, signature) ? 'passed' : 'failed', 'Ephemeral local test identity verified a signed fixture payload.'));
    }

    checks.push(check('deep:live-agent', false, 'skipped', 'No live-agent CLI mode is exposed; live model spend remains disabled.'));
    const imageTools = process.env.FACTORY_CHECK_IMAGE_ACCEPTANCE === '1' && command('buildah', ['--version']).ok && command('jq', ['--version']).ok;
    const imageRepro = imageTools && arch() === 'x64'
      ? runCommandCheck('bash', '.', ['system-images/reproducibility/run.sh', '--oci', '--output', join(fixtureRoot, 'image-repro')], true, 'Install the approved native image tools and provide required image inputs.', fixtureRoot, {}, false)
      : check('deep:image-reproducibility', true, 'incomplete', 'Native image acceptance is disabled by default or its prerequisites are unavailable.', 'Set FACTORY_CHECK_IMAGE_ACCEPTANCE=1 only for an explicit native image exercise with buildah, jq, /dev/kvm, and approved image inputs.');
    checks.push({ ...imageRepro, name: 'deep:image-reproducibility' });
    const profiles = readdirSync('system-images/profiles', { withFileTypes: true }).filter((entry) => entry.isFile() && entry.name.endsWith('.json'));

    for (const profile of profiles) {
      const parsed = JSON.parse(readFileSync(join('system-images/profiles', profile.name), 'utf8')) as Record<string, unknown>;
      checks.push(check(`deep:image-profile:${profile.name}`, true, parsed.requiresNative === true && parsed.requiresKvm === true ? 'incomplete' : 'failed', parsed.requiresNative === true && parsed.requiresKvm === true ? 'The exact boot/filesystem profile harness was not run; profile remains incomplete.' : 'Image profile does not declare required native/KVM policy.', 'Run the exact profile harness with its native tools, /dev/kvm, and approved image inputs; this command will not install or configure it.'));
    }

    let evidencePath = options.preserveFailures ? fixtureRoot : undefined;
    if (!options.preserveFailures) {
      const fixtureClean = removeOwned(fixtureRoot);
      const rootClean = fixtureClean && (!owned || removeOwned(root));
      if (!rootClean) {
        evidencePath = fixtureRoot;
        checks.push(check('deep:cleanup', true, 'failed', 'Owned fixture resources could not be cleaned up.', 'Inspect or unmount retained fixture resources, then rerun with --preserve-failures for evidence.'));
      }
    }

    return { schemaVersion: 1, kind: 'factory-diagnostic', mode: 'deep', namespace, ...(evidencePath ? { evidencePath } : {}), checks };
  } catch (cause) {
    if (!options.preserveFailures) {
      const fixtureClean = fixtureRoot ? removeOwned(fixtureRoot) : true;
      if (fixtureClean && owned) removeOwned(root);
    }
    checks.push(check('deep:execution', true, 'failed', cause instanceof Error ? cause.message : String(cause), 'Inspect the retained fixture evidence and rerun with --preserve-failures.'));

    return { schemaVersion: 1, kind: 'factory-diagnostic', mode: 'deep', namespace, checks };
  }
}

function printReport(report: DiagnosticReport, json: boolean): void {
  if (json) { console.log(JSON.stringify(report));

 return; }

  console.log(`${report.kind} (${report.mode})${report.namespace ? ` namespace=${report.namespace}` : ''}${report.evidencePath ? ` evidence=${report.evidencePath}` : ''}`);

  for (const item of report.checks) console.log(`${item.status.padEnd(10)} ${item.required ? 'required' : 'optional'} ${item.name}: ${item.detail}${item.remediation ? ` Remediation: ${item.remediation}` : ''}`);
  const failing = report.checks.filter((item) => item.required && (item.status === 'failed' || item.status === 'incomplete'));
  console.log(failing.length ? `${failing.length} required check(s) need attention.` : 'All required checks passed.');
}

function parseOptions(): FactoryCheckOptions {
  const { values } = parseArgs({ options: { deep: { type: 'boolean', default: false }, json: { type: 'boolean', default: false }, config: { type: 'string' }, 'work-dir': { type: 'string' }, 'preserve-failures': { type: 'boolean', default: false } } });

  return { deep: Boolean(values.deep), json: Boolean(values.json), config: values.config, workDir: values['work-dir'], preserveFailures: Boolean(values['preserve-failures']) };
}

if (import.meta.main) {
  if (process.argv.includes('--help') || process.argv.includes('-h')) {
    console.log('Usage: bun scripts/factory-check.ts [--json] [--config PATH] [--deep] [--work-dir PATH] [--preserve-failures]');
    process.exit(0);
  }
  const options = parseOptions();
  const report = options.deep ? await runDeepCheck(options) : await runDiagnostic(options);
  printReport(report, options.json);

  if (report.checks.some((item) => item.required && (item.status === 'failed' || item.status === 'incomplete'))) process.exitCode = 1;
}
