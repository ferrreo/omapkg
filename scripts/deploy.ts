import { existsSync } from 'node:fs';
import { chmod, mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { spawn } from 'node:child_process';

type Values = Record<string, string>;
type WranglerConfig = Record<string, any>;

function readDotEnv(text: string): Values {
  const values: Values = {};
  for (const raw of text.split('\n')) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    const match = line.match(/^([A-Za-z_][A-Za-z0-9_]*)=(.*)$/);
    if (!match) continue;
    values[match[1]] = match[2].replace(/^(['"])(.*)\1$/, '$2');
  }
  return values;
}

const root = resolve(import.meta.dir, '..');
const file = Bun.file(resolve(root, '.env'));
const fileValues = (await file.exists()) ? readDotEnv(await file.text()) : {};
const values = { ...fileValues, ...process.env } as Values;
const args = new Set(process.argv.slice(2));
const configOnly = args.has('--config-only');
const pipelineRequested = args.has('--pipeline');
const syncSecrets = args.has('--sync-secrets');
const configRequired = [
  'CLOUDFLARE_ACCOUNT_ID', 'CLOUDFLARE_D1_DATABASE_ID', 'D1_DATABASE_NAME', 'ARTIFACTS_BUCKET_NAME',
  'PUBLIC_ORIGIN',
  'GITHUB_REPOSITORY', 'REGISTRY_ACCOUNT_ID', 'PACKAGE_SIGNING_FINGERPRINT', 'SIGNING_KEY_ID',
  'AI_GATEWAY_ACCOUNT_ID', 'AI_GATEWAY_ID', 'PIPELINE_SERVICE', 'SIGNER_SERVICE', 'WEB_WORKER_NAME',
  ...(pipelineRequested ? ['PIPELINE_IMAGE', 'PIPELINE_WORKER_NAME'] : []),
];
const deploymentRequired = configOnly ? configRequired : [
  ...configRequired, 'CLOUDFLARE_API_TOKEN', 'BETTER_AUTH_SECRET', 'GITHUB_CLIENT_ID', 'GITHUB_CLIENT_SECRET',
];
const missing = deploymentRequired.filter((key) => !values[key]?.trim());
if (missing.length) throw new Error(`Missing deployment values: ${missing.join(', ')}`);

const nativeNode = values.OPR_NODE ?? Bun.which('node');
const wrangler = resolve(root, 'node_modules/wrangler/wrangler-dist/cli.js');
if (!configOnly && (!nativeNode || !existsSync(nativeNode))) throw new Error('Native Node runtime not found; set OPR_NODE or put node on PATH before deploying.');
if (!configOnly && !existsSync(wrangler)) throw new Error('Wrangler is not installed; run bun install first.');

const inheritedNames = ['HOME', 'LANG', 'LC_ALL', 'NO_COLOR', 'PATH', 'TERM', 'TMPDIR', 'XDG_CACHE_HOME', 'XDG_CONFIG_HOME'];
const commandEnv: NodeJS.ProcessEnv = Object.fromEntries(
  inheritedNames.flatMap((name) => process.env[name] ? [[name, process.env[name]]] : [])
);
commandEnv.PATH = nativeNode ? `${dirname(nativeNode)}:${commandEnv.PATH ?? ''}` : commandEnv.PATH ?? '';
commandEnv.CLOUDFLARE_API_TOKEN = values.CLOUDFLARE_API_TOKEN;
commandEnv.CLOUDFLARE_ACCOUNT_ID = values.CLOUDFLARE_ACCOUNT_ID;
commandEnv.CI = '1';

function productionURL(name: string): string {
  const value = values[name]?.trim() ?? '';
  let url: URL;
  try { url = new URL(value); }
  catch { throw new Error(`${name} must be an absolute HTTP(S) URL`); }
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || url.search || url.hash) {
    throw new Error(`${name} must be an absolute HTTP(S) URL without credentials or query parameters`);
  }
  return url.origin;
}

function configTemplate(path: string): Promise<WranglerConfig> {
  return readFile(resolve(root, path), 'utf8').then((text) => JSON.parse(text) as WranglerConfig);
}

function databaseConfig(config: WranglerConfig): WranglerConfig {
  const database = config.d1_databases?.[0];
  if (!database) throw new Error('Wrangler template is missing its D1 binding');
  database.database_name = values.D1_DATABASE_NAME;
  database.database_id = values.CLOUDFLARE_D1_DATABASE_ID;
  database.migrations_dir = resolve(root, 'migrations');
  return config;
}

function bucketConfig(config: WranglerConfig): WranglerConfig {
  const bucket = config.r2_buckets?.[0];
  if (!bucket) throw new Error('Wrangler template is missing its R2 binding');
  bucket.bucket_name = values.ARTIFACTS_BUCKET_NAME;
  return config;
}

function vars(config: WranglerConfig, updates: Record<string, string>): WranglerConfig {
  config.vars = { ...(config.vars ?? {}), ...updates };
  return config;
}

function applyWebProduction(config: WranglerConfig): WranglerConfig {
  config.name = values.WEB_WORKER_NAME;
  config.account_id = values.CLOUDFLARE_ACCOUNT_ID;
  config.main = resolve(root, '.svelte-kit/cloudflare/_worker.js');
  if (config.assets?.directory) config.assets.directory = resolve(root, '.svelte-kit/cloudflare');
  databaseConfig(config);
  bucketConfig(config);
  config.services = [
    { binding: 'PIPELINE', service: values.PIPELINE_SERVICE },
    { binding: 'SIGNER', service: values.SIGNER_SERVICE },
  ];
  vars(config, {
    PUBLIC_ORIGIN: productionURL('PUBLIC_ORIGIN'),
    AI_GATEWAY_ID: values.AI_GATEWAY_ID,
    REGISTRY_ACCOUNT_ID: values.REGISTRY_ACCOUNT_ID,
    PACKAGE_SIGNING_FINGERPRINT: values.PACKAGE_SIGNING_FINGERPRINT,
    SIGNING_KEY_ID: values.SIGNING_KEY_ID,
    GITHUB_REPOSITORY: values.GITHUB_REPOSITORY,
    QUARANTINE_HOURS: values.QUARANTINE_HOURS ?? '48',
  });
  return config;
}

function applyPipelineProduction(config: WranglerConfig, pipelineDistDir: string): WranglerConfig {
  config.name = values.PIPELINE_WORKER_NAME ?? values.PIPELINE_SERVICE;
  config.account_id = values.CLOUDFLARE_ACCOUNT_ID;
  config.main = resolve(pipelineDistDir, 'index.js');
  databaseConfig(config);
  bucketConfig(config);
  config.containers = [{ class_name: 'Sandbox', image: values.PIPELINE_IMAGE, instance_type: values.PIPELINE_INSTANCE_TYPE ?? 'basic' }];
  config.services = [{ binding: 'SIGNER', service: values.SIGNER_SERVICE }];
  vars(config, {
    GITHUB_REPOSITORY: values.GITHUB_REPOSITORY,
    PUBLIC_ORIGIN: productionURL('PUBLIC_ORIGIN'),
    AI_GATEWAY_ID: values.AI_GATEWAY_ID,
    AI_GATEWAY_ACCOUNT_ID: values.AI_GATEWAY_ACCOUNT_ID,
    AI_GATEWAY_BYOK_ALIAS: values.AI_GATEWAY_BYOK_ALIAS ?? 'default',
  });
  return config;
}

function pipelineDistDir(config: WranglerConfig): string {
  const name = typeof config.name === 'string' ? config.name : '';
  if (!/^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/.test(name)) throw new Error('Pipeline template name is invalid.');
  return resolve(root, 'services/pipeline/dist', name.replace(/[^A-Za-z0-9]+/g, '_'));
}

function applySignerProduction(config: WranglerConfig): WranglerConfig {
  config.name = values.SIGNER_WORKER_NAME ?? values.SIGNER_SERVICE;
  config.account_id = values.CLOUDFLARE_ACCOUNT_ID;
  config.main = resolve(root, 'signer/src/index.ts');
  bucketConfig(config);
  vars(config, {
    PUBLIC_ORIGIN: productionURL('PUBLIC_ORIGIN'),
    CONTROL_ORIGIN: productionURL('PUBLIC_ORIGIN'),
    KEY_ID: values.SIGNING_KEY_ID,
  });
  return config;
}

async function writeConfig(directory: string, filename: string, config: WranglerConfig): Promise<string> {
  const path = resolve(directory, filename);
  await writeFile(path, `${JSON.stringify(config, null, 2)}\n`, { mode: 0o600 });
  return path;
}

function run(command: string, args: string[], input?: string): Promise<void> {
  return new Promise((resolvePromise, reject) => {
    const child = spawn(command, args, {
      cwd: root,
      env: commandEnv,
      stdio: [input === undefined ? 'inherit' : 'pipe', 'inherit', 'inherit'],
    });
    child.once('error', reject);
    child.once('exit', (code, signal) => {
      if (code === 0) resolvePromise();
      else reject(new Error(`${command} ${args.join(' ')} failed${signal ? ` (${signal})` : ` (${code ?? 'unknown'})`}`));
    });
    if (input !== undefined) {
      child.stdin?.end(`${input}\n`);
    }
  });
}

await mkdir(resolve(root, '.local'), { recursive: true, mode: 0o700 });
const productionDir = configOnly
  ? resolve(root, '.local/production-config')
  : await mkdtemp(resolve(root, '.local/deploy-'));
await mkdir(productionDir, { recursive: true, mode: 0o700 });
await chmod(productionDir, 0o700);
const wranglerArgs = (args: string[], configPath: string) => [wrangler, ...args, '--config', configPath];

const webSecrets = [
  'BETTER_AUTH_SECRET',
  'CONTROL_TOKEN',
  'GITHUB_CLIENT_ID',
  'GITHUB_CLIENT_SECRET',
  'GITHUB_REPO_TOKEN',
  'GITHUB_APP_ID',
  'GITHUB_APP_INSTALLATION_ID',
  'GITHUB_APP_PRIVATE_KEY',
  'REGISTRY_API_TOKEN',
  'SIGNER_TOKEN',
].filter((key) => values[key]?.trim());
const pipelineSecrets = ['GITHUB_REPO_TOKEN', 'SIGNER_TOKEN', 'AI_GATEWAY_TOKEN', 'PIPELINE_TOKEN']
  .filter((key) => values[key]?.trim());

async function deploySecrets(configPath: string, secrets: string[]): Promise<void> {
  for (const key of secrets) await run(nativeNode, wranglerArgs(['secret', 'put', key], configPath), values[key]);
}

async function attachCustomDomain(): Promise<void> {
  const origin = productionURL('PUBLIC_ORIGIN');
  if (!origin.startsWith('https://')) return;
  const hostname = new URL(origin).hostname;
  const response = await fetch(`https://api.cloudflare.com/client/v4/accounts/${values.CLOUDFLARE_ACCOUNT_ID}/workers/domains`, {
    method: 'PUT',
    headers: { Authorization: `Bearer ${values.CLOUDFLARE_API_TOKEN}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ hostname, service: values.WEB_WORKER_NAME }),
  });
  const body = await response.json() as { success?: boolean; errors?: Array<{ message?: string }> };
  if (!response.ok || body.success !== true) {
    const message = (body.errors ?? []).map((error) => error.message).filter(Boolean).join('; ') || response.statusText;
    throw new Error(`Custom domain attachment failed: ${message}`);
  }
}

const web = applyWebProduction(await configTemplate('wrangler.jsonc'));
const webConfigPath = await writeConfig(productionDir, 'wrangler.jsonc', web);
const signer = applySignerProduction(await configTemplate('signer/wrangler.jsonc'));
const signerConfigPath = await writeConfig(productionDir, 'signer.wrangler.jsonc', signer);

if (configOnly) {
  const configPaths = [webConfigPath, signerConfigPath];
  if (pipelineRequested) {
    const pipelineTemplate = await configTemplate('services/pipeline/wrangler.jsonc');
    const pipeline = applyPipelineProduction(pipelineTemplate, pipelineDistDir(pipelineTemplate));
    configPaths.push(await writeConfig(productionDir, 'pipeline.wrangler.json', pipeline));
  }
  console.log(JSON.stringify({ configDirectory: productionDir, configs: configPaths }, null, 2));
} else try {
  await run(process.execPath, ['run', 'check']);
  await run(process.execPath, ['run', 'build']);
  await run(nativeNode, wranglerArgs(['d1', 'migrations', 'apply', values.D1_DATABASE_NAME, '--remote'], webConfigPath));
  if (syncSecrets) await deploySecrets(webConfigPath, webSecrets);
  await run(nativeNode, wranglerArgs(['deploy'], webConfigPath));
  await attachCustomDomain();

  if (pipelineRequested) {
    const pipelineTemplate = await configTemplate('services/pipeline/wrangler.jsonc');
    const pipelineDir = pipelineDistDir(pipelineTemplate);
    const bun = Bun.which('bun') ?? process.execPath;
    await run(bun, ['x', 'vite', 'build', '--config', 'services/pipeline/vite.config.ts']);
    const generatedPath = resolve(pipelineDir, 'wrangler.json');
    if (!existsSync(generatedPath)) throw new Error('Pipeline Vite build did not create its Wrangler config.');
    const pipeline = applyPipelineProduction(JSON.parse(await readFile(generatedPath, 'utf8')) as WranglerConfig, pipelineDir);
    const pipelineConfigPath = await writeConfig(productionDir, 'pipeline.wrangler.json', pipeline);
    if (syncSecrets) await deploySecrets(pipelineConfigPath, pipelineSecrets);
    await run(nativeNode, wranglerArgs(['deploy'], pipelineConfigPath));
  }
  console.log(`Deployment complete (${pipelineRequested ? 'web and pipeline' : 'web'}). ${syncSecrets ? 'Selected runtime secrets were supplied individually.' : 'Existing runtime secrets were retained.'} Provisioning credentials were not forwarded.`);
} finally {
  await rm(productionDir, { recursive: true, force: true });
}
