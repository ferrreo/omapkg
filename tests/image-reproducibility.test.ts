import { expect, test } from 'bun:test';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const root = new URL('..', import.meta.url).pathname;

const harness = join(root, 'system-images/reproducibility/run.sh');

const adapter = join(root, 'worker/image_reproducibility_test.go');
const systemWorker = join(root, 'worker/factory_image_system_e2e_test.go');
const factoryWorker = join(root, 'worker/factory_image.go');

const profile = join(root, 'system-images/reproducibility/oci-profile.json');
const armProfile = join(root, 'system-images/profiles/aarch64-uefi.json');

const fetcher = join(root, 'system-images/reproducibility/fetch-real-packages.sh');

const toolImage = join(root, 'system-images/reproducibility/prepare-tool-image.sh');
const filesystemFixture = join(root, 'system-images/reproducibility/boot-fixture.sh');

test('system image archive ownership follows mtree defaults and unset directives', () => {
  const builder = readFileSync(join(root, 'scripts/build-system-image.sh'), 'utf8');
  const inspection = builder.slice(builder.indexOf('archive_paths_checked=0'), builder.indexOf('normalize_ext4_metadata()'));
  const script = `set -euo pipefail
die() { echo "$*" >&2; exit 2; }
bsdtar() {
  if [[ "$1" == --list ]]; then printf './srv/ftp\\n'; else printf '%s\\n' "$MTREE" | gzip; fi
}
${inspection}
inspect_package_archive fixture
declare -p allowed_owners
`;
  const run = (mtree: string) => spawnSync('bash', ['-c', script], { env: { ...process.env, MTREE: mtree }, encoding: 'utf8' });
  const result = run('/set uid=0 gid=0\n./srv/ftp time=1 gid=11\n/set uid=5\n./next time=1\n/unset all\n./explicit time=1 uid=8 gid=9');
  expect(result.status).toBe(0);
  for (const pair of ['0:11', '5:0', '8:9']) expect(result.stdout).toContain(pair);
  expect(run('/set uid=0 gid=0\n/unset gid\n./missing time=1').status).toBe(2);
});

test('image reproducibility harness keeps raw comparison and explicit incomplete status', () => {
  const source = readFileSync(harness, 'utf8') + readFileSync(adapter, 'utf8') + readFileSync(factoryWorker, 'utf8') + readFileSync(systemWorker, 'utf8') + readFileSync(fetcher, 'utf8') + readFileSync(toolImage, 'utf8') + readFileSync(filesystemFixture, 'utf8');
  expect(source).toContain('RunReproducibilityPair');
  expect(source).toContain('build-system-image.sh');
  expect(source).toContain('return 3');
  expect(source).toContain('nondeterministic');
  expect(source).toContain('--filesystem-fixture');
  expect(source).toContain('--fetch-real-packages');
  expect(source).toContain('qemu-img gptfdisk dosfstools');
  expect(source).toContain('OPR_IMAGE_REPRO_INPUT_PROFILE');
  expect(source).toContain('firmware_package_name');
  expect(source).toContain('--package-cache');
  expect(source).toContain('SYSTEM_IMAGE_REPRO_PACKAGE_CACHE');
  expect(source).toContain('TestFactoryImageSystemNativeExecution');
  expect(source).toContain('system-context.tar');
  expect(source).toContain('bindFactoryImageContextFile');
  expect(source).not.toContain('openssl s_server');
  expect(source).not.toContain('localhost:8443');
  expect(JSON.parse(readFileSync(profile, 'utf8'))).toMatchObject({ builder: 'buildah', architecture: 'x86_64', sourceDateEpoch: 1700000000 });
  expect(JSON.parse(readFileSync(armProfile, 'utf8'))).toMatchObject({ architecture: 'aarch64', kernel: { package: 'linux-aarch64' }, firmware: { package: 'edk2-aarch64', varsTemplatePath: '/usr/share/edk2/aarch64/QEMU_VARS.fd' } });
});

test('missing boot inputs are incomplete instead of a skipped pass', () => {
  const output = mkdtempSync(join(tmpdir(), 'omapkg-image-repro-test-'));
  const env = { ...process.env };

  for (const key of Object.keys(env)) {
    if (key.startsWith('SYSTEM_IMAGE_REPRO_')) delete env[key as keyof typeof env];
  }

  try {
    const result = spawnSync('bash', [harness, '--boot', '--output', output], { cwd: root, env, encoding: 'utf8' });
    expect(result.status).toBe(3);
    expect(`${result.stdout}${result.stderr}`).toContain('incomplete');
    expect(`${result.stdout}${result.stderr}`).not.toContain('pair passed');
  } finally {
    rmSync(output, { recursive: true, force: true });
  }
});
