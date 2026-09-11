import { expect, test } from 'bun:test';
import { createHash } from 'node:crypto';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
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
  const inspection = builder.slice(builder.indexOf('archive_paths_checked=0'), builder.indexOf('\ntemporary_root='));
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

test('system image ownership accepts target accounts and groups but rejects undeclared IDs', () => {
  const builder = readFileSync(join(root, 'scripts/build-system-image.sh'), 'utf8');
  const start = builder.indexOf('declare -A image_uids=()');
  const end = builder.indexOf('\nuncontrolled_timestamp=$(find "$root"', start);
  expect(start).toBeGreaterThanOrEqual(0);
  expect(end).toBeGreaterThan(start);
  const directory = mkdtempSync(join(tmpdir(), 'omapkg-image-owners-'));
  mkdirSync(join(directory, 'etc'));
  writeFileSync(join(directory, 'etc/passwd'), 'root:x:0:0::/:/bin/sh\nuuidd:x:971:971::/:/usr/bin/nologin\n');
  writeFileSync(join(directory, 'etc/group'), 'root:x:0:\nuuidd:x:971:\nsystemd-journal:x:981:\n');
  const script = `set -euo pipefail
root=\${TEST_ROOT:?}
declare -A allowed_owners=()
die() { exit 2; }
safe_file() { [[ -f "$1" && ! -L "$1" ]]; }
find() { printf '%s/fake\\n' "$root"; }
stat() { printf '%s\\n' "$TEST_OWNER"; }
${builder.slice(start, end)}
`;
  try {
    for (const [owner, status] of [['971:971', 0], ['0:981', 0], ['972:971', 2], ['0:982', 2]] as const) {
      const result = spawnSync('bash', ['-c', script], { env: { ...process.env, TEST_ROOT: directory, TEST_OWNER: owner }, encoding: 'utf8' });
      expect(result.status).toBe(status);
    }
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test('system image metadata hashes retained firmware members without host firmware', () => {
  const builder = readFileSync(join(root, 'scripts/build-system-image.sh'), 'utf8');
  const start = builder.indexOf('profile_recipe=$(sha256_value "$builder_script")');
  const end = builder.indexOf('\njq -cS -n --arg profile', start);
  expect(start).toBeGreaterThanOrEqual(0);
  expect(end).toBeGreaterThan(start);
  const metadata = builder.slice(start, end);
  const directory = mkdtempSync(join(tmpdir(), 'omapkg-image-firmware-test-'));
  const stage = join(directory, 'stage');
  const cache = join(directory, 'cache');
  const fixtureName = directory.slice(directory.lastIndexOf('/') + 1);
  const codePath = `/opr-firmware-${fixtureName}/code.fd`;
  const varsPath = `/opr-firmware-${fixtureName}/vars.fd`;
  const memberDirectory = join(stage, codePath.slice(1, codePath.lastIndexOf('/')));
  mkdirSync(memberDirectory, { recursive: true });
  mkdirSync(cache);
  writeFileSync(join(memberDirectory, 'code.fd'), 'firmware-code');
  writeFileSync(join(memberDirectory, 'vars.fd'), 'firmware-vars');
  const archive = join(cache, 'firmware-1-any.pkg.tar.zst');
  const archiveResult = spawnSync('tar', ['-cf', archive, '-C', stage, codePath.slice(1), varsPath.slice(1)], { encoding: 'utf8' });
  expect(archiveResult.status).toBe(0);
  writeFileSync(join(directory, 'profile.json'), JSON.stringify({ architecture: 'x86_64', firmware: { package: 'firmware-fixture', codePath, varsTemplatePath: varsPath } }));
  writeFileSync(join(directory, 'lock.json'), JSON.stringify({ packages: [{ name: 'firmware-fixture', filename: 'firmware-1-any.pkg.tar.zst', sha256: '0'.repeat(64) }] }));
  const script = `set -euo pipefail
die() { echo "$*" >&2; exit 2; }
sha256_value() { sha256sum "$1" | awk '{print $1}'; }
root=\${TEST_ROOT:?}
profile="$root/profile.json"
lock="$root/lock.json"
cache="$root/cache"
builder_script=/dev/null
${metadata}
printf '%s\\n' "$archive_code_sha" "$archive_vars_sha"
`;
  try {
    const result = spawnSync('bash', ['-c', script], { env: { ...process.env, TEST_ROOT: directory }, encoding: 'utf8' });
    const codeSha = createHash('sha256').update('firmware-code').digest('hex');
    const varsSha = createHash('sha256').update('firmware-vars').digest('hex');
    expect(result.status).toBe(0);
    expect(result.stdout.trim()).toBe(`${codeSha}\n${varsSha}`);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test.skipIf(!Bun.which('mkfs.ext4'))('fresh ext4 construction preserves reproducible bytes across staging order and time', async () => {
  const builder = readFileSync(join(root, 'scripts/build-system-image.sh'), 'utf8');
  const command = builder.split('\n').find((line) => line.startsWith('mkfs.ext4 ') && line.includes('-d "$root_stage"'));
  expect(command).toBeDefined();
  const directory = mkdtempSync(join(tmpdir(), 'omapkg-ext4-repro-'));
  try {
    const hashes = [];
    for (const names of [['z', 'a'], ['a', 'z']]) {
      const index = hashes.length;
      const tree = join(directory, `tree-${index}`);
      const output = join(directory, `image-${index}`);
      mkdirSync(tree);
      for (const name of names) writeFileSync(join(tree, name), name);
      const script = `set -euo pipefail
root_uuid=11111111-2222-3333-4444-555555555555
root_stage="$1"
root_image="$2"
find "$root_stage" -print0 | xargs -0 touch -h -d @1700000000
truncate -s 67108864 "$root_image"
${command}
sha256sum "$root_image"
`;
      const result = spawnSync('bash', ['-c', script, '--', tree, output], { env: { ...process.env, E2FSPROGS_FAKE_TIME: '1700000000', SOURCE_DATE_EPOCH: '1700000000', TZ: 'UTC' }, encoding: 'utf8' });
      expect(result.status).toBe(0);
      hashes.push(result.stdout.split(' ')[0]);
      if (index === 0) await Bun.sleep(1100);
    }
    expect(hashes[0]).toMatch(/^[a-f0-9]{64}$/);
    expect(hashes[1]).toBe(hashes[0]);
  } finally { rmSync(directory, { recursive: true, force: true }); }
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
