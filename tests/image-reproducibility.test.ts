import { expect, test } from 'bun:test';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const root = new URL('..', import.meta.url).pathname;

const harness = join(root, 'system-images/reproducibility/run.sh');

const adapter = join(root, 'worker/image_reproducibility_test.go');

const profile = join(root, 'system-images/reproducibility/oci-profile.json');

const fetcher = join(root, 'system-images/reproducibility/fetch-real-packages.sh');

const toolImage = join(root, 'system-images/reproducibility/prepare-tool-image.sh');

test('image reproducibility harness keeps raw comparison and explicit incomplete status', () => {
  const source = readFileSync(harness, 'utf8') + readFileSync(adapter, 'utf8') + readFileSync(fetcher, 'utf8') + readFileSync(toolImage, 'utf8');
  expect(source).toContain('RunReproducibilityPair');
  expect(source).toContain('build-system-image.sh');
  expect(source).toContain('return 3');
  expect(source).toContain('nondeterministic');
  expect(source).toContain('--filesystem-fixture');
  expect(source).toContain('--fetch-real-packages');
  expect(source).toContain('qemu-img gptfdisk dosfstools');
  expect(JSON.parse(readFileSync(profile, 'utf8'))).toMatchObject({ builder: 'buildah', architecture: 'x86_64', sourceDateEpoch: 1700000000 });
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
