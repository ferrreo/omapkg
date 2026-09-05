import { expect, test } from 'bun:test';
import { mkdtemp, mkdir, copyFile, writeFile, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

test('production config generation rejects HTTP before writing credential-bearing origins', async () => {
  const root = await mkdtemp(join(tmpdir(), 'omapkg-deploy-test-'));
  const values = Object.fromEntries([
    'CLOUDFLARE_ACCOUNT_ID', 'CLOUDFLARE_D1_DATABASE_ID', 'D1_DATABASE_NAME', 'ARTIFACTS_BUCKET_NAME',
    'GITHUB_REPOSITORY', 'REGISTRY_ACCOUNT_ID', 'PACKAGE_SIGNING_FINGERPRINT', 'SIGNING_KEY_ID',
    'AI_GATEWAY_ACCOUNT_ID', 'AI_GATEWAY_ID', 'PIPELINE_SERVICE', 'SIGNER_SERVICE', 'WEB_WORKER_NAME',
  ].map((name) => [name, 'test']));
  try {
    await mkdir(join(root, 'scripts'));
    await mkdir(join(root, 'signer'));
    await copyFile(new URL('../scripts/deploy.ts', import.meta.url), join(root, 'scripts/deploy.ts'));
    await writeFile(join(root, 'wrangler.jsonc'), JSON.stringify({ d1_databases: [{}], r2_buckets: [{}] }));
    await writeFile(join(root, 'signer/wrangler.jsonc'), JSON.stringify({ r2_buckets: [{}] }));
    for (const origin of ['http://packages.example', 'https://packages.example']) {
      const child = Bun.spawn([process.execPath, 'scripts/deploy.ts', '--config-only'], {
        cwd: root, env: { ...values, PUBLIC_ORIGIN: origin }, stdout: 'pipe', stderr: 'pipe',
      });
      const [code, stderr] = await Promise.all([child.exited, new Response(child.stderr).text(), new Response(child.stdout).text()]);
      if (origin.startsWith('http:')) {
        expect(code).not.toBe(0);
        expect(stderr).toContain('must be an absolute HTTPS URL');
      } else {
        expect(code).toBe(0);
        const config = JSON.parse(await readFile(join(root, '.local/production-config/signer.wrangler.jsonc'), 'utf8'));
        expect(config.vars.CONTROL_ORIGIN).toBe(origin);
      }
    }
  } finally { await rm(root, { recursive: true, force: true }); }
});
