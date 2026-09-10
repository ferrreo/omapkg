import { expect, test } from 'bun:test';
import { chmodSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { validateWorkerConfig } from '../scripts/factory-check';

test('factory diagnostic validates permitted config fields without printing secrets', () => {
  const directory = mkdtempSync(join(tmpdir(), 'omapkg-factory-check-test-'), { encoding: 'utf8' });

  try {
    const filename = join(directory, 'config.json');
    writeFileSync(filename, JSON.stringify({ origin: 'https://omapkg.example', workerId: 'worker-1', privateKey: 'private-test-key', image: `builder@sha256:${'a'.repeat(64)}`, imageDigest: `sha256:${'a'.repeat(64)}`, architecture: 'x86_64', containerRuntime: 'podman', stateDir: directory }), { mode: 0o600 });
    chmodSync(filename, 0o600);
    expect(validateWorkerConfig(filename).status).toBe('passed');
    writeFileSync(filename, JSON.stringify({ origin: 'https://omapkg.example', workerId: 'worker-1', privateKey: 'do-not-print', architecture: 'x86_64', containerRuntime: 'podman', stateDir: directory, unexpected: true }), { mode: 0o600 });
    const invalid = validateWorkerConfig(filename);
    expect(invalid.status).toBe('failed');
    expect(invalid.detail).not.toContain('do-not-print');
  } finally { rmSync(directory, { recursive: true, force: true }); }
});
