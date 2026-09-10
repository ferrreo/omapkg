import { expect, test } from 'bun:test';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { repositoryDatabaseForPackages } from '../src/lib/server/repository';
import type { Env } from '../src/lib/server/env';
import { MemoryR2 } from './release-fixtures';

const image = process.env.NATIVE_REPOSITORY_IMAGE;

test.skipIf(!image)('native pacman reads every owned repository database name', async () => {
  const directory = mkdtempSync(join(tmpdir(), 'owned-repository-names-'));

  try {
    const artifacts = new MemoryR2();
    artifacts.objects.set('fixture.sig', new Uint8Array([1]));
    const names = ['core', 'extra', 'multilib', 'omarchy', 'omapkg'];

    for (const name of names) {
      const packageName = `local-${name}-fixture`;

      const bytes = await repositoryDatabaseForPackages({ ARTIFACTS: artifacts } as unknown as Env, [{
        id: packageName, name: packageName, version: '1:2.0-3', architecture: 'any',
        artifactKey: 'fixture', signatureKey: 'fixture.sig', artifactSha256: 'a'.repeat(64), artifactSize: 1,
        artifactFilename: `${packageName}-2.0-3-any.pkg.tar.zst`, installedSize: 1, sourceDateEpoch: 1,
        license: 'MIT', upstreamUrl: 'https://example.invalid', description: 'Local database naming fixture',
        metadata: { name: packageName, fullVersion: '1:2.0-3', architecture: 'x86_64', installedSize: 1, depends: [], provides: [], conflicts: [], replaces: [] },
      }]);

      writeFileSync(join(directory, `${name}.db`), bytes);
    }

    // Database parsing only: no package installation, network, or host pacman state.
    writeFileSync(join(directory, 'pacman.conf'), `[options]\nArchitecture = x86_64\nSigLevel = Never\n${names.map(name => `[${name}]\nServer = file:///fixture`).join('\n')}\n`);

    const result = Bun.spawnSync(['docker', 'run', '--rm', '--pull=never', '--network=none', '--read-only', '--cap-drop=ALL',
      '--security-opt=no-new-privileges', '--tmpfs', '/tmp', '-v', `${directory}:/fixture:ro`, '--entrypoint', '/bin/sh', image!, '-ec',
      'mkdir -p /tmp/db /tmp/cache; pacman --config /fixture/pacman.conf --dbpath /tmp/db --cachedir /tmp/cache --logfile /tmp/pacman.log -Sy; pacman --config /fixture/pacman.conf --dbpath /tmp/db -Sl'], { timeout: 60_000 });

    expect(result.exitCode, result.stderr.toString()).toBe(0);

    for (const name of names) expect(result.stdout.toString()).toContain(`${name} local-${name}-fixture 1:2.0-3`);
  } finally { rmSync(directory, { recursive: true, force: true }); }
}, 90_000);
