import { expect, test } from 'bun:test';
import { GET } from '../src/routes/repo/[...path]/+server';
import { asD1, TestD1 } from './d1';
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';

test('pacman opr-dev database names resolve to the same signed dev snapshot as legacy opr names', async () => {
  const db = new TestD1(`CREATE TABLE repository_snapshots(architecture TEXT,channel TEXT,active INTEGER,created_at INTEGER,db_key TEXT,db_signature_key TEXT);
    INSERT INTO repository_snapshots VALUES('x86_64','dev',1,1,'dev/database','dev/signature');`);

  const event = (path: string) => ({
    params: { path },
    platform: { env: { DB: asD1(db), ARTIFACTS: {
      get: async (key: string) => ({ body: key, size: key.length, httpEtag: '"snapshot"' }),
    } } },
  }) as unknown as Parameters<typeof GET>[0];

  try {
    for (const name of ['opr-dev.db', 'opr.db', 'opr-dev.db.tar.gz']) {
      expect(await (await GET(event(`dev/x86_64/${name}`))).text()).toBe('dev/database');
      expect(await (await GET(event(`dev/x86_64/${name}.sig`))).text()).toBe('dev/signature');
    }

    await expect(GET(event('dev/x86_64/unlisted.db'))).rejects.toMatchObject({ status: 404 });
    await expect(GET(event('x86_64/opr-dev.db'))).rejects.toMatchObject({ status: 404 });
  } finally { db.close(); }
});

test('rollback parser needs no Python and rejects invalid origins and digests before installation', () => {
  const directory = mkdtempSync(join(tmpdir(), 'omapkg-rollback-'));
  const bin = join(directory, 'bin'); mkdirSync(bin);
  const script = new URL('../src/lib/rollback-client.sh', import.meta.url).pathname;
  const fixture = join(directory, 'manifest.json'), calls = join(directory, 'calls');
  const sha = (value: string) => createHash('sha256').update(value).digest('hex');
  const command = (name: string, lines: string[]) => writeFileSync(join(bin, name), '#!/usr/bin/env bash\nset -euo pipefail\n' + lines.join('\n') + '\n', { mode: 0o755 });
  command('curl', [
    'destination=""; address=""',
    'while [ "$#" -gt 0 ]; do if [ "$1" = --output ]; then destination=$2; shift 2; else address=$1; shift; fi; done',
    'printf "fetch %s\\n" "$address" >> "$OPR_TEST_CALLS"',
    'case "$address" in */manifest.json) cp "$OPR_TEST_MANIFEST" "$destination" ;; *.pkg.tar.zst) printf artifact > "$destination" ;; */PKGBUILD) printf "pkgname=fixture\\n" > "$destination" ;; *) printf signature > "$destination" ;; esac',
  ]);
  command('gpg', ['if [[ " $* " == *" --verify "* ]]; then last="${!#}"; test -f "$last"; test -f "$last.sig"; printf "verified\\n" >> "$OPR_TEST_CALLS"; fi']);
  command('sudo', ['test "$1" = pacman; last="${!#}"; test -f "$last.sig"; printf "installed\\n" >> "$OPR_TEST_CALLS"']);
  command('makepkg', ['test -f PKGBUILD; printf "recipe-built\\n" >> "$OPR_TEST_CALLS"']);
  command('python3', ['echo "Python must not run" >&2; exit 97']);
  command('python', ['echo "Python must not run" >&2; exit 97']);
  const env = { PATH: `${bin}:/usr/bin:/bin`, OPR_TEST_MANIFEST: fixture, OPR_TEST_CALLS: calls };
  const binary = { schemaVersion: 1, kind: 'opr-downgrade', artifact: { url: 'https://packages.example.org/repo/fixture-1-1-x86_64.pkg.tar.zst', sha256: sha('artifact') } };

  const run = (manifest: unknown) => { writeFileSync(fixture, JSON.stringify(manifest)); writeFileSync(calls, '');

 return spawnSync('bash', [script, 'https://packages.example.org/manifest.json'], { env, encoding: 'utf8' }); };

  try {
    const valid = run(binary);
    expect({ status: valid.status, error: valid.stderr }).toEqual({ status: 0, error: '' });
    expect(readFileSync(calls, 'utf8')).toContain('verified\ninstalled');
    const recipe = run({ schemaVersion: 1, kind: 'opr-downgrade', recipe: { url: 'https://packages.example.org/recipe/PKGBUILD', sha256: sha('pkgname=fixture\n') } });
    expect({ status: recipe.status, error: recipe.stderr }).toEqual({ status: 0, error: '' });
    expect(readFileSync(calls, 'utf8')).toContain('recipe-built');

    for (const manifest of [
      { ...binary, schemaVersion: 2 }, { ...binary, artifact: { ...binary.artifact, sha256: 'wrong' } },
      { ...binary, artifact: { ...binary.artifact, url: binary.artifact.url.replace('packages.example.org', 'different.example.org') } },
      { ...binary, artifact: { ...binary.artifact, url: binary.artifact.url + '\ncommand' } },
      { ...binary, publicKeyUrl: 'https://user:password@packages.example.org/key.asc' },
      { ...binary, artifact: { ...binary.artifact, url: 'https://packages.example.org/../bad' } },
    ]) {
      expect(run(manifest).status).not.toBe(0);
      expect(readFileSync(calls, 'utf8')).toBe('fetch https://packages.example.org/manifest.json\n');
    }
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test('rollback client leaves package signature beside package for pacman trust checks', async () => {
  const db = new TestD1('CREATE TABLE repository_snapshots(architecture TEXT,channel TEXT,active INTEGER,created_at INTEGER,db_key TEXT,db_signature_key TEXT);');

  const event = {
    params: { path: 'rollback/client.sh' },
    platform: { env: { DB: asD1(db), ARTIFACTS: { head: async () => null, get: async () => null } } },
  } as unknown as Parameters<typeof GET>[0];

  try {
    const script = await (await GET(event)).text();
    expect(script).toContain('--output "$tmp/$filename.sig" "$signature_url"');
    expect(script).toContain('--verify "$tmp/$filename.sig" "$tmp/$filename"');
    expect(script).not.toContain('--output "$tmp/package.sig" "$signature_url"');
  } finally { db.close(); }
});
