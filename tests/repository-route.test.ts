import { expect, test } from 'bun:test';
import { GET } from '../src/routes/repo/[...path]/+server';
import { asD1, TestD1 } from './d1';

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
