import { expect, test } from 'bun:test';
import { GET, HEAD } from '../src/routes/maintain/builds/[id]/artifact/+server';
import { asD1, TestD1 } from './d1';

test('build artifacts download privately with authorization and missing-object checks', async () => {
  const db = new TestD1(`CREATE TABLE builds(id TEXT,artifact_key TEXT,artifact_filename TEXT,attempt INTEGER DEFAULT 1);
    INSERT INTO builds(id,artifact_key,artifact_filename) VALUES('built','private/package','demo.pkg.tar.zst'),('pending',NULL,NULL),('missing','missing/package','gone.pkg.tar.zst');
    CREATE TABLE build_artifacts(build_id TEXT,attempt INTEGER,artifact_key TEXT,filename TEXT);
    INSERT INTO build_artifacts VALUES('built',1,'private/package','docs-2:1.0-1-any.pkg.tar.zst'),('built',0,'private/old','old.pkg.tar.zst');`);
  const reads: string[] = [];
  const event = (id = 'built', role: string | null = 'maintainer', method = 'GET', filename = '') => ({
    params: { id },
    url: new URL(`https://omapkg.example/maintain/builds/${id}/artifact${filename ? `?filename=${encodeURIComponent(filename)}` : ''}`),
    request: new Request(`https://omapkg.example/maintain/builds/${id}/artifact`, { method }),
    locals: { actor: role ? { id: 'user', role } : null },
    platform: { env: { DB: asD1(db), ARTIFACTS: {
      get: async (key: string) => {
        reads.push(key);
        return key === 'private/package' ? { body: new Blob(['package']).stream(), size: 7, httpEtag: '"artifact"' } : null;
      }
    } } }
  }) as unknown as Parameters<typeof GET>[0];
  try {
    await expect(GET(event('built', null))).rejects.toMatchObject({ status: 401 });
    await expect(GET(event('built', 'public'))).rejects.toMatchObject({ status: 403 });
    expect(reads).toEqual([]);
    const response = await GET(event());
    expect(await response.text()).toBe('package');
    expect(response.headers.get('Content-Disposition')).toBe(`attachment; filename="demo.pkg.tar.zst"; filename*=UTF-8''demo.pkg.tar.zst`);
    expect(response.headers.get('Content-Type')).toBe('application/octet-stream');
    expect(response.headers.get('Content-Length')).toBe('7');
    expect(response.headers.get('Cache-Control')).toBe('private, no-store');
    expect(reads).toEqual(['private/package']);
    const head = await HEAD(event('built', 'maintainer', 'HEAD'));
    expect(await head.text()).toBe('');
    expect(head.headers.get('Content-Length')).toBe('7');
    for (const id of ['unknown', 'pending', 'missing']) {
      await expect(GET(event(id))).rejects.toMatchObject({ status: 404 });
    }
    expect((await GET(event('built', 'maintainer', 'GET', 'docs-2:1.0-1-any.pkg.tar.zst'))).headers.get('Content-Disposition')).toContain('docs-2%3A1.0-1-any.pkg.tar.zst');
    for (const filename of ['old.pkg.tar.zst', 'private/package']) await expect(GET(event('built', 'maintainer', 'GET', filename))).rejects.toMatchObject({ status: 404 });
  } finally { db.close(); }
});
