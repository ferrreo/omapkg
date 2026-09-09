import { expect, test } from 'bun:test';
import { repositoryStatus } from '../src/lib/server/repository-status';
import { TestD1 } from './d1';
import { env, MemoryR2 } from './release-fixtures';

test('public repository status reads publication records only and reports each target independently', async () => {
  const db = new TestD1(`CREATE TABLE repository_snapshots(id TEXT,architecture TEXT,channel TEXT,created_at INTEGER,db_key TEXT,db_signature_key TEXT,active INTEGER);
    CREATE TABLE releases(id TEXT,name TEXT,architecture TEXT,channel TEXT,surface TEXT,published_at INTEGER);
    INSERT INTO repository_snapshots VALUES('published-x86','x86_64','stable',1,'db/x86','db/x86.sig',1),('unreachable-arm','aarch64','stable',2,'db/arm','db/arm.sig',1);
    INSERT INTO releases VALUES('one','example','x86_64','stable','binary',1),('two','example','x86_64','stable','binary',2),
      ('three','recipe','aarch64','stable','recipe',2),('withdrawn','removed','aarch64','withdrawn','binary',2);`);
  const bucket = new MemoryR2(); bucket.objects.set('db/x86', new Uint8Array([1])); bucket.objects.set('db/x86.sig', new Uint8Array([2]));
  const service = env(db); service.ARTIFACTS = bucket as unknown as R2Bucket;
  try {
    const result = await repositoryStatus(service);
    expect(result.repositories).toHaveLength(4);
    expect(result.repositories.find((row) => row.channel === 'stable' && row.architecture === 'x86_64')).toMatchObject({ state: 'available', binaryPackages: 1, recipePackages: 0 });
    expect(result.repositories.find((row) => row.channel === 'stable' && row.architecture === 'aarch64')).toMatchObject({ state: 'unavailable', binaryPackages: 0, recipePackages: 1 });
    expect(result.repositories.filter((row) => row.channel === 'dev').every((row) => row.state === 'not-published')).toBe(true);
    expect(JSON.stringify(result)).not.toContain('db/x86');
  } finally { db.close(); }
});
