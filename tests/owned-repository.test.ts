import { expect, test } from 'bun:test';
import { readFileSync, readdirSync } from 'node:fs';
import { canonicalJson } from '../src/lib/canonical-json';
import { repositoryDatabaseForPackages } from '../src/lib/server/repository';
import { ownedRepositoryReleaseRepositories, ownedRepositoryUniversePages, prepareOwnedRepositorySnapshots, serveOwnedRepositoryPath } from '../src/lib/server/owned-repository';
import { POST as prepareRepositories } from '../src/routes/api/maintain/distribution-releases/+server';
import { sha256 } from '../src/lib/server/db';
import type { Env } from '../src/lib/server/env';
import { MemoryR2 } from './release-fixtures';
import { asD1, TestD1 } from './d1';

const schema = readdirSync(new URL('../migrations', import.meta.url)).filter((name) => name.endsWith('.sql')).sort()
  .map((name) => readFileSync(new URL(`../migrations/${name}`, import.meta.url), 'utf8')).join('\n');

function env(db: TestD1, artifacts: MemoryR2): Env {
  return { DB: asD1(db), ARTIFACTS: artifacts as unknown as R2Bucket, PUBLIC_ORIGIN: 'https://repo.test', QUARANTINE_HOURS: '48' } as Env;
}

test('owned database serializer preserves named Arch metadata and deterministic bytes', async () => {
  const db = new TestD1(); const artifacts = new MemoryR2();
  artifacts.objects.set('pkg.sig', new Uint8Array([1, 2, 3]));

  const item = {
    id: 'artifact-1', name: 'demo', version: '1.0-1', architecture: 'any' as const, artifactKey: 'pkg', signatureKey: 'pkg.sig', artifactSha256: 'a'.repeat(64), artifactSize: 12,
    artifactFilename: 'demo-1.0-1-any.pkg.tar.zst', installedSize: 42, sourceDateEpoch: 1, license: 'MIT', upstreamUrl: 'https://example.org/demo', description: 'Demo package',
    metadata: { name: 'demo', fullVersion: '1.0-1', architecture: 'x86_64' as const, installedSize: 42, depends: ['glibc'], provides: [], conflicts: [], replaces: [] },
  };

  const first = await repositoryDatabaseForPackages({ DB: asD1(db), ARTIFACTS: artifacts as unknown as R2Bucket } as Env, [item]);
  const second = await repositoryDatabaseForPackages({ DB: asD1(db), ARTIFACTS: artifacts as unknown as R2Bucket } as Env, [item]);
  expect(await sha256(first)).toBe(await sha256(second));
  const stream = new DecompressionStream('gzip'); const writer = stream.writable.getWriter(); await writer.write(first as BufferSource); await writer.close();
  const tar = new TextDecoder().decode(await new Response(stream.readable).arrayBuffer());
  expect(tar).toContain('%FILENAME%\ndemo-1.0-1-any.pkg.tar.zst');
  expect(tar).toContain('%ARCH%\nany');
  db.close();
});

test('owned route serves only published named snapshots and immutable filename map', async () => {
  const db = new TestD1(schema); const artifacts = new MemoryR2(); const service = env(db, artifacts); const timestamp = 1;
  const dbBytes = new Uint8Array([1, 2]); const dbSig = new Uint8Array([3]); const packageBytes = new Uint8Array([4]); const packageSig = new Uint8Array([5]); const attestation = new Uint8Array([6]); const attestationSig = new Uint8Array([7]); const map = new TextEncoder().encode('{}');

  for (const [key, bytes] of [['owned-repo.db', dbBytes], ['owned-repo.db.sig', dbSig], ['pkg', packageBytes], ['pkg.sig', packageSig], ['attestation', attestation], ['attestation.sig', attestationSig], ['map', map]] as const) artifacts.objects.set(key, bytes);
  const digest = async (bytes: Uint8Array) => sha256(bytes);
  db.prepare(`INSERT INTO owned_repository_artifacts
    (id,collection,target_architecture,name,version,architecture,pkgbase,filename,artifact_key,artifact_sha256,artifact_size,metadata_json,description,license,upstream_url,source_date_epoch,rebuild_on_json,abi_inventory_ref,
     signature_key,signature_sha256,attestation_key,attestation_sha256,attestation_size,attestation_signature_key,attestation_signature_sha256,build_id,build_attempt,revision_id,cohort_id,cohort_revision,created_at)
    VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).bind(
    'artifact-1','core','x86_64','demo','1.0-1','x86_64','demo','demo-1.0-1-x86_64.pkg.tar.zst','pkg',await digest(packageBytes),1,'{"name":"demo","fullVersion":"1.0-1","architecture":"x86_64","installedSize":1,"depends":[],"provides":[],"conflicts":[],"replaces":[]}',
    'Demo','MIT','https://example.org/demo',1,'[]',null,'pkg.sig',await digest(packageSig),'attestation',await digest(attestation),1,'attestation.sig',await digest(attestationSig),'build-1',1,'revision-1','cohort-1',1,timestamp).run();
  db.prepare(`INSERT INTO owned_repository_snapshots
    (id,lane,release_id,architecture,collection,db_filename,db_key,db_sha256,db_size,db_signature_key,db_signature_sha256,filename_map_key,filename_map_sha256,filename_map_size,package_count,status,created_at)
    VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).bind('snapshot-1','system','4.0.3','x86_64','core','core.db','owned-repo.db',await digest(dbBytes),dbBytes.byteLength,'owned-repo.db.sig',await digest(dbSig),'map',await digest(map),map.byteLength,1,'published',timestamp).run();
  db.prepare('INSERT INTO owned_repository_snapshot_packages(snapshot_id,artifact_id,ordinal,filename,artifact_sha256) VALUES(?,?,?,?,?)').bind('snapshot-1','artifact-1',0,'demo-1.0-1-x86_64.pkg.tar.zst',await digest(packageBytes)).run();
  db.prepare("INSERT INTO owned_repository_memberships(id,snapshot_id,lane,release_id,channel,status,created_at) VALUES('membership-1','snapshot-1','system','4.0.3','stable','active',1)").run();
  expect(await (await serveOwnedRepositoryPath(service, 'releases/4.0.3/core/x86_64/core.db'))!.arrayBuffer()).toEqual(dbBytes.buffer);
  expect(await (await serveOwnedRepositoryPath(service, 'releases/4.0.3/core/x86_64/demo-1.0-1-x86_64.pkg.tar.zst'))!.arrayBuffer()).toEqual(packageBytes.buffer);
  expect(await serveOwnedRepositoryPath(service, 'releases/4.0.3/core/x86_64/unknown.pkg.tar.zst')).toBeNull();
  db.close();
});

test('owned universe pages use persisted root index and expose ABI/build identity', async () => {
  const db = new TestD1(schema); const artifacts = new MemoryR2(); const metadata = { name: 'demo', fullVersion: '1.0-1', architecture: 'x86_64', installedSize: 1, depends: ['glibc'], provides: [], conflicts: [], replaces: [] };
  db.prepare("INSERT INTO owned_repository_universes(id,lane,release_id,root_sha256,package_count,status,created_at) VALUES('u-1','system','4.0.3',? ,1,'published',1)").bind('a'.repeat(64)).run();
  db.prepare(`INSERT INTO owned_repository_artifacts
    (id,collection,target_architecture,name,version,architecture,pkgbase,filename,artifact_key,artifact_sha256,artifact_size,metadata_json,description,license,upstream_url,source_date_epoch,rebuild_on_json,abi_inventory_ref,
     signature_key,signature_sha256,attestation_key,attestation_sha256,attestation_size,attestation_signature_key,attestation_signature_sha256,build_id,build_attempt,revision_id,cohort_id,cohort_revision,created_at)
    VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).bind(
    'artifact-1','core','x86_64','demo','1.0-1','x86_64','demo','demo-1.0-1-x86_64.pkg.tar.zst','pkg','b'.repeat(64),1,canonicalJson(metadata),'Demo','MIT','https://example.org/demo',1,'["glibc"]','c'.repeat(64),'pkg.sig','d'.repeat(64),'attestation','e'.repeat(64),1,'attestation.sig','f'.repeat(64),'build-1',1,'revision-1','cohort-1',1,1).run();
  db.prepare("INSERT INTO owned_repository_universe_packages(universe_id,ordinal,artifact_id,collection,target_architecture) VALUES('u-1',0,'artifact-1','core','x86_64')").run();
  const pages = [];

  for await (const page of ownedRepositoryUniversePages({ DB: asD1(db), ARTIFACTS: artifacts as unknown as R2Bucket } as Env, { lane: 'system', releaseId: '4.0.3' }, 1)) pages.push(page);
  expect(pages).toHaveLength(1); expect(pages[0][0]).toMatchObject({ name: 'demo', artifactArch: 'x86_64', targetArchitecture: 'x86_64', abiInventoryRef: 'c'.repeat(64), buildId: 'build-1', attempt: 1, depends: ['glibc'] });
  db.close();
});

test('owned preparation expands trusted parent into all named target snapshots and bounded chunks', async () => {
  const db = new TestD1(schema); const artifacts = new MemoryR2(); const service = env(db, artifacts); const timestamp = 1;
  const packageBytes = new Uint8Array([4]); const packageSig = new Uint8Array([5]); const attestation = new Uint8Array([6]); const attestationSig = new Uint8Array([7]);
  const metadata = { name: 'demo', fullVersion: '1.0-1', architecture: 'x86_64' as const, installedSize: 1, depends: [], provides: [], conflicts: [], replaces: [] };
  const hash = async (bytes: Uint8Array) => sha256(bytes);
  artifacts.objects.set('parent-package', packageBytes); artifacts.objects.set('parent-package.sig', packageSig); artifacts.objects.set('parent-attestation', attestation); artifacts.objects.set('parent-attestation.sig', attestationSig);

  const packageItem = { id: 'parent-artifact', name: 'demo', version: '1.0-1', architecture: 'x86_64' as const, artifactKey: 'parent-package', signatureKey: 'parent-package.sig', artifactSha256: await hash(packageBytes), artifactSize: 1,
    artifactFilename: 'demo-1.0-1-x86_64.pkg.tar.zst', installedSize: 1, sourceDateEpoch: 1, license: 'MIT', upstreamUrl: 'https://example.org/demo', description: 'Demo', metadata };

  db.prepare(`INSERT INTO owned_repository_artifacts
    (id,collection,target_architecture,name,version,architecture,pkgbase,filename,artifact_key,artifact_sha256,artifact_size,metadata_json,description,license,upstream_url,source_date_epoch,rebuild_on_json,abi_inventory_ref,
     signature_key,signature_sha256,attestation_key,attestation_sha256,attestation_size,attestation_signature_key,attestation_signature_sha256,build_id,build_attempt,revision_id,cohort_id,cohort_revision,created_at)
    VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).bind(
    'parent-artifact','core','x86_64','demo','1.0-1','x86_64','demo',packageItem.artifactFilename,packageItem.artifactKey,packageItem.artifactSha256,1,canonicalJson(metadata),'Demo','MIT','https://example.org/demo',1,'[]',null,
    packageItem.signatureKey,await hash(packageSig),'parent-attestation',await hash(attestation),1,'parent-attestation.sig',await hash(attestationSig),'parent-build',1,'parent-revision','parent-cohort',1,timestamp).run();
  const coreDatabase = await repositoryDatabaseForPackages(service, [packageItem]); const emptyDatabase = await repositoryDatabaseForPackages(service, []);
  const pairs = [['core','x86_64',coreDatabase], ['core','aarch64',emptyDatabase], ['extra','x86_64',emptyDatabase], ['extra','aarch64',emptyDatabase], ['multilib','x86_64',emptyDatabase], ['omarchy','x86_64',emptyDatabase], ['omarchy','aarch64',emptyDatabase], ['omapkg','x86_64',emptyDatabase], ['omapkg','aarch64',emptyDatabase]] as const;

  for (const [collection, architecture, database] of pairs) {
    const dbKey = `parent/${collection}/${architecture}.db`; const sigKey = `${dbKey}.sig`; const mapKey = `parent/${collection}/${architecture}.json`; const dbSig = new Uint8Array([collection.length, architecture.length]); const map = new TextEncoder().encode('{}');
    artifacts.objects.set(dbKey, database); artifacts.objects.set(sigKey, dbSig); artifacts.objects.set(mapKey, map);
    const dbSha = await hash(database); const sigSha = await hash(dbSig); const mapSha = await hash(map); const snapshotId = `parent-${collection}-${architecture}`;
    db.prepare(`INSERT INTO owned_repository_snapshots
      (id,lane,release_id,architecture,collection,db_filename,db_key,db_sha256,db_size,db_signature_key,db_signature_sha256,filename_map_key,filename_map_sha256,filename_map_size,package_count,status,created_at)
      VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).bind(snapshotId,'system','4.0.3',architecture,collection,`${collection}.db`,dbKey,dbSha,database.byteLength,sigKey,sigSha,mapKey,mapSha,map.byteLength,collection === 'core' && architecture === 'x86_64' ? 1 : 0,'published',timestamp).run();

    if (collection === 'core' && architecture === 'x86_64') db.prepare('INSERT INTO owned_repository_snapshot_packages(snapshot_id,artifact_id,ordinal,filename,artifact_sha256) VALUES(?,?,?,?,?)').bind(snapshotId,'parent-artifact',0,packageItem.artifactFilename,packageItem.artifactSha256).run();
    db.prepare('INSERT INTO owned_repository_memberships(id,snapshot_id,lane,release_id,channel,status,created_at) VALUES(?,?,?,?,?,?,?)').bind(`membership-${collection}-${architecture}`,snapshotId,'system','4.0.3','stable','active',timestamp).run();
  }

  const http = await prepareRepositories({
    platform: { env: service },
    request: new Request('https://repo.test/api/maintain/distribution-releases', { method: 'POST', headers: { origin: 'https://repo.test', 'content-type': 'application/json' }, body: JSON.stringify({ operation: 'prepare-repositories', repository: { lane: 'system', releaseId: '4.0.4', cohortIds: [], trustedParentReleaseId: '4.0.3' } }) }),
    url: new URL('https://repo.test/api/maintain/distribution-releases'),
    locals: { actor: { id: 'github:1', role: 'maintainer', areas: ['system'] } },
    params: {},
  } as any);

  expect(http.status).toBe(200);
  const payload = await http.json() as { preparation: Awaited<ReturnType<typeof prepareOwnedRepositorySnapshots>> };
  const prepared = payload.preparation;
  expect(prepared.snapshots).toHaveLength(7);
  expect(prepared.snapshots.map((snapshot) => snapshot.collection).sort()).toEqual(['core','core','extra','extra','multilib','omarchy','omarchy']);
  expect(prepared.snapshots.every((snapshot) => snapshot.snapshotDigest === snapshot.dbSha256 && snapshot.dbFilename === `${snapshot.collection}.db`)).toBe(true);
  expect(prepared.packageCount).toBe(1); expect(prepared.packageChunks).toHaveLength(1);
  expect(ownedRepositoryReleaseRepositories(prepared).map((repository) => repository.name)).toEqual(['core','core','extra','extra','multilib','omarchy','omarchy']);
  db.close();
});
