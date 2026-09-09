import { expect, test } from 'bun:test';
import { readFileSync, readdirSync } from 'node:fs';
import { asD1, TestD1 } from './d1';
import { canonicalJson } from '../src/lib/canonical-json';
import { packagePath, parseSystemVersion, type CatalogManifest } from '../src/lib/distribution';
import { approveCatalogPackage, getCatalogPackage, listCatalogPackages, parseCatalogManifest, proposeCatalogPackage } from '../src/lib/server/catalog-ownership';
import { parseFactoryRequest } from '../services/pipeline/tools';

const schema = readdirSync(new URL('../migrations', import.meta.url)).filter((file) => file.endsWith('.sql')).sort()
  .map((file) => readFileSync(new URL(`../migrations/${file}`, import.meta.url), 'utf8')).join('\n');
const owner = { id: 'github:1', role: 'maintainer' as const, areas: ['system'] };
const security = { id: 'github:2', role: 'security' as const, areas: ['system'] };
export const catalogFixture = (pkgbase = 'example'): CatalogManifest => ({
  schemaVersion: 1, pkgbase, outputs: [pkgbase], collection: 'core', lane: 'system', role: 'base-system', origin: 'arch',
  upstreamUrl: 'https://example.org/source.git', sourceKind: 'git', description: 'Example system library', license: 'MIT', ownerArea: 'system',
  architectures: ['x86_64', 'aarch64'], artifactArchitecture: 'native', architectureExceptions: [], sourceReference: null, rebuildOn: [],
});

test('catalog pins identity, requires both targets and keeps external packaging out of admitted source URLs', () => {
  expect(canonicalJson({ b: [2, 1], a: { y: 2, x: 1 } })).toBe('{"a":{"x":1,"y":2},"b":[2,1]}');
  expect(parseSystemVersion('4.0.3')).toEqual({ version: '4.0.3', candidate: 'final', sequence: 0 });
  expect(parseSystemVersion('4.0.3-rc2')?.candidate).toBe('rc');
  expect(parseSystemVersion('4.0.4-edge.1')?.candidate).toBe('edge');
  for (const version of ['v4.0.3', '4.00.3', '4.0.3-rc0', '4.0.3-rc2suffix', '4.0.3+changed']) expect(parseSystemVersion(version)).toBeNull();
  expect(packagePath('example', 'core')).toBe('packages/core/example');
  expect(() => packagePath('../secret', 'core')).toThrow();
  expect(() => parseCatalogManifest({ ...catalogFixture(), lane: 'opr' })).toThrow('versioned system');
  expect(() => parseCatalogManifest({ ...catalogFixture(), architectures: ['x86_64'] })).toThrow('Both primary');
  expect(() => parseCatalogManifest({ ...catalogFixture(), upstreamUrl: 'https://aur.archlinux.org/example.git' })).toThrow('reference evidence');
  expect(() => parseCatalogManifest({ ...catalogFixture(), origin: 'alarm-reference' })).toThrow('immutable commit');
  expect(parseCatalogManifest({ ...catalogFixture(), architectures: ['x86_64'], architectureExceptions: [{ architecture: 'aarch64', reason: 'x86-only hardware driver' }] }).architectureExceptions).toHaveLength(1);
  for (const upstream_url of ['https://aur.archlinux.org/example.git', 'https://mirror.archlinuxarm.org/aarch64/core/example.pkg.tar.xz']) {
    expect(() => parseFactoryRequest({ id: 'example', name: 'example', upstream_url, source_kind: 'git', area: 'system', declared_license: 'MIT' })).toThrow('authoritative upstream');
  }
});

test('catalog admission is immutable, independently reviewed, collision-safe and fenced against stale decisions', async () => {
  const db = new TestD1(schema); const d1 = asD1(db);
  try {
    await expect(proposeCatalogPackage(d1, { ...owner, role: 'public' }, catalogFixture(), null, 'Import baseline')).rejects.toMatchObject({ status: 403 });
    const proposed = await proposeCatalogPackage(d1, owner, catalogFixture(), null, 'Import baseline');
    expect((await getCatalogPackage(d1, 'example'))?.admitted_revision).toBeNull();
    await approveCatalogPackage(d1, security, 'example', 1, proposed.manifestSha256, 'area', 'Reviewed ownership and source');
    await expect(approveCatalogPackage(d1, security, 'example', 1, proposed.manifestSha256, 'security', 'Same reviewer')).rejects.toThrow('independent');
    await approveCatalogPackage(d1, owner, 'example', 1, proposed.manifestSha256, 'area', 'Area review');
    expect(await approveCatalogPackage(d1, security, 'example', 1, proposed.manifestSha256, 'security', 'Security review')).toMatchObject({ admitted: true });
    const next = await proposeCatalogPackage(d1, owner, { ...catalogFixture(), description: 'Updated description' }, 1, 'Clarify purpose');
    expect((await getCatalogPackage(d1, 'example', true))?.revision).toBe(1);
    await expect(approveCatalogPackage(d1, security, 'example', 1, proposed.manifestSha256, 'security', 'Stale review')).rejects.toMatchObject({ status: 409 });
    await expect(proposeCatalogPackage(d1, owner, catalogFixture(), 1, 'Stale edit')).rejects.toMatchObject({ status: 409 });
    expect(next.revision).toBe(2);
    await expect(proposeCatalogPackage(d1, owner, { ...catalogFixture('collision'), outputs: ['example'] }, null, 'Take name')).rejects.toMatchObject({ status: 409 });
    expect(await getCatalogPackage(d1, 'collision')).toBeNull();
    expect(await listCatalogPackages(d1, { search: 'example', collection: 'core' })).toHaveLength(1);
    expect(() => db.exec("UPDATE catalog_revisions SET manifest_json='{}'")).toThrow('immutable');
    expect(db.prepare('PRAGMA foreign_key_check').all().results).toEqual([]);
  } finally { db.close(); }
});
