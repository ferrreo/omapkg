import { expect, test } from 'bun:test';
import { archRelationCovers, compareArchVersions, parseArchRelation, parsePackageMetadata, satisfiesArchRelation } from '../src/lib/server/arch';

const valid = {
  name: 'libfoo',
  fullVersion: '1:2.0-1',
  architecture: 'x86_64' as const,
  installedSize: 42,
  depends: ['glibc', 'lib:libOpenCL.so.1'],
  provides: ['lib:libOpenCL.so.1', 'virtual-foo'],
  conflicts: ['old-libfoo<2-1'],
  replaces: ['old-libfoo=1.9-1'],
};

test('parses bounded native Arch package metadata and SONAME relations', () => {
  expect(parsePackageMetadata(valid)).toEqual(valid);
  const metadata = parsePackageMetadata(valid);
  if (!metadata) throw new Error('expected valid metadata');
  expect(parseArchRelation('lib:libOpenCL.so.1')).toEqual({ name: 'lib:libOpenCL.so.1', operator: null, version: null });
  expect(parseArchRelation('libOpenCL.so=1-64')).toEqual({ name: 'libOpenCL.so', operator: '=', version: '1-64' });
  expect(satisfiesArchRelation(parseArchRelation('lib:libOpenCL.so.1')!, metadata)).toBe(true);
});

test('rejects malformed or non-canonical package metadata', () => {
  expect(parsePackageMetadata({ ...valid, provides: ['libfoo.so>2-64'] })).toBeNull();
  expect(parsePackageMetadata({ ...valid, depends: ['glibc\nmalicious'] })).toBeNull();
  expect(parsePackageMetadata({ ...valid, extra: true })).toBeNull();
  expect(parsePackageMetadata({ ...valid, installedSize: -1 })).toBeNull();
  expect(parsePackageMetadata({ ...valid, provides: Array.from({ length: 257 }, () => 'virtual-foo') })).toBeNull();
});

test('requires native metadata to cover reviewed dependencies', () => {
  expect(archRelationCovers('runtime>=2', 'runtime>=1')).toBe(true);
  expect(archRelationCovers('runtime=2-1', 'runtime>=2')).toBe(true);
  expect(archRelationCovers('runtime>=1', 'runtime>1')).toBe(false);
  expect(archRelationCovers('runtime', 'runtime>=1')).toBe(false);
  expect(archRelationCovers('runtime>1.0-1', 'runtime>1.0')).toBe(false);
  expect(archRelationCovers('runtime=1.0-1.1', 'runtime>1.0')).toBe(false);
  expect(archRelationCovers('runtime=1.0', 'runtime=1.0-2')).toBe(false);
  expect(archRelationCovers('runtime>=1.0', 'runtime>=1.0-2')).toBe(false);
  expect(archRelationCovers('runtime>1.0', 'runtime>1.0-1')).toBe(true);
  expect(archRelationCovers('runtime>=1.0-2', 'runtime>=1.0')).toBe(true);
  expect(archRelationCovers('runtime=1.0-2', 'runtime=1.0')).toBe(true);
  expect(archRelationCovers('lib:libOpenCL.so.1', 'libOpenCL.so')).toBe(true);
  expect(archRelationCovers('libOpenCL.so=1-64', 'libOpenCL.so')).toBe(true);
  expect(archRelationCovers('lib:libOther.so.1', 'libOpenCL.so')).toBe(false);
});

test('matches native vercmp ordering for fractional releases and prereleases', () => {
  for (const [left, right, expected] of [
    ['1.0-1.1', '1.0', 0],
    ['1.0-1.1', '1.0-1', 1],
    ['1.0-1.1', '1.0-2', -1],
    ['1:1.0-1.1', '1.0-2', 1],
    ['1.0alpha', '1.0', -1],
    ['1.0beta', '1.0alpha', 1],
    ['1.0-1.10', '1.0-1.2', 1],
    ['1.0-1.1', '1.0-1.10', -1],
  ] as const) {
    expect(Math.sign(compareArchVersions(left, right) ?? 0)).toBe(expected);
  }
});
