import { expect, test } from 'bun:test';
import { planRebuilds } from '../src/lib/rebuild-plan';

const pkg = (name: string, dependencies: string[] = [], overrides: Partial<Parameters<typeof planRebuilds>[0][number]> = {}) => ({
  name, pkgbase: name, version: '1-1', target: 'x86_64' as const, dependencies, makeDependencies: [], checkDependencies: [], provides: [], ...overrides,
});

test('rebuild scope follows old and candidate providers, split outputs, check/static consumers and cycles without granting readiness', () => {
  const old = [pkg('library', [], { provides: ['lib:libdemo.so.1', 'virtual=2'] }),
    pkg('app', ['lib:libdemo.so.1']), pkg('app-data', [], { pkgbase: 'app' }), pkg('optional', ['app-data']),
    pkg('builder', [], { makeDependencies: ['virtual>=2'], checkDependencies: ['test-tool'] }), pkg('test-tool', ['builder']),
    pkg('static-app'), pkg('unrelated'), pkg('arm-only', ['library'], { target: 'aarch64' }),
  ];

  const candidate = old.map((entry) => entry.name === 'library' ? { ...entry, version: '2-1', provides: ['lib:libdemo.so.2', 'virtual=2'] } : entry);
  const rules = [{ pkgbase: 'static-app', rebuildOn: ['library'] }];
  const plan = planRebuilds(old, candidate, 'x86_64', ['library'], rules);
  expect(plan.members.map((item) => item.pkgbase)).toEqual(['app', 'builder', 'library', 'optional', 'static-app', 'test-tool']);
  expect(plan.members.find((item) => item.pkgbase === 'optional')?.affectedBy).toEqual(['app']);
  expect(plan.findings).toContainEqual({ snapshot: 'candidate', pkgbase: 'app', output: 'app', relation: 'lib:libdemo.so.1', providers: [] });
  expect(plan.unresolvedCandidateRelations).toBe(1);
  expect(plan.buildGroups).toContainEqual({ members: ['builder', 'test-tool'], requiresBootstrapReview: true });
  const position = (name: string) => plan.buildGroups.findIndex((group) => group.members.includes(name));
  expect(position('builder')).toBeGreaterThan(position('library'));
  expect(position('optional')).toBeGreaterThan(position('app'));
  expect(position('static-app')).toBeGreaterThan(position('library'));
  expect(planRebuilds([...old].reverse(), [...candidate].reverse(), 'x86_64', ['library'], rules)).toEqual(plan);

  const removed = planRebuilds(old, old.filter((entry) => entry.name !== 'library'), 'x86_64', ['library']);
  expect(removed.members.find((item) => item.pkgbase === 'library')?.removed).toBe(true);
  expect(removed.members.some((item) => item.pkgbase === 'optional')).toBe(true);
  expect(removed.buildGroups.flatMap((group) => group.members)).not.toContain('library');
  expect(() => planRebuilds(old, [...candidate, candidate[0]], 'x86_64', ['library'])).toThrow('duplicate package authorities');
  expect(() => planRebuilds(old, candidate, 'aarch64', ['library'])).toThrow('absent from this target');
});

test('versioned virtual provider alternatives stay explicit and all affected consumers are retained', () => {
  const entries = [pkg('one', [], { provides: ['virtual=2'] }), pkg('two', [], { provides: ['virtual=3'] }),
    pkg('unversioned', [], { provides: ['virtual'] }), pkg('consumer', ['virtual>=2'])];

  const plan = planRebuilds(entries, entries, 'x86_64', ['two']);
  expect(plan.members.map((item) => item.pkgbase)).toEqual(['consumer', 'two']);
  expect(plan.ambiguousCandidateRelations).toBe(1);
  expect(plan.findings.find((item) => item.snapshot === 'candidate')?.providers).toEqual(['one', 'two']);
  expect(planRebuilds(entries, entries, 'x86_64', ['unversioned']).members.map((item) => item.pkgbase)).toEqual(['unversioned']);
});

test('full catalog dependency chains produce complete ordered scope without recursive stack or 512-member truncation', () => {
  const entries = Array.from({ length: 15_000 }, (_, index) => pkg(`pkg-${String(index).padStart(5, '0')}`,
    index ? [`pkg-${String(index - 1).padStart(5, '0')}`] : []));

  const plan = planRebuilds(entries, entries, 'x86_64', [entries[0].name]);
  expect(plan.members.length).toBe(entries.length);
  expect(plan.buildGroups.length).toBe(entries.length);
  expect(plan.buildGroups.every((group, index) => group.members[0] === entries[index].name && !group.requiresBootstrapReview)).toBe(true);
  expect(plan.findings).toEqual([]);
});
