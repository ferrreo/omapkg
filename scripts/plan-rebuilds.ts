#!/usr/bin/env bun
import { createHash } from 'node:crypto';
import { readFileSync, readdirSync, statSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { parseArgs } from 'node:util';
import { canonicalJson } from '../src/lib/canonical-json';
import { collections, requiredArchitectures } from '../src/lib/distribution';
import { parseImportEntry, parseImportManifest } from '../src/lib/server/catalog-imports';
import { planRebuilds, type RebuildRule } from '../src/lib/rebuild-plan';
import type { ImportEntry } from '../src/lib/imports';

const hash = (value: unknown) => createHash('sha256').update(canonicalJson(value)).digest('hex');
function readCapture(directory: string) {
  const read = (name: string) => {
    const path = join(directory, name);
    if (statSync(path).size > 8 * 1024 * 1024) throw new Error('Captured metadata file exceeds 8 MiB.');
    return JSON.parse(readFileSync(path, 'utf8'));
  };
  const manifest = parseImportManifest(read('manifest.json')), entries: ImportEntry[] = [];
  for (const name of readdirSync(directory).filter((name) => /^entries-\d+\.json$/.test(name)).sort()) {
    const values = read(name);
    if (!Array.isArray(values) || entries.length + values.length > 100_000) throw new Error('Captured inventory exceeds 100,000 records.');
    entries.push(...values.map((value) => parseImportEntry(value, manifest)));
  }
  const index = entries.map((entry) => [entry.sourceId, entry.name, hash(entry)]).sort((a, b) =>
    a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : a[1] < b[1] ? -1 : a[1] > b[1] ? 1 : 0);
  if (hash(index) !== manifest.entriesSha256 || new Set(index.map((entry) => entry[0] + '/' + entry[1])).size !== entries.length ||
      manifest.sources.some((source) => entries.filter((entry) => entry.sourceId === source.id).length !== source.entries)) {
    throw new Error('Captured package records differ from their sealed index.');
  }
  return { manifest, entries, sha256: hash(manifest) };
}

const { values } = parseArgs({ options: {
  baseline: { type: 'string' }, candidate: { type: 'string' }, seed: { type: 'string', multiple: true },
  architecture: { type: 'string', default: 'all' }, rules: { type: 'string' }, output: { type: 'string' },
  'repository-order': { type: 'string' },
} });
if (!values.baseline || !values.candidate || !values.seed?.length || !values.output ||
    !['all', ...requiredArchitectures].includes(values.architecture)) {
  throw new Error('Usage: bun scripts/plan-rebuilds.ts --baseline DIR --candidate DIR --seed PKGBASE [--seed PKGBASE] --output FILE [--architecture all|x86_64|aarch64] [--rules FILE] [--repository-order core,extra,multilib,omarchy,omapkg]');
}
let rules: RebuildRule[] = [];
if (values.rules) {
  if (statSync(values.rules).size > 8 * 1024 * 1024) throw new Error('Rebuild rules exceed 8 MiB.');
  rules = JSON.parse(readFileSync(values.rules, 'utf8'));
  if (!Array.isArray(rules) || rules.length > 100_000 || rules.some((rule) => !rule || typeof rule !== 'object' ||
      Object.keys(rule).sort().join(',') !== 'pkgbase,rebuildOn' || typeof rule.pkgbase !== 'string' || !Array.isArray(rule.rebuildOn) ||
      rule.rebuildOn.some((name) => typeof name !== 'string'))) throw new Error('Use an array of package bases and rebuildOn package names.');
}
const baseline = readCapture(values.baseline), candidate = readCapture(values.candidate);
const targets = requiredArchitectures.filter((target) => values.architecture === 'all' || values.architecture === target);
const repositoryOrder = values['repository-order']?.split(',') ?? [];
if (new Set(repositoryOrder).size !== repositoryOrder.length || repositoryOrder.some((name) => !collections.includes(name as typeof collections[number]))) {
  throw new Error('Repository order must enumerate unique captured repository names.');
}
const shadowed: Array<{ snapshot: string; name: string; target: string; selected: string; shadowed: string }> = [];
const universe = (capture: typeof baseline, snapshot: string) => {
  if (!repositoryOrder.length) return capture.entries.filter((entry) => targets.includes(entry.target));
  if (capture.manifest.sources.some((source) => targets.includes(source.target) && source.entries && !repositoryOrder.includes(source.collection))) {
    throw new Error('Repository order must include every captured repository for the selected targets.');
  }
  const selected = new Map<string, ImportEntry>();
  for (const entry of [...capture.entries].sort((a, b) => repositoryOrder.indexOf(a.collection) - repositoryOrder.indexOf(b.collection))) {
    if (!targets.includes(entry.target)) continue;
    const key = entry.target + '/' + entry.name, previous = selected.get(key);
    if (!previous) selected.set(key, entry);
    else {
      if (previous.collection === entry.collection) throw new Error('Repository order cannot resolve two sources with the same collection and target.');
      shadowed.push({ snapshot, name: entry.name, target: entry.target, selected: previous.collection, shadowed: entry.collection });
    }
  }
  return [...selected.values()];
};
const before = universe(baseline, 'baseline'), after = universe(candidate, 'candidate');
const allBases = new Set([...baseline.entries, ...candidate.entries].map((entry) => entry.pkgbase));
if (rules.some((rule) => !allBases.has(rule.pkgbase))) throw new Error('A rebuild rule names a package base absent from both inventories.');
shadowed.sort((a, b) => JSON.stringify(a).localeCompare(JSON.stringify(b)));
const plans = targets.map((target) => {
  const present = new Set([...before, ...after].filter((entry) => entry.target === target).map((entry) => entry.pkgbase));
  const missingSeeds = values.seed!.filter((name) => !present.has(name));
  // Every requested target remains explicit, including entirely absent ARM source coverage.
  return { architecture: target, missingSeeds, unappliedRules: rules.filter((rule) => !present.has(rule.pkgbase)).map((rule) => rule.pkgbase),
    sourceGaps: [baseline, candidate].flatMap((capture, index) => capture.manifest.sources.filter((source) => source.target === target && source.status !== 'captured')
      .map((source) => ({ snapshot: index ? 'candidate' : 'baseline', source: source.id, reason: source.error }))),
    plan: missingSeeds.length ? null : planRebuilds(before, after, target, values.seed!, rules.filter((rule) => present.has(rule.pkgbase))),
  };
});
const report = { schemaVersion: 1, kind: 'rebuild-scope-proposal', baseline: baseline.sha256, candidate: candidate.sha256,
  requiredArchitectures: targets, repositoryOrder, shadowed, rules, plans,
  limits: ['Declared dependencies and explicit rebuild rules only; undeclared/static linkage and ABI compatibility require artifact analysis.',
    'Provider alternatives require explicit resolution and a native pacman transaction. Cycles need reviewed bootstrap inputs.',
    'Source inventories do not establish ownership admission, build approval or release readiness.'],
};
writeFileSync(values.output, canonicalJson(report) + '\n', { flag: 'wx' });
console.log(JSON.stringify({ output: values.output, sha256: hash(report), targets: plans.map((item) => ({ architecture: item.architecture,
  members: item.plan?.members.length ?? 0, cycles: item.plan?.buildGroups.filter((group) => group.requiresBootstrapReview).length ?? 0,
  missingSeeds: item.missingSeeds, sourceGaps: item.sourceGaps.length, unresolved: item.plan?.unresolvedCandidateRelations ?? null })) }));
