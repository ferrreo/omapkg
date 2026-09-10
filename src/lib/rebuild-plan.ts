import type { Architecture } from './model';
import type { ImportEntry } from './imports';
import { parseArchRelation, satisfiesArchRelation } from './server/arch';

type Package = Pick<ImportEntry, 'name' | 'pkgbase' | 'version' | 'target' | 'dependencies' | 'makeDependencies' | 'checkDependencies' | 'provides'>;

export type RebuildRule = { pkgbase: string; rebuildOn: string[] };

export type RebuildFinding = { snapshot: 'baseline' | 'candidate'; pkgbase: string; output: string; relation: string; providers: string[] };

/** Dependency metadata proposes conservative scope. It does not establish ABI or install compatibility. */
export function planRebuilds(baseline: Package[], candidate: Package[], architecture: Architecture, seeds: string[], rules: RebuildRule[] = []) {
  if (!['x86_64', 'aarch64'].includes(architecture) || !seeds.length || seeds.length > 100_000 || new Set(seeds).size !== seeds.length) {
    throw new Error('Choose a native target and unique changed package bases.');
  }

  const allBases = new Set<string>(), currentBases = new Set<string>();
  const reverse = new Map<string, Set<string>>(), dependencies = new Map<string, Set<string>>();
  const findings: RebuildFinding[] = [];
  const causes = new Map<string, Set<string>>();
  const outputBases = new Map<string, Set<string>>();
  let edgeCount = 0, relationCount = 0;

  const edge = (consumer: string, provider: string, current: boolean) => {
    if (consumer === provider) return; // Split outputs are built as one package base.

    if (!reverse.has(provider)) reverse.set(provider, new Set());

    if (!reverse.get(provider)!.has(consumer) && ++edgeCount > 2_000_000) throw new Error('Rebuild graph exceeds its two-million-edge budget.');
    reverse.get(provider)!.add(consumer);

    if (current) {
      if (!dependencies.has(consumer)) dependencies.set(consumer, new Set());
      dependencies.get(consumer)!.add(provider);
    }
  };

  for (const [snapshot, entries] of [['baseline', baseline], ['candidate', candidate]] as const) {
    if (entries.length > 100_000) throw new Error('Rebuild inventory exceeds 100,000 package records.');
    const packages = entries.filter((entry) => entry.target === architecture);

    if (new Set(packages.map((entry) => entry.name)).size !== packages.length) throw new Error('Resolve duplicate package authorities before planning rebuilds.');
    const providers = new Map<string, Package[]>();

    for (const entry of packages) {
      allBases.add(entry.pkgbase);

      if (snapshot === 'candidate') currentBases.add(entry.pkgbase);

      if (!outputBases.has(entry.name)) outputBases.set(entry.name, new Set());
      outputBases.get(entry.name)!.add(entry.pkgbase);
      const capabilities = new Set([entry.name]);

      for (const value of entry.provides) {
        const relation = parseArchRelation(value);

        if (!relation || (relation.operator && relation.operator !== '=')) throw new Error(`Invalid provided relation for ${entry.name}: ${value}`);
        capabilities.add(relation.name);
      }

      for (const name of capabilities) {
        if (++relationCount > 2_000_000) throw new Error('Rebuild graph exceeds its dependency metadata budget.');

        if (!providers.has(name)) providers.set(name, []);
        providers.get(name)!.push(entry);
      }
    }

    for (const entry of packages) {
      const relations = [...new Set([...entry.dependencies, ...entry.makeDependencies, ...entry.checkDependencies])].sort();
      relationCount += relations.length;

      if (relations.length > 6144 || relationCount > 2_000_000) throw new Error('Rebuild graph exceeds its dependency metadata budget.');

      for (const value of relations) {
        const relation = parseArchRelation(value);

        if (!relation) throw new Error(`Invalid dependency for ${entry.name}: ${value}`);

        const matches = (providers.get(relation.name) ?? []).filter((provider) => satisfiesArchRelation(relation,
          { name: provider.name, fullVersion: provider.version, provides: provider.provides }));

        const names = matches.map((provider) => provider.name).sort();

        if (names.length !== 1) findings.push({ snapshot, pkgbase: entry.pkgbase, output: entry.name, relation: value, providers: names });

        for (const provider of matches) edge(entry.pkgbase, provider.pkgbase, snapshot === 'candidate');
      }
    }
  }

  for (const rule of rules) {
    if (!allBases.has(rule.pkgbase) || rule.rebuildOn.length > 256) throw new Error('Rebuild rule must name an existing package base with at most 256 triggers.');

    for (const trigger of rule.rebuildOn) {
      const bases = new Set(outputBases.get(trigger) ?? []);

      if (allBases.has(trigger)) bases.add(trigger);

      if (!bases.size) throw new Error(`Rebuild trigger ${trigger} for ${rule.pkgbase} is absent from both inventories.`);

      for (const provider of bases) edge(rule.pkgbase, provider, currentBases.has(rule.pkgbase) && currentBases.has(provider));
    }
  }

  for (const seed of seeds) if (!allBases.has(seed)) throw new Error(`Changed package base is absent from this target: ${seed}`);
  const changed = new Set(seeds), members = new Set(seeds), queue = [...seeds].sort();

  for (let offset = 0; offset < queue.length; offset++) {
    const provider = queue[offset];

    for (const consumer of [...(reverse.get(provider) ?? [])].sort()) {
      if (!causes.has(consumer)) causes.set(consumer, new Set());
      causes.get(consumer)!.add(provider);

      if (!members.has(consumer)) { members.add(consumer); queue.push(consumer); }
    }
  }

  const build = [...members].filter((name) => currentBases.has(name)).sort();
  const selected = new Set(build);
  const edges = new Map(build.map((name) => [name, [...(dependencies.get(name) ?? [])].filter((provider) => selected.has(provider)).sort()]));
  // Iterative Kosaraju avoids call-stack limits during a full toolchain transition.
  const finished: string[] = [], seen = new Set<string>();

  for (const root of build) {
    const stack: Array<[string, boolean]> = [[root, false]];

    while (stack.length) {
      const [node, returning] = stack.pop()!;

      if (returning) { finished.push(node); continue; }

      if (seen.has(node)) continue;
      seen.add(node); stack.push([node, true]);

      for (const next of edges.get(node)!.toReversed()) if (!seen.has(next)) stack.push([next, false]);
    }
  }

  const reversed = new Map(build.map((name) => [name, [] as string[]]));

  for (const [consumer, providers] of edges) for (const provider of providers) reversed.get(provider)!.push(consumer);
  const groups: Array<{ members: string[]; requiresBootstrapReview: boolean }> = [];
  seen.clear();

  for (const root of finished.toReversed()) {
    if (seen.has(root)) continue;
    const group: string[] = [], stack = [root]; seen.add(root);

    while (stack.length) {
      const node = stack.pop()!; group.push(node);

      for (const next of reversed.get(node)!) if (!seen.has(next)) { seen.add(next); stack.push(next); }
    }

    groups.push({ members: group.sort(), requiresBootstrapReview: group.length > 1 });
  }

  findings.sort((a, b) => JSON.stringify(a).localeCompare(JSON.stringify(b)));

  return { architecture, seeds: [...seeds].sort(),
    members: [...members].sort().map((pkgbase) => ({ pkgbase, changed: changed.has(pkgbase), removed: !currentBases.has(pkgbase), affectedBy: [...(causes.get(pkgbase) ?? [])].sort() })),
    buildGroups: groups.reverse(), findings,
    unresolvedCandidateRelations: findings.filter((finding) => finding.snapshot === 'candidate' && !finding.providers.length).length,
    ambiguousCandidateRelations: findings.filter((finding) => finding.snapshot === 'candidate' && finding.providers.length > 1).length,
  };
}
