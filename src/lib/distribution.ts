import type { Architecture, Area } from './model';

export const requiredArchitectures: readonly Architecture[] = ['x86_64', 'aarch64'];
export const collections = ['core', 'extra', 'multilib', 'omarchy', 'omapkg'] as const;
export type Collection = typeof collections[number];
export type ReleaseLane = 'system' | 'opr';
export type ArtifactArchitecture = Architecture | 'any';
export type InstallationRole = 'base-system' | 'omarchy-default' | 'optional' | 'build-only';
export type PackageOrigin = 'arch' | 'omarchy' | 'upstream' | 'aur-reference' | 'alarm-reference';

export interface CatalogManifest {
  schemaVersion: 1;
  pkgbase: string;
  outputs: string[];
  collection: Collection;
  lane: ReleaseLane;
  role: InstallationRole;
  origin: PackageOrigin;
  upstreamUrl: string;
  sourceKind: 'git' | 'archive';
  description: string;
  license: string;
  ownerArea: Area;
  architectures: Architecture[];
  artifactArchitecture: 'any' | 'native';
  architectureExceptions: Array<{ architecture: Architecture; reason: string }>;
  sourceReference: { url: string; commit: string } | null;
  rebuildOn: string[];
}

export const cohortPhases = ['plan', 'review', 'build', 'verify', 'stage', 'approve', 'publish', 'observe'] as const;
export type CohortPhase = typeof cohortPhases[number];
export const cohortPhaseLabels: Record<CohortPhase, string> = {
  plan: 'Plan and admit', review: 'Review recipes', build: 'Build', verify: 'Verify',
  stage: 'Stage and test', approve: 'Approve release', publish: 'Publish', observe: 'Observe or recover',
};

export function parseSystemVersion(value: string): { version: string; candidate: 'final' | 'rc' | 'edge'; sequence: number } | null {
  const match = /^(0|[1-9]\d{0,5})\.(0|[1-9]\d{0,5})\.(0|[1-9]\d{0,5})(?:-(rc|edge\.)([1-9]\d{0,5}))?$/.exec(value);
  if (!match) return null;
  return { version: `${match[1]}.${match[2]}.${match[3]}`, candidate: match[4] === 'rc' ? 'rc' : match[4] === 'edge.' ? 'edge' : 'final', sequence: Number(match[5] ?? 0) };
}

export function packagePath(pkgbase: string, collection: Collection | null = null): string {
  if (!/^[a-z0-9][a-z0-9@._+-]{0,63}$/.test(pkgbase) || (collection !== null && !collections.includes(collection))) {
    throw new Error('Invalid catalog package path');
  }
  return `packages/${collection ? `${collection}/` : ''}${pkgbase}`;
}

export function externalPackageSource(url: string): boolean {
  const host = new URL(url).hostname.toLowerCase();
  return host === 'aur.archlinux.org' || host === 'archlinuxarm.org' || host.endsWith('.archlinuxarm.org');
}
