import type { Architecture } from './model';

export type ReleaseKind = 'system' | 'opr' | 'resolved-transaction';

export type ReleaseStatus = 'candidate' | 'testing' | 'stable' | 'blocked' | 'superseded' | 'withdrawn' | 'unavailable';

export type ReleaseCheckStatus = 'passed' | 'failed' | 'pending' | 'not-required';

export interface ReleaseIdentity {
  version: string | null;
  generation: string | null;
}

export interface ReleaseBlocker {
  code: string;
  reason: string;
  owner?: string | null;
  architecture?: Architecture | null;
  href?: string | null;
}

export interface ReleaseCheck {
  architecture: Architecture;
  status: ReleaseCheckStatus;
  label: string;
  detail?: string | null;
  checkedAt?: number | null;
}

export interface ReleaseRepository {
  name?: string;
  architecture: Architecture;
  channel: string;
  state: 'available' | 'candidate' | 'unavailable' | 'not-published';
  packageCount?: number | null;
  databaseUrl?: string | null;
  signatureUrl?: string | null;
  digest?: string | null;
}

export interface ReleaseChangelog {
  digest: string | null;
  summary: string | null;
  comparison: string | null;
  approved: boolean;
  markdownUrl?: string | null;
  jsonUrl?: string | null;
}

export interface ReleaseRecovery {
  predecessor: string | null;
  manifestUrl: string | null;
  instructions: string | null;
}

export interface ReleaseHistoryEntry {
  label: string;
  status: string;
  timestamp: number;
  digest?: string | null;
}

export interface ReleaseView {
  id: string;
  candidateId?: string;
  manifestDigest?: string | null;
  parentDigest?: string | null;
  parentSequence?: number | null;
  kind: ReleaseKind;
  channel: 'edge' | 'rc' | 'stable' | 'quarantine';
  identity: ReleaseIdentity;
  sequence: string | number;
  createdAt: number;
  expiresAt: number | null;
  status: ReleaseStatus;
  phase: string;
  condition: string | null;
  summary: string;
  systemCompatibility: string[];
  architectures: Architecture[];
  repositories: ReleaseRepository[];
  packageChunks: number | null;
  packageName?: string | null;
  packageVersion?: string | null;
  blockers: ReleaseBlocker[];
  checks: ReleaseCheck[];
  changelog: ReleaseChangelog;
  recovery: ReleaseRecovery;
  history: ReleaseHistoryEntry[];
  href?: string | null;
}

export interface ReleaseWorkbenchView {
  engine: 'published' | 'candidate' | 'empty';
  source: 'distribution' | 'legacy';
  notice: string | null;
  checkedAt: number;
  selectedSystemVersion: string | null;
  selectedArchitecture: Architecture | null;
  systemReleases: ReleaseView[];
  oprReleases: ReleaseView[];
  transactions: ReleaseView[];
}

export const architectureLabel = (architecture: Architecture) => architecture === 'aarch64' ? 'ARM64 · aarch64' : 'Intel/AMD · x86_64';

export function releaseKindLabel(kind: ReleaseKind): string {
  switch (kind) {
    case 'system': return 'System release';
    case 'opr': return 'Independent OPR';
    case 'resolved-transaction': return 'Resolved transaction';
  }
}

export const releaseStatusLabel = (status: ReleaseStatus) => status.replaceAll('-', ' ');

export const releaseDate = (timestamp: number | null | undefined) => timestamp ? new Date(timestamp * 1000).toISOString().replace('T', ' ').replace('.000Z', ' UTC') : 'Not recorded';

export function releaseVersion(view: Pick<ReleaseView, 'kind' | 'identity'> & Pick<ReleaseView, 'packageName' | 'packageVersion'>): string {
  if (view.kind === 'opr' && view.packageName && view.packageVersion) return `${view.packageName} ${view.packageVersion}`;

  if (view.identity.version) return view.identity.version;

  if (view.identity.generation) return view.identity.generation;

  return 'Version not recorded';
}

export function releaseCompatibility(view: Pick<ReleaseView, 'kind' | 'systemCompatibility'>): string {
  if (view.kind === 'system') return 'Pinned system set';

  if (!view.systemCompatibility.length) return 'Compatibility snapshot not recorded';

  return view.systemCompatibility.join(', ');
}
