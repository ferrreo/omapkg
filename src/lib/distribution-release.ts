import { canonicalJson } from './canonical-json';
import type { Architecture } from './model';

export const DISTRIBUTION_RELEASE_SCHEMA_VERSION = 1 as const;

export const DISTRIBUTION_RELEASE_POLICY = 'distribution-release-v1' as const;

export const RELEASE_ARCHITECTURES = ['x86_64', 'aarch64'] as const;

export const RELEASE_LANES = ['system', 'opr', 'transaction'] as const;

export const RELEASE_KINDS = ['system', 'opr', 'resolved-transaction'] as const;

export const RELEASE_REPOSITORIES = ['core', 'extra', 'multilib', 'omarchy', 'omapkg'] as const;

export const SYSTEM_RELEASE_CHANNELS = ['edge', 'rc', 'stable'] as const;

export const OPR_RELEASE_CHANNELS = ['quarantine', 'stable'] as const;

export const TRANSACTION_RELEASE_CHANNELS = SYSTEM_RELEASE_CHANNELS;

export const RELEASE_CHANNELS = ['edge', 'rc', 'stable', 'quarantine'] as const;

export type DistributionReleaseKind = typeof RELEASE_KINDS[number];

export type DistributionReleaseLane = typeof RELEASE_LANES[number];

export type ReleaseRepository = typeof RELEASE_REPOSITORIES[number];

export type ReleaseArchitecture = Architecture;

export type SystemReleaseChannel = typeof SYSTEM_RELEASE_CHANNELS[number];

export type OprReleaseChannel = typeof OPR_RELEASE_CHANNELS[number];

export type TransactionReleaseChannel = typeof TRANSACTION_RELEASE_CHANNELS[number];

export type DistributionReleaseChannel = SystemReleaseChannel | OprReleaseChannel;

export interface ReleaseObjectRef {
  url: string;
  sha256: string;
  size: number;
}

export interface ReleaseManifestRef {
  url: string;
  digest: string;
  signatureUrl: string;
  channel: DistributionReleaseChannel;
  sequence: number;
  version: string | null;
  generation: string | null;
}

export interface ReleaseRepositoryRef {
  name: ReleaseRepository;
  architecture: ReleaseArchitecture;
  snapshotDigest: string;
  dbUrl: string;
  signatureUrl: string;
  packageBaseUrl: string;
}

export interface ReleasePackageRef {
  releaseId: string;
  name: string;
  version: string;
  architecture: ReleaseArchitecture | 'any';
  artifactUrl: string;
  artifactSha256: string;
  artifactSignatureUrl: string;
  artifactSignatureSha256: string;
  cohortId: string | null;
  evidence: ReleaseObjectRef[];
}

export interface ReleasePackageChunkRef extends ReleaseObjectRef {
  index: number;
  count: number;
  packageCount: number;
}

export interface ReleaseSourceRef {
  name: string;
  ref: string;
  digest: string;
}

export interface ReleaseChangelogRef extends ReleaseObjectRef {
  approvedBy: string;
  cohortDigests: Array<{ cohortId: string; revision: number; digest: string }>;
}

export interface ReleaseRecoveryRef {
  fromDigest: string | null;
  target: ReleaseManifestRef | null;
  authorized: boolean;
  reason: string | null;
  constraints: string[];
}

export interface ReleaseManifest {
  schemaVersion: 1;
  kind: DistributionReleaseKind;
  lane: DistributionReleaseLane;
  channel: DistributionReleaseChannel;
  identity: { version: string | null; generation: string | null };
  releaseId: string;
  parent: { digest: string | null; sequence: number | null };
  createdAt: number;
  expiresAt: number;
  sequence: number;
  architectures: ReleaseArchitecture[];
  sourceRefs: ReleaseSourceRef[];
  repositories: ReleaseRepositoryRef[];
  packageChunks: ReleasePackageChunkRef[];
  packageCount: number;
  compatibility: {
    systemManifestDigest: string | null;
    systemSnapshotDigests: string[];
    oprManifestDigest: string | null;
  };
  systemManifest: ReleaseManifestRef | null;
  oprManifest: ReleaseManifestRef | null;
  changelog: ReleaseChangelogRef;
  approvals: { releaseTeam: string[]; baseOwners: string[] };
  recovery: ReleaseRecoveryRef;
  policy: { schemaVersion: 1; version: typeof DISTRIBUTION_RELEASE_POLICY };
}

export interface ResolvedTransactionManifest extends ReleaseManifest {
  kind: 'resolved-transaction';
  lane: 'transaction';
  systemManifest: ReleaseManifestRef;
  oprManifest: ReleaseManifestRef;
}

async function sha256(value: string): Promise<string> {
  const bytes = new TextEncoder().encode(value);

  return Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)), (byte) => byte.toString(16).padStart(2, '0')).join('');
}

export async function releaseManifestDigest(value: ReleaseManifest): Promise<string> {
  return sha256(canonicalJson(value));
}

export function releaseManifestBytes(value: ReleaseManifest): string {
  return canonicalJson(value);
}

export function isReleaseManifest(value: unknown): value is ReleaseManifest {
  if (!value || typeof value !== 'object' || (value as { schemaVersion?: unknown }).schemaVersion !== 1) return false;
  const item = value as { kind?: DistributionReleaseKind; lane?: DistributionReleaseLane; channel?: unknown };

  if (!RELEASE_KINDS.includes(item.kind as DistributionReleaseKind) || typeof item.channel !== 'string') return false;

  if (item.kind === 'system') return item.lane === 'system' && SYSTEM_RELEASE_CHANNELS.includes(item.channel as SystemReleaseChannel);

  if (item.kind === 'opr') return item.lane === 'opr' && OPR_RELEASE_CHANNELS.includes(item.channel as OprReleaseChannel);

  return item.lane === 'transaction' && TRANSACTION_RELEASE_CHANNELS.includes(item.channel as TransactionReleaseChannel);
}
