import type { Architecture } from './model';
import type { CatalogManifest, CohortPhase, ReleaseLane } from './distribution';

export const cohortCauses = ['new-package', 'source-update', 'abi', 'static-link', 'runtime-transition', 'dependency', 'rebuild', 'security'] as const;

export type CohortCause = typeof cohortCauses[number];

export type CohortCondition = 'ready' | 'blocked' | 'held' | 'recovering' | 'complete';

export interface CohortMember {
  pkgbase: string;
  catalogRevision: number;
  catalogSha256: string;
  policy: CatalogManifest;
  recipe: { id: string; manifestSha256: string; fullVersion: string; requestId: string } | null;
  cause: CohortCause;
  reason: string;
}

export interface CohortMetadata {
  title: string;
  lane: ReleaseLane;
  systemVersion: string | null;
  parentSnapshot: string | null;
  compatibleSystems: string[];
}

export interface CohortInlineManifest extends CohortMetadata { schemaVersion: 1; members: CohortMember[] }

export interface CohortMemberChunk { index: number; start: number; count: number; first: string; last: string; sha256: string }

export interface CohortChunkedManifest extends CohortMetadata {
  schemaVersion: 2;
  memberCount: number;
  ownerAreas: string[];
  architectures: Architecture[];
  memberChunks: CohortMemberChunk[];
}

export type CohortManifest = CohortInlineManifest | CohortChunkedManifest;

export const cohortPageSize = 25;

export const cohortGatePageSize = (phase: CohortPhase) => phase === 'plan' || phase === 'review' ? cohortPageSize : 1;

export const cohortMemberCount = (manifest: CohortManifest) => manifest.schemaVersion === 1 ? manifest.members.length : manifest.memberCount;

export const cohortOwnerAreas = (manifest: CohortManifest) => manifest.schemaVersion === 1 ? [...new Set(manifest.members.map((member) => member.policy.ownerArea))].sort() : manifest.ownerAreas;

export interface CohortEvent {
  schemaVersion: 1;
  cohortId: string;
  revision: number;
  sequence: number;
  kind: 'scope' | 'phase' | 'condition' | 'changelog' | 'changelog-review' | 'publication' | 'recovery';
  previousEventSha256: string | null;
  priorManifestSha256: string | null;
  manifestSha256: string;
  from: CohortPhase | null;
  phase: CohortPhase;
  condition: CohortCondition;
  actor: string;
  timestamp: number;
  cause: string;
  evidence: Record<string, string>;
}

export interface CohortRow {
  id: string; current_revision: number; event_sequence: number; event_sha256: string | null;
  phase: CohortPhase; condition: CohortCondition; updated_at: number;
  manifest_json: string; manifest_sha256: string; title: string; lane: ReleaseLane;
}

export interface CohortBlocker {
  code: string; pkgbase: string | null; architecture: Architecture | null; reason: string; href: string | null;
}
