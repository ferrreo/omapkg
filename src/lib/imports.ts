import type { Architecture } from './model';
import type { ArtifactArchitecture, Collection } from './distribution';

export interface ImportSource {
  id: string;
  url: string;
  collection: Collection;
  target: Architecture;
  status: 'captured' | 'unavailable';
  sha256: string | null;
  entries: number;
  signature: 'verified' | 'unverified' | 'missing' | 'failed';
  signatureSha256: string | null;
  error: string | null;
  format?: 'pacman-db' | 'recipe-catalog';
}
export interface ImportManifest {
  schemaVersion: 1;
  kind: 'arch' | 'omarchy' | 'opr';
  channel: 'upstream' | 'stable' | 'rc' | 'edge' | 'dev';
  sources: ImportSource[];
  entriesSha256: string;
}
export interface ImportEntry {
  sourceId: string;
  name: string;
  pkgbase: string;
  version: string;
  architecture: ArtifactArchitecture;
  target: Architecture;
  collection: Collection;
  filename: string;
  sha256: string;
  size: number;
  installedSize: number;
  description: string;
  upstreamUrl: string | null;
  licenses: string[];
  dependencies: string[];
  makeDependencies: string[];
  checkDependencies: string[];
  provides: string[];
  conflicts: string[];
  replaces: string[];
  packageSignature: string | null;
  surface?: 'binary' | 'recipe';
  recipeUrl?: string;
}
export const importDispositionLabels = {
  unreviewed: 'Needs ownership review', linked: 'Linked to owned policy', replacement: 'OPR replacement needed',
  blocked: 'Blocked', excluded: 'Explicit exclusion',
} as const;
export type ImportDisposition = keyof typeof importDispositionLabels;
