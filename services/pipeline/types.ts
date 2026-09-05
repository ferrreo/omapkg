import type { Architecture, Area, BuildImageMap, Revision, Source } from '../../src/lib/model';
import type { GitHubEnv } from '../../src/lib/server/github';
import type { VendorArtifactManifest } from './artifacts';

export type SourceKind = 'git' | 'archive';
export type Surface = 'binary' | 'recipe';
export type VendorKind = 'go' | 'rust' | 'npm';

export interface VendorComponent {
  name: string;
  version: string;
  source: string;
  checksum: string | null;
  checksumAlgorithm: 'SHA256' | 'GO-H1' | null;
  integrity: string | null;
  license: string | null;
}

export interface VendorEvidence {
  kind: VendorKind;
  sourceName: string;
  sourceSha256: string;
  sourceUrl: string;
  sourceKey: string;
  components: VendorComponent[];
}

export interface FactoryRequest {
  id: string;
  name: string;
  upstreamUrl: string;
  sourceKind: SourceKind;
  area: Area;
  /** Requester-provided description retained as an untrusted factory hint. */
  descriptionHint?: string;
  /** Maintainer-provided regeneration feedback retained as an untrusted factory advisory. */
  maintainerFeedback?: string;
  /** Requester-provided, untrusted license hint. Candidate license is verified independently. */
  declaredLicense: string;
  /** Optional immutable upstream release ref selected by the watcher. */
  upstreamRef?: string | null;
  /** Trusted platform-selected images passed to the factory run. */
  buildImages?: BuildImageMap;
  /** Server-selected Arch package release number for this generation. */
  pkgrel?: number;
}

export interface SourceEvidence {
  sourceKind: SourceKind;
  upstreamUrl: string;
  normalizedUrl: string;
  finalUrl?: string;
  redirectChain?: string[];
  sourceName: string;
  sourceSha256: string;
  sourceKey?: string;
  upstreamCommit: string | null;
  sourceRoot?: string;
  files: string[];
  licenseFiles: string[];
  vendor?: VendorEvidence;
  vendorArtifact?: VendorArtifactManifest;
}

export interface FactoryCandidate {
  request: FactoryRequest;
  version: string;
  sources: Source[];
  /** Trusted single-directory root from archive inspection; never accepted from model output. */
  sourceRoot?: string;
  dependencies: string[];
  makeDependencies?: string[];
  smokeCommands: string[];
  architectures: Architecture[];
  buildImages?: BuildImageMap;
  vendorArtifact?: VendorArtifactManifest;
  /** Public client recipe. Internal recipe may use private sealed source URLs. */
  publicRecipe?: string | null;
  pkgrel?: number;
  sourceDateEpoch: number;
  imageDigest: string;
  license: string;
  surface: Surface;
  description: string;
  buildCommands: string[];
  packageCommands: string[];
  explanation: string;
  sbom?: Record<string, unknown>;
  upstreamCommit?: string | null;
  prUrl?: string | null;
  commitSha?: string | null;
}

export interface RecipeLint {
  passed: boolean;
  checks: Array<{ name: string; passed: boolean; detail: string }>;
  repairAttempts: number;
}

export interface FactoryRevisionDraft {
  revision: Revision;
  manifest: {
    requestId: string;
    packageName: string;
    version: string;
    sourceKind: SourceKind;
    sources: Source[];
    dependencies: string[];
    makeDependencies: string[];
    smokeCommands: string[];
    architectures: Architecture[];
    buildImages: BuildImageMap;
    pkgrel: number;
    sourceDateEpoch: number;
    imageDigest: string;
    license: string;
    surface: Surface;
    description: string;
    publicRecipeSha256: string | null;
  };
  lint: RecipeLint;
}

export interface FactoryEnv extends GitHubEnv {
  DB: D1Database;
  ARTIFACTS: R2Bucket;
  AI?: { run(modelId: string, inputs: Record<string, unknown>, options?: Record<string, unknown>): Promise<Response | Record<string, unknown>> };
  Sandbox?: DurableObjectNamespace;
  FACTORY?: Fetcher;
  FACTORY_BUILDER_IMAGE?: string;
  FACTORY_BUILDER_IMAGE_DIGEST?: string;
  PUBLIC_ORIGIN?: string;
}

export interface FactoryWorkflowParams {
  requestId: string;
  generationId?: string;
}

export interface FactoryWorkflowBinding {
  create(options: { id: string; params: FactoryWorkflowParams }): Promise<unknown>;
  get(id: string): Promise<{ status(): Promise<{ status: string }> }>;
}

export type PipelineEnv = Omit<FactoryEnv, 'FACTORY'> & {
  FACTORY?: FactoryWorkflowBinding;
};
