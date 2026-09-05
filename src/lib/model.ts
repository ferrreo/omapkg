export const areas = ['desktop', 'development', 'gaming', 'multimedia', 'productivity', 'system'] as const;
export type Area = (typeof areas)[number];
export const teams = [...areas, 'security', 'admin'] as const;
export type Team = (typeof teams)[number];
export type Architecture = 'x86_64' | 'aarch64';
export type BuildImageMap = Partial<Record<Architecture, string>>;
export type Role = 'public' | 'maintainer' | 'security' | 'admin';
export type Source = { name: string; url: string; sha256: string };
export type RequestStatus = 'pending' | 'generating' | 'review' | 'queued' | 'building' | 'built' | 'failed' | 'rejected';
export interface PackageRequest {
  id: string; name: string; upstream_url: string; source_kind: 'git' | 'archive'; area: Area;
  description: string; declared_license: string; requested_by: string; status: RequestStatus; created_at: number; updated_at: number; rejection_reason: string | null;
}
export interface Revision {
  id: string; request_id: string; version: string; recipe: string; recipe_sha256: string;
  public_recipe?: string | null; public_recipe_sha256?: string | null;
  manifest_sha256: string; sources_json: string; dependencies_json: string; smoke_commands_json: string;
  architectures_json: string; make_dependencies_json?: string | null; build_images_json?: string | null; pkgrel?: number | null;
  source_date_epoch: number; image_digest: string; license: string;
  surface: 'binary' | 'recipe'; description?: string | null; explanation: string; sbom_json: string; lint_json: string;
  upstream_commit: string | null; pr_url: string | null; commit_sha: string | null; created_at: number;
}
export interface Build {
  id: string; revision_id: string; architecture: Architecture; status: 'queued' | 'leased' | 'succeeded' | 'failed' | 'cancelled';
  worker_id: string | null; lease_token: string | null; lease_expires_at: number | null;
  attempt: number; artifact_key: string | null; artifact_sha256: string | null; artifact_size: number | null;
  artifact_filename: string | null; installed_size: number | null; dependency_plan_json: string | null; provenance: string | null; provenance_signature: string | null;
  smoke_passed: number; error: string | null; created_at: number; started_at: number | null; finished_at: number | null;
}
export interface Worker {
  id: string; name: string; architecture: Architecture; public_key: string;
  status: 'active' | 'revoked'; enrolled_at: number; last_seen_at: number | null;
  daemon_version: string | null; runtime: 'podman' | 'docker' | null; capabilities_json: string | null;
  accepting_jobs: number; paused_at: number | null; removed_at: number | null;
}
export interface AuditEvent { id: number; actor: string; action: string; target: string; detail: string; created_at: number }
export interface Approval { id: string; revision_id: string; actor: string; kind: 'area' | 'security'; manifest_sha256: string; created_at: number }
export interface Release {
  id: string; build_id: string; name: string; version: string; architecture: Architecture; surface: 'binary' | 'recipe';
  channel: 'dev' | 'stable' | 'withdrawn'; artifact_key: string | null; signature_key: string | null;
  recipe_key: string; sbom_key: string; provenance_key: string; published_at: number;
  stable_at: number | null; batch_id: string | null; previous_release_id: string | null;
}
export interface Actor { id: string; role: Role; areas: readonly string[] }

export type CatalogRelease = Release & Pick<Build, 'artifact_filename' | 'artifact_sha256' | 'artifact_size'>;
