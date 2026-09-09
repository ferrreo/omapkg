import type { Architecture, Revision } from '../model';
import type { ArtifactArchitecture } from '../distribution';
import type { CohortManifest } from '../cohorts';
import { canonicalJson } from '../canonical-json';
import { isArchPkgver, parsePackageMetadata, type PackageMetadata } from './arch';
import { query } from './db';
import { readOprEvidence } from './sbom';
import { WorkerProtocolError, type ArtifactReference, type WorkerLease } from './worker-protocol';

export type OutputMetadata = Omit<PackageMetadata, 'architecture'> & { architecture: ArtifactArchitecture };
export type ExpectedOutput = { name: string; fullVersion: string; architecture: ArtifactArchitecture };
export type OutputContract = {
  schemaVersion: 2;
  cohort: { id: string; revision: number; manifestSha256: string };
  outputs: ExpectedOutput[];
  runtimeGroups: string[][];
};
export const MAX_BUILD_OUTPUTS = 256;

export function packageFilename(output: ExpectedOutput): string {
  return `${output.name}-${output.fullVersion}-${output.architecture}.pkg.tar.zst`;
}

/** Explicit import version fields live inside the immutable, reviewed SBOM. */
export function reviewedPackageVersion(revision: Pick<Revision, 'version' | 'pkgrel' | 'sbom_json'>): string {
  const version = readOprEvidence(JSON.parse(revision.sbom_json))?.packageVersion;
  if (version === undefined) return `${revision.version}-${revision.pkgrel ?? 1}`;
  if (!version || typeof version !== 'object' || Array.isArray(version)) throw new Error('Invalid reviewed package version');
  const item = version as Record<string, unknown>;
  if (Object.keys(item).sort().join(',') !== 'epoch,pkgrel' || !Number.isSafeInteger(item.epoch) || (item.epoch as number) < 0 ||
      typeof item.pkgrel !== 'string' || !/^[1-9]\d{0,3}(?:\.[1-9]\d{0,3})?$/.test(item.pkgrel) || Number(item.pkgrel.split('.')[0]) !== (revision.pkgrel ?? 1)) {
    throw new Error('Invalid reviewed epoch or package release');
  }
  return `${item.epoch ? `${item.epoch}:` : ''}${revision.version}-${item.pkgrel}`;
}

export function parseOutputMetadata(value: unknown): OutputMetadata | null {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  const item = value as Record<string, unknown>;
  const native = parsePackageMetadata(item.architecture === 'any' ? { ...item, architecture: 'x86_64' } : item);
  return native ? { ...native, architecture: item.architecture as ArtifactArchitecture } : null;
}

export function parseOutputContract(value: unknown, target: Architecture): OutputContract {
  const item = value as OutputContract;
  if (!item || typeof item !== 'object' || Object.keys(item).sort().join(',') !== 'cohort,outputs,runtimeGroups,schemaVersion' || item.schemaVersion !== 2 ||
      !item.cohort || Object.keys(item.cohort).sort().join(',') !== 'id,manifestSha256,revision' ||
      !/^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/.test(item.cohort.id) || !Number.isSafeInteger(item.cohort.revision) || item.cohort.revision < 1 ||
      !/^[a-f0-9]{64}$/.test(item.cohort.manifestSha256) || !Array.isArray(item.outputs) || !item.outputs.length || item.outputs.length > MAX_BUILD_OUTPUTS) {
    throw new WorkerProtocolError(409, 'Invalid build output contract');
  }
  for (const output of item.outputs) {
    const version = typeof output?.fullVersion === 'string' ? /^(?:([0-9]+):)?(.+)-([1-9]\d{0,3}(?:\.[1-9]\d{0,3})?)$/.exec(output.fullVersion) : null;
    if (!output || Object.keys(output).sort().join(',') !== 'architecture,fullVersion,name' ||
        !/^[a-z0-9][a-z0-9@._+-]{0,63}$/.test(output.name) || !version || output.fullVersion.length > 128 || !isArchPkgver(version[2]) ||
        (output.architecture !== target && output.architecture !== 'any')) throw new WorkerProtocolError(409, 'Invalid expected package output');
  }
  if (new Set(item.outputs.map((output) => output.name)).size !== item.outputs.length) throw new WorkerProtocolError(409, 'Duplicate expected package output');
  if (!Array.isArray(item.runtimeGroups) || !item.runtimeGroups.length || item.runtimeGroups.length > MAX_BUILD_OUTPUTS ||
      item.runtimeGroups.some((group) => !Array.isArray(group) || !group.length || group.length > MAX_BUILD_OUTPUTS || new Set(group).size !== group.length || group.some((name) => !item.outputs.some((output) => output.name === name))) ||
      new Set(item.runtimeGroups.flat()).size !== item.outputs.length || new Set(item.runtimeGroups.map((group) => [...group].sort().join(' '))).size !== item.runtimeGroups.length) {
    throw new WorkerProtocolError(409, 'Native installation groups must cover every output without duplicate groups');
  }
  return item;
}

export async function cohortOutputContract(db: D1Database, revision: { id: string; version: string; pkgrel: number | null; sbom_json: string }, target: Architecture): Promise<OutputContract | null> {
  const row = await db.prepare(`SELECT c.id,c.current_revision,r.manifest_sha256,r.manifest_json FROM cohort_recipe_ownership o
    JOIN cohorts c ON c.id=o.cohort_id JOIN cohort_revisions r ON r.cohort_id=c.id AND r.revision=c.current_revision
    WHERE o.recipe_revision_id=?`).bind(revision.id).first<{ id: string; current_revision: number; manifest_sha256: string; manifest_json: string }>();
  if (!row) return null;
  const manifest: CohortManifest = JSON.parse(row.manifest_json);
  const member = manifest.members.find((member) => member.recipe?.id === revision.id);
  if (!member || !member.policy.architectures.includes(target)) throw new WorkerProtocolError(409, 'Build is outside current cohort scope');
  const fullVersion = reviewedPackageVersion(revision);
  return parseOutputContract({ schemaVersion: 2, cohort: { id: row.id, revision: row.current_revision, manifestSha256: row.manifest_sha256 },
    runtimeGroups: member.policy.runtimeGroups ?? [member.policy.outputs],
    outputs: member.policy.outputs.map((name) => ({ name, fullVersion, architecture: member.policy.artifactArchitecture === 'any' || member.policy.portableOutputs?.includes(name) ? 'any' : target })) }, target);
}

export function storedOutputContract(build: Pick<WorkerLease, 'output_contract_json' | 'architecture'>): OutputContract | null {
  return build.output_contract_json ? parseOutputContract(JSON.parse(build.output_contract_json), build.architecture) : null;
}

export function assertExpectedFilename(build: WorkerLease, filename: string): void {
  const contract = storedOutputContract(build);
  if (contract && !contract.outputs.some((output) => packageFilename(output) === filename)) throw new WorkerProtocolError(409, 'Artifact is outside expected output set');
}

export async function buildArtifacts(db: D1Database, build: Pick<WorkerLease, 'id' | 'attempt'>): Promise<ArtifactReference[]> {
  return query<ArtifactReference>(db, 'SELECT artifact_key AS key,sha256,size,filename FROM build_artifacts WHERE build_id=? AND attempt=? ORDER BY filename', build.id, build.attempt);
}

export function artifactInsert(db: D1Database, build: WorkerLease, workerId: string, token: string, artifact: ArtifactReference, timestamp: number): D1PreparedStatement {
  return db.prepare(`INSERT OR IGNORE INTO build_artifacts(build_id,attempt,filename,artifact_key,sha256,size,created_at)
    SELECT id,attempt,?,?,?,?,? FROM builds WHERE id=? AND attempt=? AND worker_id=? AND lease_token=? AND status='leased' AND lease_expires_at>?
    AND output_contract_json=? AND EXISTS(SELECT 1 FROM workers WHERE id=? AND status='active')
    AND revision_id=(SELECT latest.id FROM revisions latest WHERE latest.request_id=(SELECT request_id FROM revisions WHERE id=builds.revision_id) ORDER BY latest.created_at DESC,latest.rowid DESC LIMIT 1)
    AND (SELECT COUNT(DISTINCT kind) FROM approvals WHERE revision_id=builds.revision_id AND manifest_sha256=(SELECT manifest_sha256 FROM revisions WHERE id=builds.revision_id) AND revoked_at IS NULL)=2`)
    .bind(artifact.filename, artifact.key, artifact.sha256, artifact.size, timestamp, build.id, build.attempt, workerId, token, timestamp, build.output_contract_json, workerId);
}

export function sameArtifacts(left: ArtifactReference[], right: ArtifactReference[]): boolean {
  const ordered = (items: ArtifactReference[]) => [...items].sort((a, b) => a.filename < b.filename ? -1 : a.filename > b.filename ? 1 : 0);
  return canonicalJson(ordered(left)) === canonicalJson(ordered(right));
}
