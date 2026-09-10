import type { Architecture } from '../model';
import { canonicalJson } from '../canonical-json';
import { collections, parseSystemVersion, type ArtifactArchitecture, type Collection } from '../distribution';
import type { CatalogManifest } from '../distribution';
import { parseOutputMetadata, type OutputMetadata } from '../output-contract';
import { parsePackageMetadata, type PackageMetadata } from './arch';
import { currentNativeBuild } from './native-signing';
import { cohortMemberStream } from './cohort-members';
import type { CohortMember } from '../cohorts';
import { repositoryDatabaseForPackages, type RepositoryDatabasePackage, PACKAGE_FILENAME } from './repository';
import { signingRequest } from './release-evidence';
import { attestationKey } from './release-attestation';
import { immutableBytes, safeKey, SHA256, verifyR2Object } from './release-storage';
import { id, now, query, sha256 } from './db';
import type { Env } from './env';
import { PolicyError } from './policy';

const MAX_PACKAGES = 100_000;

const MAX_CHUNK_BYTES = 1_048_576;

const MAX_CHUNKS = 100_000;

const PACKAGE_NAME = /^[a-z0-9][a-z0-9@._+-]{0,63}$/;

const RELEASE_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;

const TARGETS: readonly Architecture[] = ['x86_64', 'aarch64'];

export type OwnedRepositoryLane = 'system' | 'opr';

export type OwnedRepositoryChannel = 'edge' | 'rc' | 'stable' | 'quarantine';

export interface OwnedRepositoryPrepareInput {
  lane: OwnedRepositoryLane;
  releaseId: string;
  cohortIds: string[];
  trustedParentReleaseId?: string | null;
}

export interface OwnedRepositorySnapshotRef {
  id: string;
  lane: OwnedRepositoryLane;
  releaseId: string;
  architecture: Architecture;
  collection: Collection;
  dbFilename: string;
  dbKey: string;
  dbSha256: string;
  snapshotDigest: string;
  dbSize: number;
  dbSignatureKey: string;
  dbSignatureSha256: string;
  filenameMapKey: string;
  filenameMapSha256: string;
  filenameMapSize: number;
  packageCount: number;
  dbUrl: string;
  signatureUrl: string;
  packageBaseUrl: string;
}

export interface OwnedRepositoryPackageRef {
  releaseId: string;
  name: string;
  version: string;
  architecture: ArtifactArchitecture;
  collection: Collection;
  targetArchitecture: Architecture;
  artifactUrl: string;
  artifactSha256: string;
  artifactSignatureUrl: string;
  artifactSignatureSha256: string;
  cohortId: string;
  evidence: Array<{ url: string; sha256: string; size: number }>;
  ownedArtifactId: string;
}

export interface OwnedRepositoryPackageChunkRef {
  key: string;
  url: string;
  sha256: string;
  size: number;
  index: number;
  count: number;
  packageCount: number;
}

export interface OwnedRepositoryPreparation {
  lane: OwnedRepositoryLane;
  releaseId: string;
  snapshots: OwnedRepositorySnapshotRef[];
  packageChunks: OwnedRepositoryPackageChunkRef[];
  packageCount: number;
  universeId: string;
  universeSha256: string;
}

export interface OwnedRepositoryReleaseRepository {
  name: Collection;
  architecture: Architecture;
  snapshotDigest: string;
  dbUrl: string;
  signatureUrl: string;
  packageBaseUrl: string;
  dbKey: string;
  signatureKey: string;
  signatureSha256: string;
}

export interface OwnedRepositoryUniversePackage {
  ownedArtifactId: string;
  collection: Collection;
  targetArchitecture: Architecture;
  pkgbase: string;
  name: string;
  version: string;
  architecture: ArtifactArchitecture;
  artifactArch: ArtifactArchitecture;
  artifactSha256: string;
  artifactSize: number;
  depends: string[];
  provides: string[];
  conflicts: string[];
  replaces: string[];
  rebuildOn: string[];
  buildId: string;
  attempt: number;
  abiInventoryRef: string | null;
  cohortId: string;
  cohortRevision: number;
}

export interface OwnedRepositoryUniverse {
  id: string;
  lane: OwnedRepositoryLane;
  releaseId: string;
  rootSha256: string;
  packageCount: number;
}

type PackageRecord = RepositoryDatabasePackage & {
  ownedArtifactId?: string;
  collection: Collection;
  targetArchitecture: Architecture;
  pkgbase: string;
  cohortId: string;
  cohortRevision: number;
  buildId: string;
  buildAttempt: number;
  revisionId: string;
  signatureSha256: string;
  attestationKey: string;
  attestationSha256: string;
  attestationSignatureKey: string;
  attestationSignatureSha256: string;
  attestationSize: number;
  rebuildOn: string[];
  abiInventoryRef: string | null;
};

type SnapshotRow = OwnedRepositorySnapshotRef & { status: 'prepared' | 'published' | 'superseded'; created_at: number };

type ArtifactRow = PackageRecord & { ownedArtifactId: string };

function reject(message: string, status = 409): never {
  throw new PolicyError(status, message);
}

function text(value: unknown, label: string, maximum = 256): string {
  if (typeof value !== 'string' || !value || value.length > maximum || [...value].some((character) => character <= '\u001f' || character === '\u007f')) reject(`${label} is invalid.`, 400);

  return value;
}

function releaseId(lane: OwnedRepositoryLane, value: unknown): string {
  const result = text(value, 'Release identity', 128);

  if (!RELEASE_ID.test(result) || (lane === 'system' && !parseSystemVersion(result)) || (lane === 'opr' && !/^opr-[A-Za-z0-9][A-Za-z0-9._-]{0,110}$/.test(result))) {
    reject('Owned release identity is invalid.', 400);
  }

  return result;
}

function encoded(value: string): string {
  return encodeURIComponent(value);
}

function baseUrl(env: Env, lane: OwnedRepositoryLane, idValue: string, name: Collection, architecture: Architecture): string {
  const root = lane === 'system' ? `/repo/releases/${encoded(idValue)}` : `/repo/opr/${encoded(idValue)}`;

  return `${env.PUBLIC_ORIGIN.replace(/\/$/, '')}${root}/${name}/${architecture}/`;
}

function objectKey(lane: OwnedRepositoryLane, release: string, collectionValue: Collection, architecture: Architecture, filename: string): string {
  return `owned-repositories/${lane}/${encoded(release)}/${collectionValue}/${architecture}/${filename}`;
}

function mapKey(lane: OwnedRepositoryLane, release: string, collectionValue: Collection, architecture: Architecture): string {
  return `owned-repositories/${lane}/${encoded(release)}/${collectionValue}/${architecture}/filename-map.json`;
}

function chunkKey(lane: OwnedRepositoryLane, release: string, index: number): string {
  return `owned-repositories/${lane}/${encoded(release)}/package-chunks/${index}.json`;
}

function assertPackageFilename(value: string): void {
  if (!PACKAGE_FILENAME.test(value)) reject('Native output filename is invalid.');
}

function parseOutputReport(value: string): Array<{ pkgbase: string; filename: string; artifactSha256: string; packageMetadata: OutputMetadata }> {
  let parsed: unknown;

  try { parsed = JSON.parse(value); } catch { reject('Native build provenance is invalid.'); }

  const outputs = parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? (parsed as { outputs?: unknown }).outputs : null;

  if (!Array.isArray(outputs) || !outputs.length || outputs.length > 256) reject('Native build output set is incomplete.');

  return outputs.map((value) => {
    if (!value || typeof value !== 'object' || Array.isArray(value)) reject('Native output evidence is invalid.');
    const output = value as Record<string, unknown>;
    const metadata = parseOutputMetadata(output.packageMetadata);

    if (!metadata || typeof output.pkgbase !== 'string' || !PACKAGE_NAME.test(output.pkgbase) || typeof output.filename !== 'string' ||
        typeof output.artifactSha256 !== 'string' || !SHA256.test(output.artifactSha256)) reject('Native output evidence is invalid.');
    assertPackageFilename(output.filename);

    return { pkgbase: output.pkgbase, filename: output.filename, artifactSha256: output.artifactSha256, packageMetadata: metadata };
  });
}

async function signatureBytes(env: Env, key: string, expected: string): Promise<number> {
  const object = await env.ARTIFACTS.get(key);

  if (!object) reject('Signed repository object is missing.');
  const bytes = new Uint8Array(await object!.arrayBuffer());

  if (!bytes.length || bytes.byteLength > 16_384 || await sha256(bytes) !== expected) reject('Signed repository object digest changed.');

  return bytes.byteLength;
}

async function signedIntent(env: Env, buildId: string, attempt: number, kind: 'package' | 'attestation', key: string, digestValue: string, filename: string, manifestSha256: string, expectedSize?: number) {
  const row = await env.DB.prepare(`SELECT id,object_key,artifact_sha256,artifact_filename,signature_key,signature_sha256,artifact_size
    FROM signing_intents WHERE build_id=? AND build_attempt=? AND object_kind=? AND status='signed' AND manifest_sha256=?
      AND object_key=? AND artifact_sha256=? AND artifact_filename=? ORDER BY created_at DESC LIMIT 1`)
    .bind(buildId, attempt, kind, manifestSha256, key, digestValue, filename)
    .first<{ id: string; object_key: string; artifact_sha256: string; artifact_filename: string; signature_key: string; signature_sha256: string; artifact_size: number | null }>();

  if (!row || !row.signature_key || !row.signature_sha256 || !SHA256.test(row.signature_sha256)) reject(`Current signed ${kind} evidence is required.`);

  if (row.artifact_size !== null && (row.artifact_size <= 0 || (expectedSize !== undefined && row.artifact_size !== expectedSize))) reject(`Current signed ${kind} evidence is invalid.`);
  const size = await signatureBytes(env, row.signature_key, row.signature_sha256);

  return { ...row, signatureSize: size };
}

async function currentAttestation(env: Env, context: Awaited<ReturnType<typeof currentNativeBuild>>) {
  const key = attestationKey(context.build.id, context.build.attempt);
  const object = await env.ARTIFACTS.get(key);

  if (!object) reject('Current native attestation is missing.');
  const bytes = new Uint8Array(await object!.arrayBuffer());
  const attestationSha256 = await sha256(bytes);
  const intent = await signedIntent(env, context.build.id, context.build.attempt, 'attestation', key, attestationSha256, 'attestation.json', context.revision.manifest_sha256, bytes.byteLength);

  return { key, sha256: attestationSha256, size: bytes.byteLength, signatureKey: intent.signature_key, signatureSha256: intent.signature_sha256 };
}

function abiInventoryRef(value: string, name: string): string | null {
  try {
    const report = JSON.parse(value) as { runtimeTests?: Array<{ analyses?: Array<{ name?: string; runtimeAnalysis?: { abiInventory?: { sha256?: unknown } } }> }> };

    for (const test of report.runtimeTests ?? []) for (const analysis of test.analyses ?? []) {
      const digestValue = analysis.name === name ? analysis.runtimeAnalysis?.abiInventory?.sha256 : null;

      if (typeof digestValue === 'string' && SHA256.test(digestValue)) return digestValue;
    }
  } catch { /* currentNativeBuild already authenticated report bytes */ }

  return null;
}

async function currentCatalog(env: Env, member: CohortMember, cohortId: string, cohortRevision: number) {
  if (!member.recipe?.id) reject(`Cohort ${cohortId} member ${member.pkgbase} has no reviewed recipe.`);

  const row = await env.DB.prepare(`SELECT p.current_revision,p.admitted_revision,r.manifest_json,r.manifest_sha256,r.collection,r.lane
    FROM catalog_packages p JOIN catalog_revisions r ON r.pkgbase=p.pkgbase AND r.revision=p.current_revision WHERE p.pkgbase=?`).bind(member.pkgbase)
    .first<{ current_revision: number; admitted_revision: number | null; manifest_json: string; manifest_sha256: string; collection: string; lane: string }>();

  if (!row || row.current_revision !== member.catalogRevision || row.admitted_revision !== member.catalogRevision || row.manifest_sha256 !== member.catalogSha256) {
    reject(`Catalog ownership for ${member.pkgbase} is no longer current.`);
  }

  let manifest: CatalogManifest;

  try { manifest = JSON.parse(row.manifest_json) as CatalogManifest; } catch { reject(`Catalog ownership for ${member.pkgbase} is invalid.`); }

  if (manifest.pkgbase !== member.pkgbase || manifest.collection !== row.collection || manifest.lane !== row.lane || canonicalJson(manifest) !== canonicalJson(member.policy)) {
    reject(`Catalog ownership for ${member.pkgbase} differs from current cohort scope.`);
  }

  const membership = await env.DB.prepare(`SELECT recipe_revision_id,catalog_revision FROM cohort_members WHERE cohort_id=? AND revision=? AND pkgbase=?`)
    .bind(cohortId, cohortRevision, member.pkgbase).first<{ recipe_revision_id: string | null; catalog_revision: number }>();

  if (!membership || membership.catalog_revision !== member.catalogRevision || membership.recipe_revision_id !== member.recipe.id) reject(`Cohort membership for ${member.pkgbase} is no longer current.`);

  for (const output of manifest.outputs) {
    const owner = await env.DB.prepare('SELECT pkgbase FROM catalog_outputs WHERE name=?').bind(output).first<{ pkgbase: string }>();

    if (!owner || owner.pkgbase !== member.pkgbase) reject(`Catalog output ${output} has foreign ownership.`);
  }

  return manifest;
}

async function currentPackageRecords(env: Env, input: OwnedRepositoryPrepareInput): Promise<PackageRecord[]> {
  const records: PackageRecord[] = [];
  const seenCohorts = new Set<string>();

  for (const cohortId of [...new Set(input.cohortIds)].sort()) {
    if (!/^[-A-Za-z0-9_]{1,128}$/.test(cohortId)) reject('Cohort identity is invalid.', 400);

    const cohort = await env.DB.prepare(`SELECT c.id,c.current_revision,c.condition,r.manifest_json,r.manifest_sha256,r.lane
      FROM cohorts c JOIN cohort_revisions r ON r.cohort_id=c.id AND r.revision=c.current_revision WHERE c.id=?`).bind(cohortId)
      .first<{ id: string; current_revision: number; condition: string; manifest_json: string; manifest_sha256: string; lane: string }>();

    if (!cohort || (cohort.lane !== input.lane && !(cohort.lane === 'system' && input.lane === 'opr')) || cohort.condition === 'held') {
      reject(`Cohort ${cohortId} is not a current owned ${input.lane} cohort.`);
    }

    if (seenCohorts.has(cohortId)) continue;
    seenCohorts.add(cohortId);
    const record = { id: cohort.id, current_revision: cohort.current_revision, manifest_json: cohort.manifest_json, manifest_sha256: cohort.manifest_sha256 };

    for await (const member of cohortMemberStream(env.DB, record)) {
      // A coupled system cohort owns both slices. Repository preparation is lane-specific;
      // policy ownership, rather than cohort metadata, selects the slice.
      if (member.policy.lane !== input.lane) continue;
      const manifest = await currentCatalog(env, member, cohortId, cohort.current_revision);
      const exception = new Map(member.policy.architectureExceptions.map((value) => [value.architecture, value.reason]));

      for (const target of TARGETS) {
        if (!member.policy.architectures.includes(target)) {
          if (!exception.has(target)) reject(`${member.pkgbase} has no reviewed ${target} disposition.`);
          continue;
        }

        const build = await env.DB.prepare('SELECT id FROM builds WHERE revision_id=? AND architecture=?').bind(member.recipe!.id, target).first<{ id: string }>();

        if (!build) reject(`${member.pkgbase} has no current native ${target} build.`);
        const context = await currentNativeBuild(env, build!.id);

        if (context.contract.cohort.id !== cohortId || context.contract.cohort.revision !== cohort.current_revision || context.contract.cohort.manifestSha256 !== cohort.manifest_sha256) reject(`${member.pkgbase} native build left current cohort scope.`);
        const reportOutputs = parseOutputReport(context.build.provenance!);
        const attestation = await currentAttestation(env, context);
        const expected = new Set(manifest.outputs);

        if (reportOutputs.length !== expected.size || reportOutputs.some((output) => !expected.has(output.packageMetadata.name) || output.pkgbase !== member.pkgbase)) reject(`${member.pkgbase} native output set differs from admitted catalog.`);

        for (const output of reportOutputs) {
          const metadata = output.packageMetadata;
          const expectedArchitecture: ArtifactArchitecture = manifest.artifactArchitecture === 'any' || (manifest.portableOutputs ?? []).includes(metadata.name) ? 'any' : target;

          if (metadata.architecture !== expectedArchitecture) reject(`${metadata.name} has a foreign output architecture for ${target}.`);
          const artifact = context.artifacts.find((item) => item.filename === output.filename && item.sha256 === output.artifactSha256);

          if (!artifact || artifact.size <= 0) reject(`${metadata.name} has no registered native output.`);
          await verifyR2Object(env, artifact!.key, artifact!.sha256, artifact!.size);
          const signed = await signedIntent(env, context.build.id, context.build.attempt, 'package', artifact!.key, artifact!.sha256, artifact!.filename, context.revision.manifest_sha256, artifact!.size);
          const packageMetadata: PackageMetadata = { ...metadata, architecture: target };

          const record: PackageRecord = {
            id: '', name: metadata.name, version: metadata.fullVersion, architecture: expectedArchitecture, artifactKey: artifact!.key,
            signatureKey: signed.signature_key, artifactSha256: artifact!.sha256, artifactSize: artifact!.size, artifactFilename: artifact!.filename,
            installedSize: metadata.installedSize, sourceDateEpoch: context.revision.source_date_epoch, license: manifest.license,
            upstreamUrl: manifest.upstreamUrl, description: manifest.description, metadata: packageMetadata,
            collection: manifest.collection, targetArchitecture: target, pkgbase: member.pkgbase, cohortId, cohortRevision: cohort.current_revision,
            buildId: context.build.id, buildAttempt: context.build.attempt, revisionId: context.revision.id, signatureSha256: signed.signature_sha256,
            attestationKey: attestation.key, attestationSha256: attestation.sha256, attestationSignatureKey: attestation.signatureKey,
            attestationSignatureSha256: attestation.signatureSha256, attestationSize: attestation.size, rebuildOn: [...manifest.rebuildOn], abiInventoryRef: abiInventoryRef(context.build.provenance!, metadata.name),
          };

          records.push(record);
        }
      }
    }
  }

  if (!records.length && !input.trustedParentReleaseId) reject('Owned repository candidate has no native outputs.');

  return records;
}

async function trustedParentRecords(env: Env, input: OwnedRepositoryPrepareInput): Promise<{ records: ArtifactRow[]; snapshots: SnapshotRow[] }> {
  if (!input.trustedParentReleaseId) return { records: [], snapshots: [] };
  const parent = releaseId(input.lane, input.trustedParentReleaseId);

  const snapshots = await query<SnapshotRow>(env.DB, `SELECT s.id,s.lane,s.release_id AS releaseId,s.architecture,s.collection,s.db_filename AS dbFilename,s.db_key AS dbKey,s.db_sha256 AS dbSha256,s.db_size AS dbSize,
      s.db_signature_key AS dbSignatureKey,s.db_signature_sha256 AS dbSignatureSha256,s.filename_map_key AS filenameMapKey,s.filename_map_sha256 AS filenameMapSha256,s.filename_map_size AS filenameMapSize,s.package_count AS packageCount,s.status,
      s.created_at, '' AS dbUrl, '' AS signatureUrl, '' AS packageBaseUrl, s.db_sha256 AS snapshotDigest
    FROM owned_repository_snapshots s JOIN owned_repository_memberships m ON m.snapshot_id=s.id
    WHERE s.lane=? AND s.release_id=? AND s.status='published' AND m.status='active' AND m.lane=? AND m.release_id=?
    ORDER BY s.collection,s.architecture`, input.lane, parent, input.lane, parent);

  if (!snapshots.length) reject('Trusted parent owned snapshots are unavailable.');
  const keys = new Set(snapshots.map((row) => `${row.collection}:${row.architecture}`));

  for (const pair of pairs(input.lane)) if (!keys.has(`${pair.collection}:${pair.architecture}`)) reject(`Trusted parent is missing ${pair.collection} for ${pair.architecture}.`);
  const records: ArtifactRow[] = [];

  for (const snapshot of snapshots) {
    await verifyR2Object(env, snapshot.dbKey, snapshot.dbSha256, snapshot.dbSize);
    await signatureBytes(env, snapshot.dbSignatureKey, snapshot.dbSignatureSha256);
    const map = await env.ARTIFACTS.get(snapshot.filenameMapKey);

    if (!map) reject('Trusted parent filename map is missing.');
    const mapBytes = new Uint8Array(await map!.arrayBuffer());

    if (mapBytes.byteLength !== snapshot.filenameMapSize || await sha256(mapBytes) !== snapshot.filenameMapSha256) reject('Trusted parent filename map digest changed.');

    const links = await query<{ artifact_id: string; filename: string; artifact_sha256: string }>(env.DB,
      'SELECT artifact_id,filename,artifact_sha256 FROM owned_repository_snapshot_packages WHERE snapshot_id=? ORDER BY ordinal', snapshot.id);

    if (links.length !== snapshot.packageCount) reject('Trusted parent snapshot package index is incomplete.');

    for (const link of links) {
      const row = await env.DB.prepare(`SELECT id,collection,target_architecture,name,version,architecture,pkgbase,filename,artifact_key,artifact_sha256,artifact_size,
          metadata_json,description,license,upstream_url,source_date_epoch,rebuild_on_json,abi_inventory_ref,signature_key,signature_sha256,
          attestation_key,attestation_sha256,attestation_size,attestation_signature_key,attestation_signature_sha256,build_id,build_attempt,revision_id,cohort_id,cohort_revision
        FROM owned_repository_artifacts WHERE id=?`).bind(link.artifact_id).first<Record<string, unknown>>();

      if (!row || row.filename !== link.filename || row.artifact_sha256 !== link.artifact_sha256 || row.collection !== snapshot.collection || row.target_architecture !== snapshot.architecture) reject('Trusted parent artifact index is inconsistent.');
      let metadata: PackageMetadata | null;

      try { metadata = parsePackageMetadata(JSON.parse(String(row.metadata_json))); } catch { metadata = null; }

      if (!metadata) reject('Trusted parent package metadata is invalid.');
      await verifyR2Object(env, String(row.artifact_key), String(row.artifact_sha256), Number(row.artifact_size));
      await signatureBytes(env, String(row.signature_key), String(row.signature_sha256));
      await verifyR2Object(env, String(row.attestation_key), String(row.attestation_sha256), Number(row.attestation_size));
      await signatureBytes(env, String(row.attestation_signature_key), String(row.attestation_signature_sha256));
      records.push({
        id: String(row.id), collection: row.collection as Collection, targetArchitecture: row.target_architecture as Architecture,
        name: String(row.name), version: String(row.version), architecture: row.architecture as ArtifactArchitecture, pkgbase: String(row.pkgbase),
        artifactKey: String(row.artifact_key), artifactSha256: String(row.artifact_sha256), artifactSize: Number(row.artifact_size), artifactFilename: String(row.filename),
        signatureKey: String(row.signature_key), signatureSha256: String(row.signature_sha256), installedSize: metadata.installedSize,
        sourceDateEpoch: Number(row.source_date_epoch), license: String(row.license), upstreamUrl: String(row.upstream_url), description: String(row.description), metadata,
        cohortId: String(row.cohort_id), cohortRevision: Number(row.cohort_revision), buildId: String(row.build_id), buildAttempt: Number(row.build_attempt), revisionId: String(row.revision_id),
        attestationKey: String(row.attestation_key), attestationSha256: String(row.attestation_sha256), attestationSize: Number(row.attestation_size),
        attestationSignatureKey: String(row.attestation_signature_key), attestationSignatureSha256: String(row.attestation_signature_sha256),
        rebuildOn: JSON.parse(String(row.rebuild_on_json)) as string[], abiInventoryRef: row.abi_inventory_ref ? String(row.abi_inventory_ref) : null, ownedArtifactId: String(row.id),
      });
    }
  }

  return { records, snapshots };
}

function mergeRecords(current: PackageRecord[], parent: ArtifactRow[]): PackageRecord[] {
  const byTargetName = new Map<string, PackageRecord | ArtifactRow>();
  const byFilename = new Map<string, PackageRecord | ArtifactRow>();
  const currentNames = new Set<string>();
  const currentFiles = new Set<string>();

  for (const record of current) {
    const nameKey = `${record.targetArchitecture}:${record.name}`;
    const fileKey = `${record.targetArchitecture}:${record.artifactFilename}`;

    if (currentNames.has(nameKey) || currentFiles.has(fileKey)) reject('Current owned cohort contains duplicate package names or filenames.');
    currentNames.add(nameKey); currentFiles.add(fileKey);
  }

  const addParent = (record: ArtifactRow) => {
    const nameKey = `${record.targetArchitecture}:${record.name}`;
    const fileKey = `${record.targetArchitecture}:${record.artifactFilename}`;

    if (byTargetName.has(nameKey) || byFilename.has(fileKey)) reject('Trusted parent contains duplicate package names or filenames.');
    byTargetName.set(nameKey, record); byFilename.set(fileKey, record);
  };

  for (const record of parent) addParent(record);

  for (const record of current) {
    const nameKey = `${record.targetArchitecture}:${record.name}`;
    const fileKey = `${record.targetArchitecture}:${record.artifactFilename}`;
    const previousName = byTargetName.get(nameKey);

    if (previousName && previousName.collection !== record.collection) reject(`Package ${record.name} changes owned repository collection.`);
    const previousFile = byFilename.get(fileKey);

    if (previousFile && previousFile.artifactSha256 !== record.artifactSha256) reject(`Package filename ${record.artifactFilename} is already bound to different bytes.`);

    for (const target of TARGETS) {
      if (record.architecture === 'any') {
        const existing = byTargetName.get(`${target}:${record.name}`);

        if (existing && existing.collection !== record.collection) reject(`Package ${record.name} changes owned repository collection.`);

        if (existing) byFilename.delete(`${target}:${existing.artifactFilename}`);
        byTargetName.delete(`${target}:${record.name}`);
        const copy = target === record.targetArchitecture ? record : { ...record, targetArchitecture: target };
        byTargetName.set(`${target}:${record.name}`, copy); byFilename.set(`${target}:${record.artifactFilename}`, copy);
      }
    }

    if (record.architecture !== 'any') {
      if (previousName) byFilename.delete(`${record.targetArchitecture}:${previousName.artifactFilename}`);
      byTargetName.set(nameKey, record); byFilename.set(fileKey, record);
    }
  }

  const result = [...byTargetName.values()];

  if (new Set(result.map((record) => `${record.targetArchitecture}:${record.name}`)).size !== result.length ||
      new Set(result.map((record) => `${record.targetArchitecture}:${record.artifactFilename}`)).size !== result.length) reject('Owned repository contains duplicate package names or filenames.');

  return result.sort((a, b) => `${a.collection}:${a.targetArchitecture}:${a.name}:${a.version}`.localeCompare(`${b.collection}:${b.targetArchitecture}:${b.name}:${b.version}`));
}

async function persistArtifact(env: Env, record: PackageRecord): Promise<ArtifactRow> {
  const existing = await env.DB.prepare('SELECT * FROM owned_repository_artifacts WHERE target_architecture=? AND filename=?')
    .bind(record.targetArchitecture, record.artifactFilename).first<Record<string, unknown>>();

  if (existing) {
    if (existing.artifact_sha256 !== record.artifactSha256 || existing.name !== record.name || existing.version !== record.version || existing.collection !== record.collection ||
        existing.target_architecture !== record.targetArchitecture || existing.architecture !== record.architecture) reject(`Immutable package filename ${record.artifactFilename} has changed.`);
    const metadata = parsePackageMetadata(JSON.parse(String(existing.metadata_json)));

    if (!metadata) reject('Stored owned package metadata is invalid.');

    return { ...record, ...recordFromStored(existing, metadata), ownedArtifactId: String(existing.id) };
  }

  const artifactId = id();
  await env.DB.prepare(`INSERT INTO owned_repository_artifacts
    (id,collection,target_architecture,name,version,architecture,pkgbase,filename,artifact_key,artifact_sha256,artifact_size,metadata_json,description,license,upstream_url,source_date_epoch,rebuild_on_json,abi_inventory_ref,
     signature_key,signature_sha256,attestation_key,attestation_sha256,attestation_size,attestation_signature_key,attestation_signature_sha256,build_id,build_attempt,revision_id,cohort_id,cohort_revision,created_at)
    VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).bind(
      artifactId, record.collection, record.targetArchitecture, record.name, record.version, record.architecture, record.pkgbase, record.artifactFilename,
      record.artifactKey, record.artifactSha256, record.artifactSize, canonicalJson(record.metadata), record.description, record.license, record.upstreamUrl, record.sourceDateEpoch,
      canonicalJson(record.rebuildOn), record.abiInventoryRef, record.signatureKey, record.signatureSha256, record.attestationKey, record.attestationSha256, record.attestationSize,
      record.attestationSignatureKey, record.attestationSignatureSha256, record.buildId, record.buildAttempt, record.revisionId, record.cohortId, record.cohortRevision, now(),
    ).run();

  return { ...record, ownedArtifactId: artifactId };
}

function recordFromStored(row: Record<string, unknown>, metadata: PackageMetadata): Omit<ArtifactRow, 'ownedArtifactId'> {
  return {
    id: String(row.id), collection: row.collection as Collection, targetArchitecture: row.target_architecture as Architecture,
    name: String(row.name), version: String(row.version), architecture: row.architecture as ArtifactArchitecture, pkgbase: String(row.pkgbase),
    artifactKey: String(row.artifact_key), artifactSha256: String(row.artifact_sha256), artifactSize: Number(row.artifact_size), artifactFilename: String(row.filename),
    signatureKey: String(row.signature_key), signatureSha256: String(row.signature_sha256), installedSize: metadata.installedSize,
    sourceDateEpoch: Number(row.source_date_epoch), license: String(row.license), upstreamUrl: String(row.upstream_url), description: String(row.description), metadata,
    cohortId: String(row.cohort_id), cohortRevision: Number(row.cohort_revision), buildId: String(row.build_id), buildAttempt: Number(row.build_attempt), revisionId: String(row.revision_id),
    attestationKey: String(row.attestation_key), attestationSha256: String(row.attestation_sha256), attestationSize: Number(row.attestation_size),
    attestationSignatureKey: String(row.attestation_signature_key), attestationSignatureSha256: String(row.attestation_signature_sha256),
    rebuildOn: JSON.parse(String(row.rebuild_on_json)) as string[], abiInventoryRef: row.abi_inventory_ref ? String(row.abi_inventory_ref) : null,
  };
}

function pairs(lane: OwnedRepositoryLane): Array<{ collection: Collection; architecture: Architecture }> {
  const names: Collection[] = lane === 'system' ? ['core', 'extra', 'multilib', 'omarchy'] : ['omapkg'];

  return names.flatMap((name) => TARGETS.filter((architecture) => name !== 'multilib' || architecture === 'x86_64').map((architecture) => ({ collection: name, architecture })));
}

function publicPackageRef(env: Env, lane: OwnedRepositoryLane, release: string, record: ArtifactRow): OwnedRepositoryPackageRef {
  const base = baseUrl(env, lane, release, record.collection, record.targetArchitecture);

  return {
    releaseId: record.ownedArtifactId,
    name: record.name,
    version: record.version,
    architecture: record.architecture,
    collection: record.collection,
    targetArchitecture: record.targetArchitecture,
    artifactUrl: `${base}${encoded(record.artifactFilename)}`,
    artifactSha256: record.artifactSha256,
    artifactSignatureUrl: `${base}${encoded(record.artifactFilename)}.sig`,
    artifactSignatureSha256: record.signatureSha256,
    cohortId: record.cohortId,
    evidence: [{ url: `${env.PUBLIC_ORIGIN.replace(/\/$/, '')}/repo/owned-attestations/${encoded(record.buildId)}/${record.buildAttempt}.json`, sha256: record.attestationSha256, size: record.attestationSize }],
    ownedArtifactId: record.ownedArtifactId,
  };
}

async function snapshotRef(env: Env, row: SnapshotRow): Promise<OwnedRepositorySnapshotRef> {
  const base = baseUrl(env, row.lane, row.releaseId, row.collection, row.architecture);

  return { ...row, snapshotDigest: row.dbSha256, dbUrl: `${base}${row.dbFilename}`, signatureUrl: `${base}${row.dbFilename}.sig`, packageBaseUrl: base };
}

async function storeSnapshot(env: Env, input: OwnedRepositoryPrepareInput, pair: { collection: Collection; architecture: Architecture }, records: ArtifactRow[], parent: SnapshotRow | undefined, anchor: PackageRecord | ArtifactRow): Promise<SnapshotRow> {
  const packageRows = records.filter((record) => record.collection === pair.collection && record.targetArchitecture === pair.architecture);
  const dbFilename = `${pair.collection}.db`;
  const dbKey = objectKey(input.lane, input.releaseId, pair.collection, pair.architecture, dbFilename);
  const database = await repositoryDatabaseForPackages(env, packageRows);
  const dbSha256 = await sha256(database);
  await immutableBytes(env, dbKey, database, dbSha256, 'application/gzip');
  const signatureKey = `${dbKey}.sig`;
  let dbSignatureKey = signatureKey;
  let dbSignatureSha256: string;

  if (parent && parent.dbSha256 === dbSha256) {
    const parentSignature = await env.ARTIFACTS.get(parent.dbSignatureKey);

    if (!parentSignature) reject('Trusted parent database signature is missing.');
    const bytes = new Uint8Array(await parentSignature!.arrayBuffer());
    dbSignatureSha256 = await sha256(bytes);
    await immutableBytes(env, signatureKey, bytes, dbSignatureSha256, 'application/octet-stream');
  } else {
    const signed = await signingRequest(env, {
      buildId: anchor.buildId, buildAttempt: anchor.buildAttempt, revisionId: anchor.revisionId,
      manifestSha256: (await env.DB.prepare('SELECT manifest_sha256 FROM revisions WHERE id=?').bind(anchor.revisionId).first<{ manifest_sha256: string }>())?.manifest_sha256 ?? '',
      objectKey: dbKey, objectKind: 'database', artifactSha256: dbSha256, artifactSize: database.byteLength, artifactFilename: dbFilename,
    });

    dbSignatureKey = signed.signatureKey;
    dbSignatureSha256 = signed.signatureSha256;
  }

  const base = baseUrl(env, input.lane, input.releaseId, pair.collection, pair.architecture);

  const mapValue = {
    schemaVersion: 1, lane: input.lane, releaseId: input.releaseId, collection: pair.collection, architecture: pair.architecture,
    packageCount: packageRows.length,
    packages: packageRows.map((record) => ({ id: record.ownedArtifactId, name: record.name, version: record.version, architecture: record.architecture,
      filename: record.artifactFilename, artifactSha256: record.artifactSha256, artifactSize: record.artifactSize,
      artifactUrl: `${base}${encoded(record.artifactFilename)}`, artifactSignatureSha256: record.signatureSha256,
      artifactSignatureUrl: `${base}${encoded(record.artifactFilename)}.sig`, attestationSha256: record.attestationSha256 })).sort((a, b) => a.filename.localeCompare(b.filename)),
  };

  const mapBytes = new TextEncoder().encode(canonicalJson(mapValue));
  const filenameMapKey = mapKey(input.lane, input.releaseId, pair.collection, pair.architecture);
  const filenameMapSha256 = await sha256(mapBytes);
  await immutableBytes(env, filenameMapKey, mapBytes, filenameMapSha256, 'application/json');
  const snapshotId = id();
  await env.DB.prepare(`INSERT INTO owned_repository_snapshots
    (id,lane,release_id,architecture,collection,db_filename,db_key,db_sha256,db_size,db_signature_key,db_signature_sha256,filename_map_key,filename_map_sha256,filename_map_size,package_count,status,created_at)
    VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).bind(snapshotId,input.lane,input.releaseId,pair.architecture,pair.collection,dbFilename,dbKey,dbSha256,database.byteLength,dbSignatureKey,dbSignatureSha256,filenameMapKey,filenameMapSha256,mapBytes.byteLength,packageRows.length,'prepared',now()).run();

  for (const [ordinal, record] of packageRows.entries()) await env.DB.prepare(`INSERT INTO owned_repository_snapshot_packages(snapshot_id,artifact_id,ordinal,filename,artifact_sha256) VALUES(?,?,?,?,?)`)
    .bind(snapshotId, record.ownedArtifactId, ordinal, record.artifactFilename, record.artifactSha256).run();

  return {
    id: snapshotId, lane: input.lane, releaseId: input.releaseId, architecture: pair.architecture, collection: pair.collection, dbFilename, dbKey, dbSha256,
    dbSize: database.byteLength, dbSignatureKey, dbSignatureSha256, filenameMapKey, filenameMapSha256, filenameMapSize: mapBytes.byteLength,
    packageCount: packageRows.length, status: 'prepared', created_at: now(), dbUrl: '', signatureUrl: '', packageBaseUrl: '', snapshotDigest: dbSha256,
  };
}

async function existingPreparation(env: Env, lane: OwnedRepositoryLane, release: string): Promise<OwnedRepositoryPreparation | null> {
  const universe = await env.DB.prepare('SELECT id,lane,release_id,root_sha256,package_count FROM owned_repository_universes WHERE lane=? AND release_id=? AND status IN (\'prepared\',\'published\')')
    .bind(lane, release).first<{ id: string; lane: OwnedRepositoryLane; release_id: string; root_sha256: string; package_count: number }>();

  if (!universe) return null;

  const rows = await query<SnapshotRow>(env.DB, `SELECT s.id,s.lane,s.release_id AS releaseId,s.architecture,s.collection,s.db_filename AS dbFilename,s.db_key AS dbKey,s.db_sha256 AS dbSha256,s.db_size AS dbSize,s.db_signature_key AS dbSignatureKey,s.db_signature_sha256 AS dbSignatureSha256,
      s.filename_map_key AS filenameMapKey,s.filename_map_sha256 AS filenameMapSha256,s.filename_map_size AS filenameMapSize,s.package_count AS packageCount,s.status,s.created_at,'' AS dbUrl,'' AS signatureUrl,'' AS packageBaseUrl,s.db_sha256 AS snapshotDigest
    FROM owned_repository_snapshots s WHERE s.lane=? AND s.release_id=? ORDER BY s.collection,s.architecture`, lane, release);

  const chunks = await query<{ object_key: string; object_sha256: string; object_size: number; index: number; count: number; package_count: number }>(env.DB,
    `SELECT object_key,object_sha256,object_size,chunk_index AS index,chunk_count AS count,package_count FROM owned_repository_package_chunks
     WHERE lane=? AND release_id=? AND status IN ('prepared','published') ORDER BY chunk_index`, lane, release);

  if (!rows.length || !chunks.length) reject('Owned repository preparation is incomplete.');

  return { lane, releaseId: release, snapshots: await Promise.all(rows.map((row) => snapshotRef(env, row))), packageChunks: chunks.map((row) => ({
    key: row.object_key, url: `${env.PUBLIC_ORIGIN.replace(/\/$/, '')}/repo/${lane === 'system' ? 'releases/' : 'opr/'}${encoded(release)}/package-chunks/${row.index}.json`,
    sha256: row.object_sha256, size: row.object_size, index: row.index, count: row.count, packageCount: row.package_count,
  })), packageCount: universe.package_count, universeId: universe.id, universeSha256: universe.root_sha256 };
}

function packageRefIdentity(record: ArtifactRow): string {
  return `${record.targetArchitecture}:${record.collection}:${record.name}:${record.version}:${record.architecture}:${record.artifactFilename}`;
}

async function persistUniverse(env: Env, input: OwnedRepositoryPrepareInput, records: ArtifactRow[]): Promise<{ id: string; rootSha256: string; packageRefs: OwnedRepositoryPackageRef[] }> {
  const ordered = [...records].sort((a, b) => packageRefIdentity(a).localeCompare(packageRefIdentity(b)));
  const identities = new Set<string>();
  const filenames = new Set<string>();

  for (const record of ordered) {
    const identity = `${record.targetArchitecture}:${record.name}`;
    const filename = `${record.targetArchitecture}:${record.artifactFilename}`;

    if (identities.has(identity) || filenames.has(filename)) reject('Owned repository contains duplicate package names or files.');
    identities.add(identity); filenames.add(filename);
  }

  const universeValue = ordered.map((record) => ({ id: record.ownedArtifactId, collection: record.collection, targetArchitecture: record.targetArchitecture,
    pkgbase: record.pkgbase, name: record.name, version: record.version, architecture: record.architecture, artifactSha256: record.artifactSha256,
    artifactSize: record.artifactSize, depends: record.metadata.depends, provides: record.metadata.provides, conflicts: record.metadata.conflicts, replaces: record.metadata.replaces,
    rebuildOn: record.rebuildOn, buildId: record.buildId, attempt: record.buildAttempt, abiInventoryRef: record.abiInventoryRef, cohortId: record.cohortId, cohortRevision: record.cohortRevision }));

  const rootSha256 = await sha256(canonicalJson(universeValue));
  const universeId = id();
  await env.DB.prepare('INSERT INTO owned_repository_universes(id,lane,release_id,root_sha256,package_count,status,created_at) VALUES(?,?,?,?,?,\'prepared\',?)')
    .bind(universeId, input.lane, input.releaseId, rootSha256, ordered.length, now()).run();

  for (const [ordinal, record] of ordered.entries()) await env.DB.prepare(`INSERT INTO owned_repository_universe_packages(universe_id,ordinal,artifact_id,collection,target_architecture) VALUES(?,?,?,?,?)`)
    .bind(universeId, ordinal, record.ownedArtifactId, record.collection, record.targetArchitecture).run();

  return { id: universeId, rootSha256, packageRefs: ordered.map((record) => publicPackageRef(env, input.lane, input.releaseId, record)) };
}

async function persistChunks(env: Env, input: OwnedRepositoryPrepareInput, packageRefs: OwnedRepositoryPackageRef[]): Promise<OwnedRepositoryPackageChunkRef[]> {
  if (!packageRefs.length) reject('Owned repository package universe is empty.');
  const chunks: OwnedRepositoryPackageRef[][] = [];
  let current: OwnedRepositoryPackageRef[] = [];

  for (const item of packageRefs) {
    const next = [...current, item];
    const bytes = new TextEncoder().encode(canonicalJson({ schemaVersion: 1, index: chunks.length, count: MAX_CHUNKS, packages: next }));

    if (bytes.byteLength > MAX_CHUNK_BYTES && !current.length) reject('Owned repository package record exceeds chunk limit.');

    if (bytes.byteLength > MAX_CHUNK_BYTES) { chunks.push(current); current = [item]; } else current = next;

    if (chunks.length >= MAX_CHUNKS) reject('Owned repository package chunk limit exceeded.');
  }

  if (current.length) chunks.push(current);
  const refs: OwnedRepositoryPackageChunkRef[] = [];

  for (let index = 0; index < chunks.length; index += 1) {
    const value = { schemaVersion: 1, index, count: chunks.length, packages: chunks[index] };
    const bytes = new TextEncoder().encode(canonicalJson(value));

    if (bytes.byteLength > MAX_CHUNK_BYTES) reject('Owned repository package chunk exceeds size limit.');
    const objectSha256 = await sha256(bytes);
    const key = chunkKey(input.lane, input.releaseId, index);
    await immutableBytes(env, key, bytes, objectSha256, 'application/json');
    await env.DB.prepare(`INSERT INTO owned_repository_package_chunks(id,lane,release_id,chunk_index,chunk_count,package_count,object_key,object_sha256,object_size,status,created_at)
      VALUES(?,?,?,?,?,?,?,?,?,'prepared',?)`).bind(id(), input.lane, input.releaseId, index, chunks.length, chunks[index].length, key, objectSha256, bytes.byteLength, now()).run();
    refs.push({ key, url: `${env.PUBLIC_ORIGIN.replace(/\/$/, '')}/repo/${input.lane === 'system' ? 'releases/' : 'opr/'}${encoded(input.releaseId)}/package-chunks/${index}.json`, sha256: objectSha256, size: bytes.byteLength, index, count: chunks.length, packageCount: chunks[index].length });
  }

  return refs;
}

export async function prepareOwnedRepositorySnapshots(env: Env, rawInput: OwnedRepositoryPrepareInput): Promise<OwnedRepositoryPreparation> {
  if (!rawInput || typeof rawInput !== 'object') reject('Owned repository preparation input is required.', 400);

  if (rawInput.lane !== 'system' && rawInput.lane !== 'opr') reject('Owned repository lane is invalid.', 400);
  const input: OwnedRepositoryPrepareInput = { lane: rawInput.lane, releaseId: releaseId(rawInput.lane, rawInput.releaseId), cohortIds: rawInput.cohortIds, trustedParentReleaseId: rawInput.trustedParentReleaseId ?? null };

  if (!Array.isArray(input.cohortIds) || input.cohortIds.length > 512 || new Set(input.cohortIds).size !== input.cohortIds.length) reject('Owned cohort selection is invalid.', 400);
  const existing = await existingPreparation(env, input.lane, input.releaseId);

  if (existing) return existing;
  const current = await currentPackageRecords(env, input);
  const trusted = await trustedParentRecords(env, input);
  const merged = mergeRecords(current, trusted.records);

  if (merged.length > MAX_PACKAGES) reject('Owned repository package limit exceeded.');
  const records: ArtifactRow[] = [];

  for (const record of merged) records.push(await persistArtifact(env, record));
  const anchor = current[0] ?? records[0];

  if (!anchor) reject('Owned repository has no signing context.');
  const parentByPair = new Map(trusted.snapshots.map((row) => [`${row.collection}:${row.architecture}`, row]));
  const snapshots: SnapshotRow[] = [];

  for (const pair of pairs(input.lane)) snapshots.push(await storeSnapshot(env, input, pair, records, parentByPair.get(`${pair.collection}:${pair.architecture}`), anchor));
  const universe = await persistUniverse(env, input, records);
  const packageChunks = await persistChunks(env, input, universe.packageRefs);

  return { lane: input.lane, releaseId: input.releaseId, snapshots: await Promise.all(snapshots.map((row) => snapshotRef(env, row))), packageChunks, packageCount: universe.packageRefs.length, universeId: universe.id, universeSha256: universe.rootSha256 };
}

export function ownedRepositoryReleaseRepositories(preparation: OwnedRepositoryPreparation): OwnedRepositoryReleaseRepository[] {
  return preparation.snapshots.map((snapshot) => ({ name: snapshot.collection, architecture: snapshot.architecture, snapshotDigest: snapshot.dbSha256,
    dbUrl: snapshot.dbUrl, signatureUrl: snapshot.signatureUrl, packageBaseUrl: snapshot.packageBaseUrl,
    dbKey: snapshot.dbKey, signatureKey: snapshot.dbSignatureKey, signatureSha256: snapshot.dbSignatureSha256,
  })).sort((a, b) => collections.indexOf(a.name) - collections.indexOf(b.name) || a.architecture.localeCompare(b.architecture));
}

function universePackage(row: Record<string, unknown>, metadata: PackageMetadata): OwnedRepositoryUniversePackage {
  return {
    ownedArtifactId: String(row.id), collection: row.collection as Collection, targetArchitecture: row.target_architecture as Architecture,
    pkgbase: String(row.pkgbase), name: String(row.name), version: String(row.version), architecture: row.architecture as ArtifactArchitecture,
    artifactArch: row.architecture as ArtifactArchitecture,
    artifactSha256: String(row.artifact_sha256), artifactSize: Number(row.artifact_size), depends: metadata.depends, provides: metadata.provides,
    conflicts: metadata.conflicts, replaces: metadata.replaces, rebuildOn: JSON.parse(String(row.rebuild_on_json)) as string[], buildId: String(row.build_id),
    attempt: Number(row.build_attempt), abiInventoryRef: row.abi_inventory_ref ? String(row.abi_inventory_ref) : null, cohortId: String(row.cohort_id), cohortRevision: Number(row.cohort_revision),
  };
}

export async function ownedRepositoryUniverse(env: Env, input: { lane: OwnedRepositoryLane; releaseId: string }): Promise<OwnedRepositoryUniverse> {
  const release = releaseId(input.lane, input.releaseId);

  const row = await env.DB.prepare('SELECT id,lane,release_id,root_sha256,package_count FROM owned_repository_universes WHERE lane=? AND release_id=? AND status IN (\'prepared\',\'published\')')
    .bind(input.lane, release).first<{ id: string; lane: OwnedRepositoryLane; release_id: string; root_sha256: string; package_count: number }>();

  if (!row) reject('Owned repository universe is unavailable.', 404);

  return { id: row!.id, lane: row!.lane, releaseId: row!.release_id, rootSha256: row!.root_sha256, packageCount: row!.package_count };
}

export async function* ownedRepositoryUniversePages(env: Env, input: { lane: OwnedRepositoryLane; releaseId: string }, pageSize = 256): AsyncGenerator<OwnedRepositoryUniversePackage[]> {
  if (!Number.isSafeInteger(pageSize) || pageSize < 1 || pageSize > 1_024) reject('Owned repository universe page is invalid.', 400);
  const universe = await ownedRepositoryUniverse(env, input);

  for (let offset = 0; offset < universe.packageCount; offset += pageSize) {
    const rows = await query<Record<string, unknown>>(env.DB, `SELECT a.id,a.collection,a.target_architecture,a.name,a.version,a.architecture,a.pkgbase,a.artifact_sha256,a.artifact_size,a.metadata_json,a.rebuild_on_json,a.abi_inventory_ref,
        a.build_id,a.build_attempt,a.cohort_id,a.cohort_revision
      FROM owned_repository_universe_packages u JOIN owned_repository_artifacts a ON a.id=u.artifact_id
      WHERE u.universe_id=? ORDER BY u.ordinal LIMIT ? OFFSET ?`, universe.id, pageSize, offset);

    if (!rows.length || rows.length > pageSize) reject('Owned repository universe page is incomplete.');
    yield rows.map((row) => {
      let metadata: PackageMetadata | null;

      try { metadata = parsePackageMetadata(JSON.parse(String(row.metadata_json))); } catch { metadata = null; }

      if (!metadata) reject('Owned repository universe metadata is invalid.');

      return universePackage(row, metadata);
    });
  }
}

async function verifySnapshotObjects(env: Env, row: SnapshotRow): Promise<void> {
  await verifyR2Object(env, row.dbKey, row.dbSha256, row.dbSize);
  await signatureBytes(env, row.dbSignatureKey, row.dbSignatureSha256);
  const map = await env.ARTIFACTS.get(row.filenameMapKey);

  if (!map) reject('Owned repository filename map is missing.');
  const mapBytes = new Uint8Array(await map!.arrayBuffer());

  if (mapBytes.byteLength !== row.filenameMapSize || await sha256(mapBytes) !== row.filenameMapSha256) reject('Owned repository filename map digest changed.');
  const links = await query<{ artifact_id: string; filename: string; artifact_sha256: string }>(env.DB, 'SELECT artifact_id,filename,artifact_sha256 FROM owned_repository_snapshot_packages WHERE snapshot_id=? ORDER BY ordinal', row.id);

  if (links.length !== row.packageCount) reject('Owned repository snapshot package index is incomplete.');

  for (const link of links) {
    const artifact = await env.DB.prepare('SELECT artifact_key,artifact_sha256,artifact_size,signature_key,signature_sha256,attestation_key,attestation_sha256,attestation_size,attestation_signature_key,attestation_signature_sha256 FROM owned_repository_artifacts WHERE id=?')
      .bind(link.artifact_id).first<{ artifact_key: string; artifact_sha256: string; artifact_size: number; signature_key: string; signature_sha256: string; attestation_key: string; attestation_sha256: string; attestation_size: number; attestation_signature_key: string; attestation_signature_sha256: string }>();

    if (!artifact || artifact.artifact_sha256 !== link.artifact_sha256) reject('Owned repository artifact index changed.');
    await verifyR2Object(env, artifact!.artifact_key, artifact!.artifact_sha256, artifact!.artifact_size);
    await signatureBytes(env, artifact!.signature_key, artifact!.signature_sha256);
    await verifyR2Object(env, artifact!.attestation_key, artifact!.attestation_sha256, artifact!.attestation_size);
    await signatureBytes(env, artifact!.attestation_signature_key, artifact!.attestation_signature_sha256);
  }
}

export async function publishOwnedRepositorySnapshots(env: Env, input: { lane: OwnedRepositoryLane; releaseId: string; channel: OwnedRepositoryChannel; snapshotIds: string[] }): Promise<void> {
  if (input.lane !== 'system' && input.lane !== 'opr') reject('Owned repository lane is invalid.', 400);
  const release = releaseId(input.lane, input.releaseId);

  if (!Array.isArray(input.snapshotIds) || !input.snapshotIds.length || new Set(input.snapshotIds).size !== input.snapshotIds.length) reject('Owned snapshot selection is invalid.', 400);

  const rows = await query<SnapshotRow>(env.DB, `SELECT id,lane,release_id AS releaseId,architecture,collection,db_filename AS dbFilename,db_key AS dbKey,db_sha256 AS dbSha256,db_size AS dbSize,
      db_signature_key AS dbSignatureKey,db_signature_sha256 AS dbSignatureSha256,filename_map_key AS filenameMapKey,filename_map_sha256 AS filenameMapSha256,filename_map_size AS filenameMapSize,
      package_count AS packageCount,status,created_at,'' AS dbUrl,'' AS signatureUrl,'' AS packageBaseUrl,db_sha256 AS snapshotDigest FROM owned_repository_snapshots
      WHERE lane=? AND release_id=? AND id IN (SELECT value FROM json_each(?))`, input.lane, release, JSON.stringify(input.snapshotIds));

  if (rows.length !== input.snapshotIds.length) reject('Owned snapshot selection changed.');
  const selectedPairs = new Set(rows.map((row) => `${row.collection}:${row.architecture}`));

  if (selectedPairs.size !== pairs(input.lane).length || pairs(input.lane).some((pair) => !selectedPairs.has(`${pair.collection}:${pair.architecture}`))) reject('All named owned repository snapshots are required before publication.');

  for (const row of rows) if (row.status === 'prepared') await verifySnapshotObjects(env, row);
  const universe = await ownedRepositoryUniverse(env, { lane: input.lane, releaseId: release });

  const chunks = await query<{ id: string; object_key: string; object_sha256: string; object_size: number; status: string }>(env.DB,
    `SELECT id,object_key,object_sha256,object_size,status FROM owned_repository_package_chunks WHERE lane=? AND release_id=?`, input.lane, release);

  if (!chunks.length) reject('Owned repository package chunks are unavailable.');

  for (const chunk of chunks) { await verifyR2Object(env, chunk.object_key, chunk.object_sha256, chunk.object_size); }

  const timestamp = now();
  const statements: D1PreparedStatement[] = [];

  for (const row of rows) {
    if (row.status === 'prepared') statements.push(env.DB.prepare("UPDATE owned_repository_snapshots SET status='published' WHERE id=? AND status='prepared'").bind(row.id));
    statements.push(env.DB.prepare('INSERT OR IGNORE INTO owned_repository_memberships(id,snapshot_id,lane,release_id,channel,status,created_at) VALUES(?,?,?,?,?,\'active\',?)')
      .bind(id(), row.id, input.lane, release, input.channel, timestamp));
  }

  for (const chunk of chunks) if (chunk.status === 'prepared') statements.push(env.DB.prepare("UPDATE owned_repository_package_chunks SET status='published' WHERE id=? AND status='prepared'").bind(chunk.id));
  const universeRow = await env.DB.prepare('SELECT status FROM owned_repository_universes WHERE id=?').bind(universe.id).first<{ status: string }>();

  if (universeRow?.status === 'prepared') statements.push(env.DB.prepare("UPDATE owned_repository_universes SET status='published' WHERE id=? AND status='prepared'").bind(universe.id));
  await env.DB.batch(statements);
}

function decode(value: string): string | null {
  try { const decoded = decodeURIComponent(value);

 return decoded && decoded !== '.' && decoded !== '..' && !decoded.includes('\u0000') && !decoded.includes('\r') && !decoded.includes('\n') ? decoded : null; } catch { return null; }
}

async function responseObject(env: Env, key: string, path: string, type: string): Promise<Response | null> {
  safeKey(key);
  const object = await env.ARTIFACTS.get(key);

  if (!object) return null;
  const headers = new Headers({ 'Content-Type': type, 'Cache-Control': 'public, max-age=31536000, immutable', ETag: object.httpEtag });

  if (object.size >= 0) headers.set('Content-Length', String(object.size));

  return new Response(object.body, { headers });
}

export async function serveOwnedRepositoryPath(env: Env, rawPath: string): Promise<Response | null> {
  const parts = rawPath.split('/').filter(Boolean).map(decode);

  if (parts.some((part) => part === null)) return null;
  const values = parts as string[];

  if (values.length === 3 && values[0] === 'owned-attestations' && /^\d+$/.test(values[2].replace(/\.json$/, ''))) {
    const attestation = await env.DB.prepare(`SELECT a.attestation_key FROM owned_repository_artifacts a
      JOIN owned_repository_snapshot_packages p ON p.artifact_id=a.id JOIN owned_repository_snapshots s ON s.id=p.snapshot_id
      JOIN owned_repository_memberships m ON m.snapshot_id=s.id
      WHERE a.build_id=? AND a.build_attempt=? AND s.status='published' AND m.status='active' LIMIT 1`)
      .bind(values[1], Number(values[2].replace(/\.json$/, ''))).first<{ attestation_key: string }>();

    return attestation ? responseObject(env, attestation.attestation_key, values.join('/'), 'application/json') : null;
  }

  const offset = values[0] === 'releases' ? 2 : values[0] === 'opr' ? 2 : -1;

  if (offset < 0 || values.length < offset + 1) return null;
  const lane: OwnedRepositoryLane = values[0] === 'releases' ? 'system' : 'opr';
  const release = values[1];

  if (!release || !RELEASE_ID.test(release)) return null;

  if (values.length === 4 && values[2] === 'package-chunks' && /^\d+\.json$/.test(values[3])) {
    const chunk = await env.DB.prepare(`SELECT object_key FROM owned_repository_package_chunks c JOIN owned_repository_memberships m ON m.lane=c.lane AND m.release_id=c.release_id
      WHERE c.lane=? AND c.release_id=? AND c.chunk_index=? AND c.status='published' AND m.status='active' LIMIT 1`).bind(lane, release, Number(values[3].slice(0, -5))).first<{ object_key: string }>();

    return chunk ? responseObject(env, chunk.object_key, values.join('/'), 'application/json') : null;
  }

  if (values.length !== 5 || !collections.includes(values[2] as Collection) || !TARGETS.includes(values[3] as Architecture)) return null;
  const collectionValue = values[2] as Collection; const architecture = values[3] as Architecture;
  const requested = values[4]; const signature = requested.endsWith('.sig'); const filename = signature ? requested.slice(0, -4) : requested;

  const snapshot = await env.DB.prepare(`SELECT s.* FROM owned_repository_snapshots s JOIN owned_repository_memberships m ON m.snapshot_id=s.id
    WHERE s.lane=? AND s.release_id=? AND s.collection=? AND s.architecture=? AND s.status='published' AND m.status='active' LIMIT 1`)
    .bind(lane, release, collectionValue, architecture).first<Record<string, unknown>>();

  if (!snapshot) return null;

  if (filename === `${collectionValue}.db` || filename === `${collectionValue}.db.tar.gz`) {
    return responseObject(env, signature ? String(snapshot.db_signature_key) : String(snapshot.db_key), requested, signature ? 'application/octet-stream' : 'application/gzip');
  }

  if (filename === 'filename-map.json') return responseObject(env, String(snapshot.filename_map_key), requested, 'application/json');

  if (!PACKAGE_FILENAME.test(filename)) return null;

  const artifact = await env.DB.prepare(`SELECT a.artifact_key,a.signature_key FROM owned_repository_snapshot_packages p JOIN owned_repository_artifacts a ON a.id=p.artifact_id
    WHERE p.snapshot_id=? AND p.filename=? LIMIT 1`).bind(snapshot.id, filename).first<{ artifact_key: string; signature_key: string }>();

  return artifact ? responseObject(env, signature ? artifact.signature_key : artifact.artifact_key, requested, signature ? 'application/octet-stream' : 'application/octet-stream') : null;
}
