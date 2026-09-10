import type { Env } from './env';
import type { Actor, Architecture } from '../model';
import { canonicalJson } from '../canonical-json';
import {
  DISTRIBUTION_RELEASE_POLICY,
  DISTRIBUTION_RELEASE_SCHEMA_VERSION,
  OPR_RELEASE_CHANNELS,
  RELEASE_ARCHITECTURES,
  RELEASE_KINDS,
  RELEASE_REPOSITORIES,
  SYSTEM_RELEASE_CHANNELS,
  type DistributionReleaseKind,
  type ReleaseArchitecture,
  type ReleaseChangelogRef,
  type ReleaseManifest,
  type ReleaseManifestRef,
  type ReleaseObjectRef,
  type ReleasePackageChunkRef,
  type ReleaseRepositoryRef,
  type ReleaseRepository,
  type DistributionReleaseChannel,
  type SystemReleaseChannel,
  releaseManifestBytes,
  releaseManifestDigest,
} from '../distribution-release';
import { parseSystemVersion } from '../distribution';
import { audit, id, now, query, sha256 } from './db';
import { PolicyError } from './policy';
import { humanMaintainer } from './catalog-ownership';
import { getCohort, releaseAuthority } from './cohorts';
import { qualifyCohort } from './cohort-qualification';
import { hasPassingQualification } from './native-qualification';
import { immutableBytes, safeKey, SHA256, verifyR2Object } from './release-storage';
import { requestManifestSignature } from './distribution-release-signing';

const ID = /^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/;
const URL_RE = /^https:\/\//;
const MAX_CHUNK_BYTES = 1_048_576;
const MAX_CHUNKS = 100_000;
const MAX_TEXT = 4_096;
const DEFAULT_SNAPSHOT_EXPIRY_SECONDS = 365 * 24 * 60 * 60;
const DEFAULT_TRANSACTION_EXPIRY_SECONDS = 24 * 60 * 60;

type CandidateKind = 'system' | 'opr';

function validChannel(kind: CandidateKind, channel: unknown): channel is DistributionReleaseChannel {
  return (kind === 'system' && SYSTEM_RELEASE_CHANNELS.includes(channel as SystemReleaseChannel)) ||
    (kind === 'opr' && OPR_RELEASE_CHANNELS.includes(channel as typeof OPR_RELEASE_CHANNELS[number]));
}

function repositorySort(left: Pick<ReleaseRepositoryRef, 'name' | 'architecture'>, right: Pick<ReleaseRepositoryRef, 'name' | 'architecture'>): number {
  const name = RELEASE_REPOSITORIES.indexOf(left.name) - RELEASE_REPOSITORIES.indexOf(right.name);
  return name || left.architecture.localeCompare(right.architecture);
}

export interface DistributionObjectInput extends ReleaseObjectRef {
  key: string;
}

export interface DistributionRepositoryInput extends ReleaseRepositoryRef {
  dbKey: string;
  signatureKey: string;
  signatureSha256: string;
}

export interface DistributionCandidateInput {
  kind: CandidateKind;
  channel: DistributionReleaseChannel;
  releaseId: string;
  sequence?: number;
  architectures: ReleaseArchitecture[];
  parent?: { digest: string | null; sequence: number | null } | null;
  sourceRefs?: Array<{ name: string; ref: string; digest: string }>;
  repositories: DistributionRepositoryInput[];
  packageChunks: DistributionObjectInput[];
  packageCount: number;
  compatibility?: {
    systemManifestDigest?: string | null;
    systemSnapshotDigests?: string[];
    oprManifestDigest?: string | null;
  };
  changelog: DistributionObjectInput;
  baseOwnerAreas?: string[];
  expiresAt?: number | null;
  recovery?: { fromDigest?: string | null; constraints?: string[]; authorized?: boolean; reason?: string | null };
}

export interface DistributionApprovalInput {
  candidateId: string;
  kind: 'release' | 'base';
  area?: string | null;
  reason: string;
}

interface CandidateRow {
  id: string;
  kind: CandidateKind | 'resolved-transaction';
  lane: 'system' | 'opr' | 'transaction';
  channel: DistributionReleaseChannel;
  release_id: string;
  sequence: number;
  parent_digest: string | null;
  parent_sequence: number | null;
  manifest_json: string;
  manifest_sha256: string;
  manifest_key: string;
  manifest_size: number;
  signature_key: string | null;
  signature_sha256: string | null;
  signature_intent_id: string | null;
  changelog_key: string;
  changelog_sha256: string;
  status: 'candidate' | 'signed' | 'active' | 'superseded' | 'held';
  created_by: string;
  created_at: number;
  activated_at: number | null;
}

interface ApprovalRow {
  kind: 'release' | 'base';
  actor: string;
  area: string | null;
  reason: string;
}

export interface OwnedPackageRow {
  id: string; name: string; version: string; architecture: string;
  artifact_key: string | null; signature_key: string | null; artifact_sha256: string | null; artifact_size: number | null;
  artifact_filename?: string | null; filename?: string; collection?: string; target_architecture?: ReleaseArchitecture; cohort_id?: string; cohort_revision?: number; pkgbase?: string; revision_id?: string;
  attestation_key?: string; attestation_sha256?: string; attestation_size?: number; attestation_signature_key?: string; attestation_signature_sha256?: string;
}

export interface OmarchyPairBinding {
  commit: string;
  packageNames: string[];
}

function reject(message: string, status = 409): never {
  throw new PolicyError(status, message);
}

function configuredLifetime(env: Env, name: 'DISTRIBUTION_SNAPSHOT_EXPIRY_SECONDS' | 'DISTRIBUTION_TRANSACTION_EXPIRY_SECONDS', fallback: number): number {
  const value = Number((env as Env & Record<string, string | undefined>)[name] ?? fallback);
  if (!Number.isSafeInteger(value) || value < 60 * 60) reject(`${name} must be at least one hour.`, 503);
  return value;
}

function text(value: unknown, label: string, maximum = MAX_TEXT): string {
  if (typeof value !== 'string' || !value.trim() || value.length > maximum || /[\u0000-\u001f\u007f]/.test(value)) reject(`${label} is invalid.`, 400);
  return value.trim();
}

function digest(value: unknown, label: string): string {
  if (typeof value !== 'string' || !SHA256.test(value)) reject(`${label} must be a SHA-256 digest.`, 400);
  return value;
}

function positiveInteger(value: unknown, label: string, maximum = Number.MAX_SAFE_INTEGER): number {
  if (!Number.isSafeInteger(value) || (value as number) < 1 || (value as number) > maximum) reject(`${label} is invalid.`, 400);
  return value as number;
}

function safeUrl(value: unknown, label: string): string {
  const url = text(value, label, 2_048);
  try {
    const parsed = new URL(url);
    if (!URL_RE.test(url) || parsed.username || parsed.password || parsed.hash) throw new Error();
  } catch { reject(`${label} must be an HTTPS URL without credentials or fragments.`, 400); }
  return url;
}

function safeRef(value: unknown, label: string, sizeMaximum = MAX_CHUNK_BYTES): DistributionObjectInput {
  if (!value || typeof value !== 'object' || Array.isArray(value)) reject(`${label} is invalid.`, 400);
  const item = value as Record<string, unknown>;
  return {
    key: safeKey(text(item.key, `${label} storage key`, 1_024)),
    url: safeUrl(item.url, `${label} URL`),
    sha256: digest(item.sha256, `${label} digest`),
    size: positiveInteger(item.size, `${label} size`, sizeMaximum),
  };
}

function objectRef(input: DistributionObjectInput): ReleaseObjectRef {
  return { url: input.url, sha256: input.sha256, size: input.size };
}

function assertArchitectureList(value: unknown): ReleaseArchitecture[] {
  if (!Array.isArray(value) || !value.length || value.length > RELEASE_ARCHITECTURES.length ||
      value.some((item) => !RELEASE_ARCHITECTURES.includes(item as ReleaseArchitecture)) || new Set(value).size !== value.length) {
    reject('Both required release architectures must be selected.', 400);
  }
  return [...value].sort() as ReleaseArchitecture[];
}

function assertReleaseId(kind: CandidateKind, value: unknown): string {
  const releaseId = text(value, 'Release identity', 128);
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(releaseId)) reject('Release identity is invalid.', 400);
  if (kind === 'system' && !parseSystemVersion(releaseId)) reject('System release must use an Omarchy version such as 4.0.3 or 4.0.3-rc1.', 400);
  if (kind === 'opr' && !/^opr-[A-Za-z0-9][A-Za-z0-9._-]{0,110}$/.test(releaseId)) reject('OPR release must use an immutable generation such as opr-20260910-1.', 400);
  return releaseId;
}

function assertRefArray(value: unknown, label: string, maximum: number): Array<{ name: string; ref: string; digest: string }> {
  if (!Array.isArray(value) || value.length > maximum) reject(`${label} is invalid.`, 400);
  const result = value.map((item) => {
    if (!item || typeof item !== 'object' || Array.isArray(item)) reject(`${label} is invalid.`, 400);
    const row = item as Record<string, unknown>;
    const ref = text(row.ref, `${label} ref`, 128);
    if (!/^[a-f0-9]{40,64}$/i.test(ref)) reject(`${label} ref must be an immutable commit.`, 400);
    return { name: text(row.name, `${label} name`, 256), ref: ref.toLowerCase(), digest: digest(row.digest, `${label} digest`) };
  });
  if (new Set(result.map((item) => item.name)).size !== result.length) reject(`${label} cannot repeat.`, 400);
  return result.sort((left, right) => left.name.localeCompare(right.name));
}

function assertRepositoryInputs(value: unknown, architectures: readonly ReleaseArchitecture[]): DistributionRepositoryInput[] {
  if (!Array.isArray(value) || value.length > RELEASE_REPOSITORIES.length * architectures.length) reject('Repository snapshots are invalid.', 400);
  const result = value.map((item) => {
    if (!item || typeof item !== 'object' || Array.isArray(item)) reject('Repository snapshot is invalid.', 400);
    const row = item as Record<string, unknown>;
    const name = row.name as ReleaseRepository;
    if (!RELEASE_REPOSITORIES.includes(name)) reject('Repository name is invalid.', 400);
    const architecture = row.architecture as ReleaseArchitecture;
    if (!architectures.includes(architecture)) reject('Repository architecture is not in this release.', 400);
    return {
      name,
      architecture,
      snapshotDigest: digest(row.snapshotDigest, 'Repository snapshot digest'),
      dbUrl: safeUrl(row.dbUrl, 'Repository database URL'),
      signatureUrl: safeUrl(row.signatureUrl, 'Repository signature URL'),
      packageBaseUrl: safeUrl(row.packageBaseUrl, 'Repository package URL'),
      dbKey: safeKey(text(row.dbKey, 'Repository database storage key', 1_024)),
      signatureKey: safeKey(text(row.signatureKey, 'Repository signature storage key', 1_024)),
      signatureSha256: digest(row.signatureSha256, 'Repository signature digest'),
    };
  });
  const keys = result.map((item) => `${item.name}:${item.architecture}`);
  if (new Set(keys).size !== keys.length) reject('Repository snapshots cannot repeat.', 400);
  return result.sort(repositorySort);
}

function releaseManifestKey(kind: DistributionReleaseKind, channel: DistributionReleaseChannel, releaseId: string): string {
  const encoded = encodeURIComponent(releaseId);
  return kind === 'system' ? `distribution/releases/system/${channel}/${encoded}/manifest.json`
    : kind === 'opr' ? `distribution/releases/opr/${channel}/${encoded}/manifest.json`
      : `distribution/releases/transactions/${channel}/${encoded}/manifest.json`;
}

function publicManifestUrl(env: Env, kind: DistributionReleaseKind, channel: DistributionReleaseChannel, releaseId: string): string {
  const origin = env.PUBLIC_ORIGIN.replace(/\/$/, '');
  const encoded = encodeURIComponent(releaseId);
  return kind === 'system' ? `${origin}/repo/releases/${channel}/${encoded}/manifest.json`
    : kind === 'opr' ? `${origin}/repo/opr/${channel}/${encoded}/manifest.json`
      : `${origin}/repo/transactions/${channel}/${encoded}/manifest.json`;
}

function publicManifestSignatureUrl(env: Env, kind: DistributionReleaseKind, channel: DistributionReleaseChannel, releaseId: string): string {
  return `${publicManifestUrl(env, kind, channel, releaseId)}.sig`;
}

function publicReleaseObjectUrl(env: Env, kind: 'package-chunk' | 'changelog', digestValue: string): string {
  return `${env.PUBLIC_ORIGIN.replace(/\/$/, '')}/repo/distribution/${kind === 'package-chunk' ? 'chunks' : 'changelogs'}/${digestValue}.json`;
}

function manifestRef(env: Env, row: CandidateRow): ReleaseManifestRef {
  const manifest = JSON.parse(row.manifest_json) as ReleaseManifest;
  return { url: publicManifestUrl(env, row.kind, row.channel, row.release_id), digest: row.manifest_sha256,
    signatureUrl: publicManifestSignatureUrl(env, row.kind, row.channel, row.release_id), channel: row.channel, sequence: row.sequence,
    version: manifest.identity.version, generation: manifest.identity.generation };
}

async function verifyObject(env: Env, ref: DistributionObjectInput, label: string, maximum = MAX_CHUNK_BYTES): Promise<void> {
  if (ref.size > maximum) reject(`${label} is too large.`);
  try { await verifyR2Object(env, ref.key, ref.sha256, ref.size); }
  catch (cause) { reject(cause instanceof Error ? `${label}: ${cause.message}` : `${label} is unavailable.`); }
}

async function verifyStoredDigest(env: Env, key: string, expected: string, label: string, maximum = 4 * 1024 * 1024): Promise<void> {
  safeKey(key);
  const object = await env.ARTIFACTS.get(key);
  if (!object || object.size <= 0 || object.size > maximum) reject(`${label} is unavailable.`);
  const bytes = new Uint8Array(await object!.arrayBuffer());
  if (await sha256(bytes) !== expected) reject(`${label} digest changed.`);
}

async function tableExists(db: D1Database, name: string): Promise<boolean> {
  return Boolean(await db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?").bind(name).first());
}

async function readJsonObject<T>(env: Env, ref: DistributionObjectInput, label: string): Promise<T> {
  const object = await env.ARTIFACTS.get(ref.key);
  if (!object) reject(`${label} is unavailable.`);
  let value: T;
  try { value = JSON.parse(await object.text()) as T; }
  catch { reject(`${label} is not valid JSON.`); }
  return value!;
}

function packageChunk(value: unknown, index: number, count: number): number {
  if (!value || typeof value !== 'object' || Array.isArray(value)) reject('Package chunk must be a JSON object.');
  const row = value as Record<string, unknown>;
  if (row.schemaVersion !== 1 || row.index !== index || row.count !== count || !Array.isArray(row.packages)) reject('Package chunk contract is invalid.');
  for (const packageValue of row.packages) {
    if (!packageValue || typeof packageValue !== 'object' || Array.isArray(packageValue)) reject('Package reference is invalid.');
    const item = packageValue as Record<string, unknown>;
    text(item.releaseId, 'Package release ID', 128); text(item.name, 'Package name', 128); text(item.version, 'Package version', 256);
    if (!RELEASE_ARCHITECTURES.includes(item.architecture as ReleaseArchitecture) && item.architecture !== 'any') reject('Package architecture is invalid.');
    safeUrl(item.artifactUrl, 'Package URL'); digest(item.artifactSha256, 'Package digest'); safeUrl(item.artifactSignatureUrl, 'Package signature URL');
    digest(item.artifactSignatureSha256, 'Package signature digest');
    if (item.cohortId !== null && !ID.test(String(item.cohortId))) reject('Package cohort ID is invalid.');
    if (!Array.isArray(item.evidence) || item.evidence.length > 32) reject('Package evidence is invalid.');
    for (const evidence of item.evidence) {
      if (!evidence || typeof evidence !== 'object' || Array.isArray(evidence)) reject('Package evidence is invalid.');
      const ref = evidence as Record<string, unknown>;
      safeUrl(ref.url, 'Package evidence URL'); digest(ref.sha256, 'Package evidence digest'); positiveInteger(ref.size, 'Package evidence size', MAX_CHUNK_BYTES);
    }
  }
  return row.packages.length;
}

async function packageChunkRows(env: Env, refs: DistributionObjectInput[]): Promise<Array<Record<string, unknown>>> {
  const rows: Array<Record<string, unknown>> = [];
  for (let index = 0; index < refs.length; index += 1) {
    const value = await readJsonObject<unknown>(env, refs[index], `Package chunk ${index}`);
    packageChunk(value, index, refs.length);
    const packages = (value as { packages: unknown[] }).packages;
    rows.push(...packages as Array<Record<string, unknown>>);
  }
  return rows;
}

async function assertOwnedPackageChunks(env: Env, refs: DistributionObjectInput[], kind: CandidateKind, candidateReleaseId: string): Promise<{ cohortIds: string[]; ownerAreas: string[]; changelogReviewers: string[]; changelogDigests: Array<{ cohortId: string; revision: number; digest: string }>; omarchyPair: OmarchyPairBinding | null }> {
  const packages = await packageChunkRows(env, refs);
  const cohortIds = [...new Set(packages.map((item) => item.cohortId).filter((value): value is string => typeof value === 'string'))].sort();
  if (!cohortIds.length) reject('Every package in a release must bind a current owned cohort.');
  const ownerAreas = new Set<string>(); const changelogReviewers = new Set<string>();
  const changelogDigests: Array<{ cohortId: string; revision: number; digest: string }> = [];
  for (const cohortId of cohortIds) {
    const cohort = await env.DB.prepare(`SELECT c.current_revision,r.lane,r.manifest_sha256 FROM cohorts c JOIN cohort_revisions r ON r.cohort_id=c.id AND r.revision=c.current_revision WHERE c.id=?`).bind(cohortId)
      .first<{ current_revision: number; lane: string; manifest_sha256: string }>();
    if (!cohort || (cohort.lane !== kind && !(cohort.lane === 'system' && kind === 'opr'))) reject(`Cohort ${cohortId} is not an owned ${kind} cohort.`);
    const owners = await query<{ owner_area: string; lane: string }>(env.DB,
      `SELECT DISTINCT r.owner_area,r.lane FROM cohort_members m JOIN catalog_revisions r ON r.pkgbase=m.pkgbase AND r.revision=m.catalog_revision WHERE m.cohort_id=? AND m.revision=?`, cohortId, cohort!.current_revision);
    if (!owners.length) reject(`Cohort ${cohortId} has no current catalog ownership records.`);
    for (const owner of owners) if (!owner.lane || owner.lane === kind) ownerAreas.add(owner.owner_area);
    const changelog = await env.DB.prepare(`SELECT digest FROM cohort_changelogs WHERE cohort_id=? AND revision=? ORDER BY created_at DESC LIMIT 1`).bind(cohortId, cohort!.current_revision).first<{ digest: string }>();
    if (!changelog) reject(`Cohort ${cohortId} has no generated changelog.`);
    changelogDigests.push({ cohortId, revision: cohort!.current_revision, digest: changelog!.digest });
    const reviews = await query<{ actor: string }>(env.DB, 'SELECT actor FROM cohort_changelog_reviews WHERE cohort_id=? AND revision=? AND changelog_sha256=?', cohortId, cohort!.current_revision, changelog!.digest);
    if (!reviews.length) reject(`Cohort ${cohortId} changelog has no current human review.`);
    for (const review of reviews) changelogReviewers.add(review.actor);
  }
  const ownedRows: Array<{ item: Record<string, unknown>; row: OwnedPackageRow }> = [];
  for (const item of packages) {
    const packageId = text(item.releaseId, 'Package release ID', 128);
    const row = await env.DB.prepare(`SELECT id,name,version,architecture,artifact_key,signature_key,artifact_sha256,artifact_size,filename,collection,target_architecture,cohort_id,cohort_revision,pkgbase,revision_id,attestation_key,attestation_sha256,attestation_size,attestation_signature_key,attestation_signature_sha256
      FROM owned_repository_artifacts WHERE id=?`).bind(packageId).first<OwnedPackageRow>();
    const artifactFilename = row?.filename;
    if (!row || row.artifact_key === null || row.signature_key === null || row.artifact_sha256 === null || row.artifact_size === null || !artifactFilename) reject(`Package ${packageId} is not an owned signed binary release.`);
    const policy = await env.DB.prepare(`SELECT r.lane FROM cohort_members m JOIN catalog_revisions r ON r.pkgbase=m.pkgbase AND r.revision=m.catalog_revision
      WHERE m.cohort_id=? AND m.revision=? AND m.pkgbase=?`).bind(row!.cohort_id, row!.cohort_revision, row!.pkgbase).first<{ lane: string }>();
    if (!policy || policy.lane !== kind) reject(`Package ${packageId} is outside the ${kind} lane slice of its cohort.`);
    ownedRows.push({ item, row });
    if (item.name !== row!.name || item.version !== row!.version || item.architecture !== row!.architecture || item.artifactSha256 !== row!.artifact_sha256) reject(`Package ${packageId} bytes or identity changed.`);
    const artifactUrl = `${env.PUBLIC_ORIGIN.replace(/\/$/, '')}/${kind === 'system' ? 'repo/releases' : 'repo/opr'}/${encodeURIComponent(candidateReleaseId)}/${row!.collection!}/${row!.target_architecture!}/${encodeURIComponent(row!.filename!)}`;
    if (item.artifactUrl !== artifactUrl || item.artifactSignatureUrl !== `${artifactUrl}.sig`) reject(`Package ${packageId} URL mapping is not the canonical owned route.`);
    await verifyR2Object(env, row!.artifact_key, row!.artifact_sha256, row!.artifact_size);
    const signature = await env.ARTIFACTS.get(row!.signature_key);
    if (!signature) reject(`Package ${packageId} signature is unavailable.`);
    const signatureBytes = new Uint8Array(await signature!.arrayBuffer());
    if (await sha256(signatureBytes) !== item.artifactSignatureSha256) reject(`Package ${packageId} signature digest changed.`);
    if (!Array.isArray(item.evidence) || !item.evidence.some((e) => e && typeof e === 'object' && (e as { sha256?: unknown }).sha256 === row!.attestation_sha256!)) reject(`Owned package ${packageId} has no exact attestation evidence.`);
    await verifyR2Object(env, row!.attestation_key!, row!.attestation_sha256!, row!.attestation_size!);
    await verifyStoredDigest(env, row!.attestation_signature_key!, row!.attestation_signature_sha256!, `Owned package ${packageId} attestation signature`, 1_048_576);
  }
  for (let index = 0; index < refs.length; index += 1) {
    const row = await env.DB.prepare(`SELECT 1 FROM owned_repository_package_chunks WHERE lane=? AND release_id=? AND chunk_index=? AND chunk_count=? AND object_key=? AND object_sha256=? AND object_size=? AND status IN ('prepared','published')`)
      .bind(kind, candidateReleaseId, index, refs.length, refs[index].key, refs[index].sha256, refs[index].size).first();
    if (!row) reject(`Package chunk ${index} is not a current owned repository chunk.`);
  }
  const omarchyPair = kind === 'system' ? await assertOmarchyPair(env, ownedRows, candidateReleaseId) : null;
  return { cohortIds, ownerAreas: [...ownerAreas].sort(), changelogReviewers: [...changelogReviewers].sort(), changelogDigests, omarchyPair };
}

export async function assertOmarchyPair(env: Env, rows: Array<{ item: Record<string, unknown>; row: OwnedPackageRow }>, candidateReleaseId: string): Promise<OmarchyPairBinding> {
  const pair = rows.filter(({ row }) => row.collection === 'omarchy' && (row.name === 'omarchy' || row.name === 'omarchy-settings'));
  if (pair.length !== 4 || new Set(pair.map(({ row }) => `${row.name}:${row.target_architecture}`)).size !== 4) reject('System release requires omarchy and omarchy-settings outputs on both architectures.');
  const commits = new Set<string>();
  for (const { row } of pair) {
    const source = await env.DB.prepare(`SELECT r.upstream_commit,q.upstream_ref,r.version,r.pkgrel FROM revisions r JOIN requests q ON q.id=r.request_id WHERE r.id=?`).bind(row.revision_id).first<{ upstream_commit: string | null; upstream_ref: string | null; version: string; pkgrel: number | null }>();
    const commit = source?.upstream_commit ?? source?.upstream_ref;
    if (!commit || !/^[a-f0-9]{40,64}$/.test(commit)) reject('Omarchy release pair is missing an immutable upstream commit.');
    commits.add(commit.toLowerCase());
    if (row.version !== `${source!.version}-${source!.pkgrel ?? 1}`) reject(`Omarchy output ${row.name} is not bound to its reviewed final package version.`);
  }
  if (commits.size !== 1) reject('omarchy and omarchy-settings must resolve to the same upstream commit on both architectures.');
  if (/^[0-9]+\.[0-9]+\.[0-9]+$/.test(candidateReleaseId)) {
    const rcChunks = await query<{ object_key: string; digest: string; size: number }>(env.DB, `SELECT o.object_key,o.digest,o.size FROM distribution_release_objects o
      JOIN distribution_release_candidates c ON c.id=o.candidate_id
      WHERE o.kind='package-chunk' AND c.kind='system' AND c.channel='rc' AND c.status IN ('signed','active')`);
    if (!rcChunks.length) reject('Final Omarchy artifacts have no qualified RC package universe.');
    const rcPackages: Array<{ name?: string; architecture?: string; artifactSha256?: string; version?: string }> = [];
    for (const chunk of rcChunks) {
      await verifyStoredDigest(env, chunk.object_key, chunk.digest, 'RC package chunk');
      const object = await env.ARTIFACTS.get(chunk.object_key); if (!object) continue;
      let data: { packages?: Array<{ name?: string; architecture?: string; artifactSha256?: string; version?: string }> };
      try { data = JSON.parse(await object.text()); } catch { reject('An earlier Omarchy RC package chunk is invalid.'); }
      rcPackages.push(...(data!.packages ?? []));
    }
    for (const candidate of pair) {
      const exact = rcPackages.find((prior) => prior.name === candidate.row.name && prior.architecture === candidate.row.architecture && prior.version === candidate.row.version);
      if (exact) {
        if (exact.artifactSha256 !== candidate.row.artifact_sha256) reject(`Final Omarchy output ${candidate.row.name} bytes were not qualified in RC.`);
        continue;
      }
      const sameBytes = rcPackages.find((prior) => prior.name === candidate.row.name && prior.architecture === candidate.row.architecture && prior.artifactSha256 === candidate.row.artifact_sha256);
      if (sameBytes) reject(`Final Omarchy output ${candidate.row.name} relabels earlier RC metadata.`);
      reject(`Final Omarchy output ${candidate.row.name} has no qualified final-version RC artifact.`);
    }
  }
  return { commit: [...commits][0], packageNames: ['omarchy', 'omarchy-settings'] };
}

async function verifyPackageChunks(env: Env, refs: DistributionObjectInput[], expectedCount: number): Promise<ReleasePackageChunkRef[]> {
  if (!refs.length || refs.length > MAX_CHUNKS) reject('At least one package chunk is required.', 400);
  if (new Set(refs.map((ref) => ref.sha256)).size !== refs.length) reject('Package chunk digests cannot repeat.', 400);
  let packageCount = 0;
  const output: ReleasePackageChunkRef[] = [];
  for (let index = 0; index < refs.length; index += 1) {
    const ref = refs[index];
    await verifyObject(env, ref, `Package chunk ${index}`);
    const body = await readJsonObject<unknown>(env, ref, `Package chunk ${index}`);
    packageCount += packageChunk(body, index, refs.length);
    output.push({ ...objectRef(ref), index, count: refs.length, packageCount: packageChunk(body, index, refs.length) });
  }
  if (packageCount !== expectedCount) reject('Package chunk count does not match the release root.');
  return output;
}

async function nextSequence(db: D1Database, lane: 'system' | 'opr' | 'transaction', channel: DistributionReleaseChannel): Promise<{ digest: string | null; sequence: number }> {
  const pointer = await db.prepare('SELECT manifest_sha256,sequence FROM distribution_activation_pointers WHERE lane=? AND channel=?').bind(lane, channel).first<{ manifest_sha256: string | null; sequence: number }>();
  if (!pointer) reject('Distribution activation pointers are unavailable.', 503);
  return { digest: pointer!.manifest_sha256, sequence: pointer!.sequence };
}

async function pointerForDigest(db: D1Database, lane: 'system' | 'opr', digestValue: string | null): Promise<{ channel: DistributionReleaseChannel; release_id: string | null; manifest_sha256: string | null; sequence: number } | null> {
  if (!digestValue) return null;
  return db.prepare('SELECT channel,release_id,manifest_sha256,sequence FROM distribution_activation_pointers WHERE lane=? AND manifest_sha256=? LIMIT 1').bind(lane, digestValue).first();
}

async function currentManifest(db: D1Database, digestValue: string | null): Promise<CandidateRow | null> {
  if (!digestValue) return null;
  return db.prepare('SELECT * FROM distribution_release_candidates WHERE manifest_sha256=? AND status IN (\'signed\',\'active\') ORDER BY sequence DESC LIMIT 1')
    .bind(digestValue).first<CandidateRow>();
}

async function activeTransactionFor(db: D1Database, row: Pick<CandidateRow, 'kind' | 'manifest_sha256'>): Promise<CandidateRow | null> {
  const path = row.kind === 'system' ? '$.compatibility.systemManifestDigest' : '$.compatibility.oprManifestDigest';
  const refPath = row.kind === 'system' ? '$.systemManifest.digest' : '$.oprManifest.digest';
  return db.prepare(`SELECT * FROM distribution_release_candidates
    WHERE kind='resolved-transaction' AND status='active' AND (json_extract(manifest_json,?)=? OR json_extract(manifest_json,?)=? )
    ORDER BY sequence DESC LIMIT 1`).bind(path, row.manifest_sha256, refPath, row.manifest_sha256).first<CandidateRow>();
}

async function linkedOprManifest(db: D1Database, systemDigest: string, channel: DistributionReleaseChannel): Promise<CandidateRow | null> {
  const rows = await query<CandidateRow>(db, `SELECT * FROM distribution_release_candidates
    WHERE kind='opr' AND status IN ('signed','active') AND json_extract(manifest_json,'$.compatibility.systemManifestDigest')=?
    ORDER BY sequence DESC`, systemDigest);
  if (rows.length > 1) reject(`More than one signed OPR counterpart targets system manifest ${systemDigest}.`);
  if (rows.length && channel === 'stable' && rows[0].channel !== 'stable') reject('Stable system transactions require a stable OPR snapshot.');
  return rows[0] ?? null;
}

async function approvalRows(db: D1Database, candidateId: string, manifestSha256: string): Promise<ApprovalRow[]> {
  return query<ApprovalRow>(db, 'SELECT kind,actor,area,reason FROM distribution_release_approvals WHERE candidate_id=? AND manifest_sha256=? ORDER BY created_at,actor', candidateId, manifestSha256);
}

async function assertReleaseApprovals(db: D1Database, row: CandidateRow, requiredAreas: readonly string[]): Promise<ApprovalRow[]> {
  const approvals = await approvalRows(db, row.id, row.manifest_sha256);
  const release = approvals.filter((item) => item.kind === 'release');
  if (!release.length) reject('A current human release-team approval is required.');
  for (const item of release) {
    const actorId = item.actor.startsWith('github:') ? item.actor.slice(7) : '';
    if (!actorId || !await db.prepare("SELECT 1 FROM team_memberships WHERE github_id=? AND team='release'").bind(actorId).first()) reject('Release approval actor no longer has release-team authority.');
  }
  for (const area of requiredAreas) {
    const match = approvals.find((item) => item.kind === 'base' && item.area === area);
    if (!match) reject(`A current base-owner approval is required for ${area}.`);
    const actorId = match!.actor.startsWith('github:') ? match!.actor.slice(7) : '';
    if (!actorId || !await db.prepare('SELECT 1 FROM team_memberships WHERE github_id=? AND (team=? OR team IN (\'security\',\'admin\'))').bind(actorId, area).first()) reject(`Base-owner approval for ${area} no longer has authority.`);
  }
  return approvals;
}

async function assertCandidateGates(env: Env, input: DistributionCandidateInput, kind: CandidateKind): Promise<void> {
  if (kind === 'system' && input.architectures.length !== RELEASE_ARCHITECTURES.length) reject('System release requires x86_64 and aarch64 evidence.');
  const compatibility = input.compatibility ?? {};
  if (kind === 'opr' && !compatibility.systemManifestDigest) reject('OPR release must bind a qualified system manifest.');
  if (!input.packageCount || !input.packageChunks.length) reject('A release must enumerate package chunks.');
  // Cohort qualification is deliberately fail-closed. The cohort gate implementation owns
  // exact native/ABI/install/recovery evidence; this service only accepts its approved phase.
  const chunks = await Promise.all(input.packageChunks.map((ref) => readJsonObject<unknown>(env, ref, 'Package chunk')));
  const cohortIds = new Set<string>();
  for (const chunk of chunks) {
    const packages = (chunk as { packages?: unknown[] }).packages ?? [];
    for (const packageValue of packages) {
      const cohortId = packageValue && typeof packageValue === 'object' ? (packageValue as { cohortId?: unknown }).cohortId : null;
      if (typeof cohortId === 'string') cohortIds.add(cohortId);
    }
  }
  const systemUniverse = kind === 'system'
    ? await env.DB.prepare("SELECT root_sha256 FROM owned_repository_universes WHERE lane='system' AND release_id=? AND status IN ('prepared','published') LIMIT 1").bind(input.releaseId).first<{ root_sha256: string }>()
    : null;
  if (kind === 'system' && !systemUniverse) reject('System release has no prepared final owned repository universe for this release tuple.');
  for (const cohortId of cohortIds) {
    const cohort = await env.DB.prepare('SELECT c.phase,c.condition,r.lane,c.current_revision,r.manifest_sha256 FROM cohorts c JOIN cohort_revisions r ON r.cohort_id=c.id AND r.revision=c.current_revision WHERE c.id=?').bind(cohortId)
      .first<{ phase: string; condition: string; lane: string; current_revision: number; manifest_sha256: string }>();
    const members = await query<{ pkgbase: string; lane: string }>(env.DB,
      `SELECT m.pkgbase,r.lane FROM cohort_members m JOIN catalog_revisions r ON r.pkgbase=m.pkgbase AND r.revision=m.catalog_revision WHERE m.cohort_id=? AND m.revision=? ORDER BY m.pkgbase`, cohort?.current_revision === undefined ? '' : cohortId, cohort?.current_revision ?? 0);
    const laneMembers = members.filter((member) => member.lane === kind);
    const supportsLane = Boolean(cohort) && (cohort!.lane === kind || cohort!.lane === 'system' && kind === 'opr' && laneMembers.length > 0);
    if (!cohort || !supportsLane || !['approve', 'publish', 'observe'].includes(cohort.phase) || cohort.condition !== 'ready') {
      reject(`Cohort ${cohortId} is not qualified for release activation.`);
    }
    const requiredOperations = ['reproducibility', 'install', 'upgrade', 'recovery', ...(kind === 'system' ? ['boot'] : [])];
    for (const architecture of input.architectures) {
      let qualification;
      try { qualification = await qualifyCohort(env, await getCohort(env.DB, cohortId), architecture); }
      catch (cause) { reject(cause instanceof Error ? `Cohort ${cohortId} qualification: ${cause.message}` : `Cohort ${cohortId} qualification is unavailable.`); }
      if (!qualification || qualification.report.manifestSha256 !== cohort!.manifest_sha256 || qualification.report.truncated || qualification.report.findings.length) reject(`Cohort ${cohortId} has unresolved dependency or ABI qualification findings for ${architecture}.`);
    for (const operation of requiredOperations) {
        const operationName = operation as 'install' | 'upgrade' | 'recovery' | 'boot' | 'reproducibility';
        const members = laneMembers;
        if (kind === 'system' && operationName !== 'reproducibility') {
          if (!await hasPassingQualification(env.DB, { cohortId, revision: cohort!.current_revision, operation: operationName, architecture, coverageKind: 'system', coverageReleaseId: input.releaseId, coverageRootSha256: systemUniverse!.root_sha256 })) reject(`Cohort ${cohortId} is missing passed final-universe ${operation} evidence for ${architecture}.`);
        } else {
          for (const member of members) if (!await hasPassingQualification(env.DB, { cohortId, revision: cohort!.current_revision, operation: operationName, architecture, pkgbase: member.pkgbase })) reject(`Cohort ${cohortId} is missing passed ${operation} evidence for ${member.pkgbase}/${architecture}.`);
        }
      }
    }
  }
}

type CohortScopeFence = { cohortId: string; revision: number; manifestSha256: string; phase: string; condition: string; epoch: number };

async function storedCandidateInput(env: Env, row: CandidateRow): Promise<{ input: DistributionCandidateInput; manifest: ReleaseManifest }> {
  if (row.kind === 'resolved-transaction') reject('Resolved transactions do not have candidate gates.');
  const manifest = JSON.parse(row.manifest_json) as ReleaseManifest;
  const objects = await query<{ kind: string; digest: string; object_key: string; size: number }>(env.DB,
    'SELECT kind,digest,object_key,size FROM distribution_release_objects WHERE candidate_id=?', row.id);
  const object = (kind: string, digestValue: string) => objects.find((item) => item.kind === kind && item.digest === digestValue);
  const packageChunks = manifest.packageChunks.map((chunk) => {
    const stored = object('package-chunk', chunk.sha256);
    if (!stored || stored.size !== chunk.size) reject(`Stored package chunk ${chunk.sha256} changed.`);
    return { ...chunk, key: stored!.object_key };
  });
  const changelog = object('changelog', manifest.changelog.sha256);
  if (!changelog || changelog.size !== manifest.changelog.size || changelog.object_key !== row.changelog_key) reject('Stored release changelog mapping changed.');
  return {
    manifest,
    input: {
      kind: row.kind,
      channel: row.channel,
      releaseId: row.release_id,
      sequence: row.sequence,
      parent: manifest.parent,
      architectures: manifest.architectures,
      repositories: [],
      packageChunks,
      packageCount: manifest.packageCount,
      compatibility: manifest.compatibility,
      changelog: { ...manifest.changelog, key: changelog.object_key },
    },
  };
}

async function currentCohortScopeFences(env: Env, cohortIds: string[], expected: Array<{ cohortId: string; revision: number; digest: string }>): Promise<CohortScopeFence[]> {
  if (!cohortIds.length) reject('Release has no cohort scope to fence.');
  const rows = await query<CohortScopeFence>(env.DB, `SELECT c.id AS cohortId,c.current_revision AS revision,r.manifest_sha256 AS manifestSha256,c.phase,c.condition,e.version AS epoch
    FROM cohorts c JOIN cohort_revisions r ON r.cohort_id=c.id AND r.revision=c.current_revision JOIN cohort_scope_epochs e ON e.cohort_id=c.id
    WHERE c.id IN (SELECT value FROM json_each(?)) ORDER BY c.id`, JSON.stringify(cohortIds));
  if (rows.length !== new Set(cohortIds).size) reject('Release cohort scope is unavailable.');
  const expectedById = new Map(expected.map((item) => [item.cohortId, item]));
  for (const row of rows) {
    const digestValue = expectedById.get(row.cohortId);
    const changelog = await env.DB.prepare('SELECT digest FROM cohort_changelogs WHERE cohort_id=? AND revision=? ORDER BY created_at DESC LIMIT 1').bind(row.cohortId, row.revision).first<{ digest: string }>();
    if (!digestValue || !changelog || changelog.digest !== digestValue.digest || row.revision !== digestValue.revision || row.phase !== 'approve' && row.phase !== 'publish' && row.phase !== 'observe' || row.condition !== 'ready') {
      reject(`Cohort ${row.cohortId} changed while preparing release gates.`);
    }
  }
  return rows;
}

function cohortScopeFenceStatements(db: D1Database, fences: CohortScopeFence[]): D1PreparedStatement[] {
  return fences.flatMap((fence) => [
    db.prepare(`INSERT INTO distribution_assertions(expected,actual) SELECT 1,COUNT(*) FROM cohorts c
      JOIN cohort_revisions r ON r.cohort_id=c.id AND r.revision=c.current_revision
      JOIN cohort_scope_epochs e ON e.cohort_id=c.id
      WHERE c.id=? AND c.current_revision=? AND r.manifest_sha256=? AND c.phase=? AND c.condition=? AND e.version=?`)
      .bind(fence.cohortId, fence.revision, fence.manifestSha256, fence.phase, fence.condition, fence.epoch),
  ]);
}

async function revalidateStoredCandidate(env: Env, row: CandidateRow): Promise<{ manifest: ReleaseManifest; fences: CohortScopeFence[] }> {
  if (row.kind === 'resolved-transaction') reject('Resolved transactions do not have candidate gates.');
  const kind = row.kind;
  const stored = await storedCandidateInput(env, row);
  await verifyPackageChunks(env, stored.input.packageChunks, stored.manifest.packageCount);
  await verifyObject(env, stored.input.changelog, 'Changelog', 1_048_576);
  const owned = await assertOwnedPackageChunks(env, stored.input.packageChunks, kind, row.release_id);
  const initialFences = await currentCohortScopeFences(env, owned.cohortIds, owned.changelogDigests);
  const listed = await readJsonObject<{ cohorts?: unknown }>(env, stored.input.changelog, 'Changelog');
  if (!Array.isArray(listed.cohorts)) reject('Changelog cohort records are invalid.');
  const listedDigests = listed.cohorts.map((value) => {
    if (!value || typeof value !== 'object' || Array.isArray(value)) reject('Changelog cohort records are invalid.');
    const item = value as Record<string, unknown>;
    return { cohortId: text(item.cohortId, 'Changelog cohort ID', 128), revision: positiveInteger(item.revision, 'Changelog cohort revision'), digest: digest(item.digest, 'Changelog cohort digest') };
  }).sort((left, right) => left.cohortId.localeCompare(right.cohortId));
  const currentDigests = [...owned.changelogDigests].sort((left, right) => left.cohortId.localeCompare(right.cohortId));
  if (canonicalJson(listedDigests) !== canonicalJson(currentDigests) || canonicalJson(stored.manifest.changelog.cohortDigests.sort((a, b) => a.cohortId.localeCompare(b.cohortId))) !== canonicalJson(currentDigests)) {
    reject('Release changelog is stale for the current cohort scope.');
  }
  await assertCandidateGates(env, stored.input, kind);
  const finalFences = await currentCohortScopeFences(env, owned.cohortIds, currentDigests);
  for (const before of initialFences) {
    const after = finalFences.find((item) => item.cohortId === before.cohortId);
    if (!after || after.revision !== before.revision || after.manifestSha256 !== before.manifestSha256 || after.phase !== before.phase || after.condition !== before.condition || after.epoch !== before.epoch) reject(`Cohort ${before.cohortId} changed while validating release gates.`);
  }
  return { manifest: stored.manifest, fences: finalFences };
}

function baseOwnerAreas(input: DistributionCandidateInput): string[] {
  const areas = [...new Set((input.baseOwnerAreas ?? []).map((area) => text(area, 'Base owner area', 64)))].sort();
  return areas;
}

async function candidateManifest(env: Env, input: DistributionCandidateInput, sequence: number, parent: { digest: string | null; sequence: number | null }, chunks: ReleasePackageChunkRef[], derived: { ownerAreas: string[]; changelogReviewers: string[]; changelogDigests: Array<{ cohortId: string; revision: number; digest: string }>; omarchyPair: OmarchyPairBinding | null }): Promise<ReleaseManifest> {
  const kind = input.kind;
  if (!validChannel(kind, input.channel)) reject(`Invalid ${kind} release channel.`, 400);
  const releaseId = assertReleaseId(kind, input.releaseId);
  const architectures = assertArchitectureList(input.architectures);
  const repositories = assertRepositoryInputs(input.repositories, architectures);
  if (!repositories.some((item) => item.architecture === 'x86_64') || !repositories.some((item) => item.architecture === 'aarch64')) reject('Every release needs repository snapshots for both primary architectures.');
  for (const repository of repositories) {
    const origin = new URL(env.PUBLIC_ORIGIN).origin;
    for (const url of [repository.dbUrl, repository.signatureUrl, repository.packageBaseUrl]) if (new URL(url).origin !== origin) reject(`${repository.name}/${repository.architecture} URL must use the configured repository origin.`, 400);
    const owned = await env.DB.prepare(`SELECT 1 FROM owned_repository_snapshots WHERE lane=? AND release_id=? AND architecture=? AND collection=? AND db_key=? AND db_signature_key=? AND status IN ('prepared','published') LIMIT 1`)
      .bind(kind, releaseId, repository.architecture, repository.name, repository.dbKey, repository.signatureKey).first();
    if (!owned) reject(`${repository.name}/${repository.architecture} snapshot is not an owned repository record.`);
    await verifyStoredDigest(env, repository.dbKey, repository.snapshotDigest, `${repository.name}/${repository.architecture} repository database`);
    await verifyStoredDigest(env, repository.signatureKey, repository.signatureSha256, `${repository.name}/${repository.architecture} repository signature`, 1_048_576);
  }
  const refs = assertRefArray(input.sourceRefs ?? [], 'Source refs', 512);
  if (kind === 'system' && derived.omarchyPair) {
    for (const name of derived.omarchyPair.packageNames) if (!refs.some((ref) => ref.name === name && ref.ref.toLowerCase() === derived.omarchyPair!.commit)) reject(`Source refs must bind the reviewed ${name} commit.`);
  }
  const requestedAreas = baseOwnerAreas(input);
  if (requestedAreas.length && canonicalJson(requestedAreas) !== canonicalJson(derived.ownerAreas)) reject('Base-owner areas are derived from current cohort ownership.', 409);
  const changelogInput = safeRef(input.changelog, 'Changelog', 1_048_576);
  const packageChunks = chunks;
  changelogInput.url = publicReleaseObjectUrl(env, 'changelog', changelogInput.sha256);
  for (const chunk of packageChunks) chunk.url = publicReleaseObjectUrl(env, 'package-chunk', chunk.sha256);
  await verifyObject(env, changelogInput, 'Changelog', 1_048_576);
  const changelogBytes = await env.ARTIFACTS.get(changelogInput.key);
  const changelogText = changelogBytes ? await changelogBytes.text() : '';
  let listedChangelogs: Array<{ cohortId: string; revision: number; digest: string }>;
  try {
    const parsed = JSON.parse(changelogText) as { cohorts?: unknown };
    if (!Array.isArray(parsed.cohorts)) throw new Error();
    listedChangelogs = parsed.cohorts.map((item) => {
      if (!item || typeof item !== 'object' || Array.isArray(item)) throw new Error();
      const row = item as Record<string, unknown>;
      return { cohortId: text(row.cohortId, 'Changelog cohort ID', 128), revision: positiveInteger(row.revision, 'Changelog cohort revision'), digest: digest(row.digest, 'Changelog cohort digest') };
    }).sort((left, right) => left.cohortId.localeCompare(right.cohortId));
  } catch { reject('Changelog must contain exact current cohort digest records.'); }
  if (canonicalJson(listedChangelogs!) !== canonicalJson([...derived.changelogDigests].sort((left, right) => left.cohortId.localeCompare(right.cohortId)))) reject('Changelog does not bind the exact current cohort changelogs.');
  const changelog: ReleaseChangelogRef = { ...objectRef(changelogInput), approvedBy: derived.changelogReviewers.join(','), cohortDigests: derived.changelogDigests };
  const createdAt = now();
  const expiresAt = input.expiresAt ?? createdAt + configuredLifetime(env, 'DISTRIBUTION_SNAPSHOT_EXPIRY_SECONDS', DEFAULT_SNAPSHOT_EXPIRY_SECONDS);
  if (!Number.isSafeInteger(expiresAt) || expiresAt <= createdAt) reject('Release expiry must be a future timestamp.', 400);
  const base = {
    schemaVersion: DISTRIBUTION_RELEASE_SCHEMA_VERSION,
    kind,
    lane: kind,
    channel: input.channel,
    identity: kind === 'system' ? { version: releaseId, generation: null } : { version: null, generation: releaseId },
    releaseId,
    parent,
    createdAt,
    expiresAt,
    sequence,
    architectures,
    sourceRefs: refs,
    repositories: repositories.map(({ dbKey: _dbKey, signatureKey: _signatureKey, signatureSha256: _signatureSha256, ...repository }) => repository),
    packageChunks,
    packageCount: input.packageCount,
    compatibility: {
      systemManifestDigest: input.compatibility?.systemManifestDigest ?? null,
      systemSnapshotDigests: [...new Set(input.compatibility?.systemSnapshotDigests ?? [])].map((value) => digest(value, 'System snapshot digest')).sort(),
      oprManifestDigest: input.compatibility?.oprManifestDigest ?? null,
    },
    systemManifest: null,
    oprManifest: null,
    changelog,
    approvals: { releaseTeam: [], baseOwners: derived.ownerAreas },
    recovery: { fromDigest: input.recovery?.fromDigest ?? parent.digest, target: null, authorized: input.recovery?.authorized === true, reason: input.recovery?.authorized ? text(input.recovery?.reason, 'Recovery reason', 2_000) : null, constraints: [...new Set(input.recovery?.constraints ?? [])].map((value) => text(value, 'Recovery constraint')).sort() },
    policy: { schemaVersion: 1 as const, version: DISTRIBUTION_RELEASE_POLICY },
  } satisfies ReleaseManifest;
  return base;
}

async function insertCandidate(env: Env, actor: Actor, manifest: ReleaseManifest, packageChunks: DistributionObjectInput[], changelog: DistributionObjectInput, manifestKey = releaseManifestKey(manifest.kind, manifest.channel, manifest.releaseId)): Promise<CandidateRow> {
  const manifestSha256 = await releaseManifestDigest(manifest);
  const bytes = new TextEncoder().encode(releaseManifestBytes(manifest));
  await immutableBytes(env, manifestKey, bytes, await sha256(bytes), 'application/json');
  const row: CandidateRow = {
    id: id(), kind: manifest.kind, lane: manifest.lane, channel: manifest.channel, release_id: manifest.releaseId, sequence: manifest.sequence,
    parent_digest: manifest.parent.digest, parent_sequence: manifest.parent.sequence, manifest_json: releaseManifestBytes(manifest),
    manifest_sha256: manifestSha256, manifest_key: manifestKey, manifest_size: bytes.byteLength, signature_key: null,
    signature_sha256: null, signature_intent_id: null, changelog_key: changelog.key, changelog_sha256: changelog.sha256,
    status: 'candidate', created_by: actor.id, created_at: manifest.createdAt, activated_at: null,
  };
  await env.DB.prepare(`INSERT INTO distribution_release_candidates
    (id,kind,lane,channel,release_id,sequence,parent_digest,parent_sequence,manifest_json,manifest_sha256,manifest_key,manifest_size,changelog_key,changelog_sha256,status,created_by,created_at)
    VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).bind(row.id,row.kind,row.lane,row.channel,row.release_id,row.sequence,row.parent_digest,row.parent_sequence,row.manifest_json,row.manifest_sha256,row.manifest_key,row.manifest_size,row.changelog_key,row.changelog_sha256,row.status,row.created_by,row.created_at).run();
  for (const chunk of manifest.packageChunks) {
    const source = packageChunks.find((ref) => ref.sha256 === chunk.sha256);
    if (!source) reject('Package chunk object mapping is incomplete.', 503);
    await env.DB.prepare('INSERT INTO distribution_release_objects(candidate_id,kind,digest,object_key,size) VALUES(?,?,?,?,?)').bind(row.id, 'package-chunk', chunk.sha256, source!.key, chunk.size).run();
  }
  await env.DB.prepare('INSERT INTO distribution_release_objects(candidate_id,kind,digest,object_key,size) VALUES(?,?,?,?,?)').bind(row.id, 'changelog', changelog.sha256, changelog.key, changelog.size).run();
  await audit(env.DB, actor.id, 'distribution.release_prepared', row.id, { kind: row.kind, releaseId: row.release_id, manifestSha256: row.manifest_sha256, packageCount: manifest.packageCount, chunks: manifest.packageChunks.length }).run();
  return row;
}

export async function prepareDistributionRelease(env: Env, actor: Actor | null, input: DistributionCandidateInput): Promise<{ candidate: CandidateRow; manifest: ReleaseManifest }> {
  const reviewer = humanMaintainer(actor);
  if (!input || typeof input !== 'object') reject('Release candidate input is required.', 400);
  const kind = input.kind;
  if (!RELEASE_KINDS.includes(kind as DistributionReleaseKind)) reject('Only system and OPR candidates can be prepared.', 400);
  if (!validChannel(kind, input.channel)) reject(`Invalid ${kind} release channel.`, 400);
  const releaseId = assertReleaseId(kind, input.releaseId);
  const sequence = input.sequence ?? (await nextSequence(env.DB, kind, input.channel)).sequence + 1;
  positiveInteger(sequence, 'Release sequence');
  const current = await nextSequence(env.DB, kind, input.channel);
  if (sequence !== current.sequence + 1) reject('Release sequence must advance the current lane by one.', 409);
  const parent = input.parent ?? { digest: current.digest, sequence: current.sequence || null };
  if (parent.digest !== current.digest || (parent.sequence ?? null) !== (current.sequence || null)) reject('Release parent changed; refresh before preparing a candidate.');
  const architectures = assertArchitectureList(input.architectures);
  assertReleaseId(kind, releaseId);
  const packageRefs = input.packageChunks.map((ref) => safeRef(ref, 'Package chunk'));
  const changelog = safeRef(input.changelog, 'Changelog', 1_048_576);
  await assertCandidateGates(env, { ...input, releaseId, architectures, packageChunks: packageRefs, changelog }, kind);
  const chunks = await verifyPackageChunks(env, packageRefs, positiveInteger(input.packageCount, 'Package count', 10_000_000));
  const owned = await assertOwnedPackageChunks(env, packageRefs, kind, releaseId);
  const manifest = await candidateManifest(env, { ...input, releaseId, architectures, packageChunks: packageRefs, changelog }, sequence, parent, chunks, owned);
  const manifestSha256 = await releaseManifestDigest(manifest);
  const existing = await env.DB.prepare('SELECT * FROM distribution_release_candidates WHERE manifest_sha256=? AND channel=?').bind(manifestSha256, input.channel).first<CandidateRow>();
  if (existing) return { candidate: existing, manifest: JSON.parse(existing.manifest_json) as ReleaseManifest };
  const candidate = await insertCandidate(env, reviewer, manifest, packageRefs, changelog);
  return { candidate, manifest };
}

export async function approveDistributionRelease(db: D1Database, actor: Actor | null, input: DistributionApprovalInput): Promise<{ candidateId: string; manifestSha256: string }> {
  const reviewer = humanMaintainer(actor);
  const candidateId = text(input.candidateId, 'Candidate ID', 128);
  const row = await db.prepare('SELECT * FROM distribution_release_candidates WHERE id=?').bind(candidateId).first<CandidateRow>();
  if (!row || row.kind === 'resolved-transaction') reject('Release candidate not found.', 404);
  const kind = input.kind;
  if (kind !== 'release' && kind !== 'base') reject('Approval kind is invalid.', 400);
  const reason = text(input.reason, 'Approval reason', 2_000);
  const area = kind === 'base' ? text(input.area, 'Base owner area', 64) : null;
  if (kind === 'release') await releaseAuthority(db, reviewer);
  else if (!await db.prepare("SELECT 1 FROM team_memberships WHERE github_id=? AND (team=? OR team IN ('security','admin'))").bind(reviewer.id.slice(7), area).first()) reject('Base-owner approval requires matching team authority.', 403);
  await db.prepare(`INSERT INTO distribution_release_approvals(id,candidate_id,manifest_sha256,kind,actor,area,reason,created_at)
    VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(candidate_id,manifest_sha256,kind,actor,area) DO NOTHING`)
    .bind(id(), row.id, row.manifest_sha256, kind, reviewer.id, area, reason, now()).run();
  await audit(db, reviewer.id, 'distribution.release_approved', row.id, { kind, area, manifestSha256: row.manifest_sha256 }).run();
  return { candidateId: row.id, manifestSha256: row.manifest_sha256 };
}

export async function signDistributionRelease(env: Env, actor: Actor | null, candidateId: string): Promise<{ candidateId: string; manifestSha256: string; signatureKey: string; signatureSha256: string }> {
  const reviewer = await releaseAuthority(env.DB, actor);
  const idValue = text(candidateId, 'Candidate ID', 128);
  const row = await env.DB.prepare('SELECT * FROM distribution_release_candidates WHERE id=?').bind(idValue).first<CandidateRow>();
  if (!row || row.kind === 'resolved-transaction') reject('Release candidate not found.', 404);
  if (row.status === 'signed' && row.signature_key && row.signature_sha256) {
    const revalidated = await revalidateStoredCandidate(env, row);
    try { await env.DB.batch(cohortScopeFenceStatements(env.DB, revalidated.fences)); }
    catch { reject('Release cohort scope changed during signing; refresh before retrying.'); }
    return { candidateId: row.id, manifestSha256: row.manifest_sha256, signatureKey: row.signature_key, signatureSha256: row.signature_sha256 };
  }
  if (row.status !== 'candidate') reject('Only an unsigned release candidate can be signed.');
  const pointer = await nextSequence(env.DB, row.lane, row.channel);
  if (row.parent_digest !== pointer.digest || (row.parent_sequence ?? null) !== (pointer.sequence || null)) reject('Release candidate parent is stale; prepare a successor candidate.');
  const revalidated = await revalidateStoredCandidate(env, row);
  try { await env.DB.batch(cohortScopeFenceStatements(env.DB, revalidated.fences)); }
  catch { reject('Release cohort scope changed during signing; refresh before retrying.'); }
  const signed = await finalizeManifest(env, row, reviewer);
  if (!signed.signature_key || !signed.signature_sha256) reject('Release signing produced no immutable signature.', 503);
  await audit(env.DB, reviewer.id, 'distribution.release_signed', signed.id, { manifestSha256: signed.manifest_sha256, candidateId: row.id }).run();
  return { candidateId: signed.id, manifestSha256: signed.manifest_sha256, signatureKey: signed.signature_key, signatureSha256: signed.signature_sha256 };
}

async function finalizeManifest(env: Env, row: CandidateRow, actor: Actor): Promise<CandidateRow> {
  const manifest = JSON.parse(row.manifest_json) as ReleaseManifest;
  const approvals = row.kind === 'resolved-transaction' ? [] : await assertReleaseApprovals(env.DB, row, manifest.approvals.baseOwners);
  const releaseActors = [...new Set(approvals.filter((item) => item.kind === 'release').map((item) => item.actor))].sort();
  const finalized = row.kind === 'resolved-transaction' ? manifest : { ...manifest, approvals: { ...manifest.approvals, releaseTeam: releaseActors }, changelog: { ...manifest.changelog, approvedBy: releaseActors[0] } };
  const finalizedDigest = await releaseManifestDigest(finalized);
  let signingRow = row;
  if (finalizedDigest !== row.manifest_sha256) {
    const existing = await env.DB.prepare('SELECT * FROM distribution_release_candidates WHERE manifest_sha256=?').bind(finalizedDigest).first<CandidateRow>();
    if (existing) signingRow = existing;
    else {
      const bytes = new TextEncoder().encode(releaseManifestBytes(finalized));
      const manifestKey = `${row.manifest_key.replace(/\/manifest\.json$/, '')}/${finalizedDigest}/manifest.json`;
      await immutableBytes(env, manifestKey, bytes, finalizedDigest, 'application/json');
      const successor: CandidateRow = { ...row, id: id(), manifest_json: releaseManifestBytes(finalized), manifest_sha256: finalizedDigest, manifest_key: manifestKey, manifest_size: bytes.byteLength, status: 'candidate', signature_key: null, signature_sha256: null, signature_intent_id: null };
      await env.DB.prepare(`INSERT INTO distribution_release_candidates
        (id,kind,lane,channel,release_id,sequence,parent_digest,parent_sequence,manifest_json,manifest_sha256,manifest_key,manifest_size,changelog_key,changelog_sha256,status,created_by,created_at)
        VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).bind(successor.id,successor.kind,successor.lane,successor.channel,successor.release_id,successor.sequence,successor.parent_digest,successor.parent_sequence,successor.manifest_json,successor.manifest_sha256,successor.manifest_key,successor.manifest_size,successor.changelog_key,successor.changelog_sha256,successor.status,successor.created_by,successor.created_at).run();
      const oldApprovals = await approvalRows(env.DB, row.id, row.manifest_sha256);
      for (const approval of oldApprovals) await env.DB.prepare(`INSERT INTO distribution_release_approvals(id,candidate_id,manifest_sha256,kind,actor,area,reason,created_at) VALUES(?,?,?,?,?,?,?,?)`).bind(id(), successor.id, finalizedDigest, approval.kind, approval.actor, approval.area, approval.reason, now()).run();
      const objects = await query<{ kind: string; digest: string; object_key: string; size: number }>(env.DB, 'SELECT kind,digest,object_key,size FROM distribution_release_objects WHERE candidate_id=?', row.id);
      for (const object of objects) await env.DB.prepare('INSERT INTO distribution_release_objects(candidate_id,kind,digest,object_key,size) VALUES(?,?,?,?,?)').bind(successor.id, object.kind, object.digest, object.object_key, object.size).run();
      await env.DB.prepare("UPDATE distribution_release_candidates SET status='superseded' WHERE id=? AND status='candidate'").bind(row.id).run();
      signingRow = successor;
    }
  }
  if (signingRow.status === 'signed' && signingRow.signature_key && signingRow.signature_sha256) return signingRow;
  const signed = await requestManifestSignature(env, signingRow, releaseManifestBytes(finalized));
  const signatureKey = signed.signatureKey;
  const signatureSha256 = signed.signatureSha256;
  await env.DB.prepare(`UPDATE distribution_release_candidates SET status='signed',signature_key=?,signature_sha256=?,signature_intent_id=?
    WHERE id=? AND status='candidate' AND manifest_sha256=?`).bind(signatureKey, signatureSha256, signed.intentId, signingRow.id, signingRow.manifest_sha256).run();
  const updated = await env.DB.prepare('SELECT * FROM distribution_release_candidates WHERE id=?').bind(signingRow.id).first<CandidateRow>();
  if (!updated || updated.manifest_sha256 !== signingRow.manifest_sha256 || updated.status !== 'signed') reject('Release signing state changed; retry after refreshing.');
  return updated;
}

function finalManifest(row: CandidateRow): ReleaseManifest {
  return JSON.parse(row.manifest_json) as ReleaseManifest;
}

async function buildResolvedManifest(env: Env, actor: Actor, system: CandidateRow, opr: CandidateRow, parent: { digest: string | null; sequence: number | null }): Promise<{ manifest: ReleaseManifest; row: CandidateRow }> {
  const systemManifest = finalManifest(system); const oprManifest = finalManifest(opr);
  if (systemManifest.channel === 'stable' && oprManifest.channel !== 'stable') reject('Stable system transactions require a stable OPR snapshot.');
  if (system.status !== 'active' && systemManifest.compatibility.oprManifestDigest && systemManifest.compatibility.oprManifestDigest !== opr.manifest_sha256) reject('System candidate is incompatible with active OPR snapshot.');
  if (oprManifest.compatibility.systemManifestDigest && oprManifest.compatibility.systemManifestDigest !== system.manifest_sha256) reject('OPR candidate is incompatible with active system snapshot.');
  if (!systemManifest.compatibility.oprManifestDigest && !oprManifest.compatibility.systemManifestDigest) reject('Resolved transaction needs an explicit system or OPR compatibility binding.');
  const baseReleaseId = `txn-${system.release_id}-${opr.release_id}`.slice(0, 112);
  const existing = await env.DB.prepare("SELECT * FROM distribution_release_candidates WHERE kind='resolved-transaction' AND channel=? AND release_id=? ORDER BY sequence DESC LIMIT 1").bind(systemManifest.channel, baseReleaseId).first<CandidateRow>();
  const existingManifest = existing ? JSON.parse(existing.manifest_json) as ReleaseManifest : null;
  if (existing && existingManifest!.expiresAt > now() && existingManifest!.parent.digest === parent.digest &&
      existingManifest!.parent.sequence === parent.sequence && existingManifest!.sequence === (parent.sequence ?? 0) + 1) {
    return { manifest: existingManifest!, row: existing };
  }
  const releaseId = existing ? `${baseReleaseId}-s${(parent.sequence ?? 0) + 1}`.slice(0, 120) : baseReleaseId;
  const recoveryRequested = systemManifest.recovery.authorized || oprManifest.recovery.authorized;
  let recoveryTarget: ReleaseManifestRef | null = null;
  if (recoveryRequested) {
    if (!parent.digest) reject('Authorized recovery requires an existing resolved transaction target.');
    const prior = await currentManifest(env.DB, parent.digest);
    if (!prior || prior.kind !== 'resolved-transaction') reject('Authorized recovery target is unavailable.');
    const priorManifest = JSON.parse(prior.manifest_json) as ReleaseManifest;
    if (priorManifest.systemManifest?.digest !== system.manifest_sha256 || priorManifest.oprManifest?.digest !== opr.manifest_sha256) reject('Recovery target does not match restored system and OPR selections.');
    recoveryTarget = manifestRef(env, prior);
  }
  const expiresAt = Math.min(now() + configuredLifetime(env, 'DISTRIBUTION_TRANSACTION_EXPIRY_SECONDS', DEFAULT_TRANSACTION_EXPIRY_SECONDS), systemManifest.expiresAt, oprManifest.expiresAt);
  if (!Number.isSafeInteger(expiresAt) || expiresAt <= now()) reject('Resolved transaction inputs are expired.');
  const base = {
    schemaVersion: 1 as const, kind: 'resolved-transaction' as const, lane: 'transaction' as const,
    channel: systemManifest.channel,
    identity: { version: systemManifest.identity.version, generation: oprManifest.identity.generation }, releaseId,
    parent, createdAt: now(), expiresAt,
    sequence: parent.sequence === null ? 1 : parent.sequence + 1, architectures: [...new Set([...systemManifest.architectures, ...oprManifest.architectures])].sort() as Architecture[],
    sourceRefs: [...systemManifest.sourceRefs, ...oprManifest.sourceRefs].sort((a,b) => a.name.localeCompare(b.name)),
    repositories: [...systemManifest.repositories, ...oprManifest.repositories].sort(repositorySort),
    packageChunks: [...systemManifest.packageChunks, ...oprManifest.packageChunks], packageCount: systemManifest.packageCount + oprManifest.packageCount,
    compatibility: { systemManifestDigest: system.manifest_sha256, systemSnapshotDigests: systemManifest.compatibility.systemSnapshotDigests, oprManifestDigest: opr.manifest_sha256 },
    systemManifest: manifestRef(env, system), oprManifest: manifestRef(env, opr), changelog: systemManifest.changelog,
    approvals: { releaseTeam: [...new Set([...systemManifest.approvals.releaseTeam, ...oprManifest.approvals.releaseTeam])].sort(), baseOwners: [...new Set([...systemManifest.approvals.baseOwners, ...oprManifest.approvals.baseOwners])].sort() },
    recovery: { fromDigest: parent.digest, target: recoveryTarget, authorized: recoveryRequested, reason: recoveryRequested ? (systemManifest.recovery.reason ?? oprManifest.recovery.reason) : null, constraints: [...new Set([...systemManifest.recovery.constraints, ...oprManifest.recovery.constraints])].sort() },
    policy: { schemaVersion: 1 as const, version: DISTRIBUTION_RELEASE_POLICY },
  } satisfies ReleaseManifest;
  const manifest = base;
  const manifestSha256 = await releaseManifestDigest(manifest);
  const bytes = new TextEncoder().encode(releaseManifestBytes(manifest)); const key = releaseManifestKey('resolved-transaction', systemManifest.channel, releaseId);
  await immutableBytes(env, key, bytes, await sha256(bytes), 'application/json');
  const idValue = id();
  await env.DB.prepare(`INSERT INTO distribution_release_candidates
    (id,kind,lane,channel,release_id,sequence,parent_digest,parent_sequence,manifest_json,manifest_sha256,manifest_key,manifest_size,changelog_key,changelog_sha256,status,created_by,created_at)
    VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).bind(idValue,'resolved-transaction','transaction',manifest.channel,releaseId,manifest.sequence,parent.digest,parent.sequence,releaseManifestBytes(manifest),manifestSha256,key,bytes.byteLength,system.changelog_key,system.changelog_sha256,'candidate',actor.id,manifest.createdAt).run();
  const row = await env.DB.prepare('SELECT * FROM distribution_release_candidates WHERE id=?').bind(idValue).first<CandidateRow>();
  if (!row) reject('Resolved transaction candidate was not stored.', 503);
  return { manifest, row: row! };
}

export async function activateDistributionRelease(env: Env, actor: Actor | null, candidateId: string, expectedParent?: { digest: string | null; sequence: number | null }): Promise<{ candidateId: string; manifestSha256: string; transactionManifestSha256: string; sequence: number }> {
  const reviewer = await releaseAuthority(env.DB, actor);
  const row = await env.DB.prepare('SELECT * FROM distribution_release_candidates WHERE id=?').bind(text(candidateId, 'Candidate ID', 128)).first<CandidateRow>();
  if (!row || (row.kind !== 'system' && row.kind !== 'opr')) reject('Release candidate not found.', 404);
  if (row.status === 'active') {
    const pointer = await env.DB.prepare('SELECT system_manifest_sha256,sequence FROM distribution_activation_pointers WHERE lane=? AND channel=?').bind(row.lane, row.channel).first<{ system_manifest_sha256: string | null; sequence: number }>();
    const transaction = await activeTransactionFor(env.DB, row);
    return { candidateId: row.id, manifestSha256: row.manifest_sha256, transactionManifestSha256: transaction?.manifest_sha256 ?? row.manifest_sha256, sequence: pointer?.sequence ?? row.sequence };
  }
  if (row.status !== 'signed') reject('Release candidate must be signed before activation.');
  const pointer = await nextSequence(env.DB, row.lane, row.channel);
  if (row.parent_digest !== pointer.digest || (row.parent_sequence ?? null) !== (pointer.sequence || null)) reject('Release candidate parent is stale; prepare a successor candidate.');
  const parent = expectedParent ?? { digest: pointer.digest, sequence: pointer.sequence || null };
  if (parent.digest !== pointer.digest || (parent.sequence ?? null) !== (pointer.sequence || null)) reject('Release activation parent changed; rebase candidate.');
  const manifestInput = JSON.parse(row.manifest_json) as ReleaseManifest;
  if (manifestInput.expiresAt <= now()) reject('Release candidate has expired.');
  await assertReleaseApprovals(env.DB, row, manifestInput.approvals.baseOwners);
  const systemRow = row.kind === 'system' ? row : manifestInput.compatibility.systemManifestDigest ? await currentManifest(env.DB, manifestInput.compatibility.systemManifestDigest) : null;
  const oprRow = row.kind === 'opr' ? row : manifestInput.compatibility.oprManifestDigest
    ? await currentManifest(env.DB, manifestInput.compatibility.oprManifestDigest)
    : systemRow ? await linkedOprManifest(env.DB, systemRow.manifest_sha256, systemRow.channel) : null;
  if (!systemRow || !oprRow) reject('A signed compatible system and OPR counterpart are required before transaction activation.');
  const systemManifest = JSON.parse(systemRow.manifest_json) as ReleaseManifest;
  const oprManifest = JSON.parse(oprRow.manifest_json) as ReleaseManifest;
  if (systemManifest.channel === 'stable' && oprManifest.channel !== 'stable') reject('Stable system transactions require a stable OPR snapshot.');
  if (row.kind === 'opr' && manifestInput.compatibility.systemManifestDigest !== systemRow.manifest_sha256) reject('OPR candidate must target the active system manifest.');
  if (row.kind === 'system' && manifestInput.compatibility.oprManifestDigest && manifestInput.compatibility.oprManifestDigest !== oprRow.manifest_sha256) reject('System candidate must target the active OPR manifest.');
  if (row.kind === 'opr' && systemRow.status !== 'active') reject('OPR activation requires an already active system counterpart.');
  const oprPointer = await nextSequence(env.DB, 'opr', oprRow.channel as typeof OPR_RELEASE_CHANNELS[number]);
  const activatingOprCounterpart = row.kind === 'system' && oprRow.status !== 'active';
  if (row.kind === 'system' && !activatingOprCounterpart && oprPointer.digest !== oprRow.manifest_sha256) reject('System candidate targets an OPR manifest that is not the active pointer.');
  let systemPointer: Awaited<ReturnType<typeof nextSequence>> | null = null;
  if (row.kind === 'opr') {
    systemPointer = await nextSequence(env.DB, 'system', systemRow.channel as SystemReleaseChannel);
    if (systemPointer.digest !== systemRow.manifest_sha256) reject('OPR candidate targets a system manifest that is not the active pointer.');
  }
  if (activatingOprCounterpart && (oprRow.parent_digest !== oprPointer.digest || (oprRow.parent_sequence ?? null) !== (oprPointer.sequence || null))) {
    reject('OPR counterpart parent is stale; prepare a successor candidate.');
  }
  const candidateRevalidation = await revalidateStoredCandidate(env, row);
  const counterpartRevalidation = activatingOprCounterpart ? await revalidateStoredCandidate(env, oprRow) : null;
  const signedRow = await finalizeManifest(env, row, reviewer);
  const signedOpr = activatingOprCounterpart ? await finalizeManifest(env, oprRow, reviewer) : oprRow;
  if (row.kind === 'system' && manifestInput.compatibility.oprManifestDigest && signedOpr.manifest_sha256 !== manifestInput.compatibility.oprManifestDigest) reject('System candidate points to an unfinalized OPR counterpart.');
  const transactionParent = await nextSequence(env.DB, 'transaction', systemRow.channel as SystemReleaseChannel);
  const transaction = await buildResolvedManifest(env, reviewer, row.kind === 'system' ? signedRow : systemRow, row.kind === 'opr' ? signedRow : signedOpr,
    { digest: transactionParent.digest, sequence: transactionParent.sequence || null });
  const signedTransaction = await finalizeManifest(env, transaction.row, reviewer);
  const timestamp = now();
  const counterpartFence = row.kind === 'opr'
    ? [
      env.DB.prepare(`UPDATE distribution_activation_pointers SET updated_at=updated_at
        WHERE lane='system' AND channel=? AND manifest_sha256 IS ? AND sequence=?`).bind(systemRow.channel, systemPointer!.digest, systemPointer!.sequence),
      env.DB.prepare('INSERT INTO distribution_assertions(expected,actual) SELECT 1,changes()'),
    ]
    : !activatingOprCounterpart
      ? [
        env.DB.prepare(`UPDATE distribution_activation_pointers SET updated_at=updated_at
          WHERE lane='opr' AND channel=? AND manifest_sha256 IS ? AND sequence=?`).bind(oprRow.channel, oprPointer.digest, oprPointer.sequence),
        env.DB.prepare('INSERT INTO distribution_assertions(expected,actual) SELECT 1,changes()'),
      ]
      : [];
  const statements: D1PreparedStatement[] = [
    ...cohortScopeFenceStatements(env.DB, [...candidateRevalidation.fences, ...(counterpartRevalidation?.fences ?? [])].filter((fence, index, all) => all.findIndex((item) => item.cohortId === fence.cohortId) === index)),
    env.DB.prepare(`UPDATE distribution_activation_pointers SET release_id=?,manifest_sha256=?,sequence=?,system_manifest_sha256=?,opr_manifest_sha256=?,updated_at=?
      WHERE lane=? AND channel=? AND manifest_sha256 IS ? AND sequence=?`).bind(signedRow.release_id,signedRow.manifest_sha256,signedRow.sequence,systemRow.manifest_sha256,signedOpr.manifest_sha256,timestamp,row.lane,row.channel,pointer.digest,pointer.sequence),
    env.DB.prepare('INSERT INTO distribution_assertions(expected,actual) SELECT 1,changes()'),
    ...counterpartFence,
    ...(activatingOprCounterpart ? [
      env.DB.prepare(`UPDATE distribution_activation_pointers SET release_id=?,manifest_sha256=?,sequence=?,system_manifest_sha256=?,opr_manifest_sha256=?,updated_at=?
        WHERE lane='opr' AND channel=? AND manifest_sha256 IS ? AND sequence=?`).bind(signedOpr.release_id,signedOpr.manifest_sha256,signedOpr.sequence,systemRow.manifest_sha256,signedOpr.manifest_sha256,timestamp,signedOpr.channel,oprPointer.digest,oprPointer.sequence),
      env.DB.prepare('INSERT INTO distribution_assertions(expected,actual) SELECT 1,changes()'),
    ] : []),
    env.DB.prepare(`UPDATE distribution_activation_pointers SET release_id=?,manifest_sha256=?,sequence=?,system_manifest_sha256=?,opr_manifest_sha256=?,updated_at=?
      WHERE lane='transaction' AND channel=? AND manifest_sha256 IS ? AND sequence=?`).bind(signedTransaction.release_id,signedTransaction.manifest_sha256,signedTransaction.sequence,signedRow.kind === 'system' ? signedRow.manifest_sha256 : systemRow.manifest_sha256,signedRow.kind === 'opr' ? signedRow.manifest_sha256 : signedOpr.manifest_sha256,timestamp,systemRow.channel,transactionParent.digest,transactionParent.sequence),
    env.DB.prepare('INSERT INTO distribution_assertions(expected,actual) SELECT 1,changes()'),
    env.DB.prepare("UPDATE distribution_release_candidates SET status='active',activated_at=? WHERE id=? AND status='signed'").bind(timestamp,signedRow.id),
    env.DB.prepare('INSERT INTO distribution_assertions(expected,actual) SELECT 1,changes()'),
    ...(activatingOprCounterpart ? [
      env.DB.prepare("UPDATE distribution_release_candidates SET status='active',activated_at=? WHERE id=? AND status='signed'").bind(timestamp,signedOpr.id),
      env.DB.prepare('INSERT INTO distribution_assertions(expected,actual) SELECT 1,changes()'),
    ] : []),
    env.DB.prepare("UPDATE distribution_release_candidates SET status='active',activated_at=? WHERE id=? AND status='signed'").bind(timestamp,signedTransaction.id),
    env.DB.prepare('INSERT INTO distribution_assertions(expected,actual) SELECT 1,changes()'),
    audit(env.DB, reviewer.id, 'distribution.release_activated', signedRow.id, { manifestSha256: signedRow.manifest_sha256, transactionManifestSha256: signedTransaction.manifest_sha256, parentDigest: pointer.digest, parentSequence: pointer.sequence }),
  ];
  const repositoryLanes = activatingOprCounterpart ? [['system', signedRow.release_id, signedRow.channel], ['opr', signedOpr.release_id, signedOpr.channel]] : [[row.kind, signedRow.release_id, signedRow.channel]];
  for (const [lane, releaseId, channel] of repositoryLanes) {
    const manifest = lane === 'system' ? finalManifest(signedRow) : finalManifest(signedOpr);
    const prepared = await env.DB.prepare(`SELECT
        (SELECT COUNT(*) FROM owned_repository_snapshots WHERE lane=? AND release_id=? AND status IN ('prepared','published')) AS snapshots,
        (SELECT COUNT(*) FROM owned_repository_package_chunks WHERE lane=? AND release_id=? AND status IN ('prepared','published')) AS chunks,
        (SELECT COUNT(*) FROM owned_repository_universes WHERE lane=? AND release_id=? AND status IN ('prepared','published')) AS universes`).bind(lane, releaseId, lane, releaseId, lane, releaseId).first<{ snapshots: number; chunks: number; universes: number }>();
    if (!prepared || prepared.snapshots < manifest.repositories.length || prepared.chunks < 1 || prepared.universes < 1) reject(`Owned ${lane} repository objects are incomplete for ${releaseId}.`);
    statements.push(env.DB.prepare("UPDATE owned_repository_snapshots SET status='published' WHERE lane=? AND release_id=? AND status='prepared'").bind(lane, releaseId));
    statements.push(env.DB.prepare("UPDATE owned_repository_package_chunks SET status='published' WHERE lane=? AND release_id=? AND status='prepared'").bind(lane, releaseId));
    statements.push(env.DB.prepare("UPDATE owned_repository_universes SET status='published' WHERE lane=? AND release_id=? AND status='prepared'").bind(lane, releaseId));
    statements.push(env.DB.prepare(`INSERT OR IGNORE INTO owned_repository_memberships(id,snapshot_id,lane,release_id,channel,status,created_at)
      SELECT lower(hex(randomblob(16))),id,?,?,?,'active',? FROM owned_repository_snapshots
      WHERE lane=? AND release_id=? AND status IN ('prepared','published')`).bind(lane, releaseId, channel, timestamp, lane, releaseId));
  }
  try { await env.DB.batch(statements); } catch (cause) { if (cause instanceof Error && /distribution_assertions|constraint/i.test(cause.message)) reject('Release parent changed during activation; retry after refreshing.'); throw cause; }
  return { candidateId: signedRow.id, manifestSha256: signedRow.manifest_sha256, transactionManifestSha256: signedTransaction.manifest_sha256, sequence: signedRow.sequence };
}

/** Renew short-lived resolved control for the unchanged active system/OPR pair. Leaves stay immutable. */
export async function renewResolvedTransaction(env: Env, actor: Actor | null, channel: SystemReleaseChannel = 'stable', expectedParent?: { digest: string | null; sequence: number | null }): Promise<{ candidateId: string; manifestSha256: string; sequence: number }> {
  const reviewer = await releaseAuthority(env.DB, actor);
  const system = await getActiveDistributionRelease(env.DB, 'system', channel);
  const activeTransaction = await getActiveDistributionRelease(env.DB, 'transaction', channel);
  const systemManifest = system ? JSON.parse(system.candidate.manifest_json) as ReleaseManifest : null;
  const transactionSystemDigest = activeTransaction?.manifest.systemManifest?.digest ?? activeTransaction?.manifest.compatibility.systemManifestDigest ?? null;
  const transactionOprDigest = activeTransaction?.manifest.oprManifest?.digest ?? activeTransaction?.manifest.compatibility.oprManifestDigest ?? null;
  if (!system || !activeTransaction || transactionSystemDigest !== system.candidate.manifest_sha256 || !transactionOprDigest) {
    reject('A published system and its exact active transaction pair are required before transaction renewal.');
  }
  const opr = await currentManifest(env.DB, transactionOprDigest);
  if (!opr || opr.status !== 'active') reject('The exact OPR counterpart of the active transaction is unavailable.');
  const systemPointer = await nextSequence(env.DB, 'system', channel);
  const oprPointer = await nextSequence(env.DB, 'opr', opr.channel as typeof OPR_RELEASE_CHANNELS[number]);
  if (systemPointer.digest !== system.candidate.manifest_sha256 || oprPointer.digest !== opr.manifest_sha256) reject('The active transaction pair changed; refresh before renewal.');
  const pointer = await nextSequence(env.DB, 'transaction', channel);
  const parent = expectedParent ?? { digest: pointer.digest, sequence: pointer.sequence || null };
  if (parent.digest !== pointer.digest || (parent.sequence ?? null) !== (pointer.sequence || null)) reject('Transaction renewal parent changed; refresh before retrying.');
  const active = pointer.digest ? await currentManifest(env.DB, pointer.digest) : null;
  if (active) {
    const current = JSON.parse(active.manifest_json) as ReleaseManifest;
    if (current.expiresAt > now() && active.status === 'active') return { candidateId: active.id, manifestSha256: active.manifest_sha256, sequence: active.sequence };
  }
  const transaction = await buildResolvedManifest(env, reviewer, system.candidate, opr, parent);
  const signed = await finalizeManifest(env, transaction.row, reviewer);
  const timestamp = now();
  const statements: D1PreparedStatement[] = [
    env.DB.prepare(`UPDATE distribution_activation_pointers SET updated_at=updated_at
      WHERE lane='system' AND channel=? AND manifest_sha256 IS ? AND sequence=?`).bind(channel, systemPointer.digest, systemPointer.sequence),
    env.DB.prepare('INSERT INTO distribution_assertions(expected,actual) SELECT 1,changes()'),
    env.DB.prepare(`UPDATE distribution_activation_pointers SET updated_at=updated_at
      WHERE lane='opr' AND channel=? AND manifest_sha256 IS ? AND sequence=?`).bind(opr.channel, oprPointer.digest, oprPointer.sequence),
    env.DB.prepare('INSERT INTO distribution_assertions(expected,actual) SELECT 1,changes()'),
    env.DB.prepare(`UPDATE distribution_activation_pointers SET release_id=?,manifest_sha256=?,sequence=?,system_manifest_sha256=?,opr_manifest_sha256=?,updated_at=?
      WHERE lane='transaction' AND channel=? AND manifest_sha256 IS ? AND sequence=?`).bind(signed.release_id,signed.manifest_sha256,signed.sequence,system.candidate.manifest_sha256,opr.manifest_sha256,timestamp,systemManifest!.channel,pointer.digest,pointer.sequence),
    env.DB.prepare('INSERT INTO distribution_assertions(expected,actual) SELECT 1,changes()'),
    env.DB.prepare("UPDATE distribution_release_candidates SET status='active',activated_at=? WHERE id=? AND status='signed'").bind(timestamp,signed.id),
    env.DB.prepare('INSERT INTO distribution_assertions(expected,actual) SELECT 1,changes()'),
    audit(env.DB, reviewer.id, 'distribution.transaction_renewed', signed.id, { manifestSha256: signed.manifest_sha256, parentDigest: pointer.digest, parentSequence: pointer.sequence }),
  ];
  try { await env.DB.batch(statements); } catch (cause) { if (cause instanceof Error && /distribution_assertions|constraint/i.test(cause.message)) reject('Transaction parent changed during renewal; retry after refreshing.'); throw cause; }
  return { candidateId: signed.id, manifestSha256: signed.manifest_sha256, sequence: signed.sequence };
}

export async function getDistributionRelease(db: D1Database, releaseId: string, channel: DistributionReleaseChannel = 'stable'): Promise<{ candidate: CandidateRow; manifest: ReleaseManifest; signatureKey: string | null; signatureSha256: string | null } | null> {
  const row = await db.prepare('SELECT * FROM distribution_release_candidates WHERE release_id=? AND channel=? AND status IN (\'signed\',\'active\') ORDER BY sequence DESC LIMIT 1').bind(text(releaseId, 'Release identity', 128), channel).first<CandidateRow>();
  return row ? { candidate: row, manifest: JSON.parse(row.manifest_json) as ReleaseManifest, signatureKey: row.signature_key, signatureSha256: row.signature_sha256 } : null;
}

export async function getActiveDistributionRelease(db: D1Database, lane: 'system' | 'opr' | 'transaction', channel: DistributionReleaseChannel = 'stable'): Promise<{ candidate: CandidateRow; manifest: ReleaseManifest } | null> {
  const pointer = await db.prepare('SELECT manifest_sha256 FROM distribution_activation_pointers WHERE lane=? AND channel=?').bind(lane, channel).first<{ manifest_sha256: string | null }>();
  if (!pointer?.manifest_sha256) return null;
  const row = await db.prepare('SELECT * FROM distribution_release_candidates WHERE manifest_sha256=? AND status=\'active\' LIMIT 1').bind(pointer.manifest_sha256).first<CandidateRow>();
  return row ? { candidate: row, manifest: JSON.parse(row.manifest_json) as ReleaseManifest } : null;
}

export async function distributionManifestObject(env: Env, releaseId: string, kind: DistributionReleaseKind, signature = false, channel: DistributionReleaseChannel = 'stable'): Promise<Response | null> {
  const row = await env.DB.prepare('SELECT manifest_key,signature_key FROM distribution_release_candidates WHERE release_id=? AND kind=? AND channel=? AND status IN (\'signed\',\'active\') ORDER BY sequence DESC LIMIT 1')
    .bind(text(releaseId, 'Release identity', 128), kind, channel).first<{ manifest_key: string; signature_key: string | null }>();
  const key = signature ? row?.signature_key : row?.manifest_key;
  if (!key) return null;
  const object = await env.ARTIFACTS.get(key);
  return object ? new Response(object.body, { headers: { 'Content-Type': signature ? 'application/octet-stream' : 'application/json', 'Cache-Control': 'public, max-age=31536000, immutable' } }) : null;
}

export async function currentDistributionManifestObject(env: Env, signature = false, channel: SystemReleaseChannel = 'stable'): Promise<Response | null> {
  const pointer = await env.DB.prepare("SELECT release_id FROM distribution_activation_pointers WHERE lane='transaction' AND channel=? AND manifest_sha256 IS NOT NULL").bind(channel).first<{ release_id: string }>();
  if (!pointer) return null;
  return distributionManifestObject(env, pointer.release_id, 'resolved-transaction', signature, channel);
}
