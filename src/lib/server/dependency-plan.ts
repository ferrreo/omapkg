import type { Architecture } from '../model';
import * as v from 'valibot';
import type { Env } from './env';
import { query, sha256 } from './db';
import {
  compareArchVersions,
  parseArchDependency,
  parseArchRelation,
  parsePackageMetadata,
  satisfiesArchRelation,
  type PackageMetadata,
} from './arch';

const ID = /^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/;

const NAME = /^[a-z0-9][a-z0-9@._+-]{0,63}$/;

const VERSION = /^(?:[0-9]+:)?[A-Za-z0-9][A-Za-z0-9@._+%~^:-]{0,127}$/;

const FILENAME = /^[A-Za-z0-9][A-Za-z0-9._+:-]{0,220}\.pkg\.tar\.zst$/;

const SHA256 = /^[a-f0-9]{64}$/;

const FINGERPRINT = /^[a-f0-9]{40}$/;

const MAX_PACKAGES = 64;

const MAX_PACKAGE_BYTES = 4 * 1024 * 1024 * 1024;

const MAX_PLAN_BYTES = 8 * 1024 * 1024 * 1024;

const MAX_SIGNATURE_BYTES = 1024 * 1024;

export type DependencyPlanPackage = {
  releaseId: string;
  name: string;
  version: string;
  architecture: Architecture;
  filename: string;
  url: string;
  sha256: string;
  size: number;
  signatureUrl: string;
  signatureSha256: string;
};

export type DependencyPlan = {
  channel: 'stable' | 'dev';
  publicKeyUrl: string;
  publicKeyFingerprint: string;
  packages: DependencyPlanPackage[];
  runtimeReleaseIds?: string[];
};

type PublishedRow = {
  release_id: string;
  name: string;
  version: string;
  architecture: Architecture;
  channel: 'stable' | 'dev';
  artifact_key: string | null;
  signature_key: string | null;
  artifact_sha256: string | null;
  artifact_size: number | null;
  artifact_filename: string | null;
  provenance: string | null;
  published_at: number;
};

type PublishedPackage = { row: PublishedRow; metadata: PackageMetadata };

const packageSchema = v.strictObject({
  releaseId: v.pipe(v.string(), v.regex(ID)),
  name: v.pipe(v.string(), v.regex(NAME)),
  version: v.pipe(v.string(), v.regex(VERSION)),
  architecture: v.picklist(['x86_64', 'aarch64']),
  filename: v.pipe(v.string(), v.regex(FILENAME)),
  url: v.string(),
  sha256: v.pipe(v.string(), v.regex(SHA256)),
  size: v.pipe(v.number(), v.integer(), v.minValue(1), v.maxValue(MAX_PACKAGE_BYTES)),
  signatureUrl: v.string(),
  signatureSha256: v.pipe(v.string(), v.regex(SHA256)),
});

const dependencyPlanSchema = v.strictObject({
  channel: v.picklist(['stable', 'dev']),
  publicKeyUrl: v.string(),
  publicKeyFingerprint: v.pipe(v.string(), v.regex(FINGERPRINT)),
  packages: v.pipe(v.array(packageSchema), v.minLength(1), v.maxLength(MAX_PACKAGES)),
  runtimeReleaseIds: v.optional(v.array(v.string())),
});

export function parseDependencyPlan(value: unknown): DependencyPlan | null {
  const parsedInput = v.safeParse(dependencyPlanSchema, value);

  if (!parsedInput.success) return null;
  const object = parsedInput.output;
  const parsed = object.packages.map((item) => ({ ...item, filename: item.filename }));

  if (parsed.some((item) => item.filename !== `${item.name}-${item.version}-${item.architecture}.pkg.tar.zst` || compareArchVersions(item.version, item.version) === null)) return null;

  if (new Set(parsed.map((item) => item.releaseId)).size !== parsed.length ||
      new Set(parsed.map((item) => `${item.name}:${item.architecture}`)).size !== parsed.length) return null;

  if (object.runtimeReleaseIds !== undefined && (new Set(object.runtimeReleaseIds).size !== object.runtimeReleaseIds.length ||
      object.runtimeReleaseIds.some((id) => !parsed.some((item) => item.releaseId === id)))) return null;

  const result = {
    channel: object.channel,
    publicKeyUrl: object.publicKeyUrl,
    publicKeyFingerprint: object.publicKeyFingerprint,
    packages: parsed,
  };

  if (object.runtimeReleaseIds !== undefined) Object.assign(result, { runtimeReleaseIds: object.runtimeReleaseIds });

  return result;
}

function planPayload(plan: DependencyPlan): string {
  const result = {
    channel: plan.channel,
    publicKeyUrl: plan.publicKeyUrl,
    publicKeyFingerprint: plan.publicKeyFingerprint,
    packages: plan.packages.map((item) => ({
      releaseId: item.releaseId, name: item.name, version: item.version, architecture: item.architecture,
      filename: item.filename, url: item.url, sha256: item.sha256, size: item.size,
      signatureUrl: item.signatureUrl, signatureSha256: item.signatureSha256,
    })),
  };

  if (plan.runtimeReleaseIds !== undefined) Object.assign(result, { runtimeReleaseIds: plan.runtimeReleaseIds });

  return JSON.stringify(result);
}

export function canonicalDependencyPlan(plan: DependencyPlan): string {
  return planPayload(plan);
}

export async function dependencyPlanDigest(plan: DependencyPlan | null): Promise<string | null> {
  return plan ? sha256(new TextEncoder().encode(planPayload(plan))) : null;
}

export function dependencyPlansEqual(left: DependencyPlan | null, right: DependencyPlan | null): boolean {
  return left === null && right === null || left !== null && right !== null && planPayload(left) === planPayload(right);
}

function jsonObject(value: string): Record<string, unknown> | null {
  try {
    const parsed: unknown = JSON.parse(value);

    return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed as Record<string, unknown> : null;
  } catch {
    return null;
  }
}

function metadata(row: PublishedRow): PackageMetadata | null {
  const object = row.provenance ? jsonObject(row.provenance) : null;
  const parsed = parsePackageMetadata(object?.packageMetadata);
  const artifactSize = row.artifact_size;
  const artifactFilename = row.artifact_filename;

  if (!parsed || parsed.name !== row.name || parsed.fullVersion !== row.version || parsed.architecture !== row.architecture ||
      !row.artifact_key || row.artifact_key !== `packages/${row.architecture}/${artifactFilename ?? ''}` ||
      !row.signature_key || !row.artifact_sha256 || !SHA256.test(row.artifact_sha256) ||
      !artifactFilename || !FILENAME.test(artifactFilename) || artifactSize === null || !Number.isSafeInteger(artifactSize) ||
      artifactSize < 1 || artifactSize > MAX_PACKAGE_BYTES) return null;

  return parsed;
}

function dependencyText(value: string): string {
  return value;
}

function origin(env: Pick<Env, 'PUBLIC_ORIGIN'>): string {
  let url: URL;

  try { url = new URL(env.PUBLIC_ORIGIN); }
  catch { throw new Error('public HTTPS origin is not configured'); }

  if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash) throw new Error('public HTTPS origin is not configured');

  return url.toString().replace(/\/$/, '');
}

function candidateOrder(left: PublishedPackage, right: PublishedPackage): number {
  if (left.row.channel !== right.row.channel) return left.row.channel === 'stable' ? -1 : 1;
  const version = compareArchVersions(right.row.version, left.row.version);

  if (version !== null && version !== 0) return version;

  if (left.row.published_at !== right.row.published_at) return right.row.published_at - left.row.published_at;

  return left.row.release_id.localeCompare(right.row.release_id);
}

async function packageReference(env: Pick<Env, 'ARTIFACTS' | 'PUBLIC_ORIGIN'>, item: PublishedPackage): Promise<DependencyPlanPackage> {
  const { row } = item;
  const artifactKey = row.artifact_key!;
  const artifact = await env.ARTIFACTS.head(artifactKey);

  if (!artifact || artifact.size !== row.artifact_size || artifact.customMetadata?.sha256 && artifact.customMetadata.sha256 !== row.artifact_sha256) {
    throw new Error(`published dependency artifact ${row.release_id} is unavailable or changed`);
  }

  const signatureKey = row.signature_key!;
  const signature = await env.ARTIFACTS.get(signatureKey);

  if (!signature) throw new Error(`published dependency signature ${row.release_id} is unavailable`);

  if (!Number.isSafeInteger(signature.size) || signature.size < 1 || signature.size > MAX_SIGNATURE_BYTES) {
    throw new Error(`published dependency signature ${row.release_id} is invalid`);
  }

  const signatureBytes = new Uint8Array(await signature.arrayBuffer());

  if (signatureBytes.length !== signature.size) throw new Error(`published dependency signature ${row.release_id} changed during read`);
  const publicOrigin = origin(env);
  const prefix = row.channel === 'stable' ? `${publicOrigin}/repo` : `${publicOrigin}/repo/dev`;
  const filename = row.artifact_filename!;

  return {
    releaseId: row.release_id,
    name: row.name,
    version: row.version,
    architecture: row.architecture,
    filename,
    url: `${prefix}/${row.architecture}/${encodeURIComponent(filename)}`,
    sha256: row.artifact_sha256!,
    size: row.artifact_size!,
    signatureUrl: `${prefix}/${row.architecture}/${encodeURIComponent(filename)}.sig`,
    signatureSha256: await sha256(signatureBytes),
  };
}

export async function planDependencies(
  env: Pick<Env, 'DB' | 'ARTIFACTS' | 'PUBLIC_ORIGIN'> & { PACKAGE_SIGNING_FINGERPRINT?: string; SIGNING_FINGERPRINT?: string },
  input: { architecture: Architecture; dependencies: readonly string[]; makeDependencies: readonly string[] },
): Promise<{ plan: DependencyPlan | null; digest: string | null; releaseIds: string[] }> {
  const requested = [...input.dependencies, ...input.makeDependencies];

  if (!requested.length) return { plan: null, digest: null, releaseIds: [] };

  const rows = await query<PublishedRow>(env.DB, `SELECT r.id AS release_id,r.name,r.version,r.architecture,r.channel,
      r.artifact_key,r.signature_key,b.artifact_sha256,b.artifact_size,b.artifact_filename,b.provenance,r.published_at
    FROM releases r JOIN builds b ON b.id=r.build_id JOIN revisions v ON v.id=b.revision_id
    WHERE r.surface='binary' AND r.channel IN ('stable','dev') AND b.status='succeeded'
      AND (r.channel='stable' OR (EXISTS (SELECT 1 FROM approvals a WHERE a.revision_id=v.id AND a.kind='area' AND a.manifest_sha256=v.manifest_sha256 AND a.revoked_at IS NULL)
        AND EXISTS (SELECT 1 FROM approvals a WHERE a.revision_id=v.id AND a.kind='security' AND a.manifest_sha256=v.manifest_sha256 AND a.revoked_at IS NULL)))`,);

  const published = rows.map((row) => {
    const parsed = metadata(row);

    return parsed ? { row, metadata: parsed } : null;
  }).filter((value): value is PublishedPackage => value !== null);

  const knownNames = new Set(rows.map((row) => row.name));

  for (const item of published) for (const value of item.metadata.provides) {
    const relation = parseArchRelation(value);

    if (relation) knownNames.add(relation.name);
  }

  const selected = new Map<string, PublishedPackage>();
  const selectedByName = new Map<string, PublishedPackage>();

  const providers = (dependency: ReturnType<typeof parseArchRelation>) => published
    .filter((item) => item.row.architecture === input.architecture && dependency && satisfiesArchRelation(dependency, item.metadata))
    .sort(candidateOrder);

  const checkConflicts = (candidate: PublishedPackage) => {
    for (const existing of selected.values()) {
      for (const value of candidate.metadata.conflicts) {
        const relation = parseArchDependency(dependencyText(value));

        if (!relation) throw new Error(`published dependency ${candidate.row.name} has invalid conflict metadata`);

        if (satisfiesArchRelation(relation, existing.metadata)) {
          throw new Error(`published dependencies ${candidate.row.name} and ${existing.row.name} conflict`);
        }
      }

      for (const value of existing.metadata.conflicts) {
        const relation = parseArchDependency(dependencyText(value));

        if (!relation) throw new Error(`published dependency ${existing.row.name} has invalid conflict metadata`);

        if (satisfiesArchRelation(relation, candidate.metadata)) {
          throw new Error(`published dependencies ${candidate.row.name} and ${existing.row.name} conflict`);
        }
      }
    }
  };

  const resolve = (value: string, owner: string): void => {
    const text = dependencyText(value);
    const dependency = parseArchRelation(text);

    if (!dependency) throw new Error(`Invalid Arch dependency ${text} in ${owner}`);

    if (!knownNames.has(dependency.name)) return;
    const existing = [...selected.values()].find((item) => item.row.architecture === input.architecture && satisfiesArchRelation(dependency, item.metadata));

    if (existing) return;
    const candidate = providers(dependency)[0];

    if (!candidate) throw new Error(`Known omapkg dependency ${text} is not satisfied for ${input.architecture}`);
    const sameName = selectedByName.get(candidate.row.name);

    if (sameName && sameName.row.release_id !== candidate.row.release_id) throw new Error(`Multiple versions of omapkg dependency ${candidate.row.name} are required`);

    if (!selected.has(candidate.row.release_id)) {
      if (selected.size >= MAX_PACKAGES) throw new Error('omapkg dependency plan exceeds 64 packages');
      checkConflicts(candidate);
      selected.set(candidate.row.release_id, candidate);
      selectedByName.set(candidate.row.name, candidate);

      for (const nested of candidate.metadata.depends) resolve(nested, candidate.row.name);
    }
  };

  for (const dependency of input.dependencies) resolve(dependency, 'reviewed runtime');
  const runtimeReleaseIds = [...selected.keys()];

  for (const dependency of input.makeDependencies) resolve(dependency, 'reviewed build');

  if (!selected.size) return { plan: null, digest: null, releaseIds: [] };
  const fingerprint = (env.PACKAGE_SIGNING_FINGERPRINT ?? env.SIGNING_FINGERPRINT ?? '').toLowerCase();

  if (!FINGERPRINT.test(fingerprint)) throw new Error('package signing fingerprint is not configured');
  const publicOrigin = origin(env);
  const references: DependencyPlanPackage[] = [];
  let total = 0;

  for (const item of selected.values()) {
    if (item.row.artifact_size === null || item.row.artifact_size < 1 || item.row.artifact_size > MAX_PACKAGE_BYTES ||
        total > MAX_PLAN_BYTES - item.row.artifact_size) throw new Error('omapkg dependency plan exceeds 8 GiB');
    total += item.row.artifact_size;
    references.push(await packageReference(env, item));
  }

  const plan: DependencyPlan = {
    channel: references.some((item) => selected.get(item.releaseId)?.row.channel === 'dev') ? 'dev' : 'stable',
    publicKeyUrl: `${publicOrigin}/repo/key.asc`,
    publicKeyFingerprint: fingerprint,
    packages: references,
    runtimeReleaseIds,
  };

  const parsed = parseDependencyPlan(plan);

  if (!parsed) throw new Error('generated dependency plan is invalid');

  return { plan: parsed, digest: await dependencyPlanDigest(parsed), releaseIds: references.map((item) => item.releaseId) };
}
