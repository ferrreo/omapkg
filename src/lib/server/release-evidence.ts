import { signingURL } from '../signing-url';
import type { Build, Architecture, Revision } from '../model';
import { type PackageMetadata, isArchPkgver, parsePackageMetadata, archRelationCovers } from './arch';
import { type DependencyPlan, parseDependencyPlan, dependencyPlansEqual } from './dependency-plan';
import { PolicyError, revisionImage, validateRevision } from './policy';
import type { Env } from './env';
import { query, id, now } from './db';
import { fail, jsonObject, jsonArray, BASE64, decodeBase64, safeKey, SAFE_KEY, SHA256 } from './release-storage';

type JoinedBuild = {
  build_id: string;
  build_status: Build['status'];
  build_architecture: Architecture;
  worker_id: string | null;
  artifact_key: string | null;
  artifact_sha256: string | null;
  artifact_size: number | null;
  installed_size: number | null;
  dependency_plan_json: string | null;
  artifact_filename: string | null;
  provenance: string | null;
  package_metadata?: PackageMetadata;
  provenance_signature: string | null;
  smoke_passed: number;
  revision_id: string;
  request_id: string;
  request_name: string;
  request_status: string;
  area: string;
  revision_version: string;
  recipe: string;
  recipe_sha256: string;
  public_recipe?: string | null;
  public_recipe_sha256?: string | null;
  manifest_sha256: string;
  sources_json: string;
  dependencies_json: string;
  make_dependencies_json?: string | null;
  smoke_commands_json: string;
  architectures_json: string;
  build_images_json?: string | null;
  pkgrel?: number | null;
  source_date_epoch: number;
  image_digest: string;
  license: string;
  surface: Revision['surface'];
  description?: string | null;
  explanation: string;
  sbom_json: string;
  lint_json: string;
  upstream_commit: string | null;
  pr_url: string | null;
  commit_sha: string | null;
  upstream_url: string;
};

type SignatureResult = { signatureKey: string; signatureSha256: string };

function recipeAssignment(recipe: string, name: 'pkgname' | 'pkgver' | 'pkgrel'): string {
  const match = recipe.match(new RegExp(`^${name}=([^\\r\\n]+)$`, 'm'));
  if (!match) fail(409, `Reviewed recipe is missing ${name}.`);
  const value = match[1].trim();
  if ((value.startsWith("'") && value.endsWith("'")) || (value.startsWith('"') && value.endsWith('"'))) return value.slice(1, -1);
  return value;
}

export function packageVersion(build: JoinedBuild, filename: string | null): string {
  const pkgname = recipeAssignment(build.recipe, 'pkgname');
  const pkgver = recipeAssignment(build.recipe, 'pkgver');
  const pkgrel = recipeAssignment(build.recipe, 'pkgrel');
  const reviewedPkgrel = build.pkgrel ?? Number(pkgrel);
  if (pkgname !== build.request_name || pkgver !== build.revision_version ||
      !Number.isSafeInteger(reviewedPkgrel) || reviewedPkgrel < 1 || reviewedPkgrel > 9_999 || Number(pkgrel) !== reviewedPkgrel ||
      !isArchPkgver(pkgver)) {
    fail(409, 'Reviewed package version metadata does not match the revision.');
  }
  const version = `${pkgver}-${reviewedPkgrel}`;
  if (filename && filename !== `${pkgname}-${version}-${build.build_architecture}.pkg.tar.zst`) {
    fail(409, 'Package filename does not match reviewed pkgname, pkgver, pkgrel and architecture.');
  }
  return version;
}

function fullPackageVersion(version: string, pkgrel: number | null | undefined): string {
  const release = pkgrel ?? 1;
  return version.endsWith(`-${release}`) ? version : `${version}-${release}`;
}

function packageMetadataFromValue(
  value: unknown,
  expected: { name: string; version: string; architecture: Architecture; installedSize: number | null },
): PackageMetadata {
  const metadata = parsePackageMetadata(value);
  if (!metadata || metadata.name !== expected.name || metadata.fullVersion !== expected.version ||
      metadata.architecture !== expected.architecture || expected.installedSize === null || metadata.installedSize !== expected.installedSize) {
    fail(409, 'Native package metadata does not match reviewed build.');
  }
  return metadata;
}

export function packageMetadataFromProvenance(
  provenance: string | null,
  expected: { name: string; version: string; architecture: Architecture; installedSize: number | null },
): PackageMetadata {
  if (!provenance) fail(409, 'Build provenance is missing native package metadata.');
  return packageMetadataFromValue(jsonObject(provenance, 'Build provenance').packageMetadata, expected);
}

function storedDependencyPlan(value: string | null | undefined): DependencyPlan | null {
  if (value === null || value === undefined) return null;
  try {
    const plan = parseDependencyPlan(JSON.parse(value));
    if (!plan) fail(409, 'Stored OPR dependency plan is invalid.');
    return plan;
  } catch (cause) {
    if (cause instanceof PolicyError) throw cause;
    fail(409, 'Stored OPR dependency plan is invalid.');
  }
}

export function hasPrivateSource(env: Env, sourcesJSON: string): boolean {
  let origin: URL;
  try { origin = new URL(env.PUBLIC_ORIGIN); }
  catch { return false; }
  try {
    return jsonArray(sourcesJSON, 'Source manifest').some((value) => {
      if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
      const url = (value as { url?: unknown }).url;
      if (typeof url !== 'string') return false;
      try {
        const source = new URL(url);
        return source.origin === origin.origin && /^\/sources\/[a-f0-9]{64}\.tar$/.test(source.pathname) && !source.search && !source.hash;
      } catch { return false; }
    });
  } catch { return false; }
}

export function hasPrivateSourceReference(env: Env, recipe: string): boolean {
  try {
    const origin = new URL(env.PUBLIC_ORIGIN).origin;
    return recipe.includes(`${origin}/sources/`);
  } catch { return false; }
}

export async function joinedBuild(env: Env, buildId: string): Promise<JoinedBuild> {
  const row = await env.DB.prepare(`
    SELECT b.id AS build_id, b.status AS build_status, b.architecture AS build_architecture,
      b.worker_id, b.artifact_key, b.artifact_sha256, b.artifact_size, b.installed_size, b.dependency_plan_json, b.artifact_filename,
      b.provenance, b.provenance_signature, b.smoke_passed,
      v.*, v.id AS revision_id, v.version AS revision_version,
      v.manifest_sha256, v.sources_json, v.dependencies_json, v.smoke_commands_json,
      v.architectures_json, v.source_date_epoch, v.image_digest, v.license, v.surface,
      v.sbom_json, v.lint_json, v.upstream_commit, v.pr_url, v.commit_sha,
      q.name AS request_name, q.status AS request_status, q.area, q.upstream_url
    FROM builds b
    JOIN revisions v ON v.id = b.revision_id
    JOIN requests q ON q.id = v.request_id
    WHERE b.id=?`).bind(buildId).first<JoinedBuild>();
  if (!row) fail(404, 'Build not found.');
  return row;
}

export async function assertAttestation(build: JoinedBuild, env: Env) {
  if (!build.provenance || !build.provenance_signature || !BASE64.test(build.provenance_signature)) {
    fail(409, 'A worker-signed provenance attestation is required.');
  }
  if (!build.worker_id) fail(409, 'A registered worker attestation is required.');
  const worker = await env.DB.prepare('SELECT public_key,status FROM workers WHERE id=?').bind(build.worker_id).first<{ public_key: string; status: 'active' | 'revoked' }>();
  if (!worker || worker.status !== 'active') fail(409, 'The build worker is no longer active.');
  const publicKey = decodeBase64(worker.public_key, 32, 'Worker public key');
  const signature = decodeBase64(build.provenance_signature, 64, 'Provenance signature');
  const provenance = jsonObject(build.provenance, 'Build provenance');
  if (build.surface === 'binary') {
    const metadata = packageMetadataFromValue(provenance.packageMetadata, {
      name: build.request_name,
      version: fullPackageVersion(build.revision_version, build.pkgrel),
      architecture: build.build_architecture,
      installedSize: build.installed_size,
    });
    const reviewedDependencies = jsonArray(build.dependencies_json, 'Dependency manifest');
    if (reviewedDependencies.some((reviewed) => typeof reviewed !== 'string' || !metadata.depends.some((native) => archRelationCovers(native, reviewed)))) {
      fail(409, 'Native package metadata does not contain reviewed dependencies.');
    }
  }
  let imageDigest: string;
  try {
    imageDigest = revisionImage(build, build.build_architecture).split('@').at(-1) ?? build.image_digest;
  } catch (cause) {
    if (cause instanceof PolicyError) throw cause;
    fail(409, 'Builder image is invalid for this architecture.');
  }
  const expected: Array<[string, unknown]> = [
    ['buildId', build.build_id], ['revisionId', build.revision_id], ['workerId', build.worker_id], ['architecture', build.build_architecture],
    ['recipeSha256', build.recipe_sha256], ['imageDigest', imageDigest],
    ['sourceDateEpoch', build.source_date_epoch], ['network', 'disabled'],
  ];
  for (const [field, value] of expected) if (provenance[field] !== value) fail(409, `Build provenance field ${field} does not match reviewed inputs.`);
  if (provenance.pkgrel !== undefined && provenance.pkgrel !== (build.pkgrel ?? 1)) fail(409, 'Build provenance field pkgrel does not match reviewed inputs.');
  if (provenance.artifactSha256 !== build.artifact_sha256 && build.surface === 'binary') {
    fail(409, 'Build provenance artifact digest does not match uploaded bytes.');
  }
  if (build.surface === 'recipe' && provenance.artifactSha256 !== null && typeof provenance.artifactSha256 !== 'string') {
    fail(409, 'Build provenance recipe artifact digest is invalid.');
  }
  let actualDependencyPlan: DependencyPlan | null = null;
  if (provenance.dependencyPlan !== undefined && provenance.dependencyPlan !== null) {
    actualDependencyPlan = parseDependencyPlan(provenance.dependencyPlan);
    if (!actualDependencyPlan) fail(409, 'Build provenance dependency plan is invalid.');
  }
  if (!dependencyPlansEqual(storedDependencyPlan(build.dependency_plan_json), actualDependencyPlan)) {
    fail(409, 'Build provenance dependency plan does not match the lease.');
  }
  const sources = jsonArray(build.sources_json, 'Source manifest');
  if (JSON.stringify(provenance.sources) !== JSON.stringify(sources)) fail(409, 'Build provenance source manifest does not match reviewed inputs.');
  try {
    const key = await crypto.subtle.importKey('raw', publicKey as BufferSource, { name: 'Ed25519' }, false, ['verify']);
    if (!await crypto.subtle.verify('Ed25519', key, signature as BufferSource, new TextEncoder().encode(build.provenance) as BufferSource)) {
      fail(409, 'Worker provenance signature is invalid.');
    }
  } catch (cause) {
    if (cause instanceof PolicyError) throw cause;
    fail(409, 'Worker provenance signature is invalid.');
  }
}

export async function assertReviewed(build: JoinedBuild, env: Env) {
  try {
    await validateRevision({
      id: build.revision_id, request_id: build.request_id, version: build.revision_version, recipe: build.recipe,
      recipe_sha256: build.recipe_sha256, public_recipe: build.public_recipe, public_recipe_sha256: build.public_recipe_sha256,
      manifest_sha256: build.manifest_sha256, sources_json: build.sources_json,
      dependencies_json: build.dependencies_json, make_dependencies_json: build.make_dependencies_json, smoke_commands_json: build.smoke_commands_json,
      architectures_json: build.architectures_json, build_images_json: build.build_images_json, pkgrel: build.pkgrel, source_date_epoch: build.source_date_epoch,
      image_digest: build.image_digest, license: build.license, surface: build.surface,
      description: build.description, explanation: '', sbom_json: build.sbom_json, lint_json: build.lint_json,
      upstream_commit: build.upstream_commit, pr_url: build.pr_url, commit_sha: build.commit_sha, created_at: 0,
    });
  } catch (cause) {
    if (cause instanceof PolicyError) throw cause;
    fail(409, 'Reviewed revision integrity check failed.');
  }
  const approvals = await query<{ kind: 'area' | 'security'; manifest_sha256: string }>(
    env.DB, 'SELECT kind,manifest_sha256 FROM approvals WHERE revision_id=? AND revoked_at IS NULL', build.revision_id,
  );
  const kinds = new Set(approvals.filter((approval) => approval.manifest_sha256 === build.manifest_sha256).map((approval) => approval.kind));
  if (!kinds.has('area') || !kinds.has('security')) fail(409, 'Current area and security approvals are required before publication.');
}

export async function assertCurrentApprovals(env: Env, revisionId: string, manifestSha256: string) {
  const approvals = await query<{ kind: 'area' | 'security' }>(
    env.DB, 'SELECT kind FROM approvals WHERE revision_id=? AND manifest_sha256=? AND revoked_at IS NULL', revisionId, manifestSha256,
  );
  const kinds = new Set(approvals.map((approval) => approval.kind));
  if (!kinds.has('area') || !kinds.has('security')) fail(409, 'Release revision approvals were revoked; generate a new review.');
}

export async function signingRequest(env: Env, input: {
  buildId: string;
  revisionId: string;
  manifestSha256: string;
  objectKey: string;
  objectKind: 'package' | 'database';
  artifactSha256: string;
  artifactSize: number;
  artifactFilename: string;
}): Promise<SignatureResult> {
  if (!env.SIGNER && !env.SIGNER_URL) fail(503, 'Package signing service is not configured; binary publication is blocked.');
  let url: URL;
  try {
    url = env.SIGNER ? new URL('https://signer.internal/v1/sign') : signingURL(env.SIGNER_URL, 'SIGNER_URL', '/v1/sign');
  } catch (cause) {
    fail(503, cause instanceof Error ? cause.message : 'Package signing URL is invalid.');
  }
  const configured = env as Env & { PACKAGE_SIGNING_FINGERPRINT?: string; SIGNING_FINGERPRINT?: string };
  const intentId = id();
  const createdAt = now();
  const expiresAt = createdAt + 3_600;
  await env.DB.prepare(`INSERT INTO signing_intents
    (id,build_id,revision_id,object_key,object_kind,artifact_sha256,artifact_filename,manifest_sha256,created_at,expires_at,artifact_size,key_fingerprint)
    VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`).bind(
    intentId, input.buildId, input.revisionId, safeKey(input.objectKey), input.objectKind,
    input.artifactSha256, input.artifactFilename, input.manifestSha256, createdAt, expiresAt, input.artifactSize,
    (configured.PACKAGE_SIGNING_FINGERPRINT ?? configured.SIGNING_FINGERPRINT ?? null)?.toLowerCase() ?? null,
  ).run();
  const headers = new Headers({ 'Content-Type': 'application/json' });
  if (env.SIGNER_TOKEN) headers.set('Authorization', `Bearer ${env.SIGNER_TOKEN}`);
  const request = new Request(url, {
    method: 'POST', redirect: 'manual', headers, body: JSON.stringify({ intentId, ...input }),
  });
  let response: Response;
  try {
    response = env.SIGNER ? await env.SIGNER.fetch(request) : await fetch(request);
  } catch {
    await env.DB.prepare("UPDATE signing_intents SET status='failed' WHERE id=? AND status='pending'").bind(intentId).run();
    fail(503, 'Package signing service could not be reached.');
  }
  if (!response.ok) {
    await env.DB.prepare("UPDATE signing_intents SET status='failed' WHERE id=? AND status='pending'").bind(intentId).run();
    fail(503, `Package signing service rejected request (${response.status}).`);
  }
  let result: Record<string, unknown>;
  try {
    const parsed: unknown = await response.json();
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error('invalid signer response');
    result = parsed as Record<string, unknown>;
  } catch {
    await env.DB.prepare("UPDATE signing_intents SET status='failed' WHERE id=? AND status='pending'").bind(intentId).run();
    fail(503, 'Package signing service returned invalid evidence.');
  }
  const signatureObject = result.signature && typeof result.signature === 'object' && !Array.isArray(result.signature)
    ? result.signature as Record<string, unknown>
    : null;
  const signatureKey = typeof result.signatureKey === 'string' ? result.signatureKey
    : typeof result.signature_key === 'string' ? result.signature_key
    : typeof signatureObject?.key === 'string' ? signatureObject.key : '';
  const signatureSha256 = typeof result.signatureSha256 === 'string' ? result.signatureSha256
    : typeof result.signature_sha256 === 'string' ? result.signature_sha256
    : typeof signatureObject?.sha256 === 'string' ? signatureObject.sha256 : null;
  if (!signatureKey || !SAFE_KEY.test(signatureKey) || !signatureSha256 || !SHA256.test(signatureSha256)) {
    await env.DB.prepare("UPDATE signing_intents SET status='failed' WHERE id=? AND status='pending'").bind(intentId).run();
    fail(503, 'Package signing service returned no immutable signature object.');
  }
  const signature = await env.ARTIFACTS.head(signatureKey);
  if (!signature || (signature.customMetadata?.sha256 !== signatureSha256 && signature.customMetadata?.signatureSha256 !== signatureSha256)) {
    await env.DB.prepare("UPDATE signing_intents SET status='failed' WHERE id=? AND status='pending'").bind(intentId).run();
    fail(503, 'Package signing service did not publish a verifiable signature object.');
  }
  await env.DB.prepare(`UPDATE signing_intents SET status='signed',signature_key=?,signature_sha256=?,consumed_at=?
    WHERE id=? AND status='pending'`).bind(signatureKey, signatureSha256, now(), intentId).run();
  return { signatureKey, signatureSha256 };
}
