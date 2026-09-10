import type { Worker } from '../model';
import { id, now, sha256 } from './db';
import { parsePackageMetadata, archRelationCovers } from './arch';
import { type DependencyPlan, parseDependencyPlan, dependencyPlansEqual } from './dependency-plan';
import { assertRuntimeEvidence, reviewedRuntimeExceptions } from './runtime-evidence';
import { blockerStatements, parseDependencyBlockers } from './dependency-blockers';
import { artifactInsert, assertExpectedFilename, buildArtifacts, sameArtifacts, storedOutputContract, MAX_BUILD_OUTPUTS } from './build-outputs';
import { assertRetainedAbiEvidence } from './build-abi-evidence';
import { verifyOutputProvenance } from './build-output-evidence';
import { assertStandaloneReproducibilityContract } from './output-evidence';
import {
  type WorkerMetadata,
  requireLeaseToken,
  getBuildForWorker,
  WorkerProtocolError,
  LEASE_SECONDS,
  workerMetadataChanged,
  databaseFailure,
  leaseExpiryValue,
  requireObject,
  requireExactKeys,
  requireKeys,
  requireText,
  MAX_LOG_BYTES,
  requireLease,
  safeFilenamePattern,
  type ArtifactReference,
  MAX_DIRECT_ARTIFACT_BYTES,
  requireString,
  sha256Pattern,
  MAX_ARTIFACT_BYTES,
  type CompleteInput,
  decodeBase64,
  parseJsonBytes,
  textEncoder,
  type WorkerLease,
  workerImage,
  parseStringArray,
  parseSources,
  sameJson,
  verifyEd25519,
} from './worker-protocol';

export async function heartbeatJob(
  db: D1Database,
  worker: Worker,
  buildId: string,
  leaseTokenValue: unknown,
  metadata: WorkerMetadata | null = null
): Promise<{ leaseExpiresAt: string | null; cancel: boolean }> {
  const token = requireLeaseToken(leaseTokenValue);
  const build = await getBuildForWorker(db, buildId, worker.id);

  if (!build || build.lease_token !== token) throw new WorkerProtocolError(409, 'Worker lease is fenced');

  if (build.status === 'cancelled') return { leaseExpiresAt: null, cancel: true };

  if (build.status !== 'leased' || build.lease_expires_at === null || build.lease_expires_at <= now()) {
    throw new WorkerProtocolError(409, 'Worker lease is expired');
  }

  const timestamp = now();
  const expiresAt = timestamp + LEASE_SECONDS;
  const metadataChanged = metadata ? workerMetadataChanged(worker, metadata) : false;

  try {
    await db.batch([
      db.prepare(`UPDATE builds SET lease_expires_at = ? WHERE id = ? AND worker_id = ? AND lease_token = ?
        AND status = 'leased' AND lease_expires_at > ?
        AND EXISTS (SELECT 1 FROM workers WHERE id = ? AND status = 'active')`)
        .bind(expiresAt, build.id, worker.id, token, timestamp, worker.id),
      metadata
        ? db.prepare(`UPDATE workers SET last_seen_at=?,daemon_version=?,runtime=?,capabilities_json=?
            WHERE id=? AND status='active' AND changes()=1`)
          .bind(timestamp, metadata.version, metadata.runtime, JSON.stringify(metadata.capabilities), worker.id)
        : db.prepare(`UPDATE workers SET last_seen_at = ? WHERE id = ? AND status = 'active' AND changes() = 1`).bind(timestamp, worker.id),
      db.prepare(`INSERT INTO audit_events(actor, action, target, detail, created_at)
        SELECT ?, 'worker.job_heartbeat', ?, ?, ? WHERE changes() = 1`)
        .bind(`worker:${worker.id}`, build.id, JSON.stringify({ leaseExpiresAt: expiresAt, ...(metadata ? { version: metadata.version, runtime: metadata.runtime, capabilities: metadata.capabilities } : {}) }), timestamp),
      ...(metadata ? [db.prepare(`INSERT INTO audit_events(actor,action,target,detail,created_at)
        SELECT ?, 'worker.metadata_updated', ?, ?, ? WHERE changes()=1 AND ?=1`)
        .bind(`worker:${worker.id}`, worker.id, JSON.stringify({ version: metadata.version, runtime: metadata.runtime, capabilities: metadata.capabilities }), timestamp, Number(metadataChanged))] : [])
    ]);
  } catch (cause) {
    return databaseFailure(cause);
  }

  return { leaseExpiresAt: leaseExpiryValue(expiresAt), cancel: false };
}

export async function appendJobLog(
  db: D1Database,
  worker: Worker,
  buildId: string,
  inputValue: unknown
): Promise<{ sequence: number; duplicate: boolean }> {
  const input = requireObject(inputValue);
  requireExactKeys(input, ['leaseToken', 'sequence', 'text']);
  requireKeys(input, ['leaseToken', 'sequence', 'text']);
  const token = requireLeaseToken(input.leaseToken);

  if (!Number.isSafeInteger(input.sequence) || (input.sequence as number) < 0 || (input.sequence as number) > 0x7fffffff) {
    throw new WorkerProtocolError(400, 'Invalid log sequence');
  }

  const sequence = input.sequence as number;
  const text = requireText(input.text, 'log text', MAX_LOG_BYTES);
  const build = await requireLease(db, buildId, worker.id, token);
  const timestamp = now();
  let inserted = false;

  try {
    const results = await db.batch([
      db.prepare(`INSERT OR IGNORE INTO build_logs(build_id, attempt, sequence, text, created_at)
        SELECT ?, ?, ?, ?, ? WHERE EXISTS (SELECT 1 FROM workers WHERE id = ? AND status = 'active')`)
        .bind(build.id, build.attempt, sequence, text, timestamp, worker.id),
      db.prepare(`INSERT INTO audit_events(actor, action, target, detail, created_at)
        SELECT ?, 'worker.job_log', ?, ?, ? WHERE changes() = 1`)
        .bind(`worker:${worker.id}`, build.id, JSON.stringify({ attempt: build.attempt, sequence }), timestamp)
    ]);

    inserted = Number((results[0] as { meta?: { changes?: number } } | undefined)?.meta?.changes ?? 0) > 0;
  } catch (cause) {
    return databaseFailure(cause);
  }

  let existing: { text: string } | null;

  try {
    existing = await db.prepare('SELECT text FROM build_logs WHERE build_id = ? AND attempt = ? AND sequence = ?')
      .bind(build.id, build.attempt, sequence).first<{ text: string }>();
  } catch (cause) {
    return databaseFailure(cause);
  }

  if (!existing) throw new WorkerProtocolError(500, 'Log append was not persisted');

  if (existing.text !== text) throw new WorkerProtocolError(409, 'Log sequence already contains different text');

  return { sequence, duplicate: !inserted };
}

function requireSafeFilename(value: unknown): string {
  if (typeof value !== 'string' || !safeFilenamePattern.test(value) || value.includes('/') || value.includes('\\')) {
    throw new WorkerProtocolError(400, 'Invalid artifact filename');
  }

  return value;
}

export function validateArtifactFilename(value: unknown): string {
  return requireSafeFilename(value);
}

function artifactMatches(left: ArtifactReference | null, right: ArtifactReference | null): boolean {
  if (!left || !right) return left === right;

  return left.key === right.key && artifactBytesMatch(left, right);
}

function artifactBytesMatch(left: ArtifactReference, right: ArtifactReference): boolean {
  return left.sha256 === right.sha256 && left.size === right.size && left.filename === right.filename;
}

export async function uploadArtifact(
  db: D1Database,
  bucket: R2Bucket,
  worker: Worker,
  buildId: string,
  leaseToken: string,
  filenameInput: string,
  body: Uint8Array
): Promise<ArtifactReference> {
  const filename = requireSafeFilename(filenameInput);

  if (body.byteLength > MAX_DIRECT_ARTIFACT_BYTES) throw new WorkerProtocolError(413, 'Artifact too large; use multipart upload');
  const token = requireLeaseToken(leaseToken);
  const build = await requireLease(db, buildId, worker.id, token);

  if (build.revision_surface !== 'binary') throw new WorkerProtocolError(409, 'Recipe builds cannot upload artifacts');
  assertExpectedFilename(build, filename);
  const digest = await sha256(body);

  const reference: ArtifactReference = {
    key: `private/builds/${build.id}/attempt-${build.attempt}/upload-${id()}/${digest}-${filename}`,
    sha256: digest,
    size: body.byteLength,
    filename
  };

  if (storedOutputContract(build)) {
    if (!body.byteLength) throw new WorkerProtocolError(400, 'Artifact must not be empty');
    const existing = (await buildArtifacts(db, build)).find((item) => item.filename === filename);

    if (existing) {
      if (!artifactBytesMatch(existing, reference)) throw new WorkerProtocolError(409, 'Build output already has different bytes');

      return existing;
    }

    try { await bucket.put(reference.key, body, { customMetadata: { buildId: build.id, sha256: digest } }); }
    catch { throw new WorkerProtocolError(503, 'Artifact storage unavailable'); }

    const timestamp = now();

    try { await db.batch([artifactInsert(db, build, worker.id, token, reference, timestamp),
      db.prepare(`INSERT INTO audit_events(actor,action,target,detail,created_at)
        SELECT ?,'worker.artifact_uploaded',?,?,? WHERE changes()=1`)
        .bind(`worker:${worker.id}`, build.id, JSON.stringify({ attempt: build.attempt, ...reference }), timestamp)]); }
    catch (cause) { return databaseFailure(cause); }

    const saved = (await buildArtifacts(db, build)).find((item) => item.filename === filename);

    if (saved?.key !== reference.key) await bucket.delete(reference.key).catch(() => undefined);

    if (!saved || !artifactBytesMatch(saved, reference)) throw new WorkerProtocolError(409, 'Worker output upload is fenced or conflicts');

    return saved;
  }

  const existing = build.artifact_key && build.artifact_sha256 !== null && build.artifact_size !== null && build.artifact_filename
    ? { key: build.artifact_key, sha256: build.artifact_sha256, size: build.artifact_size, filename: build.artifact_filename }
    : null;

  if (existing) {
    if (!artifactBytesMatch(existing, reference)) throw new WorkerProtocolError(409, 'Build already has a different artifact');

    return existing;
  }

  try {
    await bucket.put(reference.key, body, { customMetadata: { buildId: build.id, sha256: digest } });
  } catch {
    throw new WorkerProtocolError(503, 'Artifact storage unavailable');
  }

  const timestamp = now();

  try {
    await db.batch([
      db.prepare(`UPDATE builds SET artifact_key = ?, artifact_sha256 = ?, artifact_size = ?, artifact_filename = ?
        WHERE id = ? AND worker_id = ? AND lease_token = ? AND status = 'leased' AND lease_expires_at > ?
          AND artifact_key IS NULL AND EXISTS (SELECT 1 FROM workers WHERE id = ? AND status = 'active')`)
        .bind(reference.key, reference.sha256, reference.size, reference.filename, build.id, worker.id, token, timestamp, worker.id),
      db.prepare(`INSERT INTO audit_events(actor, action, target, detail, created_at)
        SELECT ?, 'worker.artifact_uploaded', ?, ?, ? WHERE changes() = 1`)
        .bind(`worker:${worker.id}`, build.id, JSON.stringify({ attempt: build.attempt, sha256: digest, size: body.byteLength }), timestamp)
    ]);
  } catch (cause) {
    // ponytail: retain private bytes after an uncertain commit; prune only after attempt retention expires.
    return databaseFailure(cause);
  }

  const updated = await getBuildForWorker(db, build.id, worker.id);

  const uploaded = updated && updated.artifact_key && updated.artifact_sha256 !== null && updated.artifact_size !== null && updated.artifact_filename
    ? { key: updated.artifact_key, sha256: updated.artifact_sha256, size: updated.artifact_size, filename: updated.artifact_filename }
    : null;

  if (!uploaded) {
    await bucket.delete(reference.key).catch(() => undefined);
    throw new WorkerProtocolError(409, 'Worker lease is fenced');
  }

  if (uploaded.key !== reference.key) await bucket.delete(reference.key).catch(() => undefined);

  if (!artifactBytesMatch(uploaded, reference)) {
    await bucket.delete(reference.key).catch(() => undefined);
    throw new WorkerProtocolError(409, 'Build already has a different artifact');
  }

  return uploaded;
}

function parseArtifactReference(value: unknown): ArtifactReference {
  const object = requireObject(value);
  requireExactKeys(object, ['key', 'sha256', 'size', 'filename']);
  const key = requireString(object.key, 'artifact key', 512);
  const digest = object.sha256;

  if (typeof digest !== 'string' || !sha256Pattern.test(digest)) throw new WorkerProtocolError(400, 'Invalid artifact checksum');

  if (!Number.isSafeInteger(object.size) || (object.size as number) < 0 || (object.size as number) > MAX_ARTIFACT_BYTES) {
    throw new WorkerProtocolError(400, 'Invalid artifact size');
  }

  const filename = requireSafeFilename(object.filename);

  return { key, sha256: digest, size: object.size as number, filename };
}

function parseInstalledSize(value: unknown): number {
  if (!Number.isSafeInteger(value) || (value as number) < 0) throw new WorkerProtocolError(400, 'Invalid installedSize');

  return value as number;
}

function parseCompleteInput(value: unknown): CompleteInput {
  const object = requireObject(value);
  requireExactKeys(object, ['leaseToken', 'status', 'installedSize', 'error', 'artifact', 'artifacts', 'provenance', 'provenanceSignature', 'smokePassed', 'dependencyBlockers']);
  const leaseToken = requireLeaseToken(object.leaseToken);

  if (object.status !== 'succeeded' && object.status !== 'failed') throw new WorkerProtocolError(400, 'Invalid completion status');

  if (typeof object.smokePassed !== 'boolean') throw new WorkerProtocolError(400, 'Invalid smokePassed');
  const result: CompleteInput = { leaseToken, status: object.status, smokePassed: object.smokePassed };

  if (object.installedSize !== undefined) result.installedSize = parseInstalledSize(object.installedSize);

  if (object.error !== undefined && object.error !== null) result.error = requireString(object.error, 'error', 16 * 1024);

  if (object.artifact !== undefined && object.artifact !== null) result.artifact = parseArtifactReference(object.artifact);

  if (object.artifacts !== undefined) {
    if (!Array.isArray(object.artifacts) || !object.artifacts.length || object.artifacts.length > MAX_BUILD_OUTPUTS) throw new WorkerProtocolError(400, 'Invalid output artifacts');
    result.artifacts = object.artifacts.map(parseArtifactReference);

    if (new Set(result.artifacts.map((item) => item.filename)).size !== result.artifacts.length) throw new WorkerProtocolError(400, 'Duplicate output artifacts');
  }

  if (object.provenance !== undefined && object.provenance !== null) result.provenance = requireString(object.provenance, 'provenance', 512 * 1024);

  if (object.provenanceSignature !== undefined && object.provenanceSignature !== null) {
    const signature = decodeBase64(object.provenanceSignature, 'provenanceSignature');

    if (signature.byteLength !== 64) throw new WorkerProtocolError(400, 'Invalid provenance signature');
    result.provenanceSignature = object.provenanceSignature as string;
  }

  return result;
}

function parseProvenance(value: string): Record<string, unknown> {
  const parsed = parseJsonBytes(textEncoder.encode(value));
  const object = requireObject(parsed);
  const required = ['buildId', 'revisionId', 'workerId', 'recipeSha256', 'artifactSha256', 'architecture', 'imageDigest', 'sourceDateEpoch', 'sources', 'network', 'startedAt', 'finishedAt'];
  requireExactKeys(object, [...required, 'pkgrel', 'installedSize', 'packageMetadata', 'dependencyPlan', 'buildEnvironment', 'runtimeEnvironment', 'runtimeAnalysis', 'reproducibility', 'factoryRunId', 'factoryAttempt', 'factoryInputSha256']);
  requireKeys(object, required);

  if (object.pkgrel !== undefined && (!Number.isSafeInteger(object.pkgrel) || (object.pkgrel as number) < 1 || (object.pkgrel as number) > 9_999)) {
    throw new WorkerProtocolError(400, 'Invalid provenance pkgrel');
  }

  if (object.installedSize !== undefined) parseInstalledSize(object.installedSize);

  return object;
}

function provenanceTime(value: unknown): number {
  if (typeof value === 'number' && Number.isFinite(value)) return value;

  if (typeof value === 'string') {
    const parsed = Date.parse(value);

    if (!Number.isNaN(parsed)) return parsed;
  }

  throw new WorkerProtocolError(400, 'Invalid provenance timestamp');
}

async function verifyProvenance(
  worker: Worker,
  build: WorkerLease,
  artifact: ArtifactReference | null,
  provenance: string,
  provenanceSignature: string,
  installedSize: number | undefined
): Promise<void> {
  const object = parseProvenance(provenance);

  if (object.buildId !== build.id || object.revisionId !== build.revision_id || object.workerId !== worker.id) {
    throw new WorkerProtocolError(409, 'Provenance does not match worker lease');
  }

  const { imageDigest } = workerImage(build);

  if (object.recipeSha256 !== build.revision_recipe_sha256 || object.architecture !== build.architecture ||
      object.imageDigest !== imageDigest || object.sourceDateEpoch !== build.revision_source_date_epoch || object.network !== 'disabled') {
    throw new WorkerProtocolError(409, 'Provenance does not match reviewed inputs');
  }

  if (object.pkgrel !== undefined && object.pkgrel !== (build.revision_pkgrel ?? 1)) {
    throw new WorkerProtocolError(409, 'Provenance pkgrel does not match reviewed inputs');
  }

  if (object.installedSize !== installedSize) {
    throw new WorkerProtocolError(409, 'Provenance installed size does not match completion');
  }

  if (build.revision_surface === 'binary' || object.packageMetadata !== undefined) {
    const metadata = parsePackageMetadata(object.packageMetadata);

    if (!metadata || metadata.name !== build.revision_name ||
        metadata.fullVersion !== `${build.revision_version}-${build.revision_pkgrel ?? 1}` ||
        metadata.architecture !== build.architecture || metadata.installedSize !== installedSize) {
      throw new WorkerProtocolError(409, 'Package metadata does not match reviewed build');
    }

    const reviewedDependencies = parseStringArray(build.revision_dependencies_json, 'dependencies', 256);

    if (reviewedDependencies.some((reviewed) => !metadata.depends.some((native) => archRelationCovers(native, reviewed)))) {
      throw new WorkerProtocolError(409, 'Package metadata does not contain reviewed dependencies');
    }
  }

  let expectedDependencyPlan: DependencyPlan | null = null;

  if (build.dependency_plan_json !== null) {
    try { expectedDependencyPlan = parseDependencyPlan(JSON.parse(build.dependency_plan_json)); }
    catch { expectedDependencyPlan = null; }

    if (!expectedDependencyPlan) throw new WorkerProtocolError(500, 'Stored OPR dependency plan is invalid');
  }

  let actualDependencyPlan: DependencyPlan | null = null;

  if (object.dependencyPlan !== undefined && object.dependencyPlan !== null) {
    actualDependencyPlan = parseDependencyPlan(object.dependencyPlan);

    if (!actualDependencyPlan) throw new WorkerProtocolError(409, 'Provenance dependency plan is invalid');
  }

  if (!dependencyPlansEqual(expectedDependencyPlan, actualDependencyPlan)) {
    throw new WorkerProtocolError(409, 'Provenance dependency plan does not match lease');
  }

  const sources = parseSources(build.revision_sources_json);

  if (!sameJson(object.sources, sources)) throw new WorkerProtocolError(409, 'Provenance sources do not match reviewed inputs');
  const artifactSha256 = object.artifactSha256;

  if (artifact) {
    if (artifactSha256 !== artifact.sha256) throw new WorkerProtocolError(409, 'Provenance artifact does not match upload');
  } else if (build.revision_surface === 'binary') {
    throw new WorkerProtocolError(409, 'Provenance is missing the uploaded artifact');
  } else if (artifactSha256 !== null && artifactSha256 !== '' && (typeof artifactSha256 !== 'string' || !sha256Pattern.test(artifactSha256))) {
    throw new WorkerProtocolError(409, 'Recipe provenance artifact checksum is invalid');
  }

  if (build.private_candidate === 1) {
    try {
      await assertStandaloneReproducibilityContract(object.reproducibility, {
        architecture: build.architecture, recipeSha256: build.revision_recipe_sha256, imageDigest, sourceDateEpoch: build.revision_source_date_epoch,
        sources: object.sources, inputLockSha256: '', dependencyPlan: object.dependencyPlan,
        ...(artifact ? { output: { filename: artifact.filename, size: artifact.size, sha256: artifact.sha256 } } : {}),
        ...(build.private_candidate === 1 ? { factoryRunId: build.factory_run_id ?? undefined, factoryAttempt: build.factory_attempt ?? undefined, factoryInputSha256: build.factory_input_sha256 ?? undefined } : {}),
      });
    } catch (cause) { throw new WorkerProtocolError(409, cause instanceof Error ? cause.message : 'Single-build reproducibility contract is invalid'); }
    if (build.private_candidate === 1 && (object.factoryRunId !== build.factory_run_id || object.factoryAttempt !== build.factory_attempt || object.factoryInputSha256 !== build.factory_input_sha256)) {
      throw new WorkerProtocolError(409, 'Private factory provenance does not match its reserved run attempt');
    }
  }

  if (provenanceTime(object.finishedAt) < provenanceTime(object.startedAt)) {
    throw new WorkerProtocolError(400, 'Invalid provenance time range');
  }

  const publicKey = decodeBase64(worker.public_key, 'worker public key');
  const signature = decodeBase64(provenanceSignature, 'provenance signature');

  if (!(await verifyEd25519(publicKey, textEncoder.encode(provenance), signature))) {
    throw new WorkerProtocolError(401, 'Invalid provenance signature');
  }

  try { await assertRuntimeEvidence(object, imageDigest, reviewedRuntimeExceptions(build.revision_sbom_json)); }
  catch (cause) { throw new WorkerProtocolError(409, cause instanceof Error ? cause.message : 'Runtime evidence is invalid'); }
}

function storedArtifact(build: WorkerLease): ArtifactReference | null {
  if (!build.artifact_key && build.artifact_sha256 === null && build.artifact_size === null && !build.artifact_filename) return null;

  if (!build.artifact_key || !build.artifact_sha256 || build.artifact_size === null || !build.artifact_filename) {
    throw new WorkerProtocolError(500, 'Stored artifact metadata is incomplete');
  }

  return { key: build.artifact_key, sha256: build.artifact_sha256, size: build.artifact_size, filename: build.artifact_filename };
}

async function verifyStoredArtifact(bucket: R2Bucket, artifact: ArtifactReference): Promise<void> {
  let object: R2Object | null;

  try {
    object = await bucket.head(artifact.key);
  } catch {
    throw new WorkerProtocolError(503, 'Artifact storage unavailable');
  }

  if (!object || object.size !== artifact.size || object.customMetadata?.sha256 !== artifact.sha256) {
    throw new WorkerProtocolError(409, 'Uploaded artifact is unavailable');
  }
}

function terminalCompletionMatches(build: WorkerLease, input: CompleteInput, stored: ArtifactReference | null, outputs: ArtifactReference[] | null): boolean {
  if (build.status !== input.status || build.lease_token !== input.leaseToken) return false;

  if (input.status === 'failed') {
    return input.installedSize === undefined && !input.artifact && !input.artifacts && !input.provenance && !input.provenanceSignature &&
      !input.smokePassed && (build.error ?? undefined) === input.error;
  }

  const artifactsMatch = outputs ? !input.artifact && sameArtifacts(input.artifacts ?? [], outputs) : !input.artifacts && artifactMatches(input.artifact ?? null, stored);

  return input.smokePassed && input.installedSize === (build.installed_size ?? undefined) && artifactsMatch && build.provenance === input.provenance && build.provenance_signature === input.provenanceSignature;
}

export async function completeJob(
  db: D1Database,
  bucket: R2Bucket,
  worker: Worker,
  buildId: string,
  inputValue: unknown
): Promise<{ status: 'succeeded' | 'failed'; idempotent: boolean; privateCandidate?: boolean }> {
  const input = parseCompleteInput(inputValue);
  let blockers;

  try { blockers = parseDependencyBlockers((inputValue as Record<string, unknown>).dependencyBlockers); }
  catch (cause) { throw new WorkerProtocolError(400, cause instanceof Error ? cause.message : 'Invalid dependency blockers'); }

  if (input.status !== 'failed' && blockers.length) throw new WorkerProtocolError(400, 'Successful completion cannot contain dependency blockers');

  if (blockers.some((item) => item.phase === 'factory')) throw new WorkerProtocolError(400, 'Workers cannot report factory blockers');
  const blockersJSON = blockers.length ? JSON.stringify(blockers) : null;

  if (input.status === 'failed' && (input.installedSize !== undefined || input.artifact || input.artifacts || input.provenance || input.provenanceSignature || input.smokePassed)) {
    throw new WorkerProtocolError(400, 'Failed completion contains success evidence');
  }

  const current = await getBuildForWorker(db, buildId, worker.id);

  if (!current || current.lease_token !== input.leaseToken) throw new WorkerProtocolError(409, 'Worker lease is fenced');
  const currentArtifact = storedArtifact(current);
  const outputContract = storedOutputContract(current);
  const outputs = outputContract ? await buildArtifacts(db, current) : [];

  if (input.artifacts && !outputContract) throw new WorkerProtocolError(409, 'Output set requires a v2 lease');

  if (current.status === 'succeeded' || current.status === 'failed') {
    if (terminalCompletionMatches(current, input, currentArtifact, outputContract ? outputs : null) && (current.dependency_blockers_json ?? null) === blockersJSON) return current.private_candidate === 1 ? { status: current.status, idempotent: true, privateCandidate: true } : { status: current.status, idempotent: true };
    throw new WorkerProtocolError(409, 'Build already completed');
  }

  const build = await requireLease(db, buildId, worker.id, input.leaseToken);
  const artifact = storedArtifact(build);

  if (input.status === 'succeeded') {
    if (!input.smokePassed) throw new WorkerProtocolError(400, 'Successful completion requires smokePassed');

    if (build.revision_surface === 'binary' && input.installedSize === undefined) {
      throw new WorkerProtocolError(400, 'Successful binary completion requires installedSize');
    }

    if (outputContract) {
      if (input.artifact || !input.artifacts || !sameArtifacts(input.artifacts, outputs)) throw new WorkerProtocolError(409, 'Completion output set does not match uploads');

      for (const output of outputs) await verifyStoredArtifact(bucket, output);
    } else if (build.revision_surface === 'binary') {
      if (!artifact || !input.artifact || !artifactMatches(input.artifact, artifact)) throw new WorkerProtocolError(409, 'Completion artifact does not match upload');
      await verifyStoredArtifact(bucket, artifact);
    } else if (artifact || input.artifact) {
      throw new WorkerProtocolError(409, 'Recipe completion cannot contain an artifact');
    }

    if (!input.provenance || !input.provenanceSignature) throw new WorkerProtocolError(400, 'Successful completion requires provenance');

    if (outputContract) {
      await verifyOutputProvenance(worker, build, outputs, input.provenance, input.provenanceSignature, input.installedSize);
      await assertRetainedAbiEvidence(db, build, JSON.parse(input.provenance));
    }
    else await verifyProvenance(worker, build, artifact, input.provenance, input.provenanceSignature, input.installedSize);
  } else if (input.installedSize !== undefined || input.smokePassed || input.artifact || input.artifacts || input.provenance || input.provenanceSignature) {
    throw new WorkerProtocolError(400, 'Failed completion contains success evidence');
  }

  const timestamp = now();

  try {
    const updates = input.status === 'succeeded'
      ? db.prepare(`UPDATE builds SET status = 'succeeded', installed_size = ?, provenance = ?, provenance_signature = ?, smoke_passed = 1,
          finished_at = ?, lease_expires_at = ?
          WHERE id = ? AND worker_id = ? AND lease_token = ? AND status = 'leased' AND lease_expires_at > ?
            AND EXISTS (SELECT 1 FROM workers WHERE id = ? AND status = 'active')`)
          .bind(input.installedSize ?? null, input.provenance, input.provenanceSignature, timestamp, timestamp, build.id, worker.id, input.leaseToken, timestamp, worker.id)
      : db.prepare(`UPDATE builds SET status = 'failed', error = ?, smoke_passed = 0, finished_at = ?, lease_expires_at = ?, dependency_blockers_json = ?
          WHERE id = ? AND worker_id = ? AND lease_token = ? AND status = 'leased' AND lease_expires_at > ?
            AND EXISTS (SELECT 1 FROM workers WHERE id = ? AND status = 'active')`)
          .bind(input.error ?? null, timestamp, timestamp, blockersJSON, build.id, worker.id, input.leaseToken, timestamp, worker.id);

    const statements: D1PreparedStatement[] = [
      updates,
      db.prepare(`INSERT INTO audit_events(actor, action, target, detail, created_at)
        SELECT ?, ?, ?, ?, ? WHERE changes() = 1`)
        .bind(`worker:${worker.id}`, `worker.job_${input.status}`, build.id, JSON.stringify({ attempt: build.attempt, artifactSha256: artifact?.sha256 ?? null, installedSize: input.installedSize ?? null, smokePassed: input.smokePassed }), timestamp)
    ];

    statements.push(
      db.prepare(`UPDATE requests SET status='failed',updated_at=? WHERE id=(SELECT request_id FROM revisions WHERE id=?)
        AND ?=0
        AND status IN ('queued','building')
        AND ?=(SELECT latest.id FROM revisions latest WHERE latest.request_id=requests.id ORDER BY latest.created_at DESC,latest.rowid DESC LIMIT 1)
        AND EXISTS (SELECT 1 FROM builds failed WHERE failed.revision_id=? AND failed.status='failed')
        AND NOT EXISTS (SELECT 1 FROM builds active WHERE active.revision_id=? AND active.status IN ('queued','leased'))`)
        .bind(timestamp, build.revision_id, build.private_candidate === 1 ? 1 : 0, build.revision_id, build.revision_id, build.revision_id),
      db.prepare(`INSERT INTO audit_events(actor,action,target,detail,created_at)
        SELECT ?, 'request.failed', (SELECT request_id FROM revisions WHERE id=?), ?, ? WHERE changes()=1`)
        .bind(`worker:${worker.id}`, build.revision_id, JSON.stringify({ buildId: build.id, revisionId: build.revision_id, attempt: build.attempt, reason: 'build failed' }), timestamp),
    );

    if (blockers.length) statements.push(...await blockerStatements(db, {
      requestId: build.revision_request_id, scopeId: build.revision_id, revisionId: build.revision_id,
      architecture: build.architecture, buildId: build.id, leaseToken: input.leaseToken, timestamp,
    }, blockers, `worker:${worker.id}`));
    await db.batch(statements);
  } catch (cause) {
    return databaseFailure(cause);
  }

  const completed = await getBuildForWorker(db, build.id, worker.id);

  if (completed && completed.status === input.status && completed.lease_token === input.leaseToken) {
    return completed.private_candidate === 1 ? { status: input.status, idempotent: false, privateCandidate: true } : { status: input.status, idempotent: false };
  }

  throw new WorkerProtocolError(409, 'Worker lease is fenced');
}
