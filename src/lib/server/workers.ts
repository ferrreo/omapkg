import { cohortOutputContract, storedOutputContract } from './build-outputs';
import { selectedInputLock } from './input-locks';
import { preservedBuildInputs } from '../preserved-recipe';
import { canonicalJson } from '../canonical-json';
import { assertPreservedImportCurrent } from './preserved-imports';
import { srcinfoField, type Srcinfo } from '../srcinfo';
import { archRelationCovers } from './arch';
import { revisionRecipePolicy } from '../../../services/pipeline/recipe-policy';
import { sha256, id, now, audit } from './db';
import type { Worker, Architecture, Build, Actor } from '../model';
import { PolicyError, requireMaintainer } from './policy';
import { type DependencyPlan, planDependencies, parseDependencyPlan } from './dependency-plan';
import { reviewedRuntimeExceptions } from './runtime-evidence';
import {
  type EnrollmentResult,
  requireObject,
  requireExactKeys,
  requireKeys,
  requireString,
  requireArchitecture,
  decodeBase64,
  WorkerProtocolError,
  parseWorkerMetadata,
  encodeBase64,
  isUniqueConstraint,
  databaseFailure,
  ENROLLMENT_TTL_SECONDS,
  type EnrollmentToken,
  randomHex,
  type CandidateBuild,
  type WorkerMetadata,
  type WorkerJob,
  refreshWorkerMetadata,
  parseRevisionForJob,
  verifyRecipeHash,
  workerImage,
  sha256Pattern,
  LEASE_SECONDS,
  leaseExpiryValue,
  getBuildForWorker,
} from './worker-protocol';

export async function enrollWorker(db: D1Database, input: unknown): Promise<EnrollmentResult> {
  const enrollment = requireObject(input);
  requireExactKeys(enrollment, ['token', 'name', 'architecture', 'publicKey', 'version', 'runtime', 'capabilities']);
  requireKeys(enrollment, ['token', 'name', 'architecture', 'publicKey']);
  const token = requireString(enrollment.token, 'token', 256);
  const name = requireString(enrollment.name, 'name', 128);
  const architecture = requireArchitecture(enrollment.architecture);
  const publicKeyBytes = decodeBase64(enrollment.publicKey, 'publicKey');
  if (publicKeyBytes.byteLength !== 32) throw new WorkerProtocolError(400, 'publicKey must be a raw Ed25519 key');
  const metadata = parseWorkerMetadata(enrollment);
  const publicKey = encodeBase64(publicKeyBytes);
  const tokenHash = await sha256(token);
  const workerId = id();
  const enrolledAt = now();
  try {
    await db.batch([
      db.prepare('UPDATE enrollment_tokens SET used_at = ?, worker_id = ? WHERE token_hash = ? AND used_at IS NULL AND expires_at > ? AND architecture = ?')
        .bind(enrolledAt, workerId, tokenHash, enrolledAt, architecture),
      db.prepare(`INSERT INTO workers(id, name, architecture, public_key, status, enrolled_at, last_seen_at, daemon_version, runtime, capabilities_json)
        SELECT ?, ?, ?, ?, 'active', ?, ?, ?, ?, ? WHERE changes() = 1`)
        .bind(workerId, name, architecture, publicKey, enrolledAt, enrolledAt, metadata?.version ?? null, metadata?.runtime ?? null, metadata ? JSON.stringify(metadata.capabilities) : null),
      db.prepare(`INSERT INTO audit_events(actor, action, target, detail, created_at)
        SELECT 'worker-enrollment', 'worker.enrolled', ?, ?, ? WHERE changes() = 1`)
        .bind(workerId, JSON.stringify({ architecture, name, ...(metadata ? { version: metadata.version, runtime: metadata.runtime, capabilities: metadata.capabilities } : {}) }), enrolledAt)
    ]);
  } catch (cause) {
    if (isUniqueConstraint(cause)) throw new WorkerProtocolError(409, 'Worker key is already enrolled');
    return databaseFailure(cause);
  }
  let worker: Worker | null;
  try {
    worker = await db.prepare('SELECT id, architecture FROM workers WHERE id = ?').bind(workerId).first<Worker>();
  } catch (cause) {
    return databaseFailure(cause);
  }
  if (!worker) throw new WorkerProtocolError(401, 'Invalid or expired enrollment token');
  return { id: worker.id, architecture: worker.architecture };
}

export async function createEnrollmentToken(
  db: D1Database,
  createdBy: string,
  architecture: Architecture,
  ttlSeconds = ENROLLMENT_TTL_SECONDS
): Promise<EnrollmentToken> {
  const actor = requireString(createdBy, 'createdBy', 256);
  requireArchitecture(architecture);
  if (!Number.isSafeInteger(ttlSeconds) || ttlSeconds < 60 || ttlSeconds > 24 * 60 * 60) {
    throw new WorkerProtocolError(400, 'Invalid enrollment token lifetime');
  }
  const token = randomHex();
  const tokenHash = await sha256(token);
  const expiresAt = now() + ttlSeconds;
  try {
    await db.batch([
      db.prepare('INSERT INTO enrollment_tokens(token_hash, architecture, created_by, expires_at) VALUES(?,?,?,?)')
        .bind(tokenHash, architecture, actor, expiresAt),
      audit(db, actor, 'worker.enrollment_token_created', `enrollment-token:${tokenHash}`, { architecture, expiresAt })
    ]);
  } catch (cause) {
    return databaseFailure(cause);
  }
  return { token, expiresAt };
}

export async function revokeWorker(db: D1Database, actor: string, workerId: string): Promise<Worker> {
  const auditActor = requireString(actor, 'actor', 256);
  const target = requireString(workerId, 'workerId', 128);
  let worker: Worker | null;
  try {
    worker = await db.prepare('SELECT id, name, architecture, public_key, status, enrolled_at, last_seen_at, daemon_version, runtime, capabilities_json, accepting_jobs, paused_at, removed_at FROM workers WHERE id = ?')
      .bind(target).first<Worker>();
  } catch (cause) {
    return databaseFailure(cause);
  }
  if (!worker) throw new WorkerProtocolError(404, 'Worker not found');
  if (worker.status === 'revoked') return worker;
  const timestamp = now();
  try {
    await db.batch([
      db.prepare("UPDATE workers SET status = 'revoked', accepting_jobs=0 WHERE id = ? AND status = 'active'").bind(target),
      db.prepare(`INSERT INTO audit_events(actor, action, target, detail, created_at)
        SELECT ?, 'worker.revoked', ?, ?, ? WHERE changes() = 1`)
        .bind(auditActor, target, JSON.stringify({ workerId: target }), timestamp),
      db.prepare("UPDATE builds SET status = 'queued', worker_id = NULL, lease_token = NULL, lease_expires_at = NULL, error = 'worker revoked', artifact_key = NULL, artifact_sha256 = NULL, artifact_size = NULL, artifact_filename = NULL, installed_size = NULL, dependency_plan_json = NULL, provenance = NULL, provenance_signature = NULL, smoke_passed = 0, dependency_blockers_json = NULL WHERE worker_id = ? AND status = 'leased'")
        .bind(target),
      db.prepare(`INSERT INTO audit_events(actor, action, target, detail, created_at)
        SELECT ?, 'worker.leases_requeued', ?, ?, ? WHERE changes() > 0`)
        .bind(auditActor, target, JSON.stringify({ reason: 'worker revoked' }), timestamp)
    ]);
  } catch (cause) {
    return databaseFailure(cause);
  }
  try {
    worker = await db.prepare('SELECT id, name, architecture, public_key, status, enrolled_at, last_seen_at, daemon_version, runtime, capabilities_json, accepting_jobs, paused_at, removed_at FROM workers WHERE id = ?')
      .bind(target).first<Worker>();
  } catch (cause) {
    return databaseFailure(cause);
  }
  if (!worker) throw new WorkerProtocolError(404, 'Worker not found');
  return worker;
}

export async function pauseWorker(db: D1Database, actor: string, workerId: string): Promise<Worker> {
  const auditActor = requireString(actor, 'actor', 256);
  const target = requireString(workerId, 'workerId', 128);
  let worker: Worker | null;
  try {
    worker = await db.prepare('SELECT id, name, architecture, public_key, status, enrolled_at, last_seen_at, daemon_version, runtime, capabilities_json, accepting_jobs, paused_at, removed_at FROM workers WHERE id = ?')
      .bind(target).first<Worker>();
  } catch (cause) {
    return databaseFailure(cause);
  }
  if (!worker) throw new WorkerProtocolError(404, 'Worker not found');
  if (worker.status !== 'active') throw new WorkerProtocolError(409, 'Revoked workers cannot be paused');
  if (worker.accepting_jobs === 0) return worker;
  const timestamp = now();
  try {
    await db.batch([
      db.prepare("UPDATE workers SET accepting_jobs=0,paused_at=? WHERE id=? AND status='active' AND accepting_jobs=1")
        .bind(timestamp, target),
      db.prepare(`INSERT INTO audit_events(actor,action,target,detail,created_at)
        SELECT ?, 'worker.paused', ?, ?, ? WHERE changes()=1`)
        .bind(auditActor, target, JSON.stringify({ acceptingJobs: false, pausedAt: timestamp }), timestamp)
    ]);
  } catch (cause) {
    return databaseFailure(cause);
  }
  try {
    worker = await db.prepare('SELECT id, name, architecture, public_key, status, enrolled_at, last_seen_at, daemon_version, runtime, capabilities_json, accepting_jobs, paused_at, removed_at FROM workers WHERE id = ?')
      .bind(target).first<Worker>();
  } catch (cause) {
    return databaseFailure(cause);
  }
  if (!worker) throw new WorkerProtocolError(404, 'Worker not found');
  return worker;
}

export async function resumeWorker(db: D1Database, actor: string, workerId: string): Promise<Worker> {
  const auditActor = requireString(actor, 'actor', 256);
  const target = requireString(workerId, 'workerId', 128);
  let worker: Worker | null;
  try {
    worker = await db.prepare('SELECT id, name, architecture, public_key, status, enrolled_at, last_seen_at, daemon_version, runtime, capabilities_json, accepting_jobs, paused_at, removed_at FROM workers WHERE id = ?')
      .bind(target).first<Worker>();
  } catch (cause) {
    return databaseFailure(cause);
  }
  if (!worker) throw new WorkerProtocolError(404, 'Worker not found');
  if (worker.status !== 'active') throw new WorkerProtocolError(409, 'Revoked workers cannot resume');
  if (worker.accepting_jobs === 1) return worker;
  const timestamp = now();
  try {
    await db.batch([
      db.prepare("UPDATE workers SET accepting_jobs=1,paused_at=NULL WHERE id=? AND status='active' AND accepting_jobs=0")
        .bind(target),
      db.prepare(`INSERT INTO audit_events(actor,action,target,detail,created_at)
        SELECT ?, 'worker.resumed', ?, ?, ? WHERE changes()=1`)
        .bind(auditActor, target, JSON.stringify({ acceptingJobs: true, resumedAt: timestamp }), timestamp)
    ]);
  } catch (cause) {
    return databaseFailure(cause);
  }
  try {
    worker = await db.prepare('SELECT id, name, architecture, public_key, status, enrolled_at, last_seen_at, daemon_version, runtime, capabilities_json, accepting_jobs, paused_at, removed_at FROM workers WHERE id = ?')
      .bind(target).first<Worker>();
  } catch (cause) {
    return databaseFailure(cause);
  }
  if (!worker) throw new WorkerProtocolError(404, 'Worker not found');
  return worker;
}

export async function archiveWorker(db: D1Database, actor: string, workerId: string): Promise<Worker> {
  const auditActor = requireString(actor, 'actor', 256);
  const target = requireString(workerId, 'workerId', 128);
  let worker: Worker | null;
  try {
    worker = await db.prepare('SELECT id, name, architecture, public_key, status, enrolled_at, last_seen_at, daemon_version, runtime, capabilities_json, accepting_jobs, paused_at, removed_at FROM workers WHERE id = ?')
      .bind(target).first<Worker>();
  } catch (cause) {
    return databaseFailure(cause);
  }
  if (!worker) throw new WorkerProtocolError(404, 'Worker not found');
  if (worker.status !== 'revoked') throw new WorkerProtocolError(409, 'Only revoked workers can be archived');
  if (worker.removed_at !== null) return worker;
  try {
    const activeLease = await db.prepare("SELECT 1 FROM builds WHERE worker_id=? AND status='leased' LIMIT 1").bind(target).first();
    if (activeLease) throw new WorkerProtocolError(409, 'Worker still has an active lease');
  } catch (cause) {
    if (cause instanceof WorkerProtocolError) throw cause;
    return databaseFailure(cause);
  }
  const timestamp = now();
  try {
    await db.batch([
      db.prepare("UPDATE workers SET removed_at=?,accepting_jobs=0 WHERE id=? AND status='revoked' AND removed_at IS NULL")
        .bind(timestamp, target),
      db.prepare(`INSERT INTO audit_events(actor,action,target,detail,created_at)
        SELECT ?, 'worker.archived', ?, ?, ? WHERE changes()=1`)
        .bind(auditActor, target, JSON.stringify({ removedAt: timestamp }), timestamp)
    ]);
  } catch (cause) {
    return databaseFailure(cause);
  }
  try {
    worker = await db.prepare('SELECT id, name, architecture, public_key, status, enrolled_at, last_seen_at, daemon_version, runtime, capabilities_json, accepting_jobs, paused_at, removed_at FROM workers WHERE id = ?')
      .bind(target).first<Worker>();
  } catch (cause) {
    return databaseFailure(cause);
  }
  if (!worker) throw new WorkerProtocolError(404, 'Worker not found');
  return worker;
}

type RetryBuildRow = {
  build_id: string;
  revision_id: string;
  build_status: Build['status'];
  attempt: number;
  request_id: string;
  request_status: string;
  area: string;
  latest_revision_id: string | null;
  area_approved: number;
  security_approved: number;
};

export async function retryBuild(db: D1Database, actor: Actor | null, buildId: string, reason: string): Promise<void> {
  if (typeof buildId !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/.test(buildId)) throw new PolicyError(400, 'Invalid build ID.');
  if (typeof reason !== 'string') throw new PolicyError(400, 'Provide a retry reason, up to 2,000 characters.');
  const cleanReason = reason.replace(/[\u0000\r\n]+/g, ' ').trim();
  if (!cleanReason || cleanReason.length > 2_000) throw new PolicyError(400, 'Provide a retry reason, up to 2,000 characters.');
  const caller = requireMaintainer(actor);
  let row: RetryBuildRow | null;
  try {
    row = await db.prepare(`
      SELECT b.id AS build_id, b.revision_id, b.status AS build_status, b.attempt,
        q.id AS request_id, q.status AS request_status, q.area,
        (SELECT latest.id FROM revisions latest WHERE latest.request_id=r.request_id ORDER BY latest.created_at DESC, latest.rowid DESC LIMIT 1) AS latest_revision_id,
        EXISTS (SELECT 1 FROM approvals a WHERE a.revision_id=r.id AND a.kind='area' AND a.manifest_sha256=r.manifest_sha256 AND a.revoked_at IS NULL) AS area_approved,
        EXISTS (SELECT 1 FROM approvals a WHERE a.revision_id=r.id AND a.kind='security' AND a.manifest_sha256=r.manifest_sha256 AND a.revoked_at IS NULL) AS security_approved
      FROM builds b JOIN revisions r ON r.id=b.revision_id JOIN requests q ON q.id=r.request_id
      WHERE b.id=?`).bind(buildId).first<RetryBuildRow>();
  } catch (cause) {
    return databaseFailure(cause);
  }
  if (!row) throw new PolicyError(404, 'Build not found.');
  requireMaintainer(caller, row.area);
  if (row.build_status !== 'failed' || !['queued', 'building', 'failed'].includes(row.request_status)) throw new PolicyError(409, 'Only a failed build on its current request can be retried.');
  if (row.latest_revision_id !== row.revision_id) throw new PolicyError(409, 'Only the current reviewed revision can be retried.');
  if (row.area_approved !== 1 || row.security_approved !== 1) throw new PolicyError(409, 'Current area and security approvals are required before retry.');
  const timestamp = now();
  try {
    const result = await db.batch([
      db.prepare(`UPDATE requests SET status=CASE WHEN EXISTS (SELECT 1 FROM builds sibling WHERE sibling.revision_id=? AND sibling.id<>? AND sibling.status='leased') THEN 'building' ELSE 'queued' END,updated_at=? WHERE id=? AND status IN ('queued','building','failed')
        AND ?=(SELECT latest.id FROM revisions latest WHERE latest.request_id=? ORDER BY latest.created_at DESC,latest.rowid DESC LIMIT 1)
        AND EXISTS (SELECT 1 FROM builds target WHERE target.id=? AND target.revision_id=? AND target.status='failed')
        AND EXISTS (SELECT 1 FROM approvals a WHERE a.revision_id=? AND a.kind='area' AND a.manifest_sha256=(SELECT manifest_sha256 FROM revisions WHERE id=?) AND a.revoked_at IS NULL)
        AND EXISTS (SELECT 1 FROM approvals a WHERE a.revision_id=? AND a.kind='security' AND a.manifest_sha256=(SELECT manifest_sha256 FROM revisions WHERE id=?) AND a.revoked_at IS NULL)`)
        .bind(row.revision_id, row.build_id, timestamp, row.request_id, row.revision_id, row.request_id, row.build_id, row.revision_id, row.revision_id, row.revision_id, row.revision_id, row.revision_id),
      db.prepare(`UPDATE builds SET status='queued',worker_id=NULL,lease_token=NULL,lease_expires_at=NULL,
          error=NULL,artifact_key=NULL,artifact_sha256=NULL,artifact_size=NULL,artifact_filename=NULL,
          installed_size=NULL,dependency_plan_json=NULL,provenance=NULL,provenance_signature=NULL,
          smoke_passed=0,started_at=NULL,finished_at=NULL
        WHERE changes()=1 AND id=? AND revision_id=? AND status='failed'
          AND EXISTS (SELECT 1 FROM requests q WHERE q.id=? AND q.status IN ('queued','building'))
          AND revision_id=(SELECT latest.id FROM revisions latest WHERE latest.request_id=(SELECT request_id FROM revisions current WHERE current.id=builds.revision_id)
            ORDER BY latest.created_at DESC,latest.rowid DESC LIMIT 1)
          AND EXISTS (SELECT 1 FROM approvals a WHERE a.revision_id=? AND a.kind='area' AND a.manifest_sha256=(SELECT manifest_sha256 FROM revisions WHERE id=?) AND a.revoked_at IS NULL)
          AND EXISTS (SELECT 1 FROM approvals a WHERE a.revision_id=? AND a.kind='security' AND a.manifest_sha256=(SELECT manifest_sha256 FROM revisions WHERE id=?) AND a.revoked_at IS NULL)`)
        .bind(row.build_id, row.revision_id, row.request_id, row.revision_id, row.revision_id, row.revision_id, row.revision_id),
      db.prepare(`INSERT INTO audit_events(actor,action,target,detail,created_at)
        SELECT ?, 'build.retry_requested', ?, ?, ? WHERE changes()=1`)
        .bind(caller.id, row.build_id, JSON.stringify({ requestId: row.request_id, revisionId: row.revision_id, attempt: row.attempt, reason: cleanReason }), timestamp),
    ]);
    if (!result[0]?.meta.changes || !result[1]?.meta.changes) throw new PolicyError(409, 'Build or request changed. Refresh and retry.');
  } catch (cause) {
    if (cause instanceof PolicyError) throw cause;
    return databaseFailure(cause);
  }
}

async function reviewedCandidate(db: D1Database, architecture: Architecture, timestamp: number, multiOutput: boolean, frozenInputs: boolean, preservedInputs: boolean): Promise<CandidateBuild | null> {
  try {
    return await db.prepare(`
      SELECT b.id, b.revision_id, b.architecture, b.status, b.worker_id, b.lease_token, b.lease_expires_at,
        b.attempt, b.artifact_key, b.artifact_sha256, b.artifact_size, b.artifact_filename, b.installed_size, b.dependency_plan_json, b.output_contract_json,
        b.provenance, b.provenance_signature, b.smoke_passed, b.error, b.created_at, b.started_at, b.finished_at,
        q.name AS revision_name, r.request_id AS revision_request_id, r.version AS revision_version, r.recipe AS revision_recipe,
        r.recipe_sha256 AS revision_recipe_sha256, r.manifest_sha256 AS revision_manifest_sha256,
        r.sources_json AS revision_sources_json, r.dependencies_json AS revision_dependencies_json, r.make_dependencies_json AS revision_make_dependencies_json,
        r.smoke_commands_json AS revision_smoke_commands_json, r.architectures_json AS revision_architectures_json,
        r.build_images_json AS revision_build_images_json, r.pkgrel AS revision_pkgrel, r.source_date_epoch AS revision_source_date_epoch,
        r.image_digest AS revision_image_digest,
        r.surface AS revision_surface, r.license AS revision_license, r.sbom_json AS revision_sbom_json, r.public_recipe AS revision_public_recipe
      FROM builds b
      JOIN revisions r ON r.id = b.revision_id
      JOIN requests q ON q.id = r.request_id
      WHERE b.architecture = ?
        AND (q.preserved_import_id IS NULL OR (?=1 AND
          EXISTS(SELECT 1 FROM current_preserved_recipe_imports i WHERE i.id=q.preserved_import_id AND i.revision_id=r.id) AND
          EXISTS(SELECT 1 FROM cohort_recipe_ownership WHERE recipe_revision_id=r.id) AND
          EXISTS(SELECT 1 FROM build_input_selections s JOIN current_input_locks l ON l.sha256=s.lock_sha256
            WHERE s.recipe_revision_id=r.id AND s.architecture=b.architecture AND s.cohort_id=l.cohort_id AND s.cohort_revision=l.cohort_revision)))
        AND q.status IN ('queued', 'building')
        AND (?=1 OR r.surface='recipe' OR NOT EXISTS(SELECT 1 FROM cohort_recipe_ownership WHERE recipe_revision_id=r.id))
        AND NOT EXISTS(SELECT 1 FROM build_input_selections s JOIN cohorts c ON c.id=s.cohort_id AND c.current_revision=s.cohort_revision
          WHERE s.recipe_revision_id=r.id AND s.architecture=b.architecture AND (?=0 OR NOT EXISTS(SELECT 1 FROM current_input_locks l WHERE l.sha256=s.lock_sha256)))
        AND NOT EXISTS (SELECT 1 FROM cohort_recipe_ownership owned JOIN cohorts cohort ON cohort.id=owned.cohort_id
          WHERE owned.recipe_revision_id=r.id AND (cohort.phase<>'build' OR cohort.condition NOT IN ('ready','blocked')
            OR NOT EXISTS(SELECT 1 FROM cohort_members member WHERE member.cohort_id=cohort.id
              AND member.revision=cohort.current_revision AND member.recipe_revision_id=r.id)))
        AND r.pr_url IS NOT NULL AND r.commit_sha IS NOT NULL AND length(r.image_digest) > 0
        AND (b.status = 'queued' OR (b.status = 'leased' AND b.lease_expires_at IS NOT NULL AND b.lease_expires_at < ?))
        AND r.id = (SELECT latest.id FROM revisions latest WHERE latest.request_id = r.request_id ORDER BY latest.created_at DESC, latest.rowid DESC LIMIT 1)
        AND EXISTS (SELECT 1 FROM approvals a WHERE a.revision_id = r.id AND a.kind = 'area' AND a.manifest_sha256 = r.manifest_sha256 AND a.revoked_at IS NULL)
        AND EXISTS (SELECT 1 FROM approvals a WHERE a.revision_id = r.id AND a.kind = 'security' AND a.manifest_sha256 = r.manifest_sha256 AND a.revoked_at IS NULL)
      ORDER BY b.created_at ASC, b.id ASC
      LIMIT 1`).bind(architecture, Number(preservedInputs), Number(multiOutput), Number(frozenInputs), timestamp).first<CandidateBuild>();
  } catch (cause) {
    return databaseFailure(cause);
  }
}

export async function claimJob(
  db: D1Database,
  worker: Worker,
  metadata: WorkerMetadata | null = null,
  dependencyContext?: { ARTIFACTS: R2Bucket; PUBLIC_ORIGIN: string; PACKAGE_SIGNING_FINGERPRINT?: string; SIGNING_FINGERPRINT?: string },
): Promise<WorkerJob | null> {
  const timestamp = now();
  await refreshWorkerMetadata(db, worker, metadata, timestamp);
  const capabilities = metadata?.capabilities ?? JSON.parse(worker.capabilities_json ?? '[]');
  const candidate = await reviewedCandidate(db, worker.architecture, timestamp, capabilities.includes('multi-output-v2'), Boolean(dependencyContext) && capabilities.includes('frozen-inputs-v1'),
    Boolean(dependencyContext) && ['preserved-recipe-v1', 'multi-output-v2', 'frozen-inputs-v1', 'runtime-analysis-v1'].every((capability) => capabilities.includes(capability)));
  if (!candidate) return null;
  if (revisionRecipePolicy(candidate.revision_sbom_json).recorded &&
      !(metadata?.capabilities ?? JSON.parse(worker.capabilities_json ?? '[]')).includes('runtime-analysis-v1')) return null;
  const revision = parseRevisionForJob(candidate);
  await verifyRecipeHash(candidate.revision_recipe, candidate.revision_recipe_sha256);
  const { imageRef, imageDigest } = workerImage(candidate);
  if (!revision.architectures.includes(worker.architecture)) return null;
  if (!sha256Pattern.test(candidate.revision_manifest_sha256)) throw new WorkerProtocolError(500, 'Reviewed manifest checksum is invalid');
  if (candidate.revision_surface !== 'binary' && candidate.revision_surface !== 'recipe') {
    throw new WorkerProtocolError(500, 'Reviewed surface is invalid');
  }
  const outputContract = candidate.revision_surface === 'binary' ? await cohortOutputContract(db, { id: candidate.revision_id, version: candidate.revision_version, pkgrel: candidate.revision_pkgrel, sbom_json: candidate.revision_sbom_json }, worker.architecture) : null;
  const outputContractJSON = outputContract ? JSON.stringify(outputContract) : null;
  const inputLock = outputContract && dependencyContext ? await selectedInputLock({ DB: db, ARTIFACTS: dependencyContext.ARTIFACTS }, candidate.revision_id, worker.architecture, outputContract) : null;
  const sourceRevision = { id: candidate.revision_id, sbom_json: candidate.revision_sbom_json, architectures_json: candidate.revision_architectures_json,
    manifest_sha256: candidate.revision_manifest_sha256 };
  const preserved = preservedBuildInputs(sourceRevision, worker.architecture);
  if (preserved) {
    if (!inputLock || !outputContract) throw new WorkerProtocolError(409, 'Preserved recipes require frozen native inputs');
    await assertPreservedImportCurrent(db, sourceRevision);
    const inspection = await db.prepare(`SELECT r.metadata_json FROM current_recipe_source_bundles b
      JOIN recipe_inspection_results r ON r.job_id=b.inspection_id AND r.attempt=b.inspection_attempt WHERE b.sha256=?`)
      .bind(preserved.sourceBundle.sha256).first<{ metadata_json: string }>();
    if (!inspection) throw new WorkerProtocolError(409, 'Preserved source inspection is no longer current');
    const metadata = JSON.parse(inspection.metadata_json) as Srcinfo;
    const providers = metadata.outputs.flatMap((output) => [`${output.name}=${metadata.version}`, ...srcinfoField(metadata, output, 'provides', worker.architecture)]);
    // Explicit make/check dependencies still need installed providers. Runtime
    // relations satisfied by sibling outputs are checked during installation.
    revision.dependencies = [...new Set([...revision.runtimeDependencies.filter((relation) => !providers.some((provider) => archRelationCovers(provider, relation))), ...revision.makeDependencies])];
  }
  let dependencyPlan: DependencyPlan | null = null;
  let planDigest: string | null = null;
  let dependencyReleaseIds: string[] = [];
  if (dependencyContext && !inputLock) {
    try {
      const planned = await planDependencies({ DB: db, ...dependencyContext }, {
        architecture: worker.architecture,
        dependencies: revision.runtimeDependencies,
        makeDependencies: revision.makeDependencies,
      });
      dependencyPlan = planned.plan;
      planDigest = planned.digest;
      dependencyReleaseIds = planned.releaseIds;
    } catch (cause) {
      throw new WorkerProtocolError(409, cause instanceof Error ? cause.message : 'OPR dependency plan could not be created');
    }
  }
  const dependencyPlanJSON = dependencyPlan ? JSON.stringify(dependencyPlan) : null;
  const leaseToken = randomHex();
  const leaseExpiresAt = timestamp + LEASE_SECONDS;
  try {
    await db.batch([
      db.prepare(`UPDATE builds AS b SET status = 'leased', worker_id = ?, lease_token = ?, lease_expires_at = ?,
        attempt = attempt + 1, started_at = ?, finished_at = NULL, error = NULL,
        artifact_key = NULL, artifact_sha256 = NULL, artifact_size = NULL, artifact_filename = NULL, installed_size = NULL, dependency_plan_json = ?, output_contract_json = ?, input_lock_sha256 = ?, preserved_inputs_json = ?,
        provenance = NULL, provenance_signature = NULL, smoke_passed = 0, dependency_blockers_json = NULL
        WHERE id = ? AND architecture = ?
          AND (status = 'queued' OR (status = 'leased' AND lease_expires_at IS NOT NULL AND lease_expires_at < ?))
          AND revision_id = (SELECT latest.id FROM revisions latest WHERE latest.request_id = (SELECT request_id FROM revisions current_revision WHERE current_revision.id = b.revision_id) ORDER BY latest.created_at DESC, latest.rowid DESC LIMIT 1)
          AND EXISTS (SELECT 1 FROM approvals a WHERE a.revision_id = b.revision_id AND a.kind = 'area' AND a.manifest_sha256 = ? AND a.revoked_at IS NULL)
          AND EXISTS (SELECT 1 FROM approvals a WHERE a.revision_id = b.revision_id AND a.kind = 'security' AND a.manifest_sha256 = ? AND a.revoked_at IS NULL)
          AND EXISTS (SELECT 1 FROM revisions r WHERE r.id = b.revision_id AND r.pr_url IS NOT NULL AND r.commit_sha IS NOT NULL AND length(r.image_digest) > 0)
          AND EXISTS (SELECT 1 FROM requests q WHERE q.id = (SELECT request_id FROM revisions WHERE id = b.revision_id) AND q.status IN ('queued', 'building'))
          AND EXISTS (SELECT 1 FROM workers w WHERE w.id = ? AND w.status = 'active' AND w.accepting_jobs = 1 AND w.removed_at IS NULL)`)
        .bind(worker.id, leaseToken, leaseExpiresAt, timestamp, dependencyPlanJSON, outputContractJSON, inputLock?.sha256 ?? null, preserved ? canonicalJson(preserved) : null, candidate.id, worker.architecture, timestamp,
          candidate.revision_manifest_sha256, candidate.revision_manifest_sha256, worker.id),
      db.prepare(`INSERT INTO audit_events(actor, action, target, detail, created_at)
        SELECT ?, 'worker.job_claimed', ?, ?, ? WHERE changes() = 1`)
        .bind(`worker:${worker.id}`, candidate.id, JSON.stringify({
          requestId: candidate.revision_request_id, architecture: worker.architecture, attempt: candidate.attempt + 1, revisionId: candidate.revision_id,
          dependencyPlanSha256: planDigest, dependencyReleaseIds,
          inputLockSha256: inputLock?.sha256 ?? null,
          ...(preserved ? { preservedRecipe: preserved } : {}),
          dependencyPlanRefs: dependencyPlan?.packages.map((item) => ({ releaseId: item.releaseId, url: item.url, signatureUrl: item.signatureUrl, sha256: item.sha256, size: item.size })) ?? [],
        }), timestamp),
      db.prepare(`UPDATE requests SET status='building',updated_at=? WHERE id=? AND status='queued'
        AND ?=(SELECT latest.id FROM revisions latest WHERE latest.request_id=requests.id ORDER BY latest.created_at DESC,latest.rowid DESC LIMIT 1)
        AND EXISTS (SELECT 1 FROM builds claimed WHERE claimed.id=? AND claimed.revision_id=? AND claimed.status='leased' AND claimed.worker_id=? AND claimed.lease_token=?)`)
        .bind(timestamp, candidate.revision_request_id, candidate.revision_id, candidate.id, candidate.revision_id, worker.id, leaseToken),
      db.prepare(`INSERT INTO audit_events(actor,action,target,detail,created_at)
        SELECT ?, 'request.building', ?, ?, ? WHERE changes()=1`)
        .bind(`worker:${worker.id}`, candidate.revision_request_id, JSON.stringify({ buildId: candidate.id, revisionId: candidate.revision_id, architecture: worker.architecture, attempt: candidate.attempt + 1 }), timestamp)
    ]);
  } catch (cause) {
    return databaseFailure(cause);
  }
  const claimed = await getBuildForWorker(db, candidate.id, worker.id);
  if (!claimed || !claimed.lease_expires_at || claimed.status !== 'leased' || claimed.lease_token !== leaseToken) return null;
  let claimedDependencyPlan: DependencyPlan | null = null;
  if (claimed.dependency_plan_json !== null) {
    try { claimedDependencyPlan = parseDependencyPlan(JSON.parse(claimed.dependency_plan_json)); }
    catch { claimedDependencyPlan = null; }
    if (!claimedDependencyPlan) throw new WorkerProtocolError(500, 'Stored OPR dependency plan is invalid');
  }
  return {
    ...(preserved ? { preservedRecipe: preserved } : {}),
    ...(inputLock ? { inputLock } : {}),
    ...(storedOutputContract(claimed) ? { outputContract: storedOutputContract(claimed)!, attempt: claimed.attempt } : {}),
    id: claimed.id,
    leaseToken,
    leaseExpiresAt: leaseExpiryValue(claimed.lease_expires_at),
    revisionId: claimed.revision_id,
    packageName: claimed.revision_name,
    version: claimed.revision_version,
    pkgrel: claimed.revision_pkgrel ?? 1,
    architecture: claimed.architecture,
    recipe: claimed.revision_recipe,
    ...(claimed.revision_public_recipe ? { publicRecipe: claimed.revision_public_recipe } : {}),
    runtimeExceptions: reviewedRuntimeExceptions(claimed.revision_sbom_json),
    recipeSha256: claimed.revision_recipe_sha256,
    sourceDateEpoch: claimed.revision_source_date_epoch,
    imageRef,
    imageDigest,
    sources: revision.sources,
    dependencies: revision.dependencies,
    runtimeDependencies: revision.runtimeDependencies,
    makeDependencies: revision.makeDependencies,
    ...(claimedDependencyPlan ? { dependencyPlan: claimedDependencyPlan } : {}),
    smokeCommands: revision.smokeCommands,
    surface: claimed.revision_surface
  };
}

export {
  CLOCK_SKEW_SECONDS,
  LEASE_SECONDS,
  ENROLLMENT_TTL_SECONDS,
  MAX_JSON_BODY_BYTES,
  MAX_LOG_BYTES,
  MAX_ARTIFACT_BYTES,
  MAX_DIRECT_ARTIFACT_BYTES,
  MAX_RECIPE_BYTES,
  WorkerProtocolError,
  WORKER_CAPABILITIES,
  type WorkerCapability,
  type WorkerMetadata,
  type AuthenticatedWorker,
  type EnrollmentInput,
  type EnrollmentResult,
  type EnrollmentToken,
  type WorkerJob,
  type CompleteInput,
  type ArtifactReference,
  type WorkerLease,
  workerImage,
  parseWorkerMetadata,
  readBody,
  requireJsonContentType,
  parseJsonRequest,
  authenticateWorker,
  requireWorkerLease,
  workerRouteFailure,
} from './worker-protocol';

export { heartbeatJob, appendJobLog, validateArtifactFilename, uploadArtifact, completeJob } from './worker-results';
