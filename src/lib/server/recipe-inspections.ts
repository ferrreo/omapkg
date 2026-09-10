import type { Actor, Architecture, Worker } from '../model';
import type { CatalogManifest } from '../distribution';
import type { Srcinfo } from '../srcinfo';
import { parseSrcinfo } from '../srcinfo';
import { assertNativeHost, parseInputObject, type InputObject } from '../frozen-inputs';
import { canonicalJson } from '../canonical-json';
import type { Env } from './env';
import { audit, now, query, sha256 } from './db';
import { inputAuthority, inputObject } from './input-objects';
import { actorForGithubId } from './auth';
import { getRecipeCapture } from './recipe-captures';
import { getCatalogPackage, reviewReason } from './catalog-ownership';
import { PolicyError } from './policy';
import { decodeBase64, verifyEd25519, requireExactKeys, requireKeys, requireLeaseToken, refreshWorkerMetadata, leaseExpiryValue, parseJsonRequest,
  type WorkerMetadata, WorkerProtocolError } from './worker-protocol';

type InspectionEnv = Pick<Env, 'DB' | 'ARTIFACTS' | 'GITHUB_REPOSITORY'>;

export type RecipeInspection = { id: string; capture_sha256: string; recipe_override_sha256: string | null; factory_run_id: string | null; factory_attempt: number | null; architecture: Architecture; image_id: string; image_ref: string;
  catalog_revision: number | null; catalog_sha256: string | null; requested_by: string; created_at: number; reason: string;
  status: 'queued' | 'leased' | 'succeeded' | 'failed' | 'cancelled'; attempt: number; worker_id: string | null;
  lease_token: string | null; lease_expires_at: number | null; error: string | null };

export type InspectionJob = { kind: 'recipe-inspection'; id: string; packageName: string; recipeCapture: InputObject; recipeOverride?: InputObject; factoryRunId?: string; factoryAttempt?: number; architecture: Architecture;
  attempt: number; imageRef: string; imageDigest: string; leaseToken: string; leaseExpiresAt: string };

type InspectionOptions = { recipeOverride?: InputObject; factoryRunId?: string; factoryAttempt?: number };

export async function requestRecipeInspection(env: InspectionEnv, actor: Actor | null, captureSha: string, imageId: string, reason: string, options: InspectionOptions = {}) {
  const human = await inputAuthority(env.DB, actor), message = reviewReason(reason);
  const capture = await getRecipeCapture(env, captureSha);
  const image = await env.DB.prepare('SELECT image_ref,architecture FROM build_images WHERE id=? AND enabled=1').bind(imageId).first<{ image_ref: string; architecture: Architecture }>();

  if (!image) throw new PolicyError(409, 'Choose an enabled, digest-pinned inspection image.');
  let catalogRevision: number | null = null, catalogSha: string | null = null;

  if (capture.summary.admissionRequired) {
    const catalog = await getCatalogPackage(env.DB, capture.manifest.pkgbase);

    if (!catalog || catalog.admitted_revision !== catalog.current_revision ||
        !await env.DB.prepare('SELECT 1 FROM authorized_catalog_inputs WHERE pkgbase=? AND revision=? AND manifest_sha256=?')
          .bind(catalog.pkgbase, catalog.revision, catalog.manifest_sha256).first()) throw new PolicyError(409, 'Human OPR source admission is required before executing this reference recipe.');
    const policy = JSON.parse(catalog.manifest_json) as CatalogManifest, reference = policy.sourceReference;
    const normalized = (url: string) => url.replace(/\.git$/, '').replace(/\/$/, '');

    if (!['aur-reference', 'alarm-reference'].includes(policy.origin) || !reference ||
        !((reference.commit === capture.manifest.commit && normalized(reference.url) === normalized(capture.manifest.repository)) ||
          (reference.commit === capture.summary.omarchy?.upstream_commit &&
            (new URL(reference.url).hostname === 'aur.archlinux.org' || normalized(reference.url) === 'https://github.com/archlinuxarm/PKGBUILDs')))) {
      throw new PolicyError(409, 'Admitted source policy must bind this exact reference repository and commit.');
    }

    catalogRevision = catalog.revision; catalogSha = catalog.manifest_sha256;
  }

  if (options.recipeOverride) {
    if (!/^[a-f0-9]{64}$/.test(options.recipeOverride.sha256) || !Number.isSafeInteger(options.recipeOverride.size) || options.recipeOverride.size < 1 || options.recipeOverride.size > 2 * 1024 * 1024) {
      throw new PolicyError(400, 'Recipe inspection override is invalid.');
    }
    if ((await inputObject(env.DB, options.recipeOverride.sha256)).size !== options.recipeOverride.size) throw new PolicyError(409, 'Recipe inspection override changed.');
  }
  if ((options.factoryRunId === undefined) !== (options.factoryAttempt === undefined) || (options.factoryAttempt !== undefined && (!Number.isSafeInteger(options.factoryAttempt) || options.factoryAttempt < 1 || options.factoryAttempt > 3))) throw new PolicyError(400, 'Factory inspection binding is invalid.');
  if (options.factoryRunId) {
    const run = await env.DB.prepare(`SELECT created_by FROM factory_runs WHERE id=? AND (
      (status='running' AND current_attempt=? AND lease_token IS NOT NULL AND lease_expires_at>?) OR
      (status='queued' AND attempt_count=?-1 AND current_attempt=?-1 AND lease_token IS NULL AND lease_expires_at IS NULL))`)
      .bind(options.factoryRunId, options.factoryAttempt, now(), options.factoryAttempt, options.factoryAttempt).first<{ created_by: string }>();
    if (!run || !/^github:[1-9][0-9]{0,19}$/.test(run.created_by)) throw new PolicyError(409, 'Factory inspection authority is no longer active.');
  }
  const id = await sha256(canonicalJson({ capture: captureSha, recipeOverride: options.recipeOverride ?? null, image: image.image_ref, architecture: image.architecture, catalogRevision, catalogSha, requestedBy: human.id, factoryRunId: options.factoryRunId ?? null, factoryAttempt: options.factoryAttempt ?? null }));
  const timestamp = now();
  const statements = [
    env.DB.prepare(`INSERT OR IGNORE INTO recipe_inspections(id,capture_sha256,recipe_override_sha256,factory_run_id,factory_attempt,architecture,image_id,image_ref,catalog_revision,catalog_sha256,requested_by,reason,created_at,status)
      VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,'queued')`).bind(id, captureSha, options.recipeOverride?.sha256 ?? null, options.factoryRunId ?? null, options.factoryAttempt ?? null, image.architecture, imageId, image.image_ref, catalogRevision, catalogSha, human.id, message, timestamp),
    audit(env.DB, human.id, 'recipe.inspection_requested', id, { captureSha, imageRef: image.image_ref, architecture: image.architecture, reason: message }),
  ];
  if (!options.factoryRunId) statements.splice(1, 0, env.DB.prepare(`UPDATE recipe_inspections SET status='queued',worker_id=NULL,lease_token=NULL,lease_expires_at=NULL,error=NULL WHERE id=?
      AND (status IN ('failed','cancelled') OR (status='leased' AND lease_expires_at<=?))`).bind(id, timestamp));
  await env.DB.batch(statements);

  return { id };
}

export async function requestFactoryRecipeInspection(env: InspectionEnv, runId: string, attempt: number, captureSha: string, imageId: string, override: InputObject, reason: string) {
  const run = await env.DB.prepare(`SELECT created_by FROM factory_runs WHERE id=? AND (
    (status='running' AND current_attempt=? AND lease_token IS NOT NULL AND lease_expires_at>?) OR
    (status='queued' AND attempt_count=?-1 AND current_attempt=?-1 AND lease_token IS NULL AND lease_expires_at IS NULL))`)
    .bind(runId, attempt, now(), attempt, attempt).first<{ created_by: string }>();
  if (!run || !/^github:[1-9][0-9]{0,19}$/.test(run.created_by)) throw new PolicyError(409, 'Factory inspection authority is no longer active.');
  const actor = await actorForGithubId(env.DB, run.created_by.slice(7));
  return requestRecipeInspection(env, actor, captureSha, imageId, reason, { recipeOverride: override, factoryRunId: runId, factoryAttempt: attempt });
}

export async function cancelRecipeInspection(db: D1Database, actor: Actor | null, capture: string, id: string, reason: string) {
  const human = await inputAuthority(db, actor), message = reviewReason(reason);
  await db.batch([
    db.prepare("UPDATE recipe_inspections SET status='cancelled',lease_token=NULL,lease_expires_at=NULL,error=? WHERE id=? AND capture_sha256=? AND status IN ('queued','leased')")
      .bind(message, id, capture),
    audit(db, human.id, 'recipe.inspection_cancelled', id, { captureSha: capture, reason: message }),
  ]);
}

export async function claimRecipeInspection(db: D1Database, worker: Worker, metadata: WorkerMetadata | null): Promise<InspectionJob | null> {
  if (!(metadata?.capabilities ?? JSON.parse(worker.capabilities_json ?? '[]')).includes('recipe-inspection-v1')) return null;
  const timestamp = now(); await refreshWorkerMetadata(db, worker, metadata, timestamp);
  const overrideCapability = Number((metadata?.capabilities ?? JSON.parse(worker.capabilities_json ?? '[]')).includes('recipe-inspection-override-v1'));

  const candidate = await db.prepare(`SELECT * FROM current_recipe_inspections WHERE architecture=?
    AND (recipe_override_sha256 IS NULL OR ?=1)
    AND (status='queued' OR (status='leased' AND lease_expires_at<=? AND attempt<3)) ORDER BY created_at,id LIMIT 1`)
    .bind(worker.architecture, overrideCapability, timestamp).first<RecipeInspection>();

  if (!candidate) return null;
  const token = crypto.randomUUID(), expiry = timestamp + 600, tokenSha = await sha256(token);

  try {
    const results = await db.batch([
      db.prepare(`UPDATE recipe_inspections SET status='leased',attempt=attempt+1,worker_id=?,lease_token=?,lease_expires_at=?,error=NULL WHERE id=? AND attempt=?
        AND (status='queued' OR (status='leased' AND lease_expires_at<=? AND attempt<3))
        AND EXISTS(SELECT 1 FROM current_recipe_inspections current WHERE current.id=recipe_inspections.id)
        AND EXISTS(SELECT 1 FROM workers WHERE id=? AND status='active' AND accepting_jobs=1 AND architecture=?)`)
        .bind(worker.id, token, expiry, candidate.id, candidate.attempt, timestamp, worker.id, worker.architecture),
      db.prepare(`INSERT INTO recipe_inspection_attempts(job_id,attempt,worker_id,public_key,lease_token_sha256,lease_expires_at,created_at)
        SELECT i.id,i.attempt,w.id,w.public_key,?,i.lease_expires_at,? FROM recipe_inspections i JOIN workers w ON w.id=i.worker_id
        WHERE i.id=? AND i.lease_token=? AND i.worker_id=?`).bind(tokenSha, timestamp, candidate.id, token, worker.id),
      db.prepare(`INSERT INTO audit_events(actor,action,target,detail,created_at) SELECT ?,'worker.recipe_inspection_claimed',?,?,? WHERE changes()=1`)
        .bind(`worker:${worker.id}`, candidate.id, canonicalJson({ captureSha: candidate.capture_sha256, attempt: candidate.attempt + 1 }), timestamp),
    ]);

    if (!results[0].meta.changes) return null;
  } catch (cause) {
    if (cause instanceof Error && /constraint|authority/i.test(cause.message)) return null;
    throw cause;
  }

  const capture = await db.prepare('SELECT c.pkgbase,o.size,i.recipe_override_sha256,i.factory_run_id,i.factory_attempt FROM recipe_captures c JOIN input_objects o ON o.sha256=c.sha256 JOIN recipe_inspections i ON i.id=? WHERE c.sha256=?')
    .bind(candidate.id, candidate.capture_sha256).first<{ pkgbase: string; size: number; recipe_override_sha256: string | null; factory_run_id: string | null; factory_attempt: number | null }>();

  if (!capture) throw new WorkerProtocolError(409, 'Retained recipe capture is unavailable');

  const override = capture.recipe_override_sha256 ? await inputObject(db, capture.recipe_override_sha256) : null;
  return { kind: 'recipe-inspection', id: candidate.id, packageName: capture.pkgbase, recipeCapture: { sha256: candidate.capture_sha256, size: capture.size }, ...(override ? { recipeOverride: { sha256: override.sha256, size: override.size } } : {}), ...(capture.factory_run_id ? { factoryRunId: capture.factory_run_id, factoryAttempt: capture.factory_attempt! } : {}),
    architecture: candidate.architecture, attempt: candidate.attempt + 1, imageRef: candidate.image_ref, imageDigest: candidate.image_ref.split('@')[1],
    leaseToken: token, leaseExpiresAt: leaseExpiryValue(expiry) };
}

export async function requireRecipeInspectionLease(db: D1Database, worker: Worker, id: string, token: unknown) {
  const job = await db.prepare(`SELECT i.* FROM current_recipe_inspections i JOIN workers w ON w.id=i.worker_id
    JOIN recipe_inspection_attempts a ON a.job_id=i.id AND a.attempt=i.attempt AND a.worker_id=w.id AND a.public_key=w.public_key
    WHERE i.id=? AND i.lease_token=? AND i.status='leased' AND i.lease_expires_at>? AND w.id=? AND w.status='active' AND i.architecture=w.architecture`)
    .bind(id, requireLeaseToken(token), now(), worker.id).first<RecipeInspection>();

  if (!job) throw new WorkerProtocolError(409, 'Recipe inspection lease is unavailable or source authority changed');

  return job;
}

export async function recipeInspectionObject(db: D1Database, job: RecipeInspection, digest: string) {
  if (job.recipe_override_sha256 === digest) return inputObject(db, digest);
  const grant = await db.prepare(`SELECT 1 FROM recipe_captures c WHERE c.sha256=? AND (c.sha256=? OR json_extract(c.manifest_json,'$.git.commit.sha256')=? OR
    EXISTS(SELECT 1 FROM json_each(c.manifest_json,'$.git.trees') t WHERE json_extract(t.value,'$.sha256')=?) OR
    EXISTS(SELECT 1 FROM json_each(c.manifest_json,'$.files') f WHERE json_extract(f.value,'$.object.sha256')=?))`)
    .bind(job.capture_sha256, digest, digest, digest, digest).first();

  if (!grant) throw new WorkerProtocolError(403, 'Object is outside the leased recipe capture');

  return inputObject(db, digest);
}

export async function completeRecipeInspection(db: D1Database, worker: Worker, id: string, input: Record<string, unknown>) {
  requireExactKeys(input, ['leaseToken', 'report', 'signature']);

  if (typeof input.report !== 'string' || new TextEncoder().encode(input.report).length > 2 * 1024 * 1024 || typeof input.signature !== 'string') throw new WorkerProtocolError(400, 'Invalid bounded inspection report');
  const reportSha = await sha256(input.report);

  const recorded = await db.prepare(`SELECT r.error FROM recipe_inspection_results r JOIN current_recipe_inspections i ON i.id=r.job_id AND i.attempt=r.attempt
    JOIN recipe_inspection_attempts a ON a.job_id=r.job_id AND a.attempt=r.attempt JOIN workers w ON w.id=a.worker_id AND w.public_key=a.public_key AND w.status='active'
    WHERE r.job_id=? AND r.report_sha256=? AND r.signature=? AND w.id=? AND a.lease_token_sha256=?`)
    .bind(id, reportSha, input.signature, worker.id, await sha256(requireLeaseToken(input.leaseToken))).first<{ error: string | null }>();

  if (recorded) return { status: recorded.error === null ? 'succeeded' : 'failed' };
  const job = await requireRecipeInspectionLease(db, worker, id, input.leaseToken);
  const report = parseJsonRequest(new TextEncoder().encode(input.report));
  const reportedOverride = (Object.prototype.hasOwnProperty.call(report, 'recipeOverride') ? report.recipeOverride : null) as { sha256?: unknown; size?: unknown } | null;
  const keys = ['schemaVersion', 'kind', 'jobId', 'attempt', 'capture', 'recipeOverride', 'architecture', 'imageRef', 'host', 'sandbox', 'startedAt', 'finishedAt', 'srcinfo', 'srcinfoSha256', 'log', 'error'];
  requireExactKeys(report, keys); requireKeys(report, keys.filter((key) => key !== 'recipeOverride'));
  const ref = parseInputObject(report.capture, 512 * 1024);

  if (report.schemaVersion !== 1 || report.kind !== 'recipe-inspection' || report.jobId !== id || report.attempt !== job.attempt ||
      ref.sha256 !== job.capture_sha256 || ref.size !== (await inputObject(db, ref.sha256)).size || report.architecture !== job.architecture || report.imageRef !== job.image_ref ||
      (job.recipe_override_sha256 === null ? reportedOverride !== null : !reportedOverride || reportedOverride.sha256 !== job.recipe_override_sha256 || reportedOverride.size !== (await inputObject(db, job.recipe_override_sha256)).size) ||
      canonicalJson(report.sandbox) !== canonicalJson({ network: 'disabled', readOnly: true, user: '65534:65534' }) ||
      typeof report.srcinfo !== 'string' || new TextEncoder().encode(report.srcinfo).length > 1024 * 1024 || report.srcinfoSha256 !== await sha256(report.srcinfo) ||
      typeof report.log !== 'string' || report.log.length > 128 * 1024 || (report.error !== null && (typeof report.error !== 'string' || report.error.length > 4096))) throw new WorkerProtocolError(409, 'Inspection report differs from leased scope');

  if (report.host !== null || report.error === null) assertNativeHost(report.host, job.architecture);
  const started = Date.parse(String(report.startedAt)), finished = Date.parse(String(report.finishedAt));
  const attempt = await db.prepare('SELECT created_at FROM recipe_inspection_attempts WHERE job_id=? AND attempt=?').bind(id, job.attempt).first<{ created_at: number }>();

  if (!Number.isFinite(started) || !Number.isFinite(finished) || started < (attempt!.created_at - 120) * 1000 || finished < started ||
      finished > (now() + 120) * 1000 || finished - started > 600_000) throw new WorkerProtocolError(409, 'Inspection report times exceed leased scope');

  if (!await verifyEd25519(decodeBase64(worker.public_key, 'worker public key'), new TextEncoder().encode(input.report), decodeBase64(input.signature, 'inspection signature'))) throw new WorkerProtocolError(403, 'Inspection signature is invalid');
  let metadata: Srcinfo | null = null, error = report.error as string | null;

  if (error === null) {
    try {
      metadata = parseSrcinfo(report.srcinfo);
      const capture = await db.prepare('SELECT pkgbase FROM recipe_captures WHERE sha256=?').bind(job.capture_sha256).first<{ pkgbase: string }>();

      if (metadata.pkgbase !== capture!.pkgbase) throw new Error('Inspected package base differs from capture.');
    } catch (cause) { metadata = null; error = cause instanceof Error ? cause.message : 'Inspected metadata is invalid.'; }
  }

  if (metadata && new TextEncoder().encode(canonicalJson(metadata)).length > 2 * 1024 * 1024) {
    metadata = null; error = 'Inspected metadata exceeds its 2 MiB review budget.';
  }

  const timestamp = now();

  try {
    await db.batch([
      db.prepare(`UPDATE recipe_inspections SET status=?,error=?,lease_token=NULL WHERE id=? AND attempt=? AND worker_id=? AND lease_token=? AND status='leased' AND lease_expires_at>?`)
        .bind(error === null ? 'succeeded' : 'failed', error, id, job.attempt, worker.id, input.leaseToken, timestamp),
      db.prepare('INSERT INTO distribution_assertions(expected,actual) VALUES(1,changes())'),
      db.prepare('INSERT INTO recipe_inspection_results(job_id,attempt,report_json,report_sha256,signature,metadata_json,error,created_at) VALUES(?,?,?,?,?,?,?,?)')
        .bind(id, job.attempt, input.report, reportSha, input.signature, metadata ? canonicalJson(metadata) : null, error, timestamp),
      audit(db, `worker:${worker.id}`, 'recipe.inspection_completed', id, { captureSha: job.capture_sha256, attempt: job.attempt, reportSha256: reportSha, error }),
    ]);
  } catch (cause) {
    if (cause instanceof Error && /constraint|authority/i.test(cause.message)) throw new WorkerProtocolError(409, 'Inspection lease or authority changed before completion');
    throw cause;
  }

  return { status: error === null ? 'succeeded' : 'failed' };
}

export async function listRecipeInspections(db: D1Database, capture: string) {
  const rows = await query<Pick<RecipeInspection, 'id' | 'capture_sha256' | 'architecture' | 'image_ref' | 'requested_by' | 'reason' | 'created_at' | 'status' | 'attempt' | 'worker_id' | 'lease_expires_at' | 'error'> & { metadata_bytes: number; report_sha256: string | null; current: number }>(db,
    `SELECT i.id,i.capture_sha256,i.architecture,i.image_ref,i.requested_by,i.reason,i.created_at,i.status,i.attempt,i.worker_id,i.lease_expires_at,i.error,
      COALESCE(length(CAST(r.metadata_json AS BLOB)),0) AS metadata_bytes,r.report_sha256,EXISTS(SELECT 1 FROM current_recipe_inspections current JOIN recipe_inspection_attempts a ON a.job_id=current.id
      JOIN workers w ON w.id=a.worker_id AND w.public_key=a.public_key AND w.status='active' WHERE current.id=i.id AND a.attempt=i.attempt) AS current
      FROM recipe_inspections i LEFT JOIN recipe_inspection_results r ON r.job_id=i.id AND r.attempt=i.attempt
      WHERE i.capture_sha256=? ORDER BY i.created_at DESC,i.id LIMIT 50`, capture);

  const latest = rows.filter((row, index) => row.status === 'succeeded' && row.current && !rows.slice(0, index).some((previous) => previous.architecture === row.architecture && previous.status === 'succeeded' && previous.current));

  if (latest.some((row) => row.metadata_bytes > 2 * 1024 * 1024)) throw new PolicyError(409, 'Inspected metadata exceeds its review budget.');

  const metadata = await query<{ job_id: string; metadata_json: string }>(db, `SELECT r.job_id,r.metadata_json FROM recipe_inspection_results r
    WHERE EXISTS(SELECT 1 FROM json_each(?) selected WHERE json_extract(selected.value,'$.id')=r.job_id AND json_extract(selected.value,'$.attempt')=r.attempt)`,
    canonicalJson(latest.map((row) => ({ id: row.id, attempt: row.attempt }))));

  return rows.map((row) => ({ ...row, metadata_json: metadata.find((value) => value.job_id === row.id)?.metadata_json ?? null }));
}
