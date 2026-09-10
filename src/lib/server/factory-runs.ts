import { canonicalJson } from '../canonical-json';
import type { Architecture } from '../model';
import { audit, id, now, sha256 } from './db';

export const FACTORY_MAX_ATTEMPTS = 3;

const SHA256 = /^[0-9a-f]{64}$/;

const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,255}$/;

export const FACTORY_TARGET_KINDS = ['generated', 'preserved', 'manual', 'cohort', 'cohort-member', 'image', 'system', 'opr', 'system-image', 'opr-image', 'bootstrap', 'toolchain', 'recipe', 'build'] as const;

export type FactoryTargetKind = (typeof FACTORY_TARGET_KINDS)[number];

const TARGET_KINDS = new Set<string>(FACTORY_TARGET_KINDS);

export type FactoryRunStatus = 'queued' | 'running' | 'succeeded' | 'needs-human-intervention' | 'cancelled';

export type FactoryAttemptStatus = 'running' | 'succeeded' | 'failed';

export type FactoryFailureKind = 'build' | 'validation' | 'dependency' | 'analysis' | 'runtime' | 'reproducibility' | 'policy' | 'infrastructure';

export interface FactoryRunInput {
  id?: string;
  targetKind: string;
  targetId: string;
  unitKey: string;
  policy: unknown;
  createdBy: string;
  sourceRunId?: string;
  requestedRevisionId?: string;
}

export interface FactoryRun {
  id: string;
  targetKind: string;
  targetId: string;
  unitKey: string;
  executionScope: 'private';
  status: FactoryRunStatus;
  maxAttempts: 3;
  attemptCount: number;
  currentAttempt: number | null;
  successfulAttempt: number | null;
  sourceRunId: string | null;
  requestedRevisionId: string | null;
  policy: unknown;
  artifact: unknown;
  failure: unknown;
  leaseToken: string | null;
  leaseExpiresAt: number | null;
  createdBy: string;
  createdAt: number;
  updatedAt: number;
}

export interface FactoryAttempt {
  id: string;
  runId: string;
  attempt: number;
  reservationKey: string;
  status: FactoryAttemptStatus;
  candidateRevisionId: string | null;
  candidateSha256: string;
  inputSha256: string;
  architecture: Architecture | null;
  candidate: unknown;
  failureKind: FactoryFailureKind | null;
  failure: unknown;
  artifact: unknown;
  buildIds: string[];
  dispatchId: string | null;
  leaseToken: string;
  leaseExpiresAt: number;
  startedAt: number;
  finishedAt: number | null;
  createdAt: number;
  updatedAt: number;
}

export class FactoryRunError extends Error {
  constructor(readonly code: string, message: string) {
    super(message);
    this.name = 'FactoryRunError';
  }
}

export function factoryRunErrorStatus(error: FactoryRunError): number {
  if (error.code === 'invalid-input') return 400;
  if (['storage', 'dispatch-failed', 'infrastructure', 'ambiguous'].includes(error.code)) return 503;
  return 409;
}

export class FactoryPolicyStopError extends FactoryRunError {
  constructor(message = 'Factory policy changed; human intervention is required.') {
    super('policy-stop', message);
    this.name = 'FactoryPolicyStopError';
  }
}

function requireIdentifier(value: string, field: string): string {
  if (typeof value !== 'string' || !IDENTIFIER.test(value)) throw new FactoryRunError('invalid-input', `Invalid ${field}.`);

  return value;
}

function requireDigest(value: string, field: string): string {
  if (typeof value !== 'string' || !SHA256.test(value)) throw new FactoryRunError('invalid-input', `Invalid ${field}.`);

  return value;
}

function parseJson(value: string | null, field: string): unknown {
  if (value === null) return null;

  try { return JSON.parse(value); } catch { throw new FactoryRunError('storage', `Stored factory ${field} is invalid.`); }
}

function changed(result: unknown): boolean {
  return Number((result as { meta?: { changes?: number } } | undefined)?.meta?.changes ?? 0) > 0;
}

type RunRow = {
  id: string; target_kind: string; target_id: string; unit_key: string; execution_scope: 'private'; status: FactoryRunStatus;
  max_attempts: number; attempt_count: number; current_attempt: number | null; successful_attempt: number | null;
  source_run_id: string | null; requested_revision_id: string | null; policy_json: string; artifact_json: string | null;
  failure_json: string | null; lease_token: string | null; lease_expires_at: number | null; created_by: string; created_at: number; updated_at: number;
};

type AttemptRow = {
  id: string; run_id: string; attempt: number; reservation_key: string; status: FactoryAttemptStatus;
  candidate_revision_id: string | null; candidate_sha256: string; input_sha256: string; architecture: Architecture | null;
  candidate_json: string; failure_kind: FactoryFailureKind | null; failure_json: string | null; artifact_json: string | null;
  build_ids_json: string;
  dispatch_id: string | null;
  lease_token: string; lease_expires_at: number; started_at: number; finished_at: number | null; created_at: number; updated_at: number;
};

function mapRun(row: RunRow): FactoryRun {
  if (row.execution_scope !== 'private' || row.max_attempts !== FACTORY_MAX_ATTEMPTS) throw new FactoryRunError('storage', 'Stored factory run has an invalid execution scope or retry budget.');

  return {
    id: row.id, targetKind: row.target_kind, targetId: row.target_id, unitKey: row.unit_key, executionScope: 'private', status: row.status,
    maxAttempts: FACTORY_MAX_ATTEMPTS, attemptCount: row.attempt_count, currentAttempt: row.current_attempt, successfulAttempt: row.successful_attempt,
    sourceRunId: row.source_run_id, requestedRevisionId: row.requested_revision_id, policy: parseJson(row.policy_json, 'policy'),
    artifact: parseJson(row.artifact_json, 'artifact'), failure: parseJson(row.failure_json, 'failure'), leaseToken: row.lease_token,
    leaseExpiresAt: row.lease_expires_at, createdBy: row.created_by, createdAt: row.created_at, updatedAt: row.updated_at,
  };
}

function mapAttempt(row: AttemptRow): FactoryAttempt {
  let buildIds: string[] = [];
  try {
    const parsed = JSON.parse(row.build_ids_json);
    if (!Array.isArray(parsed) || parsed.some((value) => typeof value !== 'string' || !IDENTIFIER.test(value))) throw new Error('invalid build IDs');
    buildIds = parsed;
  } catch { throw new FactoryRunError('storage', 'Stored factory attempt build binding is invalid.'); }
  return {
    id: row.id, runId: row.run_id, attempt: row.attempt, reservationKey: row.reservation_key, status: row.status,
    candidateRevisionId: row.candidate_revision_id, candidateSha256: row.candidate_sha256, inputSha256: row.input_sha256,
    architecture: row.architecture, candidate: parseJson(row.candidate_json, 'candidate'), failureKind: row.failure_kind,
    failure: parseJson(row.failure_json, 'failure'), artifact: parseJson(row.artifact_json, 'artifact'), leaseToken: row.lease_token,
    buildIds,
    dispatchId: row.dispatch_id,
    leaseExpiresAt: row.lease_expires_at, startedAt: row.started_at, finishedAt: row.finished_at, createdAt: row.created_at, updatedAt: row.updated_at,
  };
}

async function runRow(db: D1Database, runId: string): Promise<RunRow | null> {
  return db.prepare('SELECT * FROM factory_runs WHERE id=?').bind(runId).first<RunRow>();
}

async function attemptRow(db: D1Database, runId: string, attempt: number): Promise<AttemptRow | null> {
  return db.prepare('SELECT * FROM factory_run_attempts WHERE run_id=? AND attempt=?').bind(runId, attempt).first<AttemptRow>();
}

async function activeRun(db: D1Database, targetKind: string, targetId: string, unitKey: string): Promise<RunRow | null> {
  return db.prepare(`SELECT * FROM factory_runs WHERE target_kind=? AND target_id=? AND unit_key=?
    AND status IN ('queued','running') ORDER BY created_at DESC LIMIT 1`).bind(targetKind, targetId, unitKey).first<RunRow>();
}

async function latestRun(db: D1Database, targetKind: string, targetId: string, unitKey: string): Promise<RunRow | null> {
  return db.prepare('SELECT * FROM factory_runs WHERE target_kind=? AND target_id=? AND unit_key=? ORDER BY created_at DESC LIMIT 1')
    .bind(targetKind, targetId, unitKey).first<RunRow>();
}

function validateRunInput(input: FactoryRunInput): { id: string; policyJson: string } {
  if (!TARGET_KINDS.has(input.targetKind)) throw new FactoryRunError('invalid-input', 'Invalid factory target kind.');
  requireIdentifier(input.targetKind, 'target kind');
  requireIdentifier(input.targetId, 'target id');
  requireIdentifier(input.unitKey, 'unit key');
  requireIdentifier(input.createdBy, 'creator');

  if (input.policy === undefined) throw new FactoryRunError('invalid-input', 'Factory execution policy is required.');
  const policyJson = canonicalJson(input.policy);

  if (policyJson.length > 64 * 1024) throw new FactoryRunError('invalid-input', 'Factory execution policy is too large.');
  const runId = input.id ? requireIdentifier(input.id, 'run id') : id();

  if (input.sourceRunId) requireIdentifier(input.sourceRunId, 'source run id');

  if (input.requestedRevisionId) requireIdentifier(input.requestedRevisionId, 'requested revision id');

  return { id: runId, policyJson };
}

/** Return the current active run, or create one. A human successor must use createFactorySuccessorRun. */
export async function startFactoryRun(db: D1Database, input: FactoryRunInput): Promise<FactoryRun> {
  const { id: runId, policyJson } = validateRunInput(input);
  const existing = await activeRun(db, input.targetKind, input.targetId, input.unitKey);

  if (existing) {
    if (existing.policy_json !== policyJson) {
      await stopFactoryRun(db, existing.id, 'Execution policy expanded or changed.', input.policy);
      throw new FactoryPolicyStopError();
    }

    return mapRun(existing);
  }

  const previous = await latestRun(db, input.targetKind, input.targetId, input.unitKey);

  if (previous?.status === 'succeeded') {
    if (previous.policy_json === policyJson) return mapRun(previous);
    throw new FactoryRunError('run-succeeded', 'A successful factory artifact already exists; changed inputs require a new reviewed run.');
  }

  if (previous?.status === 'needs-human-intervention' && !input.sourceRunId) {
    throw new FactoryRunError('human-intervention', 'Factory run is exhausted; create an audited human successor.');
  }

  if (input.sourceRunId) {
    const source = await runRow(db, input.sourceRunId);

    if (!source || !['needs-human-intervention', 'succeeded'].includes(source.status)) throw new FactoryRunError('invalid-successor', 'Only a completed factory run can be continued by a human.');

    if (source.target_kind !== input.targetKind || source.target_id !== input.targetId || source.unit_key !== input.unitKey) {
      throw new FactoryRunError('invalid-successor', 'Factory successor must keep the same build unit.');
    }
  }

  const timestamp = now();

  try {
    await db.batch([
      db.prepare(`INSERT INTO factory_runs(
        id,target_kind,target_id,unit_key,execution_scope,status,max_attempts,attempt_count,source_run_id,requested_revision_id,policy_json,created_by,created_at,updated_at
      ) VALUES(?,?,?,?, 'private','queued',3,0,?,?,?,?,?,?)`)
        .bind(runId, input.targetKind, input.targetId, input.unitKey, input.sourceRunId ?? null, input.requestedRevisionId ?? null, policyJson, input.createdBy, timestamp, timestamp),
      audit(db, input.createdBy, 'factory.run_started', runId, { targetKind: input.targetKind, targetId: input.targetId, unitKey: input.unitKey, sourceRunId: input.sourceRunId ?? null }),
    ]);
  } catch (cause) {
    if (/unique/i.test(cause instanceof Error ? cause.message : '')) {
      const raced = await activeRun(db, input.targetKind, input.targetId, input.unitKey);

      if (raced) return mapRun(raced);
    }

    throw cause;
  }

  const created = await runRow(db, runId);

  if (!created) throw new FactoryRunError('storage', 'Factory run was not persisted.');

  return mapRun(created);
}

export async function createFactorySuccessorRun(db: D1Database, sourceRunId: string, input: Omit<FactoryRunInput, 'sourceRunId'>): Promise<FactoryRun> {
  return startFactoryRun(db, { ...input, sourceRunId });
}

export async function startFactoryIntervention(db: D1Database, input: { sourceRunId: string; targetKind: string; targetId: string; unitKey: string; policy: unknown; createdBy: string; id?: string; requestedRevisionId?: string }): Promise<FactoryRun> {
  const successor = await createFactorySuccessorRun(db, input.sourceRunId, {
    id: input.id, targetKind: input.targetKind, targetId: input.targetId, unitKey: input.unitKey,
    policy: input.policy, createdBy: input.createdBy, requestedRevisionId: input.requestedRevisionId,
  });
  await audit(db, input.createdBy, 'factory.human_successor_started', successor.id, { sourceRunId: input.sourceRunId, targetKind: input.targetKind, targetId: input.targetId, unitKey: input.unitKey }).run();
  return successor;
}

export async function reconcileExpiredFactoryBuilds(db: D1Database, at = now()): Promise<void> {
  const rows = await db.prepare(`SELECT DISTINCT factory_run_id AS run_id FROM builds
    WHERE private_candidate=1 AND status='leased' AND lease_expires_at IS NOT NULL AND lease_expires_at<=? AND factory_run_id IS NOT NULL`).bind(at).all<{ run_id: string }>();
  for (const row of rows.results) await stopFactoryRun(db, row.run_id, 'Private factory worker lease expired; execution is ambiguous and requires human intervention.');
}

export async function getFactoryRun(db: D1Database, runId: string): Promise<FactoryRun | null> {
  requireIdentifier(runId, 'run id');
  const row = await runRow(db, runId);

  return row ? mapRun(row) : null;
}

export async function latestFactoryRun(db: D1Database, targetKind: string, targetId: string, unitKey: string): Promise<FactoryRun | null> {
  if (!TARGET_KINDS.has(targetKind)) throw new FactoryRunError('invalid-input', 'Invalid factory target kind.');
  requireIdentifier(targetId, 'target id');
  requireIdentifier(unitKey, 'unit key');
  const row = await latestRun(db, targetKind, targetId, unitKey);

  return row ? mapRun(row) : null;
}

export async function getFactoryAttempt(db: D1Database, runId: string, attempt: number): Promise<FactoryAttempt | null> {
  requireIdentifier(runId, 'run id');

  if (!Number.isSafeInteger(attempt) || attempt < 1 || attempt > FACTORY_MAX_ATTEMPTS) throw new FactoryRunError('invalid-input', 'Invalid factory attempt.');
  const row = await attemptRow(db, runId, attempt);

  return row ? mapAttempt(row) : null;
}

export async function listFactoryAttempts(db: D1Database, runId: string): Promise<FactoryAttempt[]> {
  requireIdentifier(runId, 'run id');
  const rows = await db.prepare('SELECT * FROM factory_run_attempts WHERE run_id=? ORDER BY attempt').bind(runId).all<AttemptRow>();

  return rows.results.map(mapAttempt);
}

export async function attachFactoryAttemptBuilds(db: D1Database, runId: string, attempt: number, leaseToken: string, buildIds: readonly string[]): Promise<FactoryAttempt> {
  requireIdentifier(runId, 'run id');
  requireIdentifier(leaseToken, 'lease token');
  if (!Number.isSafeInteger(attempt) || attempt < 1 || attempt > FACTORY_MAX_ATTEMPTS) throw new FactoryRunError('invalid-input', 'Invalid factory attempt.');
  const ids = [...new Set(buildIds)].map((value) => requireIdentifier(value, 'build id')).sort();
  if (!ids.length || ids.length > 128) throw new FactoryRunError('invalid-input', 'Factory attempt must reference one to 128 builds.');
  const current = await attemptRow(db, runId, attempt);
  if (!current || current.status !== 'running' || current.lease_token !== leaseToken || current.lease_expires_at <= now()) throw new FactoryRunError('lease-fenced', 'Factory attempt lease is fenced or expired.');
  const mapped = mapAttempt(current);
  if (mapped.buildIds.length && canonicalJson(mapped.buildIds) !== canonicalJson(ids)) throw new FactoryRunError('reservation-conflict', 'Factory attempt is already bound to different builds.');
  if (mapped.buildIds.length) return mapped;
  const timestamp = now();
  const result = await db.prepare(`UPDATE factory_run_attempts SET build_ids_json=?,updated_at=?
    WHERE run_id=? AND attempt=? AND lease_token=? AND status='running' AND lease_expires_at>? AND build_ids_json='[]'
      AND EXISTS (SELECT 1 FROM factory_runs WHERE id=? AND current_attempt=? AND lease_token=? AND status='running' AND lease_expires_at>?)`)
    .bind(JSON.stringify(ids), timestamp, runId, attempt, leaseToken, timestamp, runId, attempt, leaseToken, timestamp).run();
  if (!changed(result)) throw new FactoryRunError('lease-fenced', 'Factory attempt lease is fenced or expired.');
  const row = await attemptRow(db, runId, attempt);
  if (!row) throw new FactoryRunError('not-found', 'Factory attempt not found.');
  return mapAttempt(row);
}

export interface FactoryAttemptInput {
  runId: string;
  reservationKey: string;
  candidateSha256: string;
  inputSha256: string;
  candidate?: unknown;
  candidateRevisionId?: string;
  architecture?: Architecture;
  policy?: unknown;
  leaseSeconds?: number;
}

/** Atomically reserve one budget slot. Reservation key makes workflow redelivery idempotent. */
export async function reserveFactoryAttempt(db: D1Database, input: FactoryAttemptInput): Promise<FactoryAttempt> {
  requireIdentifier(input.runId, 'run id');
  requireIdentifier(input.reservationKey, 'reservation key');
  requireDigest(input.candidateSha256, 'candidate digest');
  requireDigest(input.inputSha256, 'input digest');

  if (input.candidateRevisionId) requireIdentifier(input.candidateRevisionId, 'candidate revision id');

  if (input.architecture !== undefined && input.architecture !== 'x86_64' && input.architecture !== 'aarch64') throw new FactoryRunError('invalid-input', 'Invalid factory architecture.');
  const candidateProvided = input.candidate !== undefined;
  const candidateJson = canonicalJson(input.candidate ?? {});
  const leaseSeconds = input.leaseSeconds ?? 30 * 60;

  if (!Number.isSafeInteger(leaseSeconds) || leaseSeconds < 30 || leaseSeconds > 24 * 60 * 60) throw new FactoryRunError('invalid-input', 'Invalid factory attempt lease.');
  const existing = await db.prepare('SELECT * FROM factory_run_attempts WHERE run_id=? AND reservation_key=?').bind(input.runId, input.reservationKey).first<AttemptRow>();

  if (existing) {
    if (existing.candidate_sha256 !== input.candidateSha256 || existing.input_sha256 !== input.inputSha256 ||
        (input.candidateRevisionId !== undefined && existing.candidate_revision_id !== input.candidateRevisionId) ||
        (input.architecture !== undefined && existing.architecture !== input.architecture) || (candidateProvided && existing.candidate_json !== candidateJson)) {
      throw new FactoryRunError('reservation-conflict', 'Reservation key is bound to different candidate inputs.');
    }

    return mapAttempt(existing);
  }

  const run = await runRow(db, input.runId);

  if (!run) throw new FactoryRunError('not-found', 'Factory run not found.');

  if (run.status === 'succeeded') throw new FactoryRunError('run-succeeded', 'Factory run already has a successful artifact.');

  if (run.status === 'needs-human-intervention') {
    if (run.attempt_count >= FACTORY_MAX_ATTEMPTS) throw new FactoryRunError('budget-exhausted', 'Factory build budget exhausted; human intervention is required.');
    throw new FactoryRunError('human-intervention', 'Factory run requires human intervention.');
  }

  if (run.status === 'cancelled') throw new FactoryRunError('human-intervention', 'Factory run requires human intervention.');

  if (run.policy_json !== canonicalJson(input.policy ?? parseJson(run.policy_json, 'policy'))) {
    await stopFactoryRun(db, input.runId, 'Execution policy expanded or changed.', input.policy ?? parseJson(run.policy_json, 'policy'));
    throw new FactoryPolicyStopError();
  }

  if (run.status === 'running' && run.lease_expires_at !== null && run.lease_expires_at > now()) {
    throw new FactoryRunError('attempt-busy', 'Factory run already has a live attempt lease.');
  }

  if (run.status === 'running' && run.lease_expires_at !== null && run.lease_expires_at <= now()) {
    await stopFactoryRun(db, input.runId, 'Attempt lease expired; execution status is ambiguous.');
    throw new FactoryRunError('human-intervention', 'Factory attempt lease expired; reconcile before retrying.');
  }

  const attempt = run.attempt_count + 1;

  if (attempt > FACTORY_MAX_ATTEMPTS) {
    await stopFactoryRun(db, input.runId, 'Factory build budget exhausted.');
    throw new FactoryRunError('budget-exhausted', 'Factory build budget exhausted; human intervention is required.');
  }

  const timestamp = now();
  const leaseToken = id();
  const leaseExpiresAt = timestamp + leaseSeconds;
  const attemptId = id();

  try {
    const results = await db.batch([
      db.prepare(`UPDATE factory_runs SET status='running',attempt_count=?,current_attempt=?,lease_token=?,lease_expires_at=?,updated_at=?
        WHERE id=? AND status='queued' AND attempt_count=? AND max_attempts=3`).bind(attempt, attempt, leaseToken, leaseExpiresAt, timestamp, input.runId, run.attempt_count),
      db.prepare(`INSERT INTO factory_run_attempts(
        id,run_id,attempt,reservation_key,status,candidate_revision_id,candidate_sha256,input_sha256,architecture,candidate_json,
        lease_token,lease_expires_at,started_at,created_at,updated_at
      ) SELECT ?,?,?,?,?,?,?,?,?,?,?,?,?,?,? WHERE changes()=1`)
        .bind(attemptId, input.runId, attempt, input.reservationKey, 'running', input.candidateRevisionId ?? null, input.candidateSha256, input.inputSha256,
          input.architecture ?? null, candidateJson, leaseToken, leaseExpiresAt, timestamp, timestamp, timestamp),
      db.prepare(`INSERT INTO audit_events(actor,action,target,detail,created_at)
        SELECT ?,?,?,?,? WHERE changes()=1`).bind('factory', 'factory.attempt_reserved', input.runId, JSON.stringify({ attempt, reservationKey: input.reservationKey, candidateSha256: input.candidateSha256, inputSha256: input.inputSha256 }), timestamp),
    ]);

    if (!changed(results[0]) || !changed(results[1])) {
      const raced = await db.prepare('SELECT * FROM factory_run_attempts WHERE run_id=? AND reservation_key=?').bind(input.runId, input.reservationKey).first<AttemptRow>();

      if (raced) return mapAttempt(raced);
      throw new FactoryRunError('attempt-busy', 'Factory run changed while reserving an attempt.');
    }
  } catch (cause) {
    if (cause instanceof FactoryRunError) throw cause;
    throw cause;
  }

  const reserved = await attemptRow(db, input.runId, attempt);

  if (!reserved) throw new FactoryRunError('storage', 'Factory attempt was not persisted.');

  return mapAttempt(reserved);
}

export async function renewFactoryAttempt(db: D1Database, runId: string, attempt: number, leaseToken: string, leaseSeconds = 30 * 60): Promise<FactoryAttempt> {
  requireIdentifier(runId, 'run id');
  requireIdentifier(leaseToken, 'lease token');

  if (!Number.isSafeInteger(attempt) || attempt < 1 || attempt > FACTORY_MAX_ATTEMPTS) throw new FactoryRunError('invalid-input', 'Invalid factory attempt.');

  if (!Number.isSafeInteger(leaseSeconds) || leaseSeconds < 30 || leaseSeconds > 24 * 60 * 60) throw new FactoryRunError('invalid-input', 'Invalid factory attempt lease.');
  const timestamp = now();
  const expires = timestamp + leaseSeconds;

  const results = await db.batch([
    db.prepare(`UPDATE factory_run_attempts SET lease_expires_at=?,updated_at=?
      WHERE run_id=? AND attempt=? AND lease_token=? AND status='running' AND lease_expires_at>?
        AND EXISTS (SELECT 1 FROM factory_runs WHERE id=? AND current_attempt=? AND lease_token=? AND status='running' AND lease_expires_at>?)`)
      .bind(expires, timestamp, runId, attempt, leaseToken, timestamp, runId, attempt, leaseToken, timestamp),
    db.prepare(`UPDATE factory_runs SET lease_expires_at=?,updated_at=? WHERE id=? AND current_attempt=? AND lease_token=? AND status='running' AND changes()=1`)
      .bind(expires, timestamp, runId, attempt, leaseToken),
  ]);

  if (!changed(results[0]) || !changed(results[1])) throw new FactoryRunError('lease-fenced', 'Factory attempt lease is fenced or expired.');
  const row = await attemptRow(db, runId, attempt);

  if (!row) throw new FactoryRunError('not-found', 'Factory attempt not found.');

  return mapAttempt(row);
}

export interface FactoryAttemptResult {
  status: 'succeeded' | 'failed';
  artifact?: unknown;
  failureKind?: FactoryFailureKind;
  failure?: unknown;
}

/** Finish exactly one leased attempt. A failed third attempt always stops for a human. */
export async function finishFactoryAttempt(db: D1Database, runId: string, attempt: number, leaseToken: string, result: FactoryAttemptResult): Promise<FactoryAttempt> {
  requireIdentifier(runId, 'run id');
  requireIdentifier(leaseToken, 'lease token');

  if (!Number.isSafeInteger(attempt) || attempt < 1 || attempt > FACTORY_MAX_ATTEMPTS) throw new FactoryRunError('invalid-input', 'Invalid factory attempt.');

  if (result.status === 'failed' && !result.failureKind) throw new FactoryRunError('invalid-input', 'Failed factory attempts require a failure kind.');
  const current = await attemptRow(db, runId, attempt);

  if (!current) throw new FactoryRunError('not-found', 'Factory attempt not found.');

  if (current.status !== 'running') {
    if (current.status === result.status && (result.status !== 'succeeded' || canonicalJson(parseJson(current.artifact_json, 'artifact')) === canonicalJson(result.artifact ?? null))) return mapAttempt(current);
    throw new FactoryRunError('attempt-complete', 'Factory attempt is already complete.');
  }

  const run = await runRow(db, runId);
  const timestamp = now();

  if (!run || run.status !== 'running' || run.current_attempt !== attempt || run.lease_token !== leaseToken || run.lease_expires_at === null || run.lease_expires_at <= timestamp || current.lease_token !== leaseToken || current.lease_expires_at <= timestamp) {
    throw new FactoryRunError('lease-fenced', 'Factory attempt lease is fenced or expired.');
  }

  const succeeded = result.status === 'succeeded';
  const failureJson = result.failure === undefined ? null : canonicalJson(result.failure);
  const artifactJson = result.artifact === undefined ? null : canonicalJson(result.artifact);
  const runStatus: FactoryRunStatus = succeeded ? 'succeeded' : result.failureKind === 'policy' || attempt >= FACTORY_MAX_ATTEMPTS ? 'needs-human-intervention' : 'queued';
  const runFailure = succeeded ? null : failureJson ?? canonicalJson({ message: 'factory attempt failed', kind: result.failureKind });

  try {
    const results = await db.batch([
      ...(result.status === 'failed' ? [db.prepare(`UPDATE builds SET status='cancelled'
        WHERE factory_run_id=? AND factory_attempt=? AND private_candidate=1 AND status IN ('queued','leased')`).bind(runId, attempt)] : []),
      db.prepare(`UPDATE factory_run_attempts SET status=?,failure_kind=?,failure_json=?,artifact_json=?,finished_at=?,lease_expires_at=?,updated_at=?
        WHERE run_id=? AND attempt=? AND status='running' AND lease_token=? AND lease_expires_at>?`)
        .bind(result.status, result.failureKind ?? null, failureJson, artifactJson, timestamp, timestamp, timestamp, runId, attempt, leaseToken, timestamp),
      db.prepare(`UPDATE factory_runs SET status=?,successful_attempt=?,artifact_json=?,failure_json=?,lease_token=NULL,lease_expires_at=NULL,updated_at=?
        WHERE id=? AND status='running' AND current_attempt=? AND lease_token=?
          AND EXISTS (SELECT 1 FROM factory_run_attempts WHERE run_id=? AND attempt=? AND status=? AND lease_token=?)`)
        .bind(runStatus, succeeded ? attempt : null, succeeded ? artifactJson : null, runFailure, timestamp, runId, attempt, leaseToken, runId, attempt, result.status, leaseToken),
      audit(db, 'factory', `factory.attempt_${result.status}`, runId, { attempt, failureKind: result.failureKind ?? null, artifact: result.artifact ?? null }),
      ...(runStatus === 'needs-human-intervention' ? [audit(db, 'factory', 'factory.needs_human_intervention', runId, { attempt, reason: result.failureKind === 'policy' ? 'policy-stop' : 'budget-exhausted' })] : []),
    ]);

    const attemptIndex = result.status === 'failed' ? 1 : 0;
    if (!changed(results[attemptIndex]) || !changed(results[attemptIndex + 1])) throw new FactoryRunError('lease-fenced', 'Factory attempt lease is fenced.');
  } catch (cause) {
    if (cause instanceof FactoryRunError) throw cause;
    throw cause;
  }

  const finished = await attemptRow(db, runId, attempt);

  if (!finished) throw new FactoryRunError('storage', 'Factory attempt result was not persisted.');

  return mapAttempt(finished);
}

export async function stopFactoryRun(db: D1Database, runId: string, reason: string, policy?: unknown): Promise<FactoryRun> {
  requireIdentifier(runId, 'run id');
  const cleanReason = typeof reason === 'string' ? reason.trim().slice(0, 2_000) : '';

  if (!cleanReason) throw new FactoryRunError('invalid-input', 'A factory stop reason is required.');
  const timestamp = now();
  const failureValue = { reason: cleanReason, ...(policy === undefined ? {} : { policy }) };
  const failure = canonicalJson(failureValue);
  const failureKind: FactoryFailureKind = policy === undefined ? 'infrastructure' : 'policy';
  await db.batch([
    db.prepare(`UPDATE factory_run_attempts SET status='failed',failure_kind=?,failure_json=?,finished_at=?,lease_expires_at=?,updated_at=?
      WHERE run_id=? AND attempt=(SELECT current_attempt FROM factory_runs WHERE id=? AND status IN ('queued','running')) AND status='running'`)
      .bind(failureKind, failure, timestamp, timestamp, timestamp, runId, runId),
    db.prepare(`UPDATE builds SET status='cancelled'
      WHERE factory_run_id=? AND factory_attempt=(SELECT current_attempt FROM factory_runs WHERE id=? AND status IN ('queued','running'))
        AND private_candidate=1 AND status IN ('queued','leased')`).bind(runId, runId),
    db.prepare(`UPDATE factory_runs SET status='needs-human-intervention',failure_json=?,lease_token=NULL,lease_expires_at=NULL,updated_at=?
      WHERE id=? AND status IN ('queued','running')`).bind(failure, timestamp, runId),
    db.prepare(`INSERT INTO audit_events(actor,action,target,detail,created_at)
      SELECT ?,?,?,?,? WHERE changes()=1`).bind('factory', 'factory.needs_human_intervention', runId, JSON.stringify({ reason: cleanReason }), timestamp),
  ]);
  const row = await runRow(db, runId);

  if (!row) throw new FactoryRunError('not-found', 'Factory run not found.');

  return mapRun(row);
}

/** Return successful private output for exact review/promotion reuse; never schedules a rebuild. */
export async function reuseSuccessfulFactoryArtifact(db: D1Database, runId: string, binding?: { candidateSha256?: string; inputSha256?: string; candidateRevisionId?: string }): Promise<{ runId: string; attempt: number; artifact: unknown } | null> {
  const run = await getFactoryRun(db, runId);

  if (!run || run.status !== 'succeeded' || run.successfulAttempt === null || run.artifact === null) return null;
  const attempt = await getFactoryAttempt(db, runId, run.successfulAttempt);

  if (!attempt || attempt.status !== 'succeeded') return null;

  if (binding?.candidateSha256 && attempt.candidateSha256 !== binding.candidateSha256) throw new FactoryRunError('artifact-binding', 'Successful factory artifact candidate differs from review.');

  if (binding?.inputSha256 && attempt.inputSha256 !== binding.inputSha256) throw new FactoryRunError('artifact-binding', 'Successful factory artifact inputs differ from review.');

  if (binding?.candidateRevisionId && attempt.candidateRevisionId !== binding.candidateRevisionId) throw new FactoryRunError('artifact-binding', 'Successful factory artifact revision differs from review.');

  return { runId, attempt: attempt.attempt, artifact: attempt.artifact };
}

export interface FactoryRepairCandidate {
  reservationKey?: string;
  candidateSha256: string;
  inputSha256: string;
  candidate?: unknown;
  candidateRevisionId?: string;
  architecture?: Architecture;
}

export interface FactoryRepairResult<T> extends FactoryAttemptResult {
  value?: T;
}

export async function runFactoryRepairLoop<T>(input: {
  db: D1Database;
  runId: string;
  policy: unknown;
  prepare: (attempt: number, previousFailure?: unknown) => Promise<FactoryRepairCandidate>;
  execute: (attempt: FactoryAttempt) => Promise<FactoryRepairResult<T>>;
  onRepair?: (attempt: number, failure: unknown) => Promise<void>;
  onHumanIntervention?: (reason: string, attempt: number) => Promise<void>;
  /** Entry points may reserve and queue the first attempt before dispatching a workflow. */
  resumeRunningAttempt?: number;
}): Promise<T | FactoryAttempt> {
  const saved = await getFactoryRun(input.db, input.runId);
  if (!saved) throw new FactoryRunError('not-found', 'Factory run not found.');
  if (saved.status === 'succeeded' && saved.successfulAttempt !== null) {
    const completed = await getFactoryAttempt(input.db, input.runId, saved.successfulAttempt);
    if (!completed) throw new FactoryRunError('storage', 'Successful factory attempt is missing.');
    return completed;
  }
  if (saved.status === 'needs-human-intervention' || saved.status === 'cancelled') throw new FactoryRunError('human-intervention', 'Factory run requires human intervention.');
  let active: FactoryAttempt | null = null;
  if (saved.status === 'running') {
    active = await getFactoryAttempt(input.db, input.runId, saved.currentAttempt ?? 0);
    if (!active || active.status !== 'running' || input.resumeRunningAttempt !== active.attempt) {
      await stopFactoryRun(input.db, input.runId, 'Attempt execution status is ambiguous after workflow restart.');
      throw new FactoryRunError('human-intervention', 'Factory attempt execution is ambiguous; human intervention is required.');
    }
  }
  let previousFailure: unknown = saved.failure;
  if (active) {
    const result = await input.execute(active);
    const finished = await finishFactoryAttempt(input.db, input.runId, active.attempt, active.leaseToken, result);
    if (result.status === 'succeeded') return result.value === undefined ? finished : result.value;
    previousFailure = result.failure ?? { kind: result.failureKind };
    if (result.failureKind === 'policy' || active.attempt === FACTORY_MAX_ATTEMPTS) {
      const reason = result.failureKind === 'policy' ? 'Factory policy expansion requires human intervention.' : 'Factory build budget exhausted after three attempts.';
      await input.onHumanIntervention?.(reason, active.attempt);
      throw new FactoryRunError(result.failureKind === 'policy' ? 'policy-stop' : 'budget-exhausted', reason);
    }
    await input.onRepair?.(active.attempt, previousFailure);
  }
  const nextAttempt = active ? active.attempt + 1 : saved.attemptCount + 1;
  for (let attempt = nextAttempt; attempt <= FACTORY_MAX_ATTEMPTS; attempt += 1) {
    let candidate: FactoryRepairCandidate;
    try {
      candidate = await input.prepare(attempt, previousFailure);
    } catch (cause) {
      if (cause instanceof FactoryPolicyStopError || (cause && typeof cause === 'object' && (cause as { code?: unknown }).code === 'policy-stop')) {
        await stopFactoryRun(input.db, input.runId, cause instanceof Error ? cause.message : 'Factory policy expansion requires human intervention.', input.policy);
        throw cause;
      }
      const reason = cause instanceof Error ? cause.message.slice(0, 2_000) : 'Factory candidate preparation failed.';
      candidate = {
        reservationKey: `attempt:${attempt}`,
        candidateSha256: await sha256(`factory-candidate:${input.runId}:${attempt}:${reason}`),
        inputSha256: await sha256(canonicalJson(input.policy)),
        candidate: { preparationFailure: reason },
      };
      const reserved = await reserveFactoryAttempt(input.db, { ...candidate, reservationKey: candidate.reservationKey ?? `attempt:${attempt}`, runId: input.runId, policy: input.policy });
      if (reserved.status === 'succeeded') return reserved;
      const finished = await finishFactoryAttempt(input.db, input.runId, reserved.attempt, reserved.leaseToken, { status: 'failed', failureKind: 'validation', failure: { message: reason } });
      previousFailure = finished.failure ?? { message: reason };
      if (reserved.attempt === FACTORY_MAX_ATTEMPTS) {
        const terminal = 'Factory build budget exhausted after three attempts.';
        await input.onHumanIntervention?.(terminal, reserved.attempt);
        throw new FactoryRunError('budget-exhausted', terminal);
      }
      await input.onRepair?.(reserved.attempt, previousFailure);
      continue;
    }
    const reserved = await reserveFactoryAttempt(input.db, {
      runId: input.runId, reservationKey: candidate.reservationKey ?? `attempt:${attempt}`, candidateSha256: candidate.candidateSha256,
      inputSha256: candidate.inputSha256, candidate: candidate.candidate, candidateRevisionId: candidate.candidateRevisionId, architecture: candidate.architecture, policy: input.policy,
    });
    if (reserved.status === 'succeeded') return reserved;
    const result = await input.execute(reserved);
    const finished = await finishFactoryAttempt(input.db, input.runId, reserved.attempt, reserved.leaseToken, result);
    if (result.status === 'succeeded') return result.value === undefined ? finished : result.value;
    previousFailure = result.failure ?? { kind: result.failureKind };
    if (result.failureKind === 'policy' || reserved.attempt === FACTORY_MAX_ATTEMPTS) {
      const reason = result.failureKind === 'policy' ? 'Factory policy expansion requires human intervention.' : 'Factory build budget exhausted after three attempts.';
      await input.onHumanIntervention?.(reason, reserved.attempt);
      throw new FactoryRunError(result.failureKind === 'policy' ? 'policy-stop' : 'budget-exhausted', reason);
    }
    await input.onRepair?.(reserved.attempt, previousFailure);
  }
  throw new FactoryRunError('budget-exhausted', 'Factory build budget exhausted after three attempts.');
}
