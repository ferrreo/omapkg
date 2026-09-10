import type { Actor, Area, Revision } from '../model';
import { canonicalJson } from '../canonical-json';
import { humanMaintainer } from './catalog-ownership';
import { audit, id, now, sha256 } from './db';
import {
  createFactorySuccessorRun,
  FactoryRunError,
  getFactoryRun,
  getFactoryAttempt,
  reserveFactoryAttempt,
  startFactoryRun,
  type FactoryAttempt,
  type FactoryRun,
} from './factory-runs';
import { queuePrivateFactoryBuilds } from './factory-private-build';
import { preservedRecipe } from '../preserved-recipe';
import { assertPreservedImportCurrent } from './preserved-imports';
import { validateRevision } from './policy';
import { FACTORY_COHORT_PAGE_SIZE, pipelineFactoryCohortPageQueue, startFactoryCohortPaged, type FactoryCohortPageQueue } from './factory-cohort-dispatch';

export const FACTORY_UNIT_KINDS = ['preserved', 'manual', 'cohort', 'cohort-member', 'bootstrap', 'toolchain'] as const;
export type FactoryUnitKind = typeof FACTORY_UNIT_KINDS[number];

export interface FactoryUnitInput {
  targetKind: FactoryUnitKind;
  targetId: string;
  unitKey: string;
  policy: unknown;
  requestedRevisionId?: string;
  runId?: string;
}

export interface FactoryUnitDispatch {
  workflowId: string;
  runId: string;
  targetKind: FactoryUnitKind;
  targetId: string;
  unitKey: string;
  sourceRunId?: string;
  policy: unknown;
  repairReason?: string;
  attempt: number;
  buildIds: string[];
  revisionId: string;
}

export interface FactoryUnitQueue {
  enqueue(input: FactoryUnitDispatch): Promise<{ workflowId: string }>;
  enqueuePage?: FactoryCohortPageQueue['enqueuePage'];
}

export function pipelineFactoryQueue(pipeline: Fetcher): FactoryUnitQueue {
  const pageQueue = pipelineFactoryCohortPageQueue(pipeline);
  return {
    async enqueue(input) {
      const response = await pipeline.fetch(new Request('https://pipeline.internal/factory-unit', {
        method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(input),
      }));
      if (!response.ok) throw new FactoryRunError('dispatch-failed', 'Factory workflow could not be queued.');
      const body = await response.json() as { workflowId?: unknown };
      if (body.workflowId !== input.workflowId) throw new FactoryRunError('storage', 'Factory workflow returned a different identity.');
      return { workflowId: body.workflowId };
    },
    enqueuePage: pageQueue.enqueuePage,
  };
}

function interventionReason(value: unknown): string {
  if (typeof value !== 'string' || !value.trim() || value.length > 2_000) throw new FactoryRunError('invalid-input', 'A human intervention reason is required, up to 2,000 characters.');
  return value.trim();
}

export interface FactoryUnitStartResult {
  run: FactoryRun;
  workflowId: string;
  dispatchedAt: number;
}

export interface FactoryCohortStartResult {
  cohortId: string;
  revision: number;
  units: FactoryUnitStartResult[];
}

function requireText(value: unknown, field: string): string {
  if (typeof value !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,255}$/.test(value)) throw new FactoryRunError('invalid-input', `Invalid ${field}.`);
  return value;
}

function policy(value: unknown): unknown {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new FactoryRunError('invalid-input', 'Factory execution policy is required.');
  return value;
}

function validate(input: FactoryUnitInput): FactoryUnitInput {
  if (!FACTORY_UNIT_KINDS.includes(input.targetKind)) throw new FactoryRunError('invalid-input', 'Factory unit kind is not supported by this entry point.');
  return { ...input, targetId: requireText(input.targetId, 'target id'), unitKey: requireText(input.unitKey, 'unit key'), policy: policy(input.policy) };
}

type UnitRevision = Revision & { name: string; upstream_url: string; source_kind: 'git' | 'archive'; area: Area; request_status: string; latest_id: string };

async function resolveRevision(db: D1Database, actor: Actor, input: FactoryUnitInput): Promise<UnitRevision> {
  let revisionId = input.requestedRevisionId;
  if (input.targetKind === 'cohort-member') {
    const member = await db.prepare(`SELECT m.pkgbase,m.recipe_revision_id,c.phase,c.condition,r.owner_area
      FROM cohorts c JOIN cohort_members m ON m.cohort_id=c.id AND m.revision=c.current_revision
      JOIN catalog_revisions r ON r.pkgbase=m.pkgbase AND r.revision=m.catalog_revision
      WHERE c.id=? AND m.pkgbase=?`).bind(input.targetId, input.unitKey).first<{ pkgbase: string; recipe_revision_id: string | null; phase: string; condition: string; owner_area: string }>();
    if (!member?.recipe_revision_id || !['review', 'build', 'verify', 'stage'].includes(member.phase) || !['ready', 'blocked'].includes(member.condition)) throw new FactoryRunError('invalid-input', 'Cohort member is not admitted for a private factory build.');
    humanMaintainer(actor, member.owner_area);
    revisionId = member.recipe_revision_id;
  }
  if (!revisionId) throw new FactoryRunError('invalid-input', 'A reviewed revision is required for this factory unit.');
  const revision = await db.prepare(`SELECT r.*,q.name,q.upstream_url,q.source_kind,q.area,q.status AS request_status,
      (SELECT latest.id FROM revisions latest WHERE latest.request_id=r.request_id ORDER BY latest.created_at DESC,latest.rowid DESC LIMIT 1) AS latest_id
    FROM revisions r JOIN requests q ON q.id=r.request_id WHERE r.id=?`).bind(revisionId).first<UnitRevision>();
  if (!revision || revision.latest_id !== revision.id) throw new FactoryRunError('invalid-input', 'Factory unit must use the current reviewed revision.');
  humanMaintainer(actor, revision.area);
  if (!['generating', 'review', 'queued', 'building'].includes(revision.request_status)) throw new FactoryRunError('invalid-input', 'Factory unit revision is not admitted for a private build.');
  await validateRevision(revision);
  if (preservedRecipe(revision)) await assertPreservedImportCurrent(db, revision);
  if (input.targetKind === 'preserved' && !preservedRecipe(revision)) throw new FactoryRunError('invalid-input', 'Preserved factory units require retained recipe evidence.');
  return revision;
}

async function boundExecutionPolicy(db: D1Database, input: FactoryUnitInput, revision: UnitRevision): Promise<unknown> {
  const requested = policy(input.policy) as Record<string, unknown>;
  if (requested.network !== undefined && requested.network !== 'disabled') throw new FactoryRunError('invalid-input', 'Factory private builds require disabled network policy.');
  let inputLocks: Array<{ architecture: string; lockSha256: string; cohortId: string; cohortRevision: number }> = [];
  const rows = await db.prepare(`SELECT s.architecture,s.lock_sha256,l.cohort_id,l.cohort_revision
    FROM build_input_selections s JOIN current_input_locks l ON l.sha256=s.lock_sha256
    WHERE s.recipe_revision_id=? ORDER BY s.architecture,s.lock_sha256`).bind(revision.id).all<{ architecture: string; lock_sha256: string; cohort_id: string; cohort_revision: number }>();
  inputLocks = rows.results.map((row) => ({ architecture: row.architecture, lockSha256: row.lock_sha256, cohortId: row.cohort_id, cohortRevision: row.cohort_revision }));
  const architectures = JSON.parse(revision.architectures_json) as unknown;
  const sources = JSON.parse(revision.sources_json) as unknown;
  const dependencies = JSON.parse(revision.dependencies_json) as unknown;
  const makeDependencies = revision.make_dependencies_json ? JSON.parse(revision.make_dependencies_json) as unknown : undefined;
  const identity = {
    requestId: revision.request_id, packageName: revision.name, area: revision.area,
    upstreamUrl: revision.upstream_url, sourceKind: revision.source_kind, license: revision.license,
    architectures, sources, dependencies, inputLocks,
    ...(makeDependencies === undefined ? {} : { makeDependencies }),
  };
  if (requested.target !== undefined && canonicalJson(requested.target) !== canonicalJson(identity)) throw new FactoryRunError('invalid-input', 'Factory policy target does not match admitted revision.');
  for (const [key, value] of Object.entries(identity)) if (requested[key] !== undefined && canonicalJson(requested[key]) !== canonicalJson(value)) {
    throw new FactoryRunError('invalid-input', `Factory policy does not match admitted ${key}.`);
  }
  return { ...requested, network: 'disabled', executionScope: 'private', target: identity };
}

async function dispatch(db: D1Database, queue: FactoryUnitQueue, run: FactoryRun, input: FactoryUnitInput, revision: UnitRevision, attempt: FactoryAttempt, builds: Array<{ id: string; architecture: 'x86_64' | 'aarch64' }>, sourceRunId?: string, repairReason?: string): Promise<FactoryUnitStartResult> {
  const workflowId = `factory-unit-${run.id}`;
  let queued: { workflowId: string };
  try {
    queued = await queue.enqueue({ workflowId, runId: run.id, targetKind: input.targetKind, targetId: input.targetId, unitKey: input.unitKey, sourceRunId, policy: input.policy, repairReason, attempt: attempt.attempt, buildIds: builds.map((build) => build.id), revisionId: revision.id });
  } catch (cause) {
    await audit(db, 'factory', 'factory.unit_dispatch_failed', run.id, { targetKind: input.targetKind, targetId: input.targetId, message: cause instanceof Error ? cause.message.slice(0, 1_000) : 'queue failed' }).run();
    throw cause;
  }
  if (!queued || queued.workflowId !== workflowId) throw new Error('Factory queue returned a different workflow identity.');
  const dispatchedAt = now();
  await audit(db, run.createdBy, 'factory.unit_dispatched', run.id, { workflowId, targetKind: input.targetKind, targetId: input.targetId, unitKey: input.unitKey, sourceRunId: sourceRunId ?? null }).run();
  return { run, workflowId, dispatchedAt };
}

export async function startFactoryUnit(db: D1Database, actor: Actor | null, queue: FactoryUnitQueue, input: FactoryUnitInput): Promise<FactoryUnitStartResult> {
  const reviewer = humanMaintainer(actor);
  const value = validate(input);
  const revision = await resolveRevision(db, reviewer, value);
  const executionPolicy = await boundExecutionPolicy(db, value, revision);
  const executionValue = { ...value, policy: executionPolicy };
  const run = await startFactoryRun(db, { id: value.runId ?? id(), targetKind: value.targetKind, targetId: value.targetId, unitKey: value.unitKey, policy: executionPolicy, createdBy: reviewer.id, requestedRevisionId: revision.id });
  if (run.status === 'succeeded' || run.status === 'needs-human-intervention' || run.status === 'cancelled') return { run, workflowId: `factory-unit-${run.id}`, dispatchedAt: now() };
  const existingAttempt = run.currentAttempt ? await getFactoryAttempt(db, run.id, run.currentAttempt) : null;
  const attempt = existingAttempt?.status === 'running' ? existingAttempt : await reserveFactoryAttempt(db, { runId: run.id, reservationKey: `attempt:${run.attemptCount + 1}`, candidateSha256: revision.manifest_sha256, inputSha256: await sha256(canonicalJson({ revisionId: revision.id, policy: executionPolicy })), candidateRevisionId: revision.id, policy: executionPolicy });
  if (!attempt) throw new FactoryRunError('storage', 'Factory attempt was not persisted.');
  const builds = await queuePrivateFactoryBuilds({ DB: db }, run.id, attempt, revision);
  const refreshed = await getFactoryRun(db, run.id);
  if (!refreshed) throw new FactoryRunError('storage', 'Factory run disappeared after reservation.');
  return dispatch(db, queue, refreshed, executionValue, revision, attempt, builds);
}

export async function startFactoryUnitIntervention(db: D1Database, actor: Actor | null, queue: FactoryUnitQueue, input: FactoryUnitInput & { sourceRunId: string; reason?: string }): Promise<FactoryUnitStartResult> {
  const reviewer = humanMaintainer(actor);
  const value = validate(input);
  const sourceRunId = requireText(input.sourceRunId, 'source run id');
  const source = await getFactoryRun(db, sourceRunId);
  if (!source) throw new FactoryRunError('not-found', 'Source factory run not found.');
  const sourcePolicy = source.policy && typeof source.policy === 'object' && !Array.isArray(source.policy) ? { ...(source.policy as Record<string, unknown>) } : {};
  delete sourcePolicy.target;
  delete sourcePolicy.revisionId;
  let requestedRevisionId = value.requestedRevisionId;
  if (requestedRevisionId && requestedRevisionId === source.requestedRevisionId) {
    const latestAttempt = await db.prepare(`SELECT candidate_revision_id FROM factory_run_attempts
      WHERE run_id=? AND candidate_revision_id IS NOT NULL ORDER BY attempt DESC LIMIT 1`).bind(sourceRunId).first<{ candidate_revision_id: string | null }>();
    requestedRevisionId = latestAttempt?.candidate_revision_id ?? requestedRevisionId;
  }
  const sourceValue = { ...value, requestedRevisionId, policy: sourcePolicy };
  const revision = await resolveRevision(db, reviewer, sourceValue);
  const executionPolicy = await boundExecutionPolicy(db, sourceValue, revision);
  const executionValue = { ...value, policy: executionPolicy };
  const reason = interventionReason(input.reason ?? '');
  const run = await createFactorySuccessorRun(db, sourceRunId, { id: value.runId ?? id(), targetKind: value.targetKind, targetId: value.targetId, unitKey: value.unitKey, policy: executionPolicy, createdBy: reviewer.id, requestedRevisionId: revision.id });
  await audit(db, reviewer.id, 'factory.human_successor_started', run.id, { sourceRunId, reason }).run();
  const attempt = await reserveFactoryAttempt(db, { runId: run.id, reservationKey: `start:${run.id}:1`, candidateSha256: revision.manifest_sha256, inputSha256: await sha256(canonicalJson({ revisionId: revision.id, policy: executionPolicy, sourceRunId })), candidateRevisionId: revision.id, policy: executionPolicy });
  const builds = await queuePrivateFactoryBuilds({ DB: db }, run.id, attempt, revision);
  const refreshed = await getFactoryRun(db, run.id);
  if (!refreshed) throw new FactoryRunError('storage', 'Factory successor disappeared after reservation.');
  return dispatch(db, queue, refreshed, executionValue, revision, attempt, builds, sourceRunId, reason);
}

export async function startFactoryCohort(db: D1Database, actor: Actor | null, queue: FactoryUnitQueue, input: { cohortId: string; policy: unknown; createdBy?: string }): Promise<FactoryCohortStartResult> {
  const reviewer = humanMaintainer(actor);
  const cohortId = requireText(input.cohortId, 'cohort id');
  const basePolicy = policy(input.policy) as Record<string, unknown>;
  const current = await db.prepare(`SELECT c.current_revision,c.phase,c.condition FROM cohorts c WHERE c.id=?`).bind(cohortId)
    .first<{ current_revision: number; phase: string; condition: string }>();
  if (!current || !['review', 'build', 'verify', 'stage'].includes(current.phase) || !['ready', 'blocked'].includes(current.condition)) throw new FactoryRunError('invalid-input', 'Cohort is not admitted for a private factory start.');
  if (queue.enqueuePage) {
    const count = await db.prepare(`SELECT COUNT(*) AS count FROM cohort_members m WHERE m.cohort_id=? AND m.revision=? AND m.recipe_revision_id IS NOT NULL`).bind(cohortId, current.current_revision).first<{ count: number }>();
    if (Number(count?.count ?? 0) > FACTORY_COHORT_PAGE_SIZE) {
      const paged = await startFactoryCohortPaged(db, reviewer, { enqueuePage: queue.enqueuePage }, { cohortId, policy: input.policy });
      return { cohortId: paged.cohortId, revision: paged.revision, units: [] };
    }
  }
  const members = await db.prepare(`SELECT m.pkgbase,m.recipe_revision_id,r.owner_area FROM cohort_members m
    JOIN catalog_revisions r ON r.pkgbase=m.pkgbase AND r.revision=m.catalog_revision
    WHERE m.cohort_id=? AND m.revision=? AND m.recipe_revision_id IS NOT NULL ORDER BY m.pkgbase`).bind(cohortId, current.current_revision)
    .all<{ pkgbase: string; recipe_revision_id: string; owner_area: string }>();
  if (!members.results.length) throw new FactoryRunError('invalid-input', 'Cohort has no reviewed recipe members.');
  for (const member of members.results) humanMaintainer(actor, member.owner_area);
  const units: FactoryUnitStartResult[] = [];
  for (const member of members.results) units.push(await startFactoryUnit(db, reviewer, queue, {
    targetKind: 'cohort-member', targetId: cohortId, unitKey: member.pkgbase, policy: { ...basePolicy, cohortId, cohortRevision: current.current_revision, pkgbase: member.pkgbase }, requestedRevisionId: member.recipe_revision_id,
  }));
  await audit(db, reviewer.id, 'factory.cohort_dispatched', cohortId, { revision: current.current_revision, units: units.map((unit) => unit.run.id) }).run();
  return { cohortId, revision: current.current_revision, units };
}
