import type { Actor } from '../model';
import { humanMaintainer } from './catalog-ownership';
import { audit } from './db';
import { FactoryRunError, startFactoryRun, type FactoryRun } from './factory-runs';

export const FACTORY_COHORT_PAGE_SIZE = 64;

export interface FactoryCohortPageDispatch {
  workflowId: string;
  runId: string;
  cohortId: string;
  revision: number;
  offset: number;
  pageSize: number;
  policy: unknown;
  coordinator: Actor;
}

export interface FactoryCohortPageQueue {
  enqueuePage(input: FactoryCohortPageDispatch): Promise<{ workflowId: string }>;
}

export function pipelineFactoryCohortPageQueue(pipeline: Fetcher): FactoryCohortPageQueue {
  return {
    async enqueuePage(input) {
      const response = await pipeline.fetch(new Request('https://pipeline.internal/factory-cohort-page', {
        method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(input),
      }));
      if (!response.ok) throw new FactoryRunError('dispatch-failed', 'Cohort factory workflow could not be queued.');
      const body = await response.json() as { workflowId?: unknown };
      if (body.workflowId !== input.workflowId) throw new FactoryRunError('storage', 'Cohort workflow returned a different identity.');
      return { workflowId: body.workflowId };
    },
  };
}

export interface FactoryCohortDispatchResult {
  cohortId: string;
  revision: number;
  run: FactoryRun;
  workflowId: string | null;
  pageSize: number;
}

function text(value: unknown, field: string): string {
  if (typeof value !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,255}$/.test(value)) throw new FactoryRunError('invalid-input', `Invalid ${field}.`);
  return value;
}

export async function startFactoryCohortPaged(
  db: D1Database,
  actor: Actor | null,
  queue: FactoryCohortPageQueue,
  input: { cohortId: string; policy: unknown; createdBy?: string; pageSize?: number },
): Promise<FactoryCohortDispatchResult> {
  const reviewer = humanMaintainer(actor);
  const cohortId = text(input.cohortId, 'cohort id');
  const pageSize = input.pageSize ?? FACTORY_COHORT_PAGE_SIZE;
  if (!Number.isSafeInteger(pageSize) || pageSize < 1 || pageSize > FACTORY_COHORT_PAGE_SIZE) throw new FactoryRunError('invalid-input', 'Invalid cohort page size.');
  if (!input.policy || typeof input.policy !== 'object' || Array.isArray(input.policy)) throw new FactoryRunError('invalid-input', 'Factory execution policy is required.');
  const current = await db.prepare(`SELECT current_revision,phase,condition FROM cohorts WHERE id=?`).bind(cohortId)
    .first<{ current_revision: number; phase: string; condition: string }>();
  if (!current || !['review', 'build', 'verify', 'stage'].includes(current.phase) || !['ready', 'blocked'].includes(current.condition)) throw new FactoryRunError('invalid-input', 'Cohort is not admitted for a private factory start.');
  const policy = { ...(input.policy as Record<string, unknown>), cohortId, cohortRevision: current.current_revision,
    coordinator: { id: reviewer.id, role: reviewer.role, areas: [...reviewer.areas] } };
  const run = await startFactoryRun(db, {
    targetKind: 'cohort', targetId: cohortId, unitKey: `revision:${current.current_revision}`, policy, createdBy: reviewer.id,
  });
  if (run.status === 'succeeded') return { cohortId, revision: current.current_revision, run, workflowId: null, pageSize };
  if (run.status === 'needs-human-intervention' || run.status === 'cancelled') throw new FactoryRunError('human-intervention', 'Cohort factory dispatch requires human intervention.');
  const workflowId = `factory-cohort-${run.id}-page-0`;
  const dispatch: FactoryCohortPageDispatch = { workflowId, runId: run.id, cohortId, revision: current.current_revision, offset: 0, pageSize, policy, coordinator: reviewer };
  const queued = await queue.enqueuePage(dispatch);
  if (queued.workflowId !== workflowId) throw new FactoryRunError('storage', 'Cohort workflow returned a different identity.');
  await audit(db, reviewer.id, 'factory.cohort_page_dispatched', run.id, { cohortId, revision: current.current_revision, offset: 0, pageSize, workflowId }).run();
  return { cohortId, revision: current.current_revision, run, workflowId, pageSize };
}
