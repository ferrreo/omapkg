import { canonicalJson } from '../canonical-json';
import type { CohortManifest, CohortEvent } from '../cohorts';
import type { Actor } from '../model';
import { cohortPhaseLabels, type CohortPhase } from '../distribution';
import { cohortConflict, cohortEventStatements, getCohort, scopeAuthority } from './cohorts';
import { evaluateCohortGate } from './cohort-gates';
import { sha256 } from './db';
import type { Env } from './env';
import { PolicyError } from './policy';
import { reviewReason } from './catalog-ownership';

export async function changeCohortPhase(env: Env, actor: Actor | null, cohortId: string, input: {
  revision: number; sequence: number; manifestSha256: string;
  action: 'advance' | 'recheck' | 'hold' | 'resume'; reason: string;
}) {
  const current = await getCohort(env.DB, cohortId);
  const reviewer = scopeAuthority(actor, JSON.parse(current.manifest_json) as CohortManifest);
  if (!['advance', 'recheck', 'hold', 'resume'].includes(input.action)) throw new PolicyError(400, 'Choose a cohort phase action.');
  const reason = reviewReason(input.reason);
  const commandSha256 = await sha256(canonicalJson({ ...input, reason, cohortId, actor: reviewer.id }));
  const duplicate = await env.DB.prepare('SELECT event_json FROM cohort_events WHERE cohort_id=? AND command_sha256=?')
    .bind(cohortId, commandSha256).first<{ event_json: string }>();
  if (duplicate) return { event: JSON.parse(duplicate.event_json) as CohortEvent, duplicate: true };
  if (current.current_revision !== input.revision || current.event_sequence !== input.sequence || current.manifest_sha256 !== input.manifestSha256) {
    throw new PolicyError(409, 'Cohort changed. Read the current phase and revision before acting.');
  }
  if (['publish', 'observe'].includes(current.phase)) throw new PolicyError(409, 'Use the release rollout or recovery action for a published cohort.');
  const gate = await evaluateCohortGate(env, current);
  let phase: CohortPhase = current.phase;
  let condition = current.condition;
  if (input.action === 'advance') {
    if (!gate.next || gate.blockers.length) throw new PolicyError(409, gate.blockers[0]?.reason ?? 'This phase needs the release candidate action.');
    phase = gate.next; condition = 'ready';
  } else if (input.action === 'hold') condition = 'held';
  else {
    const blockers = gate.blockers.filter((blocker) => blocker.code !== 'held');
    condition = blockers.length ? 'blocked' : 'ready';
    if (input.action === 'recheck' && current.condition === 'held') condition = 'held';
  }
  const evidence = {
    blockersSha256: await sha256(canonicalJson(gate.blockers)),
    matrixSha256: await sha256(canonicalJson(gate.matrix)),
    matrix: canonicalJson(gate.matrix),
    blockers: canonicalJson(gate.blockers),
  };
  if (input.action === 'recheck') {
    const last = await env.DB.prepare('SELECT event_json FROM cohort_events WHERE cohort_id=? ORDER BY sequence DESC LIMIT 1')
      .bind(cohortId).first<{ event_json: string }>();
    const event = last ? JSON.parse(last.event_json) as CohortEvent : null;
    if (event?.condition === condition && event.evidence.blockersSha256 === evidence.blockersSha256 && event.evidence.matrixSha256 === evidence.matrixSha256) {
      return { event, duplicate: true };
    }
  }
  const change = await cohortEventStatements(env.DB, current, reviewer.id, commandSha256,
    { kind: phase === current.phase ? 'condition' : 'phase', phase, condition, cause: reason, evidence });
  try { await env.DB.batch([...(input.action === 'advance' ? gate.fences : []), ...change.statements,
    ...(current.phase === 'build' && phase === 'verify' ? [env.DB.prepare(`UPDATE requests SET status='built',updated_at=? WHERE id IN (
      SELECT r.request_id FROM cohort_members m JOIN revisions r ON r.id=m.recipe_revision_id WHERE m.cohort_id=? AND m.revision=?)`)
      .bind(change.event.timestamp, current.id, current.current_revision)] : []),
  ]); }
  catch (cause) { cohortConflict(cause); }
  return { event: change.event, duplicate: false, phaseLabel: cohortPhaseLabels[phase] };
}
