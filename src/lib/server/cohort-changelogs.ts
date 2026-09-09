import { canonicalJson } from '../canonical-json';
import type { CohortEvent, CohortManifest, CohortMember, CohortRow } from '../cohorts';
import { cohortPhaseLabels } from '../distribution';
import type { Actor } from '../model';
import { reviewReason } from './catalog-ownership';
import { cohortConflict, cohortEventStatements, cohortEvents, getCohort, scopeAuthority } from './cohorts';
import { now, sha256 } from './db';
import { PolicyError } from './policy';

export interface CohortChange {
  pkgbase: string; kind: 'added' | 'removed' | 'changed' | 'unchanged';
  oldVersion: string | null; newVersion: string | null;
  oldRepository: string | null; newRepository: string | null;
  oldRecipeSha256: string | null; newRecipeSha256: string | null;
  architectures: string[]; cause: string; reason: string;
}
export interface CohortFacts {
  schemaVersion: 1; cohortId: string; revision: number; manifestSha256: string;
  title: string; lane: 'system' | 'opr'; systemVersion: string | null;
  baseline: { kind: 'previous-cohort-revision' | 'initial-plan'; revision: number | null; manifestSha256: string | null; parentSnapshot: string | null };
  state: 'planned' | 'built' | 'published';
  changes: CohortChange[];
  phases: Array<CohortEvent & { eventSha256: string }>;
}

export async function generateCohortFacts(db: D1Database, current: CohortRow): Promise<CohortFacts> {
  const manifest: CohortManifest = JSON.parse(current.manifest_json);
  const previous = current.current_revision > 1 ? await db.prepare('SELECT manifest_json,manifest_sha256 FROM cohort_revisions WHERE cohort_id=? AND revision=?')
    .bind(current.id, current.current_revision - 1).first<{ manifest_json: string; manifest_sha256: string }>() : null;
  if (previous && await sha256(previous.manifest_json) !== previous.manifest_sha256) throw new PolicyError(409, 'Previous cohort manifest integrity check failed.');
  const oldMembers: CohortMember[] = previous ? (JSON.parse(previous.manifest_json) as CohortManifest).members : [];
  const oldByName = new Map(oldMembers.map((member) => [member.pkgbase, member]));
  const newByName = new Map(manifest.members.map((member) => [member.pkgbase, member]));
  const changes = [...new Set([...oldByName.keys(), ...newByName.keys()])].sort().map((pkgbase): CohortChange => {
    const before = oldByName.get(pkgbase); const after = newByName.get(pkgbase); const member = after ?? before!;
    return { pkgbase, kind: !before ? 'added' : !after ? 'removed' : canonicalJson(before) === canonicalJson(after) ? 'unchanged' : 'changed',
      oldVersion: before?.recipe?.fullVersion ?? null, newVersion: after?.recipe?.fullVersion ?? null,
      oldRepository: before?.policy.collection ?? null, newRepository: after?.policy.collection ?? null,
      oldRecipeSha256: before?.recipe?.manifestSha256 ?? null, newRecipeSha256: after?.recipe?.manifestSha256 ?? null,
      architectures: [...new Set([...(before?.policy.architectures ?? []), ...(after?.policy.architectures ?? [])])].sort(),
      cause: member.cause, reason: member.reason };
  });
  const phases: CohortFacts['phases'] = [];
  let sequence = 0; let previousEvent: string | null = null;
  while (sequence < current.event_sequence) {
    const rows = await cohortEvents(db, current.id, sequence);
    if (!rows.length) throw new PolicyError(409, 'Cohort phase history is incomplete.');
    for (const row of rows) {
      if (row.sequence > current.event_sequence) break;
      const event = JSON.parse(row.event_json) as CohortEvent;
      if (row.sequence !== sequence + 1 || event.sequence !== row.sequence || event.cohortId !== current.id ||
          event.previousEventSha256 !== previousEvent || await sha256(row.event_json) !== row.event_sha256) {
        throw new PolicyError(409, 'Cohort phase history integrity check failed.');
      }
      if (event.revision === current.current_revision && !['changelog', 'changelog-review'].includes(event.kind)) phases.push({ ...event, eventSha256: row.event_sha256 });
      sequence = row.sequence; previousEvent = row.event_sha256;
    }
  }
  if (previousEvent !== current.event_sha256) throw new PolicyError(409, 'Cohort history changed while generating changes.');
  return { schemaVersion: 1, cohortId: current.id, revision: current.current_revision, manifestSha256: current.manifest_sha256,
    title: manifest.title, lane: manifest.lane, systemVersion: manifest.systemVersion,
    baseline: { kind: previous ? 'previous-cohort-revision' : 'initial-plan', revision: previous ? current.current_revision - 1 : null,
      manifestSha256: previous?.manifest_sha256 ?? null, parentSnapshot: manifest.parentSnapshot },
    state: phases.some((event) => event.kind === 'publication') ? 'published' : phases.some((event) => event.kind === 'phase' && event.from === 'build' && event.phase === 'verify') ? 'built' : 'planned',
    changes, phases };
}

function markdownText(value: string) {
  return value.replace(/[\\`*_{}\[\]()#+.!|<>-]/g, '\\$&');
}

export function cohortMarkdown(facts: CohortFacts, narrative: string): string {
  const baseline = facts.baseline.kind === 'previous-cohort-revision' ? `cohort revision ${facts.baseline.revision}` : 'initial proposed membership (no earlier cohort revision)';
  return [`# ${markdownText(facts.title)}`, '', `${facts.lane === 'system' ? `System ${facts.systemVersion}` : 'Independent OPR cohort'} · revision ${facts.revision} · ${facts.state}`,
    '', `Comparison baseline: ${baseline}. Parent snapshot: ${facts.baseline.parentSnapshot ?? 'not yet selected'}.`,
    '', '## Maintainer narrative', '', narrative ? markdownText(narrative) : 'Narrative awaiting human review.',
    '', '## Generated package changes', '', '| Package | Change | Old version | New version | Repository | Targets | Cause |',
    '| --- | --- | --- | --- | --- | --- | --- |',
    ...facts.changes.map((change) => `| ${markdownText(change.pkgbase)} | ${change.kind} | ${markdownText(change.oldVersion ?? 'unbound')} | ${markdownText(change.newVersion ?? 'unbound')} | ${markdownText(`${change.oldRepository ?? '—'} → ${change.newRepository ?? '—'}`)} | ${change.architectures.join(', ')} | ${markdownText(change.reason)} |`),
    '', '## Generated phase history', '', ...facts.phases.flatMap((phase) => [
      `- ${new Date(phase.timestamp * 1000).toISOString()} · ${cohortPhaseLabels[phase.phase]} · ${phase.condition}: ${markdownText(phase.cause)}`,
      `  Actor: ${markdownText(phase.actor)}. Evidence: ${phase.eventSha256}.`,
    ]), '', `Manifest SHA-256: ${facts.manifestSha256}`, ''
  ].join('\n');
}

export type ChangelogRow = { digest: string; facts_sha256: string; document_json: string; markdown: string; created_at: number; created_by: string };

export async function saveCohortChangelog(db: D1Database, actor: Actor | null, cohortId: string, revision: number, expectedFactsSha256: string, narrative: string) {
  const current = await getCohort(db, cohortId);
  const reviewer = scopeAuthority(actor, JSON.parse(current.manifest_json));
  if (current.current_revision !== revision || ['publish', 'observe'].includes(current.phase)) throw new PolicyError(409, 'Select the current unpublished cohort revision.');
  if (typeof narrative !== 'string' || narrative.length > 16_000 || /[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/.test(narrative)) {
    throw new PolicyError(400, 'Write a narrative up to 16,000 characters without control characters.');
  }
  const facts = await generateCohortFacts(db, current); const factsHash = await sha256(canonicalJson(facts));
  if (factsHash !== expectedFactsSha256) throw new PolicyError(409, 'Generated facts changed. Read the new diff before editing the narrative.');
  const document = { schemaVersion: 1, facts, narrative: narrative.trim() };
  const json = canonicalJson(document); const hash = await sha256(json);
  if (await db.prepare('SELECT 1 FROM cohort_changelogs WHERE cohort_id=? AND revision=? AND digest=?').bind(cohortId, revision, hash).first()) return { digest: hash };
  const event = await cohortEventStatements(db, current, reviewer.id, await sha256(canonicalJson({ kind: 'changelog', revision, hash })),
    { kind: 'changelog', phase: current.phase, condition: current.condition, cause: 'Prepared a narrative for the generated cohort changes.', evidence: { changelogSha256: hash, factsSha256: factsHash } });
  try { await db.batch([
    db.prepare(`INSERT INTO cohort_changelogs(cohort_id,revision,digest,facts_sha256,document_json,markdown,created_by,created_at) VALUES(?,?,?,?,?,?,?,?)`)
      .bind(cohortId, revision, hash, factsHash, json, cohortMarkdown(facts, document.narrative), reviewer.id, now()),
    ...event.statements,
  ]); } catch (cause) { cohortConflict(cause); }
  return { digest: hash };
}

export async function approveCohortChangelog(db: D1Database, actor: Actor | null, cohortId: string, revision: number, digest: string, reason: string) {
  const current = await getCohort(db, cohortId); const reviewer = scopeAuthority(actor, JSON.parse(current.manifest_json));
  const clean = reviewReason(reason);
  if (current.current_revision !== revision || ['publish', 'observe'].includes(current.phase)) throw new PolicyError(409, 'Select the current unpublished cohort revision.');
  const row = await db.prepare('SELECT * FROM cohort_changelogs WHERE cohort_id=? AND revision=? AND digest=?').bind(cohortId, revision, digest).first<ChangelogRow>();
  if (!row || await sha256(row.document_json) !== digest) throw new PolicyError(409, 'Select an intact generated changelog.');
  if (row.facts_sha256 !== await sha256(canonicalJson(await generateCohortFacts(db, current)))) throw new PolicyError(409, 'Changelog facts are stale. Generate and review the current changes.');
  if (!JSON.parse(row.document_json).narrative) throw new PolicyError(409, 'Review a user-facing narrative before approval.');
  if (await db.prepare('SELECT 1 FROM cohort_changelog_reviews WHERE cohort_id=? AND revision=? AND changelog_sha256=? AND actor=?').bind(cohortId, revision, digest, reviewer.id).first()) return { digest };
  const event = await cohortEventStatements(db, current, reviewer.id, await sha256(canonicalJson({ kind: 'changelog-review', revision, digest, actor: reviewer.id })),
    { kind: 'changelog-review', phase: current.phase, condition: current.condition, cause: clean, evidence: { changelogSha256: digest, factsSha256: row.facts_sha256 } });
  try { await db.batch([
    db.prepare('INSERT INTO cohort_changelog_reviews(cohort_id,revision,changelog_sha256,actor,reason,created_at) VALUES(?,?,?,?,?,?)')
      .bind(cohortId, revision, digest, reviewer.id, clean, now()), ...event.statements,
  ]); } catch (cause) { cohortConflict(cause); }
  return { digest };
}
