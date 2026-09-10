import { canonicalJson } from '../canonical-json';
import { createHash } from 'node:crypto';
import { cohortGatePageSize, cohortMemberCount, cohortPageSize, type CohortBlocker, type CohortMember, type CohortRow } from '../cohorts';
import { cohortPhases, requiredArchitectures } from '../distribution';
import type { Actor, Build } from '../model';
import { cohortConflict, getCohort, scopeAuthority } from './cohorts';
import { evaluateCohortGate, type CohortGate, type CohortMatrixRow } from './cohort-gates';
import { readCohortManifest } from './cohort-members';
import { now, query, sha256 } from './db';
import type { Env } from './env';
import { PolicyError } from './policy';

interface PageReport {
  schemaVersion: 1; cohortId: string; revision: number; manifestSha256: string; phase: string; epoch: string; page: number;
  memberCount: number; checkedAt: number; checkedBy: string; blockers: CohortBlocker[]; matrix: CohortMatrixRow[];
}
type PageRow = { page: number; member_count: number; blocker_count: number; digest: string; created_at: number; pkgbase: string };
const latestPage = `p.rowid=(SELECT last.rowid FROM cohort_gate_pages last WHERE last.cohort_id=p.cohort_id AND last.revision=p.revision
  AND last.phase=p.phase AND last.epoch=p.epoch AND last.page=p.page ORDER BY last.rowid DESC LIMIT 1)`;
const pageBefore = latestPage.replace('ORDER BY last.rowid', 'AND last.rowid<=? ORDER BY last.rowid');
const epochQuery = "SELECT e.version||':'||s.version AS version FROM cohort_evidence_epoch e,cohort_scope_epochs s WHERE e.id=1 AND s.cohort_id=?";

async function evidenceEpoch(db: D1Database, cohortId: string) {
  const row = await db.prepare(epochQuery).bind(cohortId).first<{ version: string }>();
  if (!row) throw new PolicyError(409, 'Cohort verification state is unavailable.');
  return row.version;
}
function epochFence(db: D1Database, cohortId: string, epoch: string) {
  return db.prepare(`INSERT INTO distribution_assertions(expected,actual) SELECT 1,COUNT(*) FROM (${epochQuery}) WHERE version=?`).bind(cohortId, epoch);
}

/** Every page runs native verification. Display-only checks cannot enter this ledger. */
export async function checkCohortPage(env: Env, actor: Actor | null, cohortId: string, revision: number, manifestSha256: string, page: number, expectedPhase?: string) {
  const current = await getCohort(env.DB, cohortId); const manifest = await readCohortManifest(current);
  const reviewer = scopeAuthority(actor, manifest);
  if (current.current_revision !== revision || current.manifest_sha256 !== manifestSha256 || expectedPhase !== undefined && current.phase !== expectedPhase || ['publish','observe'].includes(current.phase)) throw new PolicyError(409, 'Select the current unpublished cohort revision and phase.');
  const pageSize = cohortGatePageSize(current.phase);
  if (!Number.isSafeInteger(page) || page < 0 || page * pageSize >= cohortMemberCount(manifest)) throw new PolicyError(400, 'Choose an existing member page.');
  const epoch = await evidenceEpoch(env.DB, cohortId);
  const gate = await evaluateCohortGate(env, current, true, page);
  const report: PageReport = { schemaVersion: 1, cohortId, revision, manifestSha256, phase: current.phase, epoch, page,
    memberCount: Math.min(pageSize, cohortMemberCount(manifest) - page * pageSize), checkedAt: now(), checkedBy: reviewer.id, blockers: gate.blockers, matrix: gate.matrix };
  const json = canonicalJson(report); const digest = await sha256(json);
  try { await env.DB.batch([
    epochFence(env.DB, cohortId, epoch),
    env.DB.prepare('INSERT INTO distribution_assertions(expected,actual) SELECT 1,COUNT(*) FROM cohorts WHERE id=? AND current_revision=? AND phase=? AND condition=?')
      .bind(current.id, current.current_revision, current.phase, current.condition),
    ...(!gate.blockers.length ? gate.fences : []),
    env.DB.prepare(`INSERT INTO cohort_gate_pages(cohort_id,revision,phase,epoch,page,member_count,blocker_count,report_json,digest,created_at)
      VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT DO NOTHING`).bind(cohortId, revision, current.phase, epoch, page, report.memberCount, gate.blockers.length, json, digest, report.checkedAt),
  ]); } catch (cause) { cohortConflict(cause); }
  return { digest, ...report };
}

export async function cohortPageProgress(db: D1Database, current: CohortRow) {
  const manifest = await readCohortManifest(current); const memberCount = cohortMemberCount(manifest);
  const pageSize = cohortGatePageSize(current.phase); const pages = Math.ceil(memberCount / pageSize);
  const epoch = await evidenceEpoch(db, current.id);
  const throughRowid = (await db.prepare('SELECT COALESCE(MAX(rowid),0) AS value FROM cohort_gate_pages WHERE cohort_id=? AND revision=? AND phase=? AND epoch=?')
    .bind(current.id, current.current_revision, current.phase, epoch).first<{ value: number }>())!.value;
  const filter = `p.cohort_id=? AND p.revision=? AND p.phase=? AND p.epoch=? AND p.page<? AND p.rowid<=? AND ${pageBefore}`;
  const values = [current.id, current.current_revision, current.phase, epoch, pages, throughRowid, throughRowid];
  const summary = (await db.prepare(`SELECT COUNT(*) AS checkedPages,COALESCE(SUM(p.member_count),0) AS checked,
    COALESCE(SUM(p.blocker_count>0),0) AS failed,MIN(CASE WHEN p.blocker_count>0 THEN p.page END) AS firstFailed FROM cohort_gate_pages p WHERE ${filter}`)
    .bind(...values).first<{ checkedPages: number; checked: number; failed: number; firstFailed: number | null }>())!;
  const rows = await query<PageRow>(db, `SELECT p.page,p.member_count,p.blocker_count,p.digest,p.created_at,json_extract(p.report_json,'$.matrix[0].pkgbase') AS pkgbase FROM cohort_gate_pages p
    WHERE ${filter} AND p.blocker_count>0 ORDER BY p.page LIMIT 100`, ...values);
  const nextPage = (await db.prepare(`WITH expected AS (
    SELECT DISTINCT CAST(ordinal/? AS INTEGER) AS page FROM cohort_members WHERE cohort_id=? AND revision=? AND ordinal IS NOT NULL
    UNION SELECT CAST(key/? AS INTEGER) FROM json_each(?,'$.members'))
    SELECT MIN(expected.page) AS page FROM expected WHERE NOT EXISTS(SELECT 1 FROM cohort_gate_pages p WHERE p.page=expected.page AND ${filter})`)
    .bind(pageSize, current.id, current.current_revision, pageSize, current.manifest_json, ...values).first<{ page: number | null }>())!.page;
  return { epoch, pages, pageSize, memberCount, ...summary, rows, nextPage, throughRowid };
}

export async function aggregateCohortGate(db: D1Database, current: CohortRow): Promise<CohortGate & { pages: Awaited<ReturnType<typeof cohortPageProgress>> }> {
  const pages = await cohortPageProgress(db, current);
  const blockers: CohortBlocker[] = [];
  const block = (code: string, reason: string) => blockers.push({ code, reason, pkgbase: null, architecture: null, href: `/maintain/cohorts/${encodeURIComponent(current.id)}?tab=tests` });
  if (pages.checkedPages !== pages.pages || pages.checked !== pages.memberCount) block('cohort-pages', `Verified ${pages.checked} of ${pages.memberCount} members. Check every page against unchanged evidence before advancing.`);
  if (pages.failed) block('cohort-page-blockers', `${pages.failed} verified member pages still have required blockers.`);
  if (['held','recovering'].includes(current.condition)) block('held', 'A maintainer must resolve the hold before progression.');
  let next: CohortGate['next'] = cohortPhases[cohortPhases.indexOf(current.phase) + 1] ?? null;
  if (cohortPhases.indexOf(current.phase) >= 5) { next = null; block('release-activation', 'Publication uses the separate reviewed release candidate action.'); }
  const fences = [epochFence(db, current.id, pages.epoch),
    db.prepare(`INSERT INTO distribution_assertions(expected,actual) SELECT ?,COALESCE(MAX(rowid),0) FROM cohort_gate_pages WHERE cohort_id=? AND revision=? AND phase=? AND epoch=?`)
      .bind(pages.throughRowid, current.id, current.current_revision, current.phase, pages.epoch),
    db.prepare(`INSERT INTO distribution_assertions(expected,actual) SELECT ?,COUNT(*) FROM cohort_gate_pages p
      WHERE p.cohort_id=? AND p.revision=? AND p.phase=? AND p.epoch=? AND p.blocker_count=0 AND p.page<?
      AND p.member_count=MIN(?,?-p.page*?) AND ${latestPage}`)
      .bind(pages.pages, current.id, current.current_revision, current.phase, pages.epoch, pages.pages, pages.pageSize, pages.memberCount, pages.pageSize)];
  return { next, blockers, matrix: [], fences, pages };
}

export async function currentCohortPage(db: D1Database, current: CohortRow, page: number) {
  const epoch = await evidenceEpoch(db, current.id);
  const row = await db.prepare(`SELECT report_json,digest FROM cohort_gate_pages WHERE cohort_id=? AND revision=? AND phase=? AND epoch=? AND page=?
    ORDER BY rowid DESC LIMIT 1`).bind(current.id, current.current_revision, current.phase, epoch, page)
    .first<{ report_json: string; digest: string }>();
  if (!row) return null;
  if (await sha256(row.report_json) !== row.digest) throw new PolicyError(409, 'Cohort page evidence integrity check failed.');
  return { report: JSON.parse(row.report_json) as PageReport, digest: row.digest };
}

/** UI reads current status and saved checks without repeating native artifact work. */
export async function cohortPageView(db: D1Database, current: CohortRow, members: CohortMember[], displayPage: number) {
  const epoch = await evidenceEpoch(db, current.id); const pageSize = cohortGatePageSize(current.phase);
  const start = displayPage * cohortPageSize / pageSize; const end = Math.ceil((displayPage * cohortPageSize + members.length) / pageSize);
  const rows = await query<{ report_json: string; digest: string }>(db, `SELECT p.report_json,p.digest FROM cohort_gate_pages p
    WHERE p.cohort_id=? AND p.revision=? AND p.phase=? AND p.epoch=? AND p.page>=? AND p.page<? AND ${latestPage} ORDER BY p.page`,
    current.id, current.current_revision, current.phase, epoch, start, end);
  const reports: PageReport[] = [];
  for (const row of rows) {
    if (await sha256(row.report_json) !== row.digest) throw new PolicyError(409, 'Cohort page evidence integrity check failed.');
    reports.push(JSON.parse(row.report_json) as PageReport);
  }
  const builds = await query<Pick<Build, 'id' | 'revision_id' | 'architecture' | 'status' | 'attempt' | 'error'>>(db,
    'SELECT id,revision_id,architecture,status,attempt,error FROM builds WHERE revision_id IN (SELECT value FROM json_each(?))', canonicalJson(members.flatMap((member) => member.recipe ? [member.recipe.id] : [])));
  const matrix: CohortMatrixRow[] = members.flatMap((member) => requiredArchitectures.map((architecture) => {
    const build = builds.find((row) => row.revision_id === member.recipe?.id && row.architecture === architecture);
    const required = member.policy.architectures.includes(architecture);
    return { pkgbase: member.pkgbase, architecture, required, status: required ? build?.status ?? 'missing' : 'not-required', buildId: build?.id ?? null, attempt: build?.attempt ?? null,
      reason: required ? build?.error ?? null : member.policy.architectureExceptions.find((item) => item.architecture === architecture)?.reason ?? null };
  }));
  const blockers = reports.flatMap((report) => report.blockers);
  if (reports.length !== end - start) blockers.push({ code: 'page-unchecked', reason: 'Verify the remaining members on this page to inspect their required checks.', pkgbase: null, architecture: null, href: null });
  return { matrix, blockers, checkedAt: reports.length === end - start ? Math.min(...reports.map((report) => report.checkedAt)) : null };
}

/** Hash ordered page references with bounded reads; the event commits their bytes. */
export async function cohortPageProof(db: D1Database, current: CohortRow, pages: Awaited<ReturnType<typeof cohortPageProgress>>) {
  const hash = createHash('sha256').update('cohort-page-proofs-v1\n'); let after = -1; let count = 0;
  while (true) {
    const rows = await query<{ page: number; digest: string }>(db, `SELECT p.page,p.digest FROM cohort_gate_pages p WHERE p.cohort_id=? AND p.revision=? AND p.phase=?
      AND p.epoch=? AND p.page>? AND p.page<? AND p.rowid<=? AND ${pageBefore} ORDER BY p.page LIMIT 512`,
      current.id, current.current_revision, current.phase, pages.epoch, after, pages.pages, pages.throughRowid, pages.throughRowid);
    for (const row of rows) { hash.update(canonicalJson(row) + '\n'); count++; after = row.page; }
    if (rows.length < 512) break;
  }
  if (count !== pages.checkedPages) throw new PolicyError(409, 'Cohort page proof coverage changed.');
  return { schemaVersion: 1, cohortId: current.id, revision: current.current_revision, phase: current.phase, epoch: pages.epoch,
    throughRowid: pages.throughRowid, pageSize: pages.pageSize, pages: count, memberCount: pages.checked, reportsSha256: hash.digest('hex') };
}

/** Historical selections keep their original page heads after later retries. */
export async function cohortEventPageProofs(db: D1Database, cohortId: string, sequence: number, after = -1) {
  if (!Number.isSafeInteger(sequence) || sequence < 1 || !Number.isSafeInteger(after) || after < -1 || after > 100000) throw new PolicyError(400, 'Choose a phase event and page cursor.');
  const row = await db.prepare('SELECT event_json,event_sha256 FROM cohort_events WHERE cohort_id=? AND sequence=?')
    .bind(cohortId, sequence).first<{ event_json: string; event_sha256: string }>();
  if (!row || await sha256(row.event_json) !== row.event_sha256) throw new PolicyError(404, 'Verified cohort event not found.');
  const event = JSON.parse(row.event_json) as { evidence: Record<string, string> };
  if (!event.evidence.pageSelection) throw new PolicyError(400, 'This event uses inline verification evidence.');
  if (await sha256(event.evidence.pageSelection) !== event.evidence.matrixSha256) throw new PolicyError(409, 'Cohort page selection integrity check failed.');
  const selection = JSON.parse(event.evidence.pageSelection) as Awaited<ReturnType<typeof cohortPageProof>>;
  const refs = await query<{ page: number; digest: string }>(db, `SELECT p.page,p.digest FROM cohort_gate_pages p WHERE p.cohort_id=? AND p.revision=? AND p.phase=?
    AND p.epoch=? AND p.page>? AND p.rowid<=? AND ${pageBefore} ORDER BY p.page LIMIT 512`,
    cohortId, selection.revision, selection.phase, selection.epoch, after, selection.throughRowid, selection.throughRowid);
  return { event, eventSha256: row.event_sha256, selection, refs, next: refs.length === 512 ? refs.at(-1)!.page : null };
}
