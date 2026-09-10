import { canonicalJson } from '../canonical-json';
import { cohortOwnerAreas, type CohortChunkedManifest, type CohortMemberChunk, type CohortMetadata, type CohortRow } from '../cohorts';
import type { Actor, Architecture } from '../model';
import { humanMaintainer, reviewReason } from './catalog-ownership';
import { cohortConflict, cohortEventStatements, cohortManifest, getCohort, parseCohortMetadata, scopeAuthority, scopeAuthorityFence } from './cohorts';
import { now, query, sha256 } from './db';
import { PolicyError } from './policy';

interface ScopeUpload {
  id: string; cohort_id: string; expected_revision: number | null; base_sha256: string | null; metadata_json: string;
  expected_count: number; next_chunk: number; member_count: number; last_pkgbase: string; sealed_revision: number | null; created_by: string;
}

async function scopeUpload(db: D1Database, actor: Actor | null, uploadId: string): Promise<ScopeUpload> {
  const reviewer = humanMaintainer(actor);
  const row = await db.prepare('SELECT * FROM cohort_scope_uploads WHERE id=?').bind(uploadId).first<ScopeUpload>();
  if (!row) throw new PolicyError(404, 'Cohort scope upload not found.');
  if (row.created_by !== reviewer.id) throw new PolicyError(403, 'Resume a scope upload created by your own account.');
  return row;
}

export async function beginCohortScope(db: D1Database, actor: Actor | null, cohortId: string, expectedRevision: number | null, input: unknown, expectedCount: number, proposalId: string) {
  const reviewer = humanMaintainer(actor); const metadata = parseCohortMetadata(input);
  if (typeof proposalId !== 'string' || !/^[A-Za-z0-9_-]{1,128}$/.test(proposalId) || !/^[A-Za-z0-9_-]{1,128}$/.test(cohortId) || (expectedRevision !== null && (!Number.isSafeInteger(expectedRevision) || expectedRevision < 1)) ||
      !Number.isSafeInteger(expectedCount) || expectedCount < 1 || expectedCount > 100000) throw new PolicyError(400, 'Choose a cohort, expected revision and complete member count (1–100,000).');
  const prior = expectedRevision === null ? null : await db.prepare('SELECT manifest_sha256 FROM cohort_revisions WHERE cohort_id=? AND revision=?')
    .bind(cohortId, expectedRevision).first<{ manifest_sha256: string }>();
  if (expectedRevision !== null && !prior) throw new PolicyError(409, 'Expected cohort revision does not exist.');
  const metadataJson = canonicalJson(metadata); const base = prior?.manifest_sha256 ?? null;
  const uploadId = await sha256(canonicalJson({ cohortId, expectedRevision, base, metadata, expectedCount, proposalId, actor: reviewer.id }));
  if (await db.prepare('SELECT 1 FROM cohort_scope_uploads WHERE id=?').bind(uploadId).first()) return scopeUpload(db, actor, uploadId);
  const exists = await db.prepare('SELECT id FROM cohorts WHERE id=?').bind(cohortId).first();
  const current = exists ? await getCohort(db, cohortId) : null;
  if ((current?.current_revision ?? null) !== expectedRevision || current && ['publish', 'observe'].includes(current.phase)) throw new PolicyError(409, 'Select the current unpublished cohort revision.');
  if (current) scopeAuthority(actor, JSON.parse(current.manifest_json));
  await db.prepare(`INSERT INTO cohort_scope_uploads(id,cohort_id,expected_revision,base_sha256,metadata_json,expected_count,created_by,created_at)
    VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(id) DO NOTHING`).bind(uploadId, cohortId, expectedRevision, base, metadataJson, expectedCount, reviewer.id, now()).run();
  return scopeUpload(db, actor, uploadId);
}

export async function appendCohortScope(db: D1Database, actor: Actor | null, uploadId: string, index: number, input: unknown) {
  const upload = await scopeUpload(db, actor, uploadId);
  if (!Number.isSafeInteger(index) || index < 0 || index >= 4096 || !Array.isArray(input) || !input.length || input.length > 100) throw new PolicyError(400, 'Upload 1–100 members in each numbered scope chunk.');
  const manifest = await cohortManifest(db, actor, { ...JSON.parse(upload.metadata_json), members: input });
  const members = manifest.members; const json = canonicalJson(members); const hash = await sha256(json);
  if (new TextEncoder().encode(json).byteLength > 1024 * 1024) throw new PolicyError(413, 'Scope chunk exceeds one MiB. Reduce its member count.');
  const previous = await db.prepare('SELECT sha256 FROM cohort_scope_chunks WHERE upload_id=? AND chunk_index=?').bind(uploadId, index).first<{ sha256: string }>();
  if (previous) {
    if (previous.sha256 !== hash) throw new PolicyError(409, 'An uploaded scope chunk cannot change. Start a new scope proposal.');
    return upload;
  }
  if (upload.sealed_revision !== null || index !== upload.next_chunk || members[0].pkgbase <= upload.last_pkgbase || upload.member_count + members.length > upload.expected_count) {
    throw new PolicyError(409, 'Append the next chunk in package-name order without exceeding the complete member count.');
  }
  try { await db.batch([
    db.prepare(`UPDATE cohort_scope_uploads SET next_chunk=next_chunk+1,member_count=member_count+?,last_pkgbase=?
      WHERE id=? AND next_chunk=? AND member_count=? AND sealed_revision IS NULL`)
      .bind(members.length, members.at(-1)!.pkgbase, uploadId, index, upload.member_count),
    db.prepare('INSERT INTO distribution_assertions(expected,actual) VALUES(1,changes())'),
    db.prepare(`INSERT INTO cohort_scope_chunks(upload_id,chunk_index,start,member_count,first_pkgbase,last_pkgbase,members_json,sha256) VALUES(?,?,?,?,?,?,?,?)`)
      .bind(uploadId, index, upload.member_count, members.length, members[0].pkgbase, members.at(-1)!.pkgbase, json, hash),
    db.prepare(`INSERT INTO cohort_scope_entries(upload_id,chunk_index,ordinal,pkgbase,catalog_revision,recipe_revision_id,member_json)
      SELECT ?,?,?+CAST(key AS INTEGER),json_extract(value,'$.pkgbase'),json_extract(value,'$.catalogRevision'),json_extract(value,'$.recipe.id'),value FROM json_each(?)`)
      .bind(uploadId, index, upload.member_count, json),
  ]); } catch (cause) { cohortConflict(cause); }
  return scopeUpload(db, actor, uploadId);
}

export async function sealCohortScope(db: D1Database, actor: Actor | null, uploadId: string, reason: string) {
  const upload = await scopeUpload(db, actor, uploadId); const clean = reviewReason(reason);
  if (upload.sealed_revision !== null) {
    const selected = await db.prepare('SELECT cohort_id,revision,manifest_sha256 FROM cohort_revisions WHERE cohort_id=? AND revision=?')
      .bind(upload.cohort_id, upload.sealed_revision).first<{ cohort_id: string; revision: number; manifest_sha256: string }>();
    return { ...selected!, unchanged: upload.sealed_revision === upload.expected_revision };
  }
  if (upload.member_count !== upload.expected_count) throw new PolicyError(409, 'Upload every declared cohort member before sealing scope.');
  const exists = await db.prepare('SELECT id FROM cohorts WHERE id=?').bind(upload.cohort_id).first();
  const current = exists ? await getCohort(db, upload.cohort_id) : null;
  if ((current?.current_revision ?? null) !== upload.expected_revision || (current?.manifest_sha256 ?? null) !== upload.base_sha256 ||
      current && ['publish', 'observe'].includes(current.phase)) throw new PolicyError(409, 'Cohort scope changed. Start from the current unpublished revision.');
  const chunks = await query<CohortMemberChunk>(db, `SELECT chunk_index AS 'index',start,member_count AS count,first_pkgbase AS first,last_pkgbase AS last,sha256
    FROM cohort_scope_chunks WHERE upload_id=? ORDER BY chunk_index`, uploadId);
  const areas = await query<{ area: string }>(db, "SELECT DISTINCT json_extract(member_json,'$.policy.ownerArea') AS area FROM cohort_scope_entries WHERE upload_id=? ORDER BY area", uploadId);
  const targets = await query<{ architecture: Architecture }>(db, "SELECT DISTINCT target.value AS architecture FROM cohort_scope_entries entry,json_each(entry.member_json,'$.policy.architectures') target WHERE upload_id=? ORDER BY architecture", uploadId);
  let count = 0; let last = '';
  for (const [index, chunk] of chunks.entries()) {
    if (chunk.index !== index || chunk.start !== count || chunk.first <= last) throw new PolicyError(409, 'Cohort chunk index is incomplete or unordered.');
    count += chunk.count; last = chunk.last;
  }
  if (count !== upload.expected_count || chunks.length !== upload.next_chunk || !areas.length || !targets.length) throw new PolicyError(409, 'Cohort chunk coverage is incomplete.');
  const metadata: CohortMetadata = JSON.parse(upload.metadata_json);
  const manifest: CohortChunkedManifest = { ...metadata, schemaVersion: 2, memberCount: count, memberChunks: chunks,
    ownerAreas: areas.map((item) => item.area), architectures: targets.map((item) => item.architecture) };
  const reviewer = scopeAuthority(actor, manifest);
  const allAreas = new Set(manifest.ownerAreas);
  if (current) {
    const prior = JSON.parse(current.manifest_json); scopeAuthority(actor, prior);
    for (const area of cohortOwnerAreas(prior)) allAreas.add(area);
  }
  const json = canonicalJson(manifest); const hash = await sha256(json); const revision = (upload.expected_revision ?? 0) + 1; const timestamp = now();
  if (new TextEncoder().encode(json).byteLength > 1024 * 1024) throw new PolicyError(413, 'Scope index exceeds one MiB. Use larger member chunks.');
  if (current?.manifest_sha256 === hash) {
    try { await db.batch([
      scopeAuthorityFence(db, reviewer, [...allAreas]),
      db.prepare('INSERT INTO distribution_assertions(expected,actual) SELECT 1,COUNT(*) FROM cohorts WHERE id=? AND current_revision=? AND event_sequence=?')
        .bind(current.id, current.current_revision, current.event_sequence),
      db.prepare('UPDATE cohort_scope_uploads SET sealed_revision=? WHERE id=? AND sealed_revision IS NULL AND member_count=expected_count AND next_chunk=?')
        .bind(current.current_revision, uploadId, chunks.length),
      db.prepare('INSERT INTO distribution_assertions(expected,actual) VALUES(1,changes())'),
    ]); } catch (cause) { cohortConflict(cause); }
    return { cohort_id: current.id, revision: current.current_revision, manifest_sha256: hash, unchanged: true };
  }
  const base: CohortRow = current ?? { id: upload.cohort_id, current_revision: 1, event_sequence: 0, event_sha256: null, phase: 'plan', condition: 'ready',
    updated_at: timestamp, manifest_json: json, manifest_sha256: hash, title: manifest.title, lane: manifest.lane };
  const event = await cohortEventStatements(db, base, reviewer.id, await sha256(canonicalJson({ kind: 'scope', revision, hash })),
    { kind: 'scope', phase: 'plan', condition: 'ready', cause: clean, evidence: { scopeUploadSha256: uploadId } }, { revision, manifestSha256: hash });
  try { await db.batch([
    scopeAuthorityFence(db, reviewer, [...allAreas]),
    db.prepare(`UPDATE cohort_scope_uploads SET sealed_revision=? WHERE id=? AND sealed_revision IS NULL AND member_count=expected_count AND next_chunk=?`)
      .bind(revision, uploadId, chunks.length),
    db.prepare('INSERT INTO distribution_assertions(expected,actual) VALUES(1,changes())'),
    db.prepare(`INSERT INTO distribution_assertions(expected,actual) SELECT ?,COUNT(*) FROM cohort_scope_entries e
      JOIN catalog_packages p ON p.pkgbase=e.pkgbase AND p.current_revision=e.catalog_revision WHERE e.upload_id=?`).bind(count, uploadId),
    db.prepare(`INSERT INTO distribution_assertions(expected,actual) SELECT 0,COUNT(*) FROM cohort_scope_entries e WHERE upload_id=? AND recipe_revision_id IS NOT NULL
      AND NOT EXISTS(SELECT 1 FROM revisions r JOIN requests q ON q.id=r.request_id WHERE r.id=e.recipe_revision_id
        AND r.manifest_sha256=json_extract(e.member_json,'$.recipe.manifestSha256') AND q.id=json_extract(e.member_json,'$.recipe.requestId')
        AND q.name=e.pkgbase AND q.upstream_url=json_extract(e.member_json,'$.policy.upstreamUrl') AND q.source_kind=json_extract(e.member_json,'$.policy.sourceKind')
        AND q.area=json_extract(e.member_json,'$.policy.ownerArea') AND (q.catalog_pkgbase IS NULL OR q.catalog_pkgbase=e.pkgbase)
        AND r.id=(SELECT latest.id FROM revisions latest WHERE latest.request_id=q.id ORDER BY latest.created_at DESC,latest.rowid DESC LIMIT 1))`).bind(uploadId),
    ...(!current ? [db.prepare("INSERT INTO cohorts(id,current_revision,phase,condition,created_at,updated_at) VALUES(?,1,'plan','ready',?,?)").bind(upload.cohort_id, timestamp, timestamp)] : []),
    db.prepare(`INSERT INTO cohort_revisions(cohort_id,revision,manifest_json,manifest_sha256,title,lane,created_by,created_at) VALUES(?,?,?,?,?,?,?,?)`)
      .bind(upload.cohort_id, revision, json, hash, manifest.title, manifest.lane, reviewer.id, timestamp),
    db.prepare(`INSERT INTO cohort_revision_chunks(cohort_id,revision,chunk_index,members_json,sha256)
      SELECT ?,?,chunk_index,members_json,sha256 FROM cohort_scope_chunks WHERE upload_id=?`).bind(upload.cohort_id, revision, uploadId),
    db.prepare(`INSERT INTO cohort_members(cohort_id,revision,pkgbase,catalog_revision,recipe_revision_id,ordinal,chunk_index)
      SELECT ?,?,pkgbase,catalog_revision,recipe_revision_id,ordinal,chunk_index FROM cohort_scope_entries WHERE upload_id=?`).bind(upload.cohort_id, revision, uploadId),
    db.prepare(`INSERT INTO cohort_recipe_ownership(recipe_revision_id,cohort_id)
      SELECT recipe_revision_id,? FROM cohort_scope_entries WHERE upload_id=? AND recipe_revision_id IS NOT NULL ON CONFLICT(recipe_revision_id) DO NOTHING`).bind(upload.cohort_id, uploadId),
    db.prepare(`INSERT INTO distribution_assertions(expected,actual) SELECT 0,COUNT(*) FROM cohort_scope_entries e
      JOIN cohort_recipe_ownership o ON o.recipe_revision_id=e.recipe_revision_id WHERE e.upload_id=? AND o.cohort_id<>?`).bind(uploadId, upload.cohort_id),
    db.prepare(`UPDATE requests SET catalog_pkgbase=e.pkgbase,catalog_revision=e.catalog_revision FROM cohort_scope_entries e
      WHERE e.upload_id=? AND e.recipe_revision_id IS NOT NULL AND requests.id=json_extract(e.member_json,'$.recipe.requestId')`).bind(uploadId),
    ...event.statements,
  ]); } catch (cause) { cohortConflict(cause); }
  return { cohort_id: upload.cohort_id, revision, manifest_sha256: hash, unchanged: false };
}
