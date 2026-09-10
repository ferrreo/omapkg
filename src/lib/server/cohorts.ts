import * as v from 'valibot';
import { canonicalJson } from '../canonical-json';
import { cohortCauses, cohortOwnerAreas, type CohortEvent, type CohortInlineManifest, type CohortManifest, type CohortMember, type CohortMetadata, type CohortRow } from '../cohorts';
import { parseSystemVersion } from '../distribution';
import type { Actor, Revision } from '../model';
import { getCatalogPackage, humanMaintainer, parseCatalogManifest, reviewReason } from './catalog-ownership';
import { audit, now, query, sha256 } from './db';
import { PolicyError } from './policy';
import { reviewedPackageVersion } from './build-outputs';

const digest = v.pipe(v.string(), v.regex(/^[a-f0-9]{64}$/));
const identifier = v.pipe(v.string(), v.regex(/^[A-Za-z0-9_-]{1,128}$/));
const name = v.pipe(v.string(), v.regex(/^[a-z0-9][a-z0-9@._+-]{0,63}$/));
const text = v.pipe(v.string(), v.trim(), v.minLength(1), v.maxLength(2000), v.regex(/^[^\x00-\x1f\x7f]+$/));
const metadataSchema = v.strictObject({
  title: v.pipe(text, v.maxLength(160)), lane: v.picklist(['system', 'opr']),
  systemVersion: v.nullable(v.string()), parentSnapshot: v.nullable(digest),
  compatibleSystems: v.pipe(v.array(digest), v.maxLength(32)),
});
const scopeSchema = v.strictObject({
  ...metadataSchema.entries,
  members: v.pipe(v.array(v.strictObject({
    pkgbase: name, catalogRevision: v.pipe(v.number(), v.integer(), v.minValue(1)),
    recipeRevisionId: v.nullable(identifier), cause: v.picklist(cohortCauses), reason: text,
  })), v.minLength(1), v.maxLength(512)),
});
export type CohortScopeInput = v.InferOutput<typeof scopeSchema>;

export async function getCohort(db: D1Database, cohortId: string): Promise<CohortRow> {
  const row = await db.prepare(`SELECT c.*,r.manifest_json,r.manifest_sha256,r.title,r.lane
    FROM cohorts c JOIN cohort_revisions r ON r.cohort_id=c.id AND r.revision=c.current_revision WHERE c.id=?`)
    .bind(cohortId).first<CohortRow>();
  if (!row) throw new PolicyError(404, 'Build cohort not found.');
  if (await sha256(row.manifest_json) !== row.manifest_sha256) throw new PolicyError(409, 'Cohort manifest integrity check failed.');
  return row;
}

export function scopeAuthority(actor: Actor | null, manifest: CohortManifest): Actor {
  const reviewer = humanMaintainer(actor);
  for (const area of cohortOwnerAreas(manifest)) humanMaintainer(reviewer, area);
  return reviewer;
}

export function scopeAuthorityFence(db: D1Database, actor: Actor, areas: string[]) {
  return db.prepare(`INSERT INTO distribution_assertions(expected,actual) SELECT 0,COUNT(*) FROM json_each(?) area
    WHERE NOT EXISTS(SELECT 1 FROM team_memberships WHERE github_id=? AND (team IN ('admin','security') OR team=area.value))`)
    .bind(canonicalJson(areas), actor.id.slice(7));
}

export async function releaseAuthority(db: D1Database, actor: Actor | null): Promise<Actor> {
  const reviewer = humanMaintainer(actor);
  if (!await db.prepare("SELECT 1 FROM team_memberships WHERE github_id=? AND team='release'").bind(reviewer.id.slice(7)).first()) {
    throw new PolicyError(403, 'Explicit release team membership is required. Recipe or administrator access does not grant release authority.');
  }
  return reviewer;
}

export function parseCohortMetadata(input: unknown): CohortMetadata {
  const parsed = v.safeParse(metadataSchema, input);
  if (!parsed.success) throw new PolicyError(400, 'Check cohort title, lane and pinned snapshots.');
  const value = parsed.output;
  if (value.lane === 'system' ? !value.systemVersion || !parseSystemVersion(value.systemVersion) : value.systemVersion !== null) {
    throw new PolicyError(400, 'System cohorts need an Omarchy version such as 4.0.3-rc2; OPR cohorts use package versions.');
  }
  if (value.lane === 'system' && value.compatibleSystems.length) throw new PolicyError(400, 'Only independent OPR cohorts select supported system snapshots.');
  if (new Set(value.compatibleSystems).size !== value.compatibleSystems.length) throw new PolicyError(400, 'Supported snapshots cannot repeat.');
  return { ...value, compatibleSystems: value.compatibleSystems.sort() };
}

export async function cohortManifest(db: D1Database, actor: Actor | null, input: unknown): Promise<CohortInlineManifest> {
  humanMaintainer(actor);
  const parsed = v.safeParse(scopeSchema, input);
  if (!parsed.success) throw new PolicyError(400, 'Check cohort title, lane, pinned snapshots and enumerated members (1–512). Use chunked scope uploads for larger cohorts.');
  const { members: requested, ...metadata } = parsed.output;
  const value = { ...parseCohortMetadata(metadata), members: requested };
  if (new Set(value.members.map((member) => member.pkgbase)).size !== value.members.length) throw new PolicyError(400, 'Cohort members cannot repeat.');
  const members: CohortMember[] = [];
  for (const member of value.members.sort((a, b) => a.pkgbase < b.pkgbase ? -1 : a.pkgbase > b.pkgbase ? 1 : 0)) {
    const record = await getCatalogPackage(db, member.pkgbase);
    if (!record || record.revision !== member.catalogRevision) throw new PolicyError(409, `${member.pkgbase}: select the current catalog policy revision.`);
    const policy = parseCatalogManifest(JSON.parse(record.manifest_json));
    if (await sha256(record.manifest_json) !== record.manifest_sha256) throw new PolicyError(409, `${member.pkgbase}: catalog integrity check failed.`);
    humanMaintainer(actor, policy.ownerArea);
    if (value.lane === 'opr' && policy.lane !== 'opr') throw new PolicyError(409, `${member.pkgbase} belongs to a versioned system release.`);
    let recipe: CohortMember['recipe'] = null;
    if (member.recipeRevisionId) {
      const revision = await db.prepare(`SELECT r.*,q.name,q.upstream_url,q.source_kind,q.area,
        (SELECT latest.id FROM revisions latest WHERE latest.request_id=q.id ORDER BY latest.created_at DESC,latest.rowid DESC LIMIT 1) AS latest_id
        FROM revisions r JOIN requests q ON q.id=r.request_id WHERE r.id=?`).bind(member.recipeRevisionId)
        .first<Revision & { name: string; upstream_url: string; source_kind: string; area: string; latest_id: string }>();
      if (!revision || revision.id !== revision.latest_id || revision.name !== member.pkgbase || revision.upstream_url !== policy.upstreamUrl ||
          revision.source_kind !== policy.sourceKind || revision.area !== policy.ownerArea) {
        throw new PolicyError(409, `${member.pkgbase}: recipe must match the current owned identity, source and area.`);
      }
      if (canonicalJson([...new Set(JSON.parse(revision.architectures_json) as string[])].sort()) !== canonicalJson(policy.architectures)) {
        throw new PolicyError(409, `${member.pkgbase}: recipe targets do not match the catalog policy.`);
      }
      recipe = { id: revision.id, manifestSha256: revision.manifest_sha256, fullVersion: reviewedPackageVersion(revision), requestId: revision.request_id };
    }
    members.push({ pkgbase: member.pkgbase, catalogRevision: record.revision, catalogSha256: record.manifest_sha256,
      policy, recipe, cause: member.cause, reason: member.reason });
  }
  return { schemaVersion: 1, title: value.title, lane: value.lane, systemVersion: value.systemVersion,
    parentSnapshot: value.parentSnapshot, compatibleSystems: value.compatibleSystems.sort(), members };
}

export function cohortConflict(cause: unknown): never {
  if (cause instanceof Error && /constraint|cohort|published legacy/i.test(cause.message)) {
    throw new PolicyError(409, 'Cohort, review or publication state changed. Refresh before retrying; already published builds need new revisions.');
  }
  throw cause;
}

export type CohortEventInput = Pick<CohortEvent, 'kind' | 'phase' | 'condition' | 'cause' | 'evidence'>;

/** Callers add their checked mutations to this same D1 transaction. */
export async function cohortEventStatements(db: D1Database, current: CohortRow, actor: string, commandSha256: string, input: CohortEventInput,
  next?: { revision: number; manifestSha256: string }) {
  const event: CohortEvent = { schemaVersion: 1, cohortId: current.id, revision: next?.revision ?? current.current_revision,
    sequence: current.event_sequence + 1, kind: input.kind, previousEventSha256: current.event_sha256,
    priorManifestSha256: current.event_sequence ? current.manifest_sha256 : null,
    manifestSha256: next?.manifestSha256 ?? current.manifest_sha256, from: current.event_sequence ? current.phase : null,
    phase: input.phase, condition: input.condition, actor, timestamp: now(), cause: reviewReason(input.cause), evidence: input.evidence };
  const json = canonicalJson(event); const hash = await sha256(json);
  return { event, digest: hash, statements: [
    db.prepare(`UPDATE cohorts SET current_revision=?,event_sequence=?,event_sha256=?,phase=?,condition=?,updated_at=?
      WHERE id=? AND current_revision=? AND event_sequence=? AND event_sha256 IS ?`)
      .bind(event.revision, event.sequence, hash, event.phase, event.condition, event.timestamp, current.id, current.current_revision, current.event_sequence, current.event_sha256),
    db.prepare('INSERT INTO distribution_assertions(expected,actual) VALUES(1,changes())'),
    db.prepare(`INSERT INTO cohort_events(cohort_id,sequence,revision,command_sha256,event_json,event_sha256,created_at) VALUES(?,?,?,?,?,?,?)`)
      .bind(current.id, event.sequence, event.revision, commandSha256, json, hash, event.timestamp),
    audit(db, actor, `cohort.${event.kind}`, current.id, { revision: event.revision, sequence: event.sequence, eventSha256: hash, cause: event.cause }),
  ] };
}

export async function proposeCohort(db: D1Database, actor: Actor | null, cohortId: string, expectedRevision: number | null, input: unknown, reason: string) {
  if (!v.safeParse(identifier, cohortId).success) throw new PolicyError(400, 'Invalid cohort ID.');
  const manifest = await cohortManifest(db, actor, input); const reviewer = scopeAuthority(actor, manifest);
  const previous = await db.prepare('SELECT id FROM cohorts WHERE id=?').bind(cohortId).first();
  const current = previous ? await getCohort(db, cohortId) : null;
  if (current) {
    scopeAuthority(actor, JSON.parse(current.manifest_json));
    if (['publish', 'observe'].includes(current.phase)) throw new PolicyError(409, 'Published scope is immutable. Open a follow-up cohort.');
  }
  const json = canonicalJson(manifest); const hash = await sha256(json);
  if (current?.manifest_sha256 === hash && (current.current_revision === expectedRevision || current.current_revision === (expectedRevision ?? 0) + 1)) return current;
  if ((current?.current_revision ?? null) !== expectedRevision) throw new PolicyError(409, 'Cohort changed. Review its current revision.');
  const revision = (current?.current_revision ?? 0) + 1; const timestamp = now();
  const base: CohortRow = current ?? { id: cohortId, current_revision: 1, event_sequence: 0, event_sha256: null,
    phase: 'plan', condition: 'ready', updated_at: timestamp, manifest_json: json, manifest_sha256: hash, title: manifest.title, lane: manifest.lane };
  const event = await cohortEventStatements(db, base, reviewer.id, await sha256(canonicalJson({ kind: 'scope', revision, hash })),
    { kind: 'scope', phase: 'plan', condition: 'ready', cause: reason, evidence: {} }, { revision, manifestSha256: hash });
  const statements: D1PreparedStatement[] = [
    ...(!current ? [db.prepare("INSERT INTO cohorts(id,current_revision,phase,condition,created_at,updated_at) VALUES(?,1,'plan','ready',?,?)").bind(cohortId, timestamp, timestamp)] : []),
    db.prepare(`INSERT INTO cohort_revisions(cohort_id,revision,manifest_json,manifest_sha256,title,lane,created_by,created_at) VALUES(?,?,?,?,?,?,?,?)`)
      .bind(cohortId, revision, json, hash, manifest.title, manifest.lane, reviewer.id, timestamp),
  ];
  for (const member of manifest.members) {
    statements.push(db.prepare('INSERT INTO distribution_assertions(expected,actual) SELECT 1,COUNT(*) FROM catalog_packages WHERE pkgbase=? AND current_revision=?')
      .bind(member.pkgbase, member.catalogRevision));
    statements.push(db.prepare('INSERT INTO cohort_members(cohort_id,revision,pkgbase,catalog_revision,recipe_revision_id) VALUES(?,?,?,?,?)')
      .bind(cohortId, revision, member.pkgbase, member.catalogRevision, member.recipe?.id ?? null));
    if (member.recipe) {
      statements.push(db.prepare('INSERT INTO cohort_recipe_ownership(recipe_revision_id,cohort_id) VALUES(?,?) ON CONFLICT(recipe_revision_id) DO NOTHING').bind(member.recipe.id, cohortId));
      statements.push(db.prepare('INSERT INTO distribution_assertions(expected,actual) SELECT 1,COUNT(*) FROM cohort_recipe_ownership WHERE recipe_revision_id=? AND cohort_id=?').bind(member.recipe.id, cohortId));
      statements.push(db.prepare(`UPDATE requests SET catalog_pkgbase=?,catalog_revision=? WHERE id=? AND name=? AND upstream_url=? AND source_kind=? AND area=?
        AND (catalog_pkgbase IS NULL OR catalog_pkgbase=?)
        AND ?=(SELECT r.id FROM revisions r WHERE r.request_id=requests.id ORDER BY r.created_at DESC,r.rowid DESC LIMIT 1)`)
        .bind(member.pkgbase, member.catalogRevision, member.recipe.requestId, member.pkgbase, member.policy.upstreamUrl, member.policy.sourceKind,
          member.policy.ownerArea, member.pkgbase, member.recipe.id));
      statements.push(db.prepare('INSERT INTO distribution_assertions(expected,actual) VALUES(1,changes())'));
    }
  }
  try { await db.batch([...statements, ...event.statements]); } catch (cause) { cohortConflict(cause); }
  return getCohort(db, cohortId);
}

export async function listCohorts(db: D1Database, input: { search?: string; lane?: string; phase?: string; after?: string }) {
  const filters = ['c.id>?']; const values: string[] = [input.after ?? ''];
  if (input.lane) { filters.push('r.lane=?'); values.push(input.lane); }
  if (input.phase) { filters.push('c.phase=?'); values.push(input.phase); }
  if (input.search) { filters.push("r.title LIKE ? ESCAPE '\\'"); values.push(`%${input.search.slice(0,100).replace(/[\\%_]/g, '\\$&')}%`); }
  return query<CohortRow & { member_count: number }>(db, `SELECT c.*,r.title,r.lane,r.manifest_sha256,
    COALESCE(json_array_length(r.manifest_json,'$.members'),json_extract(r.manifest_json,'$.memberCount')) AS member_count FROM cohorts c
    JOIN cohort_revisions r ON r.cohort_id=c.id AND r.revision=c.current_revision WHERE ${filters.join(' AND ')} ORDER BY c.id LIMIT 50`, ...values);
}

export async function cohortEvents(db: D1Database, cohortId: string, after = 0, limit = 100) {
  return query<{ sequence: number; event_sha256: string; event_json: string }>(db,
    'SELECT sequence,event_sha256,event_json FROM cohort_events WHERE cohort_id=? AND sequence>? ORDER BY sequence LIMIT ?', cohortId, after, Math.min(100, limit));
}

export async function cohortForBuild(db: D1Database, buildId: string) {
  return db.prepare('SELECT c.cohort_id FROM cohort_recipe_ownership c JOIN builds b ON b.revision_id=c.recipe_revision_id WHERE b.id=?')
    .bind(buildId).first<{ cohort_id: string }>();
}
