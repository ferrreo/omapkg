import { cohortMemberCount, cohortPageSize, type CohortManifest, type CohortMember, type CohortMemberChunk } from '../cohorts';
import { query, sha256 } from './db';
import { PolicyError } from './policy';

export type CohortScopeRecord = { id: string; current_revision: number; manifest_json: string; manifest_sha256: string };

export async function readCohortManifest(record: Pick<CohortScopeRecord, 'manifest_json' | 'manifest_sha256'>): Promise<CohortManifest> {
  if (await sha256(record.manifest_json) !== record.manifest_sha256) throw new PolicyError(409, 'Cohort manifest integrity check failed.');

  return JSON.parse(record.manifest_json) as CohortManifest;
}

async function verifiedChunk(row: { members_json: string; sha256: string } | null, chunk: CohortMemberChunk): Promise<CohortMember[]> {
  if (!row || row.sha256 !== chunk.sha256 || await sha256(row.members_json) !== chunk.sha256) throw new PolicyError(409, 'Cohort member chunk integrity check failed.');
  const values = JSON.parse(row.members_json) as CohortMember[];

  if (values.length !== chunk.count || values[0]?.pkgbase !== chunk.first || values.at(-1)?.pkgbase !== chunk.last) throw new PolicyError(409, 'Cohort member chunk coverage check failed.');

  return values;
}

/** The root commits every chunk. A page never hydrates unrelated catalog members. */
export async function cohortMembers(db: D1Database, record: CohortScopeRecord, start = 0, limit = cohortPageSize): Promise<CohortMember[]> {
  if (!Number.isSafeInteger(start) || start < 0 || !Number.isSafeInteger(limit) || limit < 1 || limit > 512) throw new PolicyError(400, 'Invalid cohort member page.');
  const manifest = await readCohortManifest(record);

  if (manifest.schemaVersion === 1) return manifest.members.slice(start, start + limit);
  const end = Math.min(start + limit, cohortMemberCount(manifest));
  const members: CohortMember[] = [];

  for (const chunk of manifest.memberChunks.filter((item) => item.start < end && item.start + item.count > start)) {
    const row = await db.prepare('SELECT members_json,sha256 FROM cohort_revision_chunks WHERE cohort_id=? AND revision=? AND chunk_index=?')
      .bind(record.id, record.current_revision, chunk.index).first<{ members_json: string; sha256: string }>();

    const values = await verifiedChunk(row, chunk);
    members.push(...values.slice(Math.max(0, start - chunk.start), Math.min(chunk.count, end - chunk.start)));
  }

  if (members.length !== Math.max(0, end - start)) throw new PolicyError(409, 'Cohort membership is incomplete.');

  return members;
}

/** Sequential exports batch small chunk reads and retain at most sixteen chunks. */
export async function* cohortMemberStream(db: D1Database, record: CohortScopeRecord): AsyncGenerator<CohortMember> {
  const manifest = await readCohortManifest(record);

  if (manifest.schemaVersion === 1) {
    yield* [...manifest.members].sort((a, b) => a.pkgbase < b.pkgbase ? -1 : a.pkgbase > b.pkgbase ? 1 : 0);

    return;
  }

  let count = 0; let last = '';

  for (let offset = 0; offset < manifest.memberChunks.length; offset += 16) {
    const rows = await query<{ chunk_index: number; members_json: string; sha256: string }>(db, `SELECT chunk_index,members_json,sha256 FROM cohort_revision_chunks
      WHERE cohort_id=? AND revision=? AND chunk_index>=? ORDER BY chunk_index LIMIT 16`, record.id, record.current_revision, offset);

    if (rows.length !== Math.min(16, manifest.memberChunks.length - offset)) throw new PolicyError(409, 'Cohort member chunks are missing.');

    for (const [index, row] of rows.entries()) {
      const chunk = manifest.memberChunks[offset + index];

      if (row.chunk_index !== chunk.index || chunk.start !== count) throw new PolicyError(409, 'Cohort chunk order is invalid.');

      for (const member of await verifiedChunk(row, chunk)) {
        if (member.pkgbase <= last) throw new PolicyError(409, 'Cohort members are duplicated or unordered.');
        last = member.pkgbase; count++; yield member;
      }
    }
  }

  if (count !== manifest.memberCount) throw new PolicyError(409, 'Cohort member count is incomplete.');
}

export async function cohortRecipeMember(db: D1Database, record: CohortScopeRecord, recipeId: string) {
  const manifest = await readCohortManifest(record);

  const binding = await db.prepare('SELECT source_revision_id FROM factory_revision_bindings WHERE revision_id=?').bind(recipeId).first<{ source_revision_id: string }>();
  const sourceId = binding?.source_revision_id ?? recipeId;
  if (manifest.schemaVersion === 1) {
    const member = manifest.members.find((item) => item.recipe?.id === sourceId);
    return member && binding ? { ...member, recipe: member.recipe ? { ...member.recipe, id: recipeId } : member.recipe } : member;
  }
  const rows = await query<{ ordinal: number }>(db, 'SELECT ordinal FROM cohort_members WHERE cohort_id=? AND revision=? AND recipe_revision_id=?', record.id, record.current_revision, sourceId);

  if (rows.length !== 1) return undefined;
  const member = (await cohortMembers(db, record, rows[0].ordinal, 1))[0];

  if (member?.recipe?.id !== sourceId) throw new PolicyError(409, 'Cohort recipe membership integrity check failed.');

  return member && binding ? { ...member, recipe: member.recipe ? { ...member.recipe, id: recipeId } : member.recipe } : member;
}

export async function namedCohortMembers(db: D1Database, record: CohortScopeRecord, names: string[]) {
  const manifest = await readCohortManifest(record);

  if (manifest.schemaVersion === 1) return manifest.members.filter((member) => names.includes(member.pkgbase));

  const rows = await query<{ ordinal: number; pkgbase: string }>(db, `SELECT ordinal,pkgbase FROM cohort_members
    WHERE cohort_id=? AND revision=? AND pkgbase IN (SELECT value FROM json_each(?))`, record.id, record.current_revision, JSON.stringify(names));

  const members = new Map<number, CohortMember>();

  for (const chunk of manifest.memberChunks.filter((chunk) => rows.some((row) => row.ordinal >= chunk.start && row.ordinal < chunk.start + chunk.count))) {
    for (const [index, member] of (await cohortMembers(db, record, chunk.start, chunk.count)).entries()) members.set(chunk.start + index, member);
  }

  return rows.map((row) => {
    const member = members.get(row.ordinal);

    if (member?.pkgbase !== row.pkgbase) throw new PolicyError(409, 'Cohort name index integrity check failed.');

    return member;
  });
}
