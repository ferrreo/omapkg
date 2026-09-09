import * as v from 'valibot';
import { areas, type Actor } from '../model';
import { collections, requiredArchitectures, externalPackageSource, type CatalogManifest } from '../distribution';
import { canonicalJson } from '../canonical-json';
import { audit, now, query, sha256 } from './db';
import { parseDeclaredLicense, PolicyError, publicSourceURL, requireMaintainer, requireSecurity } from './policy';

const name = v.pipe(v.string(), v.regex(/^[a-z0-9][a-z0-9@._+-]{0,63}$/));
const reason = v.pipe(v.string(), v.trim(), v.minLength(1), v.maxLength(2000), v.regex(/^[^\x00-\x1f\x7f]+$/));
const architecture = v.picklist(['x86_64', 'aarch64']);
const schema = v.strictObject({
  schemaVersion: v.literal(1), pkgbase: name,
  outputs: v.pipe(v.array(name), v.minLength(1), v.maxLength(256)),
  collection: v.picklist(collections), lane: v.picklist(['system', 'opr']),
  role: v.picklist(['base-system', 'omarchy-default', 'optional', 'build-only']),
  origin: v.picklist(['arch', 'omarchy', 'upstream', 'aur-reference', 'alarm-reference']),
  upstreamUrl: v.pipe(v.string(), v.maxLength(2048)), sourceKind: v.picklist(['git', 'archive']),
  description: v.pipe(v.string(), v.trim(), v.minLength(1), v.maxLength(500)),
  license: v.string(), ownerArea: v.picklist(areas),
  architectures: v.pipe(v.array(architecture), v.minLength(1), v.maxLength(2)),
  artifactArchitecture: v.picklist(['any', 'native']),
  portableOutputs: v.optional(v.pipe(v.array(name), v.maxLength(256))),
  runtimeGroups: v.optional(v.pipe(v.array(v.pipe(v.array(name), v.minLength(1), v.maxLength(256))), v.minLength(1), v.maxLength(256))),
  architectureExceptions: v.pipe(v.array(v.strictObject({ architecture, reason })), v.maxLength(1)),
  sourceReference: v.nullable(v.strictObject({ url: v.string(), commit: v.pipe(v.string(), v.regex(/^[a-f0-9]{40}(?:[a-f0-9]{24})?$/)) })),
  rebuildOn: v.pipe(v.array(name), v.maxLength(256)),
});

export function reviewReason(value: unknown): string {
  const result = v.safeParse(reason, value);
  if (!result.success) throw new PolicyError(400, 'Provide a clear reason, up to 2,000 characters.');
  return result.output;
}

export function humanMaintainer(actor: Actor | null, area?: string): Actor {
  const reviewer = requireMaintainer(actor, area);
  if (!/^github:[1-9][0-9]{0,19}$/.test(reviewer.id)) throw new PolicyError(403, 'A signed-in human maintainer must make this decision.');
  return reviewer;
}

export function parseCatalogManifest(input: unknown): CatalogManifest {
  const parsed = v.safeParse(schema, input);
  if (!parsed.success) throw new PolicyError(400, 'Invalid catalog manifest. Check package identity, ownership, source and architecture fields.');
  const value = parsed.output;
  value.upstreamUrl = publicSourceURL(value.upstreamUrl);
  value.license = parseDeclaredLicense(value.license);
  if (externalPackageSource(value.upstreamUrl)) throw new PolicyError(400, 'Use the authoritative upstream source for an OPR replacement; AUR/ALARM is reference evidence only.');
  if (value.sourceReference) value.sourceReference.url = publicSourceURL(value.sourceReference.url);
  if ((value.origin === 'aur-reference' || value.origin === 'alarm-reference') && !value.sourceReference) {
    throw new PolicyError(400, 'Retain the original AUR/ALARM reference and immutable commit.');
  }
  if (new Set(value.outputs).size !== value.outputs.length || new Set(value.architectures).size !== value.architectures.length ||
      new Set(value.rebuildOn).size !== value.rebuildOn.length) throw new PolicyError(400, 'Catalog lists cannot contain duplicate entries.');
  if (value.portableOutputs && (new Set(value.portableOutputs).size !== value.portableOutputs.length || value.portableOutputs.some((name) => !value.outputs.includes(name)))) {
    throw new PolicyError(400, 'Portable outputs must be unique names from this package output set.');
  }
  value.portableOutputs?.sort();
  if (value.runtimeGroups) {
    const covered = new Set(value.runtimeGroups.flat());
    if (covered.size !== value.outputs.length || value.outputs.some((name) => !covered.has(name)) ||
        value.runtimeGroups.some((group) => new Set(group).size !== group.length || group.some((name) => !value.outputs.includes(name)))) {
      throw new PolicyError(400, 'Installation groups must cover every output using only unique names from this package.');
    }
    value.runtimeGroups = value.runtimeGroups.map((group) => group.sort()).sort((a, b) => a.join(' ') < b.join(' ') ? -1 : a.join(' ') > b.join(' ') ? 1 : 0);
    if (new Set(value.runtimeGroups.map((group) => group.join(' '))).size !== value.runtimeGroups.length) throw new PolicyError(400, 'Installation groups cannot repeat.');
  }
  const exceptions = new Set(value.architectureExceptions.map((entry) => entry.architecture));
  if (value.architectures.some((arch) => exceptions.has(arch)) ||
      requiredArchitectures.some((arch) => !value.architectures.includes(arch) && !exceptions.has(arch))) {
    throw new PolicyError(400, 'Both primary architectures are required unless a missing target has an explicit reviewed reason.');
  }
  if ((['core', 'extra', 'multilib'].includes(value.collection) || ['base-system', 'omarchy-default'].includes(value.role)) && value.lane !== 'system') {
    throw new PolicyError(400, 'Core/extra and default-system packages belong to versioned system releases.');
  }
  if (value.collection === 'multilib' && value.architectures.includes('aarch64')) throw new PolicyError(400, 'Multilib is an x86_64-only collection.');
  return { ...value, outputs: value.outputs.sort(), architectures: value.architectures.sort(), rebuildOn: value.rebuildOn.sort(),
    architectureExceptions: value.architectureExceptions.sort((a, b) => a.architecture.localeCompare(b.architecture)) };
}

export type CatalogRecord = {
  pkgbase: string; current_revision: number; admitted_revision: number | null; revision: number;
  manifest_json: string; manifest_sha256: string; collection: string; lane: string; owner_area: string; created_by: string;
};

export async function getCatalogPackage(db: D1Database, pkgbase: string, admitted = false): Promise<CatalogRecord | null> {
  return db.prepare(`SELECT p.pkgbase,p.current_revision,p.admitted_revision,r.* FROM catalog_packages p JOIN catalog_revisions r
    ON r.pkgbase=p.pkgbase AND r.revision=${admitted ? 'p.admitted_revision' : 'p.current_revision'} WHERE p.pkgbase=?`).bind(pkgbase).first<CatalogRecord>();
}

export async function proposeCatalogPackage(db: D1Database, actor: Actor | null, input: unknown, expectedRevision: number | null, message: string) {
  const manifest = parseCatalogManifest(input);
  const reviewer = humanMaintainer(actor, manifest.ownerArea);
  const current = await getCatalogPackage(db, manifest.pkgbase);
  if (current) humanMaintainer(actor, current.owner_area);
  if ((current?.current_revision ?? null) !== expectedRevision) throw new PolicyError(409, 'Catalog changed. Review the current revision before proposing changes.');
  const json = canonicalJson(manifest);
  const digest = await sha256(json);
  if (current?.manifest_sha256 === digest) return { pkgbase: current.pkgbase, revision: current.revision, manifestSha256: digest };
  const clean = reviewReason(message);
  const revision = (current?.current_revision ?? 0) + 1;
  const timestamp = now();
  const statements: D1PreparedStatement[] = [
    current
      ? db.prepare('UPDATE catalog_packages SET current_revision=?,updated_at=? WHERE pkgbase=? AND current_revision=?').bind(revision, timestamp, manifest.pkgbase, expectedRevision)
      : db.prepare('INSERT INTO catalog_packages(pkgbase,current_revision,created_at,updated_at) VALUES(?,?,?,?)').bind(manifest.pkgbase, revision, timestamp, timestamp),
    db.prepare('INSERT INTO distribution_assertions(expected,actual) VALUES(1,changes())'),
    db.prepare(`INSERT INTO catalog_revisions(pkgbase,revision,manifest_json,manifest_sha256,collection,lane,owner_area,created_by,reason,created_at)
      VALUES(?,?,?,?,?,?,?,?,?,?)`).bind(manifest.pkgbase, revision, json, digest, manifest.collection, manifest.lane, manifest.ownerArea, reviewer.id, clean, timestamp),
  ];
  for (const output of manifest.outputs) {
    statements.push(db.prepare('INSERT INTO catalog_outputs(name,pkgbase) VALUES(?,?) ON CONFLICT(name) DO NOTHING').bind(output, manifest.pkgbase));
    statements.push(db.prepare('INSERT INTO distribution_assertions(expected,actual) SELECT 1,COUNT(*) FROM catalog_outputs WHERE name=? AND pkgbase=?').bind(output, manifest.pkgbase));
  }
  statements.push(audit(db, reviewer.id, 'catalog.proposed', manifest.pkgbase, { revision, manifestSha256: digest, reason: clean }));
  try { await db.batch(statements); }
  catch (cause) {
    if (cause instanceof Error && /constraint|unique/i.test(cause.message)) throw new PolicyError(409, 'Catalog changed or an output name belongs to another package. Refresh before retrying.');
    throw cause;
  }
  return { pkgbase: manifest.pkgbase, revision, manifestSha256: digest };
}

export async function approveCatalogPackage(db: D1Database, actor: Actor | null, pkgbase: string, revision: number, digest: string, kind: string, message: string) {
  const current = await getCatalogPackage(db, pkgbase);
  if (!current || current.revision !== revision || current.manifest_sha256 !== digest) throw new PolicyError(409, 'Review the current exact catalog revision.');
  const reviewer = humanMaintainer(actor, current.owner_area);
  if (kind === 'security') requireSecurity(reviewer);
  else if (kind !== 'area') throw new PolicyError(400, 'Choose area or security review.');
  parseCatalogManifest(JSON.parse(current.manifest_json));
  if (await sha256(current.manifest_json) !== digest) throw new PolicyError(409, 'Catalog manifest integrity check failed.');
  const clean = reviewReason(message);
  const timestamp = now();
  let results: D1Result[];
  try { results = await db.batch([
    db.prepare(`INSERT INTO catalog_reviews(pkgbase,revision,kind,actor,manifest_sha256,reason,created_at)
      SELECT ?,?,?,?,?,?,? WHERE EXISTS (SELECT 1 FROM catalog_packages WHERE pkgbase=? AND current_revision=?)
        AND NOT EXISTS (SELECT 1 FROM catalog_reviews WHERE pkgbase=? AND revision=? AND kind<>? AND actor=?)
      ON CONFLICT(pkgbase,revision,kind) DO UPDATE SET actor=excluded.actor,reason=excluded.reason,created_at=excluded.created_at`)
      .bind(pkgbase, revision, kind, reviewer.id, digest, clean, timestamp, pkgbase, revision, pkgbase, revision, kind, reviewer.id),
    db.prepare('INSERT INTO distribution_assertions(expected,actual) VALUES(1,changes())'),
    db.prepare(`UPDATE catalog_packages SET admitted_revision=?,updated_at=? WHERE pkgbase=? AND current_revision=?
      AND (SELECT COUNT(DISTINCT actor) FROM catalog_reviews WHERE pkgbase=? AND revision=? AND manifest_sha256=?)=2`)
      .bind(revision, timestamp, pkgbase, revision, pkgbase, revision, digest),
    audit(db, reviewer.id, 'catalog.reviewed', pkgbase, { revision, kind, manifestSha256: digest, reason: clean }),
  ]); } catch (cause) {
    if (cause instanceof Error && /constraint/i.test(cause.message)) throw new PolicyError(409, 'Catalog changed or independent reviewers are required.');
    throw cause;
  }
  return { admitted: Boolean(results[2]?.meta.changes), revision };
}

export async function listCatalogPackages(db: D1Database, input: { search?: string; collection?: string; after?: string; limit?: number }) {
  const limit = Math.min(100, Math.max(1, Math.floor(input.limit ?? 50)));
  const filters = ['r.revision=p.current_revision', 'r.pkgbase=p.pkgbase', 'p.pkgbase>?'];
  const values: unknown[] = [input.after ?? ''];
  if (input.collection) { filters.push('r.collection=?'); values.push(input.collection); }
  if (input.search) { filters.push("(p.pkgbase LIKE ? ESCAPE '\\' OR json_extract(r.manifest_json,'$.description') LIKE ? ESCAPE '\\')"); const search = `%${input.search.slice(0,100).replace(/[\\%_]/g, '\\$&')}%`; values.push(search, search); }
  return query<CatalogRecord>(db, `SELECT p.current_revision,p.admitted_revision,r.* FROM catalog_packages p,catalog_revisions r
    WHERE ${filters.join(' AND ')} ORDER BY p.pkgbase LIMIT ?`, ...values, limit);
}

export function catalogManifestFromForm(form: FormData): CatalogManifest {
  const text = (key: string) => String(form.get(key) ?? '');
  const list = (key: string) => text(key).split(/[\s,]+/).filter(Boolean);
  const architectures = form.getAll('architectures').map(String);
  return parseCatalogManifest({
    schemaVersion: 1, pkgbase: text('pkgbase'), outputs: list('outputs'), collection: text('collection'), lane: text('lane'),
    role: text('role'), origin: text('origin'), upstreamUrl: text('upstreamUrl'), sourceKind: text('sourceKind'),
    description: text('description'), license: text('license'), ownerArea: text('ownerArea'), architectures,
    artifactArchitecture: text('artifactArchitecture'), rebuildOn: list('rebuildOn'),
    ...(list('portableOutputs').length ? { portableOutputs: list('portableOutputs') } : {}),
    ...(text('runtimeGroups').trim() ? { runtimeGroups: text('runtimeGroups').trim().split(/\r?\n/).filter((line) => line.trim()).map((line) => line.trim().split(/[\s,]+/)) } : {}),
    architectureExceptions: requiredArchitectures.filter((architecture) => !architectures.includes(architecture))
      .map((architecture) => ({ architecture, reason: text(`exception_${architecture}`) })),
    sourceReference: text('referenceUrl') || text('referenceCommit') ? { url: text('referenceUrl'), commit: text('referenceCommit') } : null,
  });
}
