import * as v from 'valibot';
import type { Actor } from '../model';
import type { ImportEntry, ImportManifest, ImportDisposition } from '../imports';
import { collections } from '../distribution';
import { canonicalJson } from '../canonical-json';
import { audit, now, query, sha256 } from './db';
import { parseArchRelation, compareArchVersions } from './arch';
import { PolicyError, publicSourceURL } from './policy';
import { humanMaintainer, reviewReason } from './catalog-ownership';

const digest = v.pipe(v.string(), v.regex(/^[a-f0-9]{64}$/));

const name = v.pipe(v.string(), v.regex(/^[a-z0-9][a-z0-9@._+-]{0,63}$/));

const architecture = v.picklist(['x86_64', 'aarch64']);

const text = (max: number) => v.pipe(v.string(), v.maxLength(max), v.check((value) => !value.includes('\u0000') && !value.includes('\r'), 'Control characters are not allowed.'));

const list = v.pipe(v.array(text(256)), v.maxLength(2048));

const sourceSchema = v.strictObject({
  id: v.pipe(v.string(), v.regex(/^[a-z0-9][a-z0-9._-]{0,95}$/)), url: text(2048), collection: v.picklist(collections), target: architecture,
  status: v.picklist(['captured', 'unavailable']), sha256: v.nullable(digest), entries: v.pipe(v.number(), v.integer(), v.minValue(0), v.maxValue(100_000)),
  signature: v.picklist(['verified', 'unverified', 'missing', 'failed']), signatureSha256: v.nullable(digest), error: v.nullable(text(2000)),
  format: v.optional(v.picklist(['pacman-db', 'recipe-catalog'])),
});

const manifestSchema = v.strictObject({
  schemaVersion: v.literal(1), kind: v.picklist(['arch', 'omarchy', 'opr']), channel: v.picklist(['upstream', 'stable', 'rc', 'edge', 'dev']),
  sources: v.pipe(v.array(sourceSchema), v.minLength(1), v.maxLength(32)), entriesSha256: digest,
});

const entrySchema = v.strictObject({
  sourceId: sourceSchema.entries.id, name, pkgbase: name, version: text(128), architecture: v.picklist(['x86_64', 'aarch64', 'any']), target: architecture,
  collection: v.picklist(collections), filename: text(256), sha256: digest,
  size: v.pipe(v.number(), v.integer(), v.minValue(1), v.maxValue(32 * 1024 ** 3)), installedSize: v.pipe(v.number(), v.integer(), v.minValue(0), v.maxValue(128 * 1024 ** 3)),
  description: text(2000), upstreamUrl: v.nullable(text(2048)), licenses: list, dependencies: list, makeDependencies: list, checkDependencies: list,
  provides: list, conflicts: list, replaces: list, packageSignature: v.nullable(v.pipe(v.string(), v.maxLength(64 * 1024), v.regex(/^[A-Za-z0-9+/]+={0,2}$/))),
  surface: v.optional(v.picklist(['binary', 'recipe'])), recipeUrl: v.optional(text(2048)),
});

export type ImportRow = { id: string; manifest_json: string; manifest_sha256: string; expected_count: number; status: 'capturing' | 'captured' | 'reconciled'; created_at: number; created_by: string };

export type ImportEntryRow = { source_id: string; name: string; pkgbase: string; architecture: string; target_architecture: string; collection: string; entry_json: string; entry_sha256: string; disposition: ImportDisposition; reason: string | null };

export function parseImportManifest(input: unknown): ImportManifest {
  const result = v.safeParse(manifestSchema, input);

  if (!result.success) throw new PolicyError(400, 'Invalid import manifest. Use the catalog capture tool.');
  const manifest = result.output;

  if (manifest.sources.reduce((count, source) => count + source.entries, 0) > 100_000) throw new PolicyError(400, 'Capture exceeds the 100,000-record import budget.');

  if (new Set(manifest.sources.map((source) => source.id)).size !== manifest.sources.length) throw new PolicyError(400, 'Import sources must have unique identities.');

  for (const source of manifest.sources) {
    publicSourceURL(source.url);

    if ((source.status === 'captured' && (!source.sha256 || source.error)) || (source.status === 'unavailable' && (source.entries || !source.error))) throw new PolicyError(400, 'Captured and unavailable sources need distinct evidence.');

    if (source.signature === 'verified' && !source.signatureSha256) throw new PolicyError(400, 'Verified source signatures need their captured digest.');

    if (source.collection === 'multilib' && source.target !== 'x86_64') throw new PolicyError(400, 'Do not invent ARM multilib coverage.');
  }

  return { ...manifest, sources: manifest.sources.sort((a, b) => a.id.localeCompare(b.id)) };
}

export function parseImportEntry(input: unknown, manifest: ImportManifest): ImportEntry {
  const result = v.safeParse(entrySchema, input);

  if (!result.success) throw new PolicyError(400, 'Invalid captured package metadata.');
  const entry = result.output;
  const source = manifest.sources.find((source) => source.id === entry.sourceId);

  if (!source || source.status !== 'captured' || source.collection !== entry.collection || source.target !== entry.target ||
      (entry.architecture !== 'any' && entry.architecture !== entry.target)) throw new PolicyError(400, 'Package does not belong to its declared captured source and architecture.');

  if (entry.surface === 'recipe') {
    if (source.format !== 'recipe-catalog' || entry.filename !== 'PKGBUILD' || !entry.recipeUrl || entry.packageSignature) throw new PolicyError(400, 'Recipe imports require a public recipe identity, not a binary package signature.');
    const recipeUrl = publicSourceURL(entry.recipeUrl);

    if (new URL(recipeUrl).origin !== new URL(source.url).origin) throw new PolicyError(400, 'Imported recipes must come from the captured OPR origin.');
  } else if (!/^[A-Za-z0-9][A-Za-z0-9@._+:%~^-]{0,220}\.pkg\.tar\.(?:zst|xz|gz)$/.test(entry.filename) || source.format === 'recipe-catalog') {
    throw new PolicyError(400, 'Invalid captured binary package filename or source format.');
  }

  if (compareArchVersions(entry.version, entry.version) === null) throw new PolicyError(400, 'Captured package version is invalid.');

  for (const relation of [...entry.dependencies, ...entry.makeDependencies, ...entry.checkDependencies, ...entry.provides, ...entry.conflicts, ...entry.replaces]) {
    if (!parseArchRelation(relation)) throw new PolicyError(400, `Invalid captured package relation: ${relation}`);
  }

  return entry;
}

export async function getCatalogImport(db: D1Database, importId: string) {
  const record = await db.prepare('SELECT * FROM catalog_imports WHERE id=?').bind(importId).first<ImportRow>();

  if (!record) throw new PolicyError(404, 'Catalog import not found.');

  if (await sha256(record.manifest_json) !== record.manifest_sha256) throw new PolicyError(409, 'Import manifest integrity check failed.');
  const manifest = parseImportManifest(JSON.parse(record.manifest_json));
  const counts = await query<{ disposition: string; count: number }>(db, 'SELECT disposition,COUNT(*) AS count FROM catalog_import_entries WHERE import_id=? GROUP BY disposition', importId);

  return { record, manifest, received: counts.reduce((total, item) => total + item.count, 0), counts: Object.fromEntries(counts.map((item) => [item.disposition, item.count])) };
}

export async function beginCatalogImport(db: D1Database, actor: Actor | null, input: unknown) {
  const reviewer = humanMaintainer(actor, 'system');
  const manifest = parseImportManifest(input); const json = canonicalJson(manifest); const manifestSha256 = await sha256(json);
  await db.batch([
    db.prepare(`INSERT INTO catalog_imports(id,manifest_sha256,manifest_json,expected_count,status,created_by,created_at)
      VALUES(?,?,?,?,'capturing',?,?) ON CONFLICT(manifest_sha256) DO NOTHING`).bind(manifestSha256, manifestSha256, json,
        manifest.sources.reduce((count, source) => count + source.entries, 0), reviewer.id, now()),
    db.prepare(`INSERT INTO audit_events(actor,action,target,detail,created_at) SELECT ?,'catalog.import_started',?,?,? WHERE changes()=1`)
      .bind(reviewer.id, manifestSha256, canonicalJson({ kind: manifest.kind, channel: manifest.channel, manifestSha256 }), now()),
  ]);
  const state = await db.prepare('SELECT status FROM catalog_imports WHERE id=?').bind(manifestSha256).first<{ status: ImportRow['status'] }>();

  return { importId: manifestSha256, status: state!.status };
}

export async function appendCatalogImport(db: D1Database, actor: Actor | null, importId: string, values: unknown) {
  humanMaintainer(actor, 'system');

  if (!Array.isArray(values) || !values.length || values.length > 250) throw new PolicyError(400, 'Upload between 1 and 250 entries per chunk.');
  const { record, manifest } = await getCatalogImport(db, importId);

  if (record.status !== 'capturing') throw new PolicyError(409, 'This import capture is already sealed.');

  const entries = await Promise.all(values.map(async (input) => {
    const entry = parseImportEntry(input, manifest); const json = canonicalJson(entry);

    return { ...entry, json, digest: await sha256(json) };
  }));

  if (new Set(entries.map((entry) => `${entry.sourceId}/${entry.name}`)).size !== entries.length) throw new PolicyError(400, 'Duplicate package in upload chunk.');
  const payload = canonicalJson(entries);

  if (new TextEncoder().encode(payload).length > 1024 * 1024) throw new PolicyError(413, 'Import chunk exceeds one MiB. Reduce its size.');

  try {
    await db.batch([
      db.prepare("INSERT INTO distribution_assertions(expected,actual) SELECT 1,COUNT(*) FROM catalog_imports WHERE id=? AND status='capturing'").bind(importId),
      db.prepare(`INSERT INTO catalog_import_entries(import_id,source_id,name,architecture,target_architecture,collection,pkgbase,entry_json,entry_sha256)
        SELECT ?,json_extract(value,'$.sourceId'),json_extract(value,'$.name'),json_extract(value,'$.architecture'),json_extract(value,'$.target'),
          json_extract(value,'$.collection'),json_extract(value,'$.pkgbase'),json_extract(value,'$.json'),json_extract(value,'$.digest') FROM json_each(?) WHERE 1
        ON CONFLICT(import_id,source_id,name) DO NOTHING`).bind(importId, payload),
      db.prepare(`INSERT INTO distribution_assertions(expected,actual) SELECT ?,COUNT(*) FROM json_each(?) incoming JOIN catalog_import_entries stored
        ON stored.import_id=? AND stored.source_id=json_extract(incoming.value,'$.sourceId') AND stored.name=json_extract(incoming.value,'$.name')
        AND stored.entry_sha256=json_extract(incoming.value,'$.digest')`).bind(entries.length, payload, importId),
      db.prepare(`INSERT INTO distribution_assertions(expected,actual) SELECT 0,COUNT(*) FROM json_each(?) source WHERE
        (SELECT COUNT(*) FROM catalog_import_entries e WHERE e.import_id=? AND e.source_id=json_extract(source.value,'$.id'))>json_extract(source.value,'$.entries')`)
        .bind(canonicalJson(manifest.sources), importId),
    ]);
  } catch (cause) {
    if (cause instanceof Error && /constraint|unique/i.test(cause.message)) throw new PolicyError(409, 'Import was sealed or an existing package has different captured bytes.');
    throw cause;
  }

  return { received: (await getCatalogImport(db, importId)).received };
}

export async function sealCatalogImport(db: D1Database, actor: Actor | null, importId: string) {
  const reviewer = humanMaintainer(actor, 'system');
  const { record, manifest, received } = await getCatalogImport(db, importId);

  if (record.status !== 'capturing') return { importId, status: record.status };

  if (received !== record.expected_count) throw new PolicyError(409, `Capture incomplete: received ${received} of ${record.expected_count} packages.`);
  const counts = await query<{ source_id: string; count: number }>(db, 'SELECT source_id,COUNT(*) AS count FROM catalog_import_entries WHERE import_id=? GROUP BY source_id', importId);

  if (manifest.sources.some((source) => (counts.find((row) => row.source_id === source.id)?.count ?? 0) !== source.entries)) throw new PolicyError(409, 'Per-source counts do not match the captured manifest.');

  const index = await query<{ source_id: string; name: string; entry_sha256: string }>(db,
    'SELECT source_id,name,entry_sha256 FROM catalog_import_entries WHERE import_id=? ORDER BY source_id,name', importId);

  if (await sha256(canonicalJson(index.map((entry) => [entry.source_id, entry.name, entry.entry_sha256]))) !== manifest.entriesSha256) throw new PolicyError(409, 'Captured package index digest does not match.');
  await db.batch([
    db.prepare('INSERT INTO distribution_assertions(expected,actual) SELECT ?,COUNT(*) FROM catalog_import_entries WHERE import_id=?').bind(record.expected_count, importId),
    db.prepare("UPDATE catalog_imports SET status='captured' WHERE id=? AND status='capturing'").bind(importId),
    db.prepare(`INSERT INTO audit_events(actor,action,target,detail,created_at) SELECT ?,'catalog.import_captured',?,?,? WHERE changes()=1`)
      .bind(reviewer.id, importId, canonicalJson({ received, unavailableSources: manifest.sources.filter((source) => source.status === 'unavailable').map((source) => source.id) }), now()),
  ]);

  return { importId, status: 'captured' };
}

export async function reviewImportEntry(db: D1Database, actor: Actor | null, importId: string, sourceId: string, name: string, disposition: string, message: string) {
  const reviewer = humanMaintainer(actor, 'system'); const clean = reviewReason(message);

  if (!['linked', 'replacement', 'blocked', 'excluded'].includes(disposition)) throw new PolicyError(400, 'Choose a reviewed import disposition.');
  const entry = await db.prepare('SELECT * FROM catalog_import_entries WHERE import_id=? AND source_id=? AND name=?').bind(importId, sourceId, name).first<ImportEntryRow>();

  if (!entry) throw new PolicyError(404, 'Captured package not found.');

  if (disposition === 'linked') {
    if (!await db.prepare(`SELECT 1 FROM catalog_outputs o JOIN catalog_packages p ON p.pkgbase=o.pkgbase WHERE o.name=? AND p.admitted_revision IS NOT NULL`).bind(name).first()) {
      throw new PolicyError(409, 'An independently admitted catalog policy is required before linking an imported output.');
    }
  }

  await db.batch([
    db.prepare('UPDATE catalog_import_entries SET disposition=?,reason=? WHERE import_id=? AND source_id=? AND name=?').bind(disposition, clean, importId, sourceId, name),
    db.prepare('INSERT INTO catalog_import_reviews(import_id,source_id,name,disposition,reason,actor,created_at) VALUES(?,?,?,?,?,?,?)').bind(importId, sourceId, name, disposition, clean, reviewer.id, now()),
    audit(db, reviewer.id, 'catalog.import_entry_reviewed', importId, { sourceId, name, disposition, reason: clean }),
  ]);
}

export async function listCatalogImports(db: D1Database) {
  return query<ImportRow & { received: number }>(db, `SELECT i.*,(SELECT COUNT(*) FROM catalog_import_entries e WHERE e.import_id=i.id) AS received FROM catalog_imports i ORDER BY created_at DESC,id LIMIT 50`);
}

export async function listImportEntries(db: D1Database, importId: string, input: { search?: string; disposition?: string; after?: string } = {}) {
  const pattern = `%${(input.search ?? '').slice(0,100).replace(/[\\%_]/g, '\\$&')}%`;

  return query<ImportEntryRow>(db, `SELECT * FROM catalog_import_entries WHERE import_id=? AND name LIKE ? ESCAPE '\\'
    AND (?='' OR disposition=?) AND (source_id||'/'||name)>? ORDER BY source_id,name LIMIT 50`,
    importId, pattern, input.disposition ?? '', input.disposition ?? '', input.after ?? '');
}
