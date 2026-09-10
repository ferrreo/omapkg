import { expect, test } from 'bun:test';
import { readFileSync, readdirSync } from 'node:fs';
import { asD1, TestD1 } from './d1';
import { canonicalJson } from '../src/lib/canonical-json';
import { sha256 } from '../src/lib/server/db';
import { beginCatalogImport, appendCatalogImport, getCatalogImport, sealCatalogImport, parseImportEntry } from '../src/lib/server/catalog-imports';
import { compareImportEntries, reconcileCatalogImports, importBuildCoverage } from '../src/lib/server/catalog-reconciliation';
import { startCatalogCapture } from '../src/lib/server/catalog-capture';
import type { ImportEntry, ImportManifest, ImportSource } from '../src/lib/imports';
import type { Env } from '../src/lib/server/env';

const schema = readdirSync(new URL('../migrations', import.meta.url)).filter((file) => file.endsWith('.sql')).sort()
  .map((file) => readFileSync(new URL(`../migrations/${file}`, import.meta.url), 'utf8')).join('\n');
const owner = { id: 'github:1', role: 'maintainer' as const, areas: ['system'] };
const entry = (name: string, target: 'x86_64' | 'aarch64' = 'x86_64', version = '1.0-1'): ImportEntry => ({
  sourceId: `core-${target}`, name, pkgbase: name, version, architecture: 'any', target, collection: 'core', filename: `${name}-${version}-any.pkg.tar.zst`,
  sha256: 'a'.repeat(64), size: 10, installedSize: 20, description: 'Fixture package', upstreamUrl: 'https://example.org/project', licenses: ['MIT'],
  dependencies: [], makeDependencies: [], checkDependencies: [], provides: [], conflicts: [], replaces: [], packageSignature: null,
});
async function manifest(entries: ImportEntry[], options: { channel?: 'stable' | 'upstream'; missingArm?: boolean } = {}): Promise<ImportManifest> {
  const sources: ImportSource[] = ['x86_64', 'aarch64'].map((target) => ({ id: `core-${target}`, url: `https://example.org/${target}/core.db`,
    collection: 'core', target: target as 'x86_64' | 'aarch64', status: target === 'aarch64' && options.missingArm ? 'unavailable' : 'captured',
    sha256: target === 'aarch64' && options.missingArm ? null : 'b'.repeat(64), entries: entries.filter((entry) => entry.target === target).length,
    signature: 'missing', signatureSha256: null, error: target === 'aarch64' && options.missingArm ? 'HTTP 404' : null }));
  const index = await Promise.all([...entries].sort((a, b) => `${a.sourceId}/${a.name}`.localeCompare(`${b.sourceId}/${b.name}`))
    .map(async (entry) => [entry.sourceId, entry.name, await sha256(canonicalJson(entry))]));
  return { schemaVersion: 1, kind: options.channel === 'upstream' ? 'arch' : 'omarchy', channel: options.channel ?? 'stable', sources, entriesSha256: await sha256(canonicalJson(index)) };
}
async function capture(db: D1Database, entries: ImportEntry[], options?: Parameters<typeof manifest>[1]) {
  const { importId } = await beginCatalogImport(db, owner, await manifest(entries, options));
  if (entries.length) await appendCatalogImport(db, owner, importId, entries);
  await sealCatalogImport(db, owner, importId);
  return importId;
}

test('capture is resumable and sealed only after exact source counts and index match; any keeps both target records', async () => {
  const db = new TestD1(schema); const d1 = asD1(db);
  try {
    const entries = [entry('shared'), entry('shared', 'aarch64')];
    const input = await manifest(entries); const { importId } = await beginCatalogImport(d1, owner, input);
    await expect(sealCatalogImport(d1, owner, importId)).rejects.toThrow('incomplete');
    await appendCatalogImport(d1, owner, importId, entries.slice(0, 1));
    await appendCatalogImport(d1, owner, importId, entries.slice(0, 1));
    expect((await getCatalogImport(d1, importId)).received).toBe(1);
    await expect(appendCatalogImport(d1, owner, importId, [{ ...entries[0], sha256: 'c'.repeat(64) }])).rejects.toMatchObject({ status: 409 });
    await appendCatalogImport(d1, owner, importId, entries.slice(1));
    expect(await sealCatalogImport(d1, owner, importId)).toMatchObject({ status: 'captured' });
    expect((await getCatalogImport(d1, importId)).received).toBe(2);
    expect(await importBuildCoverage(d1, importId)).toEqual({ captured: 2, admitted: 0, built: 0 });
    await expect(appendCatalogImport(d1, owner, importId, entries)).rejects.toThrow('sealed');
    expect(() => db.exec("UPDATE catalog_import_entries SET entry_json='{}'")).toThrow('immutable');
  } finally { db.close(); }
});

test('import build progress includes registered split outputs and preserves legacy evidence', async () => {
  const holder = new TestD1(`
    CREATE TABLE catalog_import_entries(import_id TEXT,name TEXT,target_architecture TEXT,entry_json TEXT);
    CREATE TABLE catalog_outputs(name TEXT,pkgbase TEXT);
    CREATE TABLE catalog_packages(pkgbase TEXT,admitted_revision INTEGER);
    CREATE TABLE requests(id TEXT,catalog_pkgbase TEXT,catalog_revision INTEGER);
    CREATE TABLE revisions(id TEXT,request_id TEXT,manifest_sha256 TEXT);
    CREATE TABLE builds(id TEXT,revision_id TEXT,architecture TEXT,status TEXT,smoke_passed INTEGER,provenance_signature TEXT,provenance TEXT,output_contract_json TEXT,attempt INTEGER);
    CREATE TABLE build_artifacts(build_id TEXT,attempt INTEGER,filename TEXT,sha256 TEXT);
    CREATE TABLE approvals(revision_id TEXT,kind TEXT,revoked_at INTEGER,manifest_sha256 TEXT);
    INSERT INTO catalog_packages VALUES('base',1);
    INSERT INTO requests VALUES('request','base',1);
    INSERT INTO revisions VALUES('revision','request','reviewed');
    INSERT INTO approvals VALUES('revision','area',NULL,'reviewed'),('revision','security',NULL,'reviewed');
  `);
  const db = asD1(holder);
  try {
    for (const name of ['legacy', 'split', 'split-docs', 'missing-output']) {
      holder.prepare('INSERT INTO catalog_outputs VALUES(?,?)').bind(name, 'base').run();
      holder.prepare('INSERT INTO catalog_import_entries VALUES(?,?,?,?)').bind('capture', name, 'x86_64', JSON.stringify({ version: '2:1.0-1' })).run();
    }
    holder.prepare("INSERT INTO builds VALUES('legacy-build','revision','x86_64','succeeded',1,'signed',?,NULL,1)")
      .bind(JSON.stringify({ packageMetadata: { name: 'legacy', fullVersion: '2:1.0-1' } })).run();
    const outputs = ['split', 'split-docs', 'missing-output'].map((name) => ({ filename: `${name}.pkg.tar.zst`, artifactSha256: name,
      packageMetadata: { name, fullVersion: '2:1.0-1' } }));
    holder.prepare("INSERT INTO builds VALUES('split-build','revision','x86_64','succeeded',1,'signed',?,'contract',2)")
      .bind(JSON.stringify({ schemaVersion: 2, outputs })).run();
    for (const output of outputs.slice(0, 2)) holder.prepare("INSERT INTO build_artifacts VALUES('split-build',2,?,?)").bind(output.filename, output.artifactSha256).run();
    expect(await importBuildCoverage(db, 'capture')).toEqual({ captured: 4, admitted: 4, built: 3 });
    holder.exec("UPDATE build_artifacts SET attempt=1 WHERE filename='split-docs.pkg.tar.zst'");
    expect((await importBuildCoverage(db, 'capture')).built).toBe(2);
    holder.exec("UPDATE approvals SET revoked_at=1 WHERE kind='security'");
    expect((await importBuildCoverage(db, 'capture')).built).toBe(0);
  } finally { holder.close(); }
});

test('reconciliation retains missing packages and target gaps when an ARM baseline exists', async () => {
  const db = new TestD1(schema); const d1 = asD1(db);
  try {
    const baseline = await capture(d1, [entry('present'), entry('missing'), entry('present', 'aarch64')]);
    const candidate = await capture(d1, [entry('present', 'x86_64', '2.0-1'), entry('extra')], { channel: 'upstream', missingArm: true });
    const { report } = await reconcileCatalogImports(d1, owner, candidate, baseline);
    expect(report.counts).toMatchObject({ missing: 2, extra: 1, version: 1 });
    expect(report.sourceGaps.some((gap) => gap.includes('aarch64'))).toBe(true);
    expect(report.matchesBaseline).toBe(false); expect(report.coverageComplete).toBe(false); expect(report.releaseReady).toBe(false);
    expect(db.prepare('SELECT COUNT(*) AS n FROM catalog_reconciliation_items').first<{ n: number }>()).toEqual({ n: 4 });
    expect((await reconcileCatalogImports(d1, owner, candidate, baseline)).report).toEqual(report);
    expect(compareImportEntries([entry('shared')], [{ ...entry('shared'), architecture: 'x86_64' }], ['core'])[0].kind).toBe('architecture');
    await expect(reconcileCatalogImports(d1, owner, candidate, candidate)).rejects.toThrow('separately');
    expect(() => db.exec("UPDATE catalog_reconciliations SET report_json='{}'")).toThrow('immutable');
  } finally { db.close(); }
});

test('existing OPR recipe-only packages remain recipes and cannot masquerade as signed binaries', async () => {
  const recipe = { ...entry('recipe-only'), filename: 'PKGBUILD', surface: 'recipe' as const, recipeUrl: 'https://example.org/repo/recipes/recipe-only/1.0-1/x86_64/PKGBUILD' };
  const input = await manifest([recipe]);
  input.sources[0].format = 'recipe-catalog';
  expect(parseImportEntry(recipe, input).surface).toBe('recipe');
  expect(() => parseImportEntry({ ...recipe, recipeUrl: 'https://another.example/PKGBUILD' }, input)).toThrow('origin');
  expect(() => parseImportEntry({ ...recipe, packageSignature: 'AAAA' }, input)).toThrow('signature');
});

test('capture jobs are authorized and deduplicated; OPR capture is distinct from Omarchy system channels', async () => {
  const db = new TestD1(schema); const d1 = asD1(db); let dispatched = 0;
  const env = { DB: d1, PUBLIC_ORIGIN: 'https://omapkg.example', PIPELINE: { fetch: async () => { dispatched++; return Response.json({}, { status: 202 }); } } } as unknown as Env;
  try {
    await expect(startCatalogCapture(env, { ...owner, role: 'public' }, 'arch', 'upstream', 'omapkg')).rejects.toMatchObject({ status: 403 });
    const first = await startCatalogCapture(env, owner, 'arch', 'upstream', 'omapkg');
    expect(await startCatalogCapture(env, owner, 'arch', 'upstream', 'omapkg')).toEqual(first); expect(dispatched).toBe(1);
    await expect(startCatalogCapture(env, owner, 'opr', 'rc', 'omapkg')).rejects.toThrow('Channel');
    await startCatalogCapture(env, owner, 'opr', 'stable', 'omapkg');
    await startCatalogCapture(env, owner, 'omarchy', 'stable', 'omarchy');
    expect(dispatched).toBe(3);
  } finally { db.close(); }
});

test('absent Omarchy ARM baseline is a new qualification target, not a comparison blocker', async () => {
  const db = new TestD1(schema); const d1 = asD1(db);
  try {
    const baseline = await capture(d1, [entry('present')], { missingArm: true });
    const candidate = await capture(d1, [entry('present'), entry('arm-reference', 'aarch64')], { channel: 'upstream' });
    const { report } = await reconcileCatalogImports(d1, owner, candidate, baseline);
    expect(report.matchesBaseline).toBe(true);
    expect(report.sourceGaps).toEqual([]);
    expect(report.counts.extra).toBe(0);
    expect(report.newTargets).toEqual([{ collection: 'core', target: 'aarch64', referencePackages: 1 }]);
    expect(report.requiredNativeTargets).toEqual(['x86_64', 'aarch64']);
    expect(report.releaseReady).toBe(false);
  } finally { db.close(); }
});
