import { expect, test } from 'bun:test';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, readFileSync, readdirSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { parseRecipeCapture, verifyRecipeCapture, } from '../src/lib/recipe-capture';
import { parseSrcinfo, srcinfoField } from '../src/lib/srcinfo';
import { retainRecipeCapture, getRecipeCapture } from '../src/lib/server/recipe-captures';
import { retainInputBytes } from '../src/lib/server/input-objects';
import { canonicalJson } from '../src/lib/canonical-json';
import { beginCatalogImport, appendCatalogImport, sealCatalogImport } from '../src/lib/server/catalog-imports';
import type { ImportEntry, ImportManifest } from '../src/lib/imports';
import { sha256 } from '../src/lib/server/db';
import { TestD1, asD1 } from './d1';

const metadata = `pkgbase = demo
\tpkgver = 1.4
\tpkgrel = 3.2
\tepoch = 2
\tarch = x86_64
\tarch = aarch64
\tdepends = glibc
\tmakedepends = cc
\tsource = demo.tar.xz::https://example.org/source.tar.xz
\tsha256sums = ${'a'.repeat(64)}
pkgname = demo
\tinstall = demo.install
pkgname = demo-docs
\tarch = any
\tdepends =
`;

test('.SRCINFO preserves split outputs, complete versions and per-output overrides without shell evaluation', () => {
  const parsed = parseSrcinfo(metadata);
  expect(parsed.version).toBe('2:1.4-3.2');
  expect(srcinfoField(parsed, parsed.outputs[0], 'depends', 'aarch64')).toEqual(['glibc']);
  expect(srcinfoField(parsed, parsed.outputs[1], 'depends', 'aarch64')).toEqual([]);
  expect(srcinfoField(parsed, parsed.outputs[1], 'arch')).toEqual(['any']);
  expect(() => parseSrcinfo(metadata + '\tpkgver = 7\n')).toThrow('overrides');
  expect(() => parseSrcinfo(metadata.replace('\tpkgver = 1.4', '\tpkgver = $(touch /unexpected)'))).toThrow();
  expect(() => parseSrcinfo(metadata.replace('\tpkgver = 1.4', '\tpkgver = 1.4\n\tpkgver = 1.5'))).toThrow('Repeated');
});

test('real Git recipe capture rejects substitutions and omissions, retains immutable source mapping, and grants no approval', async () => {
  const root = mkdtempSync(join(tmpdir(), 'opr-recipe-capture-'));
  const schema = readdirSync(new URL('../migrations', import.meta.url)).filter((name) => name.endsWith('.sql')).sort().map((name) => readFileSync(new URL(`../migrations/${name}`, import.meta.url), 'utf8')).join('\n');
  const db = new TestD1(schema); const objects = new Map<string, Uint8Array>();
  const env = { DB: asD1(db), GITHUB_REPOSITORY: 'example/recipes', ARTIFACTS: {
    put: async (key: string, bytes: Uint8Array) => { objects.set(key, bytes.slice()); },
    get: async (key: string) => { const bytes = objects.get(key); return bytes ? { size: bytes.length, arrayBuffer: async () => bytes.slice().buffer } : null; },
  } as unknown as R2Bucket };
  const actor = { id: 'github:1', role: 'maintainer' as const, areas: ['system'] };
  db.exec("INSERT INTO team_memberships VALUES('1','system')");
  try {
    const repo = join(root, 'repo'); mkdirSync(repo); mkdirSync(join(repo, 'recipe/.omarchy'), { recursive: true });
    const git = (...args: string[]) => execFileSync('git', ['-C', repo, ...args], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim();
    git('init');
    writeFileSync(join(repo, 'recipe/PKGBUILD'), `pkgname=demo\npkgver=1.4\npkgrel=3.2\ntouch '${root}/MUST_NOT_EXECUTE'\n`);
    writeFileSync(join(repo, 'recipe/.SRCINFO'), metadata);
    writeFileSync(join(repo, 'recipe/demo.install'), 'post_install() { true; }\n');
    writeFileSync(join(repo, 'recipe/empty'), '');
    writeFileSync(join(repo, 'recipe/Notes with spaces.md'), 'Original notes.\n');
    writeFileSync(join(repo, 'recipe/fix.patch'), new Uint8Array([0, 128, 255]));
    writeFileSync(join(repo, 'recipe/.omarchy/package.json'), '{"source":"aur","pinned":true,"rebuild_on":["glibc"],"future_policy":"review me"}\n');
    symlinkSync('fix.patch', join(repo, 'recipe/patch-link'));
    git('add', '.'); git('-c', 'user.name=Recipe test', '-c', 'user.email=test@example.invalid', 'commit', '-m', 'Fixture');
    const commit = git('rev-parse', 'HEAD');
    const capture = join(root, 'capture');
    execFileSync('python3', [new URL('../services/pipeline/capture-recipe.py', import.meta.url).pathname, '--git-directory', repo,
      '--repository', 'https://github.com/example/recipes', '--commit', commit, '--directory', 'recipe', '--pkgbase', 'demo', '--origin', 'opr', '--output', capture]);
    const manifest = parseRecipeCapture(JSON.parse(readFileSync(join(capture, 'manifest.json'), 'utf8')), env.GITHUB_REPOSITORY);
    const read = async (ref: { sha256: string }) => new Uint8Array(readFileSync(join(capture, 'objects', ref.sha256)));
    const inspected = await verifyRecipeCapture(manifest, read);
    expect(new TextDecoder().decode(inspected.get('.SRCINFO'))).toBe(metadata);
    expect(readdirSync(root)).not.toContain('MUST_NOT_EXECUTE');
    await expect(verifyRecipeCapture({ ...manifest, files: manifest.files.slice(1) }, read)).rejects.toThrow('inventory');
    await expect(verifyRecipeCapture({ ...manifest, commit: 'f'.repeat(40) }, read)).rejects.toThrow('commit proof');
    await expect(verifyRecipeCapture({ ...manifest, git: { ...manifest.git, trees: [] } }, read)).rejects.toThrow('incomplete');
    const changed = structuredClone(manifest);
    changed.files.find((file) => file.path === 'PKGBUILD')!.object = manifest.files.find((file) => file.path === '.SRCINFO')!.object;
    await expect(verifyRecipeCapture(changed, read)).rejects.toThrow('original Git blob');
    const traversal = structuredClone(manifest); traversal.files[0].path = '../escape';
    expect(() => parseRecipeCapture(traversal, env.GITHUB_REPOSITORY)).toThrow('Unsafe');
    expect(() => parseRecipeCapture({ ...manifest, origin: 'arch' }, env.GITHUB_REPOSITORY)).toThrow('origin');
    for (const digest of readdirSync(join(capture, 'objects'))) await retainInputBytes(env, actor, await read({ sha256: digest }));
    const entries: ImportEntry[] = ['demo', 'demo-docs'].map((name) => ({ sourceId: 'opr-x86', name, pkgbase: 'demo', version: '2:1.4-3.2', architecture: name.endsWith('docs') ? 'any' : 'x86_64', target: 'x86_64', collection: 'omapkg',
      filename: `${name}-1.4-3.2-x86_64.pkg.tar.zst`, sha256: 'b'.repeat(64), size: 20, installedSize: 30, description: 'Demo', upstreamUrl: 'https://example.org/demo', licenses: ['MIT'],
      dependencies: name.endsWith('docs') ? [] : ['glibc'], makeDependencies: ['cc'], checkDependencies: [], provides: [], conflicts: [], replaces: [], packageSignature: null }));
    const index = await Promise.all(entries.map(async (entry) => [entry.sourceId, entry.name, await sha256(canonicalJson(entry))]));
    const inventory: ImportManifest = { schemaVersion: 1, kind: 'opr', channel: 'stable', sources: [{ id: 'opr-x86', url: 'https://example.org/opr.db', collection: 'omapkg', target: 'x86_64', status: 'captured', sha256: 'c'.repeat(64), entries: 2, signature: 'missing', signatureSha256: null, error: null }], entriesSha256: await sha256(canonicalJson(index)) };
    const { importId } = await beginCatalogImport(env.DB, actor, inventory);
    await appendCatalogImport(env.DB, actor, importId, entries); await sealCatalogImport(env.DB, actor, importId);
    const ref = JSON.parse(readFileSync(join(capture, 'reference.json'), 'utf8'));
    const retained = await retainRecipeCapture(env, actor, ref, importId, 'opr-x86', 'Match captured upstream packaging commit.');
    expect(retained.comparison).toMatchObject({ matches: true, metadataPresent: true, differences: [] });
    expect((await getRecipeCapture(env, ref.sha256)).summary).toMatchObject({ admissionRequired: true, rebuildOn: ['glibc'] });
    expect((await getRecipeCapture(env, ref.sha256)).summary.reviewNotes.join(' ')).toContain('future_policy');
    await retainRecipeCapture(env, actor, ref, importId, 'opr-x86', 'Identical retry.');
    expect(db.prepare('SELECT COUNT(*) AS n FROM recipe_capture_links').first<{ n: number }>()).toEqual({ n: 1 });
    for (const table of ['catalog_packages', 'approvals', 'builds']) expect(db.prepare(`SELECT COUNT(*) AS n FROM ${table}`).first<{ n: number }>()).toEqual({ n: 0 });
    expect(db.prepare("SELECT COUNT(*) AS n FROM catalog_import_entries WHERE disposition='unreviewed'").first<{ n: number }>()).toEqual({ n: 2 });
    expect(() => db.exec("UPDATE recipe_captures SET summary_json='{}'")).toThrow('immutable');
    db.exec("DELETE FROM team_memberships WHERE github_id='1'");
    await expect(retainRecipeCapture(env, actor, ref, importId, 'opr-x86', 'Stale authority.')).rejects.toThrow();

    symlinkSync('../../outside', join(repo, 'recipe/escape')); git('add', '.'); git('-c', 'user.name=Recipe test', '-c', 'user.email=test@example.invalid', 'commit', '-m', 'Unsafe link');
    const unsafe = join(root, 'unsafe');
    execFileSync('python3', [new URL('../services/pipeline/capture-recipe.py', import.meta.url).pathname, '--git-directory', repo,
      '--repository', 'https://github.com/example/recipes', '--commit', git('rev-parse', 'HEAD'), '--directory', 'recipe', '--pkgbase', 'demo', '--origin', 'opr', '--output', unsafe]);
    const unsafeManifest = parseRecipeCapture(JSON.parse(readFileSync(join(unsafe, 'manifest.json'), 'utf8')), env.GITHUB_REPOSITORY);
    await expect(verifyRecipeCapture(unsafeManifest, async (ref) => new Uint8Array(readFileSync(join(unsafe, 'objects', ref.sha256))))).rejects.toThrow('escapes');
  } finally { db.close(); rmSync(root, { recursive: true, force: true }); }
});
