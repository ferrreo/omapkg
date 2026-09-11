import { expect, test } from 'bun:test';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, readFileSync, readdirSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { parseRecipeCapture, verifyRecipeCapture } from '../src/lib/recipe-capture';
import { parseSrcinfo, srcinfoField } from '../src/lib/srcinfo';
import { retainRecipeCapture, getRecipeCapture, recipeCaptureCoverage } from '../src/lib/server/recipe-captures';
import { retainInputBytes } from '../src/lib/server/input-objects';
import { canonicalJson } from '../src/lib/canonical-json';
import { beginCatalogImport, appendCatalogImport, sealCatalogImport } from '../src/lib/server/catalog-imports';
import type { ImportEntry, ImportManifest } from '../src/lib/imports';
import { sha256 } from '../src/lib/server/db';
import { TestD1, asD1 } from './d1';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { requestRecipeInspection, requestFactoryRecipeInspection, claimRecipeInspection, requireRecipeInspectionLease, recipeInspectionObject, completeRecipeInspection, listRecipeInspections } from '../src/lib/server/recipe-inspections';
import { proposeCatalogPackage, approveCatalogPackage } from '../src/lib/server/catalog-ownership';
import { registerBuildImage, setBuildImageEnabled } from '../src/lib/server/build-images';
import type { Worker } from '../src/lib/model';
import type { WorkerMetadata } from '../src/lib/server/worker-protocol';
import { POST as inspectionInput } from '../src/routes/api/worker/inspections/[id]/inputs/[digest]/+server';
import { parseRecipeSourceBundle, recipeSources } from '../src/lib/recipe-sources';
import { recipeSourcePlan, retainRecipeSources } from '../src/lib/server/recipe-source-plans';
import { reservePreservedImport, resumePreservedImport, assertPreservedImportCurrent, cancelPreservedImport } from '../src/lib/server/preserved-imports';
import { revisionRecipeFiles } from '../services/pipeline/github-pr';
import type { FactoryRevisionDraft } from '../services/pipeline/types';
import { validateRevision } from '../src/lib/server/policy';
import { reviewedPackageVersion } from '../src/lib/server/build-outputs';
import { startFactory } from '../src/lib/server/requests';
import { finishFactoryAttempt, reserveFactoryAttempt, startFactoryRun, stopFactoryRun } from '../src/lib/server/factory-runs';
import type { Env } from '../src/lib/server/env';
import { checkPreservedWorker } from './preserved-worker-fixture';

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
\tdepends = glibc
\tdepends = demo-docs=2:1.4-3.2
pkgname = demo-docs
\tarch = any
\tdepends =
`;

test('.SRCINFO preserves split outputs, complete versions and per-output overrides without shell evaluation', () => {
  const parsed = parseSrcinfo(metadata);
  expect(parsed.version).toBe('2:1.4-3.2');
  expect(srcinfoField(parsed, parsed.outputs[0], 'depends', 'aarch64')).toEqual(['glibc', 'demo-docs=2:1.4-3.2']);
  expect(srcinfoField(parsed, parsed.outputs[1], 'depends', 'aarch64')).toEqual([]);
  expect(srcinfoField(parsed, parsed.outputs[1], 'arch')).toEqual(['any']);
  expect(() => parseSrcinfo(metadata + '\tpkgver = 7\n')).toThrow('overrides');
  expect(() => parseSrcinfo(metadata.replace('\tpkgver = 1.4', '\tpkgver = $(touch /unexpected)'))).toThrow();
  expect(() => parseSrcinfo(metadata.replace('\tpkgver = 1.4', '\tpkgver = 1.4\n\tpkgver = 1.5'))).toThrow('Repeated');
});

test('real Git recipe capture rejects substitutions and omissions, retains immutable source mapping, and grants no approval', async () => {
  const root = mkdtempSync(join(tmpdir(), 'opr-recipe-capture-'));
  const schema = readdirSync(new URL('../migrations', import.meta.url)).filter((name) => name.endsWith('.sql')).sort().map((name) => readFileSync(new URL(`../migrations/${name}`, import.meta.url), 'utf8')).join('\n');
  const db = new TestD1(schema); const objects = new Map<string, Uint8Array>(), objectMetadata = new Map<string, Record<string, string>>();

  const env = { DB: asD1(db), GITHUB_REPOSITORY: 'example/recipes', ARTIFACTS: {
    put: async (key: string, bytes: Uint8Array | string, options?: R2PutOptions) => { objects.set(key, typeof bytes === 'string' ? new TextEncoder().encode(bytes) : bytes.slice()); objectMetadata.set(key, options?.customMetadata ?? {}); },
    head: async (key: string) => { const bytes = objects.get(key);

 return bytes ? { size: bytes.length, customMetadata: objectMetadata.get(key) ?? {} } : null; },
    get: async (key: string) => { const bytes = objects.get(key);

 return bytes ? { size: bytes.length, arrayBuffer: async () => bytes.slice().buffer,
      body: new ReadableStream({ start(controller) { controller.enqueue(bytes); controller.close(); } }) } : null; },
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
    writeFileSync(join(repo, 'recipe/opr-manifest.json'), '{"upstream":"must remain byte-for-byte"}\n');
    writeFileSync(join(repo, 'recipe/.omarchy/update'), '#!/bin/sh\nexit 0\n', { mode: 0o755 });
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
    const sourceMetadata = parseSrcinfo(metadata);
    sourceMetadata.base.source = ['fix.patch', 'archive.zip::https://example.org/source?release=1', 'git+https://example.org/source.git#branch=release/quattro', 'https://example.org/file?release=1'];
    sourceMetadata.base.sha256sums = ['SKIP', 'b'.repeat(64), 'SKIP', 'c'.repeat(64)];
    sourceMetadata.base.source_aarch64 = ['arm.patch::https://example.org/arm.patch'];
    sourceMetadata.base.sha512sums_aarch64 = ['d'.repeat(128)];
    const planned = recipeSources(manifest, sourceMetadata, 'aarch64');
    expect(planned.sources.map((source) => [source.kind, source.name])).toEqual([['local', 'fix.patch'], ['file', 'archive.zip'], ['git', 'source'], ['file', 'file?release=1'], ['file', 'arm.patch']]);
    expect(planned.sources[2]).toMatchObject({ url: 'https://example.org/source.git', ref: { kind: 'branch', value: 'release/quattro' } });
    expect(planned.sources[4].checksums).toEqual({ sha512: 'd'.repeat(128) });
    expect(recipeSources(manifest, sourceMetadata, 'x86_64').sources).toHaveLength(4);
    const invalidSources = structuredClone(sourceMetadata);
    invalidSources.base.source[1] = 'fix.patch::https://example.org/archive.zip';
    expect(() => recipeSources(manifest, invalidSources, 'x86_64')).toThrow('unique');
    invalidSources.base.source[1] = '../escape::https://example.org/archive.zip';
    expect(() => recipeSources(manifest, invalidSources, 'x86_64')).toThrow('Unsafe');
    invalidSources.base.source[1] = 'git+https://example.org/archive.git#commit=abcdef';
    expect(() => recipeSources(manifest, invalidSources, 'x86_64')).toThrow('full immutable commit');
    invalidSources.base.source[1] = 'file:///etc/passwd';
    expect(() => recipeSources(manifest, invalidSources, 'x86_64')).toThrow('supported HTTPS');
    invalidSources.base.source = sourceMetadata.base.source;
    invalidSources.base.sha256sums.pop();
    expect(() => recipeSources(manifest, invalidSources, 'x86_64')).toThrow('checksum array');
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
      dependencies: name.endsWith('docs') ? [] : ['glibc', 'demo-docs=2:1.4-3.2'], makeDependencies: ['cc'], checkDependencies: [], provides: [], conflicts: [], replaces: [], packageSignature: null }));

    const index = await Promise.all(entries.map(async (entry) => [entry.sourceId, entry.name, await sha256(canonicalJson(entry))]));
    const inventory: ImportManifest = { schemaVersion: 1, kind: 'opr', channel: 'stable', sources: [{ id: 'opr-x86', url: 'https://example.org/opr.db', collection: 'omapkg', target: 'x86_64', status: 'captured', sha256: 'c'.repeat(64), entries: 2, signature: 'missing', signatureSha256: null, error: null }], entriesSha256: await sha256(canonicalJson(index)) };
    const { importId } = await beginCatalogImport(env.DB, actor, inventory);
    expect(await recipeCaptureCoverage(env.DB, importId)).toEqual({ total: 0, retained: 0, matching: 0, differing: 0, missingMetadata: 0 });
    await appendCatalogImport(env.DB, actor, importId, entries); await sealCatalogImport(env.DB, actor, importId);
    expect(await recipeCaptureCoverage(env.DB, importId)).toEqual({ total: 1, retained: 0, matching: 0, differing: 0, missingMetadata: 0 });
    const ref = JSON.parse(readFileSync(join(capture, 'reference.json'), 'utf8'));
    const retained = await retainRecipeCapture(env, actor, ref, importId, 'opr-x86', 'Match captured upstream packaging commit.');
    expect(retained.comparison).toMatchObject({ matches: true, metadataPresent: true, differences: [] });
    expect((await getRecipeCapture(env, ref.sha256)).summary).toMatchObject({ admissionRequired: true, rebuildOn: ['glibc'] });
    expect((await getRecipeCapture(env, ref.sha256)).summary.reviewNotes.join(' ')).toContain('future_policy');
    await retainRecipeCapture(env, actor, ref, importId, 'opr-x86', 'Identical retry.');
    expect(await recipeCaptureCoverage(env.DB, importId)).toEqual({ total: 1, retained: 1, matching: 1, differing: 0, missingMetadata: 0 });
    expect(db.prepare('SELECT COUNT(*) AS n FROM recipe_capture_links').first<{ n: number }>()).toEqual({ n: 1 });

    for (const table of ['catalog_packages', 'approvals', 'builds']) expect(db.prepare(`SELECT COUNT(*) AS n FROM ${table}`).first<{ n: number }>()).toEqual({ n: 0 });
    expect(db.prepare("SELECT COUNT(*) AS n FROM catalog_import_entries WHERE disposition='unreviewed'").first<{ n: number }>()).toEqual({ n: 2 });
    expect(() => db.exec("UPDATE recipe_captures SET summary_json='{}'")).toThrow('immutable');

    const imageRef = `registry.example.org/inspection@sha256:${'d'.repeat(64)}`;
    const image = await registerBuildImage(env, { id: 'github:3', role: 'admin', areas: ['system'] }, { label: 'Test inspection image', image_ref: imageRef, architecture: 'x86_64', mirror: 'custom' });
    await setBuildImageEnabled(env, { id: 'github:3', role: 'admin', areas: ['system'] }, image.id, true);
    await expect(requestRecipeInspection(env, actor, ref.sha256, image.id, 'Inspect admitted source.')).rejects.toThrow('admission');
    db.exec("INSERT INTO team_memberships VALUES('2','security')");

    const policy = await proposeCatalogPackage(env.DB, actor, { schemaVersion: 1, pkgbase: 'demo', outputs: ['demo', 'demo-docs'], collection: 'omapkg', lane: 'opr', role: 'optional',
      origin: 'aur-reference', upstreamUrl: 'https://example.org/demo.tar.xz', sourceKind: 'archive', description: 'Test source admission', license: 'MIT', ownerArea: 'system',
      architectures: ['x86_64', 'aarch64'], artifactArchitecture: 'native', portableOutputs: ['demo-docs'], architectureExceptions: [], rebuildOn: [],
      sourceReference: { url: 'https://github.com/example/recipes', commit } }, null, 'Local test source admission.');

    await approveCatalogPackage(env.DB, actor, 'demo', policy.revision, policy.manifestSha256, 'area', 'Local source review.');
    await expect(requestRecipeInspection(env, actor, ref.sha256, image.id, 'Inspect admitted source.')).rejects.toThrow('admission');
    await approveCatalogPackage(env.DB, { id: 'github:2', role: 'security', areas: ['system'] }, 'demo', policy.revision, policy.manifestSha256, 'security', 'Local security source review.');
    const queued = await requestRecipeInspection(env, actor, ref.sha256, image.id, 'Inspect admitted source.');
    expect(await requestRecipeInspection(env, actor, ref.sha256, image.id, 'Identical retry.')).toEqual(queued);
    const keys = generateKeyPairSync('ed25519');
    const publicKey = Buffer.from(keys.publicKey.export({ type: 'spki', format: 'der' }).subarray(-32)).toString('base64');
    db.prepare("INSERT INTO workers(id,name,architecture,public_key,status,enrolled_at,accepting_jobs) VALUES('inspection-worker','Inspection test','x86_64',?,'active',?,1)").bind(publicKey, Math.floor(Date.now() / 1000)).run();
    const worker = db.prepare("SELECT * FROM workers WHERE id='inspection-worker'").first<Worker>()!;
    const workerMetadata: WorkerMetadata = { version: 'test', runtime: 'podman', capabilities: ['recipe-inspection-v1'] };
    expect(await claimRecipeInspection(env.DB, worker, { ...workerMetadata, capabilities: [] })).toBeNull();
    const first = (await claimRecipeInspection(env.DB, worker, workerMetadata))!;
    expect(first).toMatchObject({ kind: 'recipe-inspection', id: queued.id, recipeCapture: ref, attempt: 1 });
    expect((await listRecipeInspections(env.DB, ref.sha256))[0]).not.toHaveProperty('lease_token');
    const leased = await requireRecipeInspectionLease(env.DB, worker, first.id, first.leaseToken);
    const recipeFile = manifest.files.find((file) => file.path === 'PKGBUILD')!;
    expect((await recipeInspectionObject(env.DB, leased, recipeFile.object.sha256)).size).toBe(recipeFile.object.size);
    const outside = await retainInputBytes(env, actor, new TextEncoder().encode('outside the leased recipe'));
    await expect(recipeInspectionObject(env.DB, leased, outside.sha256)).rejects.toMatchObject({ status: 403 });

    const requestInput = async (digest: string, token: string) => {
      const path = `/api/worker/inspections/${first.id}/inputs/${digest}`;
      const body = JSON.stringify({ leaseToken: token }), timestamp = String(Math.floor(Date.now() / 1000)), nonce = crypto.randomUUID().replaceAll('-', '');
      const signature = Buffer.from(sign(null, Buffer.from(`POST\n${path}\n${timestamp}\n${nonce}\n${await sha256(body)}`), keys.privateKey)).toString('base64');

      return inspectionInput({ params: { id: first.id, digest }, platform: { env }, url: new URL('https://example.org' + path),
        request: new Request('https://example.org' + path, { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-OPR-Worker': worker.id, 'X-OPR-Timestamp': timestamp, 'X-OPR-Nonce': nonce, 'X-OPR-Signature': signature }, body }) } as unknown as Parameters<typeof inspectionInput>[0]);
    };

    expect(new Uint8Array(await (await requestInput(recipeFile.object.sha256, first.leaseToken)).arrayBuffer())).toEqual(await read(recipeFile.object));
    await expect(requestInput(outside.sha256, first.leaseToken)).rejects.toMatchObject({ status: 403 });

    db.exec("DELETE FROM team_memberships WHERE github_id='2'");
    db.exec("INSERT INTO team_memberships VALUES('2','security')");
    await expect(requireRecipeInspectionLease(env.DB, worker, first.id, first.leaseToken)).rejects.toThrow('unavailable');
    await requestRecipeInspection(env, actor, ref.sha256, image.id, 'Retry after source authority restored.');
    const second = (await claimRecipeInspection(env.DB, worker, workerMetadata))!;
    expect(second.attempt).toBe(2); expect(second.leaseToken).not.toBe(first.leaseToken);
    await expect(requestInput(recipeFile.object.sha256, first.leaseToken)).rejects.toMatchObject({ status: 409 });

    const report = { schemaVersion: 1, kind: 'recipe-inspection', jobId: second.id, attempt: second.attempt, capture: ref, architecture: 'x86_64', imageRef,
      host: { architecture: 'x86_64', kernel: 'test-only', cpuInfoSha256: 'e'.repeat(64), cpuModel: 'Protocol fixture', runtime: 'podman', runtimeVersion: 'test', goVersion: 'test' },
      sandbox: { network: 'disabled', readOnly: true, user: '65534:65534' }, startedAt: new Date().toISOString(), finishedAt: new Date().toISOString(),
      srcinfo: metadata, srcinfoSha256: await sha256(metadata), log: '', error: null };

    const completion = (value = report) => { const report = JSON.stringify(value);

 return { leaseToken: second.leaseToken, report, signature: Buffer.from(sign(null, Buffer.from(report), keys.privateKey)).toString('base64') }; };

    await expect(completeRecipeInspection(env.DB, worker, second.id, completion({ ...report, imageRef: `registry.example.org/changed@sha256:${'e'.repeat(64)}` }))).rejects.toThrow('scope');
    await expect(completeRecipeInspection(env.DB, worker, second.id, { ...completion(), signature: Buffer.alloc(64).toString('base64') })).rejects.toThrow('signature');
    expect(await completeRecipeInspection(env.DB, worker, second.id, completion())).toEqual({ status: 'succeeded' });
    expect(await completeRecipeInspection(env.DB, worker, second.id, completion())).toEqual({ status: 'succeeded' });
    expect((await listRecipeInspections(env.DB, ref.sha256))[0]).toMatchObject({ current: 1, status: 'succeeded' });

    const repairRun = await startFactoryRun(env.DB, { id: 'repair-run', targetKind: 'preserved', targetId: 'demo', unitKey: 'demo', policy: {}, createdBy: actor.id });
    const firstRepairAttempt = await reserveFactoryAttempt(env.DB, { runId: repairRun.id, reservationKey: 'repair:1', candidateSha256: 'a'.repeat(64), inputSha256: 'b'.repeat(64), architecture: 'x86_64', policy: {} });
    await finishFactoryAttempt(env.DB, repairRun.id, firstRepairAttempt.attempt, firstRepairAttempt.leaseToken, { status: 'failed', failureKind: 'build', failure: { message: 'native build failed' } });
    const repairOverride = await retainInputBytes(env, actor, new TextEncoder().encode("pkgname=demo\npkgver=1.4\npkgrel=4\narch=('x86_64')\nsource=()\n"));
    const repairInspection = await requestFactoryRecipeInspection(env, 'repair-run', 2, ref.sha256, image.id, repairOverride, 'Inspect automatic preserved successor.');
    expect(await claimRecipeInspection(env.DB, worker, workerMetadata)).toBeNull();
    const overrideMetadata: WorkerMetadata = { ...workerMetadata, capabilities: ['recipe-inspection-v1', 'recipe-inspection-override-v1'] };
    const overrideLease = (await claimRecipeInspection(env.DB, worker, overrideMetadata))!;
    expect(overrideLease).toMatchObject({ id: repairInspection.id, recipeOverride: { sha256: repairOverride.sha256, size: repairOverride.size }, factoryRunId: 'repair-run', factoryAttempt: 2 });
    expect((await recipeInspectionObject(env.DB, await requireRecipeInspectionLease(env.DB, worker, overrideLease.id, overrideLease.leaseToken), repairOverride.sha256)).size).toBe(repairOverride.size);
    const overrideReport = JSON.stringify({ ...report, jobId: overrideLease.id, attempt: overrideLease.attempt, recipeOverride: repairOverride });
    await expect(completeRecipeInspection(env.DB, worker, overrideLease.id, { leaseToken: overrideLease.leaseToken, report: overrideReport, signature: Buffer.from(sign(null, Buffer.from(overrideReport), keys.privateKey)).toString('base64') })).resolves.toEqual({ status: 'succeeded' });
    const secondRepairAttempt = await reserveFactoryAttempt(env.DB, { runId: 'repair-run', reservationKey: 'repair:2', candidateSha256: 'c'.repeat(64), inputSha256: 'd'.repeat(64), architecture: 'x86_64', policy: {} });
    expect(secondRepairAttempt.attempt).toBe(2);

    await startFactoryRun(env.DB, { id: 'first-inspection-run', targetKind: 'preserved', targetId: 'demo', unitKey: 'first-inspection', policy: {}, createdBy: actor.id });
    const firstInspection = await requestFactoryRecipeInspection(env, 'first-inspection-run', 1, ref.sha256, image.id, repairOverride, 'Inspect the first candidate.\nBefore an attempt is reserved.');
    expect(await env.DB.prepare('SELECT reason FROM recipe_inspections WHERE id=?').bind(firstInspection.id).first()).toEqual({ reason: 'Inspect the first candidate. Before an attempt is reserved.' });
    const firstInspectionLease = (await claimRecipeInspection(env.DB, worker, overrideMetadata))!;
    expect(firstInspectionLease).toMatchObject({ id: firstInspection.id, factoryRunId: 'first-inspection-run', factoryAttempt: 1 });
    await stopFactoryRun(env.DB, 'first-inspection-run', 'First-inspection fixture complete.');
    await expect(requireRecipeInspectionLease(env.DB, worker, firstInspection.id, firstInspectionLease.leaseToken)).rejects.toThrow('unavailable');

    expect(await recipeSourcePlan(env, ref.sha256, second.id, second.attempt)).toMatchObject({ capture: ref, architecture: 'x86_64', version: '2:1.4-3.2',
      inspection: { jobId: second.id, attempt: 2, srcinfoSha256: report.srcinfoSha256 }, sources: [{ kind: 'file', name: 'demo.tar.xz', url: 'https://example.org/source.tar.xz', checksums: { sha256: 'a'.repeat(64) } }] });
    await expect(recipeSourcePlan(env, ref.sha256, second.id, 1)).rejects.toThrow('current successful');
    const sourcePlan = await recipeSourcePlan(env, ref.sha256, second.id, second.attempt);
    const sourcePlanRef = await retainInputBytes(env, actor, new TextEncoder().encode(canonicalJson(sourcePlan)));
    const sourceObject = await retainInputBytes(env, actor, new TextEncoder().encode('Source protocol fixture; native makepkg must verify upstream checksums.'));

    const sourceBundle = { schemaVersion: 1, kind: 'recipe-source-bundle', plan: sourcePlanRef,
      sources: [{ kind: 'file', name: 'demo.tar.xz', object: sourceObject, redirects: ['https://example.org/source.tar.xz'] }], caches: [], keys: [] };

    const storeBundle = (value: unknown) => retainInputBytes(env, actor, new TextEncoder().encode(canonicalJson(value)));
    const sourceRef = await storeBundle(sourceBundle);
    expect(await retainRecipeSources(env, actor, ref.sha256, sourceRef, 'Protocol source retention.')).toEqual({ sha256: sourceRef.sha256 });
    expect(await retainRecipeSources(env, actor, ref.sha256, sourceRef, 'Identical retry.')).toEqual({ sha256: sourceRef.sha256 });
    expect(db.prepare('SELECT COUNT(*) AS n FROM current_recipe_source_bundles').first<{ n: number }>()).toEqual({ n: 1 });
    expect(() => db.exec("UPDATE recipe_source_bundles SET reason='changed'")).toThrow('immutable');
    await expect(retainRecipeSources(env, actor, ref.sha256, await storeBundle({ ...sourceBundle, sources: [] }), 'Missing input.')).rejects.toThrow('differ from inspected');
    const alteredPlan = await storeBundle({ ...sourcePlan, version: '9.0-1' });
    await expect(retainRecipeSources(env, actor, ref.sha256, await storeBundle({ ...sourceBundle, plan: alteredPlan }), 'Changed plan.')).rejects.toThrow('differs from current');
    expect(() => parseRecipeSourceBundle({ ...sourceBundle, sources: [...sourceBundle.sources, ...sourceBundle.sources] })).toThrow('repeats');
    expect(() => parseRecipeSourceBundle({ ...sourceBundle, caches: [{ kind: 'go', object: sourceObject, entries: 200001, expandedBytes: 10 }] })).toThrow();
    expect(db.prepare('SELECT COUNT(*) AS n FROM recipe_inspection_results').first<{ n: number }>()).toEqual({ n: 2 });

    for (const table of ['approvals', 'builds']) expect(db.prepare(`SELECT COUNT(*) AS n FROM ${table}`).first<{ n: number }>()).toEqual({ n: 0 });
    await expect(reservePreservedImport(env, actor, ref.sha256, { x86_64: sourceRef }, ['test -f /usr/share/doc/demo/README'], 'Preserve inspected fixture.')).rejects.toThrow('every admitted catalog target');
    const armImage = await registerBuildImage(env, { id: 'github:3', role: 'admin', areas: ['system'] }, { label: 'ARM protocol fixture', image_ref: imageRef.replace('d'.repeat(64), 'e'.repeat(64)), architecture: 'aarch64', mirror: 'custom' });
    await setBuildImageEnabled(env, { id: 'github:3', role: 'admin', areas: ['system'] }, armImage.id, true);
    const armQueued = await requestRecipeInspection(env, actor, ref.sha256, armImage.id, 'Native ARM protocol fixture.');
    const armKeys = generateKeyPairSync('ed25519');
    const armPublicKey = Buffer.from(armKeys.publicKey.export({ type: 'spki', format: 'der' }).subarray(-32)).toString('base64');
    db.prepare("INSERT INTO workers(id,name,architecture,public_key,status,enrolled_at,accepting_jobs) VALUES('inspection-arm','ARM protocol fixture','aarch64',?,'active',?,1)").bind(armPublicKey, Math.floor(Date.now() / 1000)).run();
    const armWorker = db.prepare("SELECT * FROM workers WHERE id='inspection-arm'").first<Worker>()!;
    const armLease = (await claimRecipeInspection(env.DB, armWorker, workerMetadata))!;

    const armReport = JSON.stringify({ ...report, jobId: armQueued.id, attempt: armLease.attempt, architecture: 'aarch64', imageRef: armLease.imageRef,
      host: { ...report.host, architecture: 'aarch64' }, srcinfo: metadata.replace('makedepends = cc', 'makedepends = cc\n\tmakedepends_aarch64 = arm-tool') });

    const armReportValue = JSON.parse(armReport); armReportValue.srcinfoSha256 = await sha256(armReportValue.srcinfo);
    const armSigned = JSON.stringify(armReportValue);
    await completeRecipeInspection(env.DB, armWorker, armLease.id, { leaseToken: armLease.leaseToken, report: armSigned, signature: Buffer.from(sign(null, Buffer.from(armSigned), armKeys.privateKey)).toString('base64') });
    const armPlan = await recipeSourcePlan(env, ref.sha256, armLease.id, armLease.attempt);
    const armRef = await storeBundle({ ...sourceBundle, plan: await storeBundle(armPlan) });
    await retainRecipeSources(env, actor, ref.sha256, armRef, 'Retain ARM protocol source bundle.');
    const sources = { x86_64: sourceRef, aarch64: armRef }, commands = ['test -f /usr/share/doc/demo/README'];
    const imported = await reservePreservedImport(env, actor, ref.sha256, sources, commands, 'Preserve inspected fixture.');
    expect(await reservePreservedImport(env, actor, ref.sha256, sources, commands, 'Preserve inspected fixture.')).toEqual(imported);
    const draft = JSON.parse(imported.draft_json) as FactoryRevisionDraft;
    expect(draft.revision.recipe).toBe(readFileSync(join(repo, 'recipe/PKGBUILD'), 'utf8'));
    expect(draft.revision.sources_json).toBe('[]');
    expect(reviewedPackageVersion(draft.revision)).toBe('2:1.4-3.2');
    expect(draft.revision.source_date_epoch).toBe(Number(git('show', '-s', '--format=%ct', commit)));
    expect(JSON.parse(imported.evidence_json).dependencies).toEqual({ x86_64: { runtime: ['demo-docs=2:1.4-3.2', 'glibc'], build: ['cc'] }, aarch64: { runtime: ['demo-docs=2:1.4-3.2', 'glibc'], build: ['arm-tool', 'cc'] } });
    const treeFiles = await revisionRecipeFiles(env, draft), rootPath = 'packages/omapkg/demo/';
    expect(treeFiles).toHaveLength(manifest.files.length + 3);

    for (const file of manifest.files) {
      const retainedFile = treeFiles.find((item) => item.path === rootPath + file.path)!;
      expect(retainedFile.mode).toBe(file.mode);
      expect(await sha256(retainedFile.bytes)).toBe(file.object.sha256);
    }

    expect(treeFiles.filter((file) => file.path.startsWith(`${rootPath}.opr-review-${draft.revision.id}/`))).toHaveLength(3);
    await expect(startFactory(env as Env, actor, imported.request_id, 'Must not invoke a model.')).rejects.toThrow('cannot be regenerated');
    expect(() => db.prepare('UPDATE requests SET factory_run_id=? WHERE id=?').bind('another-generation', imported.request_id).run()).toThrow('different factory generation');
    const previousFetch = globalThis.fetch;
    let failUpload = true, head = '1'.repeat(40), prCalls = 0, fetchCalls = 0;
    globalThis.fetch = (async (input, init) => {
      fetchCalls++;
      const path = new URL(String(input)).pathname, body = init?.body ? JSON.parse(String(init.body)) : null;

      if (path === '/repos/example/recipes') return Response.json({ default_branch: 'main' });

      if (path.includes('/git/ref/heads/')) return Response.json({ object: { sha: head } });

      if (path.endsWith(`/git/commits/${head}`)) return Response.json({ tree: { sha: head === '1'.repeat(40) ? '2'.repeat(40) : '3'.repeat(40) } });

      if (path.endsWith('/git/blobs')) {
        if (failUpload) return new Response('upload unavailable', { status: 503 });
        const bytes = Buffer.from(body.content, 'base64');

        return Response.json({ sha: createHash('sha1').update(`blob ${bytes.length}\0`).update(bytes).digest('hex') }, { status: 201 });
      }

      if (path.endsWith('/git/trees')) return Response.json({ sha: '3'.repeat(40) }, { status: 201 });

      if (path.endsWith('/git/commits')) return Response.json({ sha: '4'.repeat(40) }, { status: 201 });

      if (path.includes('/git/refs/heads/')) { head = body.sha;

 return Response.json({ object: { sha: head } }); }

      if (path.endsWith('/pulls') && init?.method !== 'POST') return Response.json([]);

      if (path.endsWith('/pulls')) { prCalls++;

 return Response.json({ html_url: 'https://github.com/example/recipes/pull/1', head: { sha: head } }, { status: 201 }); }

      throw new Error(`Unexpected fixture Git path ${path}`);
    }) as typeof fetch;

    try {
      const gitEnv = { ...env, GITHUB_REPO_TOKEN: 'github_pat_test' };
      await expect(resumePreservedImport(gitEnv, actor, ref.sha256, imported.id)).rejects.toMatchObject({ status: 503 });
      expect(db.prepare('SELECT status FROM requests WHERE id=?').bind(imported.request_id).first<{ status: string }>()).toEqual({ status: 'generating' });
      expect(db.prepare('SELECT COUNT(*) AS n FROM revisions').first<{ n: number }>()).toEqual({ n: 0 });
      failUpload = false;
      const resumed = await resumePreservedImport(gitEnv, actor, ref.sha256, imported.id);
      expect(resumed).toEqual({ requestId: imported.request_id, revisionId: imported.revision_id, prUrl: 'https://github.com/example/recipes/pull/1' });
      const recorded = db.prepare('SELECT * FROM revisions WHERE id=?').bind(imported.revision_id).first<FactoryRevisionDraft['revision']>()!;
      await validateRevision(recorded);
      const calls = fetchCalls;
      expect(await resumePreservedImport(gitEnv, actor, ref.sha256, imported.id)).toEqual(resumed);
      expect(fetchCalls).toBe(calls); expect(prCalls).toBe(1);
      expect(db.prepare('SELECT COUNT(*) AS n FROM approvals').first<{ n: number }>()).toEqual({ n: 0 });
      expect(db.prepare('SELECT COUNT(*) AS n FROM builds').first<{ n: number }>()).toEqual({ n: 0 });
    } finally { globalThis.fetch = previousFetch; }

    await checkPreservedWorker(db, env, (await env.DB.prepare('SELECT * FROM revisions WHERE id=?').bind(draft.revision.id).first<FactoryRevisionDraft['revision']>())!);
    const replacement = await reservePreservedImport(env, actor, ref.sha256, sources, commands, 'New review after rejecting the old import.');
    expect(replacement.request_id).not.toBe(imported.request_id);
    await cancelPreservedImport(env.DB, actor, ref.sha256, replacement.id, 'Cancel unused replacement draft.');
    await expect(resumePreservedImport(env, actor, ref.sha256, replacement.id)).rejects.toThrow('authority changed');
    expect(readdirSync(root)).not.toContain('MUST_NOT_EXECUTE');
    db.exec("UPDATE workers SET status='revoked' WHERE id='inspection-worker'");
    expect(db.prepare('SELECT COUNT(*) AS n FROM current_recipe_source_bundles').first<{ n: number }>()).toEqual({ n: 1 });
    await expect(assertPreservedImportCurrent(env.DB, draft.revision)).rejects.toThrow('authority changed');
    await expect(retainRecipeSources(env, actor, ref.sha256, sourceRef, 'Revoked inspection.')).rejects.toThrow('current successful');
    await expect(recipeSourcePlan(env, ref.sha256, second.id, second.attempt)).rejects.toThrow('current successful');
    expect((await listRecipeInspections(env.DB, ref.sha256)).find((item) => item.id === second.id)!.current).toBe(0);
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
