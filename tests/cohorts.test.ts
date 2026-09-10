import { expect, test } from 'bun:test';
import { readFileSync, readdirSync } from 'node:fs';
import { canonicalJson } from '../src/lib/canonical-json';
import type { CatalogManifest } from '../src/lib/distribution';
import type { Revision, Worker } from '../src/lib/model';
import { approveCatalogPackage, proposeCatalogPackage } from '../src/lib/server/catalog-ownership';
import { approveCohortChangelog, cohortChangePage, cohortChangeStream, generateCohortFacts, saveCohortChangelog } from '../src/lib/server/cohort-changelogs';
import { evaluateCohortGate } from '../src/lib/server/cohort-gates';
import { changeCohortPhase } from '../src/lib/server/cohort-phases';
import { getCohort, listCohorts, proposeCohort, releaseAuthority, type CohortScopeInput } from '../src/lib/server/cohorts';
import { appendCohortScope, beginCohortScope, sealCohortScope } from '../src/lib/server/cohort-scope-uploads';
import { aggregateCohortGate, checkCohortPage, cohortEventPageProofs, currentCohortPage } from '../src/lib/server/cohort-gate-pages';
import { cohortMembers, cohortRecipeMember } from '../src/lib/server/cohort-members';
import { cohortOutputContract } from '../src/lib/server/build-outputs';
import { GET as getScopeApi, POST as postScopeApi } from '../src/routes/api/maintain/cohorts/+server';
import { GET as exportChangelog } from '../src/routes/maintain/cohorts/[id]/changelog/+server';
import { GET as exportScope } from '../src/routes/maintain/cohorts/[id]/scope/+server';
import { sha256 } from '../src/lib/server/db';
import { manifestDigest } from '../src/lib/server/policy';
import { claimJob } from '../src/lib/server/workers';
import { enqueuePublication } from '../services/pipeline/publication-dispatch';
import { env } from './release-fixtures';
import { asD1, TestD1 } from './d1';

const schema = readdirSync(new URL('../migrations', import.meta.url)).filter((file) => file.endsWith('.sql')).sort()
  .map((file) => readFileSync(new URL(`../migrations/${file}`, import.meta.url), 'utf8')).join('\n');

const owner = { id: 'github:1', role: 'maintainer' as const, areas: ['system'] };

const security = { id: 'github:2', role: 'security' as const, areas: ['system'] };

const catalog = (pkgbase = 'example'): CatalogManifest => ({ schemaVersion: 1, pkgbase, outputs: [pkgbase], collection: 'core', lane: 'system',
  role: 'base-system', origin: 'arch', upstreamUrl: `https://example.org/${pkgbase}.git`, sourceKind: 'git', description: 'Example library',
  license: 'MIT', ownerArea: 'system', architectures: ['x86_64', 'aarch64'], artifactArchitecture: 'native', architectureExceptions: [], sourceReference: null, rebuildOn: [] });

const scope = (pkgbase = 'example', recipeRevisionId: string | null = null): CohortScopeInput => ({ title: 'Example library transition', lane: 'system', systemVersion: '4.0.3-rc2',
  parentSnapshot: null, compatibleSystems: [], members: [{ pkgbase, catalogRevision: 1, recipeRevisionId, cause: 'abi', reason: 'Library SONAME changed; consumers rebuild together.' }] });

function database() {
  const db = new TestD1(schema);
  db.exec("INSERT INTO team_memberships VALUES('1','system'),('2','security'),('3','release'),('4','admin');");

  return db;
}

async function admit(db: TestD1, pkgbase = 'example') {
  const result = await proposeCatalogPackage(asD1(db), owner, catalog(pkgbase), null, 'Import reviewed upstream identity.');
  await approveCatalogPackage(asD1(db), owner, pkgbase, 1, result.manifestSha256, 'area', 'Owner reviewed.');
  await approveCatalogPackage(asD1(db), security, pkgbase, 1, result.manifestSha256, 'security', 'Source reviewed.');

  return result;
}

async function recipe(db: TestD1, pkgbase = 'example') {
  const policy = catalog(pkgbase);
  db.prepare(`INSERT INTO requests(id,name,upstream_url,source_kind,area,requested_by,status,created_at,updated_at,description,declared_license)
    VALUES(?,?,?,?,?,?,'review',1,1,?,?)`).bind(`request-${pkgbase}`, pkgbase, policy.upstreamUrl, 'git', 'system', owner.id, 'Example library', 'MIT').run();

  const revision: Revision = { id: `recipe-${pkgbase}`, request_id: `request-${pkgbase}`, version: '2.0', pkgrel: 1,
    recipe: `pkgname=${pkgbase}\npkgver=2.0\npkgrel=1\n`, recipe_sha256: '', manifest_sha256: '',
    sources_json: JSON.stringify([{ name: 'source.tar', url: 'https://example.org/source.tar', sha256: 'a'.repeat(64) }]), dependencies_json: '[]', make_dependencies_json: '[]',
    smoke_commands_json: '[]', architectures_json: '["x86_64","aarch64"]', build_images_json: '{}',
    source_date_epoch: 1, image_digest: `registry.example/builder@sha256:${'b'.repeat(64)}`, license: 'MIT', surface: 'binary',
    explanation: '', sbom_json: '{}', lint_json: '{"passed":true}', upstream_commit: null, pr_url: 'https://github.com/example/recipes/pull/1', commit_sha: 'c'.repeat(40), created_at: 1 };

  revision.recipe_sha256 = await sha256(revision.recipe); revision.manifest_sha256 = await manifestDigest(revision);
  const keys = Object.keys(revision);
  db.prepare(`INSERT INTO revisions(${keys.join(',')}) VALUES(${keys.map(() => '?').join(',')})`).bind(...Object.values(revision)).run();

  return revision;
}

const phaseInput = (current: Awaited<ReturnType<typeof getCohort>>, action: 'advance' | 'hold' | 'resume' | 'recheck') => ({
  revision: current.current_revision, sequence: current.event_sequence, manifestSha256: current.manifest_sha256, action, reason: 'Reviewed current evidence and next action.',
});

test('cohort phases derive admission and native gates; history and reviewed narrative stay immutable and idempotent', async () => {
  const db = database(); const d1 = asD1(db); const service = env(db);

  try {
    const proposed = await proposeCatalogPackage(d1, owner, catalog(), null, 'Review new identity.');
    const draft = await proposeCohort(d1, owner, 'library-transition', null, scope(), 'Plan native library transition.');
    expect((await evaluateCohortGate(service, draft)).blockers.map((item) => item.code)).toContain('catalog-review');
    await expect(changeCohortPhase(service, owner, draft.id, phaseInput(draft, 'advance'))).rejects.toThrow('catalog policy');
    await approveCatalogPackage(d1, owner, 'example', 1, proposed.manifestSha256, 'area', 'Area reviewed.');
    await approveCatalogPackage(d1, security, 'example', 1, proposed.manifestSha256, 'security', 'Security reviewed.');
    const advanced = await changeCohortPhase(service, owner, draft.id, phaseInput(draft, 'advance'));
    expect(advanced.event?.phase).toBe('review');
    expect((await changeCohortPhase(service, owner, draft.id, phaseInput(draft, 'advance'))).duplicate).toBe(true);
    let current = await getCohort(d1, draft.id);
    expect((await evaluateCohortGate(service, current)).blockers.some((item) => item.code === 'recipe-missing')).toBe(true);
    const facts = await generateCohortFacts(d1, current);
    expect(facts.baseline.kind).toBe('initial-plan'); expect(facts.state).toBe('planned');
    const factsHash = await sha256(canonicalJson(facts));
    const notes = await saveCohortChangelog(d1, owner, current.id, 1, factsHash, 'Rebuild consumers for the new library.\nNative builds are still required.');
    expect(await sha256(canonicalJson(await generateCohortFacts(d1, await getCohort(d1, current.id))))).toBe(factsHash);
    await approveCohortChangelog(d1, owner, current.id, 1, notes.digest, 'Narrative matches the plan.');
    await approveCohortChangelog(d1, owner, current.id, 1, notes.digest, 'Retry approval.');
    expect(db.prepare('SELECT COUNT(*) AS count FROM cohort_changelog_reviews').first<{ count: number }>()?.count).toBe(1);
    current = await getCohort(d1, current.id);
    const input = phaseInput(current, 'recheck');
    expect((await changeCohortPhase(service, owner, current.id, input)).event?.condition).toBe('blocked');
    current = await getCohort(d1, current.id);
    expect((await changeCohortPhase(service, owner, current.id, phaseInput(current, 'recheck'))).duplicate).toBe(true);
    await expect(approveCohortChangelog(d1, owner, current.id, 1, notes.digest, 'Old facts')).rejects.toThrow('stale');
    await admit(db, 'consumer');
    const expanded = scope(); expanded.members.push(scope('consumer').members[0]);
    const revision2 = await proposeCohort(d1, owner, current.id, 1, expanded, 'Include reverse consumer.');
    expect(revision2.current_revision).toBe(2); expect(revision2.phase).toBe('plan');
    const diff = await generateCohortFacts(d1, revision2);
    expect(diff.baseline.revision).toBe(1);

    if (diff.schemaVersion !== 1) throw new Error('Expected inline cohort diff.');
    expect(diff.changes.find((item) => item.pkgbase === 'consumer')?.kind).toBe('added');
    expect(diff.changes.find((item) => item.pkgbase === 'example')?.kind).toBe('unchanged');
    await expect(proposeCohort(d1, owner, current.id, 1, scope(), 'Stale removal.')).rejects.toThrow('changed');
    expect(() => db.exec("UPDATE cohort_events SET event_json='{}'")).toThrow('append-only');
    expect(() => db.exec('DELETE FROM cohort_revisions')).toThrow('immutable');
    expect(() => db.exec("UPDATE cohort_changelogs SET document_json='{}'")).toThrow('immutable');
    expect(db.prepare('PRAGMA foreign_key_check').all().results).toEqual([]);
  } finally { db.close(); }
});

test('12,000-member scope seals atomically, streams complete changes and advances only after every current page passes', async () => {
  const db = database(); const d1 = asD1(db); const service = env(db);

  try {
    const count = 12000;
    const name = (index: number) => `package-${String(index).padStart(5, '0')}`;

    for (let index = 0; index < count; index++) await admit(db, name(index));
    const bound = await recipe(db, name(count - 1));
    const { members: _, ...metadata } = scope();
    const upload = await beginCohortScope(d1, owner, 'complete-toolchain', null, metadata, count, 'toolchain-proposal');
    const chunk = (offset: number) => Array.from({ length: Math.min(100, count - offset) }, (_, index) => scope(name(offset + index), offset + index === count - 1 ? bound.id : null).members[0]);
    await appendCohortScope(d1, owner, upload.id, 0, chunk(0));
    expect((await appendCohortScope(d1, owner, upload.id, 0, chunk(0))).member_count).toBe(100);
    await expect(sealCohortScope(d1, owner, upload.id, 'Select complete toolchain transition.')).rejects.toThrow('every declared');
    expect(db.prepare("SELECT 1 FROM cohorts WHERE id='complete-toolchain'").first()).toBeNull();
    await expect(appendCohortScope(d1, security, upload.id, 1, chunk(100))).rejects.toThrow('own account');
    await expect(appendCohortScope(d1, owner, upload.id, 2, chunk(100))).rejects.toThrow('next chunk');

    for (let offset = 100; offset < count; offset += 100) await appendCohortScope(d1, owner, upload.id, offset / 100, chunk(offset));
    const sealed = await sealCohortScope(d1, owner, upload.id, 'Select complete toolchain transition.');
    expect(await sealCohortScope(d1, owner, upload.id, 'Retry complete scope.')).toEqual(sealed);
    const current = await getCohort(d1, 'complete-toolchain');
    const manifest = JSON.parse(current.manifest_json);
    expect(manifest.memberCount).toBe(count); expect(manifest.memberChunks).toHaveLength(120); expect(current.manifest_json.length).toBeLessThan(32000);
    expect((await listCohorts(d1, {}))[0].member_count).toBe(count);
    expect((await cohortMembers(d1, current, count - 25)).map((member) => member.pkgbase)).toEqual(Array.from({ length: 25 }, (_, index) => name(count - 25 + index)));
    expect((await cohortRecipeMember(d1, current, bound.id))?.pkgbase).toBe(name(count - 1));
    expect((await cohortOutputContract(d1, { ...bound, pkgrel: bound.pkgrel ?? 1 }, 'aarch64'))?.cohort.manifestSha256).toBe(current.manifest_sha256);
    const nativePage = await evaluateCohortGate(service, { ...current, phase: 'build' }, true, 125);
    expect(nativePage.matrix).toHaveLength(2); expect(new Set(nativePage.matrix.map((row) => row.pkgbase))).toEqual(new Set([name(125)]));
    const facts = await generateCohortFacts(d1, current);
    expect(facts.schemaVersion).toBe(2); expect(facts.changes).toMatchObject({ count, manifestSha256: current.manifest_sha256 });
    expect((await cohortChangePage(d1, current)).next).toBe(name(24));
    let streamed = 0;

    for await (const change of cohortChangeStream(d1, current)) { expect(change.pkgbase).toBe(name(streamed)); streamed++; }

    expect(streamed).toBe(count);
    expect((await aggregateCohortGate(d1, current)).blockers[0].code).toBe('cohort-pages');
    await expect(changeCohortPhase(service, owner, current.id, phaseInput(current, 'advance'))).rejects.toThrow('every page');

    for (let page = 0; page < count / 25; page++) expect((await checkCohortPage(service, owner, current.id, 1, current.manifest_sha256, page)).blockers).toEqual([]);
    const gate = await aggregateCohortGate(d1, current);
    expect(gate.blockers).toEqual([]); expect(gate.pages.checked).toBe(count);
    expect((await currentCohortPage(d1, current, 0))?.report.memberCount).toBe(25);
    await admit(db, 'independent-job');
    const independentRecipe = await recipe(db, 'independent-job');
    await proposeCohort(d1, owner, 'independent-job', null, scope('independent-job', independentRecipe.id), 'Independent build activity.');
    db.prepare("INSERT INTO builds(id,revision_id,architecture,status,created_at) VALUES('independent-build',?,'x86_64','queued',1)").bind(independentRecipe.id).run();
    expect((await aggregateCohortGate(d1, current)).pages.checked).toBe(count);
    await changeCohortPhase(service, owner, current.id, phaseInput(current, 'advance'));
    expect((await getCohort(d1, current.id)).phase).toBe('review');
    const proof = await cohortEventPageProofs(d1, current.id, 2);
    expect(proof.refs).toHaveLength(count / 25);
    expect(await sha256('cohort-page-proofs-v1\n' + proof.refs.map((ref) => canonicalJson(ref) + '\n').join(''))).toBe(proof.selection.reportsSha256);
    await expect(checkCohortPage(service, owner, current.id, 1, current.manifest_sha256, 0, 'plan')).rejects.toThrow('phase');
    db.exec("DELETE FROM team_memberships WHERE github_id='1'");
    expect(() => db.batch(gate.fences as never)).toThrow();
    expect((await aggregateCohortGate(d1, current)).pages.checked).toBe(0);
    expect((await cohortEventPageProofs(d1, current.id, 2)).selection).toEqual(proof.selection);
    expect(() => db.exec("DELETE FROM cohort_revision_chunks")).toThrow('immutable');
    expect(() => db.exec("DELETE FROM cohort_gate_pages")).toThrow('immutable');
    expect(db.prepare('SELECT COUNT(*) AS count FROM distribution_assertions').first<{ count: number }>()?.count).toBe(0);
    expect(() => db.exec('INSERT INTO distribution_assertions(expected,actual) VALUES(1,0)')).toThrow();
    db.exec('INSERT INTO distribution_assertions(expected,actual) VALUES(1,1)');
    expect(db.prepare('SELECT changes() AS count').first<{ count: number }>()?.count).toBe(1);
    expect(db.prepare('PRAGMA foreign_key_check').all().results).toEqual([]);
  } finally { db.close(); }
}, 60000);

test('chunked scope API keeps identities private, rejects stale seals and exports exact historical changes across storage versions', async () => {
  const db = database(); const d1 = asD1(db); const service = env(db);

  try {
    const call = (path: string, actor = owner, body?: unknown) => ({ platform: { env: service }, locals: { actor }, params: { id: 'paged-edit' },
      url: new URL(`https://omapkg.example${path}`), request: new Request(`https://omapkg.example${path}`, body === undefined ? {} : {
        method: 'POST', headers: { Origin: 'https://omapkg.example', 'Content-Type': 'application/json' }, body: JSON.stringify(body),
      }) }) as never;

    expect((await getScopeApi(call('/api/maintain/cohorts', null as never))).status).toBe(401);
    expect((await postScopeApi(call('/api/maintain/cohorts', null as never, { operation: 'begin' }))).status).toBe(401);
    expect((await postScopeApi(call('/api/maintain/cohorts', owner, { operation: 'begin' }))).status).toBe(400);
    await admit(db); await admit(db, 'consumer');
    const first = await proposeCohort(d1, owner, 'paged-edit', null, scope(), 'Initial scope.');
    const { members: _, ...metadata } = scope();
    const request = { operation: 'begin', cohortId: first.id, expectedRevision: 1, metadata, memberCount: 1, proposalId: 'replace-example' };
    const begun = await postScopeApi(call('/api/maintain/cohorts', owner, request)); expect(begun.status).toBe(200);
    const upload = await begun.json() as { id: string };
    expect((await postScopeApi(call('/api/maintain/cohorts', owner, { operation: 'append', uploadId: upload.id, index: 0, members: scope('consumer').members }))).status).toBe(200);
    expect((await getCohort(d1, first.id)).current_revision).toBe(1);
    expect((await postScopeApi(call('/api/maintain/cohorts', owner, { operation: 'seal', uploadId: upload.id, reason: 'Replace affected package.' }))).status).toBe(200);
    const second = await getCohort(d1, first.id); const facts = await generateCohortFacts(d1, second);
    expect(facts.schemaVersion).toBe(2); expect(facts.changes).toMatchObject({ count: 2 });
    expect((await cohortChangePage(d1, second)).changes.map((change) => [change.pkgbase, change.kind])).toEqual([['consumer', 'added'], ['example', 'removed']]);
    const document = await saveCohortChangelog(d1, owner, first.id, 2, await sha256(canonicalJson(facts)), 'Replace example with consumer.');
    await approveCohortChangelog(d1, owner, first.id, 2, document.digest, 'Reviewed both addition and removal.');
    const beforeRetry = await getCohort(d1, first.id);
    const identical = await beginCohortScope(d1, owner, first.id, 2, metadata, 1, 'same-selected-scope');
    await appendCohortScope(d1, owner, identical.id, 0, scope('consumer').members);
    expect((await sealCohortScope(d1, owner, identical.id, 'Repeated scope upload.')).unchanged).toBe(true);
    expect((await getCohort(d1, first.id)).event_sequence).toBe(beforeRetry.event_sequence);
    const scopeDownload = await exportScope(call(`/maintain/cohorts/paged-edit/scope?digest=${second.manifest_sha256}`));
    expect((await scopeDownload.json() as CohortScopeInput).members).toEqual(scope('consumer').members);
    const third = await proposeCohort(d1, owner, first.id, 2, scope(), 'Return to initial scope.');
    expect((await generateCohortFacts(d1, third)).schemaVersion).toBe(2);
    expect((await getScopeApi(call(`/api/maintain/cohorts?cohortId=${first.id}&manifestSha256=${second.manifest_sha256}`))).status).toBe(409);
    const oldChanges = await exportChangelog(call(`/maintain/cohorts/paged-edit/changelog?digest=${document.digest}&format=changes`));
    expect((await oldChanges.json() as { changes: { pkgbase: string; kind: string }[] }).changes.map((change) => [change.pkgbase, change.kind]))
      .toEqual([['consumer', 'added'], ['example', 'removed']]);
    const markdown = await (await exportChangelog(call(`/maintain/cohorts/paged-edit/changelog?digest=${document.digest}&format=markdown`))).text();
    expect(markdown).toContain('| consumer | added |'); expect(markdown).toContain('| example | removed |');
    const stale = await beginCohortScope(d1, owner, first.id, 3, metadata, 1, 'stale-catalog-policy');
    await appendCohortScope(d1, owner, stale.id, 0, scope().members);
    await proposeCatalogPackage(d1, owner, { ...catalog(), description: 'Changed after scope upload.' }, 1, 'Update catalog identity.');
    await expect(sealCohortScope(d1, owner, stale.id, 'Attempt stale scope.')).rejects.toMatchObject({ status: 409 });
    expect((await getCohort(d1, first.id)).current_revision).toBe(3);
    expect(db.prepare('SELECT sealed_revision FROM cohort_scope_uploads WHERE id=?').bind(stale.id).first<{ sealed_revision: number | null }>()?.sealed_revision).toBeNull();
    expect(db.prepare('SELECT COUNT(*) AS count FROM cohort_revisions WHERE cohort_id=?').bind(first.id).first<{ count: number }>()?.count).toBe(3);
  } finally { db.close(); }
});

test('cohort publication cannot fall through per-build path and native omissions never qualify', async () => {
  const db = database(); const d1 = asD1(db); const service = env(db);

  try {
    await admit(db); const revision = await recipe(db);
    const cohort = await proposeCohort(d1, owner, 'native-transition', null, scope('example', revision.id), 'Build both native targets.');
    expect(db.prepare('SELECT catalog_pkgbase,catalog_revision FROM requests WHERE id=?').bind(revision.request_id)
      .first<{ catalog_pkgbase: string; catalog_revision: number }>()).toEqual({ catalog_pkgbase: 'example', catalog_revision: 1 });
    db.prepare("INSERT INTO builds(id,revision_id,architecture,status,created_at) VALUES('cohort-build',?,'x86_64','queued',1)").bind(revision.id).run();
    db.exec("UPDATE requests SET status='queued' WHERE id='request-example'");
    db.prepare("INSERT INTO workers(id,name,architecture,public_key,status,enrolled_at) VALUES('phase-worker','phase worker','x86_64',?,'active',1)")
      .bind(btoa('x'.repeat(32))).run();
    const worker = db.prepare("SELECT * FROM workers WHERE id='phase-worker'").first<Worker>()!;
    expect(await claimJob(d1, worker)).toBeNull();
    await changeCohortPhase(service, owner, cohort.id, phaseInput(cohort, 'advance'));
    let current = await getCohort(d1, cohort.id);
    expect((await evaluateCohortGate(service, current)).blockers.map((item) => item.code)).toContain('recipe-review');

    for (const [kind, actor] of [['area', owner.id], ['security', security.id]]) db.prepare('INSERT INTO approvals(id,revision_id,actor,kind,manifest_sha256,created_at) VALUES(?,?,?,?,?,1)')
      .bind(`approval-${kind}`, revision.id, actor, kind, revision.manifest_sha256).run();
    await changeCohortPhase(service, owner, cohort.id, phaseInput(current, 'advance'));
    current = await getCohort(d1, cohort.id);
    expect(await claimJob(d1, worker)).toBeNull();
    const leased = await claimJob(d1, worker, { version: 'test-v2', runtime: 'podman', capabilities: ['multi-output-v2', 'single-build-reproducibility-v1'] });
    expect(leased?.id).toBe('cohort-build');
    expect(leased?.outputContract?.outputs).toEqual([{ name: 'example', fullVersion: '2.0-1', architecture: 'x86_64' }]);
    await changeCohortPhase(service, owner, cohort.id, phaseInput(current, 'hold'));
    db.exec("UPDATE builds SET lease_expires_at=1 WHERE id='cohort-build'");
    expect(await claimJob(d1, worker)).toBeNull();
    current = await getCohort(d1, cohort.id);
    await changeCohortPhase(service, owner, cohort.id, phaseInput(current, 'resume'));
    current = await getCohort(d1, cohort.id);
    const gate = await evaluateCohortGate(service, current);
    expect(gate.blockers.filter((item) => item.code === 'native-build').map((item) => item.architecture).sort()).toEqual(['aarch64', 'x86_64']);
    db.exec("UPDATE builds SET status='succeeded',finished_at=unixepoch() WHERE id='cohort-build'");
    expect(await enqueuePublication(service, 'cohort-build')).toEqual({ id: 'cohort-native-transition', dispatched: false });
    expect(db.prepare('SELECT COUNT(*) AS count FROM publication_jobs').first<{ count: number }>()?.count).toBe(0);
    expect(() => db.prepare(`INSERT INTO releases(id,build_id,name,version,architecture,surface,channel,recipe_key,sbom_key,provenance_key,published_at)
      VALUES('leak','cohort-build','example','2.0-1','x86_64','binary','dev','recipe','sbom','provenance',1)`).run()).toThrow('coordinated distribution');
    await expect(changeCohortPhase(service, owner, cohort.id, phaseInput(current, 'advance'))).rejects.toThrow('native');
    await expect(proposeCohort(d1, owner, 'other-cohort', null, scope('example', revision.id), 'Reuse managed recipe.')).rejects.toMatchObject({ status: 409 });
    db.exec("DELETE FROM team_memberships WHERE github_id='2'");
    expect((await evaluateCohortGate(service, current)).blockers.some((item) => item.code === 'recipe-authority')).toBe(true);
  } finally { db.close(); }
});

test('release authority and release lane are explicit, independent of administrator or recipe access', async () => {
  const db = database(); const d1 = asD1(db);

  try {
    await admit(db);
    await expect(releaseAuthority(d1, { id: 'github:4', role: 'admin', areas: ['system'] })).rejects.toThrow('Explicit release');
    expect((await releaseAuthority(d1, { id: 'github:3', role: 'maintainer', areas: [] })).id).toBe('github:3');
    await expect(proposeCohort(d1, owner, 'wrong-lane', null, { ...scope(), lane: 'opr', systemVersion: null }, 'Independent core update.')).rejects.toThrow('versioned system');
    await expect(proposeCohort(d1, { id: 'workflow:agent', role: 'admin', areas: [] }, 'agent-approval', null, scope(), 'Agent attempts approval.')).rejects.toThrow('human');
    await expect(proposeCohort(d1, owner, 'duplicate-member', null, { ...scope(), members: [...scope().members, ...scope().members] }, 'Duplicate member.')).rejects.toThrow('cannot repeat');
  } finally { db.close(); }
});

test('owned cutover disables legacy publication and channel writers while retaining historical records', async () => {
  const db = database();

  try {
    const revision = await recipe(db);
    db.prepare("INSERT INTO builds(id,revision_id,architecture,status,created_at) VALUES('legacy-build',?,'x86_64','succeeded',1)").bind(revision.id).run();

    const insertRelease = (id: string) => db.prepare(`INSERT INTO releases(id,build_id,name,version,architecture,surface,channel,recipe_key,sbom_key,provenance_key,artifact_key,signature_key,published_at)
      VALUES(?,'legacy-build','example','2.0-1','x86_64','binary','dev','recipe','sbom','provenance','artifact','signature',1)`).bind(id).run();

    insertRelease('historical');
    db.exec("INSERT INTO repository_snapshots(id,architecture,channel,db_key,db_signature_key,created_at) VALUES('legacy-snapshot','x86_64','dev','db','sig',1)");
    db.exec("UPDATE distribution_control SET mode='owned',revision=revision+1 WHERE id=1");
    expect(() => insertRelease('new-legacy')).toThrow('coordinated distribution');
    expect(() => db.exec("UPDATE releases SET channel='stable' WHERE id='historical'")).toThrow('disabled in owned mode');
    expect(() => db.exec("UPDATE repository_snapshots SET active=0")).toThrow('disabled in owned mode');
    expect(db.prepare("SELECT channel FROM releases WHERE id='historical'").first<{ channel: string }>()?.channel).toBe('dev');
  } finally { db.close(); }
});
