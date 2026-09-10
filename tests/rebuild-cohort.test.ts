import { expect, test } from 'bun:test';
import { readFileSync, readdirSync } from 'node:fs';
import { manifestDigest } from '../src/lib/server/policy';
import { approveCatalogPackage, proposeCatalogPackage } from '../src/lib/server/catalog-ownership';
import { proposeCohort } from '../src/lib/server/cohorts';
import { createRebuildCohortDraft, parseRebuildScopeReport, previewRebuildCohort, rebuildCoverage } from '../src/lib/server/rebuild-cohort';
import { sha256 } from '../src/lib/server/db';
import type { CatalogManifest } from '../src/lib/distribution';
import { asD1, TestD1 } from './d1';

const fullSchema = readdirSync(new URL('../migrations', import.meta.url)).filter((file) => file.endsWith('.sql')).sort()
  .map((file) => readFileSync(new URL(`../migrations/${file}`, import.meta.url), 'utf8')).join('\n');

const plan = (architecture: 'x86_64' | 'aarch64') => ({ architecture, missingSeeds: [], unappliedRules: [], sourceGaps: [], plan: {
  architecture, seeds: ['library'], members: [{ pkgbase: 'library', changed: true, removed: false, affectedBy: [] }],
  buildGroups: [{ members: ['library'], requiresBootstrapReview: false }], findings: [], unresolvedCandidateRelations: 0, ambiguousCandidateRelations: 0,
} });
const report = () => ({ schemaVersion: 1, kind: 'rebuild-scope-proposal', baseline: 'a'.repeat(64), candidate: 'b'.repeat(64),
  requiredArchitectures: ['x86_64', 'aarch64'], repositoryOrder: [], shadowed: [], rules: [], plans: [plan('x86_64'), plan('aarch64')], limits: [],
});

test('rebuild report parser preserves target selection and planner blockers', () => {
  expect(parseRebuildScopeReport(report()).plans).toHaveLength(2);
  expect(parseRebuildScopeReport({ ...report(), requiredArchitectures: ['x86_64'], plans: [plan('x86_64')] }).plans).toHaveLength(1);
  expect(() => parseRebuildScopeReport({ ...report(), plans: [{ ...plan('x86_64'), plan: { ...plan('x86_64').plan, unresolvedCandidateRelations: -1 } }, plan('aarch64')] })).toThrow('unresolved relation');
});

test('operations coverage reports queue age and scoped target parity, with check coverage unknown when empty', async () => {
  const db = new TestD1(`
    CREATE TABLE builds(revision_id TEXT,status TEXT,architecture TEXT,created_at INTEGER);
    CREATE TABLE cohorts(id TEXT,current_revision INTEGER);
    CREATE TABLE cohort_members(cohort_id TEXT,revision INTEGER,pkgbase TEXT,catalog_revision INTEGER,recipe_revision_id TEXT);
    CREATE TABLE catalog_revisions(pkgbase TEXT,revision INTEGER,manifest_json TEXT);
    CREATE TABLE cohort_checks(kind TEXT,architecture TEXT);
    CREATE TABLE catalog_packages(current_revision INTEGER,admitted_revision INTEGER);
  `);
  db.exec("INSERT INTO builds VALUES('recipe','queued','x86_64',90)");
  db.exec("INSERT INTO cohorts VALUES('cohort',1)");
  db.exec("INSERT INTO cohort_members VALUES('cohort',1,'library',1,'recipe')");
  db.exec("INSERT INTO catalog_revisions VALUES('library',1,'{\"architectures\":[\"x86_64\",\"aarch64\"]}')");
  db.exec('INSERT INTO catalog_packages VALUES(1,1)');
  const result = await rebuildCoverage(asD1(db), 100);
  expect(result.queue).toContainEqual({ architecture: 'x86_64', queued: 1, oldestAgeSeconds: 10 });
  expect(result.targetParity).toContainEqual({ architecture: 'x86_64', expected: 1, succeeded: 0, measured: true });
  expect(result.targetParity).toContainEqual({ architecture: 'aarch64', expected: 1, succeeded: 0, measured: true });
  expect(result.checks).toEqual({ measured: false, records: 0, byKind: [] });
  expect(result.catalog).toEqual({ total: 1, admitted: 1 });
  db.close();
});

test('scope preview maps only current admitted policy and reviewed recipe, then creates no builds', async () => {
  const db = new TestD1(fullSchema); const d1 = asD1(db); const owner = { id: 'github:1', role: 'maintainer' as const, areas: ['system'] };
  db.exec("INSERT INTO team_memberships VALUES('1','system'),('2','security')");
  const policy: CatalogManifest = { schemaVersion: 1, pkgbase: 'library', outputs: ['library'], collection: 'core', lane: 'system', role: 'base-system', origin: 'arch',
    upstreamUrl: 'https://example.org/library.git', sourceKind: 'git', description: 'Library', license: 'MIT', ownerArea: 'system', architectures: ['aarch64', 'x86_64'],
    artifactArchitecture: 'native', architectureExceptions: [], sourceReference: null, rebuildOn: [] };
  const catalog = await proposeCatalogPackage(d1, owner, policy, null, 'Admit current library policy.');
  await approveCatalogPackage(d1, owner, 'library', 1, catalog.manifestSha256, 'area', 'Area review.');
  await approveCatalogPackage(d1, { id: 'github:2', role: 'security', areas: ['system'] }, 'library', 1, catalog.manifestSha256, 'security', 'Security review.');
  db.prepare(`INSERT INTO requests(id,name,upstream_url,source_kind,area,requested_by,status,created_at,updated_at)
    VALUES('request-library','library',?,'git','system','github:1','review',1,1)`).bind(policy.upstreamUrl).run();
  const recipe = 'pkgname=library\npkgver=2.0\npkgrel=1\n';
  const revision = { id: 'recipe-library', request_id: 'request-library', version: '2.0', recipe, recipe_sha256: await sha256(recipe), manifest_sha256: '',
    sources_json: '[]', dependencies_json: '[]', smoke_commands_json: '[]', architectures_json: '["aarch64","x86_64"]', source_date_epoch: 1,
    image_digest: `registry.example/builder@sha256:${'b'.repeat(64)}`, license: 'MIT', surface: 'binary' as const, explanation: 'test', sbom_json: '{}', lint_json: '{}', upstream_commit: null,
    pr_url: null, commit_sha: 'c'.repeat(40), created_at: 1 };
  revision.manifest_sha256 = await manifestDigest(revision);
  db.prepare(`INSERT INTO revisions(${Object.keys(revision).join(',')}) VALUES(${Object.keys(revision).map(() => '?').join(',')})`).bind(...Object.values(revision)).run();
  db.prepare('INSERT INTO approvals(id,revision_id,actor,kind,manifest_sha256,created_at) VALUES(?,?,?,?,?,1),(?,?,?,?,?,1)')
    .bind('approval-area', revision.id, owner.id, 'area', revision.manifest_sha256, 'approval-security', revision.id, 'github:2', 'security', revision.manifest_sha256).run();
  await proposeCohort(d1, owner, 'library-cohort', null, { title: 'Library rebuild', lane: 'system', systemVersion: '4.0.3-rc2', parentSnapshot: null, compatibleSystems: [],
    members: [{ pkgbase: 'library', catalogRevision: 1, recipeRevisionId: revision.id, cause: 'source-update', reason: 'Current reviewed recipe.' }] }, 'Create current scope.');
  const parsed = parseRebuildScopeReport(report()); const preview = await previewRebuildCohort(d1, 'library-cohort', parsed);
  expect(preview.complete).toBe(true); expect(preview.members[0]?.recipeRevisionId).toBe(revision.id);
  const created = await createRebuildCohortDraft(d1, owner, 'library-cohort', parsed, 'Create explicit planner draft.');
  expect(created.buildsCreated).toBe(0); expect(db.prepare('SELECT current_revision FROM cohorts WHERE id=?').bind('library-cohort').first<{ current_revision: number }>()?.current_revision).toBe(2);
  expect(db.prepare('SELECT COUNT(*) AS count FROM builds').first<{ count: number }>()?.count).toBe(0);
  db.close();
});
