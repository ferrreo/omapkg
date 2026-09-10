import { expect, test } from 'bun:test';
import { readFileSync, readdirSync } from 'node:fs';
import { asD1, TestD1 } from './d1';
import { createFactoryRevision } from '../services/pipeline/revision';
import { startFactoryCohort, startFactoryUnit, startFactoryUnitIntervention, type FactoryUnitDispatch, type FactoryUnitQueue } from '../src/lib/server/factory-entrypoints';
import { startFactoryCohortPaged, type FactoryCohortPageDispatch, type FactoryCohortPageQueue } from '../src/lib/server/factory-cohort-dispatch';
import { finishFactoryAttempt, getFactoryAttempt } from '../src/lib/server/factory-runs';

const digest = (value: string) => value.repeat(64);
const builder = `registry.example/builder@sha256:${'f'.repeat(64)}`;

function database() {
  const schema = readdirSync('migrations').filter((name) => name.endsWith('.sql')).sort().map((name) => readFileSync(`migrations/${name}`, 'utf8')).join('\n');
  return new TestD1(schema);
}

async function insertRevision(db: TestD1, requestId: string, revisionId: string, name: string, createdAt: number) {
  const draft = await createFactoryRevision({
    request: { id: requestId, name, upstreamUrl: 'https://example.org/source.tar.gz', sourceKind: 'archive', area: 'system', declaredLicense: 'MIT' },
    version: '1.0.0', sources: [{ name: 'source.tar.gz', url: 'https://example.org/source.tar.gz', sha256: digest('a') }], dependencies: [], makeDependencies: [], smokeCommands: [],
    architectures: ['x86_64'], buildImages: { x86_64: builder }, imageDigest: builder, sourceDateEpoch: 1, license: 'MIT', surface: 'binary', description: name,
    recipeMode: 'template', template: { id: 'make-v1', binary: name }, buildCommands: [], packageCommands: [], explanation: 'Fixture revision.', pkgrel: 1,
  }, 0, revisionId);
  draft.revision.pr_url = `https://github.com/example/recipes/pull/${createdAt}`;
  draft.revision.commit_sha = digest('c').slice(0, 40);
  db.prepare(`INSERT INTO revisions(
    id,request_id,version,recipe,recipe_sha256,manifest_sha256,sources_json,dependencies_json,make_dependencies_json,smoke_commands_json,
    architectures_json,build_images_json,pkgrel,source_date_epoch,image_digest,license,surface,description,explanation,sbom_json,lint_json,
    upstream_commit,pr_url,commit_sha,created_at
  ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).bind(
    draft.revision.id, draft.revision.request_id, draft.revision.version, draft.revision.recipe, draft.revision.recipe_sha256, draft.revision.manifest_sha256,
    draft.revision.sources_json, draft.revision.dependencies_json, draft.revision.make_dependencies_json, draft.revision.smoke_commands_json, draft.revision.architectures_json,
    draft.revision.build_images_json, draft.revision.pkgrel, draft.revision.source_date_epoch, draft.revision.image_digest, draft.revision.license, draft.revision.surface,
    draft.revision.description, draft.revision.explanation, draft.revision.sbom_json, draft.revision.lint_json, draft.revision.upstream_commit,
    draft.revision.pr_url, draft.revision.commit_sha, createdAt,
  ).run();
}

function insertRequest(db: TestD1, id: string, name: string, createdAt: number) {
  db.prepare(`INSERT INTO requests(id,name,description,upstream_url,source_kind,area,declared_license,requested_by,status,created_at,updated_at)
    VALUES(?,?,?,?,?,?,?,?,?,?,?)`).bind(id, name, name, 'https://example.org/source.tar.gz', 'archive', 'system', 'MIT', 'github:1', 'review', createdAt, createdAt).run();
}

function insertCohort(db: TestD1, cohortId: string, pkgbase: string, revisionId: string, revision: number, createdAt: number) {
  db.prepare(`INSERT OR IGNORE INTO cohorts(id,current_revision,phase,condition,created_at,updated_at) VALUES(?,?,?,?,?,?)`).bind(cohortId, revision, 'build', 'ready', createdAt, createdAt).run();
  db.prepare(`INSERT OR IGNORE INTO cohort_revisions(cohort_id,revision,manifest_json,manifest_sha256,title,lane,created_by,created_at) VALUES(?,?,?,?,?,?,?,?)`).bind(cohortId, revision, '{}', digest('r'), 'Fixture cohort', 'opr', 'github:1', createdAt).run();
  db.prepare(`INSERT OR IGNORE INTO catalog_packages(pkgbase,current_revision,admitted_revision,created_at,updated_at) VALUES(?,?,?,?,?)`).bind(pkgbase, revision, revision, createdAt, createdAt).run();
  db.prepare(`INSERT INTO catalog_revisions(pkgbase,revision,manifest_json,manifest_sha256,collection,lane,owner_area,created_by,reason,created_at)
    VALUES(?,?,?,?,?,?,?,?,?,?)`).bind(pkgbase, revision, '{}', digest('b'), 'omapkg', 'opr', 'system', 'github:1', 'Fixture admission.', createdAt).run();
  db.prepare('INSERT INTO cohort_members(cohort_id,revision,pkgbase,catalog_revision,recipe_revision_id) VALUES(?,?,?,?,?)').bind(cohortId, revision, pkgbase, 1, revisionId).run();
}

function advanceCohortMember(db: TestD1, cohortId: string, pkgbase: string, revisionId: string, revision: number, createdAt: number) {
  db.prepare('UPDATE cohorts SET current_revision=?,updated_at=? WHERE id=?').bind(revision, createdAt, cohortId).run();
  db.prepare(`INSERT INTO cohort_revisions(cohort_id,revision,manifest_json,manifest_sha256,title,lane,created_by,created_at) VALUES(?,?,?,?,?,?,?,?)`).bind(cohortId, revision, '{}', digest('r'), 'Fixture cohort', 'opr', 'github:1', createdAt).run();
  db.prepare('INSERT INTO cohort_members(cohort_id,revision,pkgbase,catalog_revision,recipe_revision_id) VALUES(?,?,?,?,?)').bind(cohortId, revision, pkgbase, 1, revisionId).run();
}

function queue(calls: FactoryUnitDispatch[]): FactoryUnitQueue {
  return { enqueue: async (input) => { calls.push(input); return { workflowId: input.workflowId }; } };
}

test('recipe unit entry points persist one durable queued run per unit and dispatch it', async () => {
  const db = database(); const calls: FactoryUnitDispatch[] = []; const actor = { id: 'github:1', role: 'maintainer' as const, areas: ['system'] as const };
  try {
    for (const [index, targetKind] of (['manual', 'cohort-member', 'bootstrap', 'toolchain'] as const).entries()) {
      const requestId = `request-${index}`; const revisionId = `revision-${index}`; const name = `pkg-${index}`;
      insertRequest(db, requestId, name, index + 1); await insertRevision(db, requestId, revisionId, name, index + 1);
      if (targetKind === 'cohort-member') insertCohort(db, 'cohort-1', name, revisionId, 1, index + 1);
      const result = await startFactoryUnit(asD1(db), actor, queue(calls), { targetKind, targetId: targetKind === 'cohort-member' ? 'cohort-1' : `unit-${index}`, unitKey: targetKind === 'cohort-member' ? name : `${targetKind}:x86_64`, policy: { network: 'disabled', targetKind }, requestedRevisionId: revisionId });
      expect(result.run.status).toBe('running'); expect(result.run.currentAttempt).toBe(1); expect(result.workflowId).toBe(`factory-unit-${result.run.id}`);
    }
    expect(calls.map((call) => call.targetKind)).toEqual(['manual', 'cohort-member', 'bootstrap', 'toolchain']);
    expect(db.prepare("SELECT COUNT(*) AS count FROM factory_runs WHERE status='running'").first<{ count: number }>()?.count).toBe(4);
  } finally { db.close(); }
});

test('cohort intervention keeps exhausted run history and shares three-attempt budget', async () => {
  const db = database(); const calls: FactoryUnitDispatch[] = []; const actor = { id: 'github:1', role: 'maintainer' as const, areas: ['system'] as const };
  try {
    insertRequest(db, 'request-cohort', 'cohort-pkg', 1); await insertRevision(db, 'request-cohort', 'revision-cohort', 'cohort-pkg', 1); insertCohort(db, 'cohort-1', 'cohort-pkg', 'revision-cohort', 1, 1);
    const started = await startFactoryUnit(asD1(db), actor, queue(calls), { targetKind: 'cohort-member', targetId: 'cohort-1', unitKey: 'cohort-pkg', policy: { network: 'disabled' } });
    let current = started;
    for (const attemptNumber of [1, 2, 3]) {
      const attempt = await getFactoryAttempt(asD1(db), current.run.id, attemptNumber);
      if (!attempt) throw new Error('factory attempt missing');
      await finishFactoryAttempt(asD1(db), current.run.id, attempt.attempt, attempt.leaseToken, { status: 'failed', failureKind: 'build', failure: { attempt: attemptNumber } });
      if (attemptNumber < 3) {
        const revisionId = `revision-cohort-${attemptNumber + 1}`;
        await insertRevision(db, 'request-cohort', revisionId, 'cohort-pkg', attemptNumber + 1);
        advanceCohortMember(db, 'cohort-1', 'cohort-pkg', revisionId, attemptNumber + 1, attemptNumber + 1);
        current = await startFactoryUnit(asD1(db), actor, queue(calls), { targetKind: 'cohort-member', targetId: 'cohort-1', unitKey: 'cohort-pkg', policy: { network: 'disabled' }, requestedRevisionId: revisionId });
      }
    }
    await insertRevision(db, 'request-cohort', 'revision-successor', 'cohort-pkg', 4); advanceCohortMember(db, 'cohort-1', 'cohort-pkg', 'revision-successor', 4, 4);
    const successor = await startFactoryUnitIntervention(asD1(db), actor, queue(calls), { sourceRunId: started.run.id, reason: 'Replace failed private candidate after reviewing worker finding.', targetKind: 'cohort-member', targetId: 'cohort-1', unitKey: 'cohort-pkg', policy: { network: 'disabled' }, requestedRevisionId: 'revision-successor', runId: 'cohort-successor' });
    expect(successor.run.sourceRunId).toBe(started.run.id); expect(successor.run.attemptCount).toBe(1); expect(calls.at(-1)?.repairReason).toContain('worker finding');
    expect(db.prepare("SELECT status,attempt_count FROM factory_runs WHERE id=?").bind(started.run.id).first<{ status: string; attempt_count: number }>()).toEqual({ status: 'needs-human-intervention', attempt_count: 3 });
  } finally { db.close(); }
});

test('cohort start iterates every current recipe member through the same private queue', async () => {
  const db = database(); const calls: FactoryUnitDispatch[] = []; const actor = { id: 'github:1', role: 'maintainer' as const, areas: ['system'] as const };
  try {
    db.prepare("INSERT INTO cohorts(id,current_revision,phase,condition,created_at,updated_at) VALUES('cohort-batch',1,'build','ready',1,1)").run();
    for (const [index, pkgbase] of ['pkg-a', 'pkg-b'].entries()) { const requestId = `request-batch-${index}`; const revisionId = `revision-batch-${index}`; insertRequest(db, requestId, pkgbase, index + 1); await insertRevision(db, requestId, revisionId, pkgbase, index + 1); insertCohort(db, 'cohort-batch', pkgbase, revisionId, 1, index + 1); }
    const result = await startFactoryCohort(asD1(db), actor, queue(calls), { cohortId: 'cohort-batch', policy: { network: 'disabled' } });
    expect(result.units).toHaveLength(2); expect(calls.map((call) => call.unitKey)).toEqual(['pkg-a', 'pkg-b']);
  } finally { db.close(); }
});

test('large cohort start enqueues one bounded durable page without loading members', async () => {
  const db = database(); const actor = { id: 'github:1', role: 'maintainer' as const, areas: ['system'] as const }; const pages: FactoryCohortPageDispatch[] = [];
  const queue: FactoryCohortPageQueue = { enqueuePage: async (input) => { pages.push(input); return { workflowId: input.workflowId }; } };
  try {
    db.prepare("INSERT INTO cohorts(id,current_revision,phase,condition,created_at,updated_at) VALUES('cohort-large',7,'build','ready',1,1)").run();
    const result = await startFactoryCohortPaged(asD1(db), actor, queue, { cohortId: 'cohort-large', policy: { network: 'disabled' } });
    expect(result.workflowId).toBe(`factory-cohort-${result.run.id}-page-0`);
    expect(pages).toHaveLength(1);
    expect(pages[0]).toMatchObject({ cohortId: 'cohort-large', revision: 7, offset: 0, pageSize: 64, runId: result.run.id });
  } finally { db.close(); }
});

test('large cohort entry point counts and pages over 1,000 members without per-member dispatch', async () => {
  const db = database(); const actor = { id: 'github:1', role: 'maintainer' as const, areas: ['system'] as const }; const pages: FactoryCohortPageDispatch[] = [];
  const queue: FactoryUnitQueue = { enqueue: async (input) => ({ workflowId: input.workflowId }), enqueuePage: async (input) => { pages.push(input); return { workflowId: input.workflowId }; } };
  try {
    db.exec('PRAGMA foreign_keys=OFF');
    insertCohort(db, 'cohort-1000', 'seed', 'missing-revision', 1, 1);
    for (let index = 0; index < 1_200; index += 1) db.prepare('INSERT INTO cohort_members(cohort_id,revision,pkgbase,catalog_revision,recipe_revision_id) VALUES(?,?,?,?,?)').bind('cohort-1000', 1, `member-${index}`, 1, `revision-${index}`).run();
    db.exec('PRAGMA foreign_keys=ON');
    const result = await startFactoryCohort(asD1(db), actor, queue, { cohortId: 'cohort-1000', policy: { network: 'disabled' } });
    expect(result.units).toEqual([]);
    expect(pages).toHaveLength(1);
    expect(pages[0].pageSize).toBe(64);
  } finally { db.close(); }
});
