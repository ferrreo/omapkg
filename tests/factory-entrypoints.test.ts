import { expect, test } from 'bun:test';
import { readFileSync, readdirSync } from 'node:fs';
import { asD1, TestD1 } from './d1';
import { createFactoryRevision } from '../services/pipeline/revision';
import { startFactoryCohort, startFactoryUnit, startFactoryUnitIntervention, type FactoryUnitDispatch, type FactoryUnitQueue } from '../src/lib/server/factory-entrypoints';
import { startFactoryCohortPaged, type FactoryCohortPageDispatch, type FactoryCohortPageQueue } from '../src/lib/server/factory-cohort-dispatch';
import { finishFactoryAttempt, getFactoryAttempt } from '../src/lib/server/factory-runs';
import { createFactorySuccessorDraft } from '../src/lib/server/preserved-factory';
import type { Revision } from '../src/lib/model';
import { actions as factoryRunActions } from '../src/routes/maintain/factory-runs/[id]/+page.server';

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

test('human restart of an already-built revision defers a fresh candidate without reusing historical builds', async () => {
  const db = database(); const calls: FactoryUnitDispatch[] = []; const actor = { id: 'github:1', role: 'maintainer' as const, areas: ['system'] as const };
  try {
    insertRequest(db, 'restart-request', 'restart-demo', 1);
    await insertRevision(db, 'restart-request', 'restart-revision', 'restart-demo', 1);
    const input = { targetKind: 'manual' as const, targetId: 'restart-revision', unitKey: 'restart-demo', policy: { network: 'disabled' }, requestedRevisionId: 'restart-revision' };
    const source = await startFactoryUnit(asD1(db), actor, queue(calls), input);
    const attempt = await getFactoryAttempt(asD1(db), source.run.id, 1);
    if (!attempt) throw Error('Initial attempt missing');
    await finishFactoryAttempt(asD1(db), source.run.id, 1, attempt.leaseToken, { status: 'failed', failureKind: 'policy', failure: { message: 'Worker input permissions need intervention.' } });
    const restarted = await startFactoryUnitIntervention(asD1(db), actor, queue(calls), { ...input, sourceRunId: source.run.id, reason: 'Worker permissions fixed; retry the same input scope.' });
    expect(restarted.run.sourceRunId).toBe(source.run.id);
    expect(restarted.run.attemptCount).toBe(0);
    expect(calls.at(-1)?.buildIds).toEqual([]);
    expect(calls.at(-1)?.revisionId).toBe('restart-revision');
    expect(db.prepare('SELECT COUNT(*) AS count FROM builds WHERE factory_run_id=?').bind(source.run.id).first<{ count: number }>()?.count).toBe(1);
    expect(db.prepare('SELECT COUNT(*) AS count FROM builds WHERE factory_run_id=?').bind(restarted.run.id).first<{ count: number }>()?.count).toBe(0);
    const parent = db.prepare('SELECT * FROM revisions WHERE id=?').bind('restart-revision').first<Revision>();
    if (!parent) throw Error('Parent revision missing');
    const draft = await createFactorySuccessorDraft({ DB: asD1(db) }, parent, parent.recipe, 1, null, 'Human-authorized restart', undefined, `factory-${restarted.run.id}-attempt-1`);
    expect(draft.revision.id).not.toBe(parent.id);
    expect(draft.revision.pkgrel).toBe((parent.pkgrel ?? 1) + 1);
    expect(draft.revision.sources_json).toBe(parent.sources_json);
    expect(draft.revision.architectures_json).toBe(parent.architectures_json);
  } finally { db.close(); }
});

test('a first factory run also preserves an existing build of its reviewed revision', async () => {
  const db = database(); const calls: FactoryUnitDispatch[] = []; const actor = { id: 'github:1', role: 'maintainer' as const, areas: ['system'] as const };
  try {
    insertRequest(db, 'existing-request', 'existing-demo', 1);
    await insertRevision(db, 'existing-request', 'existing-revision', 'existing-demo', 1);
    db.prepare("INSERT INTO builds(id,revision_id,architecture,status,created_at) VALUES('existing-build','existing-revision','x86_64','failed',1)").run();
    const started = await startFactoryUnit(asD1(db), actor, queue(calls), { targetKind: 'manual', targetId: 'existing-revision', unitKey: 'existing-demo', policy: { network: 'disabled' }, requestedRevisionId: 'existing-revision' });
    expect(started.run.attemptCount).toBe(0);
    expect(calls.at(-1)?.buildIds).toEqual([]);
    expect(db.prepare("SELECT factory_run_id FROM builds WHERE id='existing-build'").first<{ factory_run_id: string | null }>()?.factory_run_id).toBeNull();
  } finally { db.close(); }
});

test('run owner can stop private work while unrelated maintainers cannot', async () => {
  const db = database(); const calls: FactoryUnitDispatch[] = []; const actor = { id: 'github:1', role: 'maintainer' as const, areas: ['system'] as const };
  try {
    insertRequest(db, 'stop-request', 'stop-demo', 1);
    await insertRevision(db, 'stop-request', 'stop-revision', 'stop-demo', 1);
    const started = await startFactoryUnit(asD1(db), actor, queue(calls), { targetKind: 'manual', targetId: 'stop-revision', unitKey: 'stop-demo', policy: { network: 'disabled' }, requestedRevisionId: 'stop-revision' });
    const stop = factoryRunActions.stop;
    if (!stop) throw Error('Stop action missing');
    const event = (who: typeof actor) => {
      const body = new FormData(); body.set('reason', 'Replace the retired builder before restarting.');
      // The action reads only these event fields; no browser/session hooks run in this unit check.
      return { request: new Request('https://repo.test/maintain/factory-runs/test?/stop', { method: 'POST', body }), locals: { actor: who },
        params: { id: started.run.id }, platform: { env: { DB: asD1(db) } } } as unknown as Parameters<typeof stop>[0];
    };
    expect(await stop(event({ ...actor, id: 'github:2' }))).toMatchObject({ status: 403 });
    expect(await stop(event(actor))).toMatchObject({ success: true, stopped: true });
    expect(db.prepare('SELECT status FROM factory_runs WHERE id=?').bind(started.run.id).first<{ status: string }>()?.status).toBe('needs-human-intervention');
    expect(db.prepare('SELECT status FROM builds WHERE factory_run_id=?').bind(started.run.id).first<{ status: string }>()?.status).toBe('cancelled');
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
