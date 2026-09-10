import { expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import { asD1, TestD1 } from './d1';
import { startFactoryCohort, startFactoryUnit, startFactoryUnitIntervention, type FactoryUnitDispatch, type FactoryUnitQueue } from '../src/lib/server/factory-entrypoints';
import { finishFactoryAttempt, getFactoryAttempt } from '../src/lib/server/factory-runs';

const digest = (value: string) => value.repeat(64);

function database() {
  return new TestD1(`CREATE TABLE requests(id TEXT PRIMARY KEY,area TEXT,status TEXT,requested_by TEXT);
    CREATE TABLE revisions(id TEXT PRIMARY KEY,request_id TEXT,manifest_sha256 TEXT,architectures_json TEXT,created_at INTEGER);
    CREATE TABLE catalog_revisions(pkgbase TEXT,revision INTEGER,owner_area TEXT,lane TEXT,PRIMARY KEY(pkgbase,revision));
    CREATE TABLE cohorts(id TEXT PRIMARY KEY,current_revision INTEGER,phase TEXT,condition TEXT);
    CREATE TABLE cohort_members(cohort_id TEXT,revision INTEGER,pkgbase TEXT,catalog_revision INTEGER,recipe_revision_id TEXT);
    CREATE TABLE builds(id TEXT PRIMARY KEY,revision_id TEXT,architecture TEXT,status TEXT,created_at INTEGER,UNIQUE(revision_id,architecture));
    ${readFileSync('migrations/0052_factory_runs.sql', 'utf8')}
    CREATE TABLE audit_events(actor TEXT,action TEXT,target TEXT,detail TEXT,created_at INTEGER);`);
}

function queue(calls: FactoryUnitDispatch[]): FactoryUnitQueue {
  return { enqueue: async (input) => { calls.push(input);

 return { workflowId: input.workflowId }; } };
}

test('recipe unit entry points persist one durable queued run per unit and dispatch it', async () => {
  const db = database(); const calls: FactoryUnitDispatch[] = []; const actor = { id: 'github:1', role: 'maintainer' as const, areas: ['system'] as const };

  try {
    for (const [index, targetKind] of (['preserved', 'manual', 'cohort-member', 'bootstrap', 'toolchain'] as const).entries()) {
      const requestId = `request-${index}`; const revisionId = `revision-${index}`; const pkgbase = `pkgbase-${index}`;
      db.prepare('INSERT INTO requests VALUES(?,?,?,?)').bind(requestId, 'system', 'review', 'github:1').run();
      db.prepare('INSERT INTO revisions VALUES(?,?,?,?,?)').bind(revisionId, requestId, digest(String.fromCharCode(97 + index)), '["x86_64"]', index + 1).run();

      if (targetKind === 'cohort-member') { db.prepare("INSERT INTO cohorts VALUES('cohort-1',1,'build','ready')").run(); db.prepare('INSERT INTO catalog_revisions VALUES(?,?,?,?)').bind(pkgbase, 1, 'system', 'system').run(); }

      if (targetKind === 'cohort-member') db.prepare('INSERT INTO cohort_members VALUES(?,?,?,?,?)').bind('cohort-1', 1, pkgbase, 1, revisionId).run();
      const result = await startFactoryUnit(asD1(db), actor, queue(calls), { targetKind, targetId: targetKind === 'cohort-member' ? 'cohort-1' : `unit-${index}`, unitKey: targetKind === 'cohort-member' ? pkgbase : `${targetKind}:x86_64`, policy: { network: 'disabled', targetKind }, requestedRevisionId: revisionId });
      expect(result.run.status).toBe('running'); expect(result.run.currentAttempt).toBe(1); expect(result.workflowId).toBe(`factory-unit-${result.run.id}`);
    }

    expect(calls.map((call) => call.targetKind)).toEqual(['preserved', 'manual', 'cohort-member', 'bootstrap', 'toolchain']);
    expect(db.prepare("SELECT COUNT(*) AS count FROM factory_runs WHERE status='running'").first<{ count: number }>()?.count).toBe(5);
    expect(db.prepare("SELECT COUNT(*) AS count FROM audit_events WHERE action='factory.unit_dispatched'").first<{ count: number }>()?.count).toBe(5);
  } finally { db.close(); }
});

test('cohort intervention keeps exhausted run history and shares three-attempt budget', async () => {
  const db = database(); const calls: FactoryUnitDispatch[] = []; const actor = { id: 'github:1', role: 'maintainer' as const, areas: ['system'] as const };

  try {
    db.prepare("INSERT INTO requests VALUES('request-cohort','system','review','github:1')").run(); db.prepare('INSERT INTO revisions VALUES(?,?,?,?,?)').bind('revision-cohort', 'request-cohort', digest('a'), '["x86_64"]', 1).run(); db.prepare("INSERT INTO cohorts VALUES('cohort-1',1,'build','ready')").run(); db.prepare("INSERT INTO catalog_revisions VALUES('cohort-pkg',1,'system','system')").run(); db.prepare("INSERT INTO cohort_members VALUES('cohort-1',1,'cohort-pkg',1,'revision-cohort')").run();
    const started = await startFactoryUnit(asD1(db), actor, queue(calls), { targetKind: 'cohort-member', targetId: 'cohort-1', unitKey: 'cohort-pkg', policy: { network: 'disabled' } });
    let current = started;

    for (const attemptNumber of [1, 2, 3]) {
      const attempt = await getFactoryAttempt(asD1(db), current.run.id, attemptNumber);

      if (!attempt) throw new Error('factory attempt missing');
      await finishFactoryAttempt(asD1(db), current.run.id, attempt.attempt, attempt.leaseToken, { status: 'failed', failureKind: 'build', failure: { attempt: attemptNumber } });

      if (attemptNumber < 3) { const revisionId = `revision-cohort-${attemptNumber + 1}`; db.prepare('INSERT INTO revisions VALUES(?,?,?,?,?)').bind(revisionId, 'request-cohort', digest(String.fromCharCode(97 + attemptNumber)), '["x86_64"]', attemptNumber + 1).run(); db.prepare('UPDATE cohort_members SET recipe_revision_id=? WHERE cohort_id=?').bind(revisionId, 'cohort-1').run(); current = await startFactoryUnit(asD1(db), actor, queue(calls), { targetKind: 'cohort-member', targetId: 'cohort-1', unitKey: 'cohort-pkg', policy: { network: 'disabled' }, requestedRevisionId: revisionId }); }
    }

    db.prepare("INSERT INTO revisions VALUES('revision-successor','request-cohort',?,?,?)").bind(digest('e'), '["x86_64"]', 4).run(); db.prepare('UPDATE cohort_members SET recipe_revision_id=? WHERE cohort_id=?').bind('revision-successor', 'cohort-1').run();
    const successor = await startFactoryUnitIntervention(asD1(db), actor, queue(calls), { sourceRunId: started.run.id, reason: 'Replace failed private candidate after reviewing worker finding.', targetKind: 'cohort-member', targetId: 'cohort-1', unitKey: 'cohort-pkg', policy: { network: 'disabled' }, requestedRevisionId: 'revision-successor', runId: 'cohort-successor' });
    expect(successor.run.sourceRunId).toBe(started.run.id); expect(successor.run.attemptCount).toBe(1);
    expect(successor.run.currentAttempt).toBe(1); expect(calls.at(-1)?.sourceRunId).toBe(started.run.id); expect(calls.at(-1)?.repairReason).toContain('worker finding');
    expect(db.prepare("SELECT status,attempt_count FROM factory_runs WHERE id=?").bind(started.run.id).first<{ status: string; attempt_count: number }>()).toEqual({ status: 'needs-human-intervention', attempt_count: 3 });
  } finally { db.close(); }
});

test('cohort start iterates every current recipe member through the same private queue', async () => {
  const db = database(); const calls: FactoryUnitDispatch[] = []; const actor = { id: 'github:1', role: 'maintainer' as const, areas: ['system'] as const };

  try {
    db.prepare("INSERT INTO cohorts VALUES('cohort-batch',1,'build','ready')").run();

    for (const [index, pkgbase] of ['pkg-a', 'pkg-b'].entries()) {
      const requestId = `request-batch-${index}`; const revisionId = `revision-batch-${index}`;
      db.prepare('INSERT INTO requests VALUES(?,?,?,?)').bind(requestId, 'system', 'review', 'github:1').run();
      db.prepare('INSERT INTO revisions VALUES(?,?,?,?,?)').bind(revisionId, requestId, digest(String.fromCharCode(97 + index)), '["x86_64"]', index + 1).run();
      db.prepare('INSERT INTO catalog_revisions VALUES(?,?,?,?)').bind(pkgbase, 1, 'system', 'system').run();
      db.prepare('INSERT INTO cohort_members VALUES(?,?,?,?,?)').bind('cohort-batch', 1, pkgbase, 1, revisionId).run();
    }

    const result = await startFactoryCohort(asD1(db), actor, queue(calls), { cohortId: 'cohort-batch', policy: { network: 'disabled' } });
    expect(result.units).toHaveLength(2); expect(calls.map((call) => call.unitKey)).toEqual(['pkg-a', 'pkg-b']);
    expect(db.prepare("SELECT COUNT(*) AS count FROM factory_runs WHERE target_kind='cohort-member' AND target_id='cohort-batch'").first<{ count: number }>()?.count).toBe(2);
  } finally { db.close(); }
});
