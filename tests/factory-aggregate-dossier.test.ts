import { expect, test } from 'bun:test';
import { asD1, TestD1 } from './d1';
import { buildFactoryAggregateDossier, createFactoryAggregateDossier } from '../src/lib/server/factory-aggregate-dossier';
import type { Env } from '../src/lib/server/env';

function database() {
  return new TestD1(`
    CREATE TABLE factory_runs(id TEXT PRIMARY KEY,target_kind TEXT,target_id TEXT,policy_json TEXT,status TEXT,successful_attempt INTEGER,created_at INTEGER);
    CREATE TABLE cohorts(id TEXT PRIMARY KEY,current_revision INTEGER,updated_at INTEGER);
    CREATE TABLE cohort_members(cohort_id TEXT,revision INTEGER,pkgbase TEXT,recipe_revision_id TEXT);
    CREATE TABLE revisions(id TEXT PRIMARY KEY);
    CREATE TABLE builds(id TEXT,revision_id TEXT,attempt INTEGER,architecture TEXT,status TEXT,artifact_filename TEXT,artifact_sha256 TEXT,artifact_size INTEGER,created_at INTEGER);
    CREATE TABLE build_artifacts(build_id TEXT,attempt INTEGER,filename TEXT,artifact_key TEXT,sha256 TEXT,size INTEGER);
    CREATE TABLE factory_dossiers(id TEXT,revision_id TEXT,created_at INTEGER);
    CREATE TABLE factory_aggregate_dossiers(id TEXT,target_kind TEXT,target_id TEXT,run_id TEXT,canonical_json TEXT,canonical_sha256 TEXT,markdown TEXT,markdown_sha256 TEXT,created_by TEXT,created_at INTEGER);
    CREATE TABLE audit_events(actor TEXT,action TEXT,target TEXT,detail TEXT,created_at INTEGER);
    INSERT INTO factory_runs VALUES('cohort-run','cohort','cohort-1','{}','succeeded',1,4);
    INSERT INTO cohorts VALUES('cohort-1',1,4);
    INSERT INTO revisions VALUES('revision-a'),('revision-b');
    INSERT INTO cohort_members VALUES('cohort-1',1,'alpha','revision-a'),('cohort-1',1,'beta','revision-b');
    INSERT INTO factory_dossiers VALUES('dossier-alpha','revision-a',3);
    INSERT INTO builds VALUES('build-alpha','revision-a',1,'x86_64','succeeded','alpha.pkg.tar.zst','${'a'.repeat(64)}',10,3),('build-beta','revision-b',1,'x86_64','failed',NULL,NULL,NULL,4);
    INSERT INTO build_artifacts VALUES('build-alpha',1,'alpha.pkg.tar.zst','private/alpha','${'a'.repeat(64)}',10);
  `);
}

test('aggregate cohort dossier retains every member and failed status', async () => {
  const db = database();

  try {
    const env = { DB: asD1(db), ARTIFACTS: {} as R2Bucket, PUBLIC_ORIGIN: 'https://test.example' } as Env;
    const dossier = await buildFactoryAggregateDossier(env, { targetKind: 'cohort', targetId: 'cohort-1', runId: 'cohort-run' });
    expect(dossier.constituents.map((item) => [item.key, item.status, item.dossierId])).toEqual([
      ['alpha', 'succeeded', 'dossier-alpha'], ['beta', 'failed', null],
    ]);
    const stored = await createFactoryAggregateDossier(env, 'github:1', { targetKind: 'cohort', targetId: 'cohort-1', runId: 'cohort-run' });
    expect(stored.canonicalJson).toContain('beta');
  } finally { db.close(); }
});
