import { expect, test } from 'bun:test';
import { generateKeyPairSync, sign } from 'node:crypto';
import { mkdirSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { asD1, TestD1 } from './d1';
import { createFactoryDossier, renderFactoryDossier, storedFactoryDossier, listFactoryDossiers, factoryDossierPublicProjection, factoryDossierPublicCanonicalJson, factoryDossierMarkdown } from '../src/lib/server/factory-dossier';
import type { Env } from '../src/lib/server/env';

const digest = 'a'.repeat(64);

async function database() {
  const db = new TestD1();

  for (const file of readdirSync('migrations').filter((name) => name.endsWith('.sql')).sort()) db.exec(readFileSync(`migrations/${file}`, 'utf8'));
  db.exec(`
    INSERT INTO requests(id,name,upstream_url,source_kind,area,declared_license,requested_by,status,created_at,updated_at,factory_run_id)
      VALUES('request-dossier','demo','https://example.org/demo.tar','archive','development','MIT','github:1','review',100,100,'run-dossier');
    INSERT INTO revisions(id,request_id,version,recipe,recipe_sha256,public_recipe,public_recipe_sha256,manifest_sha256,sources_json,dependencies_json,make_dependencies_json,smoke_commands_json,architectures_json,build_images_json,pkgrel,source_date_epoch,image_digest,license,surface,description,explanation,sbom_json,lint_json,upstream_commit,pr_url,commit_sha,created_at)
      VALUES('revision-dossier','request-dossier','1','pkgname=demo','${digest}',NULL,NULL,'${digest}','[{"name":"demo.tar","url":"https://example.org/demo.tar","sha256":"${digest}"}]','[]','[]','["/usr/bin/demo --version"]','["x86_64"]','{"x86_64":"builder@sha256:${digest}"}',1,1,'builder@sha256:${digest}','MIT','binary','Demo package','Factory rationale with https://user:password@example.org/private?token=secret','{}','{}','deadbeef','https://example.org/pr/1','commit',100);
    INSERT INTO workers(id,name,architecture,public_key,status,enrolled_at) VALUES('worker-dossier','worker','x86_64','key','active',100);
    INSERT INTO factory_runs(id,target_kind,target_id,unit_key,status,max_attempts,attempt_count,current_attempt,successful_attempt,policy_json,created_by,created_at,updated_at)
      VALUES('run-dossier','generated','request-dossier','revision-dossier','succeeded',3,3,3,3,'{}','github:1',100,103);
    INSERT INTO factory_run_attempts(id,run_id,attempt,reservation_key,status,candidate_revision_id,candidate_sha256,input_sha256,architecture,candidate_json,failure_kind,failure_json,lease_token,lease_expires_at,started_at,finished_at,created_at,updated_at)
      VALUES('run-attempt-1','run-dossier',1,'reservation-1','failed','revision-dossier','${digest}','${digest}','x86_64','{}','validation','{"reason":"lint failed"}','lease-1',200,101,101,101,101),
      ('run-attempt-2','run-dossier',2,'reservation-2','failed','repair-revision','${digest}','${digest}','x86_64','{}','runtime','{"reason":"PRIVATE_FAILURE_SECRET"}','lease-2',200,102,102,102,102),
      ('run-attempt-3','run-dossier',3,'reservation-3','succeeded','revision-dossier','${digest}','${digest}','x86_64','{}',NULL,NULL,'lease-3',200,103,103,103,103);
    INSERT INTO builds(id,revision_id,architecture,status,worker_id,attempt,artifact_key,artifact_sha256,artifact_size,artifact_filename,provenance,smoke_passed,created_at,started_at,finished_at)
      VALUES('build-dossier','revision-dossier','x86_64','succeeded','worker-dossier',3,'private-r2-artifact-key','${digest}',3,'demo.pkg.tar.zst','{"schemaVersion":1,"buildId":"build-dossier","revisionId":"revision-dossier","workerId":"worker-dossier","recipeSha256":"${digest}","architecture":"x86_64","sourceDateEpoch":1,"imageDigest":"builder@sha256:${digest}","packageMetadata":{},"runtimeTests":[],"reproducibility":{"schemaVersion":1,"status":"reproducibility-contract-verified","mode":"single-build","target":"x86_64","inputs":{"recipeSha256":"${digest}","sourceManifestSha256":"5eecd5e6d624e43a442d91c131bf51c70601774ce977b1f1cd11054353e10db3","inputLockSha256":"","dependencyPlanSha256":"","imageDigest":"builder@sha256:${digest}","sourceDateEpoch":1},"controls":{"network":"disabled","locale":"C","timezone":"UTC","umask":"022","hostSecrets":"excluded","writableCaches":"excluded","nativeTarget":"x86_64","archivePathsChecked":true,"archiveMetadataChecked":true,"timestampOwnershipOrderChecked":true},"outputs":{"setSha256":"d24c3aaef0b6f76ff51ae6ad301c9f3072206a0e3ea5ce7f77c3d9ea69664f0e","files":[{"filename":"demo.pkg.tar.zst","size":3,"sha256":"${digest}"}],"unexpected":[],"prohibitedPaths":[]},"limitations":["fixture"]}}',1,101,102,103);
    INSERT INTO build_attempts(build_id,attempt,revision_id,architecture,worker_id,worker_public_key,started_at,input_lock_sha256)
      VALUES('build-dossier',1,'revision-dossier','x86_64','worker-dossier','key',101,NULL),('build-dossier',2,'revision-dossier','x86_64','worker-dossier','key',102,NULL),('build-dossier',3,'revision-dossier','x86_64','worker-dossier','key',103,NULL);
    INSERT INTO build_attempt_results(build_id,attempt,status,error,finished_at) VALUES('build-dossier',1,'failed','lint failed',101),('build-dossier',2,'failed','runtime failed',102),('build-dossier',3,'succeeded',NULL,103);
    INSERT INTO build_artifacts(build_id,attempt,filename,artifact_key,sha256,size,created_at) VALUES('build-dossier',3,'demo.pkg.tar.zst','packages/demo.pkg.tar.zst','${digest}',3,103);
    INSERT INTO build_logs(build_id,attempt,sequence,text,created_at) VALUES('build-dossier',1,0,'first failure',101),('build-dossier',2,0,'second failure',102),('build-dossier',3,0,'success token=private',103);
    INSERT INTO factory_events(request_id,stage,detail,created_at) VALUES('request-dossier','candidate.repair_requested','{"attempt":1,"reason":"lint failed","prompt":"private prompt","model":"stub-model","inputTokens":4}',101),('request-dossier','candidate.repair_requested','{"attempt":2,"reason":"runtime failed","candidateRevisionId":"repair-revision","recipeSha256":"${digest}"}',102);
    INSERT INTO approvals(id,revision_id,actor,kind,manifest_sha256,created_at) VALUES('approval-area','revision-dossier','github:1','area','${digest}',104),('approval-security','revision-dossier','github:2','security','old','104');
    INSERT INTO releases(id,build_id,name,version,architecture,surface,channel,artifact_key,signature_key,recipe_key,sbom_key,provenance_key,published_at)
      VALUES('release-dossier','build-dossier','demo','1','x86_64','binary','stable','packages/demo.pkg.tar.zst','packages/demo.sig','recipes/demo','metadata/demo-sbom','metadata/demo-provenance',105);
  `);

  const keys = generateKeyPairSync('ed25519');
  const publicKey = Buffer.from(keys.publicKey.export({ type: 'spki', format: 'der' }).subarray(-32)).toString('base64');
  const provenance = db.prepare('SELECT provenance FROM builds WHERE id=?').bind('build-dossier').first<{ provenance: string }>()!.provenance;
  db.prepare('UPDATE workers SET public_key=? WHERE id=?').bind(publicKey, 'worker-dossier').run();
  db.prepare('UPDATE builds SET provenance_signature=? WHERE id=?').bind(Buffer.from(sign(null, Buffer.from(provenance), keys.privateKey)).toString('base64'), 'build-dossier').run();

  return db;
}

function env(db: TestD1): Env {
  return { DB: asD1(db), ARTIFACTS: {} as R2Bucket, PUBLIC_ORIGIN: 'https://omapkg.example' } as Env;
}

test('factory dossier preserves every attempt/output and stable canonical exports', async () => {
  const db = await database();

  try {
    const first = await createFactoryDossier(env(db), 'github:1', { requestId: 'request-dossier', revisionId: 'revision-dossier' });
    const second = await createFactoryDossier(env(db), 'github:1', { requestId: 'request-dossier', revisionId: 'revision-dossier' });
    if (process.env.FACTORY_DOSSIER_EXPORT_DIR) {
      mkdirSync(process.env.FACTORY_DOSSIER_EXPORT_DIR, { recursive: true, mode: 0o700 });
      writeFileSync(`${process.env.FACTORY_DOSSIER_EXPORT_DIR}/dossier.json`, `${first.canonicalJson}\n`, { mode: 0o600 });
      writeFileSync(`${process.env.FACTORY_DOSSIER_EXPORT_DIR}/dossier.md`, first.markdown, { mode: 0o600 });
    }
    expect(first.dossier.attempts.map((attempt) => attempt.attempt)).toEqual([1, 2, 3]);
    expect(first.dossier.attempts.map((attempt) => attempt.result)).toEqual(['failed', 'failed', 'succeeded']);
    expect(first.dossier.outputs).toHaveLength(1);
    expect(first.canonicalJson).toBe(second.canonicalJson);
    expect(first.markdown).toBe(second.markdown);
    expect(first.canonicalSha256).toMatch(/^[a-f0-9]{64}$/);
    expect(first.markdown).toContain('repair-revision');
    expect(first.markdown).toContain('demo.pkg.tar.zst');
    expect(first.dossier.evidence.events[0].detail.prompt).toBeUndefined();
    expect(first.dossier.evidence.events[1].detail.candidateRevisionId).toBe('repair-revision');
    expect(first.dossier.evidence.evidenceAsOfAt).toBe(105);
    expect(first.dossier.reviews[0].currentAtSnapshot).toBe(true);
    expect(first.dossier.reviews[0]).not.toHaveProperty('current');
    expect(first.dossier.checks.find((check) => check.name === 'x86_64/reproducibility-contract')?.status).toBe('passed');
    db.exec("INSERT INTO factory_events(request_id,stage,detail,created_at) VALUES('request-dossier','late.evidence','{\"attempt\":3,\"message\":\"late result\"}',106)");
    const changed = await createFactoryDossier(env(db), 'github:1', { requestId: 'request-dossier', revisionId: 'revision-dossier' });
    expect(changed.dossier.id).not.toBe(first.dossier.id);
    expect(db.prepare('SELECT COUNT(*) AS count FROM factory_dossiers').first<{ count: number }>()?.count).toBe(2);
    db.prepare("UPDATE builds SET provenance=replace(provenance,'reproducibility-contract-verified','verified') WHERE id='build-dossier'").run();
    const fake = await createFactoryDossier(env(db), 'github:1', { requestId: 'request-dossier', revisionId: 'revision-dossier' });
    expect(fake.dossier.checks.find((check) => check.name === 'x86_64/reproducibility-contract')?.status).not.toBe('passed');
  } finally { db.close(); }
});

test('changed evidence creates a new snapshot with the same ID before and after storage', async () => {
  const db = await database();
  try {
    const input = { requestId: 'request-dossier', revisionId: 'revision-dossier' };
    const first = await createFactoryDossier(env(db), 'github:1', input);
    db.prepare("UPDATE approvals SET revoked_at=200 WHERE id='approval-area'").run();
    const rendered = await renderFactoryDossier(env(db), input);
    const second = await createFactoryDossier(env(db), 'github:1', input);
    const repeated = await createFactoryDossier(env(db), 'github:2', input);
    expect(second.dossier.id).not.toBe(first.dossier.id);
    expect(second.canonicalJson).toBe(rendered.canonicalJson);
    expect(repeated.canonicalJson).toBe(second.canonicalJson);
    expect((await storedFactoryDossier(env(db), first.dossier.id)).canonicalJson).toBe(first.canonicalJson);
    expect((await listFactoryDossiers(env(db), input.requestId))[0].id).toBe(second.dossier.id);
    expect(db.prepare('SELECT COUNT(*) AS count FROM factory_dossiers').first<{ count: number }>()?.count).toBe(2);
  } finally { db.close(); }
});

test('public dossier projection requires publication and omits private recipe/rationale/log material', async () => {
  const db = await database();

  try {
    const stored = await createFactoryDossier(env(db), 'github:1', { requestId: 'request-dossier', revisionId: 'revision-dossier' });
    const projection = factoryDossierPublicProjection(stored.dossier) as Record<string, unknown>;
    expect(projection.revision).not.toHaveProperty('recipe');
    expect(projection).not.toHaveProperty('rationale');
    const serialized = JSON.stringify(projection);
    expect(serialized).not.toContain('private prompt');
    expect(serialized).not.toContain('PRIVATE_FAILURE_SECRET');
    expect(serialized).not.toContain('private-r2-artifact-key');
    expect(serialized).not.toContain('user:password');
    expect(serialized).not.toContain('/maintain/builds/');
    expect((projection.outputs as Array<Record<string, unknown>>)[0]).not.toHaveProperty('artifactKey');
    expect((projection.checks as Array<Record<string, unknown>>)[0]).not.toHaveProperty('evidence');
    expect(factoryDossierPublicCanonicalJson(stored.dossier)).toBe(factoryDossierPublicCanonicalJson(stored.dossier));
    expect(factoryDossierMarkdown(stored.dossier, true)).not.toContain('pkgname=demo');
  } finally { db.close(); }
});
