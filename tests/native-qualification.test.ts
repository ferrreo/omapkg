import { expect, test } from 'bun:test';
import { canonicalJson } from '../src/lib/canonical-json';
import { outputSetDigest, parseQualificationPlan, qualificationPlanDigest, createQualificationPlan, reviewQualificationPlan, recordNativeQualification, addQualificationException, qualificationEvidenceForGate } from '../src/lib/server/native-qualification';
import { sha256 } from '../src/lib/server/db';
import { TestD1, asD1 } from './d1';
import { readFileSync, readdirSync } from 'node:fs';
import type { Env } from '../src/lib/server/env';
import { GET as workerQualificationGet, POST as workerQualificationPost } from '../src/routes/api/worker/qualification/+server';

const digest = 'a'.repeat(64);

function plan(operation = 'install') {
  return {
    schemaVersion: 1, cohortId: 'cohort-1', revision: 1, operation, architecture: 'x86_64',
    candidateSha256: digest, inputSha256: 'b'.repeat(64), artifactSha256: 'c'.repeat(64), environmentSha256: 'd'.repeat(64),
    profile: { id: 'x86-uefi', sha256: 'e'.repeat(64) },
    coverage: { kind: 'member', pkgbase: 'demo', rootSha256: null, releaseId: '4.0.3-rc2', members: ['demo'], sha256: 'f'.repeat(64) },
    commands: [{ name: 'state', executable: '/usr/bin/test', arguments: ['-f', 'state'] }],
    observations: [{ name: 'packages', path: 'packages.json', kind: 'package-state' }], expectedObservationSha256: 'f'.repeat(64), expected: { packageSet: 'reviewed' },
  };
}

const schema = readdirSync(new URL('../migrations', import.meta.url)).filter((name) => name.endsWith('.sql')).sort()
  .map((name) => readFileSync(new URL(`../migrations/${name}`, import.meta.url), 'utf8')).join('\n');

const base64 = (bytes: ArrayBuffer) => btoa(String.fromCharCode(...new Uint8Array(bytes)));

async function fixture() {
  const holder = new TestD1(schema); const db = asD1(holder); const timestamp = Math.floor(Date.now() / 1000);
  const candidateSha256 = 'a'.repeat(64); const inputSha256 = 'c'.repeat(64); const artifactSha256 = 'f'.repeat(64);
  const first = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
  const second = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
  const publicKey = base64(await crypto.subtle.exportKey('raw', first.publicKey)); const secondPublicKey = base64(await crypto.subtle.exportKey('raw', second.publicKey));
  await db.batch([
    db.prepare("INSERT INTO team_memberships(github_id,team) VALUES('1','system'),('2','security')"),
    db.prepare("INSERT INTO workers(id,name,architecture,public_key,status,enrolled_at,last_seen_at) VALUES('worker-1','x86','x86_64',?,'active',?,?)").bind(publicKey, timestamp, timestamp),
    db.prepare("INSERT INTO workers(id,name,architecture,public_key,status,enrolled_at,last_seen_at) VALUES('worker-2','x86-other','x86_64',?,'active',?,?)").bind(secondPublicKey, timestamp, timestamp),
    db.prepare("INSERT INTO cohorts(id,current_revision,event_sequence,phase,condition,created_at,updated_at) VALUES('cohort-1',1,0,'build','ready',?,?)").bind(timestamp, timestamp),
    db.prepare("INSERT INTO cohort_revisions(cohort_id,revision,manifest_json,manifest_sha256,title,lane,created_by,created_at) VALUES('cohort-1',1,?,'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','Candidate','system','github:1',?)").bind('{"schemaVersion":1}', timestamp),
    db.prepare("INSERT INTO catalog_packages(pkgbase,current_revision,admitted_revision,created_at,updated_at) VALUES('demo',1,1,?,?)").bind(timestamp, timestamp),
    db.prepare("INSERT INTO catalog_revisions(pkgbase,revision,manifest_json,manifest_sha256,collection,lane,owner_area,created_by,reason,created_at) VALUES('demo',1,?,'b','core','system','system','github:1','fixture',?)").bind('{"schemaVersion":1}', timestamp),
    db.prepare("INSERT INTO requests(id,name,upstream_url,source_kind,area,requested_by,status,created_at,updated_at) VALUES('request-1','demo','https://example.com/demo.tar','archive','system','github:1','queued',?,?)").bind(timestamp, timestamp),
    db.prepare("INSERT INTO revisions(id,request_id,version,recipe,recipe_sha256,manifest_sha256,sources_json,dependencies_json,smoke_commands_json,architectures_json,source_date_epoch,image_digest,license,surface,explanation,sbom_json,lint_json,created_at) VALUES('revision-1','request-1','1','pkgname=demo','d','a','[]','[]','[]','[\"x86_64\"]',0,'sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd','MIT','binary','fixture','{}','{}',?)").bind(timestamp),
    db.prepare("INSERT INTO cohort_members(cohort_id,revision,pkgbase,catalog_revision,recipe_revision_id) VALUES('cohort-1',1,'demo',1,?)").bind('revision-1'),
    db.prepare("INSERT INTO input_objects(sha256,size,object_key,created_by,created_at) VALUES(? ,1,'inputs/c','github:1',?)").bind(inputSha256, timestamp),
    db.prepare("INSERT INTO input_locks(sha256,recipe_revision_id,cohort_id,cohort_revision,architecture,purpose,manifest_json,object_count,package_count,transfer_bytes,status,created_by,created_at,reason) VALUES(?,'revision-1','cohort-1',1,'x86_64','owned',?,0,0,0,'ready','github:1',?,'fixture')").bind(inputSha256, JSON.stringify({ recipeSha256: 'd', cohortSha256: candidateSha256 }), timestamp),
    db.prepare("INSERT INTO catalog_reviews(pkgbase,revision,kind,actor,manifest_sha256,reason,created_at) VALUES('demo',1,'area','github:1','b','fixture',?),('demo',1,'security','github:2','b','fixture',?)").bind(timestamp, timestamp),
    db.prepare("INSERT INTO approvals(id,revision_id,actor,kind,manifest_sha256,created_at) VALUES('approval-area','revision-1','github:1','area','a',?),('approval-security','revision-1','github:2','security','a',?)").bind(timestamp, timestamp),
    db.prepare("INSERT INTO input_lock_reviews(id,lock_sha256,kind,actor,reason,created_at) VALUES('lock-review-area',?,'area','github:1','fixture',?),('lock-review-security',?,'security','github:2','fixture',?)").bind(inputSha256, timestamp, inputSha256, timestamp),
    db.prepare("INSERT INTO build_input_selections(recipe_revision_id,architecture,cohort_id,cohort_revision,lock_sha256,selected_by,selected_at) VALUES('revision-1','x86_64','cohort-1',1,?,'github:1',?)").bind(inputSha256, timestamp),
    db.prepare("INSERT INTO builds(id,revision_id,architecture,status,worker_id,attempt,artifact_sha256,artifact_size,created_at) VALUES('build-1','revision-1','x86_64','succeeded','worker-1',1,?,1,?)").bind(artifactSha256, timestamp),
    db.prepare("INSERT INTO build_attempts(build_id,attempt,revision_id,architecture,worker_id,worker_public_key,started_at,input_lock_sha256) VALUES('build-1',1,'revision-1','x86_64','worker-1',?,?,?)").bind(publicKey, timestamp, inputSha256),
    db.prepare("INSERT INTO build_attempt_results(build_id,attempt,status,provenance,provenance_signature,finished_at) VALUES('build-1',1,'succeeded','{}','signed',?)").bind(timestamp),
    db.prepare("INSERT INTO build_artifacts(build_id,attempt,filename,artifact_key,sha256,size,created_at) VALUES('build-1',1,'demo-1-1-x86_64.pkg.tar.zst','artifacts/demo',?,1,?)").bind(artifactSha256, timestamp),
  ]);
  const env = { DB: db, ARTIFACTS: {} } as unknown as Env;

  return { holder, db, env, first, second, publicKey };
}

async function signedEvidence(state: Awaited<ReturnType<typeof fixture>>, planRecord: Awaited<ReturnType<typeof createQualificationPlan>>, overrides: Record<string, unknown> = {}) {
  const observed = { files: [{ name: 'packages', kind: 'package-state', sha256: '1'.repeat(64), size: 1, value: [{ name: 'demo', version: '1', architecture: 'x86_64' }] }], states: { packages: [{ name: 'demo', version: '1', architecture: 'x86_64' }] } };
  const machine = { architecture: 'x86_64', goarch: 'amd64', goos: 'linux', runtime: 'go1.26' };
  const details = { profileId: 'x86-uefi', operation: 'install' };

  const evidence = { schemaVersion: 1, planId: planRecord.id, testPlanSha256: planRecord.planSha256, cohortId: 'cohort-1', revision: 1, operation: 'install', architecture: 'x86_64',
    candidate: { sha256: 'a'.repeat(64) }, input: { sha256: 'c'.repeat(64) }, artifact: { sha256: 'f'.repeat(64) }, environment: { sha256: await sha256(canonicalJson({ machine, details })), machine, details }, profile: planRecord.profile,
    coverage: planRecord.coverage, command: { sha256: await sha256(canonicalJson(planRecord.commands)) }, result: { startedAt: new Date(0).toISOString(), finishedAt: new Date(1000).toISOString(), exitCode: 0, commands: [{ name: 'state', exitCode: 0, passed: true, stdoutSha256: '2'.repeat(64), stderrSha256: '3'.repeat(64) }] }, observed,
    observedSha256: await sha256(canonicalJson(observed)), workerId: 'worker-1', workerPublicKey: state.publicKey, signature: '', ...overrides };

  const payload = { ...evidence }; delete (payload as { signature?: string }).signature;
  evidence.signature = base64(await crypto.subtle.sign({ name: 'Ed25519' }, state.first.privateKey, new TextEncoder().encode(canonicalJson(payload))));

  return evidence;
}

async function workerRequest(state: Awaited<ReturnType<typeof fixture>>, body: Uint8Array, signatureKey = state.first.privateKey, signature = '') {
  const path = '/api/worker/qualification'; const timestamp = Math.floor(Date.now() / 1000).toString(); const nonce = crypto.randomUUID().replaceAll('-', '').padEnd(32, '0').slice(0, 32);
  const bodySha256 = await sha256(body); const message = new TextEncoder().encode(`POST\n${path}\n${timestamp}\n${nonce}\n${bodySha256}`);
  const signed = signature || base64(await crypto.subtle.sign({ name: 'Ed25519' }, signatureKey, message));

  return new Request(`https://opr.test${path}`, { method: 'POST', body: body as unknown as BodyInit, headers: { 'content-type': 'application/json', 'X-OPR-Worker': 'worker-1', 'X-OPR-Timestamp': timestamp, 'X-OPR-Nonce': nonce, 'X-OPR-Signature': signed } });
}

async function workerPlanRequest(state: Awaited<ReturnType<typeof fixture>>, planId: string) {
  const path = `/api/worker/qualification?planId=${encodeURIComponent(planId)}`; const timestamp = Math.floor(Date.now() / 1000).toString(); const nonce = crypto.randomUUID().replaceAll('-', '').padEnd(32, '0').slice(0, 32);
  const body = new Uint8Array(); const bodySha256 = await sha256(body); const message = new TextEncoder().encode(`GET\n${path}\n${timestamp}\n${nonce}\n${bodySha256}`); const signature = base64(await crypto.subtle.sign({ name: 'Ed25519' }, state.first.privateKey, message));

  return new Request(`https://opr.test${path}`, { method: 'GET', headers: { 'X-OPR-Worker': 'worker-1', 'X-OPR-Timestamp': timestamp, 'X-OPR-Nonce': nonce, 'X-OPR-Signature': signature } });
}

test('qualification plans have stable canonical digests and output sets are order independent', async () => {
  const parsed = await parseQualificationPlan(plan());
  expect(await qualificationPlanDigest(parsed)).toHaveLength(64);
  expect(await outputSetDigest([{ filename: 'b.pkg.tar.zst', sha256: digest }, { filename: 'a.pkg.tar.zst', sha256: digest }])).toBe(
    await outputSetDigest([{ filename: 'a.pkg.tar.zst', sha256: digest }, { filename: 'b.pkg.tar.zst', sha256: digest }])
  );
});

test('reproducibility plans name both retained attempts', async () => {
  await expect(parseQualificationPlan(plan('reproducibility'))).rejects.toThrow('Reproducibility plans must name both retained build attempts.');
});

test('worker qualification endpoint stores only signed plan-bound observations and keeps failures exception-scoped', async () => {
  const state = await fixture();

  try {
    const input = plan(); input.inputSha256 = 'c'.repeat(64); input.artifactSha256 = 'f'.repeat(64); input.coverage.sha256 = await sha256(canonicalJson({ kind: 'member', pkgbase: 'demo', rootSha256: null, releaseId: '4.0.3-rc2', members: ['demo'], artifactSha256: input.artifactSha256 })); input.expectedObservationSha256 = await sha256(canonicalJson({ files: [{ name: 'packages', kind: 'package-state', sha256: '1'.repeat(64), size: 1, value: [{ name: 'demo', version: '1', architecture: 'x86_64' }] }], states: { packages: [{ name: 'demo', version: '1', architecture: 'x86_64' }] } }));
    const machine = { architecture: 'x86_64', goarch: 'amd64', goos: 'linux', runtime: 'go1.26' }; const details = { profileId: 'x86-uefi', operation: 'install' };
    input.environmentSha256 = await sha256(canonicalJson({ machine, details }));
    const planRecord = await createQualificationPlan(state.env, { id: 'github:1', role: 'maintainer', areas: ['system'] }, input);
    await reviewQualificationPlan(state.env, { id: 'github:1', role: 'maintainer', areas: ['system'] }, planRecord.id, 'area', 'fixture');
    await reviewQualificationPlan(state.env, { id: 'github:2', role: 'security', areas: [] }, planRecord.id, 'security', 'fixture');
    const worker = await state.db.prepare('SELECT * FROM workers WHERE id=?').bind('worker-1').first<any>();
    const auth = { worker, timestamp: Math.floor(Date.now() / 1000), nonce: 'a'.repeat(32) };
    const planResponse = await workerQualificationGet({ request: await workerPlanRequest(state, planRecord.id), platform: { env: state.env }, url: new URL(`https://opr.test/api/worker/qualification?planId=${planRecord.id}`) } as any);
    expect(planResponse.status).toBe(200);
    const accepted = await recordNativeQualification(state.env, auth, await signedEvidence(state, planRecord));
    expect(accepted.status).toBe('passed');
    const timestamp = Math.floor(Date.now() / 1000);
    await state.db.batch([
      state.db.prepare("INSERT INTO catalog_packages(pkgbase,current_revision,admitted_revision,created_at,updated_at) VALUES('other',1,1,?,?)").bind(timestamp, timestamp),
      state.db.prepare("INSERT INTO catalog_revisions(pkgbase,revision,manifest_json,manifest_sha256,collection,lane,owner_area,created_by,reason,created_at) VALUES('other',1,'{\"schemaVersion\":1}','b2','core','system','system','github:1','fixture',?)").bind(timestamp),
      state.db.prepare("INSERT INTO cohort_members(cohort_id,revision,pkgbase,catalog_revision,recipe_revision_id) VALUES('cohort-1',1,'other',1,NULL)"),
    ]);
    expect(await qualificationEvidenceForGate(state.db, { cohortId: 'cohort-1', revision: 1, operation: 'install', architecture: 'x86_64', pkgbase: 'demo' })).not.toBeNull();
    expect(await qualificationEvidenceForGate(state.db, { cohortId: 'cohort-1', revision: 1, operation: 'install', architecture: 'x86_64', pkgbase: 'other' })).toBeNull();
    const systemPlan = { ...plan(), coverage: { kind: 'system' as const, pkgbase: null, rootSha256: 'a'.repeat(64), releaseId: '4.0.3-rc2', members: ['demo', 'other'], sha256: 'f'.repeat(64) } }; systemPlan.inputSha256 = 'c'.repeat(64); systemPlan.artifactSha256 = 'f'.repeat(64); systemPlan.coverage.sha256 = await sha256(canonicalJson({ kind: 'system', pkgbase: null, rootSha256: systemPlan.coverage.rootSha256, releaseId: systemPlan.coverage.releaseId, members: ['demo', 'other'], artifactSha256: systemPlan.artifactSha256 }));
    await expect(createQualificationPlan(state.env, { id: 'github:1', role: 'maintainer', areas: ['system'] }, systemPlan)).rejects.toThrow('final owned universe root');
    const endpointBody = new TextEncoder().encode(JSON.stringify(await signedEvidence(state, planRecord)));
    const endpoint = await workerQualificationPost({ request: await workerRequest(state, endpointBody), platform: { env: state.env }, url: new URL('https://opr.test/api/worker/qualification') } as any);
    expect(endpoint.status).toBe(200);

    try { await workerQualificationPost({ request: await workerRequest(state, endpointBody, state.first.privateKey, 'invalid'), platform: { env: state.env }, url: new URL('https://opr.test/api/worker/qualification') } as any); throw new Error('invalid worker signature accepted'); }
    catch (cause) { expect((cause as { status?: number }).status).toBe(401); }

    const invalid = await signedEvidence(state, planRecord); invalid.signature = 'invalid';
    await expect(recordNativeQualification(state.env, auth, invalid)).rejects.toThrow('Invalid qualification evidence signature.');
    const wrongWorker = await signedEvidence(state, planRecord); wrongWorker.workerId = 'worker-2';
    await expect(recordNativeQualification(state.env, auth, wrongWorker)).rejects.toThrow('Qualification evidence worker identity is not current.');
    const wrongCandidate = await signedEvidence(state, planRecord, { candidate: { sha256: '9'.repeat(64) } });
    await expect(recordNativeQualification(state.env, auth, wrongCandidate)).rejects.toThrow('Qualification evidence does not match its reviewed test plan.');
    const failedObserved = { files: [{ name: 'packages', kind: 'package-state', sha256: '1'.repeat(64), size: 1, value: [{ name: 'demo', version: '2', architecture: 'x86_64' }] }], states: { packages: [{ name: 'demo', version: '2', architecture: 'x86_64' }] } };
    const failed = await recordNativeQualification(state.env, auth, await signedEvidence(state, planRecord, { observed: failedObserved, observedSha256: await sha256(canonicalJson(failedObserved)) }));
    expect(failed.status).toBe('not-checked');
    await expect(addQualificationException(state.env, { id: 'github:2', role: 'security', areas: [] }, { evidenceId: failed.id, subjectSha256: '8'.repeat(64), reason: 'fixture exception', expiresAt: Math.floor(Date.now() / 1000) + 60 })).rejects.toThrow('cannot be waived');
  } finally { state.holder.close(); }
});
