import { expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import { asD1, TestD1 } from './d1';
import { sha256 } from '../src/lib/server/db';
import {
  claimPrivateFactoryImage,
  completePrivateFactoryImage,
  dispatchPrivateFactoryImage,
  factoryImageInputSha256,
  factoryImageInputForWorker,
  type FactoryImageCandidate,
} from '../src/lib/server/factory-image-run';
import type { FactoryImageEnvironment } from '../src/lib/server/factory-image-run';
import { authorizeFactoryImageCandidate } from '../src/lib/server/factory-private-image';
import { reserveFactoryAttempt, startFactoryRun } from '../src/lib/server/factory-runs';

const digest = (value: string) => value.repeat(64);

class MemoryR2 {
  readonly values = new Map<string, Uint8Array>();
  async head(key: string) { const value = this.values.get(key); return value ? { size: value.byteLength } : null; }
  async get(key: string) { const value = this.values.get(key); return value ? { size: value.byteLength, body: new Response(value.buffer as ArrayBuffer).body } : null; }
  async put(key: string, value: Uint8Array) { this.values.set(key, value); return {}; }
}

function database() {
  return new TestD1(`CREATE TABLE builds(id TEXT PRIMARY KEY,revision_id TEXT,architecture TEXT,status TEXT,created_at INTEGER,UNIQUE(revision_id,architecture));
    CREATE TABLE workers(id TEXT PRIMARY KEY,status TEXT,accepting_jobs INTEGER,removed_at INTEGER);
    CREATE TABLE audit_events(actor TEXT,action TEXT,target TEXT,detail TEXT,created_at INTEGER);
    ${readFileSync('migrations/0052_factory_runs.sql', 'utf8')}
    ${readFileSync('migrations/0057_factory_image_jobs.sql', 'utf8')}`);
}

async function candidate(bucket: MemoryR2): Promise<FactoryImageCandidate> {
  const ref = async (name: string, bytes: string) => {
    const value = new TextEncoder().encode(bytes); const sha = await sha256(value); const key = `private/test/${name}`;
    bucket.values.set(key, value); return { key, sha256: sha, size: value.byteLength, filename: name };
  };
  return {
    id: 'candidate-1', architecture: 'x86_64', kind: 'system', profileId: 'x86_64-uefi', nativePlanId: 'plan-1',
    profile: await ref('profile.json', '{}'), candidateLock: await ref('candidate-lock.json', '{}'), candidateLockSignature: await ref('candidate-lock.sig', 'sig'),
    nativePlan: await ref('native-plan.json', '{}'), nativePlanSignature: await ref('native-plan.sig', 'sig'), trustedAuthorityKey: await ref('authority.asc', 'key'),
    builder: await ref('build-system-image.sh', '#!/bin/sh\nexit 0'), trustedAuthorityFingerprint: 'f'.repeat(40), sourceDateEpoch: 1, outputFilename: 'candidate.raw',
  };
}

test('private image queue binds signed inputs to a fenced worker job', async () => {
  const db = database(); const bucket = new MemoryR2(); const env = { DB: asD1(db), ARTIFACTS: bucket } as unknown as FactoryImageEnvironment;
  try {
    const value = await candidate(bucket); const policy = { executionScope: 'private', image: value.id };
    const run = await startFactoryRun(env.DB, { id: 'image-run', targetKind: 'system-image', targetId: 'image-definition', unitKey: 'x86_64', policy, createdBy: 'factory' });
    const inputSha256 = await factoryImageInputSha256(value);
    const attempt = await reserveFactoryAttempt(env.DB, { runId: run.id, reservationKey: 'attempt:1', candidateSha256: digest('a'), inputSha256, candidate: value, policy });
    const queued = await dispatchPrivateFactoryImage(env, run.id, attempt, value);
    expect(queued.dispatchId).toMatch(/^factory-image-/);
    await env.DB.prepare("INSERT INTO workers(id,status,accepting_jobs,removed_at) VALUES('worker-1','active',1,NULL)").run();
    const worker = { id: 'worker-1', name: 'native', architecture: 'x86_64', public_key: '', status: 'active', enrolled_at: 1, last_seen_at: null, daemon_version: null, runtime: 'podman', capabilities_json: '["factory-image-v1"]', accepting_jobs: 1, paused_at: null, removed_at: null } as const;
    const claimed = await claimPrivateFactoryImage(env.DB, worker);
    expect(claimed?.id).toBe(queued.dispatchId);
    expect(claimed?.candidate.id).toBe(value.id);
    const input = await factoryImageInputForWorker(env, { worker, timestamp: Math.floor(Date.now() / 1000), nonce: 'n' }, claimed!.id, claimed!.leaseToken, 'profile');
    expect(input.ref.sha256).toBe(value.profile.sha256);
    expect(await new Response(input.body).text()).toBe('{}');
  } finally { db.close(); }
});

test('private image dispatch rejects a candidate whose reserved input lock differs', async () => {
  const db = database(); const bucket = new MemoryR2(); const env = { DB: asD1(db), ARTIFACTS: bucket } as unknown as FactoryImageEnvironment;
  try {
    const value = await candidate(bucket); const policy = { executionScope: 'private' };
    const run = await startFactoryRun(env.DB, { id: 'image-run-2', targetKind: 'system-image', targetId: 'image-definition', unitKey: 'x86_64', policy, createdBy: 'factory' });
    const attempt = await reserveFactoryAttempt(env.DB, { runId: run.id, reservationKey: 'attempt:1', candidateSha256: digest('b'), inputSha256: digest('c'), candidate: value, policy });
    await expect(dispatchPrivateFactoryImage(env, run.id, attempt, value)).rejects.toThrow('inputs differ');
  } finally { db.close(); }
});

test('private image completion requires worker-signed observed evidence and finishes the exact attempt', async () => {
  const db = database(); const bucket = new MemoryR2(); const env = { DB: asD1(db), ARTIFACTS: bucket } as unknown as FactoryImageEnvironment;
  try {
    const value = await candidate(bucket); const policy = { executionScope: 'private', image: value.id };
    const run = await startFactoryRun(env.DB, { id: 'image-run-3', targetKind: 'system-image', targetId: 'image-definition', unitKey: 'x86_64', policy, createdBy: 'factory' });
    const inputSha256 = await factoryImageInputSha256(value);
    const attempt = await reserveFactoryAttempt(env.DB, { runId: run.id, reservationKey: 'attempt:1', candidateSha256: digest('d'), inputSha256, candidate: value, policy });
    const queued = await dispatchPrivateFactoryImage(env, run.id, attempt, value);
    const keyPair = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
    const publicKey = new Uint8Array(await crypto.subtle.exportKey('raw', keyPair.publicKey));
    const publicKeyText = btoa(String.fromCharCode(...publicKey));
    const worker = { id: 'worker-3', name: 'native', architecture: 'x86_64', public_key: publicKeyText, status: 'active', enrolled_at: 1, last_seen_at: null, daemon_version: null, runtime: 'podman', capabilities_json: '["factory-image-v1"]', accepting_jobs: 1, paused_at: null, removed_at: null } as const;
    await env.DB.prepare('INSERT INTO workers(id,status,accepting_jobs,removed_at) VALUES(?,?,?,?)').bind(worker.id, worker.status, worker.accepting_jobs, worker.removed_at).run();
    const claimed = await claimPrivateFactoryImage(env.DB, worker);
    const artifact = { key: 'private/factory-images/image.raw', sha256: await sha256(new TextEncoder().encode('test')), size: 4, filename: value.outputFilename };
    bucket.values.set(artifact.key, new TextEncoder().encode('test'));
    await env.DB.prepare('UPDATE factory_image_jobs SET artifact_key=?,artifact_sha256=?,artifact_size=?,artifact_filename=? WHERE id=?').bind(artifact.key, artifact.sha256, artifact.size, artifact.filename, queued.dispatchId).run();
    const evidence = { schemaVersion: 1, kind: 'factory-image-result', jobId: claimed!.id, runId: run.id, attempt: 1, candidateId: value.id, architecture: 'x86_64', imageKind: 'system', imageRef: null, inputSha256, profileSha256: value.profile.sha256, nativePlanSha256: value.nativePlan.sha256, artifact, builderSha256: value.builder.sha256, observed: { built: true } };
    const evidenceText = JSON.stringify(evidence);
    const signature = await crypto.subtle.sign({ name: 'Ed25519' }, keyPair.privateKey, new TextEncoder().encode(evidenceText));
    const completed = await completePrivateFactoryImage(env, worker, claimed!.id, { leaseToken: claimed!.leaseToken, status: 'succeeded', evidence: evidenceText, evidenceSignature: btoa(String.fromCharCode(...new Uint8Array(signature))) });
    expect(completed.status).toBe('succeeded');
    expect((await env.DB.prepare('SELECT status,successful_attempt FROM factory_runs WHERE id=?').bind(run.id).first<{ status: string; successful_attempt: number }>())).toEqual({ status: 'succeeded', successful_attempt: 1 });
  } finally { db.close(); }
});

test('image admission rejects self-signed authority and stale native plans before queueing', async () => {
  const db = database(); const bucket = new MemoryR2(); const base = { DB: asD1(db), ARTIFACTS: bucket } as unknown as FactoryImageEnvironment;
  try {
    db.exec(`CREATE TABLE cohorts(id TEXT PRIMARY KEY,current_revision INTEGER); CREATE TABLE native_qualification_plans(id TEXT PRIMARY KEY,cohort_id TEXT,revision INTEGER,operation TEXT,architecture TEXT,candidate_sha256 TEXT,input_sha256 TEXT,artifact_sha256 TEXT,environment_sha256 TEXT,profile_id TEXT,profile_sha256 TEXT,coverage_kind TEXT,coverage_pkgbase TEXT,coverage_release_id TEXT,coverage_root_sha256 TEXT,coverage_sha256 TEXT,coverage_json TEXT,plan_json TEXT,plan_sha256 TEXT,created_by TEXT,created_at INTEGER); CREATE TABLE native_qualification_plan_reviews(plan_id TEXT,kind TEXT,actor TEXT,reason TEXT,created_at INTEGER,PRIMARY KEY(plan_id,kind)); CREATE TABLE team_memberships(github_id TEXT,team TEXT);`);
    const value = await candidate(bucket); const profileText = '{}'; const profileSha = await sha256(profileText); const qualificationPlan = { schemaVersion: 1, cohortId: 'cohort-1', revision: 1, operation: 'boot', architecture: 'x86_64' }; const qualificationPlanText = JSON.stringify(qualificationPlan); const qualificationPlanSha = await sha256(qualificationPlanText);
    const plan = { kind: 'factory-image-native-plan', status: 'reviewed', operation: 'boot', nativePlanId: 'plan-1', qualificationPlanSha256: qualificationPlanSha, candidateId: value.id, architecture: 'x86_64', profileSha256: profileSha, inputLockSha256: '2'.repeat(64), ownedUniverseSha256: '1'.repeat(64) }; const planText = JSON.stringify(plan); const planSha = await sha256(planText);
    const planKey = value.nativePlan.key; bucket.values.set(planKey, new TextEncoder().encode(planText)); value.nativePlan = { ...value.nativePlan, sha256: planSha, size: planText.length };
    db.prepare('INSERT INTO cohorts(id,current_revision) VALUES(?,?)').bind('cohort-1', 1).run();
    db.prepare(`INSERT INTO native_qualification_plans(id,cohort_id,revision,operation,architecture,candidate_sha256,input_sha256,artifact_sha256,environment_sha256,profile_id,profile_sha256,coverage_kind,coverage_release_id,coverage_sha256,coverage_json,plan_json,plan_sha256,created_by,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).bind('plan-1', 'cohort-1', 1, 'boot', 'x86_64', '3'.repeat(64), '2'.repeat(64), '4'.repeat(64), '5'.repeat(64), value.profileId, profileSha, 'system', 'release-1', '6'.repeat(64), '{}', qualificationPlanText, qualificationPlanSha, 'github:area', 1).run();
    db.prepare("INSERT INTO native_qualification_plan_reviews(plan_id,kind,actor,reason,created_at) VALUES('plan-1','area','github:area','review',1),('plan-1','security','github:security','review',1)").run();
    db.prepare("INSERT INTO team_memberships(github_id,team) VALUES('area','development'),('security','security')").run();
    const env = { ...base, PACKAGE_SIGNING_FINGERPRINT: 'f'.repeat(40), PACKAGE_SIGNING_PUBLIC_KEY_R2_KEY: value.trustedAuthorityKey.key, FACTORY_IMAGE_BUILDER_SHA256: value.builder.sha256 };
    await expect(authorizeFactoryImageCandidate(env, value)).resolves.toMatchObject({ nativePlanId: 'plan-1' });
    await expect(authorizeFactoryImageCandidate(env, { ...value, trustedAuthorityFingerprint: 'e'.repeat(40) })).rejects.toThrow('authority');
    await expect(authorizeFactoryImageCandidate(env, { ...value, builder: { ...value.builder, sha256: 'e'.repeat(64) } })).rejects.toThrow('authority');
  } finally { db.close(); }
});
