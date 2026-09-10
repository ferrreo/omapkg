import { expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import { asD1, TestD1 } from './d1';
import { sha256 } from '../src/lib/server/db';
import { canonicalJson } from '../src/lib/canonical-json';
import {
  claimPrivateFactoryImage,
  completePrivateFactoryImage,
  dispatchPrivateFactoryImage,
  factoryImageInputSha256,
  factoryImageInputForWorker,
  type FactoryImageCandidate,
} from '../src/lib/server/factory-image-run';
import type { FactoryImageEnvironment } from '../src/lib/server/factory-image-run';
import { authorizeFactoryImageCandidate, latestPrivateFactoryImageCandidate, readVerifiedFactoryImageDockerfile, retainFactoryImageDockerfileRepair, startPrivateFactoryImageWorkflow } from '../src/lib/server/factory-private-image';
import { finishFactoryAttempt, reserveFactoryAttempt, startFactoryRun } from '../src/lib/server/factory-runs';
import { actions as factoryRunActions } from '../src/routes/maintain/factory-runs/[id]/+page.server';

const digest = (value: string) => value.repeat(64);

class MemoryR2 {
  readonly values = new Map<string, Uint8Array>();
  async head(key: string) { const value = this.values.get(key); return value ? { size: value.byteLength } : null; }
  async get(key: string) { const value = this.values.get(key); return value ? { size: value.byteLength, body: new Response(value.buffer as ArrayBuffer).body } : null; }
  async put(key: string, value: Uint8Array) { this.values.set(key, value); return {}; }
}

interface RetainedFactoryImageFixture {
  completion: { leaseToken: string; status: string; evidence: string; evidenceSignature: string };
  candidate: FactoryImageCandidate;
  jobId: string;
  runId: string;
  attempt: number;
  leaseToken: string;
  inputSha256: string;
  workerId: string;
  workerPublicKey: string;
  artifactKey: string;
  artifactSha256: string;
  artifactSize: number;
  artifactFile: string;
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
    id: 'candidate-1', architecture: 'x86_64', kind: 'system', profileId: 'x86_64-uefi', constructionPolicySha256: 'a'.repeat(64),
    profile: await ref('profile.json', '{}'), candidateLock: await ref('candidate-lock.json', '{}'), candidateLockSignature: await ref('candidate-lock.sig', 'sig'),
    nativePlan: await ref('native-plan.json', '{}'), nativePlanSignature: await ref('native-plan.sig', 'sig'), trustedAuthorityKey: await ref('authority.asc', 'key'),
    builder: await ref('build-system-image.sh', '#!/bin/sh\nexit 0'), trustedAuthorityFingerprint: 'f'.repeat(40), sourceDateEpoch: 1, outputFilename: 'candidate.raw',
  };
}

async function admittedCandidate(bucket: MemoryR2, policy: unknown): Promise<FactoryImageCandidate> {
  const value = await candidate(bucket);
  const policySha256 = await sha256(canonicalJson(policy));
  const proof = { kind: 'factory-image-construction-proof', status: 'reviewed', runPolicySha256: policySha256, candidateId: value.id, architecture: value.architecture, profileSha256: value.profile.sha256, inputLockSha256: '2'.repeat(64) };
  const proofText = JSON.stringify(proof);
  bucket.values.set(value.nativePlan.key, new TextEncoder().encode(proofText));
  value.nativePlan = { ...value.nativePlan, sha256: await sha256(proofText), size: proofText.length };
  value.constructionPolicySha256 = policySha256;
  return value;
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
    const jobRow = await env.DB.prepare('SELECT run_id,attempt,lease_token FROM factory_image_jobs WHERE id=?').bind(claimed!.id).first<{ run_id: string; attempt: number; lease_token: string }>();
    const attemptRow = await env.DB.prepare('SELECT lease_token FROM factory_run_attempts WHERE run_id=? AND attempt=?').bind(jobRow!.run_id, jobRow!.attempt).first<{ lease_token: string }>();
    await finishFactoryAttempt(env.DB, jobRow!.run_id, jobRow!.attempt, attemptRow!.lease_token, { status: 'succeeded', artifact: { ...artifact, evidence, evidenceSha256: await sha256(evidenceText) } });
    expect((await env.DB.prepare('SELECT status,successful_attempt FROM factory_runs WHERE id=?').bind(run.id).first<{ status: string; successful_attempt: number }>())).toEqual({ status: 'succeeded', successful_attempt: 1 });
  } finally { db.close(); }
});

test('image intervention uses latest retained candidate, approved policy and human source run', async () => {
  const db = database(); const bucket = new MemoryR2();
  const policy = { executionScope: 'private', network: 'disabled' };
  const value = await admittedCandidate(bucket, policy);
  const run = await startFactoryRun(asD1(db), { id: 'image-intervention-source', targetKind: 'image', targetId: 'image-definition', unitKey: 'x86_64', policy, createdBy: 'github:7' });
  await db.prepare("UPDATE factory_runs SET status='needs-human-intervention',attempt_count=3,current_attempt=3 WHERE id=?").bind(run.id).run();
  const inputSha256 = await factoryImageInputSha256(value);
  const older = { ...value, id: 'candidate-older' };
  const latest = { ...value };
  await db.prepare(`INSERT INTO factory_image_jobs(id,run_id,attempt,candidate_id,architecture,kind,input_sha256,candidate_json,status,error,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)`)
    .bind('image-job-1', run.id, 1, older.id, older.architecture, older.kind, inputSha256, JSON.stringify(older), 'failed', 'first candidate failed', 1).run();
  await db.prepare(`INSERT INTO factory_image_jobs(id,run_id,attempt,candidate_id,architecture,kind,input_sha256,candidate_json,status,error,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)`)
    .bind('image-job-3', run.id, 3, latest.id, latest.architecture, latest.kind, inputSha256, JSON.stringify(latest), 'failed', 'last candidate failed', 3).run();
  let workflowBody: Record<string, unknown> | null = null;
  const pipeline = { fetch: async (request: Request) => { workflowBody = await request.json() as Record<string, unknown>; return Response.json({ workflowId: workflowBody.workflowId }); } };
  const actor = { id: 'github:42', role: 'admin' as const, areas: [] };
  const event = {
    request: new Request('https://omapkg.example/maintain/factory-runs/image-intervention-source', { method: 'POST', body: new URLSearchParams({ reason: 'Review latest image candidate and retry.' }) }),
    params: { id: run.id },
    locals: { actor }, platform: { env: { DB: asD1(db), ARTIFACTS: bucket, PIPELINE: pipeline, PACKAGE_SIGNING_FINGERPRINT: 'f'.repeat(40), PACKAGE_SIGNING_PUBLIC_KEY_R2_KEY: value.trustedAuthorityKey.key, FACTORY_IMAGE_BUILDER_SHA256: value.builder.sha256 } },
  } as any;
  try {
    const result = await (factoryRunActions.intervene as any)(event);
    expect(result).toMatchObject({ success: true });
    const successorId = (result as { successorId: string }).successorId;
    expect(successorId).toBeTruthy();
    const successor = await db.prepare('SELECT source_run_id,created_by,policy_json FROM factory_runs WHERE id=?').bind(successorId).first<{ source_run_id: string; created_by: string; policy_json: string }>();
    expect(successor).toEqual({ source_run_id: run.id, created_by: actor.id, policy_json: canonicalJson(policy) });
    expect(workflowBody).toMatchObject({ factoryRunId: successorId, targetId: run.targetId, unitKey: run.unitKey, policy });
    expect(((workflowBody as unknown as Record<string, unknown>).imageCandidate as FactoryImageCandidate).id).toBe(latest.id);
  } finally { db.close(); }
});

test('paged cohort coordinator intervention points to member runs instead of requesting a package revision', async () => {
  const db = database();
  const run = await startFactoryRun(asD1(db), { id: 'cohort-coordinator', targetKind: 'cohort', targetId: 'cohort-1', unitKey: 'revision:7', policy: { cohortId: 'cohort-1', cohortRevision: 7 }, createdBy: 'github:7' });
  await db.prepare("UPDATE factory_runs SET status='needs-human-intervention',attempt_count=3,current_attempt=3 WHERE id=?").bind(run.id).run();
  const event = {
    request: new Request('https://omapkg.example/maintain/factory-runs/cohort-coordinator', { method: 'POST', body: new URLSearchParams({ reason: 'Retry coordinator.' }) }),
    params: { id: run.id }, locals: { actor: { id: 'github:42', role: 'admin' as const, areas: [] } }, platform: { env: { DB: asD1(db) } },
  } as any;
  try {
    const result = await (factoryRunActions.intervene as any)(event);
    expect(result).toMatchObject({ status: 409, data: { error: expect.stringContaining('coordinator') } });
  } finally { db.close(); }
});

test('OCI Dockerfile repair retains changed bytes and regenerates candidate proof bindings', async () => {
  const db = database(); const bucket = new MemoryR2();
  const policy = { executionScope: 'private', network: 'disabled' };
  const value = await admittedCandidate(bucket, policy);
  value.kind = 'oci'; value.imageRef = 'localhost/repair:latest';
  const contextBytes = new TextEncoder().encode('context'); bucket.values.set('private/test/context.tar', contextBytes);
  const originalDockerfile = new TextEncoder().encode('FROM scratch\nCOPY payload.txt /payload.txt\n'); bucket.values.set('private/test/Dockerfile', originalDockerfile);
  value.context = { key: 'private/test/context.tar', sha256: await sha256(contextBytes), size: contextBytes.byteLength, filename: 'context.tar' };
  value.dockerfile = { key: 'private/test/Dockerfile', sha256: await sha256(originalDockerfile), size: originalDockerfile.byteLength, filename: 'Dockerfile' };
  const lock = { schemaVersion: 1, authority: 'factory-candidate-v1', candidate: { executionScope: 'private', id: value.id, inputLockSha256: '2'.repeat(64), nativePlanSha256: value.nativePlan.sha256 }, architecture: value.architecture };
  const lockBytes = new TextEncoder().encode(JSON.stringify(lock)); bucket.values.set(value.candidateLock.key, lockBytes);
  value.candidateLock = { ...value.candidateLock, sha256: await sha256(lockBytes), size: lockBytes.byteLength };
  const env = { DB: asD1(db), ARTIFACTS: bucket, PACKAGE_SIGNING_FINGERPRINT: 'f'.repeat(40), PACKAGE_SIGNING_PUBLIC_KEY_R2_KEY: value.trustedAuthorityKey.key, FACTORY_IMAGE_BUILDER_SHA256: value.builder.sha256 } as unknown as FactoryImageEnvironment;
  try {
    expect(await readVerifiedFactoryImageDockerfile(env, value)).toBe(new TextDecoder().decode(originalDockerfile));
    const repairedText = 'FROM scratch\nCOPY repaired.txt /payload.txt\n';
    const repaired = await retainFactoryImageDockerfileRepair(env, { runId: 'repair-run', attempt: 2, candidate: value, policy, dockerfile: repairedText });
    expect(repaired.id).toBe('candidate-1-repair-2');
    expect(repaired.dockerfile?.sha256).toBe(await sha256(new TextEncoder().encode(repairedText)));
    expect(new TextDecoder().decode(await new Response((await bucket.get(repaired.dockerfile!.key))!.body).arrayBuffer().then((bytes) => new Uint8Array(bytes)))).toBe(repairedText);
    const proof = JSON.parse(new TextDecoder().decode(await new Response((await bucket.get(repaired.nativePlan.key))!.body).arrayBuffer())) as { candidateId: string };
    const repairedLock = JSON.parse(new TextDecoder().decode(await new Response((await bucket.get(repaired.candidateLock.key))!.body).arrayBuffer())) as { candidate: { id: string; nativePlanSha256: string } };
    expect(proof.candidateId).toBe(repaired.id);
    expect(repairedLock.candidate).toMatchObject({ id: repaired.id, nativePlanSha256: repaired.nativePlan.sha256 });
  } finally { db.close(); }
});

const retainedBridgeTest = process.env.OPR_FACTORY_IMAGE_E2E_FIXTURE ? test : test.skip;
retainedBridgeTest('production completion accepts retained Go OCI evidence and artifact', async () => {
  const fixturePath = process.env.OPR_FACTORY_IMAGE_E2E_FIXTURE!;
  const fixture = JSON.parse(readFileSync(fixturePath, 'utf8')) as RetainedFactoryImageFixture;
  const archive = new Uint8Array(readFileSync(`${fixturePath.slice(0, fixturePath.lastIndexOf('/'))}/${fixture.artifactFile}`));
  const db = database(); const bucket = new MemoryR2(); const env = { DB: asD1(db), ARTIFACTS: bucket } as unknown as FactoryImageEnvironment;
  const timestamp = Math.floor(Date.now() / 1000); const leaseExpiry = timestamp + 600;
  const candidateJSON = JSON.stringify(fixture.candidate);
  const artifact = { key: fixture.artifactKey, sha256: fixture.artifactSha256, size: fixture.artifactSize, filename: fixture.candidate.outputFilename };
  const worker = { id: fixture.workerId, name: 'go-oci-e2e', architecture: fixture.candidate.architecture, public_key: fixture.workerPublicKey, status: 'active', enrolled_at: timestamp, last_seen_at: timestamp, daemon_version: 'go-e2e', runtime: 'podman', capabilities_json: '["factory-image-v1"]', accepting_jobs: 1, paused_at: null, removed_at: null } as const;
  try {
    await env.DB.prepare(`INSERT INTO workers(id,status,accepting_jobs,removed_at) VALUES(?,?,?,?)`).bind(worker.id, worker.status, worker.accepting_jobs, worker.removed_at).run();
    await env.DB.prepare(`INSERT INTO factory_runs(id,target_kind,target_id,unit_key,execution_scope,status,max_attempts,attempt_count,current_attempt,policy_json,lease_token,lease_expires_at,created_by,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
      .bind(fixture.runId, 'image', 'go-oci-e2e', fixture.candidate.architecture, 'private', 'running', 3, fixture.attempt, fixture.attempt, '{}', fixture.leaseToken, leaseExpiry, 'go-e2e', timestamp, timestamp).run();
    await env.DB.prepare(`INSERT INTO factory_run_attempts(id,run_id,attempt,reservation_key,status,candidate_sha256,input_sha256,architecture,candidate_json,lease_token,lease_expires_at,started_at,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
      .bind(`${fixture.runId}-attempt-${fixture.attempt}`, fixture.runId, fixture.attempt, `go-e2e:${fixture.attempt}`, 'running', 'a'.repeat(64), fixture.inputSha256, fixture.candidate.architecture, candidateJSON, fixture.leaseToken, leaseExpiry, timestamp, timestamp, timestamp).run();
    await env.DB.prepare(`INSERT INTO factory_image_jobs(id,run_id,attempt,candidate_id,architecture,kind,input_sha256,candidate_json,status,worker_id,lease_token,lease_expires_at,artifact_key,artifact_sha256,artifact_size,artifact_filename,created_at,started_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
      .bind(fixture.jobId, fixture.runId, fixture.attempt, fixture.candidate.id, fixture.candidate.architecture, fixture.candidate.kind, fixture.inputSha256, candidateJSON, 'leased', worker.id, fixture.leaseToken, leaseExpiry, artifact.key, artifact.sha256, artifact.size, artifact.filename, timestamp, timestamp).run();
    bucket.values.set(artifact.key, archive);
    const completed = await completePrivateFactoryImage(env, worker, fixture.jobId, fixture.completion);
    expect(completed).toMatchObject({ status: 'succeeded', artifact });
    expect(await env.DB.prepare('SELECT status,evidence_sha256,artifact_sha256,artifact_size FROM factory_image_jobs WHERE id=?').bind(fixture.jobId).first()).toMatchObject({ status: 'succeeded', artifact_sha256: artifact.sha256, artifact_size: artifact.size });
  } finally { db.close(); }
});

test('image admission rejects self-signed authority and stale native plans before queueing', async () => {
  const db = database(); const bucket = new MemoryR2(); const base = { DB: asD1(db), ARTIFACTS: bucket } as unknown as FactoryImageEnvironment;
  try {
    const value = await candidate(bucket); const policy = { executionScope: 'private', network: 'disabled', target: { id: 'image-definition', architecture: 'x86_64' } }; const policySha = await sha256(canonicalJson(policy));
    value.constructionPolicySha256 = policySha;
    const proof = { kind: 'factory-image-construction-proof', status: 'reviewed', runPolicySha256: policySha, candidateId: value.id, architecture: 'x86_64', profileSha256: value.profile.sha256, inputLockSha256: '2'.repeat(64) }; const proofText = JSON.stringify(proof);
    const planKey = value.nativePlan.key; bucket.values.set(planKey, new TextEncoder().encode(proofText)); value.nativePlan = { ...value.nativePlan, sha256: await sha256(proofText), size: proofText.length };
    const env = { ...base, PACKAGE_SIGNING_FINGERPRINT: 'f'.repeat(40), PACKAGE_SIGNING_PUBLIC_KEY_R2_KEY: value.trustedAuthorityKey.key, FACTORY_IMAGE_BUILDER_SHA256: value.builder.sha256 };
    await expect(authorizeFactoryImageCandidate(env, value, policy)).resolves.toMatchObject({ constructionPolicySha256: policySha });
    await expect(authorizeFactoryImageCandidate(env, { ...value, trustedAuthorityFingerprint: 'e'.repeat(40) }, policy)).rejects.toThrow('authority');
    await expect(authorizeFactoryImageCandidate(env, { ...value, builder: { ...value.builder, sha256: 'e'.repeat(64) } }, policy)).rejects.toThrow('authority');
  } finally { db.close(); }
});
