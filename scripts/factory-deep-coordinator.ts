#!/usr/bin/env bun
import { spawnSync } from 'node:child_process';
import { generateKeyPairSync } from 'node:crypto';
import { mkdirSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { parseArgs } from 'node:util';
import { canonicalJson } from '../src/lib/canonical-json';
import type { Revision, Worker } from '../src/lib/model';
import { sha256 } from '../src/lib/server/db';
import { createFactoryDossier } from '../src/lib/server/factory-dossier';
import { uploadAbiEvidence } from '../src/lib/server/build-abi-evidence';
import { finishFactoryAttempt, getFactoryRun, listFactoryAttempts, reserveFactoryAttempt, runFactoryRepairLoop, startFactoryRun } from '../src/lib/server/factory-runs';
import { queuePrivateFactoryBuilds } from '../src/lib/server/factory-private-build';
import { claimJob, completeJob, uploadArtifact, type ArtifactReference, type WorkerJob, type WorkerMetadata } from '../src/lib/server/workers';
import { asD1, TestD1 } from '../tests/d1';
import type { Env } from '../src/lib/server/env';

const { values } = parseArgs({ options: {
  result: { type: 'string' },
  'output-dir': { type: 'string' },
  'source-root': { type: 'string' },
} });

if (!values.result || !values['output-dir']) throw new Error('Usage: bun scripts/factory-deep-coordinator.ts --result FILE --output-dir DIR [--source-root DIR]');

const resultPath = resolve(values.result);
const outputDir = resolve(values['output-dir']);
const sourceRoot = resolve(values['source-root'] ?? process.env.OPR_DEEP_SOURCE_ROOT ?? join(dirname(resultPath), 'deep-factory-source'));
const imageRef = process.env.OPR_DEEP_BUILDER_IMAGE ?? '';
const runtimeImage = process.env.OPR_DEEP_RUNTIME_IMAGE ?? '';
const runtime = process.env.OPR_DEEP_RUNTIME === 'docker' ? 'docker' : 'podman';
const digestPattern = /^sha256:[0-9a-f]{64}$/;

if (!/^\S+@sha256:[0-9a-f]{64}$/.test(imageRef) || !/^\S+@sha256:[0-9a-f]{64}$/.test(runtimeImage)) {
  throw new Error('OPR_DEEP_BUILDER_IMAGE and OPR_DEEP_RUNTIME_IMAGE must be digest pinned');
}

const imageDigest = imageRef.slice(imageRef.lastIndexOf('@') + 1);
if (!digestPattern.test(imageDigest)) throw new Error('OPR_DEEP_BUILDER_IMAGE digest is invalid');

const requestId = 'deep-factory-request';
const revisionId = 'deep-factory-revision';
const runId = 'deep-factory-run';
const workerId = 'deep-test-worker';
const exhaustionRunId = 'deep-factory-exhaustion';
const sourceName = 'fixture.txt';
const sourceUrl = 'https://127.0.0.1/deep/fixture.txt';
const sourceBytes = new TextEncoder().encode('factory deep fixture\n');

const recipeTemplate = `pkgname=opr-deep-fixture
pkgver=1.0
pkgrel=1
arch=('x86_64')
license=('MIT')
source=('fixture.txt')
sha256sums=('SOURCE_SHA')

package() {
  install -Dm644 fixture.txt "$pkgdir/usr/share/opr-deep-fixture/fixture.txt"
}
`;

class DeepMemoryR2 {
  private readonly objects = new Map<string, { bytes: Uint8Array; metadata: Record<string, string> }>();

  private object(key: string) {
    const saved = this.objects.get(key);
    if (!saved) return null;
    const bytes = saved.bytes.slice();
    return {
      size: bytes.byteLength,
      etag: key,
      httpEtag: `"${key}"`,
      customMetadata: saved.metadata,
      httpMetadata: {},
      body: new Response(bytes.buffer as ArrayBuffer).body,
      arrayBuffer: async () => bytes.buffer as ArrayBuffer,
      text: async () => new TextDecoder().decode(bytes),
    };
  }

  head(key: string) { return Promise.resolve(this.object(key)); }
  async get(key: string) { return this.object(key); }

  async put(key: string, value: ArrayBuffer | ArrayBufferView | ReadableStream<Uint8Array>, options?: R2PutOptions) {
    const bytes = value instanceof ReadableStream
      ? new Uint8Array(await new Response(value).arrayBuffer())
      : value instanceof ArrayBuffer
        ? new Uint8Array(value)
        : new Uint8Array(value.buffer as ArrayBuffer, value.byteOffset, value.byteLength);
    if (options?.sha256 && await sha256(bytes) !== options.sha256) throw new Error('artifact checksum mismatch');
    this.objects.set(key, { bytes: bytes.slice(), metadata: { ...(options?.customMetadata ?? {}), sha256: options?.sha256 ?? await sha256(bytes) } });
    return this.object(key);
  }

  async delete(key: string) { this.objects.delete(key); }
}

function rawEd25519Keys() {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const publicDer = Buffer.from(publicKey.export({ format: 'der', type: 'spki' }));
  const privateDer = Buffer.from(privateKey.export({ format: 'der', type: 'pkcs8' }));
  const publicBytes = publicDer.subarray(-32);
  const privateBytes = Buffer.concat([privateDer.subarray(-32), publicBytes]);
  return { publicKey: Buffer.from(publicBytes).toString('base64'), privateKey: privateBytes.toString('base64') };
}

function migrate(db: TestD1): void {
  for (const filename of readdirSync('migrations').filter((item) => item.endsWith('.sql')).sort()) db.exec(readFileSync(join('migrations', filename), 'utf8'));
}

function runGoFixture(jobPath: string): string {
  const childEnv: NodeJS.ProcessEnv = {
    PATH: process.env.PATH ?? '/usr/local/bin:/usr/bin:/bin',
    HOME: process.env.HOME ?? sourceRoot,
    TMPDIR: process.env.TMPDIR ?? sourceRoot,
    GOPROXY: 'off', GOSUMDB: 'off', GOTOOLCHAIN: 'local', CI: '1',
    ...(process.env.XDG_DATA_HOME ? { XDG_DATA_HOME: process.env.XDG_DATA_HOME } : {}),
    ...(process.env.XDG_RUNTIME_DIR ? { XDG_RUNTIME_DIR: process.env.XDG_RUNTIME_DIR } : {}),
    OPR_DEEP_BUILDER_IMAGE: imageRef,
    OPR_DEEP_RUNTIME_IMAGE: runtimeImage,
    OPR_DEEP_RUNTIME: runtime,
    OPR_DEEP_RESULT: resultPath,
    OPR_DEEP_SOURCE_ROOT: sourceRoot,
    OPR_DEEP_JOB_FILE: jobPath,
  };
  const child = spawnSync('go', ['test', '-run', '^TestDeepFactoryNativeFixture$', '-count=1', '-v'], {
    cwd: resolve('worker'), env: childEnv, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], timeout: 30 * 60 * 1000,
  });
  const output = `${child.stdout ?? ''}\n${child.stderr ?? ''}`.trim();
  if (child.error) throw child.error;
  if (child.status !== 0) throw new Error(`deep native factory build failed (${child.status ?? 'unknown'}): ${output.slice(-8_000)}`);
  return output;
}

async function seedFixture(db: TestD1, keys: { publicKey: string }, sourceSha256: string, recipeText: string, manifestSha256: string): Promise<void> {
  const timestamp = 1_700_000_000;
  const recipeSha256 = await sha256(recipeText);
  db.prepare(`INSERT INTO requests(id,name,upstream_url,source_kind,area,requested_by,status,created_at,updated_at,factory_run_id)
    VALUES(?,?,?,?,?,?,?,?,?,?)`).bind(requestId, 'opr-deep-fixture', sourceUrl, 'archive', 'development', 'deep-test', 'review', timestamp, timestamp, runId).run();
  db.prepare(`INSERT INTO revisions(id,request_id,version,recipe,recipe_sha256,public_recipe,public_recipe_sha256,manifest_sha256,sources_json,dependencies_json,make_dependencies_json,smoke_commands_json,architectures_json,build_images_json,pkgrel,source_date_epoch,image_digest,license,surface,description,explanation,sbom_json,lint_json,upstream_commit,pr_url,commit_sha,created_at)
    VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).bind(
    revisionId, requestId, '1.0', recipeText, recipeSha256, null, null, manifestSha256,
    JSON.stringify([{ name: sourceName, url: sourceUrl, sha256: sourceSha256 }]), '[]', '[]', JSON.stringify(['test -f /usr/share/opr-deep-fixture/fixture.txt']), '["x86_64"]', JSON.stringify({ x86_64: imageRef }), 1, 1_700_000_000,
    imageDigest, 'MIT', 'binary', 'Deep fixture', 'Deterministic local deep factory fixture.', '{}', JSON.stringify({ passed: true }), null, 'https://127.0.0.1/deep/review', 'deep'.repeat(10), timestamp,
  ).run();
  db.prepare(`INSERT INTO workers(id,name,architecture,public_key,status,enrolled_at,last_seen_at,daemon_version,runtime,capabilities_json,accepting_jobs)
    VALUES(?,?,?,?,?,?,?,?,?,?,?)`).bind(workerId, 'deep-test-worker', 'x86_64', keys.publicKey, 'active', timestamp, timestamp, 'deep-fixture', runtime, JSON.stringify(['offline-oci', 'multipart-upload', 'registry-pull', 'runtime-analysis-v1', 'multi-output-v2', 'single-build-reproducibility-v1']), 1).run();

  const policy = {
    schemaVersion: 1, pkgbase: 'opr-deep-fixture', outputs: ['opr-deep-fixture'], collection: 'omapkg', lane: 'opr', role: 'optional', origin: 'upstream', upstreamUrl: sourceUrl,
    sourceKind: 'archive', description: 'Deep fixture', license: 'MIT', ownerArea: 'development', architectures: ['x86_64'], artifactArchitecture: 'native', runtimeGroups: [['opr-deep-fixture']], architectureExceptions: [], sourceReference: null, rebuildOn: [],
  };
  const member = { pkgbase: 'opr-deep-fixture', catalogRevision: 1, catalogSha256: 'a'.repeat(64), policy, recipe: { id: revisionId, manifestSha256, fullVersion: '1.0-1', requestId }, cause: 'new-package', reason: 'Deep fixture' };
  const cohort = { schemaVersion: 1, title: 'Deep fixture', lane: 'opr', systemVersion: null, parentSnapshot: null, compatibleSystems: [], members: [member] };
  const cohortJson = canonicalJson(cohort);
  const cohortSha256 = await sha256(cohortJson);
  db.prepare('INSERT INTO cohorts(id,current_revision,event_sequence,phase,condition,created_at,updated_at) VALUES(?,?,?,?,?,?,?)').bind('deep-cohort', 1, 0, 'build', 'ready', timestamp, timestamp).run();
  db.prepare('INSERT INTO cohort_revisions(cohort_id,revision,manifest_json,manifest_sha256,title,lane,created_by,created_at) VALUES(?,?,?,?,?,?,?,?)').bind('deep-cohort', 1, cohortJson, cohortSha256, 'Deep fixture', 'opr', 'deep-test', timestamp).run();
  db.prepare('INSERT INTO catalog_packages(pkgbase,current_revision,admitted_revision,created_at,updated_at) VALUES(?,?,?,?,?)').bind('opr-deep-fixture', 1, 1, timestamp, timestamp).run();
  db.prepare('INSERT INTO catalog_revisions(pkgbase,revision,manifest_json,manifest_sha256,collection,lane,owner_area,created_by,reason,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)').bind('opr-deep-fixture', 1, JSON.stringify(policy), 'b'.repeat(64), 'omapkg', 'opr', 'development', 'deep-test', 'Deep fixture', timestamp).run();
  db.prepare('INSERT INTO cohort_members(cohort_id,revision,pkgbase,catalog_revision,recipe_revision_id) VALUES(?,?,?,?,?)').bind('deep-cohort', 1, 'opr-deep-fixture', 1, revisionId).run();
  db.prepare('INSERT INTO cohort_recipe_ownership(recipe_revision_id,cohort_id) VALUES(?,?)').bind(revisionId, 'deep-cohort').run();
  db.prepare('INSERT INTO approvals(id,revision_id,actor,kind,manifest_sha256,created_at) VALUES(?,?,?,?,?,?)').bind('deep-area', revisionId, 'deep-test', 'area', manifestSha256, timestamp).run();
  db.prepare('INSERT INTO approvals(id,revision_id,actor,kind,manifest_sha256,created_at) VALUES(?,?,?,?,?,?)').bind('deep-security', revisionId, 'deep-test-security', 'security', manifestSha256, timestamp).run();
}

interface DeepResult {
  provenance: string; provenanceSignature: string; workerId: string; artifactFilename: string; artifactSha256: string; artifactSize: number; installedSize: number; abiEvidencePath?: string; leaseToken: string; runId: string; attempt: number; inputSha256: string;
}

interface SuccessfulExecution {
  job: WorkerJob;
  result: DeepResult;
  reference: ArtifactReference;
  childOutput: string;
}

async function main(): Promise<void> {
  mkdirSync(outputDir, { recursive: true, mode: 0o700 });
  mkdirSync(sourceRoot, { recursive: true, mode: 0o700 });
  const sourcePath = join(sourceRoot, sourceName);
  const artifactPath = join(outputDir, 'deep-factory-artifact.pkg.tar.zst');
  const jobPath = join(outputDir, 'issued-worker-job.json');
  const evidencePath = join(outputDir, 'abi-evidence');
  writeFileSync(sourcePath, sourceBytes, { mode: 0o600 });
  const sourceSha256 = await sha256(sourceBytes);
  const recipeText = recipeTemplate.replace('SOURCE_SHA', sourceSha256);
  const keys = rawEd25519Keys();
  const policy = { builderImage: imageRef, runtimeImage, runtime, sourceSha256, recipeSha256: await sha256(recipeText), checks: ['build', 'smoke', 'provenance'] };
  const inputSha256 = await sha256(canonicalJson(policy));
  const db = new TestD1();
  const artifacts = new DeepMemoryR2();
  migrate(db);
  try {
    const manifestSha256 = await sha256(canonicalJson({ recipeSha256: await sha256(recipeText), sourceSha256, runId }));
    await seedFixture(db, keys, sourceSha256, recipeText, manifestSha256);
    const env = { DB: asD1(db), ARTIFACTS: artifacts as unknown as R2Bucket, PUBLIC_ORIGIN: 'http://127.0.0.1', QUARANTINE_HOURS: '0' } as unknown as Env;
    const run = await startFactoryRun(asD1(db), { id: runId, targetKind: 'opr', targetId: requestId, unitKey: 'x86_64', policy, createdBy: 'deep-test', requestedRevisionId: revisionId });
    const revision = await asD1(db).prepare('SELECT id,architectures_json FROM revisions WHERE id=?').bind(revisionId).first<{ id: string; architectures_json: string }>();
    if (!revision) throw new Error('deep fixture revision disappeared');
    const worker = await asD1(db).prepare('SELECT * FROM workers WHERE id=?').bind(workerId).first<Worker>();
    if (!worker) throw new Error('deep fixture worker disappeared');
    const metadata: WorkerMetadata = { version: 'deep-fixture', runtime, capabilities: ['offline-oci', 'multipart-upload', 'registry-pull', 'runtime-analysis-v1', 'multi-output-v2', 'single-build-reproducibility-v1'] };
    const successfulExecution = await runFactoryRepairLoop<SuccessfulExecution>({
      db: asD1(db), runId, policy,
      prepare: async (attempt, previousFailure) => ({
        reservationKey: `deep-attempt-${attempt}`,
        candidateSha256: await sha256(attempt === 1 ? 'deep-failed-candidate' : recipeText), inputSha256,
        candidateRevisionId: revisionId, architecture: 'x86_64', candidate: { repair: attempt === 1 ? 'baseline' : 'native-success', previousFailure },
      }),
      execute: async (attempt) => {
        if (attempt.attempt === 1) return { status: 'failed' as const, failureKind: 'build' as const, failure: { message: 'deterministic repair fixture failure' } };
        const queued = await queuePrivateFactoryBuilds({ DB: asD1(db) }, runId, attempt, revision as Pick<Revision, 'id' | 'architectures_json'>);
        if (queued.length !== 1) throw new Error('deep fixture did not queue exactly one private build');
        const job = await claimJob(asD1(db), worker, metadata);
        if (!job || !job.privateCandidate || job.factoryRunId !== runId || job.factoryAttempt !== attempt.attempt) throw new Error('deep fixture private worker job was not claimed');
        writeFileSync(jobPath, JSON.stringify({ job, workerId, workerPrivateKey: keys.privateKey, sourcePath, artifactPath, evidencePath, resultPath }), { mode: 0o600 });
        const childOutput = runGoFixture(jobPath);
        const result = JSON.parse(readFileSync(resultPath, 'utf8')) as DeepResult;
        if (result.workerId !== workerId || result.runId !== runId || result.attempt !== attempt.attempt || result.leaseToken !== job.leaseToken || result.inputSha256 !== inputSha256) throw new Error('native fixture result does not bind claimed job');
        const artifactBytes = readFileSync(artifactPath);
        const reference = await uploadArtifact(asD1(db), artifacts as unknown as R2Bucket, worker, job.id, job.leaseToken, result.artifactFilename, artifactBytes);
        if (reference.sha256 !== result.artifactSha256 || reference.size !== result.artifactSize) throw new Error('native fixture artifact identity changed before upload');
        const evidenceFiles = readdirSync(result.abiEvidencePath ?? evidencePath).filter((filename) => filename.endsWith('.json')).sort();
        if (!evidenceFiles.length) throw new Error('native fixture returned no ABI evidence');
        const evidenceDirectory = result.abiEvidencePath ?? evidencePath;
        const evidence = evidenceFiles.map((filename) => {
          const bytes = readFileSync(join(evidenceDirectory, filename));
          let kind = '';
          try { kind = String((JSON.parse(bytes.toString('utf8')) as { kind?: unknown }).kind ?? ''); } catch { /* uploadAbiEvidence reports invalid JSON */ }
          return { filename, bytes, kind };
        }).sort((left, right) => Number(left.kind === 'abi-inventory') - Number(right.kind === 'abi-inventory'));
        for (const item of evidence) await uploadAbiEvidence(env, worker, job.id, job.leaseToken, item.filename.slice(0, -5), item.bytes);
        const completed = await completeJob(asD1(db), artifacts as unknown as R2Bucket, worker, job.id, {
          leaseToken: job.leaseToken, status: 'succeeded', installedSize: result.installedSize, artifacts: [reference], provenance: result.provenance, provenanceSignature: result.provenanceSignature, smokePassed: true,
        });
        if (completed.status !== 'succeeded' || !completed.privateCandidate) throw new Error('private worker completion was not accepted');
        const value = { job, result, reference, childOutput };
        return { status: 'succeeded' as const, artifact: { buildId: job.id, artifact: reference, provenanceSha256: await sha256(result.provenance) }, value };
      },
    });
    if (!('job' in successfulExecution)) throw new Error('shared repair loop returned no native execution result');
    const { job, result, reference, childOutput } = successfulExecution;
    const finishedRun = await getFactoryRun(asD1(db), runId);
    if (!finishedRun || finishedRun.status !== 'succeeded' || finishedRun.successfulAttempt !== 2) throw new Error('factory run did not finish from actual worker completion');

    const exhaustionPolicy = { ...policy, scenario: 'exhaustion' };
    const exhaustion = await startFactoryRun(asD1(db), { id: exhaustionRunId, targetKind: 'opr', targetId: `${requestId}-exhaustion`, unitKey: 'x86_64', policy: exhaustionPolicy, createdBy: 'deep-test', requestedRevisionId: revisionId });
    let exhausted = false;
    try {
      await runFactoryRepairLoop({
        db: asD1(db), runId: exhaustion.id, policy: exhaustionPolicy,
        prepare: async (attempt, previousFailure) => ({ reservationKey: `exhaustion-${attempt}`, candidateSha256: await sha256(`exhaustion-candidate-${attempt}`), inputSha256, candidateRevisionId: revisionId, architecture: 'x86_64', candidate: { attempt, previousFailure } }),
        execute: async (attempt) => ({ status: 'failed' as const, failureKind: 'build' as const, failure: { message: `deterministic exhaustion failure ${attempt.attempt}` } }),
      });
    } catch (cause) {
      if ((cause as { code?: string }).code !== 'budget-exhausted') throw cause;
      exhausted = true;
    }
    const exhaustionRunState = await getFactoryRun(asD1(db), exhaustion.id);
    const exhaustionAttempts = await listFactoryAttempts(asD1(db), exhaustion.id);
    if (!exhausted || !exhaustionRunState || exhaustionRunState.attemptCount !== 3 || exhaustionRunState.status !== 'needs-human-intervention' || exhaustionAttempts.length !== 3) throw new Error('factory exhaustion fixture did not stop after exactly three attempts');
    let fourthBlocked = false;
    try { await reserveFactoryAttempt(asD1(db), { runId: exhaustion.id, reservationKey: 'exhaustion-4', candidateSha256: await sha256('exhaustion-candidate-4'), inputSha256, candidateRevisionId: revisionId, architecture: 'x86_64', policy: exhaustionPolicy }); }
    catch (cause) { fourthBlocked = (cause as { code?: string }).code === 'budget-exhausted' || (cause as Error).message.includes('human intervention'); }
    if (!fourthBlocked) throw new Error('fourth exhaustion attempt was not blocked');

    const stored = await createFactoryDossier(env, 'deep-test', { requestId, revisionId, runId });
    writeFileSync(join(outputDir, 'dossier.json'), `${stored.canonicalJson}\n`, { mode: 0o600 });
    writeFileSync(join(outputDir, 'dossier.md'), stored.markdown, { mode: 0o600 });
    writeFileSync(join(outputDir, 'deep-e2e.json'), `${JSON.stringify({ runId, successfulAttempt: 2, buildId: job.id, artifactSha256: reference.sha256, repairAttempts: (await listFactoryAttempts(asD1(db), runId)).map((attempt) => attempt.status), exhaustionAttempts: exhaustionAttempts.length, childOutput: childOutput.slice(-2_000) })}\n`, { mode: 0o600 });
    console.log(JSON.stringify({ runId, buildId: job.id, artifactSha256: reference.sha256, dossierId: stored.dossier.id, canonicalSha256: stored.canonicalSha256, repairAttempts: 2, exhaustionAttempts: 3 }));
  } finally { db.close(); }
}

await main();
