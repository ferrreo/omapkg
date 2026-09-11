import { expect } from 'bun:test';
import { generateKeyPairSync, sign } from 'node:crypto';
import type { Env } from '../src/lib/server/env';
import type { Revision, Worker } from '../src/lib/model';
import type { RecipeCapture } from '../src/lib/recipe-capture';
import { preservedBuildInputs } from '../src/lib/preserved-recipe';
import { canonicalJson } from '../src/lib/canonical-json';
import { encodeOprEvidence, readOprEvidence } from '../src/lib/server/sbom';
import { parseFrozenPage } from '../src/lib/frozen-inputs';
import { sha256 } from '../src/lib/server/db';
import { claimJob, completeJob, uploadArtifact } from '../src/lib/server/workers';
import { parseRevisionForJob, getBuildForWorker, type WorkerMetadata } from '../src/lib/server/worker-protocol';
import { cohortOutputContract, packageFilename } from '../src/lib/server/build-outputs';
import { proposeCohort, getCohort } from '../src/lib/server/cohorts';
import { changeCohortPhase } from '../src/lib/server/cohort-phases';
import { proposeInputLock, reviewInputLock, selectInputLock } from '../src/lib/server/input-locks';
import { POST as downloadInput } from '../src/routes/api/worker/jobs/[id]/inputs/[digest]/+server';
import { uploadAbiEvidence } from '../src/lib/server/build-abi-evidence';
import { nativeBuildStatement, currentNativeBuild } from '../src/lib/server/native-signing';
import { manifestDigest } from '../src/lib/server/policy';
import { deriveFactoryInputLocks, deriveFactoryRevisionBinding } from '../src/lib/server/preserved-factory';
import { queuePrivateFactoryBuilds } from '../src/lib/server/factory-private-build';
import { reserveFactoryAttempt, startFactoryRun, stopFactoryRun } from '../src/lib/server/factory-runs';
import { frozenFixture } from './frozen-fixtures';
import { runtimeEvidence } from './runtime-fixtures';
import { approveRevision, rejectRequest } from '../src/lib/server/requests';
import { evaluateCohortGate } from '../src/lib/server/cohort-gates';
import type { TestD1 } from './d1';

// Called after real Git capture, signed inspection and import persistence in the
// capture regression. All package/output bytes below are inert protocol fixtures.
export async function checkPreservedWorker(holder: TestD1, storage: Pick<Env, 'DB' | 'ARTIFACTS'>, revision: Revision) {
  const env = { ...storage, PUBLIC_ORIGIN: 'https://opr.test' };
  const actor = { id: 'github:1', role: 'maintainer' as const, areas: ['system'] };
  const security = { id: 'github:2', role: 'security' as const, areas: ['system'] };
  const timestamp = Math.floor(Date.now() / 1000);

  for (const [kind, reviewer] of [['area', actor], ['security', security]] as const) {
    await env.DB.prepare('INSERT INTO approvals(id,revision_id,actor,kind,manifest_sha256,created_at) VALUES(?,?,?,?,?,?)')
      .bind(crypto.randomUUID(), revision.id, reviewer.id, kind, revision.manifest_sha256, timestamp).run();
    await env.DB.prepare("INSERT INTO audit_events(actor,action,target,detail,created_at) VALUES(?,'revision.approved',?,?,?)")
      .bind(reviewer.id, revision.request_id, JSON.stringify({ revisionId: revision.id, kind, manifestSha256: revision.manifest_sha256, customShellAcknowledged: true }), timestamp).run();
  }

  let cohort = await proposeCohort(env.DB, actor, 'preserved-protocol-cohort', null, { title: 'Preserved protocol fixture', lane: 'opr', systemVersion: null,
    parentSnapshot: null, compatibleSystems: [], members: [{ pkgbase: 'demo', catalogRevision: 1, recipeRevisionId: revision.id, cause: 'new-package', reason: 'INERT import.' }] }, 'INERT source scope.');

  for (let index = 0; index < 2; index++) {
    await changeCohortPhase(env as Env, actor, cohort.id, { revision: cohort.current_revision, sequence: cohort.event_sequence, manifestSha256: cohort.manifest_sha256, action: 'advance', reason: 'INERT reviewed phase.' });
    cohort = await getCohort(env.DB, cohort.id);
  }

  await env.DB.prepare("UPDATE requests SET status='queued' WHERE id=?").bind(revision.request_id).run();
  await env.DB.prepare("INSERT INTO builds(id,revision_id,architecture,status,created_at) VALUES('preserved-build',?,'x86_64','queued',?)").bind(revision.id, timestamp).run();
  const keys = generateKeyPairSync('ed25519');
  const publicKey = Buffer.from(keys.publicKey.export({ type: 'spki', format: 'der' }).subarray(-32)).toString('base64');
  await env.DB.prepare("INSERT INTO workers(id,name,architecture,public_key,status,enrolled_at,accepting_jobs) VALUES('preserved-builder','Protocol fixture','x86_64',?,'active',?,1)").bind(publicKey, timestamp).run();
  const worker = (await env.DB.prepare("SELECT * FROM workers WHERE id='preserved-builder'").first<Worker>())!;
  const metadata: WorkerMetadata = { version: 'preserved-test', runtime: 'podman', capabilities: ['preserved-recipe-v1', 'multi-output-v2', 'runtime-analysis-v1', 'frozen-inputs-v1', 'helper-shell-analysis-v1', 'single-build-reproducibility-v1'] };
  expect(await claimJob(env.DB, worker, metadata, env)).toBeNull();
  const contract = (await cohortOutputContract(env.DB, { ...revision, pkgrel: revision.pkgrel ?? 1 }, 'x86_64'))!;
  const frozen = await frozenFixture(env, revision, contract);
  expect(parseFrozenPage([{ ...frozen.pkg, filename: frozen.pkg.filename.replace('.zst', '.xz') }], frozen.manifest)).toHaveLength(1);
  expect(() => parseFrozenPage([{ ...frozen.pkg, filename: frozen.pkg.filename + '.xz' }], frozen.manifest)).toThrow('Invalid frozen package');
  await expect(proposeInputLock(env, actor, revision.id, await frozen.retain({ ...frozen.manifest, shellAnalysis: 'skip' }), 'Invalid analyzer.')).rejects.toThrow('Invalid frozen manifest');
  frozen.manifest.shellAnalysis = 'helper'; frozen.lock = await frozen.retain(frozen.manifest);
  await proposeInputLock(env, actor, revision.id, frozen.lock, 'INERT frozen scope.');
  await reviewInputLock(env, actor, frozen.lock.sha256, 'area', 'INERT owner review.');
  await reviewInputLock(env, security, frozen.lock.sha256, 'security', 'INERT security review.');
  await selectInputLock(env, actor, frozen.lock.sha256, 'INERT selected inputs.');
  expect(await claimJob(env.DB, worker, { ...metadata, capabilities: metadata.capabilities.filter((value) => value !== 'helper-shell-analysis-v1') }, env)).toBeNull();
  expect(await claimJob(env.DB, worker, { ...metadata, capabilities: metadata.capabilities.filter((value) => value !== 'preserved-recipe-v1') }, env)).toBeNull();
  let job = (await claimJob(env.DB, worker, metadata, env))!;
  const inputs = preservedBuildInputs(revision, 'x86_64')!;
  expect(job.preservedRecipe).toEqual(inputs); expect(job.sources).toEqual([]); expect(job.dependencyPlan).toBeUndefined();
  expect(job.makeDependencies).toEqual(['cc']);
  expect(job.runtimeDependencies).toEqual(['demo-docs=2:1.4-3.2', 'glibc']);
  expect(job.dependencies).toEqual(['glibc', 'cc']);
  const build = (await getBuildForWorker(env.DB, job.id, worker.id))!;
  expect(parseRevisionForJob({ ...build, architecture: 'aarch64' }).makeDependencies).toEqual(['arm-tool', 'cc']);
  expect(() => holder.prepare('UPDATE builds SET preserved_inputs_json=NULL WHERE id=?').bind(job.id).run()).toThrow();

  const download = async (digest: string, token = job.leaseToken) => {
    const path = `/api/worker/jobs/${job.id}/inputs/${digest}`, body = JSON.stringify({ leaseToken: token });
    const timestamp = String(Math.floor(Date.now() / 1000)), nonce = crypto.randomUUID().replaceAll('-', '');
    const signature = Buffer.from(sign(null, Buffer.from(`POST\n${path}\n${timestamp}\n${nonce}\n${await sha256(body)}`), keys.privateKey)).toString('base64');

    const request = new Request(env.PUBLIC_ORIGIN + path, { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-OPR-Worker': worker.id,
      'X-OPR-Timestamp': timestamp, 'X-OPR-Nonce': nonce, 'X-OPR-Signature': signature }, body });

    return downloadInput({ request, url: new URL(request.url), params: { id: job.id, digest }, platform: { env } } as never);
  };

  const capture = JSON.parse((await env.DB.prepare('SELECT manifest_json FROM recipe_captures WHERE sha256=?').bind(inputs.capture.sha256).first<{ manifest_json: string }>())!.manifest_json) as RecipeCapture;

  for (const ref of [inputs.capture, inputs.sourceBundle, frozen.lock, capture.git.commit, ...capture.git.trees, ...capture.files.map((file) => file.object)].filter((ref) => ref.size)) {
    expect(await sha256(new Uint8Array(await (await download(ref.sha256)).arrayBuffer()))).toBe(ref.sha256);
  }

  await expect(download(preservedBuildInputs(revision, 'aarch64')!.sourceBundle.sha256)).rejects.toMatchObject({ status: 403 });
  await expect(download('f'.repeat(64))).rejects.toMatchObject({ status: 403 });
  const image = (await env.DB.prepare("SELECT image_id FROM recipe_inspections WHERE architecture='x86_64' AND status='succeeded'").first<{ image_id: string }>())!;

  for (const [revoke, restore] of [
    ["UPDATE workers SET status='revoked' WHERE id='inspection-worker'", "UPDATE workers SET status='active' WHERE id='inspection-worker'"],
    [`UPDATE build_images SET enabled=0 WHERE id='${image.image_id}'`, `UPDATE build_images SET enabled=1 WHERE id='${image.image_id}'`],
    ["DELETE FROM team_memberships WHERE github_id='2'", "INSERT INTO team_memberships VALUES('2','security')"],
    ["UPDATE workers SET capabilities_json='[]' WHERE id='preserved-builder'", `UPDATE workers SET capabilities_json='${JSON.stringify(metadata.capabilities)}' WHERE id='preserved-builder'`],
    [`UPDATE workers SET capabilities_json='${JSON.stringify(metadata.capabilities.filter((value) => value !== 'helper-shell-analysis-v1'))}' WHERE id='preserved-builder'`, `UPDATE workers SET capabilities_json='${JSON.stringify(metadata.capabilities)}' WHERE id='preserved-builder'`],
  ]) {
    const token = job.leaseToken, attempt = job.attempt!;
    holder.exec(revoke); holder.exec(restore);
    expect(await env.DB.prepare('SELECT status,lease_token FROM builds WHERE id=?').bind(job.id).first<{ status: string; lease_token: string | null }>()).toEqual({ status: 'queued', lease_token: null });
    await expect(download(inputs.capture.sha256, token)).rejects.toMatchObject({ status: 409 });
    expect(await env.DB.prepare('SELECT preserved_inputs_json FROM build_attempts WHERE build_id=? AND attempt=?').bind(job.id, attempt).first<{ preserved_inputs_json: string }>()).toEqual({ preserved_inputs_json: canonicalJson(inputs) });
    job = (await claimJob(env.DB, worker, metadata, env))!;
    expect(job.attempt).toBe(attempt + 1); expect(job.leaseToken).not.toBe(token);
  }

  const artifacts = await Promise.all(job.outputContract!.outputs.map((output) => uploadArtifact(env.DB, env.ARTIFACTS, worker, job.id, job.leaseToken,
    packageFilename(output), new TextEncoder().encode('INERT output ' + output.name))));

  const environment = { baseImage: job.imageRef, preparedImage: `sha256:${'d'.repeat(64)}`, packages: [`${frozen.pkg.name} ${frozen.pkg.version}`] };
  const reproducibilityFiles = artifacts.map((artifact) => ({ filename: artifact.filename, size: artifact.size, sha256: artifact.sha256 })).sort((left, right) => left.filename.localeCompare(right.filename));

  const report = { schemaVersion: 2, attempt: job.attempt, outputContract: job.outputContract, buildId: job.id, revisionId: job.revisionId, workerId: worker.id,
    recipeSha256: job.recipeSha256, architecture: job.architecture, imageDigest: job.imageDigest, sourceDateEpoch: job.sourceDateEpoch, sources: [], preservedRecipe: inputs,
    network: 'disabled', startedAt: '2026-09-09T00:00:00Z', finishedAt: '2026-09-09T00:01:00Z', buildEnvironment: environment,
    reproducibility: { schemaVersion: 1, status: 'reproducibility-contract-verified', mode: 'single-build', target: job.architecture,
      inputs: { recipeSha256: job.recipeSha256, sourceManifestSha256: await sha256(canonicalJson([])), inputLockSha256: frozen.lock.sha256, dependencyPlanSha256: '', imageDigest: job.imageDigest, sourceDateEpoch: job.sourceDateEpoch },
      controls: { network: 'disabled', locale: 'C', timezone: 'UTC', umask: '022', hostSecrets: 'excluded', writableCaches: 'excluded', nativeTarget: job.architecture, archivePathsChecked: true, archiveMetadataChecked: true, timestampOwnershipOrderChecked: true },
      outputs: { setSha256: await sha256(canonicalJson(reproducibilityFiles)), files: reproducibilityFiles, unexpected: [], prohibitedPaths: [] },
      limitations: ['single execution does not establish independent byte reproduction'] },
    frozenInputs: { lock: frozen.lock, manifest: frozen.manifest, host: { architecture: 'x86_64', kernel: 'INERT kernel', cpuInfoSha256: 'a'.repeat(64), cpuModel: 'INERT CPU', runtime: 'podman', runtimeVersion: 'INERT', goVersion: 'INERT' } },
    outputs: job.outputContract!.outputs.map((output) => ({ pkgbase: job.packageName, filename: packageFilename(output), artifactSha256: artifacts.find((artifact) => artifact.filename === packageFilename(output))!.sha256,
      packageMetadata: { ...output, installedSize: 10, depends: output.name === 'demo' ? ['glibc', 'demo-docs=2:1.4-3.2'] : [], provides: [], conflicts: [], replaces: [] } })),
    runtimeTests: job.outputContract!.runtimeGroups.map((outputs) => ({ outputs, environment, smokePassed: true,
      analyses: outputs.map((name) => ({ name, runtimeAnalysis: { ...runtimeEvidence(job.imageDigest).runtimeAnalysis, nativeCode: [], payloadSha256: 'e'.repeat(64) } })) })),
  };

  const complete = (value: unknown) => { const provenance = JSON.stringify(value);

 return { leaseToken: job.leaseToken, status: 'succeeded', installedSize: 20, smokePassed: true,
    artifacts, provenance, provenanceSignature: Buffer.from(sign(null, Buffer.from(provenance), keys.privateKey)).toString('base64') }; };

  await expect(completeJob(env.DB, env.ARTIFACTS, worker, job.id, complete({ ...report, preservedRecipe: undefined }))).rejects.toThrow('Preserved source inputs');
  await expect(completeJob(env.DB, env.ARTIFACTS, worker, job.id, complete({ ...report, preservedRecipe: { ...inputs, sourceBundle: preservedBuildInputs(revision, 'aarch64')!.sourceBundle } }))).rejects.toThrow('Preserved source inputs');
  expect(await completeJob(env.DB, env.ARTIFACTS, worker, job.id, complete(report))).toEqual({ status: 'succeeded', idempotent: false });
  const statement = JSON.parse(await nativeBuildStatement(await currentNativeBuild(env, job.id)));
  expect(statement.predicate.buildDefinition.externalParameters.preservedRecipe).toEqual(inputs);
  expect(statement.predicate.buildDefinition.resolvedDependencies.slice(0, 2).map((item: { digest: { sha256: string } }) => item.digest.sha256)).toEqual([inputs.capture.sha256, inputs.sourceBundle.sha256]);
  const originalJob = job, successorId = 'preserved-successor';
  const repairedRecipe = `${revision.recipe}\n# bounded repair successor\n`;
  const repairedRef = { sha256: await sha256(repairedRecipe), size: new TextEncoder().encode(repairedRecipe).byteLength };
  const repairedKey = `private/inputs/factory-repairs/${repairedRef.sha256}`;
  await env.ARTIFACTS.put(repairedKey, repairedRecipe, { customMetadata: { sha256: repairedRef.sha256 } });
  await env.DB.prepare('INSERT INTO input_objects(sha256,size,object_key,created_by,created_at) VALUES(?,?,?,?,?)').bind(repairedRef.sha256, repairedRef.size, repairedKey, 'factory', timestamp).run();
  const inspection = await env.DB.prepare(`SELECT r.report_json FROM current_recipe_inspections i JOIN recipe_inspection_results r ON r.job_id=i.id AND r.attempt=i.attempt
    WHERE i.capture_sha256=? AND i.architecture='x86_64' AND i.status='succeeded'`).bind(inputs.capture.sha256).first<{ report_json: string }>();
  const repairedEvidence = readOprEvidence(JSON.parse(revision.sbom_json))!;
  repairedEvidence.factoryRepair = { recipe: repairedRef, inspection: { srcinfoSha256: JSON.parse(inspection!.report_json).srcinfoSha256 } };
  const successor = { ...revision, id: successorId, recipe: repairedRecipe, recipe_sha256: repairedRef.sha256, sbom_json: JSON.stringify({ ...JSON.parse(revision.sbom_json), comment: encodeOprEvidence(repairedEvidence) }), preserved_origin_revision_id: revision.id, created_at: timestamp + 1 };
  successor.manifest_sha256 = await manifestDigest(successor);
  await env.DB.prepare("UPDATE requests SET status='review' WHERE id=?").bind(revision.request_id).run();
  await env.DB.prepare(`INSERT INTO revisions(
    id,request_id,version,recipe,recipe_sha256,manifest_sha256,sources_json,dependencies_json,make_dependencies_json,smoke_commands_json,
    architectures_json,build_images_json,pkgrel,source_date_epoch,image_digest,license,surface,description,explanation,sbom_json,lint_json,
    upstream_commit,pr_url,commit_sha,created_at,preserved_origin_revision_id
  ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).bind(
    successor.id, successor.request_id, successor.version, successor.recipe, successor.recipe_sha256, successor.manifest_sha256, successor.sources_json,
    successor.dependencies_json, successor.make_dependencies_json, successor.smoke_commands_json, successor.architectures_json, successor.build_images_json,
    successor.pkgrel, successor.source_date_epoch, successor.image_digest, successor.license, successor.surface, successor.description, successor.explanation,
    successor.sbom_json, successor.lint_json, successor.upstream_commit, successor.pr_url, successor.commit_sha, successor.created_at, successor.preserved_origin_revision_id,
  ).run();
  await deriveFactoryRevisionBinding(env.DB, revision.id, successor.id, 2);
  await deriveFactoryInputLocks(env, revision.id, successor.id, successor.recipe_sha256);
  const successorRun = await startFactoryRun(env.DB, { id: 'preserved-successor-run', targetKind: 'preserved', targetId: revision.request_id, unitKey: revision.id, policy: { network: 'disabled' }, createdBy: 'factory', requestedRevisionId: successor.id });
  const successorAttempt = await reserveFactoryAttempt(env.DB, { runId: successorRun.id, reservationKey: 'attempt:1', candidateSha256: successor.manifest_sha256, inputSha256: await sha256(canonicalJson({ revisionId: successor.id })), candidateRevisionId: successor.id, policy: { network: 'disabled' } });
  await queuePrivateFactoryBuilds(env, successorRun.id, successorAttempt, successor);
  const successorJob = (await claimJob(env.DB, worker, metadata, env))!;
  const derivedLock = (await env.DB.prepare('SELECT derived_lock_sha256 FROM factory_derived_input_locks WHERE revision_id=?').bind(successor.id).first<{ derived_lock_sha256: string }>())!;
  expect(successorJob.revisionId).toBe(successor.id); expect(successorJob.inputLock?.sha256).toBe(derivedLock.derived_lock_sha256); expect(successorJob.inputLock?.sha256).not.toBe(frozen.lock.sha256);
  job = successorJob;
  holder.prepare('UPDATE workers SET capabilities_json=capabilities_json WHERE id=?').bind(worker.id).run();
  expect(await sha256(new Uint8Array(await (await download(derivedLock.derived_lock_sha256)).arrayBuffer()))).toBe(derivedLock.derived_lock_sha256);
  await expect(download(frozen.lock.sha256)).rejects.toMatchObject({ status: 403 });
  const privateArtifacts = await Promise.all(job.outputContract!.outputs.map(output => uploadArtifact(env.DB, env.ARTIFACTS, worker, job.id, job.leaseToken,
    packageFilename(output), new TextEncoder().encode('INERT private output ' + output.name))));
  const privateArtifact = privateArtifacts[0];
  const abiBytes = new TextEncoder().encode(canonicalJson({ schemaVersion: 1, kind: 'abi-records', artifactSha256: privateArtifact.sha256, start: 0,
    records: [{ kind: 'file', path: 'usr/share/fixture', sha256: privateArtifact.sha256, type: '0', mode: 420, link: '', nativeKind: null, elf: null }] }));
  const abiSha = await sha256(abiBytes);
  expect(await uploadAbiEvidence(env, worker, job.id, job.leaseToken, abiSha, abiBytes)).toEqual({ sha256: abiSha, size: abiBytes.length });
  const privateReport = structuredClone(report) as any;
  Object.assign(privateReport, { buildId: job.id, revisionId: job.revisionId, attempt: job.attempt, outputContract: job.outputContract,
    recipeSha256: job.recipeSha256, preservedRecipe: preservedBuildInputs(successor, 'x86_64'),
    factoryRunId: job.factoryRunId, factoryAttempt: job.factoryAttempt, factoryInputSha256: job.factoryInputSha256 });
  privateReport.reproducibility.execution = { runId: job.factoryRunId, attempt: job.factoryAttempt, inputSha256: job.factoryInputSha256 };
  privateReport.frozenInputs.lock = job.inputLock;
  privateReport.frozenInputs.manifest.recipeSha256 = job.recipeSha256;
  Object.assign(privateReport.reproducibility.inputs, { recipeSha256: job.recipeSha256, inputLockSha256: job.inputLock!.sha256 });
  const privateFiles = privateArtifacts.map(({ filename, size, sha256 }) => ({ filename, size, sha256 })).sort((a, b) => a.filename.localeCompare(b.filename));
  privateReport.reproducibility.outputs.files = privateFiles;
  privateReport.reproducibility.outputs.setSha256 = await sha256(canonicalJson(privateFiles));
  for (const output of privateReport.outputs) output.artifactSha256 = privateArtifacts.find(item => item.filename === output.filename)!.sha256;
  const privateProvenance = JSON.stringify(privateReport);
  expect(await completeJob(env.DB, env.ARTIFACTS, worker, job.id, { leaseToken: job.leaseToken, status: 'succeeded', installedSize: 20,
    smokePassed: true, artifacts: privateArtifacts, provenance: privateProvenance,
    provenanceSignature: Buffer.from(sign(null, Buffer.from(privateProvenance), keys.privateKey)).toString('base64') })).toEqual({ status: 'succeeded', idempotent: false, privateCandidate: true });
  await stopFactoryRun(env.DB, successorRun.id, 'Fixture successor claim complete.');
  job = originalJob;
  await expect(rejectRequest(env as Env, { ...actor, areas: ['desktop'] }, revision.request_id, 'Wrong owner.')).rejects.toMatchObject({ status: 403 });
  holder.exec("UPDATE cohorts SET phase='publish' WHERE id='preserved-protocol-cohort'");
  await expect(rejectRequest(env as Env, actor, revision.request_id, 'Published recovery required.')).rejects.toMatchObject({ status: 409 });
  expect(() => holder.prepare("UPDATE requests SET status='rejected' WHERE id=?").bind(revision.request_id).run()).toThrow('release recovery');
  holder.exec("UPDATE cohorts SET phase='build' WHERE id='preserved-protocol-cohort'");
  const succeededAttempt = job.attempt!;
  holder.prepare("UPDATE builds SET status='queued',worker_id=NULL,lease_token=NULL,lease_expires_at=NULL WHERE id=?").bind(job.id).run();
  holder.prepare("INSERT INTO builds(id,revision_id,architecture,status,created_at) VALUES('preserved-arm-queued',?,'aarch64','queued',?)").bind(revision.id, timestamp).run();
  await rejectRequest(env as Env, actor, revision.request_id, 'Replace the obsolete imported recipe.');
  expect(holder.prepare('SELECT status,lease_token FROM builds WHERE revision_id=? ORDER BY architecture').bind(revision.id).all().results)
    .toEqual([{ status: 'cancelled', lease_token: null }, { status: 'cancelled', lease_token: null }]);
  expect(holder.prepare('SELECT status,provenance FROM build_attempt_results WHERE build_id=? AND attempt=?').bind(job.id, succeededAttempt).first<{ status: string; provenance: string }>())
    .toEqual({ status: 'succeeded', provenance: JSON.stringify(report) });
  expect(holder.prepare('SELECT COUNT(*) AS n FROM current_preserved_recipe_imports WHERE revision_id=?').bind(revision.id).first<{ n: number }>()).toEqual({ n: 0 });
  await expect(download(inputs.capture.sha256)).rejects.toMatchObject({ status: 409 });
  await expect(completeJob(env.DB, env.ARTIFACTS, worker, job.id, complete(report))).rejects.toMatchObject({ status: 409 });
  await expect(approveRevision(env as Env, actor, revision.request_id, revision.id, 'area', 'Cannot revive rejection.', true)).rejects.toMatchObject({ status: 409 });
  expect(await claimJob(env.DB, worker, metadata, env)).toBeNull();
  expect(() => holder.prepare("UPDATE requests SET status='queued' WHERE id=?").bind(revision.request_id).run()).toThrow('new reviewed request');
  expect((await evaluateCohortGate(env as Env, await getCohort(env.DB, cohort.id), false)).blockers.some((blocker) => blocker.code === 'recipe-changed')).toBe(true);
  expect(holder.prepare("SELECT COUNT(*) AS n FROM audit_events WHERE action='request.rejected' AND target=?").bind(revision.request_id).first<{ n: number }>()).toEqual({ n: 1 });
}
