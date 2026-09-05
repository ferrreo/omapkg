import { expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import { sha256 } from '../src/lib/server/db';
import {
  WorkerProtocolError,
  appendJobLog,
  authenticateWorker,
  claimJob,
  completeJob,
  createEnrollmentToken,
  enrollWorker,
  heartbeatJob,
  archiveWorker,
  pauseWorker,
  parseWorkerMetadata,
  revokeWorker,
  retryBuild,
  resumeWorker,
  uploadArtifact
} from '../src/lib/server/workers';
import { TestD1, asD1 } from './d1';

const schema = readFileSync(new URL('../migrations/0001_initial.sql', import.meta.url), 'utf8') +
  '\n' + readFileSync(new URL('../migrations/0007_core_guards.sql', import.meta.url), 'utf8') +
  '\n' + readFileSync(new URL('../migrations/0011_build_images.sql', import.meta.url), 'utf8') +
  '\n' + readFileSync(new URL('../migrations/0014_package_metadata.sql', import.meta.url), 'utf8') +
  '\n' + readFileSync(new URL('../migrations/0015_installed_size.sql', import.meta.url), 'utf8') +
  '\n' + readFileSync(new URL('../migrations/0018_worker_metadata.sql', import.meta.url), 'utf8') +
  '\n' + readFileSync(new URL('../migrations/0019_crash_triage.sql', import.meta.url), 'utf8') +
  '\n' + readFileSync(new URL('../migrations/0020_worker_lifecycle.sql', import.meta.url), 'utf8') +
  '\n' + readFileSync(new URL('../migrations/0023_dependency_plan.sql', import.meta.url), 'utf8');

class MemoryR2 {
  readonly objects = new Map<string, { body: Uint8Array; customMetadata: Record<string, string> }>();

  async put(key: string, body: Uint8Array, options?: { customMetadata?: Record<string, string> }): Promise<void> {
    this.objects.set(key, { body: new Uint8Array(body), customMetadata: options?.customMetadata ?? {} });
  }

  async head(key: string): Promise<{ size: number; customMetadata: Record<string, string> } | null> {
    const object = this.objects.get(key);
    return object ? { size: object.body.byteLength, customMetadata: object.customMetadata } : null;
  }

  async get(key: string) {
    const object = this.objects.get(key);
    return object ? { size: object.body.byteLength, customMetadata: object.customMetadata, arrayBuffer: async () => object.body.slice().buffer } : null;
  }

  async delete(key: string): Promise<void> {
    this.objects.delete(key);
  }
}

type KeyPair = { privateKey: CryptoKey; publicKey: string };

function base64(bytes: ArrayBuffer): string {
  let binary = '';
  for (const byte of new Uint8Array(bytes)) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function uniqueHex(): string {
  return crypto.randomUUID().replaceAll('-', '').padEnd(32, '0').slice(0, 32);
}

async function keyPair(): Promise<KeyPair> {
  const generated = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
  return {
    privateKey: generated.privateKey,
    publicKey: base64(await crypto.subtle.exportKey('raw', generated.publicKey))
  };
}

async function fixture() {
  const holder = new TestD1(schema);
  const db = asD1(holder);
  const keys = await keyPair();
  const enrollment = await createEnrollmentToken(db, 'maintainer-1', 'x86_64', 300);
  const enrolled = await enrollWorker(db, {
    token: enrollment.token, name: 'test-worker', architecture: 'x86_64', publicKey: keys.publicKey,
    version: 'v0.1.0', runtime: 'podman', capabilities: ['offline-oci', 'multipart-upload', 'registry-pull']
  });
  const worker = await db.prepare('SELECT id, name, architecture, public_key, status, enrolled_at, last_seen_at, daemon_version, runtime, capabilities_json, accepting_jobs, paused_at, removed_at FROM workers WHERE id = ?').bind(enrolled.id).first<any>();
  return { holder, db, keys, worker };
}

async function seedBuild(db: D1Database, options: {
  surface?: 'binary' | 'recipe'; requestStatus?: string; approved?: boolean; architecture?: 'x86_64' | 'aarch64';
  buildImages?: Partial<Record<'x86_64' | 'aarch64', string>>;
  dependencies?: string[];
} = {}) {
  const requestId = crypto.randomUUID();
  const revisionId = crypto.randomUUID();
  const buildId = crypto.randomUUID();
  const name = `package-${buildId.slice(0, 8)}`;
  const recipe = `pkgname=${name}\npkgver=1\npkgrel=1\nsource=('https://example.com/${name}.tar.gz')\nsha256sums=('${'a'.repeat(64)}')\npackage() { install -Dm644 README \"$pkgdir/usr/share/${name}/README\"; }\n`;
  const source = [{ name: `${name}.tar.gz`, url: `https://example.com/${name}.tar.gz`, sha256: 'a'.repeat(64) }];
  const manifest = await sha256(buildId);
  const timestamp = Math.floor(Date.now() / 1000);
  await db.prepare(`INSERT INTO requests(id,name,upstream_url,source_kind,area,requested_by,status,created_at,updated_at)
    VALUES(?,?,?,?,?,?,?,?,?)`).bind(requestId, name, source[0].url, 'archive', 'system', 'requestor', options.requestStatus ?? 'queued', timestamp, timestamp).run();
  await db.prepare(`INSERT INTO revisions(id,request_id,version,recipe,recipe_sha256,manifest_sha256,sources_json,dependencies_json,
    smoke_commands_json,architectures_json,build_images_json,source_date_epoch,image_digest,license,surface,explanation,sbom_json,lint_json,upstream_commit,pr_url,commit_sha,created_at)
    VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).bind(
    revisionId, requestId, '1.0.0', recipe, await sha256(recipe), manifest, JSON.stringify(source), JSON.stringify(options.dependencies ?? ['bash']),
    JSON.stringify(['printf smoke']), JSON.stringify([options.architecture ?? 'x86_64']), JSON.stringify(options.buildImages ?? {}),
    1700000000, `ghcr.io/opr/builder@sha256:${'c'.repeat(64)}`, 'MIT', options.surface ?? 'binary', 'test', '{}', '{}', 'upstream-commit', 'https://github.com/opr/test/pull/1', 'review-commit', timestamp
  ).run();
  if (options.approved !== false) {
    await db.prepare('INSERT INTO approvals(id,revision_id,actor,kind,manifest_sha256,created_at) VALUES(?,?,?,?,?,?)').bind(crypto.randomUUID(), revisionId, 'area-reviewer', 'area', manifest, timestamp).run();
    await db.prepare('INSERT INTO approvals(id,revision_id,actor,kind,manifest_sha256,created_at) VALUES(?,?,?,?,?,?)').bind(crypto.randomUUID(), revisionId, 'security-reviewer', 'security', manifest, timestamp).run();
  }
  await db.prepare(`INSERT INTO builds(id,revision_id,architecture,status,created_at) VALUES(?,?,?,?,?)`)
    .bind(buildId, revisionId, options.architecture ?? 'x86_64', 'queued', timestamp).run();
  return { requestId, revisionId, buildId, recipe, source, manifest };
}

async function signedRequest(
  method: string,
  path: string,
  body: Uint8Array,
  workerId: string,
  privateKey: CryptoKey,
  nonce = uniqueHex()
): Promise<Request> {
  const timestamp = Math.floor(Date.now() / 1000).toString();
  const digest = await sha256(body);
  const message = new TextEncoder().encode(`${method}\n${path}\n${timestamp}\n${nonce}\n${digest}`);
  const signature = await crypto.subtle.sign({ name: 'Ed25519' }, privateKey, message as BufferSource);
  return new Request(`https://opr.test${path}`, {
    method,
    body: body as unknown as BodyInit,
    headers: {
      'content-type': 'application/json',
      'X-OPR-Worker': workerId,
      'X-OPR-Timestamp': timestamp,
      'X-OPR-Nonce': nonce,
      'X-OPR-Signature': base64(signature)
    }
  });
}

async function expectProtocolError(action: Promise<unknown>, status: number): Promise<void> {
  try {
    await action;
    throw new Error(`expected protocol error ${status}`);
  } catch (cause) {
    expect(cause).toBeInstanceOf(WorkerProtocolError);
    expect((cause as WorkerProtocolError).status).toBe(status);
  }
}

test('enrollment consumes one token, signed requests reject replay, and revocation fences worker', async () => {
  const { holder, db, keys, worker } = await fixture();
  try {
    expect(worker.daemon_version).toBe('v0.1.0');
    expect(worker.runtime).toBe('podman');
    expect(worker.capabilities_json).toBe('["offline-oci","multipart-upload","registry-pull"]');
    await expectProtocolError(enrollWorker(db, { token: (await createEnrollmentToken(db, 'maintainer-2', 'x86_64', 300)).token, name: 'other', architecture: 'aarch64', publicKey: keys.publicKey }), 401);
    const body = new TextEncoder().encode('{}');
    const request = await signedRequest('POST', '/api/worker/claim', body, worker.id, keys.privateKey, uniqueHex());
    await authenticateWorker(db, request, '/api/worker/claim', body);
    await expectProtocolError(authenticateWorker(db, request, '/api/worker/claim', body), 409);
    const revoked = await revokeWorker(db, 'admin-1', worker.id);
    expect(revoked.status).toBe('revoked');
    const revokedRequest = await signedRequest('POST', '/api/worker/claim', body, worker.id, keys.privateKey);
    await expectProtocolError(authenticateWorker(db, revokedRequest, '/api/worker/claim', body), 403);
  } finally {
    holder.close();
  }
});

test('worker metadata is informational and idle claim refreshes it without changing claim policy', async () => {
  const { holder, db, worker } = await fixture();
  try {
    await expectProtocolError(Promise.resolve().then(() => parseWorkerMetadata({ version: 'v0.1.0', runtime: 'podman', capabilities: ['unsupported'] })), 400);
    await expectProtocolError(Promise.resolve().then(() => parseWorkerMetadata({ version: 'v0.1.0' })), 400);
    expect(await claimJob(db, worker, { version: 'v0.2.0', runtime: 'docker', capabilities: ['offline-oci'] })).toBeNull();
    const refreshed = await db.prepare('SELECT daemon_version, runtime, capabilities_json FROM workers WHERE id=?').bind(worker.id).first<any>();
    expect(refreshed).toEqual({ daemon_version: 'v0.2.0', runtime: 'docker', capabilities_json: '["offline-oci"]' });
  } finally {
    holder.close();
  }
});

test('pause drains dispatch while preserving active lease completion, then revoke and archive finish lifecycle', async () => {
  const fixtureState = await fixture();
  const { holder, db, keys } = fixtureState;
  let { worker } = fixtureState;
  try {
    const active = await seedBuild(db, { surface: 'recipe' });
    const job = await claimJob(db, worker);
    if (!job) throw new Error('active job was not claimed');
    await expectProtocolError(archiveWorker(db, 'admin-1', worker.id), 409);
    const waiting = await seedBuild(db, { surface: 'recipe' });
    const paused = await pauseWorker(db, 'admin-1', worker.id);
    expect(paused.accepting_jobs).toBe(0);
    expect(paused.paused_at).not.toBeNull();
    expect(await claimJob(db, worker)).toBeNull();
    expect((await heartbeatJob(db, worker, active.buildId, job.leaseToken)).cancel).toBe(false);
    const startedAt = new Date().toISOString();
    const finishedAt = new Date(Date.now() + 1000).toISOString();
    const provenance = JSON.stringify({
      buildId: job.id,
      revisionId: job.revisionId,
      workerId: worker.id,
      recipeSha256: job.recipeSha256,
      artifactSha256: null,
      architecture: job.architecture,
      imageDigest: job.imageDigest,
      sourceDateEpoch: job.sourceDateEpoch,
      sources: job.sources,
      network: 'disabled',
      startedAt,
      finishedAt
    });
    const provenanceSignature = base64(await crypto.subtle.sign({ name: 'Ed25519' }, keys.privateKey, new TextEncoder().encode(provenance) as BufferSource));
    expect((await completeJob(db, new MemoryR2() as unknown as R2Bucket, worker, active.buildId, {
      leaseToken: job.leaseToken, status: 'succeeded' as const, provenance, provenanceSignature, smokePassed: true
    })).idempotent).toBe(false);
    worker = await resumeWorker(db, 'admin-1', worker.id);
    expect(worker.accepting_jobs).toBe(1);
    const resumed = await claimJob(db, worker);
    expect(resumed?.id).toBe(waiting.buildId);
    await revokeWorker(db, 'admin-1', worker.id);
    const archived = await archiveWorker(db, 'admin-1', worker.id);
    expect(archived.status).toBe('revoked');
    expect(archived.removed_at).not.toBeNull();
    expect(archived.accepting_jobs).toBe(0);
    expect((await db.prepare("SELECT COUNT(*) AS count FROM builds WHERE worker_id=? AND status='leased'").bind(worker.id).first<any>())?.count).toBe(0);
  } finally {
    holder.close();
  }
});

test('claim requires queued/building request and both approvals, then binds lease to worker architecture', async () => {
  const { holder, db, worker } = await fixture();
  try {
    const unapproved = await seedBuild(db, { approved: false });
    expect(await claimJob(db, worker)).toBeNull();
    await db.prepare("UPDATE requests SET status = 'pending' WHERE id = ?").bind(unapproved.requestId).run();
    const approved = await seedBuild(db, {
      approved: true,
      buildImages: { x86_64: `ghcr.io/opr/builder-x86_64@sha256:${'d'.repeat(64)}` }
    });
    const job = await claimJob(db, worker);
    expect(job?.id).toBe(approved.buildId);
    expect(job?.architecture).toBe('x86_64');
    expect(job?.imageRef).toBe(`ghcr.io/opr/builder-x86_64@sha256:${'d'.repeat(64)}`);
    expect(job?.imageDigest).toBe(`sha256:${'d'.repeat(64)}`);
    const row = await db.prepare('SELECT status, worker_id, lease_token, attempt FROM builds WHERE id = ?').bind(approved.buildId).first<any>();
    expect(row.status).toBe('leased');
    expect(row.worker_id).toBe(worker.id);
    expect(row.lease_token).toBe(job?.leaseToken);
    expect(row.attempt).toBe(1);
  } finally {
    holder.close();
  }
});

test('maintainer can retry a failed current build without losing attempt logs', async () => {
  const { holder, db, worker } = await fixture();
  try {
    const seeded = await seedBuild(db);
    const timestamp = Math.floor(Date.now() / 1000);
    await db.prepare("UPDATE requests SET status='queued' WHERE id=?").bind(seeded.requestId).run();
    await db.prepare(`UPDATE builds SET status='failed',worker_id=?,lease_token=?,lease_expires_at=?,attempt=2,error=?,
      artifact_key=?,artifact_sha256=?,artifact_size=?,artifact_filename=?,installed_size=?,dependency_plan_json=?,
      provenance=?,provenance_signature=?,smoke_passed=0,started_at=?,finished_at=? WHERE id=?`).bind(
      worker.id, 'stale-lease', timestamp - 1, 'worker image failed', 'private/stale', 'a'.repeat(64), 10,
      'stale-1.0-1-x86_64.pkg.tar.zst', 12, '{"stale":true}', '{"stale":true}', 'AA==', timestamp - 10, timestamp - 1, seeded.buildId,
    ).run();
    await db.prepare('INSERT INTO build_logs(build_id,attempt,sequence,text,created_at) VALUES(?,?,?,?,?)')
      .bind(seeded.buildId, 2, 0, 'previous attempt', timestamp - 5).run();

    await retryBuild(db, { id: 'maintainer-1', role: 'maintainer', areas: ['system'] }, seeded.buildId, 'Worker image was repaired.');
    const reset = await db.prepare(`SELECT status,worker_id,lease_token,lease_expires_at,attempt,error,artifact_key,artifact_sha256,
      artifact_size,artifact_filename,installed_size,dependency_plan_json,provenance,provenance_signature,smoke_passed,started_at,finished_at
      FROM builds WHERE id=?`).bind(seeded.buildId).first<any>();
    expect(reset).toEqual({ status: 'queued', worker_id: null, lease_token: null, lease_expires_at: null, attempt: 2, error: null,
      artifact_key: null, artifact_sha256: null, artifact_size: null, artifact_filename: null, installed_size: null,
      dependency_plan_json: null, provenance: null, provenance_signature: null, smoke_passed: 0, started_at: null, finished_at: null });
    expect((await db.prepare('SELECT COUNT(*) AS count FROM build_logs WHERE build_id=?').bind(seeded.buildId).first<any>())?.count).toBe(1);
    const auditRow = await db.prepare("SELECT detail FROM audit_events WHERE action='build.retry_requested' AND target=?").bind(seeded.buildId).first<{ detail: string }>();
    expect(JSON.parse(auditRow?.detail ?? '{}')).toMatchObject({ requestId: seeded.requestId, revisionId: seeded.revisionId, attempt: 2, reason: 'Worker image was repaired.' });
    expect((await db.prepare('SELECT status FROM requests WHERE id=?').bind(seeded.requestId).first<any>())?.status).toBe('queued');

    const job = await claimJob(db, worker);
    expect(job?.id).toBe(seeded.buildId);
    expect((await db.prepare('SELECT status FROM requests WHERE id=?').bind(seeded.requestId).first<any>())?.status).toBe('building');
    expect((await db.prepare('SELECT attempt FROM builds WHERE id=?').bind(seeded.buildId).first<any>())?.attempt).toBe(3);
    expect((await completeJob(db, new MemoryR2() as unknown as R2Bucket, worker, seeded.buildId, {
      leaseToken: job!.leaseToken, status: 'failed', error: 'still failed', smokePassed: false,
    })).status).toBe('failed');
    expect((await db.prepare('SELECT status FROM requests WHERE id=?').bind(seeded.requestId).first<any>())?.status).toBe('failed');
    const failureAudit = await db.prepare("SELECT target FROM audit_events WHERE action='request.failed' AND target=?").bind(seeded.requestId).first<any>();
    expect(failureAudit?.target).toBe(seeded.requestId);
  } finally {
    holder.close();
  }
});

test('failed build retry requires both current approvals', async () => {
  const { holder, db, worker } = await fixture();
  try {
    const seeded = await seedBuild(db);
    await db.prepare("UPDATE requests SET status='failed' WHERE id=?").bind(seeded.requestId).run();
    await db.prepare("UPDATE builds SET status='failed' WHERE id=?").bind(seeded.buildId).run();
    await db.prepare("UPDATE approvals SET revoked_at=? WHERE revision_id=? AND kind='security'")
      .bind(Math.floor(Date.now() / 1000), seeded.revisionId).run();
    await expect(retryBuild(db, { id: 'maintainer-1', role: 'maintainer', areas: ['system'] }, seeded.buildId, 'Retry after worker repair.'))
      .rejects.toThrow('Current area and security approvals are required before retry');
    expect((await db.prepare('SELECT status FROM requests WHERE id=?').bind(seeded.requestId).first<any>())?.status).toBe('failed');
    expect((await db.prepare('SELECT status FROM builds WHERE id=?').bind(seeded.buildId).first<any>())?.status).toBe('failed');
  } finally {
    holder.close();
  }
});

test('claim freezes and returns an exact signed OPR dependency plan', async () => {
  const { holder, db, keys, worker } = await fixture();
  const bucket = new MemoryR2();
  try {
    const seeded = await seedBuild(db, { surface: 'recipe', dependencies: ['opr-base>=1.0'] });
    const timestamp = Math.floor(Date.now() / 1000);
    const revisionId = 'dependency-revision';
    const buildId = 'dependency-build';
    const filename = 'opr-base-1.0-1-x86_64.pkg.tar.zst';
    const artifactKey = `packages/x86_64/${filename}`;
    const artifact = new TextEncoder().encode('signed dependency package');
    const signature = new TextEncoder().encode('signed dependency signature');
    const artifactSha256 = await sha256(artifact);
    const signatureSha256 = await sha256(signature);
    await db.prepare('INSERT INTO requests(id,name,upstream_url,source_kind,area,requested_by,status,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)')
      .bind('dependency-request', 'opr-base', 'https://example.org/opr-base.tar.gz', 'archive', 'system', 'requestor', 'built', timestamp, timestamp).run();
    await db.prepare(`INSERT INTO revisions(id,request_id,version,recipe,recipe_sha256,manifest_sha256,sources_json,dependencies_json,
      smoke_commands_json,architectures_json,source_date_epoch,image_digest,license,surface,explanation,sbom_json,lint_json,created_at)
      VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).bind(
      revisionId, 'dependency-request', '1.0', 'pkgname=opr-base\n', 'a'.repeat(64), 'm'.repeat(64), '[]', '[]', '[]', '["x86_64"]', 1,
      `ghcr.io/opr/builder@sha256:${'a'.repeat(64)}`, 'MIT', 'binary', 'base', '{}', '{}', timestamp,
    ).run();
    await db.prepare('INSERT INTO approvals(id,revision_id,actor,kind,manifest_sha256,created_at) VALUES(?,?,?,?,?,?),(?,?,?,?,?,?)')
      .bind('dependency-area', revisionId, 'github:1', 'area', 'm'.repeat(64), timestamp, 'dependency-security', revisionId, 'github:2', 'security', 'm'.repeat(64), timestamp).run();
    const provenance = JSON.stringify({ packageMetadata: {
      name: 'opr-base', fullVersion: '1.0-1', architecture: 'x86_64', installedSize: 10,
      depends: [], provides: [], conflicts: [], replaces: [],
    } });
    await db.prepare(`INSERT INTO builds(id,revision_id,architecture,status,artifact_key,artifact_sha256,artifact_size,artifact_filename,provenance,smoke_passed,created_at)
      VALUES(?,?,?,?,?,?,?,?,?,?,?)`).bind(buildId, revisionId, 'x86_64', 'succeeded', artifactKey, artifactSha256, artifact.byteLength, filename, provenance, 1, timestamp).run();
    await db.prepare(`INSERT INTO releases(id,build_id,name,version,architecture,surface,channel,artifact_key,signature_key,recipe_key,sbom_key,provenance_key,published_at)
      VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`).bind('dependency-release', buildId, 'opr-base', '1.0-1', 'x86_64', 'binary', 'stable', artifactKey, `${artifactKey}.sig`, 'recipe', 'sbom', 'provenance', timestamp).run();
    await bucket.put(artifactKey, artifact, { customMetadata: { sha256: artifactSha256 } });
    await bucket.put(`${artifactKey}.sig`, signature, { customMetadata: { sha256: signatureSha256 } });

    const job = await claimJob(db, worker, null, {
      ARTIFACTS: bucket as unknown as R2Bucket, PUBLIC_ORIGIN: 'https://opr.test', PACKAGE_SIGNING_FINGERPRINT: 'a'.repeat(40),
    });
    expect(job?.id).toBe(seeded.buildId);
    expect(job?.dependencyPlan).toMatchObject({ channel: 'stable', publicKeyUrl: 'https://opr.test/repo/key.asc', packages: [{ releaseId: 'dependency-release', name: 'opr-base', version: '1.0-1', sha256: artifactSha256, signatureSha256 }] });
    if (!job) throw new Error('dependency build was not claimed');
    const frozen = await db.prepare('SELECT dependency_plan_json FROM builds WHERE id=?').bind(seeded.buildId).first<{ dependency_plan_json: string }>();
    expect(JSON.parse(frozen?.dependency_plan_json ?? '{}')).toEqual(job?.dependencyPlan);

    const dependencyReleaseProvenance = (dependencyPlan: unknown) => JSON.stringify({
      buildId: job.id, revisionId: job.revisionId, workerId: worker.id, recipeSha256: job.recipeSha256,
      artifactSha256: null, architecture: job.architecture, imageDigest: job.imageDigest, sourceDateEpoch: job.sourceDateEpoch,
      sources: job.sources, network: 'disabled', startedAt: '2026-01-01T00:00:00Z', finishedAt: '2026-01-01T00:01:00Z', dependencyPlan,
    });
    const badPlan = JSON.parse(JSON.stringify(job.dependencyPlan)) as Record<string, unknown>;
    (badPlan.packages as Array<Record<string, unknown>>)[0].sha256 = 'f'.repeat(64);
    const badProvenance = dependencyReleaseProvenance(badPlan);
    const badSignature = base64(await crypto.subtle.sign({ name: 'Ed25519' }, keys.privateKey, new TextEncoder().encode(badProvenance)));
    await expectProtocolError(completeJob(db, bucket as unknown as R2Bucket, worker, job.id, {
      leaseToken: job.leaseToken, status: 'succeeded', provenance: badProvenance, provenanceSignature: badSignature, smokePassed: true,
    }), 409);
    const goodProvenance = dependencyReleaseProvenance(job.dependencyPlan);
    const goodSignature = base64(await crypto.subtle.sign({ name: 'Ed25519' }, keys.privateKey, new TextEncoder().encode(goodProvenance)));
    expect((await completeJob(db, bucket as unknown as R2Bucket, worker, job.id, {
      leaseToken: job.leaseToken, status: 'succeeded', provenance: goodProvenance, provenanceSignature: goodSignature, smokePassed: true,
    })).status).toBe('succeeded');
  } finally {
    holder.close();
  }
});

test('heartbeat, log, artifact, and signed provenance completion are fenced and idempotent', async () => {
  const { holder, db, keys, worker } = await fixture();
  const bucket = new MemoryR2();
  try {
    const seeded = await seedBuild(db);
    const job = await claimJob(db, worker);
    expect(job?.id).toBe(seeded.buildId);
    if (!job) throw new Error('job was not claimed');
    const otherKeys = await keyPair();
    const otherToken = await createEnrollmentToken(db, 'maintainer-3', 'aarch64', 300);
    const otherEnrollment = await enrollWorker(db, { token: otherToken.token, name: 'other', architecture: 'aarch64', publicKey: otherKeys.publicKey });
    const otherWorker = await db.prepare('SELECT id, name, architecture, public_key, status, enrolled_at, last_seen_at, daemon_version, runtime, capabilities_json, accepting_jobs, paused_at, removed_at FROM workers WHERE id = ?').bind(otherEnrollment.id).first<any>();
    await expectProtocolError(heartbeatJob(db, otherWorker, job.id, job.leaseToken), 409);
    expect((await heartbeatJob(db, worker, job.id, job.leaseToken)).cancel).toBe(false);
    await heartbeatJob(db, worker, job.id, job.leaseToken, {
      version: 'v0.2.0', runtime: 'docker', capabilities: ['offline-oci']
    });
    const refreshed = await db.prepare('SELECT daemon_version, runtime, capabilities_json FROM workers WHERE id=?').bind(worker.id).first<any>();
    expect(refreshed).toEqual({ daemon_version: 'v0.2.0', runtime: 'docker', capabilities_json: '["offline-oci"]' });
    expect((await appendJobLog(db, worker, job.id, { leaseToken: job.leaseToken, sequence: 0, text: 'build started' })).duplicate).toBe(false);
    expect((await appendJobLog(db, worker, job.id, { leaseToken: job.leaseToken, sequence: 0, text: 'build started' })).duplicate).toBe(true);
    await expectProtocolError(appendJobLog(db, worker, job.id, { leaseToken: job.leaseToken, sequence: 0, text: 'tampered' }), 409);
    const artifactBody = new TextEncoder().encode('fake package bytes');
    const artifact = await uploadArtifact(db, bucket as unknown as R2Bucket, worker, job.id, job.leaseToken, 'package-1.0-1-x86_64.pkg.tar.zst', artifactBody);
    const startedAt = new Date().toISOString();
    const finishedAt = new Date(Date.now() + 1000).toISOString();
    const provenance = JSON.stringify({
      buildId: job.id,
      revisionId: job.revisionId,
      workerId: worker.id,
      recipeSha256: job.recipeSha256,
      artifactSha256: artifact.sha256,
      architecture: job.architecture,
      imageDigest: job.imageDigest,
      sourceDateEpoch: job.sourceDateEpoch,
      installedSize: 4096,
      packageMetadata: { name: job.packageName, fullVersion: `${job.version}-${job.pkgrel ?? 1}`, architecture: job.architecture, installedSize: 4096,
        depends: ['bash', 'glibc', 'lib:libOpenCL.so.1'], provides: [], conflicts: [], replaces: [] },
      sources: job.sources,
      network: 'disabled',
      startedAt,
      finishedAt
    });
    const provenanceSignature = base64(await crypto.subtle.sign({ name: 'Ed25519' }, keys.privateKey, new TextEncoder().encode(provenance) as BufferSource));
    const input = { leaseToken: job.leaseToken, status: 'succeeded' as const, installedSize: 4096, artifact, provenance, provenanceSignature, smokePassed: true };
    const missingInstalledSize = { ...input };
    delete (missingInstalledSize as { installedSize?: number }).installedSize;
    await expectProtocolError(completeJob(db, bucket as unknown as R2Bucket, worker, job.id, missingInstalledSize), 400);
    await expectProtocolError(completeJob(db, bucket as unknown as R2Bucket, worker, job.id, {
      leaseToken: job.leaseToken, status: 'failed' as const, installedSize: 4096, error: 'failed', smokePassed: false
    }), 400);
    const mismatchedProvenance = JSON.stringify({ ...JSON.parse(provenance), installedSize: 4097 });
    const mismatchedSignature = base64(await crypto.subtle.sign({ name: 'Ed25519' }, keys.privateKey, new TextEncoder().encode(mismatchedProvenance) as BufferSource));
    await expectProtocolError(completeJob(db, bucket as unknown as R2Bucket, worker, job.id, {
      ...input, provenance: mismatchedProvenance, provenanceSignature: mismatchedSignature
    }), 409);
    for (const packageMetadata of [undefined, { ...JSON.parse(provenance).packageMetadata, depends: [] },
      { ...JSON.parse(provenance).packageMetadata, name: 'unreviewed' },
      { ...JSON.parse(provenance).packageMetadata, fullVersion: '99.0-1' },
      { ...JSON.parse(provenance).packageMetadata, depends: ['glibc\nforged'] }]) {
      const changed = JSON.stringify({ ...JSON.parse(provenance), packageMetadata });
      const signature = base64(await crypto.subtle.sign({ name: 'Ed25519' }, keys.privateKey, new TextEncoder().encode(changed) as BufferSource));
      await expectProtocolError(completeJob(db, bucket as unknown as R2Bucket, worker, job.id, {
        ...input, provenance: changed, provenanceSignature: signature
      }), 409);
    }
    expect((await completeJob(db, bucket as unknown as R2Bucket, worker, job.id, input)).idempotent).toBe(false);
    expect((await completeJob(db, bucket as unknown as R2Bucket, worker, job.id, input)).idempotent).toBe(true);
    const row = await db.prepare('SELECT status, installed_size, provenance_signature, smoke_passed FROM builds WHERE id = ?').bind(job.id).first<any>();
    expect(row.status).toBe('succeeded');
    expect(row.installed_size).toBe(4096);
    expect(row.provenance_signature).toBe(provenanceSignature);
    expect(row.smoke_passed).toBe(1);
  } finally {
    holder.close();
  }
});

test('expired lease can be reclaimed and stale worker mutations fail', async () => {
  const { holder, db, worker } = await fixture();
  try {
    const seeded = await seedBuild(db);
    const first = await claimJob(db, worker);
    expect(first).not.toBeNull();
    await db.prepare("UPDATE builds SET lease_expires_at = strftime('%s','now') - 1 WHERE id = ?").bind(seeded.buildId).run();
    if (!first) throw new Error('job was not claimed');
    await expectProtocolError(appendJobLog(db, worker, seeded.buildId, { leaseToken: first.leaseToken, sequence: 0, text: 'stale' }), 409);
    const second = await claimJob(db, worker);
    expect(second?.leaseToken).not.toBe(first.leaseToken);
    await expectProtocolError(heartbeatJob(db, worker, seeded.buildId, first.leaseToken), 409);
  } finally {
    holder.close();
  }
});

test('job completion accepts verified multipart artifacts above the direct upload limit', async () => {
  const { holder, db, worker, keys } = await fixture();
  try {
    await seedBuild(db);
    const job = (await claimJob(db, worker))!;
    const artifact = { key: 'private/multipart/package.pkg.tar.zst', filename: 'package-1.0.0-1-x86_64.pkg.tar.zst',
      sha256: 'a'.repeat(64), size: 101 * 1024 * 1024 };
    // Multipart upload already streamed and verified these bytes before recording the artifact.
    await db.prepare('UPDATE builds SET artifact_key=?,artifact_filename=?,artifact_sha256=?,artifact_size=? WHERE id=?')
      .bind(artifact.key, artifact.filename, artifact.sha256, artifact.size, job.id).run();
    const bucket = { head: async () => ({ size: artifact.size, customMetadata: { sha256: artifact.sha256 } }) } as unknown as R2Bucket;
    const installedSize = 256 * 1024 * 1024;
    const provenance = JSON.stringify({ buildId: job.id, revisionId: job.revisionId, workerId: worker.id,
      recipeSha256: job.recipeSha256, artifactSha256: artifact.sha256, architecture: job.architecture,
      imageDigest: job.imageDigest, sourceDateEpoch: job.sourceDateEpoch, sources: job.sources, network: 'disabled',
      installedSize, packageMetadata: { name: job.packageName, fullVersion: `${job.version}-${job.pkgrel ?? 1}`,
        architecture: job.architecture, installedSize, depends: ['bash'], provides: [], conflicts: [], replaces: [] },
      startedAt: new Date().toISOString(), finishedAt: new Date().toISOString() });
    const provenanceSignature = base64(await crypto.subtle.sign('Ed25519', keys.privateKey, new TextEncoder().encode(provenance)));
    const input = { leaseToken: job.leaseToken, status: 'succeeded' as const, installedSize, artifact, provenance, provenanceSignature, smokePassed: true };
    await expectProtocolError(completeJob(db, bucket, worker, job.id, { ...input, artifact: { ...artifact, size: 4 * 1024 ** 3 + 1 } }), 400);
    expect((await completeJob(db, bucket, worker, job.id, input)).status).toBe('succeeded');
  } finally {
    holder.close();
  }
});

test('Surface B recipe builds cannot upload artifacts', async () => {
  const { holder, db, worker } = await fixture();
  try {
    const seeded = await seedBuild(db, { surface: 'recipe' });
    const job = await claimJob(db, worker);
    expect(job?.surface).toBe('recipe');
    if (!job) throw new Error('job was not claimed');
    await expectProtocolError(uploadArtifact(db, new MemoryR2() as unknown as R2Bucket, worker, seeded.buildId, job.leaseToken, 'package-1.0-1-x86_64.pkg.tar.zst', new Uint8Array([1])), 409);
  } finally {
    holder.close();
  }
});
