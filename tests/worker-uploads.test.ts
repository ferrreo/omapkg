import { expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import type { Worker } from '../src/lib/model';
import { sha256 } from '../src/lib/server/db';
import {
  WorkerProtocolError,
  claimJob,
  createEnrollmentToken,
  enrollWorker
} from '../src/lib/server/workers';
import {
  MAX_UPLOAD_SIZE,
  UPLOAD_PART_SIZE,
  completeMultipartUpload,
  startMultipartUpload,
  uploadMultipartPart
} from '../src/lib/server/worker-uploads';
import type { UploadStartResult } from '../src/lib/server/worker-uploads';
import { TestD1, asD1 } from './d1';

const schema = readFileSync(new URL('../migrations/0001_initial.sql', import.meta.url), 'utf8') +
  '\n' + readFileSync(new URL('../migrations/0006_worker_uploads.sql', import.meta.url), 'utf8') +
  '\n' + readFileSync(new URL('../migrations/0007_core_guards.sql', import.meta.url), 'utf8') +
  '\n' + readFileSync(new URL('../migrations/0011_build_images.sql', import.meta.url), 'utf8') +
  '\n' + readFileSync(new URL('../migrations/0014_package_metadata.sql', import.meta.url), 'utf8') +
  '\n' + readFileSync(new URL('../migrations/0015_installed_size.sql', import.meta.url), 'utf8') +
  '\n' + readFileSync(new URL('../migrations/0018_worker_metadata.sql', import.meta.url), 'utf8') +
  '\n' + readFileSync(new URL('../migrations/0019_crash_triage.sql', import.meta.url), 'utf8') +
  '\n' + readFileSync(new URL('../migrations/0020_worker_lifecycle.sql', import.meta.url), 'utf8') +
  '\n' + readFileSync(new URL('../migrations/0023_dependency_plan.sql', import.meta.url), 'utf8');

class Multipart {
  readonly parts = new Map<number, Uint8Array>();
  completed = false;

  constructor(private readonly bucket: MultipartBucket, readonly key: string, readonly uploadId: string, private readonly metadata: Record<string, string>) {}

  async uploadPart(partNumber: number, value: Uint8Array): Promise<{ partNumber: number; etag: string }> {
    this.parts.set(partNumber, new Uint8Array(value));
    return { partNumber, etag: `etag-${partNumber}-${await sha256(value)}` };
  }

  async complete(parts: Array<{ partNumber: number; etag: string }>): Promise<unknown> {
    const chunks = parts.map((part) => this.parts.get(part.partNumber));
    if (chunks.some((chunk) => !chunk)) throw new Error('missing part');
    const size = chunks.reduce((total, chunk) => total + (chunk?.byteLength ?? 0), 0);
    const body = new Uint8Array(size);
    let offset = 0;
    for (const chunk of chunks) {
      body.set(chunk!, offset);
      offset += chunk!.byteLength;
    }
    this.bucket.objects.set(this.key, { body, metadata: this.metadata });
    this.completed = true;
    return {};
  }

  async abort(): Promise<void> {
    this.bucket.multipart.delete(this.uploadId);
  }
}

class MultipartBucket {
  readonly objects = new Map<string, { body: Uint8Array; metadata: Record<string, string> }>();
  readonly multipart = new Map<string, Multipart>();
  private sequence = 0;

  async createMultipartUpload(key: string, options?: { customMetadata?: Record<string, string> }): Promise<Multipart> {
    const upload = new Multipart(this, key, `r2-upload-${++this.sequence}`, options?.customMetadata ?? {});
    this.multipart.set(upload.uploadId, upload);
    return upload;
  }

  resumeMultipartUpload(key: string, uploadId: string): Multipart {
    const upload = this.multipart.get(uploadId);
    if (!upload || upload.key !== key) throw new Error('upload not found');
    return upload;
  }

  async get(key: string): Promise<unknown> {
    const object = this.objects.get(key);
    if (!object) return null;
    return {
      size: object.body.byteLength,
      customMetadata: object.metadata,
      body: new ReadableStream({
        start(controller) {
          controller.enqueue(object.body);
          controller.close();
        }
      })
    };
  }

  async delete(key: string): Promise<void> {
    this.objects.delete(key);
  }
}

function base64(bytes: ArrayBuffer): string {
  let binary = '';
  for (const byte of new Uint8Array(bytes)) binary += String.fromCharCode(byte);
  return btoa(binary);
}

async function workerFixture() {
  const holder = new TestD1(schema);
  const db = asD1(holder);
  const keys = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
  const token = await createEnrollmentToken(db, 'maintainer', 'x86_64', 300);
  const enrolled = await enrollWorker(db, {
    token: token.token,
    name: 'upload-worker',
    architecture: 'x86_64',
    publicKey: base64(await crypto.subtle.exportKey('raw', keys.publicKey)),
    version: 'v0.1.0', runtime: 'podman', capabilities: ['offline-oci', 'multipart-upload']
  });
  const worker = await db.prepare('SELECT * FROM workers WHERE id=?').bind(enrolled.id).first<Worker>();
  return { holder, db, worker: worker!, privateKey: keys.privateKey };
}

async function buildFixture(db: D1Database, expectedSize: number, expectedSha: string) {
  const requestId = crypto.randomUUID();
  const revisionId = crypto.randomUUID();
  const buildId = crypto.randomUUID();
  const timestamp = Math.floor(Date.now() / 1000);
  const recipe = 'pkgname=chunked\npkgver=1\npkgrel=1\n';
  const manifest = await sha256(buildId);
  const source = [{ name: 'source.tar.gz', url: 'https://example.com/source.tar.gz', sha256: 'a'.repeat(64) }];
  await db.prepare(`INSERT INTO requests(id,name,upstream_url,source_kind,area,requested_by,status,created_at,updated_at)
    VALUES(?,?,?,?,?,?,?,?,?)`).bind(requestId, `chunked-${buildId.slice(0, 8)}`, source[0].url, 'archive', 'system', 'requestor', 'queued', timestamp, timestamp).run();
  await db.prepare(`INSERT INTO revisions(id,request_id,version,recipe,recipe_sha256,manifest_sha256,sources_json,dependencies_json,
    smoke_commands_json,architectures_json,build_images_json,source_date_epoch,image_digest,license,surface,explanation,sbom_json,lint_json,upstream_commit,pr_url,commit_sha,created_at)
    VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).bind(
    revisionId, requestId, '1.0.0', recipe, await sha256(recipe), manifest, JSON.stringify(source), '[]', '[]', '["x86_64"]', '{}', 1700000000,
    `ghcr.io/opr/builder@sha256:${'c'.repeat(64)}`, 'MIT', 'binary', 'test', '{}', '{}', 'commit', 'https://github.com/opr/test/pull/1', 'review', timestamp
  ).run();
  await db.prepare('INSERT INTO approvals(id,revision_id,actor,kind,manifest_sha256,created_at) VALUES(?,?,?,?,?,?)')
    .bind(crypto.randomUUID(), revisionId, 'area', 'area', manifest, timestamp).run();
  await db.prepare('INSERT INTO approvals(id,revision_id,actor,kind,manifest_sha256,created_at) VALUES(?,?,?,?,?,?)')
    .bind(crypto.randomUUID(), revisionId, 'security', 'security', manifest, timestamp).run();
  await db.prepare('INSERT INTO builds(id,revision_id,architecture,status,created_at) VALUES(?,?,?,?,?)')
    .bind(buildId, revisionId, 'x86_64', 'queued', timestamp).run();
  return { buildId, expectedSize, expectedSha };
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

function activeUpload(result: UploadStartResult) {
  if ('completed' in result) throw new Error('expected an active upload');
  return result;
}

test('multipart upload resumes parts, verifies whole-object digest, and records the build artifact', async () => {
  const { holder, db, worker } = await workerFixture();
  const bucket = new MultipartBucket();
  try {
    const body = new TextEncoder().encode('large package payload');
    const build = await buildFixture(db, body.byteLength, await sha256(body));
    const job = await claimJob(db, worker);
    expect(job?.id).toBe(build.buildId);
    if (!job) throw new Error('job was not claimed');
    const started = activeUpload(await startMultipartUpload(db, bucket as unknown as R2Bucket, worker, build.buildId, {
      leaseToken: job.leaseToken, filename: 'chunked-1.0-1-x86_64.pkg.tar.zst', size: body.byteLength, sha256: build.expectedSha
    }));
    expect(started.partSize).toBe(UPLOAD_PART_SIZE);
    expect(started.maxSize).toBe(MAX_UPLOAD_SIZE);
    const part = await uploadMultipartPart(db, bucket as unknown as R2Bucket, worker, build.buildId, started.uploadId, 1, job.leaseToken, body);
    expect(part.size).toBe(body.byteLength);
    expect((await uploadMultipartPart(db, bucket as unknown as R2Bucket, worker, build.buildId, started.uploadId, 1, job.leaseToken, body)).etag).toBe(part.etag);
    const artifact = await completeMultipartUpload(db, bucket as unknown as R2Bucket, worker, build.buildId, started.uploadId, { leaseToken: job.leaseToken });
    expect(artifact.sha256).toBe(build.expectedSha);
    expect(artifact.size).toBe(body.byteLength);
    const row = await db.prepare('SELECT status, artifact_key, artifact_sha256, artifact_size FROM builds WHERE id=?').bind(build.buildId).first<any>();
    expect(row.status).toBe('leased');
    expect(row.artifact_key).toBe(artifact.key);
    expect(row.artifact_sha256).toBe(build.expectedSha);
    expect(row.artifact_size).toBe(body.byteLength);
    expect(await completeMultipartUpload(db, bucket as unknown as R2Bucket, worker, build.buildId, started.uploadId, { leaseToken: job.leaseToken })).toEqual(artifact);
    expect(await startMultipartUpload(db, bucket as unknown as R2Bucket, worker, build.buildId, {
      leaseToken: job.leaseToken, filename: artifact.filename, size: artifact.size, sha256: artifact.sha256
    })).toEqual({ completed: artifact });
  } finally {
    holder.close();
  }
});

test('multipart upload rejects wrong part sizes and aborts incomplete uploads', async () => {
  const { holder, db, worker } = await workerFixture();
  const bucket = new MultipartBucket();
  try {
    const size = UPLOAD_PART_SIZE + 1;
    const build = await buildFixture(db, size, 'd'.repeat(64));
    const job = await claimJob(db, worker);
    if (!job) throw new Error('job was not claimed');
    const started = activeUpload(await startMultipartUpload(db, bucket as unknown as R2Bucket, worker, build.buildId, {
      leaseToken: job.leaseToken, filename: 'chunked-1.0-1-x86_64.pkg.tar.zst', size, sha256: build.expectedSha
    }));
    await expectProtocolError(uploadMultipartPart(db, bucket as unknown as R2Bucket, worker, build.buildId, started.uploadId, 1, job.leaseToken, new Uint8Array(1)), 400);
    await expectProtocolError(completeMultipartUpload(db, bucket as unknown as R2Bucket, worker, build.buildId, started.uploadId, { leaseToken: job.leaseToken }), 409);
    const row = await db.prepare('SELECT status FROM worker_uploads WHERE id=?').bind(started.uploadId).first<any>();
    expect(row.status).toBe('failed');
  } finally {
    holder.close();
  }
});

test('multipart upload enforces the four-gigabyte declared size ceiling', async () => {
  const { holder, db, worker } = await workerFixture();
  const bucket = new MultipartBucket();
  try {
    const build = await buildFixture(db, 1, 'e'.repeat(64));
    const job = await claimJob(db, worker);
    if (!job) throw new Error('job was not claimed');
    await expectProtocolError(startMultipartUpload(db, bucket as unknown as R2Bucket, worker, build.buildId, {
      leaseToken: job.leaseToken, filename: 'chunked-1.0-1-x86_64.pkg.tar.zst', size: MAX_UPLOAD_SIZE + 1, sha256: 'e'.repeat(64)
    }), 400);
  } finally {
    holder.close();
  }
});

test('a reclaimed build can replace an upload from an expired worker lease', async () => {
  const { holder, db, worker } = await workerFixture();
  const bucket = new MultipartBucket();
  try {
    const body = new TextEncoder().encode('retry payload');
    const build = await buildFixture(db, body.byteLength, await sha256(body));
    const first = await claimJob(db, worker);
    if (!first) throw new Error('job was not claimed');
    const oldUpload = activeUpload(await startMultipartUpload(db, bucket as unknown as R2Bucket, worker, build.buildId, {
      leaseToken: first.leaseToken, filename: 'chunked-1.0-1-x86_64.pkg.tar.zst', size: body.byteLength, sha256: build.expectedSha
    }));
    await db.prepare("UPDATE builds SET lease_expires_at = strftime('%s','now') - 1 WHERE id=?").bind(build.buildId).run();
    const second = await claimJob(db, worker);
    if (!second) throw new Error('expired job was not reclaimed');
    const replacement = activeUpload(await startMultipartUpload(db, bucket as unknown as R2Bucket, worker, build.buildId, {
      leaseToken: second.leaseToken, filename: 'chunked-1.0-1-x86_64.pkg.tar.zst', size: body.byteLength, sha256: build.expectedSha
    }));
    expect(replacement.uploadId).not.toBe(oldUpload.uploadId);
    const statuses = await db.prepare('SELECT status FROM worker_uploads WHERE build_id=? ORDER BY created_at').bind(build.buildId).all<{ status: string }>();
    expect(statuses.results.map((row) => row.status)).toEqual(['failed', 'active']);
  } finally {
    holder.close();
  }
});
