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
import { issueRegistryCredentials } from '../src/lib/server/worker-registry';
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
const account = 'a'.repeat(32);
const imageDigest = 'd'.repeat(64);
const imageRef = `registry.cloudflare.com/${account}/omarpkg-arch-builder:stable@sha256:${imageDigest}`;

function base64(bytes: ArrayBuffer): string {
  let binary = '';
  for (const byte of new Uint8Array(bytes)) binary += String.fromCharCode(byte);
  return btoa(binary);
}

async function fixture(options: { privateImage?: boolean; imageRef?: string } = {}) {
  const holder = new TestD1(schema);
  const db = asD1(holder);
  const keys = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
  const token = await createEnrollmentToken(db, 'maintainer', 'x86_64', 300);
  const enrolled = await enrollWorker(db, {
    token: token.token,
    name: 'registry-worker',
    architecture: 'x86_64',
    publicKey: base64(await crypto.subtle.exportKey('raw', keys.publicKey)),
    version: 'v0.1.0', runtime: 'podman', capabilities: ['offline-oci', 'registry-pull']
  });
  const worker = await db.prepare('SELECT * FROM workers WHERE id=?').bind(enrolled.id).first<Worker>();
  const requestId = crypto.randomUUID();
  const revisionId = crypto.randomUUID();
  const buildId = crypto.randomUUID();
  const timestamp = Math.floor(Date.now() / 1000);
  const recipe = 'pkgname=registry-test\npkgver=1\npkgrel=1\n';
  const manifest = await sha256(buildId);
  await db.prepare(`INSERT INTO requests(id,name,upstream_url,source_kind,area,requested_by,status,created_at,updated_at)
    VALUES(?,?,?,?,?,?,?,?,?)`).bind(requestId, `registry-${buildId.slice(0, 8)}`, 'https://example.com/source.tar.gz', 'archive', 'system', 'requestor', 'queued', timestamp, timestamp).run();
  await db.prepare(`INSERT INTO revisions(id,request_id,version,recipe,recipe_sha256,manifest_sha256,sources_json,dependencies_json,
    smoke_commands_json,architectures_json,build_images_json,source_date_epoch,image_digest,license,surface,explanation,sbom_json,lint_json,upstream_commit,pr_url,commit_sha,created_at)
    VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).bind(
    revisionId, requestId, '1.0.0', recipe, await sha256(recipe), manifest,
    JSON.stringify([{ name: 'source.tar.gz', url: 'https://example.com/source.tar.gz', sha256: 'a'.repeat(64) }]), '[]', '[]', '["x86_64"]',
    JSON.stringify(options.privateImage === false ? {} : { x86_64: options.imageRef ?? imageRef }), 1700000000,
    `ghcr.io/opr/builder@sha256:${'c'.repeat(64)}`, 'MIT', 'binary', 'test', '{}', '{}', 'commit', 'https://github.com/opr/test/pull/1', 'review', timestamp
  ).run();
  await db.prepare('INSERT INTO approvals(id,revision_id,actor,kind,manifest_sha256,created_at) VALUES(?,?,?,?,?,?)')
    .bind(crypto.randomUUID(), revisionId, 'area', 'area', manifest, timestamp).run();
  await db.prepare('INSERT INTO approvals(id,revision_id,actor,kind,manifest_sha256,created_at) VALUES(?,?,?,?,?,?)')
    .bind(crypto.randomUUID(), revisionId, 'security', 'security', manifest, timestamp).run();
  await db.prepare('INSERT INTO builds(id,revision_id,architecture,status,created_at) VALUES(?,?,?,?,?)')
    .bind(buildId, revisionId, 'x86_64', 'queued', timestamp).run();
  const env = { DB: db, REGISTRY_ACCOUNT_ID: account, REGISTRY_API_TOKEN: 'registry-runtime-token' } as Parameters<typeof issueRegistryCredentials>[0];
  return { holder, db, worker: worker!, env, buildId, imageRef };
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

test('registry credentials are least privilege, short lived, scoped to approved image namespace, and audited without secrets', async () => {
  const { holder, db, worker, env, buildId, imageRef } = await fixture();
  const originalFetch = globalThis.fetch;
  let request: { input: RequestInfo | URL; init?: RequestInit } | undefined;
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    request = { input, init };
    return Response.json({
      success: true,
      result: { account_id: account, registry_host: 'registry.cloudflare.com', username: 'pull-user', password: 'pull-secret' }
    });
  }) as unknown as typeof fetch;
  try {
    const job = await claimJob(db, worker);
    if (!job) throw new Error('job was not claimed');
    const requestedAt = Date.now();
    const credentials = await issueRegistryCredentials(env, worker, buildId, { leaseToken: job.leaseToken });
    expect(credentials).toEqual({
      registry: 'registry.cloudflare.com', username: 'pull-user', password: 'pull-secret',
      expiresAt: expect.any(String)
    });
    expect(Date.parse(credentials.expiresAt)).toBeGreaterThanOrEqual(requestedAt + 15 * 60_000);
    expect(Date.parse(credentials.expiresAt)).toBeLessThanOrEqual(Date.now() + 15 * 60_000);
    expect(String(request?.input)).toBe(`https://api.cloudflare.com/client/v4/accounts/${account}/containers/registries/registry.cloudflare.com/credentials`);
    expect(new Headers(request?.init?.headers).get('Authorization')).toBe('Bearer registry-runtime-token');
    expect(JSON.parse(String(request?.init?.body))).toEqual({ expiration_minutes: 15, permissions: ['pull'] });
    const audit = await db.prepare("SELECT detail FROM audit_events WHERE action='worker.registry_credentials_issued'").first<{ detail: string }>();
    expect(audit?.detail).toContain(imageRef);
    expect(audit?.detail).toContain(credentials.expiresAt);
    expect(audit?.detail).not.toContain('pull-secret');
    expect(audit?.detail).not.toContain('registry-runtime-token');
  } finally {
    globalThis.fetch = originalFetch;
    holder.close();
  }
});

test('registry credentials reject public images, mismatched namespaces, and arbitrary request fields before calling Cloudflare', async () => {
  const publicFixture = await fixture({ privateImage: false });
  const namespaceFixture = await fixture({ imageRef: `registry.cloudflare.com/${'b'.repeat(32)}/other@sha256:${imageDigest}` });
  let calls = 0;
  const originalFetch = globalThis.fetch;
  globalThis.fetch = (async () => { calls += 1; return Response.json({ success: true }); }) as unknown as typeof fetch;
  try {
    const publicJob = await claimJob(publicFixture.db, publicFixture.worker);
    if (!publicJob) throw new Error('public job was not claimed');
    await expectProtocolError(issueRegistryCredentials(publicFixture.env, publicFixture.worker, publicFixture.buildId, { leaseToken: publicJob.leaseToken }), 409);
    await expectProtocolError(issueRegistryCredentials(publicFixture.env, publicFixture.worker, publicFixture.buildId, { leaseToken: publicJob.leaseToken, permissions: ['pull'] }), 400);
    const namespaceJob = await claimJob(namespaceFixture.db, namespaceFixture.worker);
    if (!namespaceJob) throw new Error('namespace job was not claimed');
    await expectProtocolError(issueRegistryCredentials(namespaceFixture.env, namespaceFixture.worker, namespaceFixture.buildId, { leaseToken: namespaceJob.leaseToken }), 409);
    expect(calls).toBe(0);
  } finally {
    globalThis.fetch = originalFetch;
    publicFixture.holder.close();
    namespaceFixture.holder.close();
  }
});
