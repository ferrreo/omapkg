import { sha256 } from '../src/lib/server/db';
import type { Env } from '../src/lib/server/env';
import { asD1, TestD1 } from './d1';

export const schema = `
CREATE TABLE requests(id TEXT PRIMARY KEY,name TEXT,upstream_url TEXT,source_kind TEXT,area TEXT,requested_by TEXT,status TEXT,created_at INTEGER,updated_at INTEGER);
CREATE TABLE revisions(id TEXT PRIMARY KEY,request_id TEXT,version TEXT,recipe TEXT,recipe_sha256 TEXT,manifest_sha256 TEXT,sources_json TEXT,dependencies_json TEXT,smoke_commands_json TEXT,architectures_json TEXT,source_date_epoch INTEGER,image_digest TEXT,license TEXT,surface TEXT,explanation TEXT,sbom_json TEXT,lint_json TEXT,upstream_commit TEXT,pr_url TEXT,commit_sha TEXT,created_at INTEGER,description TEXT);
CREATE TABLE builds(id TEXT PRIMARY KEY,revision_id TEXT,status TEXT,architecture TEXT,worker_id TEXT,artifact_key TEXT,artifact_sha256 TEXT,artifact_size INTEGER,installed_size INTEGER,dependency_plan_json TEXT,artifact_filename TEXT,provenance TEXT,provenance_signature TEXT,smoke_passed INTEGER,created_at INTEGER);
CREATE TABLE approvals(id TEXT PRIMARY KEY,revision_id TEXT,actor TEXT,kind TEXT,manifest_sha256 TEXT,created_at INTEGER,revoked_at INTEGER,revoked_by TEXT);
CREATE TABLE releases(id TEXT PRIMARY KEY,build_id TEXT,name TEXT,version TEXT,architecture TEXT,surface TEXT,channel TEXT,artifact_key TEXT,signature_key TEXT,recipe_key TEXT,sbom_key TEXT,provenance_key TEXT,published_at INTEGER,stable_at INTEGER,batch_id TEXT,previous_release_id TEXT);
CREATE TABLE crash_reports(id TEXT PRIMARY KEY,release_id TEXT,summary TEXT,consent_version TEXT,created_at INTEGER,resolved_at INTEGER,resolved_by TEXT);
CREATE TABLE audit_events(id INTEGER PRIMARY KEY AUTOINCREMENT,actor TEXT,action TEXT,target TEXT,detail TEXT,created_at INTEGER);
`;

export class MemoryR2 {
  readonly objects = new Map<string, Uint8Array>();
  private object(key: string) {
    const bytes = this.objects.get(key);
    if (!bytes) return null;
    return { size: bytes.byteLength, etag: key, httpEtag: `"${key}"`, customMetadata: key.startsWith('signatures/') ? { signatureSha256: 'a'.repeat(64) } : {}, httpMetadata: {}, body: new Response(bytes.buffer as ArrayBuffer).body, arrayBuffer: async () => bytes.slice().buffer as ArrayBuffer, text: async () => new TextDecoder().decode(bytes) };
  }
  head(key: string) { return Promise.resolve(this.object(key)); }
  async get(key: string, options?: R2GetOptions) {
    const conditional = options?.onlyIf;
    const etag = conditional && 'etagMatches' in conditional ? conditional.etagMatches : undefined;
    if (typeof etag === 'string' && (etag.startsWith('"') || etag.endsWith('"'))) {
      throw new Error(`Conditional ETag should not be wrapped in quotes (${etag}).`);
    }
    if (typeof etag === 'string' && etag !== key) return null;
    return this.object(key);
  }
  async put(key: string, value: ArrayBuffer | ArrayBufferView | ReadableStream<Uint8Array>, options?: R2PutOptions) {
    const bytes = value instanceof ReadableStream
      ? new Uint8Array(await new Response(value).arrayBuffer())
      : value instanceof ArrayBuffer ? new Uint8Array(value) : new Uint8Array(value.buffer as ArrayBuffer, value.byteOffset, value.byteLength);
    if (typeof options?.sha256 === 'string' && await sha256(bytes) !== options.sha256) throw new Error('checksum mismatch');
    this.objects.set(key, new Uint8Array(bytes));
    return this.object(key);
  }
}

export function base64(bytes: ArrayBuffer): string {
  let binary = '';
  for (const byte of new Uint8Array(bytes)) binary += String.fromCharCode(byte);
  return btoa(binary);
}

export function env(db: TestD1): Env {
  return { DB: asD1(db), ARTIFACTS: {} as R2Bucket, PUBLIC_ORIGIN: 'https://opr.example', MAINTAINER_GITHUB_IDS: '', SECURITY_GITHUB_IDS: '', QUARANTINE_HOURS: '48' };
}

export function insertBinaryRelease(db: TestD1, input: {
  id: string; name: string; version: string; dependencies: string[]; channel: 'stable' | 'dev'; requestId?: string;
  nativeDependencies?: string[]; nativeProvides?: string[]; nativeConflicts?: string[]; nativeReplaces?: string[];
}) {
  const requestId = input.requestId ?? `request-${input.id}`;
  const revisionId = `revision-${input.id}`;
  const buildId = `build-${input.id}`;
  db.prepare('INSERT INTO requests VALUES(?,?,?,?,?,?,?,?,?)').bind(requestId, input.name, `https://example.org/${input.name}`, 'archive', 'development', 'github:1', 'built', 1, 1).run();
  db.prepare('INSERT INTO revisions VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)').bind(
    revisionId, requestId, input.version, `pkgname=${input.name}\n`, 'a'.repeat(64), 'b'.repeat(64), '[{"name":"source.tar.gz","url":"https://example.org/source.tar.gz","sha256":"' + 'c'.repeat(64) + '"}]', JSON.stringify(input.dependencies), '[]', '["x86_64"]', 1, 'ghcr.io/opr/builder@sha256:' + 'd'.repeat(64), 'MIT', 'binary', input.name, '{}', '{"passed":true}', null, 'https://github.com/example-owner/recipes/pull/1', 'e'.repeat(40), 1, null,
  ).run();
  db.prepare('INSERT INTO builds VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)').bind(
    buildId, revisionId, 'succeeded', 'x86_64', null, `private/${buildId}`, 'f'.repeat(64), 3, 10, null, `${input.name}-${input.version}-x86_64.pkg.tar.zst`, JSON.stringify({
      buildId, revisionId, workerId: null, recipeSha256: 'a'.repeat(64), pkgrel: 1, installedSize: 10,
      packageMetadata: {
        name: input.name, fullVersion: input.version, architecture: 'x86_64', installedSize: 10,
        depends: input.nativeDependencies ?? input.dependencies, provides: input.nativeProvides ?? [],
        conflicts: input.nativeConflicts ?? [], replaces: input.nativeReplaces ?? [],
      },
      artifactSha256: 'f'.repeat(64), architecture: 'x86_64', imageDigest: 'd'.repeat(64), sourceDateEpoch: 1, sources: [], network: 'disabled', startedAt: '2026-01-01T00:00:00Z', finishedAt: '2026-01-01T00:01:00Z',
    }), 'AA==', 1, 1,
  ).run();
  db.prepare('INSERT INTO releases VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)').bind(
    input.id, buildId, input.name, input.version, 'x86_64', 'binary', input.channel,
    `packages/x86_64/${input.name}-${input.version}-x86_64.pkg.tar.zst`, 'signatures/package.sig', `recipes/${input.name}/${input.version}/x86_64/PKGBUILD`, 'metadata/sbom', 'metadata/provenance', 1,
    input.channel === 'stable' ? 1 : null, null, null,
  ).run();
  db.prepare('INSERT INTO approvals VALUES(?,?,?,?,?,?,?,?)').bind(`approval-area-${input.id}`, revisionId, 'github:1', 'area', 'b'.repeat(64), 1, null, null).run();
  db.prepare('INSERT INTO approvals VALUES(?,?,?,?,?,?,?,?)').bind(`approval-security-${input.id}`, revisionId, 'github:2', 'security', 'b'.repeat(64), 1, null, null).run();
}
