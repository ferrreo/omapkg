import { expect, test } from 'bun:test';
import { readFileSync, readdirSync } from 'node:fs';
import { TestD1, asD1 } from './d1';
import { sha256 } from '../src/lib/server/db';
import { startInputUpload, writeInputPart, completeInputUpload } from '../src/lib/server/input-objects';
import { MAX_INPUT_OBJECT } from '../src/lib/frozen-inputs';
import { UPLOAD_PART_SIZE } from '../src/lib/server/worker-uploads';
import { execFileSync } from 'node:child_process';

test('native authorization queries fit D1 expression depth', () => {
  expect(execFileSync('python3', [new URL('./check-d1-depth.py', import.meta.url).pathname], { encoding: 'utf8' })).toContain('expression depth 100');
});

const schema = readdirSync(new URL('../migrations', import.meta.url)).filter((name) => name.endsWith('.sql')).sort()
  .map((name) => readFileSync(new URL(`../migrations/${name}`, import.meta.url), 'utf8')).join('\n');
class Bucket {
  objects = new Map<string, Blob>(); uploads = new Map<string, any>();
  async createMultipartUpload(key: string) {
    const parts = new Map<number, Uint8Array>(); const uploadId = crypto.randomUUID();
    const upload = { uploadId, uploadPart: async (partNumber: number, bytes: Uint8Array) => {
      parts.set(partNumber, bytes.slice()); return { partNumber, etag: await sha256(bytes) };
    }, complete: async (order: { partNumber: number }[]) => { this.objects.set(key, new Blob(order.map((part) => new Uint8Array(parts.get(part.partNumber)!).buffer))); },
    abort: async () => { this.uploads.delete(uploadId); } };
    this.uploads.set(uploadId, upload); return upload;
  }
  resumeMultipartUpload(_key: string, id: string) { return this.uploads.get(id); }
  async head(key: string) { const blob = this.objects.get(key); return blob ? { size: blob.size } : null; }
  async get(key: string) { const blob = this.objects.get(key); return blob ? { size: blob.size, body: blob.stream(), arrayBuffer: () => blob.arrayBuffer() } : null; }
}
const owner = { id: 'github:1', role: 'maintainer' as const, areas: ['system'] };
const security = { id: 'github:2', role: 'security' as const, areas: ['system'] };

test('private input upload resumes bounded parts, rejects substitution and rechecks human authority before retention', async () => {
  const holder = new TestD1(schema); const bucket = new Bucket();
  const env = { DB: asD1(holder), ARTIFACTS: bucket as unknown as R2Bucket };
  holder.exec("INSERT INTO team_memberships VALUES('1','system'),('2','security')");
  try {
    const bytes = new Uint8Array(UPLOAD_PART_SIZE + 5); bytes.fill(7);
    const ref = { sha256: await sha256(bytes), size: bytes.length };
    const start = await startInputUpload(env, owner, ref);
    if ('completed' in start) throw new Error('Expected new upload');
    await expect(writeInputPart(env, owner, ref.sha256, start.uploadId, 2, new Uint8Array(4))).rejects.toThrow('size');
    await writeInputPart(env, owner, ref.sha256, start.uploadId, 1, bytes.slice(0, UPLOAD_PART_SIZE));
    const resumed = await startInputUpload(env, owner, ref);
    expect(resumed).toMatchObject({ uploadId: start.uploadId, parts: [{ part_number: 1 }] });
    await expect(writeInputPart(env, owner, ref.sha256, start.uploadId, 1, new Uint8Array(UPLOAD_PART_SIZE))).rejects.toThrow('different bytes');
    await expect(completeInputUpload(env, owner, ref.sha256, start.uploadId)).rejects.toThrow('missing parts');
    await expect(writeInputPart(env, security, ref.sha256, start.uploadId, 2, bytes.slice(UPLOAD_PART_SIZE))).rejects.toThrow('unavailable');
    holder.exec("DELETE FROM team_memberships WHERE github_id='1'");
    await expect(writeInputPart(env, owner, ref.sha256, start.uploadId, 2, bytes.slice(UPLOAD_PART_SIZE))).rejects.toThrow();
    holder.exec("INSERT INTO team_memberships VALUES('1','system')");
    await writeInputPart(env, owner, ref.sha256, start.uploadId, 2, bytes.slice(UPLOAD_PART_SIZE));
    expect(await completeInputUpload(env, owner, ref.sha256, start.uploadId)).toEqual(ref);
    expect(await completeInputUpload(env, owner, ref.sha256, start.uploadId)).toEqual(ref);
    expect(await startInputUpload(env, security, ref)).toEqual({ completed: ref });
    expect(() => holder.exec("UPDATE input_objects SET object_key='substituted'")).toThrow('immutable');
    await expect(startInputUpload(env, owner, { sha256: 'a'.repeat(64), size: MAX_INPUT_OBJECT + 1 })).rejects.toThrow('size');
    const wrong = await startInputUpload(env, owner, { sha256: 'a'.repeat(64), size: 3 });
    if ('completed' in wrong) throw new Error('Expected new upload');
    await writeInputPart(env, owner, 'a'.repeat(64), wrong.uploadId, 1, new Uint8Array([1, 2, 3]));
    await expect(completeInputUpload(env, owner, 'a'.repeat(64), wrong.uploadId)).rejects.toThrow('declared checksum');
    expect(holder.prepare('SELECT COUNT(*) AS count FROM input_objects').first<{ count: number }>()).toEqual({ count: 1 });
  } finally { holder.close(); }
});
