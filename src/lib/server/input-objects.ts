import type { Actor } from '../model';
import { canonicalJson } from '../canonical-json';
import { INPUT_HASH, MAX_INPUT_OBJECT, parseInputObject, type InputObject } from '../frozen-inputs';
import type { Env } from './env';
import { actorForGithubId } from './auth';
import { humanMaintainer } from './catalog-ownership';
import { audit, id, now, query, sha256 } from './db';
import { PolicyError } from './policy';
import { hashObject, UPLOAD_PART_SIZE } from './worker-uploads';

type InputEnv = Pick<Env, 'DB' | 'ARTIFACTS'>;

export type InputObjectRow = { sha256: string; size: number; object_key: string; created_by: string; created_at: number };

type Upload = { id: string; sha256: string; size: number; object_key: string; r2_upload_id: string; created_by: string;
  status: 'active' | 'verifying' | 'complete' | 'failed'; expires_at: number };

type Part = { part_number: number; size: number; sha256: string; etag: string };

export async function inputAuthority(db: D1Database, actor: Actor | null): Promise<Actor> {
  const human = humanMaintainer(actor, 'system');

  return humanMaintainer(await actorForGithubId(db, human.id.slice(7)), 'system');
}

export async function inputObject(db: D1Database, digest: string): Promise<InputObjectRow> {
  if (!INPUT_HASH.test(digest)) throw new PolicyError(400, 'Invalid input checksum.');
  const row = await db.prepare('SELECT * FROM input_objects WHERE sha256=?').bind(digest).first<InputObjectRow>();

  if (!row) throw new PolicyError(409, `Retained input is missing: ${digest}`);

  return row;
}

export async function retainInputBytes(env: InputEnv, actor: Actor, bytes: Uint8Array): Promise<InputObject> {
  if (!bytes.length || bytes.length > 1024 * 1024) throw new PolicyError(400, 'Retained input document exceeds size limit.');
  const ref = { sha256: await sha256(bytes), size: bytes.byteLength };
  const key = `private/inputs/retained/${ref.sha256}`;
  await env.ARTIFACTS.put(key, bytes, { customMetadata: { sha256: ref.sha256 } });
  await env.DB.prepare('INSERT OR IGNORE INTO input_objects(sha256,size,object_key,created_by,created_at) VALUES(?,?,?,?,?)')
    .bind(ref.sha256, ref.size, key, actor.id, now()).run();

  if ((await inputObject(env.DB, ref.sha256)).size !== ref.size) throw new PolicyError(409, 'Retained input size changed.');
  await indexInputDocument(env.DB, ref.sha256, bytes);

  return ref;
}

async function indexInputDocument(db: D1Database, digest: string, bytes: Uint8Array) {
  if (bytes.length > 1024 * 1024) return;
  let text: string;

  try { text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);

 if (canonicalJson(JSON.parse(text)) !== text) return; }
  catch { return; } // Package archives, signatures and keys are not JSON documents.

  if (await sha256(bytes) !== digest) throw new PolicyError(409, 'Input document changed during retention.');
  await db.prepare('INSERT OR IGNORE INTO input_documents(sha256,canonical_json) VALUES(?,?)').bind(digest, text).run();
}

export async function inputDocuments(env: InputEnv, digests: string[], limit: number, totalLimit: number) {
  const unique = [...new Set(digests)];

  if (unique.some((digest) => !INPUT_HASH.test(digest))) throw new PolicyError(400, 'Invalid input document checksum.');
  const documents = new Map<string, { ref: InputObject; value: unknown }>(); let total = 0;

  for (let offset = 0; offset < unique.length; offset += 64) {
    const batch = unique.slice(offset, offset + 64);
    const rows = await query<InputObjectRow>(env.DB, 'SELECT * FROM input_objects WHERE sha256 IN (SELECT value FROM json_each(?))', JSON.stringify(batch));

    if (rows.length !== batch.length) throw new PolicyError(409, 'Retained input document is missing.');

    for (const row of rows) {
      total += row.size;

      if (row.size > limit || total > totalLimit) throw new PolicyError(409, 'Input documents exceed metadata budget.');
    }

    const indexed = await query<{ sha256: string; canonical_json: string }>(env.DB,
      'SELECT sha256,canonical_json FROM input_documents WHERE sha256 IN (SELECT value FROM json_each(?))', JSON.stringify(batch));

    const texts = new Map(indexed.map((row) => [row.sha256, row.canonical_json]));

    for (const row of rows) {
      let text = texts.get(row.sha256) ?? null;

      if (text === null) {
        const object = await env.ARTIFACTS.get(row.object_key);

        if (!object || object.size !== row.size) throw new PolicyError(409, 'Retained input object is unavailable.');
        const bytes = new Uint8Array(await object.arrayBuffer());

        if (bytes.byteLength !== row.size || await sha256(bytes) !== row.sha256) throw new PolicyError(409, 'Retained input checksum differs from lock.');
        await indexInputDocument(env.DB, row.sha256, bytes);
        text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
      }

      if (new TextEncoder().encode(text).byteLength !== row.size || await sha256(text) !== row.sha256) throw new PolicyError(409, 'Input document index differs from retained checksum.');
      const value = JSON.parse(text);

      if (canonicalJson(value) !== text) throw new PolicyError(409, 'Retained input JSON must use exact canonical fields.');
      documents.set(row.sha256, { ref: { sha256: row.sha256, size: row.size }, value });
    }
  }

  return documents;
}

export async function inputJson(env: InputEnv, ref: InputObject, limit: number): Promise<unknown> {
  parseInputObject(ref, limit);
  const document = (await inputDocuments(env, [ref.sha256], limit, limit)).get(ref.sha256)!;

  if (document.ref.size !== ref.size) throw new PolicyError(409, 'Retained input size differs from lock.');

  return document.value;
}

async function upload(env: InputEnv, actor: Actor, digest: string, uploadId: string): Promise<Upload> {
  const row = await env.DB.prepare('SELECT * FROM input_uploads WHERE id=? AND sha256=? AND created_by=?')
    .bind(uploadId, digest, actor.id).first<Upload>();

  if (!row || row.status === 'failed' || row.expires_at <= now()) throw new PolicyError(409, 'Input upload is unavailable or expired.');

  return row;
}

async function parts(db: D1Database, uploadId: string) {
  return query<Part>(db, 'SELECT part_number,size,sha256,etag FROM input_upload_parts WHERE upload_id=? ORDER BY part_number', uploadId);
}

export async function startInputUpload(env: InputEnv, actor: Actor | null, ref: InputObject) {
  const human = await inputAuthority(env.DB, actor);

  try { parseInputObject(ref); } catch { throw new PolicyError(400, 'Invalid input object size or checksum.'); }

  const completed = await env.DB.prepare('SELECT size FROM input_objects WHERE sha256=?').bind(ref.sha256).first<{ size: number }>();

  if (completed) {
    if (completed.size !== ref.size) throw new PolicyError(409, 'Retained checksum already has a different size.');

    return { completed: ref };
  }

  await env.DB.prepare("UPDATE input_uploads SET status='failed' WHERE sha256=? AND created_by=? AND expires_at<=? AND status IN ('active','verifying')")
    .bind(ref.sha256, human.id, now()).run();

  let row = await env.DB.prepare("SELECT * FROM input_uploads WHERE sha256=? AND created_by=? AND status IN ('active','verifying')")
    .bind(ref.sha256, human.id).first<Upload>();

  if (!row) {
    const uploadId = id(); const key = `private/inputs/uploads/${uploadId}/${ref.sha256}`;
    const multipart = await env.ARTIFACTS.createMultipartUpload(key);

    try {
      await env.DB.batch([
        env.DB.prepare(`INSERT INTO input_uploads(id,sha256,size,object_key,r2_upload_id,created_by,created_at,status,expires_at)
          VALUES(?,?,?,?,?,?,?,'active',?)`).bind(uploadId, ref.sha256, ref.size, key, multipart.uploadId, human.id, now(), now() + 86400),
        audit(env.DB, human.id, 'input.upload_started', ref.sha256, { uploadId, size: ref.size }),
      ]);
    } catch (cause) { await multipart.abort(); throw cause; }

    row = await upload(env, human, ref.sha256, uploadId);
  }

  if (row.size !== ref.size) throw new PolicyError(409, 'Upload checksum already has a different size.');

  return { uploadId: row.id, partSize: UPLOAD_PART_SIZE, status: row.status, parts: await parts(env.DB, row.id) };
}

export async function writeInputPart(env: InputEnv, actor: Actor | null, digest: string, uploadId: string, partNumber: number, bytes: Uint8Array) {
  const human = await inputAuthority(env.DB, actor); const row = await upload(env, human, digest, uploadId);
  const count = Math.ceil(row.size / UPLOAD_PART_SIZE);

  if (row.status !== 'active') throw new PolicyError(409, 'Input upload no longer accepts parts.');

  if (!Number.isSafeInteger(partNumber) || partNumber < 1 || partNumber > count) throw new PolicyError(400, 'Invalid input upload part number.');
  const expectedSize = partNumber === count ? row.size - (partNumber - 1) * UPLOAD_PART_SIZE : UPLOAD_PART_SIZE;

  if (bytes.byteLength !== expectedSize) throw new PolicyError(409, `Input part size is ${bytes.byteLength} bytes; expected ${expectedSize}.`);
  const hash = await sha256(bytes);
  const existing = await env.DB.prepare('SELECT * FROM input_upload_parts WHERE upload_id=? AND part_number=?').bind(uploadId, partNumber).first<Part>();

  if (existing) {
    if (existing.sha256 !== hash || existing.size !== bytes.byteLength) throw new PolicyError(409, 'Input part already contains different bytes.');

    return existing;
  }

  const part = await env.ARTIFACTS.resumeMultipartUpload(row.object_key, row.r2_upload_id).uploadPart(partNumber, bytes);

  if (part.partNumber !== partNumber || !part.etag) throw new PolicyError(503, 'Input storage returned invalid part.');
  await env.DB.prepare(`INSERT OR IGNORE INTO input_upload_parts(upload_id,part_number,size,sha256,etag)
    SELECT ?,?,?,?,? WHERE EXISTS(SELECT 1 FROM input_uploads WHERE id=? AND status='active' AND expires_at>?)`)
    .bind(uploadId, partNumber, bytes.byteLength, hash, part.etag, uploadId, now()).run();
  const saved = await env.DB.prepare('SELECT * FROM input_upload_parts WHERE upload_id=? AND part_number=?').bind(uploadId, partNumber).first<Part>();

  if (!saved || saved.sha256 !== hash || saved.size !== bytes.byteLength) throw new PolicyError(409, 'Input upload changed during part transfer.');

  return saved;
}

export async function completeInputUpload(env: InputEnv, actor: Actor | null, digest: string, uploadId: string): Promise<InputObject> {
  const human = await inputAuthority(env.DB, actor); const row = await upload(env, human, digest, uploadId);
  const ref = { sha256: row.sha256, size: row.size };

  if (row.status === 'complete') { await inputObject(env.DB, digest);

 return ref; }

  const saved = await parts(env.DB, row.id); const count = Math.ceil(row.size / UPLOAD_PART_SIZE);

  if (saved.length !== count || saved.some((part, index) => part.part_number !== index + 1 ||
      part.size !== (index + 1 === count ? row.size - index * UPLOAD_PART_SIZE : UPLOAD_PART_SIZE))) throw new PolicyError(409, 'Input upload is missing parts.');
  await env.DB.prepare("UPDATE input_uploads SET status='verifying' WHERE id=? AND status='active'").bind(row.id).run();

  // A retry after losing the completion response verifies the existing object.
  if (!await env.ARTIFACTS.head(row.object_key)) {
    await env.ARTIFACTS.resumeMultipartUpload(row.object_key, row.r2_upload_id).complete(saved.map((part) => ({ partNumber: part.part_number, etag: part.etag })));
  }

  const actual = await hashObject(env.ARTIFACTS, row.object_key, MAX_INPUT_OBJECT);

  if (actual.sha256 !== ref.sha256 || actual.size !== ref.size) {
    await env.DB.prepare("UPDATE input_uploads SET status='failed' WHERE id=? AND status='verifying'").bind(row.id).run();
    throw new PolicyError(409, 'Uploaded input bytes differ from declared checksum or size.');
  }

  await inputAuthority(env.DB, actor);
  await env.DB.batch([
    env.DB.prepare(`INSERT OR IGNORE INTO input_objects(sha256,size,object_key,created_by,created_at)
      SELECT sha256,size,object_key,created_by,? FROM input_uploads WHERE id=? AND status='verifying' AND expires_at>?
      AND EXISTS(SELECT 1 FROM team_memberships WHERE 'github:'||github_id=? AND team IN ('system','security','admin'))`)
      .bind(now(), row.id, now(), human.id),
    env.DB.prepare(`UPDATE input_uploads SET status='complete' WHERE id=? AND status='verifying'
      AND EXISTS(SELECT 1 FROM input_objects WHERE sha256=? AND size=?)`).bind(row.id, digest, row.size),
    audit(env.DB, human.id, 'input.upload_verified', digest, { uploadId, size: actual.size }),
  ]);

  if ((await inputObject(env.DB, digest)).size !== ref.size) throw new PolicyError(409, 'Input verification was fenced.');

  if (ref.size <= 1024 * 1024) {
    const object = await env.ARTIFACTS.get(row.object_key);

    if (!object || object.size !== ref.size) throw new PolicyError(409, 'Retained input object is unavailable.');
    await indexInputDocument(env.DB, digest, new Uint8Array(await object.arrayBuffer()));
  }

  return ref;
}
