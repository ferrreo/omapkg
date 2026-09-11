import { MAX_ABI_DOCUMENT, parseAbiDocument, parseAbiReference, type AbiInventory, type AbiChunk } from '../abi-inventory';
import type { InputObject } from '../frozen-inputs';
import type { Worker } from '../model';
import { now, sha256 } from './db';
import type { Env } from './env';
import { buildArtifacts, storedOutputContract } from './build-outputs';
import { requireWorkerLease, WorkerProtocolError, type WorkerLease } from './worker-protocol';
import type { OutputEvidence } from './output-evidence';

type Storage = Pick<Env, 'DB' | 'ARTIFACTS'>;

type Attempt = Pick<WorkerLease, 'id' | 'attempt'>;

export const abiObjectKey = (digest: string) => `private/abi/${digest}.json`;

const invalid = () => new WorkerProtocolError(409, 'ABI evidence is incomplete, changed or outside this build attempt');

export async function uploadAbiEvidence(env: Storage, worker: Worker, buildId: string, token: string, digest: string, bytes: Uint8Array): Promise<InputObject> {
  const build = await requireWorkerLease(env.DB, worker, buildId, token);

  if (!storedOutputContract(build) || !bytes.length || bytes.length > MAX_ABI_DOCUMENT || await sha256(bytes) !== digest) throw invalid();
  let text: string, document: AbiChunk | AbiInventory;

  try { text = new TextDecoder('utf-8', { fatal: true }).decode(bytes); document = parseAbiDocument(JSON.parse(text)); }
  catch { throw new WorkerProtocolError(400, 'Invalid ABI evidence document'); }

  if (!(await buildArtifacts(env.DB, build)).some((output) => output.sha256 === document.artifactSha256)) throw invalid();

  if (document.kind === 'abi-inventory') await assertAbiChunks(env.DB, build, document);
  const files = document.kind === 'abi-inventory' ? document.files : document.records.filter((record) => record.kind === 'file').length;
  const symbols = document.kind === 'abi-inventory' ? document.symbols : document.records.length - files;

  const existing = await env.DB.prepare('SELECT size FROM build_abi_evidence WHERE build_id=? AND attempt=? AND sha256=?')
    .bind(build.id, build.attempt, digest).first<{ size: number }>();

  if (existing) { if (existing.size !== bytes.length) throw invalid();

 return { sha256: digest, size: bytes.length }; }

  // ponytail: 4096 documents / 2 GiB per attempt; measure large split builds before raising this budget.
  const count = await env.DB.prepare('SELECT COUNT(*) AS count FROM build_abi_evidence WHERE build_id=? AND attempt=?')
    .bind(build.id, build.attempt).first<{ count: number }>();

  if ((count?.count ?? 0) >= 4096) throw new WorkerProtocolError(409, 'Build ABI evidence exceeds 4096 documents');
  await env.ARTIFACTS.put(abiObjectKey(digest), bytes, { customMetadata: { sha256: digest }, httpMetadata: { contentType: 'application/json' } });
  await env.DB.prepare(`INSERT OR IGNORE INTO build_abi_evidence(build_id,attempt,sha256,size,artifact_sha256,kind,start,files,symbols,manifest_json,created_at)
    SELECT id,attempt,?,?,?,?,?,?,?,?,? FROM builds WHERE id=? AND attempt=? AND worker_id=? AND lease_token=? AND status='leased' AND lease_expires_at>?
    AND output_contract_json=? AND EXISTS(SELECT 1 FROM workers WHERE id=? AND public_key=? AND status='active')
    AND revision_id=(SELECT r.id FROM revisions r WHERE r.request_id=(SELECT request_id FROM revisions WHERE id=builds.revision_id) ORDER BY r.created_at DESC,r.rowid DESC LIMIT 1)
    AND (builds.private_candidate=1 AND EXISTS (SELECT 1 FROM factory_runs fr JOIN factory_run_attempts fa ON fa.run_id=fr.id AND fa.attempt=fr.current_attempt
      WHERE fr.id=builds.factory_run_id AND fr.status='running' AND fr.current_attempt=builds.factory_attempt AND fr.lease_expires_at>unixepoch()
        AND fa.status='running' AND fa.lease_expires_at>unixepoch() AND fa.candidate_revision_id=builds.revision_id)
      OR builds.private_candidate=0 AND (SELECT COUNT(DISTINCT kind) FROM approvals WHERE revision_id=builds.revision_id AND manifest_sha256=(SELECT manifest_sha256 FROM revisions WHERE id=builds.revision_id) AND revoked_at IS NULL)=2)
    AND (SELECT COUNT(*) FROM build_abi_evidence e WHERE e.build_id=builds.id AND e.attempt=builds.attempt)<4096`)
    .bind(digest, bytes.length, document.artifactSha256, document.kind, document.kind === 'abi-records' ? document.start : 0,
      files, symbols, document.kind === 'abi-inventory' ? text : null, now(), build.id, build.attempt, worker.id, token, now(), build.output_contract_json, worker.id, worker.public_key).run();

  const saved = await env.DB.prepare('SELECT size FROM build_abi_evidence WHERE build_id=? AND attempt=? AND sha256=?')
    .bind(build.id, build.attempt, digest).first<{ size: number }>();

  if (saved?.size !== bytes.length) throw invalid();

  return { sha256: digest, size: bytes.length };
}

async function assertAbiChunks(db: D1Database, build: Attempt, manifest: AbiInventory) {
  const result = await db.prepare(`SELECT COUNT(*) AS count FROM json_each(?) ref JOIN build_abi_evidence e
    ON e.build_id=? AND e.attempt=? AND e.sha256=json_extract(ref.value,'$.sha256')
    WHERE e.kind='abi-records' AND e.artifact_sha256=? AND e.size=json_extract(ref.value,'$.size')
    AND e.start=json_extract(ref.value,'$.start') AND e.files=json_extract(ref.value,'$.files') AND e.symbols=json_extract(ref.value,'$.symbols')`)
    .bind(JSON.stringify(manifest.chunks), build.id, build.attempt, manifest.artifactSha256).first<{ count: number }>();

  if (result?.count !== manifest.chunks.length) throw invalid();
}

export async function retainedAbiInventory(db: D1Database, build: Attempt, ref: InputObject, artifactSha256: string): Promise<AbiInventory> {
  parseAbiReference(ref);

  const row = await db.prepare("SELECT size,manifest_json FROM build_abi_evidence WHERE build_id=? AND attempt=? AND sha256=? AND kind='abi-inventory'")
    .bind(build.id, build.attempt, ref.sha256).first<{ size: number; manifest_json: string }>();

  if (!row || row.size !== ref.size || new TextEncoder().encode(row.manifest_json).length !== ref.size || await sha256(row.manifest_json) !== ref.sha256) throw invalid();
  const manifest = parseAbiDocument(JSON.parse(row.manifest_json));

  if (manifest.kind !== 'abi-inventory' || manifest.artifactSha256 !== artifactSha256) throw invalid();
  await assertAbiChunks(db, build, manifest);

  return manifest;
}

export async function assertRetainedAbiEvidence(db: D1Database, build: Attempt, report: OutputEvidence): Promise<void> {
  const checked = new Set<string>();

  for (const test of report.runtimeTests) for (const analysis of test.analyses) {
    const ref = analysis.runtimeAnalysis.abiInventory;
    const artifact = report.outputs.find((output) => output.packageMetadata.name === analysis.name)!.artifactSha256;

    if (!ref || checked.has(`${ref.sha256}:${artifact}`)) continue;
    await retainedAbiInventory(db, build, ref, artifact);
    checked.add(`${ref.sha256}:${artifact}`);
  }
}

export async function readAbiChunk(env: Storage, ref: InputObject, artifactSha256: string): Promise<AbiChunk> {
  parseAbiReference(ref);
  const object = await env.ARTIFACTS.get(abiObjectKey(ref.sha256));

  if (!object || object.size !== ref.size) throw invalid();
  const bytes = new Uint8Array(await object.arrayBuffer());

  if (bytes.length !== ref.size || await sha256(bytes) !== ref.sha256) throw invalid();
  const chunk = parseAbiDocument(JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)));

  if (chunk.kind !== 'abi-records' || chunk.artifactSha256 !== artifactSha256) throw invalid();

  return chunk;
}
