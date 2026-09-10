import { error, type RequestHandler } from '@sveltejs/kit';
import type { Architecture } from '$lib/model';

const collections = new Set(['core', 'extra', 'multilib', 'omarchy', 'omapkg']);

const filenamePattern = /^[A-Za-z0-9][A-Za-z0-9._+@%~:-]{0,254}$/;

function contentType(filename: string): string {
  if (filename.endsWith('.json')) return 'application/json';

  if (filename.endsWith('.sig')) return 'application/octet-stream';

  if (filename.endsWith('.db') || filename.endsWith('.db.tar.zst') || filename.endsWith('.db.tar.gz')) return 'application/gzip';

  return 'application/octet-stream';
}

function isArchitecture(value: string): value is Architecture {
  return value === 'x86_64' || value === 'aarch64';
}

export const GET: RequestHandler = async ({ platform, params }) => {
  if (!platform?.env?.DB || !platform.env.ARTIFACTS) error(503, 'Repository is unavailable.');
  let lane: 'system' | 'opr' | null = null;

  if (params.lane === 'releases') lane = 'system';
  else if (params.lane === 'opr') lane = 'opr';
  const releaseId = params.releaseId ?? '';
  const collection = params.collection ?? '';
  const architecture = params.architecture ?? '';
  const filename = params.filename ?? '';

  if (!lane || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(releaseId) || !collections.has(collection) || !isArchitecture(architecture) || !filenamePattern.test(filename) || filename.includes('/')) error(404, 'Object not found.');
  const env = platform.env;

  const snapshot = await env.DB.prepare(`SELECT s.db_filename,s.db_key,s.db_signature_key,s.filename_map_key
    FROM owned_repository_snapshots s JOIN distribution_activation_pointers p ON p.lane=? AND p.release_id=s.release_id
    WHERE s.lane=? AND s.release_id=? AND s.collection=? AND s.architecture=? AND s.status IN ('prepared','published') LIMIT 1`)
    .bind(lane, lane, releaseId, collection, architecture).first<{ db_filename: string; db_key: string; db_signature_key: string; filename_map_key: string }>();

  if (!snapshot) error(404, 'Object not found.');
  let key: string | null = null;

  if (filename === snapshot!.db_filename) key = snapshot!.db_key;
  else if (filename === `${snapshot!.db_filename}.sig`) key = snapshot!.db_signature_key;
  else if (filename === 'filename-map.json') key = snapshot!.filename_map_key;
  else {
    const packageFilename = filename.endsWith('.sig') ? filename.slice(0, -4) : filename;

    const packageRow = await env.DB.prepare(`SELECT a.artifact_key,a.signature_key FROM owned_repository_snapshot_packages m
      JOIN owned_repository_artifacts a ON a.id=m.artifact_id
      WHERE m.snapshot_id=(SELECT id FROM owned_repository_snapshots WHERE lane=? AND release_id=? AND collection=? AND architecture=? AND status IN ('prepared','published') LIMIT 1)
        AND m.filename=? LIMIT 1`).bind(lane, releaseId, collection, architecture, packageFilename).first<{ artifact_key: string; signature_key: string }>();

    if (packageRow) key = filename.endsWith('.sig') ? packageRow.signature_key : packageRow.artifact_key;
  }

  if (!key || !/^(?!\/)(?!.*(?:^|\/)\.\.(?:\/|$))[\x21-\x7e]{1,1024}$/.test(key)) error(404, 'Object not found.');
  const object = await env.ARTIFACTS.get(key!);

  if (!object) error(404, 'Object not found.');

  return new Response(object.body, { headers: { 'Content-Type': object.httpMetadata?.contentType ?? contentType(filename), 'Cache-Control': 'public, max-age=31536000, immutable', ETag: object.httpEtag } });
};

export const HEAD = GET;
