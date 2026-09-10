import ROLLBACK_CLIENT from '$lib/rollback-client.sh?raw';
import { error, type RequestHandler } from '@sveltejs/kit';
import type { Architecture, Release } from '$lib/model';

type PublicReleaseRow = Release & { artifact_filename: string | null; artifact_key: string | null; signature_key: string | null };

const packageFilename = /^[A-Za-z0-9][A-Za-z0-9._+:-]{0,220}\.pkg\.tar\.zst$/;

const packageName = /^[a-z0-9][a-z0-9@._+:-]{0,63}$/;

const releaseId = /^[A-Za-z0-9_-]{1,128}$/;

const safeKey = /^(?!\/)(?!.*(?:^|\/)\.\.(?:\/|$))[\x21-\x7e]{1,1024}$/;

function decodePart(value: string): string {
  try {
    const decoded = decodeURIComponent(value);

    if (!decoded || decoded === '.' || decoded === '..' || decoded.includes('\u0000') || decoded.includes('\r') || decoded.includes('\n')) error(404, 'Object not found.');

    return decoded;
  } catch {
    error(404, 'Object not found.');
  }
}

function contentType(path: string): string {
  if (path.endsWith('.json')) return 'application/json';

  if (path.endsWith('PKGBUILD')) return 'text/plain; charset=utf-8';

  if (path.endsWith('.sig')) return 'application/octet-stream';

  if (path.endsWith('.db') || path.endsWith('.db.tar.gz') || path.endsWith('.db.tar.gz.sig')) return path.endsWith('.sig') ? 'application/octet-stream' : 'application/gzip';

  return 'application/octet-stream';
}

async function readObject(bucket: R2Bucket, key: string, path: string, immutable = true): Promise<Response> {
  if (!safeKey.test(key)) error(404, 'Object not found.');
  const object = await bucket.get(key);

  if (!object) error(404, 'Object not found.');

  const headers = new Headers({
    'Content-Type': object.httpMetadata?.contentType ?? contentType(path),
    'Cache-Control': immutable ? 'public, max-age=31536000, immutable' : 'public, max-age=30, must-revalidate',
    ETag: object.httpEtag,
  });

  if (object.size >= 0) headers.set('Content-Length', String(object.size));

  return new Response(object.body, { headers });
}

function validArchitecture(value: string): value is Architecture {
  return value === 'x86_64' || value === 'aarch64';
}

export const GET: RequestHandler = async ({ platform, params }) => {
  if (!platform?.env?.DB || !platform.env.ARTIFACTS) error(503, 'Repository is unavailable.');
  const parts = (params.path ?? '').split('/').filter(Boolean).map(decodePart);

  if (!parts.length) error(404, 'Object not found.');
  const env = platform.env;

  if (parts.length === 1 && ['key.asc', 'opr.gpg'].includes(parts[0])) {
    const key = (env as typeof env & { PACKAGE_SIGNING_PUBLIC_KEY_R2_KEY?: string }).PACKAGE_SIGNING_PUBLIC_KEY_R2_KEY ?? 'keys/opr-package-signing.asc';

    if (!(await env.ARTIFACTS.head(key)) && env.SIGNER) {
      try {
        const response = await env.SIGNER.fetch(new Request('https://signer.internal/v1/public-key'));

        if (response.ok) return new Response(response.body, { status: 200, headers: response.headers });
      } catch {
        // Fall through to the allowlisted R2 lookup and its normal 404 response.
      }
    }

    return readObject(env.ARTIFACTS, key, parts[0]);
  }

  if (parts.length === 3 && validArchitecture(parts[1]) && parts[0] === 'dev' && /^opr(?:-dev)?\.db(?:\.tar\.gz)?(?:\.sig)?$/.test(parts[2])) {
    const snapshot = await env.DB.prepare(`SELECT db_key,db_signature_key FROM repository_snapshots
      WHERE architecture=? AND channel='dev' AND active=1 ORDER BY created_at DESC LIMIT 1`).bind(parts[1]).first<{ db_key: string; db_signature_key: string }>();

    if (!snapshot) error(404, 'Development repository database not published.');
    const signature = parts[2].endsWith('.sig');

    return readObject(env.ARTIFACTS, signature ? snapshot.db_signature_key : snapshot.db_key, parts[2], false);
  }

  if (parts.length === 3 && validArchitecture(parts[1]) && parts[0] === 'dev') {
    const filename = parts[2].endsWith('.sig') ? parts[2].slice(0, -4) : parts[2];

    if (!packageFilename.test(filename)) error(404, 'Object not found.');

    const row = await env.DB.prepare(`SELECT r.*,b.artifact_filename FROM releases r JOIN builds b ON b.id=r.build_id
      WHERE r.architecture=? AND r.surface='binary' AND r.channel='dev' AND b.artifact_filename=?
      ORDER BY r.published_at DESC LIMIT 1`).bind(parts[1], filename).first<PublicReleaseRow>();

    if (!row || !row.artifact_key || !row.signature_key) error(404, 'Object not found.');

    return readObject(env.ARTIFACTS, parts[2].endsWith('.sig') ? row.signature_key : row.artifact_key, parts.join('/'));
  }

  if (parts.length === 2 && validArchitecture(parts[0]) && /^opr\.db(?:\.tar\.gz)?(?:\.sig)?$/.test(parts[1])) {
    const snapshot = await env.DB.prepare(`SELECT db_key,db_signature_key FROM repository_snapshots
      WHERE architecture=? AND channel='stable' AND active=1 ORDER BY created_at DESC LIMIT 1`).bind(parts[0]).first<{ db_key: string; db_signature_key: string }>();

    if (!snapshot) error(404, 'Repository database not published.');
    const signature = parts[1].endsWith('.sig');

    return readObject(env.ARTIFACTS, signature ? snapshot.db_signature_key : snapshot.db_key, parts[1], false);
  }

  if (parts.length === 2 && validArchitecture(parts[0])) {
    const filename = parts[1].endsWith('.sig') ? parts[1].slice(0, -4) : parts[1];

    if (!packageFilename.test(filename)) error(404, 'Object not found.');

    const row = await env.DB.prepare(`SELECT r.*,b.artifact_filename FROM releases r JOIN builds b ON b.id=r.build_id
      WHERE r.architecture=? AND r.surface='binary' AND r.channel IN ('stable','withdrawn') AND b.artifact_filename=?
      ORDER BY r.published_at DESC LIMIT 1`).bind(parts[0], filename).first<PublicReleaseRow>();

    if (!row || !row.artifact_key || !row.signature_key) error(404, 'Object not found.');

    return readObject(env.ARTIFACTS, parts[1].endsWith('.sig') ? row.signature_key : row.artifact_key, parts[1]);
  }

  const recipeOffset = parts[0] === 'dev' ? 1 : 0;

  if (parts.length === 5 + recipeOffset && parts[recipeOffset] === 'recipes' && validArchitecture(parts[3 + recipeOffset]) && parts[4 + recipeOffset] === 'PKGBUILD' && packageName.test(parts[1 + recipeOffset])) {
    const recipeName = parts[1 + recipeOffset];
    const recipeVersion = parts[2 + recipeOffset];
    const recipeArchitecture = parts[3 + recipeOffset];

    const row = await env.DB.prepare(`SELECT recipe_key FROM releases
      WHERE name=? AND version=? AND architecture=? AND surface IN ('binary','recipe') AND channel ${recipeOffset ? "= 'dev'" : "IN ('stable','withdrawn')"}
      ORDER BY published_at DESC LIMIT 1`).bind(recipeName, recipeVersion, recipeArchitecture).first<{ recipe_key: string }>();

    if (!row) error(404, 'Object not found.');

    return readObject(env.ARTIFACTS, row.recipe_key, parts.join('/'));
  }

  if (parts.length === 3 && parts[0] === 'metadata' && releaseId.test(parts[1]) && ['sbom.json', 'provenance.json', 'attestation.json', 'attestation.json.sig'].includes(parts[2])) {
    const row = await env.DB.prepare(`SELECT sbom_key,provenance_key,attestation_key FROM releases
      WHERE id=? AND channel IN ('stable','withdrawn','dev')`).bind(parts[1]).first<{ sbom_key: string; provenance_key: string; attestation_key: string | null }>();

    if (!row) error(404, 'Object not found.');

    if (parts[2].startsWith('attestation.json')) {
      if (!row.attestation_key) error(404, 'This historical release has no public signed attestation.');

      return readObject(env.ARTIFACTS, row.attestation_key + (parts[2].endsWith('.sig') ? '.sig' : ''), parts.join('/'));
    }

    return readObject(env.ARTIFACTS, parts[2] === 'sbom.json' ? row.sbom_key : row.provenance_key, parts.join('/'));
  }

  if (parts.length === 2 && parts[0] === 'rollback' && parts[1] === 'client.sh') {
    return new Response(ROLLBACK_CLIENT, { headers: {
      'Content-Type': 'text/x-shellscript; charset=utf-8',
      'Cache-Control': 'public, max-age=300, must-revalidate',
    } });
  }

  if (parts.length === 2 && parts[0] === 'rollback' && parts[1].endsWith('.json')) {
    const id = parts[1].slice(0, -5);

    if (!releaseId.test(id)) error(404, 'Object not found.');

    const row = await env.DB.prepare(`SELECT rr.manifest_key FROM release_rollbacks rr JOIN releases r ON r.id=rr.release_id
      WHERE rr.release_id=? AND r.channel IN ('stable','withdrawn')`).bind(id).first<{ manifest_key: string }>();

    if (!row) error(404, 'Object not found.');

    return readObject(env.ARTIFACTS, row.manifest_key, parts.join('/'));
  }

  error(404, 'Object not found.');
};

export const HEAD: RequestHandler = GET;
