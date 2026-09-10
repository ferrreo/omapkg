import type { Env } from './env';
import type { CandidateRowForSigning } from './distribution-release-signing-types';
import { PolicyError } from './policy';
import { safeKey, SHA256 } from './release-storage';
import { id, now, sha256 } from './db';

export interface ManifestSignatureResult {
  intentId: string;
  signatureKey: string;
  signatureSha256: string;
}

interface SignerResponse {
  signatureKey?: unknown;
  signatureSha256?: unknown;
  signature?: { key?: unknown; sha256?: unknown };
}

export async function requestManifestSignature(env: Env, row: CandidateRowForSigning, manifest: string): Promise<ManifestSignatureResult> {
  if (!env.SIGNER && !env.SIGNER_URL) throw new PolicyError(503, 'Package signing service is not configured; release activation is blocked.');
  const bytes = new TextEncoder().encode(manifest);
  const artifactSha256 = await sha256(bytes);

  if (artifactSha256 !== row.manifest_sha256 || !SHA256.test(artifactSha256)) throw new PolicyError(409, 'Release manifest bytes changed before signing.');
  const objectKey = row.manifest_key;
  safeKey(objectKey);
  const intentId = id();
  const createdAt = now();
  const expiresAt = createdAt + 3_600;
  await env.DB.prepare(`INSERT INTO distribution_manifest_signing_intents
    (id,candidate_id,object_key,artifact_sha256,artifact_filename,manifest_sha256,status,created_at,expires_at,key_fingerprint)
    VALUES(?,?,?,?,?,?,?,?,?,?)`).bind(
      intentId, row.id, objectKey, artifactSha256, 'manifest.json', artifactSha256, 'pending', createdAt, expiresAt,
      (env.PACKAGE_SIGNING_FINGERPRINT ?? env.SIGNING_FINGERPRINT ?? '').toLowerCase(),
    ).run();
  let url: URL;

  try { url = env.SIGNER ? new URL('https://signer.internal/v1/sign') : new URL(`${env.SIGNER_URL!.replace(/\/$/, '')}/v1/sign`); }
  catch { throw new PolicyError(503, 'Package signing URL is invalid.'); }

  const headers = new Headers({ 'Content-Type': 'application/json' });

  if (env.SIGNER_TOKEN) headers.set('Authorization', `Bearer ${env.SIGNER_TOKEN}`);
  let response: Response;

  try { response = env.SIGNER ? await env.SIGNER.fetch(new Request(url, { method: 'POST', headers, body: JSON.stringify({ intentId }) })) : await fetch(new Request(url, { method: 'POST', headers, body: JSON.stringify({ intentId }) })); }
  catch {
    await env.DB.prepare("UPDATE distribution_manifest_signing_intents SET status='failed' WHERE id=? AND status='pending'").bind(intentId).run();
    throw new PolicyError(503, 'Package signing service could not be reached.');
  }

  if (!response.ok) {
    await env.DB.prepare("UPDATE distribution_manifest_signing_intents SET status='failed' WHERE id=? AND status='pending'").bind(intentId).run();
    throw new PolicyError(503, `Package signing service rejected request (${response.status}).`);
  }

  let result: SignerResponse;

  try { result = await response.json() as SignerResponse; } catch { throw new PolicyError(503, 'Package signing service returned invalid evidence.'); }

  const signatureKey = typeof result.signatureKey === 'string' ? result.signatureKey : typeof result.signature?.key === 'string' ? result.signature.key : '';
  const signatureSha256 = typeof result.signatureSha256 === 'string' ? result.signatureSha256 : typeof result.signature?.sha256 === 'string' ? result.signature.sha256 : '';

  if (!signatureKey || signatureKey !== `${objectKey}.sig` || !SHA256.test(signatureSha256)) throw new PolicyError(503, 'Package signing service returned no immutable manifest signature.');
  const signature = await env.ARTIFACTS.head(signatureKey);

  if (!signature || (signature.customMetadata?.sha256 && signature.customMetadata.sha256 !== signatureSha256) || (signature.customMetadata?.signatureSha256 && signature.customMetadata.signatureSha256 !== signatureSha256)) {
    throw new PolicyError(503, 'Package signing service did not publish a verifiable manifest signature.');
  }

  return { intentId, signatureKey, signatureSha256 };
}
