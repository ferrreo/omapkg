import type { Env } from './env';
import { audit } from './db';
import {
  WorkerProtocolError,
  requireWorkerLease,
  workerImage
} from './workers';
import type { Worker } from '../model';

export const REGISTRY_HOST = 'registry.cloudflare.com';
export const REGISTRY_CREDENTIAL_TTL_MINUTES = 15;
export const MAX_REGISTRY_JSON_BODY_BYTES = 16 * 1024;

type RegistryEnv = Pick<Env, 'DB' | 'REGISTRY_API_TOKEN' | 'REGISTRY_ACCOUNT_ID'> & {
  CLOUDFLARE_ACCOUNT_ID?: string;
};

export interface RegistryCredentials {
  registry: typeof REGISTRY_HOST;
  username: string;
  password: string;
  expiresAt: string;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function protocolError(status: number, message: string): never {
  throw new WorkerProtocolError(status, message);
}

function leaseToken(value: unknown): string {
  if (!isRecord(value) || Object.keys(value).length !== 1 || typeof value.leaseToken !== 'string' ||
      value.leaseToken.length === 0 || value.leaseToken.length > 128 || /[\u0000-\u001f\u007f]/.test(value.leaseToken)) {
    protocolError(400, 'Invalid registry credential request');
  }
  return value.leaseToken;
}

function configuredAccount(env: RegistryEnv): string {
  const account = env.REGISTRY_ACCOUNT_ID ?? env.CLOUDFLARE_ACCOUNT_ID;
  if (!account || !/^[a-f0-9]{32}$/.test(account)) protocolError(503, 'Private registry is not configured');
  return account;
}

function privateRegistryImage(imageRef: string, account: string): void {
  const [reference, digest, extra] = imageRef.split('@');
  const parts = reference?.split('/') ?? [];
  const component = /^[a-z0-9][a-z0-9._-]*(?::[a-z0-9][a-z0-9._-]*)?$/;
  if (extra !== undefined || parts.length < 3 || parts[0] !== REGISTRY_HOST || parts[1] !== account ||
      parts.slice(2).some((part) => !component.test(part)) || !/^sha256:[a-f0-9]{64}$/.test(digest ?? '')) {
    protocolError(409, 'Reviewed builder image is outside the configured private registry');
  }
}

function responseString(value: unknown, field: string, maxLength: number): string {
  if (typeof value !== 'string' || value.length === 0 || value.length > maxLength || /[\u0000\r\n]/.test(value)) {
    protocolError(503, `Registry credential service returned invalid ${field}`);
  }
  return value;
}

function responseExpiry(value: unknown): string {
  const raw = responseString(value, 'expiry', 128);
  const timestamp = Date.parse(raw);
  if (!Number.isFinite(timestamp) || timestamp <= Date.now()) protocolError(503, 'Registry credential service returned an invalid expiry');
  return new Date(timestamp).toISOString();
}

async function readCredentials(response: Response, requestedExpiry: string): Promise<{ username: string; password: string; expiresAt: string }> {
  let body: unknown;
  try {
    body = await response.json();
  } catch {
    protocolError(503, 'Registry credential service returned invalid JSON');
  }
  if (!isRecord(body) || body.success !== true || !isRecord(body.result)) {
    protocolError(503, 'Registry credential service returned an invalid response');
  }
  const result = isRecord(body.result.credentials) ? body.result.credentials : body.result;
  return {
    username: responseString(result.username, 'username', 256),
    password: responseString(result.password ?? result.token, 'password', 4096),
    // Cloudflare returns credentials without expiry; count the requested TTL from before issuance.
    expiresAt: responseExpiry(result.expires_at ?? result.expiresAt ?? body.result.expires_at ?? body.result.expiresAt ?? requestedExpiry)
  };
}

export async function issueRegistryCredentials(
  env: RegistryEnv,
  worker: Worker,
  buildId: string,
  input: unknown
): Promise<RegistryCredentials> {
  const token = leaseToken(input);
  if (worker.status !== 'active') protocolError(403, 'Worker is revoked');
  const build = await requireWorkerLease(env.DB, worker, buildId, token);
  if (build.architecture !== worker.architecture) protocolError(409, 'Worker architecture does not match build');
  const { imageRef } = workerImage(build);
  const account = configuredAccount(env);
  privateRegistryImage(imageRef, account);
  const apiToken = env.REGISTRY_API_TOKEN;
  if (!apiToken || apiToken.length > 4_096 || /[\u0000\r\n]/.test(apiToken)) protocolError(503, 'Private registry is not configured');

  const endpoint = `https://api.cloudflare.com/client/v4/accounts/${account}/containers/registries/${REGISTRY_HOST}/credentials`;
  const requestedExpiry = new Date(Date.now() + REGISTRY_CREDENTIAL_TTL_MINUTES * 60_000).toISOString();
  let response: Response;
  try {
    response = await fetch(endpoint, {
      method: 'POST',
      headers: { Authorization: `Bearer ${apiToken}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ expiration_minutes: REGISTRY_CREDENTIAL_TTL_MINUTES, permissions: ['pull'] })
    });
  } catch {
    protocolError(503, 'Private registry credential service is unavailable');
  }
  if (!response.ok) protocolError(503, 'Private registry credential service rejected the request');
  const credentials = await readCredentials(response, requestedExpiry);
  try {
    await env.DB.batch([
      audit(env.DB, `worker:${worker.id}`, 'worker.registry_credentials_issued', build.id, {
        registry: REGISTRY_HOST, imageRef, expiresAt: credentials.expiresAt
      })
    ]);
  } catch {
    protocolError(500, 'Registry credential audit failed');
  }
  return { registry: REGISTRY_HOST, ...credentials };
}
