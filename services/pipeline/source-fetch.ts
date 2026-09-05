import type { Sandbox } from '@flue/runtime';
import { MAX_SOURCE_REDIRECTS, normalizeRedirectSourceUrl, normalizeSourceUrl, redactText, sourceFetchCommand, sourceMetadataCommand } from './security';

const MAX_METADATA_BYTES = 2_147_483_648;

export interface SourceFetchResolution {
  originalUrl: string;
  finalUrl: string;
  redirectChain: string[];
  result: { stdout: string; stderr: string; exitCode: number };
}

export type SourceHostAuthorizer = (hostname: string) => Promise<void>;

export interface SourceMetadataResolution {
  originalUrl: string;
  finalUrl: string;
  redirectChain: string[];
  status: number;
  headers: {
    etag: string | null;
    lastModified: string | null;
    contentLength: string | null;
    contentRange: string | null;
  };
}

export function sanitizeSourceUrl(raw: string): string {
  const url = normalizeRedirectSourceUrl(raw);
  url.search = '';
  return url.toString();
}

export function parseSourceFetchResponse(stdout: string): { status: number; location: string | null } {
  const statusText = stdout.split('\n').find((line) => line.startsWith('http_status='))?.slice('http_status='.length).trim() ?? '';
  const status = Number(statusText);
  if (!Number.isInteger(status) || status < 100 || status > 599) throw new Error('source fetch status is invalid');
  const location = stdout.split('\n').find((line) => line.startsWith('redirect_location='))?.slice('redirect_location='.length).trim() || null;
  return { status, location };
}

export function parseSourceMetadataResponse(stdout: string): {
  status: number;
  headers: Record<string, string>;
  curlStatus: number | null;
} {
  if (stdout.length > 128 * 1024) throw new Error('source metadata response is too large');
  const marker = stdout.lastIndexOf('\nhttp_status=');
  const headerText = marker >= 0 ? stdout.slice(0, marker) : stdout;
  const statusMatch = stdout.match(/(?:^|\n)http_status=(\d{3})(?:\n|$)/);
  const status = Number(statusMatch?.[1] ?? '0');
  if (!Number.isInteger(status) || status < 100 || status > 599) throw new Error('source metadata status is invalid');
  const curlStatusMatch = stdout.match(/(?:^|\n)curl_status=(\d+)(?:\n|$)/);
  const curlStatus = curlStatusMatch ? Number(curlStatusMatch[1]) : null;
  const blocks = headerText.split(/\r?\n(?=HTTP\/\d(?:\.\d)?\s)/i);
  const headers: Record<string, string> = {};
  for (const line of (blocks.at(-1) ?? '').split(/\r?\n/).slice(1)) {
    const separator = line.indexOf(':');
    if (separator <= 0) continue;
    const name = line.slice(0, separator).trim().toLowerCase();
    const value = line.slice(separator + 1).trim();
    if (name && value.length <= 8 * 1024) headers[name] = value;
  }
  return { status, headers, curlStatus };
}

function validatedMetadataLength(headers: Record<string, string>, status: number): string {
  const totalFromRange = headers['content-range']?.match(/^bytes\s+\d+-\d+\/(\d+)$/i)?.[1] ?? null;
  if (status === 206 && !totalFromRange) throw new Error('source metadata range has no total length');
  const value = totalFromRange ?? headers['content-length'] ?? '';
  if (!/^[1-9][0-9]*$/.test(value) || BigInt(value) > BigInt(MAX_METADATA_BYTES)) {
    throw new Error('source metadata has no valid content length');
  }
  return value;
}

async function runSourceMetadataCommand(
  sandbox: Sandbox,
  url: string,
  method: 'head' | 'range',
  timeoutMs: number,
  signal?: AbortSignal,
): Promise<ReturnType<typeof parseSourceMetadataResponse>> {
  const result = await sandbox.exec(sourceMetadataCommand(url, { allowRedirectQuery: true, method }), { timeoutMs, signal });
  let observed: ReturnType<typeof parseSourceMetadataResponse>;
  try {
    observed = parseSourceMetadataResponse(result.stdout);
  } catch (cause) {
    throw new Error(`source metadata fetch failed: ${redactText(result.stderr).slice(0, 1_000) || (cause instanceof Error ? cause.message : 'invalid response')}`);
  }
  if (result.exitCode !== 0) throw new Error(`source metadata command failed (${result.exitCode})`);
  // 23/141 are curl's expected write/SIGPIPE results when one-byte FIFO
  // sink closes; 63 is its max-file-size guard. Length validation below is
  // still required before any of these statuses can be accepted.
  const boundedRangeAbort = method === 'range' && [23, 63, 141].includes(observed.curlStatus ?? -1);
  if (observed.curlStatus !== null && observed.curlStatus !== 0 && !boundedRangeAbort) {
    throw new Error(`source metadata command failed (${observed.curlStatus})`);
  }
  return observed;
}

/**
 * Fetch only upstream response headers in a Sandbox. Redirects are resolved
 * one hop at a time so each new public host is added to the existing egress
 * allowlist before curl contacts it. The range fallback is capped to one byte.
 */
export async function fetchMetadataWithRedirects(
  sandbox: Sandbox,
  rawUrl: string,
  options: {
    allowHost?: SourceHostAuthorizer;
    maxRedirects?: number;
    timeoutMs?: number;
    signal?: AbortSignal;
  } = {},
): Promise<SourceMetadataResolution> {
  const original = normalizeSourceUrl(rawUrl).toString();
  const maxRedirects = options.maxRedirects ?? MAX_SOURCE_REDIRECTS;
  if (!Number.isSafeInteger(maxRedirects) || maxRedirects < 0 || maxRedirects > MAX_SOURCE_REDIRECTS) throw new Error('source redirect limit is invalid');
  const timeoutMs = options.timeoutMs ?? 60_000;
  let current = original;
  const seen = new Set([current]);
  const redirectChain = [sanitizeSourceUrl(current)];
  for (let hop = 0; hop <= maxRedirects; hop += 1) {
    let observed = await runSourceMetadataCommand(sandbox, current, 'head', timeoutMs, options.signal);
    if (observed.status === 403 || observed.status === 405 || observed.status === 501) {
      observed = await runSourceMetadataCommand(sandbox, current, 'range', timeoutMs, options.signal);
      if (observed.curlStatus === 63 && !observed.headers['content-length'] && !observed.headers['content-range']) {
        throw new Error('source metadata range response has no bounded length');
      }
    }
    if (observed.status >= 200 && observed.status < 300) {
      const contentLength = validatedMetadataLength(observed.headers, observed.status);
      return {
        originalUrl: original,
        finalUrl: current,
        redirectChain,
        status: observed.status,
        headers: {
          etag: observed.headers.etag ?? null,
          lastModified: observed.headers['last-modified'] ?? null,
          contentLength,
          contentRange: observed.headers['content-range'] ?? null,
        },
      };
    }
    if (observed.status < 300 || observed.status >= 400) throw new Error(`source metadata returned HTTP ${observed.status}`);
    if (hop === maxRedirects) throw new Error('source redirect limit exceeded');
    const location = observed.headers.location;
    if (!location) throw new Error('source redirect has no location');
    const next = normalizeSourceUrl(new URL(location, current).toString()).toString();
    if (seen.has(next)) throw new Error('source redirect loop detected');
    if (new URL(next).hostname !== new URL(current).hostname) {
      if (!options.allowHost) throw new Error('source redirect requires sandbox host authorization');
      await options.allowHost(new URL(next).hostname);
    }
    seen.add(next);
    current = next;
    redirectChain.push(sanitizeSourceUrl(current));
  }
  throw new Error('source redirect resolution failed');
}

export async function fetchSourceWithRedirects(
  sandbox: Sandbox,
  rawUrl: string,
  options: {
    allowHost?: SourceHostAuthorizer;
    destination?: string;
    maxRedirects?: number;
    timeoutMs?: number;
    signal?: AbortSignal;
  } = {},
): Promise<SourceFetchResolution> {
  const original = normalizeSourceUrl(rawUrl).toString();
  const maxRedirects = options.maxRedirects ?? MAX_SOURCE_REDIRECTS;
  if (!Number.isSafeInteger(maxRedirects) || maxRedirects < 0 || maxRedirects > MAX_SOURCE_REDIRECTS) throw new Error('source redirect limit is invalid');
  let current = original;
  const seen = new Set([current]);
  const redirectChain = [sanitizeSourceUrl(current)];
  let result: SourceFetchResolution['result'] | undefined;
  for (let hop = 0; hop <= maxRedirects; hop += 1) {
    const response = await sandbox.exec(sourceFetchCommand(current, options.destination, { allowRedirectQuery: hop > 0 }), {
      timeoutMs: options.timeoutMs ?? 180_000,
      signal: options.signal,
    });
    result = response;
    if (response.exitCode !== 0) throw new Error(`source fetch failed: ${redactText(response.stderr).slice(0, 1_000)}`);
    const observed = parseSourceFetchResponse(response.stdout);
    if (observed.status >= 200 && observed.status < 300) {
      return { originalUrl: original, finalUrl: sanitizeSourceUrl(current), redirectChain, result: response };
    }
    if (observed.status < 300 || observed.status >= 400) throw new Error(`source fetch returned HTTP ${observed.status}`);
    if (hop === maxRedirects) throw new Error('source redirect limit exceeded');
    if (!observed.location) throw new Error('source redirect has no location');
    const next = normalizeRedirectSourceUrl(new URL(observed.location, current).toString()).toString();
    if (seen.has(next)) throw new Error('source redirect loop detected');
    if (!options.allowHost) throw new Error('source redirect requires sandbox host authorization');
    await options.allowHost(new URL(next).hostname);
    seen.add(next);
    current = next;
    redirectChain.push(sanitizeSourceUrl(current));
  }
  throw new Error(result ? 'source redirect resolution failed' : 'source fetch did not run');
}
