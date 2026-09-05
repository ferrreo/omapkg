import type { Sandbox } from '@flue/runtime';
import { id, now, audit } from '../../src/lib/server/db';
import type { Area, Architecture } from '../../src/lib/model';
import type { FactoryEnv, FactoryRequest, FactoryWorkflowBinding } from './types';
import { gitTagsCommand, normalizeSourceUrl, redactText } from './security';
import { fetchMetadataWithRedirects, type SourceHostAuthorizer } from './source-fetch';

const UPSTREAM_ACTOR = 'system:upstream-check';
const MAX_AUTOMATIC_GENERATIONS = 3;
const MAX_RELEASE_LISTING_BYTES = 512 * 1024;
const MAX_RELEASE_LISTING_REDIRECTS = 3;
const UPSTREAM_CHECK_USER_AGENT = 'omapkg-upstream-check/1.0';
const UPSTREAM_REQUEST_TIMEOUT_MS = 15_000;
const MAX_METADATA_BYTES = 2_147_483_648;

class TransientMetadataError extends Error {
  readonly status: number | null;

  constructor(reason: string, status: number | null = null) {
    super(reason);
    this.name = 'TransientMetadataError';
    this.status = status;
  }
}

function isTransientMetadataError(cause: unknown): cause is TransientMetadataError {
  return cause instanceof TransientMetadataError;
}

async function fetchWithTimeout(input: URL, init: RequestInit, cancelAfterHeaders = false): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), UPSTREAM_REQUEST_TIMEOUT_MS);
  try {
    const response = await fetch(input, { ...init, signal: controller.signal });
    if (cancelAfterHeaders) controller.abort();
    return response;
  } catch (cause) {
    const message = cause instanceof Error ? cause.message.toLowerCase() : '';
    if (controller.signal.aborted || (cause instanceof Error && cause.name === 'AbortError') || /tim(?:e|ed)\s*out|timeout/.test(message)) {
      throw new TransientMetadataError('upstream metadata request timed out');
    }
    throw cause;
  } finally {
    clearTimeout(timer);
  }
}

async function cancelResponseBody(response: Response): Promise<void> {
  if (!response.body) return;
  try {
    await Promise.race([
      response.body.cancel(),
      new Promise<void>((resolve) => setTimeout(resolve, 250)),
    ]);
  } catch {
    // Metadata inspection never consumes response bodies.
  }
}

export interface UpstreamReleaseSignal {
  sourceKind: 'git' | 'archive';
  version: string | null;
  commit: string | null;
  signal: string;
  /** The immutable archive URL selected from its own upstream directory. */
  upstreamUrl?: string;
}

export interface UpstreamCheckResult {
  requestId: string;
  checkedAt: number;
  signal: UpstreamReleaseSignal;
  pendingRequestId: string | null;
}

function tagVersionParts(tag: string): string[] {
  const core = tag.match(/\d+(?:[.-]\d+)*/)?.[0] ?? '';
  return core.split(/[.-]/).filter(Boolean).map((part) => part.replace(/^0+(?=\d)/, '') || '0');
}

function compareTagVersions(left: string, right: string): number {
  const a = tagVersionParts(left);
  const b = tagVersionParts(right);
  const length = Math.max(a.length, b.length);
  for (let index = 0; index < length; index += 1) {
    const leftPart = a[index] ?? '0';
    const rightPart = b[index] ?? '0';
    if (leftPart.length !== rightPart.length) return leftPart.length > rightPart.length ? 1 : -1;
    if (leftPart !== rightPart) return leftPart > rightPart ? 1 : -1;
  }
  const leftPrerelease = /(?:alpha|beta|rc|pre|dev|snapshot)/i.test(left);
  const rightPrerelease = /(?:alpha|beta|rc|pre|dev|snapshot)/i.test(right);
  if (leftPrerelease !== rightPrerelease) return leftPrerelease ? -1 : 1;
  return 0;
}

export function parseGitTags(stdout: string): { version: string; commit: string } | null {
  const tags = new Map<string, { commit?: string; peeled?: string }>();
  const order: string[] = [];
  for (const line of stdout.split('\n')) {
    const match = line.trim().match(/^([0-9a-f]{40}(?:[0-9a-f]{24})?)\s+refs\/tags\/([A-Za-z0-9._+\-]{1,128})(\^\{\})?$/i);
    if (!match || !/\d/.test(match[2])) continue;
    const tag = match[2];
    const entry = tags.get(tag) ?? {};
    if (!tags.has(tag)) order.push(tag);
    if (match[3]) entry.peeled = match[1].toLowerCase();
    else entry.commit = match[1].toLowerCase();
    tags.set(tag, entry);
  }
  let latest: { version: string; commit: string } | null = null;
  for (const version of order) {
    const entry = tags.get(version);
    const commit = entry?.peeled ?? entry?.commit;
    if (commit && (!latest || compareTagVersions(version, latest.version) > 0)) latest = { version, commit };
  }
  return latest;
}

export async function inspectGitRelease(request: FactoryRequest, sandbox: Sandbox): Promise<UpstreamReleaseSignal> {
  const url = normalizeSourceUrl(request.upstreamUrl).toString();
  const result = await sandbox.exec(gitTagsCommand(url), { timeoutMs: 120_000 });
  if (result.exitCode !== 0) throw new Error(`upstream tag inspection failed: ${redactText(result.stderr).slice(0, 1_000)}`);
  const latest = parseGitTags(result.stdout);
  if (!latest) return { sourceKind: 'git', version: null, commit: null, signal: `git:${url}:no-versioned-tags` };
  return {
    sourceKind: 'git',
    version: latest.version,
    commit: latest.commit,
    signal: `git:${url}:${latest.version}:${latest.commit}`,
  };
}

function archiveFilename(url: URL): string | null {
  const value = url.pathname.slice(url.pathname.lastIndexOf('/') + 1);
  try {
    return decodeURIComponent(value);
  } catch {
    return null;
  }
}

function archiveVersionToken(filename: string): { start: number; raw: string; version: string } | null {
  const match = filename.match(/(?:^|[-_.])v?(\d+(?:[.-]\d+){1,3})(?=$|[-_.])/i);
  if (!match || match.index === undefined) return null;
  const start = match.index + (/^[-_.]/.test(match[0]) ? 1 : 0);
  const raw = match[0].slice(start - match.index);
  return { start, raw, version: match[1] };
}

function versionFromArchiveUrl(url: URL): string | null {
  const filename = archiveFilename(url);
  return filename ? archiveVersionToken(filename)?.version ?? null : null;
}

async function boundedResponseText(response: Response): Promise<string | null> {
  const advertised = Number(response.headers.get('content-length'));
  if (Number.isFinite(advertised) && advertised > MAX_RELEASE_LISTING_BYTES) {
    await cancelResponseBody(response);
    return null;
  }
  if (!response.body) return '';
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  let timeoutHandle: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timeoutHandle = setTimeout(() => reject(new TransientMetadataError('upstream release listing timed out')), UPSTREAM_REQUEST_TIMEOUT_MS);
  });
  try {
    while (true) {
      const part = await Promise.race([reader.read(), timeout]);
      if (part.done) break;
      size += part.value.byteLength;
      if (size > MAX_RELEASE_LISTING_BYTES) {
        await Promise.race([
          reader.cancel(),
          new Promise<void>((resolve) => setTimeout(resolve, 250)),
        ]);
        return null;
      }
      chunks.push(part.value);
    }
  } catch (cause) {
    try {
      await Promise.race([
        reader.cancel(),
        new Promise<void>((resolve) => setTimeout(resolve, 250)),
      ]);
    } catch {
      // The listing is already being rejected.
    }
    throw cause;
  } finally {
    if (timeoutHandle !== undefined) clearTimeout(timeoutHandle);
    reader.releaseLock();
  }
  const body = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder().decode(body);
}

async function fetchReleaseListing(url: URL): Promise<{ url: URL; text: string } | null> {
  let current = url;
  for (let hop = 0; hop <= MAX_RELEASE_LISTING_REDIRECTS; hop += 1) {
    const response = await fetchWithTimeout(current, {
      headers: { Accept: 'text/html,text/plain;q=0.9', 'User-Agent': UPSTREAM_CHECK_USER_AGENT },
      redirect: 'manual',
    });
    if (response.status >= 300 && response.status < 400) {
      await cancelResponseBody(response);
      const location = response.headers.get('location');
      if (!location) throw new Error('upstream redirect has no location');
      current = normalizeSourceUrl(new URL(location, current).toString());
      continue;
    }
    if (!response.ok) {
      await cancelResponseBody(response);
      return null;
    }
    const text = await boundedResponseText(response);
    return text === null ? null : { url: current, text };
  }
  throw new Error('upstream redirect limit exceeded');
}

function candidateArchiveUrls(listing: string, listingUrl: URL, sourceUrl: URL): URL[] {
  const filename = archiveFilename(sourceUrl);
  const token = filename ? archiveVersionToken(filename) : null;
  if (!filename || !token) return [];
  const prefix = filename.slice(0, token.start);
  const suffix = filename.slice(token.start + token.raw.length);
  const directory = listingUrl.pathname.endsWith('/') ? listingUrl.pathname : `${listingUrl.pathname}/`;
  const candidates = new Map<string, { url: URL; version: string }>();
  const hrefPattern = /\bhref\s*=\s*["']([^"']+)["']/gi;
  for (let match = hrefPattern.exec(listing); match; match = hrefPattern.exec(listing)) {
    let candidate: URL;
    try {
      candidate = new URL(match[1], listingUrl);
    } catch {
      continue;
    }
    if (candidate.protocol !== 'https:' || candidate.origin !== listingUrl.origin || candidate.origin !== sourceUrl.origin || candidate.username || candidate.password || candidate.port || candidate.search || candidate.hash) continue;
    if (candidate.pathname.slice(0, candidate.pathname.lastIndexOf('/') + 1) !== directory) continue;
    const candidateName = archiveFilename(candidate);
    const candidateToken = candidateName ? archiveVersionToken(candidateName) : null;
    if (!candidateName || !candidateToken) continue;
    if (candidateName.slice(0, candidateToken.start) !== prefix || candidateName.slice(candidateToken.start + candidateToken.raw.length) !== suffix) continue;
    candidates.set(candidate.toString(), { url: candidate, version: candidateToken.version });
  }
  return [...candidates.values()]
    .filter(({ version }) => compareTagVersions(version, token.version) > 0)
    .sort((left, right) => {
      const versionOrder = compareTagVersions(right.version, left.version);
      return versionOrder || left.url.toString().localeCompare(right.url.toString());
    })
    .map(({ url }) => url);
}

async function discoverArchiveUrl(sourceUrl: URL): Promise<URL> {
  const filename = archiveFilename(sourceUrl);
  const token = filename ? archiveVersionToken(filename) : null;
  if (!filename || !token) return sourceUrl;
  const slash = sourceUrl.pathname.lastIndexOf('/');
  if (slash < 1) return sourceUrl;
  const directory = new URL(sourceUrl.toString());
  directory.pathname = `${sourceUrl.pathname.slice(0, slash + 1)}`;
  directory.search = '';
  directory.hash = '';
  let listing: { url: URL; text: string } | null;
  try {
    listing = await fetchReleaseListing(directory);
  } catch (cause) {
    if (isTransientMetadataError(cause)) return sourceUrl;
    throw cause;
  }
  if (!listing) return sourceUrl;
  return candidateArchiveUrls(listing.text, listing.url, sourceUrl)[0] ?? sourceUrl;
}

async function requestMetadata(url: URL): Promise<{ response: Response; finalUrl: URL }> {
  let current = url;
  for (let hop = 0; hop <= 3; hop += 1) {
    const response = await fetchWithTimeout(current, {
      method: 'HEAD',
      headers: { Accept: '*/*', 'User-Agent': UPSTREAM_CHECK_USER_AGENT },
      redirect: 'manual',
    }, true);
    if (response.status === 522) {
      await cancelResponseBody(response);
      throw new TransientMetadataError(`upstream metadata request returned HTTP ${response.status}`, response.status);
    }
    if (response.status >= 300 && response.status < 400) {
      await cancelResponseBody(response);
      const location = response.headers.get('location');
      if (!location) throw new Error('upstream redirect has no location');
      current = normalizeSourceUrl(new URL(location, current).toString());
      continue;
    }
    if (response.status === 403 || response.status === 405 || response.status === 501) {
      await cancelResponseBody(response);
      const fallback = await fetchWithTimeout(current, {
        headers: { Accept: '*/*', Range: 'bytes=0-0', 'User-Agent': UPSTREAM_CHECK_USER_AGENT },
        redirect: 'manual',
      }, true);
      if (fallback.status === 403 || fallback.status === 522) {
        await cancelResponseBody(fallback);
        throw new TransientMetadataError(`upstream metadata request returned HTTP ${fallback.status}`, fallback.status);
      }
      if (fallback.status >= 300 && fallback.status < 400) {
        await cancelResponseBody(fallback);
        const location = fallback.headers.get('location');
        if (!location) throw new Error('upstream redirect has no location');
        current = normalizeSourceUrl(new URL(location, current).toString());
        continue;
      }
      await cancelResponseBody(fallback);
      return { response: fallback, finalUrl: current };
    }
    await cancelResponseBody(response);
    return { response, finalUrl: current };
  }
  throw new Error('upstream redirect limit exceeded');
}

export async function inspectArchiveRelease(
  request: FactoryRequest,
  sandbox?: Sandbox,
  allowHost?: SourceHostAuthorizer,
  createSandbox?: () => Promise<{ sandbox: Sandbox; allowHost?: SourceHostAuthorizer }>,
): Promise<UpstreamReleaseSignal> {
  const url = await discoverArchiveUrl(normalizeSourceUrl(request.upstreamUrl));
  let metadata: { response: Response; finalUrl: URL };
  try {
    metadata = await requestMetadata(url);
  } catch (cause) {
    if (!isTransientMetadataError(cause)) throw cause;
    const fallbackContext = sandbox
      ? { sandbox, allowHost }
      : await createSandbox?.();
    if (!fallbackContext) throw cause;
    const fallback = await fetchMetadataWithRedirects(fallbackContext.sandbox, url.toString(), { allowHost: fallbackContext.allowHost, timeoutMs: 60_000 });
    metadata = {
      response: new Response(null, {
        status: fallback.status,
        headers: {
          ...(fallback.headers.etag ? { etag: fallback.headers.etag } : {}),
          ...(fallback.headers.lastModified ? { 'last-modified': fallback.headers.lastModified } : {}),
          ...(fallback.headers.contentLength ? { 'content-length': fallback.headers.contentLength } : {}),
          ...(fallback.headers.contentRange ? { 'content-range': fallback.headers.contentRange } : {}),
        },
      }),
      finalUrl: new URL(fallback.finalUrl),
    };
  }
  const response = metadata.response;
  if (!response.ok) throw new Error(`upstream metadata request failed (${response.status})`);
  const etag = response.headers.get('etag');
  const modified = response.headers.get('last-modified');
  const contentRange = response.headers.get('content-range')?.match(/^bytes\s+\d+-\d+\/(\d+)$/i)?.[1] ?? null;
  if (response.status === 206 && !contentRange) throw new Error('upstream metadata range has no total length');
  const length = contentRange ?? response.headers.get('content-length');
  if (!length || !/^[1-9][0-9]*$/.test(length) || BigInt(length) > BigInt(MAX_METADATA_BYTES)) {
    throw new Error('upstream metadata has no valid content length');
  }
  const version = versionFromArchiveUrl(metadata.finalUrl);
  const signal = [
    `archive:${metadata.finalUrl.toString()}`,
    `version=${version ?? ''}`,
    `etag=${etag ?? ''}`,
    `last-modified=${modified ?? ''}`,
    `length=${length ?? ''}`,
  ].join('|');
  return { sourceKind: 'archive', version, commit: null, signal, upstreamUrl: metadata.finalUrl.toString() };
}

function comparableVersion(version: string | null): string | null {
  return version?.replace(/^v/i, '').trim() || null;
}

export async function trackedUpstreamRequests(
  env: Pick<FactoryEnv, 'DB'>,
  limit = 50,
): Promise<UpstreamRequestRow[]> {
  const bounded = Math.min(Math.max(limit, 1), 50);
  const rows = await env.DB.prepare(`SELECT q.id,q.name,q.upstream_url,q.source_kind,q.area,q.declared_license,
      r.version AS published_version,r.upstream_commit AS upstream_ref
    FROM requests q
    JOIN revisions r ON r.id=(
      SELECT latest.id FROM revisions latest
      WHERE latest.request_id=q.id
        AND EXISTS (
          SELECT 1 FROM builds b
          JOIN releases published ON published.build_id=b.id
          WHERE b.revision_id=latest.id AND published.channel IN ('dev','stable')
      )
      ORDER BY latest.created_at DESC,latest.rowid DESC LIMIT 1
    )
    WHERE NOT EXISTS (
      SELECT 1 FROM revisions newer
      JOIN requests newer_request ON newer_request.id=newer.request_id
      WHERE newer_request.name=q.name
        AND EXISTS (
          SELECT 1 FROM builds newer_build
          JOIN releases newer_release ON newer_release.build_id=newer_build.id
          WHERE newer_build.revision_id=newer.id AND newer_release.channel IN ('dev','stable')
        )
        AND (newer.created_at>r.created_at OR (newer.created_at=r.created_at AND newer.rowid>r.rowid))
    )
    ORDER BY q.updated_at ASC,q.id ASC LIMIT ?`).bind(bounded).all<UpstreamRequestRow>();
  return rows.results;
}

export async function recordUpstreamRelease(
  env: Pick<FactoryEnv, 'DB'>,
  request: FactoryRequest,
  signal: UpstreamReleaseSignal,
  currentVersion: string | null,
): Promise<UpstreamCheckResult> {
  const checkedAt = now();
  const previous = await env.DB.prepare('SELECT last_version FROM upstream_checks WHERE request_id=?')
    .bind(request.id).first<{ last_version: string | null }>();
  const previousSignal = previous?.last_version ?? null;
  const initialized = previousSignal !== null;
  const changed = initialized && previousSignal !== signal.signal;
  const versionChanged = signal.version != null && comparableVersion(signal.version) !== comparableVersion(currentVersion);
  const firstObservationRelease = !initialized && versionChanged;
  const knownCommitChanged = signal.commit !== null && request.upstreamRef != null && signal.commit !== request.upstreamRef;
  const shouldCreate = (changed || firstObservationRelease || knownCommitChanged) && (signal.sourceKind === 'archive' || versionChanged || signal.commit !== null);
  const upstreamUrl = normalizeSourceUrl(signal.upstreamUrl ?? request.upstreamUrl).toString();

  let pendingRequestId: string | null = null;
  const duplicate = await env.DB.prepare(`SELECT id,requested_by,status,upstream_url FROM requests
    WHERE name=? AND upstream_url=? AND source_kind=? AND upstream_ref IS ? AND status NOT IN ('built','rejected')
    ORDER BY created_at DESC LIMIT 1`)
    .bind(request.name, upstreamUrl, request.sourceKind, signal.commit).first<{
      id: string;
      requested_by: string;
      status: string;
      upstream_url: string;
    }>();
  const retryableDuplicate = duplicate && duplicate.requested_by === UPSTREAM_ACTOR &&
    ['pending', 'generating', 'failed'].includes(duplicate.status) ? duplicate : null;
  const active = shouldCreate && !duplicate
    ? await env.DB.prepare(`SELECT id,requested_by,status,upstream_url FROM requests
        WHERE name=? AND status IN ('pending','generating','review','queued','building')
        ORDER BY created_at DESC LIMIT 1`)
      .bind(request.name).first<{
        id: string;
        requested_by: string;
        status: string;
        upstream_url: string;
      }>()
    : null;
  let advanceCheckpoint = true;
  if (shouldCreate && !duplicate && active) {
    // Keep the observed signal pending until the current generated change is
    // reviewed. This prevents a faster upstream release from being forgotten.
    advanceCheckpoint = false;
    if (active.requested_by === UPSTREAM_ACTOR && ['pending', 'generating'].includes(active.status)) {
      pendingRequestId = active.id;
    }
  } else if (retryableDuplicate) {
    pendingRequestId = retryableDuplicate.id;
  }

  if (shouldCreate && !duplicate && !active) {
    pendingRequestId = id();
    await env.DB.batch([
      env.DB.prepare(`INSERT INTO requests(
        id,name,upstream_url,source_kind,area,declared_license,upstream_ref,requested_by,status,created_at,updated_at
      ) VALUES(?,?,?,?,?,?,?,'system:upstream-check','pending',?,?)`)
        .bind(pendingRequestId, request.name, upstreamUrl, request.sourceKind, request.area, request.declaredLicense, signal.commit, checkedAt, checkedAt),
      env.DB.prepare(`INSERT INTO upstream_checks(request_id,last_version,last_checked_at,error)
        VALUES(?,?,?,NULL) ON CONFLICT(request_id) DO UPDATE SET last_version=excluded.last_version,last_checked_at=excluded.last_checked_at,error=NULL`)
        .bind(request.id, signal.signal, checkedAt),
      audit(env.DB, 'system:upstream-check', 'upstream.release_detected', request.id, {
        pendingRequestId,
        version: signal.version,
        commit: signal.commit,
      }),
    ]);
  } else {
    if (shouldCreate && duplicate && duplicate.requested_by === UPSTREAM_ACTOR &&
      ['pending', 'generating'].includes(duplicate.status)) {
      pendingRequestId = duplicate.id;
    }
    if (advanceCheckpoint) {
      await env.DB.prepare(`INSERT INTO upstream_checks(request_id,last_version,last_checked_at,error)
        VALUES(?,?,?,NULL) ON CONFLICT(request_id) DO UPDATE SET last_version=excluded.last_version,last_checked_at=excluded.last_checked_at,error=NULL`)
        .bind(request.id, signal.signal, checkedAt).run();
    }
  }
  return { requestId: request.id, checkedAt, signal, pendingRequestId };
}

type AutomaticFactoryRun = {
  requestId: string;
  generationId: string;
};

type AutomaticFactoryEnv = Pick<FactoryEnv, 'DB'> & {
  FACTORY?: FactoryWorkflowBinding;
};

async function automaticGenerationAvailable(env: AutomaticFactoryEnv, requestId: string): Promise<boolean> {
  const generations = await env.DB.prepare(`SELECT COUNT(*) AS count FROM audit_events
    WHERE target=? AND action IN ('factory.auto_queued','factory.auto_retry')`)
    .bind(requestId).first<{ count: number }>();
  if (Number(generations?.count ?? 0) < MAX_AUTOMATIC_GENERATIONS) return true;
  const timestamp = now();
  await env.DB.prepare(`INSERT INTO audit_events(actor,action,target,detail,created_at)
    SELECT ?,?,?,?,? WHERE NOT EXISTS (
      SELECT 1 FROM audit_events WHERE target=? AND action='factory.auto_retry_exhausted'
    )`)
    .bind(UPSTREAM_ACTOR, 'factory.auto_retry_exhausted', requestId,
      JSON.stringify({ generations: MAX_AUTOMATIC_GENERATIONS }), timestamp, requestId).run();
  return false;
}

async function prepareAutomaticFactoryRun(env: AutomaticFactoryEnv, requestId: string): Promise<AutomaticFactoryRun | null> {
  let row = await env.DB.prepare(`SELECT status,factory_run_id,requested_by
    FROM requests WHERE id=?`).bind(requestId).first<{
      status: string;
      factory_run_id: string | null;
      requested_by: string;
  }>();
  if (!row || row.requested_by !== UPSTREAM_ACTOR) return null;

  if (row.status === 'pending') {
    if (!await automaticGenerationAvailable(env, requestId)) return null;
    const generationId = id();
    const timestamp = now();
    const result = await env.DB.batch([
      env.DB.prepare(`UPDATE requests SET status='generating',factory_run_id=?,updated_at=?
        WHERE id=? AND requested_by=? AND status='pending'`).bind(generationId, timestamp, requestId, UPSTREAM_ACTOR),
      env.DB.prepare(`INSERT INTO audit_events(actor,action,target,detail,created_at)
        SELECT ?,?,?,?,? WHERE changes()=1`)
        .bind(UPSTREAM_ACTOR, 'factory.auto_queued', requestId, JSON.stringify({ generationId }), timestamp),
    ]);
    if (result[0]?.meta.changes) return { requestId, generationId };
    row = await env.DB.prepare('SELECT status,factory_run_id,requested_by FROM requests WHERE id=?')
      .bind(requestId).first<typeof row>();
    if (!row || row.requested_by !== UPSTREAM_ACTOR) return null;
  }

  if (row.status === 'failed') {
    if (!await automaticGenerationAvailable(env, requestId)) return null;
    const generationId = id();
    const timestamp = now();
    const result = await env.DB.batch([
      env.DB.prepare(`UPDATE requests SET status='generating',factory_run_id=?,updated_at=?
        WHERE id=? AND requested_by=? AND status='failed' AND factory_run_id IS ?`)
        .bind(generationId, timestamp, requestId, UPSTREAM_ACTOR, row.factory_run_id),
      env.DB.prepare(`INSERT INTO audit_events(actor,action,target,detail,created_at)
        SELECT ?,?,?,?,? WHERE changes()=1`)
        .bind(UPSTREAM_ACTOR, 'factory.auto_retry', requestId, JSON.stringify({ generationId, previousGenerationId: row.factory_run_id }), timestamp),
    ]);
    if (result[0]?.meta.changes) return { requestId, generationId };
    row = await env.DB.prepare('SELECT status,factory_run_id,requested_by FROM requests WHERE id=?')
      .bind(requestId).first<typeof row>();
    if (!row || row.requested_by !== UPSTREAM_ACTOR) return null;
  }

  if (row.status !== 'generating' || !row.factory_run_id) return null;
  return { requestId, generationId: row.factory_run_id };
}

async function recordAutomaticDispatchFailure(env: AutomaticFactoryEnv, run: AutomaticFactoryRun, cause: unknown): Promise<void> {
  const message = redactText(cause instanceof Error ? cause.message : 'factory workflow could not be queued').slice(0, 1_000);
  const timestamp = now();
  await env.DB.batch([
    env.DB.prepare(`UPDATE requests SET status='failed',updated_at=?
      WHERE id=? AND requested_by=? AND status='generating' AND factory_run_id=?`)
      .bind(timestamp, run.requestId, UPSTREAM_ACTOR, run.generationId),
    env.DB.prepare(`INSERT INTO audit_events(actor,action,target,detail,created_at)
      VALUES(?,?,?,?,?)`)
      .bind(UPSTREAM_ACTOR, 'factory.auto_dispatch_failed', run.requestId, JSON.stringify({ generationId: run.generationId, message }), timestamp),
  ]);
}

/** Queue a detected release without creating a human approval record. */
export async function dispatchUpstreamFactory(env: AutomaticFactoryEnv, requestId: string): Promise<string | null> {
  const run = await prepareAutomaticFactoryRun(env, requestId);
  if (!run) return null;
  if (!env.FACTORY) {
    const error = new Error('factory workflow is not configured');
    await recordAutomaticDispatchFailure(env, run, error);
    throw error;
  }
  try {
    await env.FACTORY.create({
      id: run.generationId,
      params: { requestId: run.requestId, generationId: run.generationId },
    });
    await env.DB.prepare(`INSERT INTO audit_events(actor,action,target,detail,created_at)
      VALUES(?,?,?,?,?)`)
      .bind(UPSTREAM_ACTOR, 'factory.auto_dispatched', requestId, JSON.stringify({ generationId: run.generationId }), now()).run();
    return run.generationId;
  } catch (cause) {
    // A lost create response is safe when the durable workflow already exists.
    try {
      const status = await (await env.FACTORY.get(run.generationId)).status();
      if (!['errored', 'terminated'].includes(status.status)) {
        await env.DB.prepare(`INSERT INTO audit_events(actor,action,target,detail,created_at)
          VALUES(?,?,?,?,?)`)
          .bind(UPSTREAM_ACTOR, 'factory.auto_dispatch_confirmed', requestId, JSON.stringify({ generationId: run.generationId }), now()).run();
        return run.generationId;
      }
    } catch {
      // The next scheduled run retries the saved request and rotates its
      // workflow identity when the previous one is unavailable.
    }
    await recordAutomaticDispatchFailure(env, run, cause);
    throw new Error('factory workflow could not be queued');
  }
}

export async function detectUpstreamRelease(
  env: Pick<FactoryEnv, 'DB'>,
  request: FactoryRequest,
  options: {
    sandbox?: Sandbox;
    allowHost?: SourceHostAuthorizer;
    createSandbox?: () => Promise<{ sandbox: Sandbox; allowHost?: SourceHostAuthorizer }>;
    currentVersion?: string | null;
  },
): Promise<UpstreamCheckResult> {
  const signal = request.sourceKind === 'git'
    ? options.sandbox
      ? await inspectGitRelease(request, options.sandbox)
      : (() => { throw new Error('git release checks require an isolated sandbox'); })()
    : await inspectArchiveRelease(request, options.sandbox, options.allowHost, options.createSandbox);
  return recordUpstreamRelease(env, request, signal, options.currentVersion ?? null);
}

export type UpstreamRequestRow = {
  id: string;
  name: string;
  upstream_url: string;
  source_kind: 'git' | 'archive';
  area: Area;
  declared_license: string;
  published_version: string;
  upstream_ref: string | null;
};

export type SupportedArchitecture = Architecture;
