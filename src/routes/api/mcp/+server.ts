import { json, type RequestEvent, type RequestHandler } from '@sveltejs/kit';
import type { Actor, Architecture, Release } from '$lib/model';
import { audit, query } from '$lib/server/db';
import { PolicyError, requireMaintainer } from '$lib/server/policy';
import { publicRelease } from '$lib/server/releases';
import { finalDescription } from '$lib/server/descriptions';
import { readBody, requireJsonContentType, WorkerProtocolError } from '$lib/server/workers';

const PROTOCOL = '2026-07-28';
const SERVER = { name: 'omapkg', version: '0.1.0', description: 'Read-only package provenance and release evidence for omapkg.' };
const MAX_BODY = 256 * 1024;
const PACKAGE_NAME = /^[a-z0-9][a-z0-9@._+:-]{0,63}$/;
const RELEASE_ID = /^[A-Za-z0-9_-]{1,128}$/;
const TOOLS = [
  {
    name: 'packages.search', title: 'Search released packages', description: 'Search omapkg packages by name, architecture, surface, or channel.',
    inputSchema: { type: 'object', properties: { query: { type: 'string' }, architecture: { type: 'string', enum: ['x86_64', 'aarch64'] }, surface: { type: 'string', enum: ['binary', 'recipe'] }, channel: { type: 'string', enum: ['stable', 'dev'] }, cursor: { type: 'string' }, limit: { type: 'integer', minimum: 1, maximum: 100 } }, additionalProperties: false },
  },
  {
    name: 'packages.get', title: 'Read package evidence', description: 'Read public evidence for a released package and its published version history.',
    inputSchema: { type: 'object', properties: { name: { type: 'string' }, channel: { type: 'string', enum: ['stable', 'dev'] } }, required: ['name'], additionalProperties: false },
  },
  {
    name: 'provenance.get', title: 'Read release provenance', description: 'Read provenance and attestation metadata for a released package version.',
    inputSchema: { type: 'object', properties: { releaseId: { type: 'string' }, channel: { type: 'string', enum: ['stable', 'dev'] } }, required: ['releaseId'], additionalProperties: false },
  },
  {
    name: 'metrics.get', title: 'Read catalog metrics', description: 'Read counts computed from currently published package records.',
    inputSchema: { type: 'object', additionalProperties: false },
  },
];
const PRIVATE_TOOLS = [
  {
    name: 'builds.get', title: 'Read build evidence', description: 'Read maintainer-only build, smoke-test, attestation, and review evidence.',
    inputSchema: { type: 'object', properties: { buildId: { type: 'string' } }, required: ['buildId'], additionalProperties: false },
  },
  {
    name: 'tests.get', title: 'Read test evidence', description: 'Read maintainer-only smoke-test commands, result, and build log evidence.',
    inputSchema: { type: 'object', properties: { buildId: { type: 'string' } }, required: ['buildId'], additionalProperties: false },
  },
];

type RpcRequest = { jsonrpc: '2.0'; id?: string | number; method: string; params?: Record<string, unknown> };
type PublicRow = Release & { artifact_filename: string | null; artifact_sha256: string | null; artifact_size: number | null; source_json: string; license: string; upstream_url: string; dependencies_json?: string; description?: string | null; recipe?: string; explanation?: string };

function rpcError(id: string | number | undefined, code: number, message: string, data?: unknown, status = 400) {
  const error: Record<string, unknown> = { code, message };
  if (data !== undefined) error.data = data;
  return json({ jsonrpc: '2.0', ...(id === undefined ? {} : { id }), error }, { status, headers: { 'Cache-Control': 'no-store' } });
}

function completeEnvelope(id: string | number, result: Record<string, unknown>) {
  return json({ jsonrpc: '2.0', id, result }, {
    headers: { 'Cache-Control': 'no-store' },
  });
}

function toolComplete(id: string | number, value: unknown, cache: { cacheScope: 'public' | 'private'; ttlMs: number }) {
  const result = { resultType: 'complete', structuredContent: value, content: [{ type: 'text', text: JSON.stringify(value) }], isError: false, ...cache };
  return json({ jsonrpc: '2.0', id, result }, { headers: { 'Cache-Control': 'no-store' } });
}

function toolFailure(id: string | number, message: string) {
  const result = { resultType: 'complete', content: [{ type: 'text', text: message }], isError: true };
  return json({ jsonrpc: '2.0', id, result }, { status: 200, headers: { 'Cache-Control': 'no-store' } });
}

function validId(value: unknown): value is string | number {
  return (typeof value === 'string' && value.length > 0 && value.length <= 128) || (typeof value === 'number' && Number.isSafeInteger(value));
}

function paramsMeta(params: Record<string, unknown> | undefined): Record<string, unknown> | null {
  if (!params || !params._meta || typeof params._meta !== 'object' || Array.isArray(params._meta)) return null;
  const meta = params._meta as Record<string, unknown>;
  if (typeof meta['io.modelcontextprotocol/protocolVersion'] !== 'string' || !meta['io.modelcontextprotocol/clientCapabilities'] || typeof meta['io.modelcontextprotocol/clientCapabilities'] !== 'object' || Array.isArray(meta['io.modelcontextprotocol/clientCapabilities'])) return null;
  return meta;
}

function requestHeaders(event: RequestEvent, input: RpcRequest): Response | null {
  const methodHeader = event.request.headers.get('Mcp-Method');
  const versionHeader = event.request.headers.get('MCP-Protocol-Version');
  if (!methodHeader || methodHeader !== input.method) return rpcError(input.id, -32020, 'MCP request header does not match JSON-RPC method.');
  const params = input.params;
  const meta = paramsMeta(params);
  if (!meta) return rpcError(input.id, -32602, 'Request params must include MCP protocol version and client capabilities.');
  const bodyVersion = String(meta['io.modelcontextprotocol/protocolVersion']);
  if (versionHeader !== bodyVersion) return rpcError(input.id, -32020, 'MCP protocol version header does not match request metadata.');
  if (bodyVersion !== PROTOCOL || versionHeader !== PROTOCOL) return rpcError(input.id, -32022, 'Unsupported protocol version.', { supported: [PROTOCOL] });
  if (['tools/call', 'resources/read', 'prompts/get'].includes(input.method)) {
    const name = typeof params?.name === 'string' ? params.name : typeof params?.uri === 'string' ? params.uri : null;
    if (!name || event.request.headers.get('Mcp-Name') !== name) return rpcError(input.id, -32020, 'MCP name header does not match request parameters.');
  }
  return null;
}

function publicSources(value: string): Array<{ name: string; url: string; sha256: string }> {
  try {
    const parsed: unknown = JSON.parse(value);
    if (!Array.isArray(parsed)) return [];
    return parsed.filter((item): item is { name: string; url: string; sha256: string } => {
      if (!item || typeof item !== 'object') return false;
      const row = item as Record<string, unknown>;
      return typeof row.name === 'string' && typeof row.url === 'string' && typeof row.sha256 === 'string';
    });
  } catch { return []; }
}

function publicRow(row: PublicRow, origin: string, includeDev = false) {
  const release = publicRelease(row, origin, includeDev);
  if (!release) return null;
  return { ...release, description: finalDescription(row, row.name), source: { upstreamUrl: row.upstream_url, files: publicSources(row.source_json) }, license: row.license, dependencies: row.dependencies_json ? parseList(row.dependencies_json) : undefined, explanation: row.explanation };
}

function parseList(value: string): string[] {
  try { const parsed: unknown = JSON.parse(value); return Array.isArray(parsed) ? parsed.filter((item): item is string => typeof item === 'string') : []; }
  catch { return []; }
}

function encodeCursor(offset: number): string {
  return btoa(JSON.stringify({ offset })).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
}

function decodeCursor(value: unknown): number {
  if (value === undefined) return 0;
  if (typeof value !== 'string' || !value || value.length > 128) throw new PolicyError(400, 'Invalid cursor.');
  try {
    const padded = value.replaceAll('-', '+').replaceAll('_', '/') + '='.repeat((4 - value.length % 4) % 4);
    const parsed = JSON.parse(atob(padded)) as { offset?: unknown };
    if (!Number.isSafeInteger(parsed.offset) || (parsed.offset as number) < 0) throw new Error('invalid cursor');
    return parsed.offset as number;
  } catch {
    throw new PolicyError(400, 'Invalid cursor.');
  }
}

function rejectUnknownArgs(args: Record<string, unknown>, allowed: readonly string[]): void {
  if (Object.keys(args).some((key) => !allowed.includes(key))) throw new PolicyError(400, 'Unknown tool argument.');
}

function optionalChannel(args: Record<string, unknown>): 'stable' | 'dev' {
  if (args.channel === undefined || args.channel === 'stable') return 'stable';
  if (args.channel === 'dev') return 'dev';
  throw new PolicyError(400, 'Invalid channel.');
}

function optionalLimit(value: unknown): number {
  if (value === undefined) return 25;
  if (!Number.isSafeInteger(value) || (value as number) < 1 || (value as number) > 100) throw new PolicyError(400, 'Invalid limit.');
  return value as number;
}

async function packageSearch(event: RequestEvent, args: Record<string, unknown>) {
  rejectUnknownArgs(args, ['query', 'architecture', 'surface', 'channel', 'cursor', 'limit']);
  const queryText = args.query === undefined ? '' : typeof args.query === 'string' && args.query.length <= 80 && !/[\u0000-\u001f\u007f]/.test(args.query) ? args.query.trim() : (() => { throw new PolicyError(400, 'Invalid query filter.'); })();
  const channel = optionalChannel(args);
  if (args.architecture !== undefined && args.architecture !== 'x86_64' && args.architecture !== 'aarch64') throw new PolicyError(400, 'Invalid architecture filter.');
  if (args.surface !== undefined && args.surface !== 'binary' && args.surface !== 'recipe') throw new PolicyError(400, 'Invalid surface filter.');
  const filters = ['r.channel=?'];
  const values: unknown[] = [channel];
  if (queryText) { filters.push('lower(r.name) LIKE ?'); values.push(`%${queryText.toLowerCase()}%`); }
  if (args.surface !== undefined) { filters.push('r.surface=?'); values.push(args.surface); }
  if (args.architecture !== undefined) { filters.push('r.architecture=?'); values.push(args.architecture); }
  const start = decodeCursor(args.cursor);
  const limit = optionalLimit(args.limit);
  const rows = await query<PublicRow & { row_number: number }>(event.platform!.env.DB, `SELECT * FROM (
      SELECT r.*,b.artifact_filename,b.artifact_sha256,b.artifact_size,v.sources_json AS source_json,v.license,v.description,v.recipe,v.explanation,q.upstream_url,
        ROW_NUMBER() OVER (PARTITION BY r.name,r.architecture ORDER BY r.published_at DESC,r.id DESC) AS row_number
      FROM releases r JOIN builds b ON b.id=r.build_id JOIN revisions v ON v.id=b.revision_id JOIN requests q ON q.id=v.request_id
      WHERE ${filters.join(' AND ')}
    ) catalog WHERE row_number=1
    ORDER BY name COLLATE NOCASE,architecture,published_at DESC,id DESC LIMIT ? OFFSET ?`, ...values, limit + 1, start);
  const items = rows.slice(0, limit).map((row) => publicRow(row, event.url.origin, channel === 'dev')).filter(Boolean);
  return { items, nextCursor: rows.length > limit ? encodeCursor(start + limit) : null };
}

async function packageGet(event: RequestEvent, args: Record<string, unknown>) {
  rejectUnknownArgs(args, ['name', 'channel']);
  if (typeof args.name !== 'string' || !PACKAGE_NAME.test(args.name)) throw new PolicyError(400, 'Invalid package name.');
  const dev = optionalChannel(args) === 'dev';
  const rows = await query<PublicRow>(event.platform!.env.DB, `SELECT r.*,b.artifact_filename,b.artifact_sha256,b.artifact_size,v.sources_json AS source_json,v.license,v.description,v.recipe,v.dependencies_json,v.explanation,q.upstream_url
    FROM releases r JOIN builds b ON b.id=r.build_id JOIN revisions v ON v.id=b.revision_id JOIN requests q ON q.id=v.request_id
    WHERE r.name=? AND r.channel ${dev ? '= \'dev\'' : "IN ('stable','withdrawn')"} ORDER BY r.published_at DESC,r.id DESC`, args.name);
  if (!rows.length) throw new PolicyError(404, 'Package not found.');
  return { name: args.name, versions: rows.map((row) => publicRow(row, event.url.origin, dev)).filter(Boolean) };
}

async function provenanceGet(event: RequestEvent, args: Record<string, unknown>) {
  rejectUnknownArgs(args, ['releaseId', 'channel']);
  if (typeof args.releaseId !== 'string' || !RELEASE_ID.test(args.releaseId)) throw new PolicyError(400, 'Invalid release ID.');
  const dev = optionalChannel(args) === 'dev';
  const row = await event.platform!.env.DB.prepare(`SELECT provenance_key FROM releases WHERE id=? AND channel ${dev ? '= \'dev\'' : "IN ('stable','withdrawn')"}`).bind(args.releaseId).first<{ provenance_key: string }>();
  if (!row) throw new PolicyError(404, 'Released provenance not found.');
  const object = await event.platform!.env.ARTIFACTS.get(row.provenance_key);
  if (!object) throw new PolicyError(404, 'Released provenance not found.');
  try { return { releaseId: args.releaseId, provenance: JSON.parse(await object.text()) }; }
  catch { throw new PolicyError(503, 'Released provenance is unavailable.'); }
}

async function metricsGet(event: RequestEvent, actor: Actor | null) {
  const rows = await query<{ surface: string; architecture: Architecture; count: number }>(event.platform!.env.DB, "SELECT surface,architecture,COUNT(*) AS count FROM releases WHERE channel='stable' GROUP BY surface,architecture ORDER BY surface,architecture");
  const result: Record<string, unknown> = { stable: rows };
  if (actor && actor.role !== 'public') {
    requireMaintainer(actor);
    result.pipeline = await query<{ status: string; count: number }>(event.platform!.env.DB, 'SELECT status,COUNT(*) AS count FROM builds GROUP BY status ORDER BY status');
  }
  return result;
}

async function buildGet(event: RequestEvent, actor: Actor | null, args: Record<string, unknown>) {
  requireMaintainer(actor);
  rejectUnknownArgs(args, ['buildId']);
  if (typeof args.buildId !== 'string' || !RELEASE_ID.test(args.buildId)) throw new PolicyError(400, 'Invalid build ID.');
  const row = await event.platform!.env.DB.prepare(`SELECT b.id,b.revision_id,b.architecture,b.status,b.worker_id,b.artifact_key,b.artifact_sha256,b.artifact_size,
    b.artifact_filename,b.provenance,b.provenance_signature,b.smoke_passed,b.error,b.created_at,b.started_at,b.finished_at,
    v.manifest_sha256,v.recipe_sha256,v.surface,v.version,q.name FROM builds b JOIN revisions v ON v.id=b.revision_id JOIN requests q ON q.id=v.request_id WHERE b.id=?`).bind(args.buildId).first<Record<string, unknown>>();
  if (!row) throw new PolicyError(404, 'Build not found.');
  await audit(event.platform!.env.DB, actor!.id, 'mcp.build_read', args.buildId).run();
  return row;
}

async function testGet(event: RequestEvent, actor: Actor | null, args: Record<string, unknown>) {
  requireMaintainer(actor);
  rejectUnknownArgs(args, ['buildId']);
  if (typeof args.buildId !== 'string' || !RELEASE_ID.test(args.buildId)) throw new PolicyError(400, 'Invalid build ID.');
  const row = await event.platform!.env.DB.prepare(`SELECT b.id,b.status,b.smoke_passed,b.error,b.started_at,b.finished_at,v.smoke_commands_json
    FROM builds b JOIN revisions v ON v.id=b.revision_id WHERE b.id=?`).bind(args.buildId).first<{ id: string; status: string; smoke_passed: number; error: string | null; started_at: number | null; finished_at: number | null; smoke_commands_json: string }>();
  if (!row) throw new PolicyError(404, 'Build tests not found.');
  const logs = await query<{ attempt: number; sequence: number; text: string; created_at: number }>(event.platform!.env.DB,
    'SELECT attempt,sequence,text,created_at FROM build_logs WHERE build_id=? ORDER BY attempt,sequence LIMIT 500', args.buildId);
  await audit(event.platform!.env.DB, actor!.id, 'mcp.tests_read', args.buildId).run();
  return {
    buildId: row.id, status: row.status, smokePassed: row.smoke_passed === 1, commands: parseList(row.smoke_commands_json),
    error: row.error, startedAt: row.started_at, finishedAt: row.finished_at, logs,
  };
}

function availableTools(actor: Actor | null) {
  return actor && actor.role !== 'public' ? [...TOOLS, ...PRIVATE_TOOLS] : TOOLS;
}

function toolCacheHint(name: string, args: Record<string, unknown>, actor: Actor | null): { cacheScope: 'public' | 'private'; ttlMs: number } {
  if (name === 'builds.get' || name === 'tests.get' || (name === 'metrics.get' && actor && actor.role !== 'public')) {
    return { cacheScope: 'private', ttlMs: 0 };
  }
  return { cacheScope: 'public', ttlMs: args.channel === 'dev' ? 30_000 : 300_000 };
}

async function dispatch(event: RequestEvent, actor: Actor | null, input: RpcRequest): Promise<Response> {
  if (input.method === 'server/discover') return completeEnvelope(input.id!, {
    resultType: 'complete',
    supportedVersions: [PROTOCOL],
    capabilities: { tools: { listChanged: false } },
    _meta: { 'io.modelcontextprotocol/serverInfo': { name: SERVER.name, version: SERVER.version } },
    instructions: SERVER.description,
    ttlMs: 300_000,
    cacheScope: 'public',
  });
  if (input.method === 'tools/list') {
    const privateCatalog = Boolean(actor && actor.role !== 'public');
    return completeEnvelope(input.id!, {
      resultType: 'complete',
      tools: availableTools(actor),
      nextCursor: null,
      ttlMs: privateCatalog ? 0 : 300_000,
      cacheScope: privateCatalog ? 'private' : 'public',
    });
  }
  if (input.method !== 'tools/call') return rpcError(input.id, -32601, 'Method not found.', undefined, 404);
  if (!validId(input.id)) return rpcError(input.id, -32600, 'JSON-RPC request ID is required.');
  const params = input.params ?? {};
  const name = typeof params.name === 'string' ? params.name : '';
  const tool = availableTools(actor).find((item) => item.name === name);
  if (!tool) return rpcError(input.id, -32602, 'Unknown tool.');
  const args = params.arguments;
  if (args !== undefined && (!args || typeof args !== 'object' || Array.isArray(args))) return rpcError(input.id, -32602, 'Tool arguments must be an object.');
  try {
    let value: unknown;
    if (name === 'packages.search') value = await packageSearch(event, (args ?? {}) as Record<string, unknown>);
    else if (name === 'packages.get') value = await packageGet(event, (args ?? {}) as Record<string, unknown>);
    else if (name === 'provenance.get') value = await provenanceGet(event, (args ?? {}) as Record<string, unknown>);
    else if (name === 'metrics.get') value = await metricsGet(event, actor);
    else if (name === 'builds.get') value = await buildGet(event, actor, (args ?? {}) as Record<string, unknown>);
    else if (name === 'tests.get') value = await testGet(event, actor, (args ?? {}) as Record<string, unknown>);
    else return rpcError(input.id, -32602, 'Unknown tool.');
    return toolComplete(input.id, value, toolCacheHint(name, (args ?? {}) as Record<string, unknown>, actor));
  } catch (cause) {
    if (cause instanceof PolicyError && cause.status === 400) return rpcError(input.id, -32602, cause.message);
    if (cause instanceof PolicyError) return toolFailure(input.id, cause.message);
    console.error(cause instanceof Error ? cause.message : 'MCP tool failed');
    return toolFailure(input.id, 'Tool failed. Retry or check omapkg status.');
  }
}

export const POST: RequestHandler = async (event) => {
  let body: Uint8Array;
  try {
    requireJsonContentType(event.request);
    body = await readBody(event.request, MAX_BODY);
  } catch (cause) {
    if (cause instanceof WorkerProtocolError) {
      return rpcError(undefined, -32600, cause.status === 413 ? 'MCP request is too large.' : cause.message, undefined, cause.status);
    }
    return rpcError(undefined, -32600, 'MCP request is invalid.');
  }
  let parsed: unknown;
  try { parsed = JSON.parse(new TextDecoder().decode(body)); }
  catch { return rpcError(undefined, -32700, 'Parse error.'); }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return rpcError(undefined, -32600, 'Invalid JSON-RPC request.');
  const input = parsed as Record<string, unknown>;
  if (input.jsonrpc !== '2.0' || typeof input.method !== 'string' || (input.id !== undefined && !validId(input.id))) return rpcError(validId(input.id) ? input.id : undefined, -32600, 'Invalid JSON-RPC request.');
  if (input.params !== undefined && (!input.params || typeof input.params !== 'object' || Array.isArray(input.params))) return rpcError(validId(input.id) ? input.id : undefined, -32602, 'Request params must be an object.');
  const request = { jsonrpc: '2.0' as const, ...(input.id === undefined ? {} : { id: input.id as string | number }), method: input.method, params: input.params as Record<string, unknown> | undefined };
  const headerError = requestHeaders(event, request);
  if (headerError) return headerError;
  if (request.id === undefined) return new Response(null, { status: 202 });
  if (!event.platform?.env?.DB || !event.platform.env.ARTIFACTS) return rpcError(request.id, -32603, 'omapkg data store is unavailable.', undefined, 503);
  return dispatch(event, event.locals.actor, request);
};

export const GET: RequestHandler = () => new Response(null, { status: 405, headers: { Allow: 'POST', 'Cache-Control': 'no-store' } });
