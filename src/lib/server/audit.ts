import type { AuditEvent } from '../model';
import { audit, now, query } from './db';
import { PolicyError } from './policy';

const DEFAULT_LIMIT = 200;
const MAX_LIMIT = 1_000;
const MAX_QUERY_LENGTH = 256;
const MAX_BEFORE = Number.MAX_SAFE_INTEGER;
const ranges = { all: null, '24h': 24 * 60 * 60, '7d': 7 * 24 * 60 * 60, '30d': 30 * 24 * 60 * 60, '90d': 90 * 24 * 60 * 60 } as const;

export type AuditRange = keyof typeof ranges;
export type AuditExportFormat = 'csv' | 'ndjson';

export interface AuditQuery {
  q: string;
  requestId?: string | null;
  before: number;
  from: number | null;
  to: number | null;
  range: AuditRange;
  limit: number;
}

export interface AuditPage {
  events: AuditEvent[];
  nextBefore: number | null;
}

export interface AuditExportSnapshot {
  snapshotMaxId: number;
  returned: number;
  pages: number;
}

function invalidQuery(message: string): never {
  throw new PolicyError(400, message);
}

function integerParam(params: URLSearchParams, name: string, fallback: number | null, minimum: number): number | null {
  const value = params.get(name);
  if (value === null || value === '') return fallback;
  if (!/^\d+$/.test(value)) return invalidQuery(`Audit ${name} must be a whole number.`);
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < minimum) return invalidQuery(`Audit ${name} is outside the supported range.`);
  return parsed;
}

export function parseAuditQuery(source: URL | URLSearchParams, maxLimit = DEFAULT_LIMIT): AuditQuery {
  const params = source instanceof URL ? source.searchParams : source;
  if (!Number.isSafeInteger(maxLimit) || maxLimit < 1 || maxLimit > MAX_LIMIT) throw new Error('audit query limit is invalid');
  const q = (params.get('q') ?? '').trim();
  if (q.length > MAX_QUERY_LENGTH || /[\u0000-\u001f\u007f]/.test(q)) return invalidQuery('Audit search must be 256 characters or fewer.');
  const requestId = params.get('request') || null;
  if (requestId && !/^[A-Za-z0-9_-]{1,128}$/.test(requestId)) return invalidQuery('Audit request ID is invalid.');
  const before = integerParam(params, 'before', MAX_BEFORE, 1) ?? MAX_BEFORE;
  const limit = integerParam(params, 'limit', Math.min(DEFAULT_LIMIT, maxLimit), 1) ?? Math.min(DEFAULT_LIMIT, maxLimit);
  if (limit > maxLimit) return invalidQuery(`Audit limit cannot exceed ${maxLimit}.`);
  const rangeValue = params.get('range') ?? 'all';
  if (!Object.prototype.hasOwnProperty.call(ranges, rangeValue)) return invalidQuery('Audit range is invalid.');
  const range = rangeValue as AuditRange;
  const rangeFrom = ranges[range] === null ? null : now() - ranges[range];
  const requestedFrom = integerParam(params, 'from', null, 0);
  const from = rangeFrom === null ? requestedFrom : requestedFrom === null ? rangeFrom : Math.max(rangeFrom, requestedFrom);
  const to = integerParam(params, 'to', null, 0);
  if (from !== null && to !== null && from > to) return invalidQuery('Audit start must be before its end.');
  return { q, requestId, before, from, to, range, limit };
}

function escapedLike(value: string): string {
  return `%${value.replace(/[\\%_]/g, (character) => `\\${character}`)}%`;
}

export async function listAuditEvents(db: D1Database, options: AuditQuery): Promise<AuditPage> {
  const clauses = ['id < ?'];
  const values: unknown[] = [options.before];
  let scope = '';
  if (options.requestId) {
    scope = `WITH scoped_request AS (SELECT id FROM requests WHERE id=?),
      scoped_revisions AS (SELECT id FROM revisions WHERE request_id IN (SELECT id FROM scoped_request)),
      scoped_builds AS (SELECT id FROM builds WHERE revision_id IN (SELECT id FROM scoped_revisions)),
      scoped_releases AS (SELECT id FROM releases WHERE build_id IN (SELECT id FROM scoped_builds))`;
    values.unshift(options.requestId);
    clauses.push(`(target IN (SELECT id FROM scoped_request)
      OR target IN (SELECT id FROM scoped_revisions)
      OR target IN (SELECT id FROM scoped_builds)
      OR target IN (SELECT id FROM scoped_releases)
      OR target IN (SELECT id FROM signing_intents WHERE build_id IN (SELECT id FROM scoped_builds))
      OR target IN (SELECT p.id FROM promotion_batches p, json_each(p.release_ids_json) member
        WHERE member.value IN (SELECT id FROM scoped_releases)))`);
  }
  if (options.from !== null) {
    clauses.push('created_at >= ?');
    values.push(options.from);
  }
  if (options.to !== null) {
    clauses.push('created_at <= ?');
    values.push(options.to);
  }
  if (options.q) {
    const pattern = escapedLike(options.q);
    const usernameQuery = options.q.replace(/^@/, '');
    const usernamePattern = usernameQuery ? escapedLike(usernameQuery) : null;
    clauses.push(`(actor LIKE ? ESCAPE '\\' OR action LIKE ? ESCAPE '\\' OR target LIKE ? ESCAPE '\\' OR detail LIKE ? ESCAPE '\\'${usernamePattern ? " OR EXISTS (SELECT 1 FROM github_identities i WHERE (actor = 'github:' || i.github_id OR target = 'github:' || i.github_id) AND i.username LIKE ? ESCAPE '\\')" : ''})`);
    values.push(pattern, pattern, pattern, pattern);
    if (usernamePattern) values.push(usernamePattern);
  }
  values.push(options.limit + 1);
  const rows = await query<AuditEvent>(db, `${scope} SELECT id,actor,action,target,detail,created_at FROM audit_events
    WHERE ${clauses.join(' AND ')} ORDER BY id DESC LIMIT ?`, ...values);
  const events = rows.slice(0, options.limit);
  return { events, nextBefore: rows.length > options.limit ? events.at(-1)?.id ?? null : null };
}

export async function maxAuditId(db: D1Database): Promise<number> {
  const rows = await query<{ max_id: number }>(db, 'SELECT COALESCE(MAX(id),0) AS max_id FROM audit_events');
  const value = Number(rows[0]?.max_id ?? 0);
  if (!Number.isSafeInteger(value) || value < 0) throw new Error('audit snapshot is invalid');
  return value;
}

function exportDetail(options: AuditQuery, format: AuditExportFormat, snapshotMaxId: number, extra: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    format,
    range: options.range,
    from: options.from,
    to: options.to,
    limit: options.limit,
    snapshotMaxId,
    filtered: Boolean(options.q),
    requestId: options.requestId ?? null,
    ...extra,
  };
}

export async function recordAuditExportStarted(db: D1Database, actor: string, options: AuditQuery, format: AuditExportFormat, snapshotMaxId: number): Promise<void> {
  await audit(db, actor, 'audit.export_started', 'audit', exportDetail(options, format, snapshotMaxId)).run();
}

export async function recordAuditExportCompleted(db: D1Database, actor: string, options: AuditQuery, format: AuditExportFormat, snapshot: AuditExportSnapshot): Promise<void> {
  await audit(db, actor, 'audit.export_completed', 'audit', exportDetail(options, format, snapshot.snapshotMaxId, {
    returned: snapshot.returned,
    pages: snapshot.pages,
  })).run();
}

export async function recordAuditExportFailed(db: D1Database, actor: string, options: AuditQuery, format: AuditExportFormat, snapshot: AuditExportSnapshot): Promise<void> {
  await audit(db, actor, 'audit.export_failed', 'audit', exportDetail(options, format, snapshot.snapshotMaxId, {
    returned: snapshot.returned,
    pages: snapshot.pages,
  })).run();
}

export async function recordAuditExport(db: D1Database, actor: string, options: AuditQuery, format: AuditExportFormat, returned: number, nextBefore: number | null): Promise<void> {
  await audit(db, actor, 'audit.exported', 'audit', {
    format,
    range: options.range,
    from: options.from,
    to: options.to,
    limit: options.limit,
    returned,
    nextBefore,
    filtered: Boolean(options.q),
    requestId: options.requestId ?? null,
  }).run();
}

export function auditExportStream(db: D1Database, actor: string, options: AuditQuery, format: AuditExportFormat, snapshotMaxId: number): ReadableStream<Uint8Array> {
  const encoder = new TextEncoder();
  const firstBefore = snapshotMaxId < Number.MAX_SAFE_INTEGER ? snapshotMaxId + 1 : snapshotMaxId;
  let before = Math.min(options.before, firstBefore);
  let returned = 0;
  let pages = 0;
  let finished = false;
  let headerSent = false;

  return new ReadableStream<Uint8Array>({
    async pull(controller) {
      if (finished) return;
      try {
        if (format === 'csv' && !headerSent) {
          controller.enqueue(encoder.encode(auditCsvHeader()));
          headerSent = true;
        }
        const page = await listAuditEvents(db, { ...options, before });
        if (page.events.length) {
          pages += 1;
          returned += page.events.length;
          const chunk = format === 'csv' ? auditCsvRowsChunk(page.events) : auditNdjson(page.events);
          if (chunk) controller.enqueue(encoder.encode(chunk));
        }
        if (page.nextBefore === null) {
          await recordAuditExportCompleted(db, actor, options, format, { snapshotMaxId, returned, pages });
          finished = true;
          controller.close();
        } else {
          before = page.nextBefore;
        }
      } catch {
        finished = true;
        try { await recordAuditExportFailed(db, actor, options, format, { snapshotMaxId, returned, pages }); }
        catch { /* preserve original stream failure */ }
        controller.error(new Error('Audit export failed.'));
      }
    },
    async cancel() {
      if (finished) return;
      finished = true;
      try { await recordAuditExportFailed(db, actor, options, format, { snapshotMaxId, returned, pages }); }
      catch { /* preserve cancellation */ }
    },
  });
}

const csvHeader = '"id","actor","action","target","detail","created_at"\r\n';

function auditCsvRows(events: readonly AuditEvent[]): string {
  const cell = (value: string | number): string => {
    const text = String(value);
    const safe = /^\s*[=+\-@]/.test(text) ? `'${text}` : text;
    return `"${safe.replace(/"/g, '""')}"`;
  };
  return events.map((event) => [event.id, event.actor, event.action, event.target, event.detail, event.created_at].map((value) => cell(value)).join(',')).join('\r\n') + (events.length ? '\r\n' : '');
}

export function auditCsvHeader(): string {
  return csvHeader;
}

export function auditCsvRowsChunk(events: readonly AuditEvent[]): string {
  return auditCsvRows(events);
}

export function auditCsv(events: readonly AuditEvent[]): string {
  return csvHeader + auditCsvRows(events);
}

export function auditNdjson(events: readonly AuditEvent[]): string {
  return events.map((event) => JSON.stringify(event)).join('\n') + (events.length ? '\n' : '');
}

export { DEFAULT_LIMIT, MAX_LIMIT };
