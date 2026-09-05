import { json, type RequestHandler } from '@sveltejs/kit';
import { auditCsv, auditExportStream, auditNdjson, listAuditEvents, maxAuditId, parseAuditQuery, recordAuditExport, recordAuditExportStarted, MAX_LIMIT } from '$lib/server/audit';
import { environment, maintainer } from '$lib/server/http';
import { PolicyError } from '$lib/server/policy';

const headers = { 'Cache-Control': 'private, no-store', Vary: 'Cookie' };

export const GET: RequestHandler = async (event) => {
  try {
    const actor = maintainer(event);
    const env = environment(event);
    const formatValue = event.url.searchParams.get('format') ?? 'csv';
    if (formatValue !== 'csv' && formatValue !== 'ndjson') throw new PolicyError(400, 'Audit export format must be CSV or NDJSON.');
    const pagedValue = event.url.searchParams.get('paged');
    if (pagedValue !== null && pagedValue !== '0' && pagedValue !== '1') throw new PolicyError(400, 'Audit paging option is invalid.');
    const options = parseAuditQuery(event.url, MAX_LIMIT);
    const contentType = formatValue === 'csv' ? 'text/csv; charset=utf-8' : 'application/x-ndjson; charset=utf-8';
    const responseHeaders = new Headers({ ...headers, 'Content-Type': contentType, 'Content-Disposition': `attachment; filename="omapkg-audit.${formatValue}"` });
    if (pagedValue === '1') {
      const page = await listAuditEvents(env.DB, options);
      await recordAuditExport(env.DB, actor.id, options, formatValue, page.events.length, page.nextBefore);
      const body = formatValue === 'csv' ? auditCsv(page.events) : auditNdjson(page.events);
      if (page.nextBefore !== null) responseHeaders.set('X-Audit-Next-Before', String(page.nextBefore));
      return new Response(body, { headers: responseHeaders });
    }
    const snapshotMaxId = await maxAuditId(env.DB);
    await recordAuditExportStarted(env.DB, actor.id, options, formatValue, snapshotMaxId);
    responseHeaders.set('X-Audit-Snapshot-Max', String(snapshotMaxId));
    return new Response(auditExportStream(env.DB, actor.id, options, formatValue, snapshotMaxId), { headers: responseHeaders });
  } catch (cause) {
    if (cause instanceof PolicyError) return json({ error: cause.message }, { status: cause.status, headers });
    throw cause;
  }
};
