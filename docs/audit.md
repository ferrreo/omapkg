# Audit retention and export

`audit_events` stores append-only records. Database triggers reject updates and deletes, and omapkg retains audit events indefinitely. Retention does not remove or rewrite historical records.

Maintainers can export a fixed database snapshot through `/api/admin/audit/export`. CSV and NDJSON downloads stream bounded pages until every event in the selected search and time scope has been emitted. New events created after the snapshot do not extend an export. `paged=1` returns one bounded page with `X-Audit-Next-Before` for clients that need to resume explicitly.

Exports contain private operational records. Store routine backups and exported files in access-controlled storage, restrict access to maintainers, and remove copies according to the operator's storage policy. Export start, completion, and failure are recorded in the audit stream without copying search text or credentials into audit details.
