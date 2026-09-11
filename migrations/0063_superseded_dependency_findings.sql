-- Regenerated recipes retain previous findings as history, not current blockers.
UPDATE dependency_blockers
SET status='superseded',resolved_at=unixepoch()
WHERE status='open' AND revision_id IS NOT NULL
  AND revision_id<>(SELECT id FROM revisions WHERE request_id=dependency_blockers.request_id
    ORDER BY created_at DESC,rowid DESC LIMIT 1);
