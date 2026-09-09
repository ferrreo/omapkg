CREATE INDEX catalog_import_match ON catalog_import_entries(import_id,collection,target_architecture,name);

-- Comparison rows are assembled privately before their final digest is sealed.
DROP TRIGGER import_reconciliation_immutable;
CREATE TRIGGER import_reconciliation_immutable BEFORE UPDATE OF candidate_import_id,baseline_import_id,report_json,report_sha256,created_by,created_at ON catalog_reconciliations
WHEN OLD.status='ready'
BEGIN SELECT RAISE(ABORT,'reconciliation reports are immutable'); END;
