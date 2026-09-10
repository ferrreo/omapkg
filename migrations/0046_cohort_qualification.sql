-- Candidate dependency/ABI qualification is derived from exact package bytes and
-- retained ABI records. It is never a worker-supplied pass/fail flag.
CREATE TABLE cohort_qualification_runs (
 cohort_id TEXT NOT NULL,
 revision INTEGER NOT NULL,
 architecture TEXT NOT NULL CHECK(architecture IN ('x86_64','aarch64')),
 input_sha256 TEXT NOT NULL CHECK(length(input_sha256)=64),
 universe_sha256 TEXT NOT NULL CHECK(length(universe_sha256)=64),
 report_sha256 TEXT NOT NULL CHECK(length(report_sha256)=64),
 report_json TEXT NOT NULL CHECK(json_valid(report_json)),
 created_at INTEGER NOT NULL,
 PRIMARY KEY(cohort_id,revision,architecture,input_sha256,universe_sha256),
 FOREIGN KEY(cohort_id,revision) REFERENCES cohort_revisions(cohort_id,revision)
);
CREATE INDEX cohort_qualification_scope ON cohort_qualification_runs(cohort_id,revision,architecture,created_at);
CREATE TRIGGER cohort_qualification_no_update BEFORE UPDATE ON cohort_qualification_runs
BEGIN SELECT RAISE(ABORT,'candidate qualification is immutable'); END;
CREATE TRIGGER cohort_qualification_no_delete BEFORE DELETE ON cohort_qualification_runs
BEGIN SELECT RAISE(ABORT,'candidate qualification is immutable'); END;

-- ABI evidence belongs to one build attempt and therefore invalidates only the
-- cohort that owns that recipe. Unrelated uploads must not reset full-catalog
-- page verification.
CREATE TRIGGER cohort_epoch_build_abi_evidence_insert AFTER INSERT ON build_abi_evidence
BEGIN UPDATE cohort_scope_epochs SET version=version+1 WHERE cohort_id IN (
 SELECT o.cohort_id FROM build_attempts a JOIN cohort_recipe_ownership o ON o.recipe_revision_id=a.revision_id
 WHERE a.build_id=NEW.build_id AND a.attempt=NEW.attempt); END;
CREATE TRIGGER cohort_epoch_build_abi_evidence_update AFTER UPDATE ON build_abi_evidence
BEGIN UPDATE cohort_scope_epochs SET version=version+1 WHERE cohort_id IN (
 SELECT o.cohort_id FROM build_attempts a JOIN cohort_recipe_ownership o ON o.recipe_revision_id=a.revision_id
 WHERE a.build_id IN (OLD.build_id,NEW.build_id) AND a.attempt IN (OLD.attempt,NEW.attempt)); END;
CREATE TRIGGER cohort_epoch_build_abi_evidence_delete AFTER DELETE ON build_abi_evidence
BEGIN UPDATE cohort_scope_epochs SET version=version+1 WHERE cohort_id IN (
 SELECT o.cohort_id FROM build_attempts a JOIN cohort_recipe_ownership o ON o.recipe_revision_id=a.revision_id
 WHERE a.build_id=OLD.build_id AND a.attempt=OLD.attempt); END;
