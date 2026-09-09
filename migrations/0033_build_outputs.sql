ALTER TABLE builds ADD COLUMN output_contract_json TEXT;

-- Every output belongs to one fenced attempt; retries retain old evidence.
CREATE TABLE build_artifacts (
 build_id TEXT NOT NULL REFERENCES builds(id),
 attempt INTEGER NOT NULL CHECK(attempt>0),
 filename TEXT NOT NULL,
 artifact_key TEXT NOT NULL,
 sha256 TEXT NOT NULL CHECK(length(sha256)=64),
 size INTEGER NOT NULL CHECK(size>0),
 created_at INTEGER NOT NULL,
 PRIMARY KEY(build_id,attempt,filename)
);
CREATE TRIGGER build_artifacts_no_update BEFORE UPDATE ON build_artifacts
BEGIN SELECT RAISE(ABORT,'build artifacts are immutable'); END;
CREATE TRIGGER build_artifacts_no_delete BEFORE DELETE ON build_artifacts
BEGIN SELECT RAISE(ABORT,'build artifacts are immutable'); END;
CREATE TRIGGER build_output_contract_fenced BEFORE UPDATE OF output_contract_json ON builds
WHEN OLD.status='leased' AND OLD.lease_expires_at>unixepoch()
 AND NEW.status='leased' AND NEW.output_contract_json IS NOT OLD.output_contract_json
BEGIN SELECT RAISE(ABORT,'leased output contract is immutable'); END;
CREATE TRIGGER cohort_output_contract_current BEFORE UPDATE OF status,worker_id,lease_token ON builds
WHEN NEW.status='leased' AND (SELECT surface FROM revisions WHERE id=NEW.revision_id)='binary'
 AND EXISTS(SELECT 1 FROM cohort_recipe_ownership WHERE recipe_revision_id=NEW.revision_id)
 AND NOT EXISTS(SELECT 1 FROM cohort_recipe_ownership o JOIN cohorts c ON c.id=o.cohort_id
  JOIN cohort_revisions r ON r.cohort_id=c.id AND r.revision=c.current_revision
  WHERE o.recipe_revision_id=NEW.revision_id AND json_extract(NEW.output_contract_json,'$.schemaVersion')=2
   AND json_extract(NEW.output_contract_json,'$.cohort.id')=c.id
   AND json_extract(NEW.output_contract_json,'$.cohort.revision')=c.current_revision
   AND json_extract(NEW.output_contract_json,'$.cohort.manifestSha256')=r.manifest_sha256)
BEGIN SELECT RAISE(ABORT,'current cohort output contract is required'); END;

CREATE TABLE build_attempts (
 build_id TEXT NOT NULL REFERENCES builds(id),
 attempt INTEGER NOT NULL,
 revision_id TEXT NOT NULL REFERENCES revisions(id),
 architecture TEXT NOT NULL,
 worker_id TEXT NOT NULL,
 worker_public_key TEXT NOT NULL,
 started_at INTEGER NOT NULL,
 output_contract_json TEXT,
 dependency_plan_json TEXT,
 PRIMARY KEY(build_id,attempt)
);
CREATE TABLE build_attempt_results (
 build_id TEXT NOT NULL,
 attempt INTEGER NOT NULL,
 status TEXT NOT NULL CHECK(status IN ('succeeded','failed')),
 provenance TEXT,
 provenance_signature TEXT,
 installed_size INTEGER,
 artifact_key TEXT,
 artifact_sha256 TEXT,
 artifact_filename TEXT,
 artifact_size INTEGER,
 error TEXT,
 finished_at INTEGER NOT NULL,
 PRIMARY KEY(build_id,attempt),
 FOREIGN KEY(build_id,attempt) REFERENCES build_attempts(build_id,attempt)
);
CREATE TRIGGER build_attempt_start AFTER UPDATE ON builds
WHEN NEW.status='leased' AND NEW.attempt>OLD.attempt
BEGIN
 INSERT INTO build_attempts(build_id,attempt,revision_id,architecture,worker_id,worker_public_key,started_at,output_contract_json,dependency_plan_json)
 SELECT NEW.id,NEW.attempt,NEW.revision_id,NEW.architecture,NEW.worker_id,w.public_key,NEW.started_at,NEW.output_contract_json,NEW.dependency_plan_json
 FROM workers w WHERE w.id=NEW.worker_id;
END;
CREATE TRIGGER build_attempt_finish AFTER UPDATE ON builds
WHEN NEW.status IN ('succeeded','failed') AND OLD.status='leased'
 AND EXISTS(SELECT 1 FROM build_attempts WHERE build_id=NEW.id AND attempt=NEW.attempt)
BEGIN
 INSERT INTO build_attempt_results(build_id,attempt,status,provenance,provenance_signature,installed_size,artifact_key,artifact_sha256,artifact_filename,artifact_size,error,finished_at)
 VALUES(NEW.id,NEW.attempt,NEW.status,NEW.provenance,NEW.provenance_signature,NEW.installed_size,NEW.artifact_key,NEW.artifact_sha256,NEW.artifact_filename,NEW.artifact_size,NEW.error,NEW.finished_at);
END;
CREATE TRIGGER build_attempts_no_update BEFORE UPDATE ON build_attempts BEGIN SELECT RAISE(ABORT,'build attempts are immutable'); END;
CREATE TRIGGER build_attempts_no_delete BEFORE DELETE ON build_attempts BEGIN SELECT RAISE(ABORT,'build attempts are immutable'); END;
CREATE TRIGGER build_attempt_results_no_update BEFORE UPDATE ON build_attempt_results BEGIN SELECT RAISE(ABORT,'build attempt results are immutable'); END;
CREATE TRIGGER build_attempt_results_no_delete BEFORE DELETE ON build_attempt_results BEGIN SELECT RAISE(ABORT,'build attempt results are immutable'); END;
