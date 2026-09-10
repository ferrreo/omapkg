-- A factory run owns one bounded private build unit.  Requests, preserved
-- imports, cohorts and images use the same tables without sharing their
-- lifecycle columns or release approvals.
CREATE TABLE factory_runs (
  id TEXT PRIMARY KEY,
  target_kind TEXT NOT NULL,
  target_id TEXT NOT NULL,
  unit_key TEXT NOT NULL,
  execution_scope TEXT NOT NULL DEFAULT 'private' CHECK(execution_scope='private'),
  status TEXT NOT NULL DEFAULT 'queued' CHECK(status IN ('queued','running','succeeded','needs-human-intervention','cancelled')),
  max_attempts INTEGER NOT NULL DEFAULT 3 CHECK(max_attempts=3),
  attempt_count INTEGER NOT NULL DEFAULT 0 CHECK(attempt_count BETWEEN 0 AND 3),
  current_attempt INTEGER,
  successful_attempt INTEGER,
  source_run_id TEXT REFERENCES factory_runs(id),
  requested_revision_id TEXT,
  policy_json TEXT NOT NULL CHECK(json_valid(policy_json)),
  artifact_json TEXT CHECK(artifact_json IS NULL OR json_valid(artifact_json)),
  failure_json TEXT CHECK(failure_json IS NULL OR json_valid(failure_json)),
  lease_token TEXT,
  lease_expires_at INTEGER,
  created_by TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE UNIQUE INDEX factory_runs_active_unit
  ON factory_runs(target_kind,target_id,unit_key)
  WHERE status IN ('queued','running');
CREATE INDEX factory_runs_target ON factory_runs(target_kind,target_id,created_at);
CREATE INDEX factory_runs_status ON factory_runs(status,updated_at);
CREATE TRIGGER factory_runs_no_delete BEFORE DELETE ON factory_runs
BEGIN SELECT RAISE(ABORT,'factory runs are retained evidence'); END;

CREATE TABLE factory_run_attempts (
  id TEXT PRIMARY KEY,
  run_id TEXT NOT NULL REFERENCES factory_runs(id),
  attempt INTEGER NOT NULL CHECK(attempt BETWEEN 1 AND 3),
  reservation_key TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('running','succeeded','failed')),
  candidate_revision_id TEXT,
  candidate_sha256 TEXT NOT NULL CHECK(length(candidate_sha256)=64),
  input_sha256 TEXT NOT NULL CHECK(length(input_sha256)=64),
  architecture TEXT,
  candidate_json TEXT NOT NULL CHECK(json_valid(candidate_json)),
  failure_kind TEXT CHECK(failure_kind IS NULL OR failure_kind IN ('build','validation','dependency','analysis','runtime','reproducibility','policy','infrastructure')),
  failure_json TEXT CHECK(failure_json IS NULL OR json_valid(failure_json)),
  artifact_json TEXT CHECK(artifact_json IS NULL OR json_valid(artifact_json)),
  lease_token TEXT NOT NULL,
  lease_expires_at INTEGER NOT NULL,
  started_at INTEGER NOT NULL,
  finished_at INTEGER,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  UNIQUE(run_id,attempt),
  UNIQUE(run_id,reservation_key)
);
CREATE INDEX factory_run_attempts_status ON factory_run_attempts(run_id,status,attempt);
CREATE INDEX factory_run_attempts_candidate ON factory_run_attempts(candidate_revision_id);

-- Candidate and input identity are immutable.  Only lifecycle/evidence fields
-- may change after reservation, so a callback cannot mix attempts.
CREATE TRIGGER factory_run_attempt_identity_immutable BEFORE UPDATE ON factory_run_attempts
WHEN NEW.id IS NOT OLD.id OR NEW.run_id IS NOT OLD.run_id OR NEW.attempt IS NOT OLD.attempt OR
 NEW.reservation_key IS NOT OLD.reservation_key OR NEW.candidate_revision_id IS NOT OLD.candidate_revision_id OR
 NEW.candidate_sha256 IS NOT OLD.candidate_sha256 OR NEW.input_sha256 IS NOT OLD.input_sha256 OR
 NEW.architecture IS NOT OLD.architecture OR NEW.candidate_json IS NOT OLD.candidate_json OR NEW.created_at IS NOT OLD.created_at
BEGIN SELECT RAISE(ABORT,'factory attempt identity is immutable'); END;
CREATE TRIGGER factory_run_attempt_no_delete BEFORE DELETE ON factory_run_attempts
BEGIN SELECT RAISE(ABORT,'factory attempts are immutable'); END;
CREATE TRIGGER factory_run_attempt_terminal_immutable BEFORE UPDATE ON factory_run_attempts
WHEN OLD.status IN ('succeeded','failed') AND NEW.status IS NOT OLD.status
BEGIN SELECT RAISE(ABORT,'completed factory attempts are immutable'); END;

CREATE TRIGGER factory_run_budget_immutable BEFORE UPDATE OF max_attempts ON factory_runs
WHEN NEW.max_attempts IS NOT OLD.max_attempts
BEGIN SELECT RAISE(ABORT,'factory retry budget is immutable'); END;
CREATE TRIGGER factory_run_attempt_count_monotonic BEFORE UPDATE OF attempt_count ON factory_runs
WHEN NEW.attempt_count < OLD.attempt_count OR NEW.attempt_count > NEW.max_attempts
BEGIN SELECT RAISE(ABORT,'factory retry budget cannot reset'); END;
CREATE TRIGGER factory_run_terminal_status_immutable BEFORE UPDATE OF status ON factory_runs
WHEN OLD.status IN ('succeeded','needs-human-intervention','cancelled') AND NEW.status IS NOT OLD.status
BEGIN SELECT RAISE(ABORT,'completed factory runs are immutable'); END;
CREATE TRIGGER factory_run_identity_immutable BEFORE UPDATE ON factory_runs
WHEN NEW.id IS NOT OLD.id OR NEW.target_kind IS NOT OLD.target_kind OR NEW.target_id IS NOT OLD.target_id OR
 NEW.unit_key IS NOT OLD.unit_key OR NEW.execution_scope IS NOT OLD.execution_scope OR NEW.max_attempts IS NOT OLD.max_attempts OR
 NEW.source_run_id IS NOT OLD.source_run_id OR NEW.requested_revision_id IS NOT OLD.requested_revision_id OR
 NEW.policy_json IS NOT OLD.policy_json OR NEW.created_by IS NOT OLD.created_by OR NEW.created_at IS NOT OLD.created_at
BEGIN SELECT RAISE(ABORT,'factory run identity is immutable'); END;
CREATE TRIGGER factory_run_terminal_evidence_immutable BEFORE UPDATE ON factory_runs
WHEN OLD.status IN ('succeeded','needs-human-intervention','cancelled') AND (
 NEW.attempt_count IS NOT OLD.attempt_count OR NEW.current_attempt IS NOT OLD.current_attempt OR
 NEW.successful_attempt IS NOT OLD.successful_attempt OR NEW.artifact_json IS NOT OLD.artifact_json OR
 NEW.failure_json IS NOT OLD.failure_json OR NEW.lease_token IS NOT OLD.lease_token OR
 NEW.lease_expires_at IS NOT OLD.lease_expires_at OR NEW.updated_at IS NOT OLD.updated_at)
BEGIN SELECT RAISE(ABORT,'completed factory run evidence is immutable'); END;

-- Private factory candidates use the existing native worker queue and output
-- protocol.  These flags are cleared only after exact revision approvals so a
-- candidate artifact cannot enter publication through a private build row.
ALTER TABLE builds ADD COLUMN factory_run_id TEXT;
ALTER TABLE builds ADD COLUMN factory_attempt INTEGER;
ALTER TABLE builds ADD COLUMN private_candidate INTEGER NOT NULL DEFAULT 0 CHECK(private_candidate IN (0,1));
CREATE UNIQUE INDEX builds_factory_candidate_unit ON builds(factory_run_id,factory_attempt,architecture) WHERE private_candidate=1;
ALTER TABLE factory_run_attempts ADD COLUMN build_ids_json TEXT NOT NULL DEFAULT '[]' CHECK(json_valid(build_ids_json));
ALTER TABLE factory_run_attempts ADD COLUMN dispatch_id TEXT;
CREATE TRIGGER factory_run_attempt_terminal_evidence_immutable BEFORE UPDATE ON factory_run_attempts
WHEN OLD.status IN ('succeeded','failed') AND (
 NEW.failure_kind IS NOT OLD.failure_kind OR NEW.failure_json IS NOT OLD.failure_json OR NEW.artifact_json IS NOT OLD.artifact_json OR
 NEW.build_ids_json IS NOT OLD.build_ids_json OR NEW.lease_token IS NOT OLD.lease_token OR NEW.lease_expires_at IS NOT OLD.lease_expires_at OR
 NEW.dispatch_id IS NOT OLD.dispatch_id OR
 NEW.finished_at IS NOT OLD.finished_at OR NEW.updated_at IS NOT OLD.updated_at)
BEGIN SELECT RAISE(ABORT,'completed factory attempt evidence is immutable'); END;
