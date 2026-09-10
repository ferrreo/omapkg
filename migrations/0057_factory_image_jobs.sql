-- Private image candidates use a dedicated authenticated worker queue. They
-- are not package builds and never enter release publication tables.
CREATE TABLE factory_image_jobs (
  id TEXT PRIMARY KEY,
  run_id TEXT NOT NULL REFERENCES factory_runs(id),
  attempt INTEGER NOT NULL CHECK(attempt BETWEEN 1 AND 3),
  candidate_id TEXT NOT NULL,
  architecture TEXT NOT NULL CHECK(architecture IN ('x86_64','aarch64')),
  kind TEXT NOT NULL CHECK(kind IN ('oci','system')),
  input_sha256 TEXT NOT NULL CHECK(length(input_sha256)=64),
  candidate_json TEXT NOT NULL CHECK(json_valid(candidate_json)),
  status TEXT NOT NULL DEFAULT 'queued' CHECK(status IN ('queued','leased','succeeded','failed','cancelled')),
  worker_id TEXT REFERENCES workers(id),
  lease_token TEXT,
  lease_expires_at INTEGER,
  artifact_key TEXT,
  artifact_sha256 TEXT CHECK(artifact_sha256 IS NULL OR length(artifact_sha256)=64),
  artifact_size INTEGER CHECK(artifact_size IS NULL OR artifact_size>0),
  artifact_filename TEXT,
  evidence_json TEXT CHECK(evidence_json IS NULL OR json_valid(evidence_json)),
  evidence_sha256 TEXT CHECK(evidence_sha256 IS NULL OR length(evidence_sha256)=64),
  evidence_signature TEXT,
  error TEXT,
  created_at INTEGER NOT NULL,
  started_at INTEGER,
  finished_at INTEGER,
  UNIQUE(run_id,attempt)
);
CREATE INDEX factory_image_jobs_queue ON factory_image_jobs(status,architecture,created_at);
CREATE INDEX factory_image_jobs_worker ON factory_image_jobs(worker_id,status,created_at);
CREATE TRIGGER factory_image_job_identity_immutable BEFORE UPDATE ON factory_image_jobs
WHEN NEW.id IS NOT OLD.id OR NEW.run_id IS NOT OLD.run_id OR NEW.attempt IS NOT OLD.attempt OR
 NEW.candidate_id IS NOT OLD.candidate_id OR NEW.architecture IS NOT OLD.architecture OR NEW.kind IS NOT OLD.kind OR
 NEW.input_sha256 IS NOT OLD.input_sha256 OR NEW.candidate_json IS NOT OLD.candidate_json OR NEW.created_at IS NOT OLD.created_at
BEGIN SELECT RAISE(ABORT,'factory image job identity is immutable'); END;
CREATE TRIGGER factory_image_job_terminal_immutable BEFORE UPDATE ON factory_image_jobs
WHEN OLD.status IN ('succeeded','failed','cancelled') AND (
 NEW.status IS NOT OLD.status OR NEW.worker_id IS NOT OLD.worker_id OR NEW.lease_token IS NOT OLD.lease_token OR
 NEW.lease_expires_at IS NOT OLD.lease_expires_at OR NEW.artifact_key IS NOT OLD.artifact_key OR
 NEW.artifact_sha256 IS NOT OLD.artifact_sha256 OR NEW.artifact_size IS NOT OLD.artifact_size OR
 NEW.artifact_filename IS NOT OLD.artifact_filename OR NEW.evidence_json IS NOT OLD.evidence_json OR
 NEW.evidence_sha256 IS NOT OLD.evidence_sha256 OR NEW.evidence_signature IS NOT OLD.evidence_signature OR
 NEW.error IS NOT OLD.error OR NEW.finished_at IS NOT OLD.finished_at)
BEGIN SELECT RAISE(ABORT,'completed factory image job is immutable'); END;

CREATE TABLE factory_image_uploads (
  id TEXT PRIMARY KEY,
  job_id TEXT NOT NULL REFERENCES factory_image_jobs(id),
  worker_id TEXT NOT NULL REFERENCES workers(id),
  attempt INTEGER NOT NULL CHECK(attempt BETWEEN 1 AND 3),
  lease_token TEXT NOT NULL,
  filename TEXT NOT NULL,
  object_key TEXT NOT NULL UNIQUE,
  r2_upload_id TEXT NOT NULL,
  expected_size INTEGER NOT NULL CHECK(expected_size>0 AND expected_size<=4294967296),
  expected_sha256 TEXT NOT NULL CHECK(length(expected_sha256)=64),
  status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','completed','aborted','failed')),
  actual_size INTEGER,
  actual_sha256 TEXT,
  created_at INTEGER NOT NULL,
  completed_at INTEGER
);
CREATE UNIQUE INDEX factory_image_uploads_active_job ON factory_image_uploads(job_id) WHERE status='active';
CREATE INDEX factory_image_uploads_worker ON factory_image_uploads(worker_id,status,created_at);
CREATE TABLE factory_image_upload_parts (
  upload_id TEXT NOT NULL REFERENCES factory_image_uploads(id) ON DELETE CASCADE,
  part_number INTEGER NOT NULL CHECK(part_number>0 AND part_number<=512),
  sha256 TEXT NOT NULL CHECK(length(sha256)=64),
  size INTEGER NOT NULL CHECK(size>0 AND size<=8388608),
  etag TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  PRIMARY KEY(upload_id,part_number)
);
CREATE INDEX factory_image_upload_parts_order ON factory_image_upload_parts(upload_id,part_number);
