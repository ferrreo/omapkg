-- Native qualification is separate from package build provenance. A worker can
-- submit observations, but only a reviewed immutable plan can define what they
-- mean and only the coordinator can bind them to a candidate.
CREATE TABLE native_qualification_plans (
  id TEXT PRIMARY KEY,
  cohort_id TEXT NOT NULL,
  revision INTEGER NOT NULL,
  operation TEXT NOT NULL CHECK(operation IN ('install','upgrade','recovery','boot','reproducibility')),
  architecture TEXT NOT NULL CHECK(architecture IN ('x86_64','aarch64')),
  candidate_sha256 TEXT NOT NULL CHECK(length(candidate_sha256)=64),
  input_sha256 TEXT NOT NULL CHECK(length(input_sha256)=64),
  artifact_sha256 TEXT NOT NULL CHECK(length(artifact_sha256)=64),
  environment_sha256 TEXT NOT NULL CHECK(length(environment_sha256)=64),
  profile_id TEXT NOT NULL,
  profile_sha256 TEXT NOT NULL CHECK(length(profile_sha256)=64),
  coverage_kind TEXT NOT NULL CHECK(coverage_kind IN ('member','system')),
  coverage_pkgbase TEXT,
  coverage_release_id TEXT,
  coverage_root_sha256 TEXT,
  coverage_sha256 TEXT NOT NULL CHECK(length(coverage_sha256)=64),
  coverage_json TEXT NOT NULL CHECK(json_valid(coverage_json)),
  plan_json TEXT NOT NULL CHECK(json_valid(plan_json)),
  plan_sha256 TEXT NOT NULL CHECK(length(plan_sha256)=64),
  created_by TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  FOREIGN KEY(cohort_id,revision) REFERENCES cohort_revisions(cohort_id,revision),
  UNIQUE(cohort_id,revision,operation,architecture,plan_sha256)
  ,CHECK((coverage_kind='member')=(coverage_pkgbase IS NOT NULL)),
  CHECK((coverage_kind='system')=(coverage_root_sha256 IS NOT NULL)),
  CHECK(coverage_release_id IS NOT NULL),
  CHECK(coverage_root_sha256 IS NULL OR length(coverage_root_sha256)=64)
);
CREATE INDEX native_qualification_plan_scope ON native_qualification_plans(cohort_id,revision,operation,architecture,created_at);
CREATE TRIGGER native_qualification_plan_no_update BEFORE UPDATE ON native_qualification_plans
BEGIN SELECT RAISE(ABORT,'qualification plans are immutable'); END;
CREATE TRIGGER native_qualification_plan_no_delete BEFORE DELETE ON native_qualification_plans
BEGIN SELECT RAISE(ABORT,'qualification plans are immutable'); END;

CREATE TABLE native_qualification_plan_reviews (
  plan_id TEXT NOT NULL REFERENCES native_qualification_plans(id),
  kind TEXT NOT NULL CHECK(kind IN ('area','security')),
  actor TEXT NOT NULL,
  reason TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  PRIMARY KEY(plan_id,kind),
  UNIQUE(plan_id,actor)
);
CREATE TRIGGER native_qualification_plan_review_no_update BEFORE UPDATE ON native_qualification_plan_reviews
BEGIN SELECT RAISE(ABORT,'qualification plan reviews are append-only'); END;
CREATE TRIGGER native_qualification_plan_review_no_delete BEFORE DELETE ON native_qualification_plan_reviews
BEGIN SELECT RAISE(ABORT,'qualification plan review history is immutable'); END;

CREATE TABLE native_qualification_evidence (
  id TEXT PRIMARY KEY,
  plan_id TEXT NOT NULL REFERENCES native_qualification_plans(id),
  cohort_id TEXT NOT NULL,
  revision INTEGER NOT NULL,
  operation TEXT NOT NULL CHECK(operation IN ('install','upgrade','recovery','boot','reproducibility')),
  architecture TEXT NOT NULL CHECK(architecture IN ('x86_64','aarch64')),
  candidate_sha256 TEXT NOT NULL CHECK(length(candidate_sha256)=64),
  input_sha256 TEXT NOT NULL CHECK(length(input_sha256)=64),
  artifact_sha256 TEXT NOT NULL CHECK(length(artifact_sha256)=64),
  environment_sha256 TEXT NOT NULL CHECK(length(environment_sha256)=64),
  profile_id TEXT NOT NULL,
  profile_sha256 TEXT NOT NULL CHECK(length(profile_sha256)=64),
  coverage_kind TEXT NOT NULL CHECK(coverage_kind IN ('member','system')),
  coverage_pkgbase TEXT,
  coverage_release_id TEXT,
  coverage_root_sha256 TEXT,
  coverage_sha256 TEXT NOT NULL CHECK(length(coverage_sha256)=64),
  coverage_json TEXT NOT NULL CHECK(json_valid(coverage_json)),
  observed_sha256 TEXT NOT NULL CHECK(length(observed_sha256)=64),
  status TEXT NOT NULL CHECK(status IN ('passed','failed','not-checked')),
  reproducibility_status TEXT CHECK(reproducibility_status IS NULL OR reproducibility_status IN ('verified-reproducible','mismatch','not-checked')),
  worker_id TEXT NOT NULL REFERENCES workers(id),
  worker_public_key TEXT NOT NULL,
  report_json TEXT NOT NULL CHECK(json_valid(report_json)),
  report_sha256 TEXT NOT NULL CHECK(length(report_sha256)=64),
  signature TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  FOREIGN KEY(cohort_id,revision) REFERENCES cohort_revisions(cohort_id,revision),
  CHECK((operation='reproducibility')=(reproducibility_status IS NOT NULL)),
  CHECK((coverage_kind='member')=(coverage_pkgbase IS NOT NULL)),
  CHECK((coverage_kind='system')=(coverage_root_sha256 IS NOT NULL)),
  CHECK(coverage_release_id IS NOT NULL),
  CHECK(coverage_root_sha256 IS NULL OR length(coverage_root_sha256)=64),
  UNIQUE(plan_id,worker_id,report_sha256)
);
CREATE INDEX native_qualification_current ON native_qualification_evidence(cohort_id,revision,operation,architecture,created_at);
CREATE TRIGGER native_qualification_evidence_no_update BEFORE UPDATE ON native_qualification_evidence
BEGIN SELECT RAISE(ABORT,'qualification evidence is immutable'); END;
CREATE TRIGGER native_qualification_evidence_no_delete BEFORE DELETE ON native_qualification_evidence
BEGIN SELECT RAISE(ABORT,'qualification evidence is immutable'); END;

-- Exceptions never alter a worker report. They are scoped to one immutable
-- report and expire, so a future candidate cannot inherit one by accident.
CREATE TABLE native_qualification_exceptions (
  id TEXT PRIMARY KEY,
  evidence_id TEXT NOT NULL REFERENCES native_qualification_evidence(id),
  cohort_id TEXT NOT NULL,
  revision INTEGER NOT NULL,
  operation TEXT NOT NULL CHECK(operation IN ('install','upgrade','recovery','boot','reproducibility')),
  architecture TEXT NOT NULL CHECK(architecture IN ('x86_64','aarch64')),
  candidate_sha256 TEXT NOT NULL CHECK(length(candidate_sha256)=64),
  subject_sha256 TEXT NOT NULL CHECK(length(subject_sha256)=64),
  reason TEXT NOT NULL,
  actor TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL CHECK(expires_at>created_at),
  FOREIGN KEY(cohort_id,revision) REFERENCES cohort_revisions(cohort_id,revision),
  UNIQUE(evidence_id,subject_sha256)
);
CREATE INDEX native_qualification_exception_scope ON native_qualification_exceptions(cohort_id,operation,architecture,expires_at);
CREATE TRIGGER native_qualification_exception_no_update BEFORE UPDATE ON native_qualification_exceptions
BEGIN SELECT RAISE(ABORT,'qualification exceptions are immutable'); END;
CREATE TRIGGER native_qualification_exception_no_delete BEFORE DELETE ON native_qualification_exceptions
BEGIN SELECT RAISE(ABORT,'qualification exceptions are immutable'); END;

-- Keep paged cohort verification stale when qualification scope changes.
CREATE TRIGGER native_qualification_plan_epoch AFTER INSERT ON native_qualification_plans
BEGIN UPDATE cohort_scope_epochs SET version=version+1 WHERE cohort_id=NEW.cohort_id; END;
CREATE TRIGGER native_qualification_review_epoch AFTER INSERT ON native_qualification_plan_reviews
BEGIN UPDATE cohort_scope_epochs SET version=version+1 WHERE cohort_id=(SELECT cohort_id FROM native_qualification_plans WHERE id=NEW.plan_id); END;
CREATE TRIGGER native_qualification_evidence_epoch AFTER INSERT ON native_qualification_evidence
BEGIN UPDATE cohort_scope_epochs SET version=version+1 WHERE cohort_id=NEW.cohort_id; END;
CREATE TRIGGER native_qualification_exception_epoch AFTER INSERT ON native_qualification_exceptions
BEGIN UPDATE cohort_scope_epochs SET version=version+1 WHERE cohort_id=(SELECT cohort_id FROM native_qualification_evidence WHERE id=NEW.evidence_id); END;
