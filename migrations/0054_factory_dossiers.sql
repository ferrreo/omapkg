
-- Immutable content-addressed package dossier exports.
CREATE TABLE factory_dossiers (
 id TEXT PRIMARY KEY,
 request_id TEXT NOT NULL REFERENCES requests(id),
 revision_id TEXT NOT NULL REFERENCES revisions(id),
 run_id TEXT NOT NULL,
 canonical_json TEXT NOT NULL CHECK(json_valid(canonical_json)),
 canonical_sha256 TEXT NOT NULL CHECK(length(canonical_sha256)=64),
 markdown TEXT NOT NULL,
 markdown_sha256 TEXT NOT NULL CHECK(length(markdown_sha256)=64),
 created_by TEXT NOT NULL,
 created_at INTEGER NOT NULL,
 UNIQUE(request_id,revision_id,run_id,canonical_sha256)
);
CREATE INDEX factory_dossiers_request ON factory_dossiers(request_id,created_at DESC);
CREATE INDEX factory_dossiers_revision ON factory_dossiers(revision_id,created_at DESC);
CREATE TRIGGER factory_dossiers_no_update BEFORE UPDATE ON factory_dossiers
BEGIN SELECT RAISE(ABORT,'factory dossiers are immutable'); END;
CREATE TRIGGER factory_dossiers_no_delete BEFORE DELETE ON factory_dossiers
BEGIN SELECT RAISE(ABORT,'factory dossiers are retained evidence'); END;

-- Aggregate dossiers retain complete cohort/image membership and failed members.
CREATE TABLE factory_aggregate_dossiers (
 id TEXT PRIMARY KEY,
 target_kind TEXT NOT NULL CHECK(target_kind IN ('cohort','image')),
 target_id TEXT NOT NULL,
 run_id TEXT NOT NULL,
 canonical_json TEXT NOT NULL CHECK(json_valid(canonical_json)),
 canonical_sha256 TEXT NOT NULL CHECK(length(canonical_sha256)=64),
 markdown TEXT NOT NULL,
 markdown_sha256 TEXT NOT NULL CHECK(length(markdown_sha256)=64),
 created_by TEXT NOT NULL,
 created_at INTEGER NOT NULL,
 UNIQUE(target_kind,target_id,run_id,canonical_sha256)
);
CREATE INDEX factory_aggregate_dossiers_target ON factory_aggregate_dossiers(target_kind,target_id,created_at DESC);
CREATE TRIGGER factory_aggregate_dossiers_no_update BEFORE UPDATE ON factory_aggregate_dossiers
BEGIN SELECT RAISE(ABORT,'aggregate factory dossiers are immutable'); END;
CREATE TRIGGER factory_aggregate_dossiers_no_delete BEFORE DELETE ON factory_aggregate_dossiers
BEGIN SELECT RAISE(ABORT,'aggregate factory dossiers are retained evidence'); END;
