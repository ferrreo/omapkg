CREATE TABLE distribution_release_candidates (
  id TEXT PRIMARY KEY,
  kind TEXT NOT NULL CHECK(kind IN ('system','opr','resolved-transaction')),
  lane TEXT NOT NULL CHECK(lane IN ('system','opr','transaction')),
  release_id TEXT NOT NULL,
  sequence INTEGER NOT NULL,
  parent_digest TEXT,
  parent_sequence INTEGER,
  manifest_json TEXT NOT NULL,
  manifest_sha256 TEXT NOT NULL,
  manifest_key TEXT NOT NULL UNIQUE,
  manifest_size INTEGER NOT NULL,
  signature_key TEXT,
  signature_sha256 TEXT,
  signature_intent_id TEXT UNIQUE,
  changelog_key TEXT NOT NULL,
  changelog_sha256 TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'candidate' CHECK(status IN ('candidate','signed','active','superseded','held')),
  created_by TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  activated_at INTEGER
);
CREATE INDEX distribution_release_candidates_lane ON distribution_release_candidates(lane,status,sequence);
CREATE INDEX distribution_release_candidates_parent ON distribution_release_candidates(parent_digest);

CREATE TABLE distribution_release_objects (
  candidate_id TEXT NOT NULL REFERENCES distribution_release_candidates(id),
  kind TEXT NOT NULL CHECK(kind IN ('package-chunk','changelog')),
  digest TEXT NOT NULL,
  object_key TEXT NOT NULL,
  size INTEGER NOT NULL,
  PRIMARY KEY(candidate_id,kind,digest)
);
CREATE INDEX distribution_release_objects_digest ON distribution_release_objects(kind,digest);
CREATE TRIGGER distribution_release_object_no_update
BEFORE UPDATE ON distribution_release_objects
BEGIN SELECT RAISE(ABORT,'distribution release object mapping is immutable'); END;
CREATE TRIGGER distribution_release_object_no_delete
BEFORE DELETE ON distribution_release_objects
BEGIN SELECT RAISE(ABORT,'distribution release object mapping is immutable'); END;

CREATE TABLE distribution_release_approvals (
  id TEXT PRIMARY KEY,
  candidate_id TEXT NOT NULL REFERENCES distribution_release_candidates(id),
  manifest_sha256 TEXT NOT NULL,
  kind TEXT NOT NULL CHECK(kind IN ('release','base')),
  actor TEXT NOT NULL,
  area TEXT,
  reason TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  UNIQUE(candidate_id,manifest_sha256,kind,actor,area)
);
CREATE INDEX distribution_release_approvals_candidate ON distribution_release_approvals(candidate_id,manifest_sha256,kind);

CREATE TABLE distribution_manifest_signing_intents (
  id TEXT PRIMARY KEY,
  candidate_id TEXT NOT NULL REFERENCES distribution_release_candidates(id),
  object_key TEXT NOT NULL,
  artifact_sha256 TEXT NOT NULL,
  artifact_filename TEXT NOT NULL,
  manifest_sha256 TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','signed','failed','expired')),
  signature_key TEXT,
  signature_sha256 TEXT,
  created_at INTEGER NOT NULL,
  consumed_at INTEGER,
  expires_at INTEGER NOT NULL,
  key_fingerprint TEXT NOT NULL
);
CREATE INDEX distribution_manifest_signing_status ON distribution_manifest_signing_intents(status,expires_at,created_at);
CREATE INDEX distribution_manifest_signing_candidate ON distribution_manifest_signing_intents(candidate_id,manifest_sha256);
CREATE TRIGGER distribution_manifest_signing_inputs_immutable
BEFORE UPDATE OF candidate_id,object_key,artifact_sha256,artifact_filename,manifest_sha256,created_at,expires_at,key_fingerprint
ON distribution_manifest_signing_intents
BEGIN SELECT RAISE(ABORT,'distribution manifest signing inputs are immutable'); END;

CREATE TABLE distribution_activation_pointers (
  lane TEXT PRIMARY KEY CHECK(lane IN ('system','opr','transaction')),
  release_id TEXT,
  manifest_sha256 TEXT,
  sequence INTEGER NOT NULL DEFAULT 0,
  system_manifest_sha256 TEXT,
  opr_manifest_sha256 TEXT,
  updated_at INTEGER NOT NULL
);
INSERT INTO distribution_activation_pointers(lane,sequence,updated_at) VALUES
  ('system',0,0),('opr',0,0),('transaction',0,0);

CREATE TRIGGER distribution_release_manifest_immutable
BEFORE UPDATE OF kind,lane,release_id,sequence,parent_digest,parent_sequence,manifest_json,manifest_sha256,manifest_key,manifest_size,changelog_key,changelog_sha256,created_by,created_at
ON distribution_release_candidates
BEGIN SELECT RAISE(ABORT,'distribution release manifest is immutable'); END;
CREATE TRIGGER distribution_release_manifest_no_delete
BEFORE DELETE ON distribution_release_candidates
BEGIN SELECT RAISE(ABORT,'distribution release manifest is immutable'); END;
CREATE TRIGGER distribution_release_approval_immutable
BEFORE UPDATE ON distribution_release_approvals
BEGIN SELECT RAISE(ABORT,'distribution release approval is immutable'); END;
CREATE TRIGGER distribution_release_approval_no_delete
BEFORE DELETE ON distribution_release_approvals
BEGIN SELECT RAISE(ABORT,'distribution release approval is immutable'); END;
