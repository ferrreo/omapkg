CREATE TABLE build_abi_evidence (
  build_id TEXT NOT NULL,
  attempt INTEGER NOT NULL,
  sha256 TEXT NOT NULL CHECK(length(sha256)=64),
  size INTEGER NOT NULL CHECK(size BETWEEN 1 AND 524288),
  artifact_sha256 TEXT NOT NULL CHECK(length(artifact_sha256)=64),
  kind TEXT NOT NULL CHECK(kind IN ('abi-records','abi-inventory')),
  start INTEGER NOT NULL,
  files INTEGER NOT NULL,
  symbols INTEGER NOT NULL,
  manifest_json TEXT,
  created_at INTEGER NOT NULL,
  PRIMARY KEY(build_id,attempt,sha256),
  FOREIGN KEY(build_id,attempt) REFERENCES build_attempts(build_id,attempt),
  CHECK((kind='abi-inventory')=(manifest_json IS NOT NULL))
);
CREATE TRIGGER build_abi_evidence_no_update BEFORE UPDATE ON build_abi_evidence
BEGIN SELECT RAISE(ABORT,'ABI evidence is immutable'); END;
CREATE TRIGGER build_abi_evidence_no_delete BEFORE DELETE ON build_abi_evidence
BEGIN SELECT RAISE(ABORT,'ABI evidence is immutable'); END;
