-- Retained ABI records are indexed by immutable artifact identity. Qualification
-- may stream/query this index without retaining a full catalog's symbols in a
-- worker heap. The original chunk objects remain the audit source of truth.
CREATE TABLE cohort_qualification_abi_records (
 cohort_id TEXT NOT NULL,
 revision INTEGER NOT NULL,
 architecture TEXT NOT NULL CHECK(architecture IN ('x86_64','aarch64')),
 artifact_sha256 TEXT NOT NULL CHECK(length(artifact_sha256)=64),
 inventory_sha256 TEXT NOT NULL CHECK(length(inventory_sha256)=64),
 ordinal INTEGER NOT NULL CHECK(ordinal>=0),
 record_kind TEXT NOT NULL CHECK(record_kind IN ('file','symbol')),
 path TEXT NOT NULL,
 table_name TEXT,
 symbol_index INTEGER,
 symbol_name TEXT,
 dynamic INTEGER,
 defined INTEGER,
 version TEXT,
 version_file TEXT,
 version_hidden INTEGER,
 binding TEXT,
 symbol_type TEXT,
 visibility TEXT,
 symbol_size INTEGER,
 native_kind TEXT,
 soname TEXT,
 needed_json TEXT,
 rpath_json TEXT,
 runpath_json TEXT,
 file_sha256 TEXT,
 record_json TEXT NOT NULL CHECK(json_valid(record_json)),
 PRIMARY KEY(cohort_id,revision,architecture,artifact_sha256,inventory_sha256,ordinal)
);
CREATE INDEX cohort_qualification_abi_artifact ON cohort_qualification_abi_records(cohort_id,revision,architecture,artifact_sha256,record_kind);
CREATE INDEX cohort_qualification_abi_symbol ON cohort_qualification_abi_records(cohort_id,revision,architecture,symbol_name,version,version_hidden);
CREATE INDEX cohort_qualification_abi_file ON cohort_qualification_abi_records(cohort_id,revision,architecture,path,soname);
CREATE TRIGGER cohort_qualification_abi_no_update BEFORE UPDATE ON cohort_qualification_abi_records
BEGIN SELECT RAISE(ABORT,'qualification ABI index is immutable'); END;
CREATE TRIGGER cohort_qualification_abi_no_delete BEFORE DELETE ON cohort_qualification_abi_records
BEGIN SELECT RAISE(ABORT,'qualification ABI index is immutable'); END;

CREATE TABLE cohort_qualification_abi_index_state (
 cohort_id TEXT NOT NULL,
 revision INTEGER NOT NULL,
 architecture TEXT NOT NULL CHECK(architecture IN ('x86_64','aarch64')),
 artifact_sha256 TEXT NOT NULL CHECK(length(artifact_sha256)=64),
 inventory_sha256 TEXT NOT NULL CHECK(length(inventory_sha256)=64),
 type_abi TEXT NOT NULL,
 record_count INTEGER NOT NULL CHECK(record_count>=0),
 created_at INTEGER NOT NULL,
 PRIMARY KEY(cohort_id,revision,architecture,artifact_sha256,inventory_sha256)
);
CREATE TRIGGER cohort_qualification_abi_state_no_update BEFORE UPDATE ON cohort_qualification_abi_index_state
BEGIN SELECT RAISE(ABORT,'qualification ABI index state is immutable'); END;
CREATE TRIGGER cohort_qualification_abi_state_no_delete BEFORE DELETE ON cohort_qualification_abi_index_state
BEGIN SELECT RAISE(ABORT,'qualification ABI index state is immutable'); END;

CREATE TABLE cohort_qualification_abi_progress (
 cohort_id TEXT NOT NULL,
 revision INTEGER NOT NULL,
 architecture TEXT NOT NULL CHECK(architecture IN ('x86_64','aarch64')),
 artifact_sha256 TEXT NOT NULL CHECK(length(artifact_sha256)=64),
 inventory_sha256 TEXT NOT NULL CHECK(length(inventory_sha256)=64),
 next_chunk INTEGER NOT NULL CHECK(next_chunk>=0),
 updated_at INTEGER NOT NULL,
 PRIMARY KEY(cohort_id,revision,architecture,artifact_sha256,inventory_sha256)
);
