ALTER TABLE cohort_members ADD COLUMN ordinal INTEGER;
ALTER TABLE cohort_members ADD COLUMN chunk_index INTEGER;
CREATE UNIQUE INDEX cohort_member_ordinal ON cohort_members(cohort_id,revision,ordinal) WHERE ordinal IS NOT NULL;

CREATE TABLE cohort_scope_uploads (
 id TEXT PRIMARY KEY,
 cohort_id TEXT NOT NULL,
 expected_revision INTEGER,
 base_sha256 TEXT,
 metadata_json TEXT NOT NULL CHECK(json_valid(metadata_json)),
 expected_count INTEGER NOT NULL CHECK(expected_count BETWEEN 1 AND 100000),
 next_chunk INTEGER NOT NULL DEFAULT 0,
 member_count INTEGER NOT NULL DEFAULT 0,
 last_pkgbase TEXT NOT NULL DEFAULT '',
 sealed_revision INTEGER,
 created_by TEXT NOT NULL,
 created_at INTEGER NOT NULL
);
CREATE TABLE cohort_scope_chunks (
 upload_id TEXT NOT NULL REFERENCES cohort_scope_uploads(id),
 chunk_index INTEGER NOT NULL,
 start INTEGER NOT NULL,
 member_count INTEGER NOT NULL CHECK(member_count BETWEEN 1 AND 100),
 first_pkgbase TEXT NOT NULL,
 last_pkgbase TEXT NOT NULL,
 members_json TEXT NOT NULL CHECK(json_valid(members_json)),
 sha256 TEXT NOT NULL,
 PRIMARY KEY(upload_id,chunk_index)
);
CREATE TABLE cohort_scope_entries (
 upload_id TEXT NOT NULL,
 chunk_index INTEGER NOT NULL,
 ordinal INTEGER NOT NULL,
 pkgbase TEXT NOT NULL,
 catalog_revision INTEGER NOT NULL,
 recipe_revision_id TEXT,
 member_json TEXT NOT NULL CHECK(json_valid(member_json)),
 PRIMARY KEY(upload_id,pkgbase),
 UNIQUE(upload_id,ordinal),
 FOREIGN KEY(upload_id,chunk_index) REFERENCES cohort_scope_chunks(upload_id,chunk_index)
);
CREATE TABLE cohort_revision_chunks (
 cohort_id TEXT NOT NULL,
 revision INTEGER NOT NULL,
 chunk_index INTEGER NOT NULL,
 members_json TEXT NOT NULL CHECK(json_valid(members_json)),
 sha256 TEXT NOT NULL,
 PRIMARY KEY(cohort_id,revision,chunk_index),
 FOREIGN KEY(cohort_id,revision) REFERENCES cohort_revisions(cohort_id,revision)
);
CREATE UNIQUE INDEX cohort_scope_request ON cohort_scope_entries(upload_id,json_extract(member_json,'$.recipe.requestId')) WHERE recipe_revision_id IS NOT NULL;
CREATE TRIGGER cohort_scope_upload_header BEFORE UPDATE ON cohort_scope_uploads WHEN
 NEW.id IS NOT OLD.id OR NEW.cohort_id IS NOT OLD.cohort_id OR NEW.expected_revision IS NOT OLD.expected_revision OR NEW.base_sha256 IS NOT OLD.base_sha256
 OR NEW.metadata_json IS NOT OLD.metadata_json OR NEW.expected_count IS NOT OLD.expected_count OR NEW.created_by IS NOT OLD.created_by
 OR NEW.created_at IS NOT OLD.created_at OR OLD.sealed_revision IS NOT NULL
 BEGIN SELECT RAISE(ABORT,'cohort scope upload header is immutable'); END;
CREATE TRIGGER cohort_scope_chunk_open BEFORE INSERT ON cohort_scope_chunks
 WHEN (SELECT sealed_revision FROM cohort_scope_uploads WHERE id=NEW.upload_id) IS NOT NULL
 BEGIN SELECT RAISE(ABORT,'cohort scope is already sealed'); END;
CREATE TRIGGER cohort_scope_entry_open BEFORE INSERT ON cohort_scope_entries
 WHEN (SELECT sealed_revision FROM cohort_scope_uploads WHERE id=NEW.upload_id) IS NOT NULL
 BEGIN SELECT RAISE(ABORT,'cohort scope is already sealed'); END;
CREATE TRIGGER cohort_scope_chunk_no_update BEFORE UPDATE ON cohort_scope_chunks BEGIN SELECT RAISE(ABORT,'cohort scope chunks are immutable'); END;
CREATE TRIGGER cohort_scope_chunk_no_delete BEFORE DELETE ON cohort_scope_chunks BEGIN SELECT RAISE(ABORT,'cohort scope chunks are immutable'); END;
CREATE TRIGGER cohort_scope_entry_no_update BEFORE UPDATE ON cohort_scope_entries BEGIN SELECT RAISE(ABORT,'cohort scope entries are immutable'); END;
CREATE TRIGGER cohort_scope_entry_no_delete BEFORE DELETE ON cohort_scope_entries BEGIN SELECT RAISE(ABORT,'cohort scope entries are immutable'); END;
CREATE TRIGGER cohort_revision_chunk_no_update BEFORE UPDATE ON cohort_revision_chunks BEGIN SELECT RAISE(ABORT,'cohort revision chunks are immutable'); END;
CREATE TRIGGER cohort_revision_chunk_no_delete BEFORE DELETE ON cohort_revision_chunks BEGIN SELECT RAISE(ABORT,'cohort revision chunks are immutable'); END;
