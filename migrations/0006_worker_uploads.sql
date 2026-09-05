-- Multipart package uploads. Parts are private until their complete operation
-- verifies the assembled object against the worker-declared digest.
CREATE TABLE worker_uploads (
 id TEXT PRIMARY KEY,
 build_id TEXT NOT NULL REFERENCES builds(id) ON DELETE CASCADE,
 worker_id TEXT NOT NULL REFERENCES workers(id),
 attempt INTEGER NOT NULL,
 lease_token TEXT NOT NULL,
 filename TEXT NOT NULL,
 object_key TEXT NOT NULL UNIQUE,
 r2_upload_id TEXT NOT NULL,
 expected_size INTEGER NOT NULL CHECK(expected_size > 0 AND expected_size <= 4294967296),
 expected_sha256 TEXT NOT NULL CHECK(length(expected_sha256) = 64),
 status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','completed','aborted','failed')),
 actual_size INTEGER,
 actual_sha256 TEXT,
 created_at INTEGER NOT NULL,
 completed_at INTEGER
);
CREATE UNIQUE INDEX worker_uploads_active_build ON worker_uploads(build_id) WHERE status = 'active';
CREATE INDEX worker_uploads_worker ON worker_uploads(worker_id, status, created_at);

CREATE TABLE worker_upload_parts (
 upload_id TEXT NOT NULL REFERENCES worker_uploads(id) ON DELETE CASCADE,
 part_number INTEGER NOT NULL CHECK(part_number > 0 AND part_number <= 512),
 sha256 TEXT NOT NULL CHECK(length(sha256) = 64),
 size INTEGER NOT NULL CHECK(size > 0 AND size <= 8388608),
 etag TEXT NOT NULL,
 created_at INTEGER NOT NULL,
 PRIMARY KEY(upload_id, part_number)
);
CREATE INDEX worker_upload_parts_order ON worker_upload_parts(upload_id, part_number);
