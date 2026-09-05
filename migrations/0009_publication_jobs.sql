CREATE TABLE IF NOT EXISTS publication_jobs (
 build_id TEXT PRIMARY KEY REFERENCES builds(id),
 status TEXT NOT NULL DEFAULT 'queued' CHECK(status IN ('queued','dispatched','completed','failed')),
 attempts INTEGER NOT NULL DEFAULT 0,
 next_attempt_at INTEGER NOT NULL,
 last_error TEXT,
 created_at INTEGER NOT NULL,
 updated_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS publication_jobs_queue ON publication_jobs(status, next_attempt_at);
