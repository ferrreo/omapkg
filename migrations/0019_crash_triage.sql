ALTER TABLE crash_reports ADD COLUMN confirmed_at INTEGER;
ALTER TABLE crash_reports ADD COLUMN confirmed_by TEXT;
CREATE TABLE crash_quarantines (
  release_id TEXT PRIMARY KEY REFERENCES releases(id),
  status TEXT NOT NULL CHECK(status IN ('queued','processing','failed','completed')),
  attempts INTEGER NOT NULL DEFAULT 0,
  next_attempt_at INTEGER NOT NULL,
  lease_expires_at INTEGER,
  last_error TEXT,
  updated_at INTEGER NOT NULL
);
