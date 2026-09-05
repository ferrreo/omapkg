-- Pause dispatch without revoking active leases; archived workers remain queryable for provenance.
ALTER TABLE workers ADD COLUMN accepting_jobs INTEGER NOT NULL DEFAULT 1 CHECK(accepting_jobs IN (0,1));
ALTER TABLE workers ADD COLUMN paused_at INTEGER;
ALTER TABLE workers ADD COLUMN removed_at INTEGER;
CREATE INDEX workers_lifecycle ON workers(status, removed_at, accepting_jobs, enrolled_at);
