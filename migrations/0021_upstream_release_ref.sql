-- Automated release detection pins Git sources to the discovered commit.
-- The factory never falls back to a mutable branch for a pinned request.
ALTER TABLE requests ADD COLUMN upstream_ref TEXT;
