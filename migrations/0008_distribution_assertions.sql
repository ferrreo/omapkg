-- Add compare-and-swap assertions without changing already-applied migrations.
CREATE TABLE IF NOT EXISTS distribution_assertions (
 expected INTEGER NOT NULL,
 actual INTEGER NOT NULL,
 CHECK(expected=actual)
);
