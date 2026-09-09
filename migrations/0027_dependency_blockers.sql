PRAGMA defer_foreign_keys = ON;
CREATE TABLE requests_new (
 id TEXT PRIMARY KEY, name TEXT NOT NULL, upstream_url TEXT NOT NULL,
 source_kind TEXT NOT NULL CHECK(source_kind IN ('git','archive')),
 area TEXT NOT NULL CHECK(area IN ('desktop','development','gaming','multimedia','productivity','system')),
 requested_by TEXT NOT NULL,
 status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','generating','review','queued','building','built','failed','rejected','blocked')),
 created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, rejection_reason TEXT,
 factory_run_id TEXT, declared_license TEXT NOT NULL DEFAULT 'unknown', upstream_ref TEXT,
 description TEXT NOT NULL DEFAULT '' CHECK(length(description) <= 500)
);
INSERT INTO requests_new SELECT * FROM requests;
DROP TABLE requests;
ALTER TABLE requests_new RENAME TO requests;
CREATE INDEX requests_queue ON requests(status, area, created_at);
CREATE UNIQUE INDEX requests_active_name ON requests(name) WHERE status NOT IN ('built','rejected','failed');
CREATE INDEX requests_factory_run ON requests(factory_run_id);
CREATE TABLE migration_foreign_keys (violations INTEGER CHECK(violations=0));
INSERT INTO migration_foreign_keys SELECT COUNT(*) FROM pragma_foreign_key_check;
DROP TABLE migration_foreign_keys;
PRAGMA defer_foreign_keys = OFF;
