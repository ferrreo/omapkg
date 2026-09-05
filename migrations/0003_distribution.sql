CREATE TABLE signing_intents (
 id TEXT PRIMARY KEY,
 build_id TEXT NOT NULL REFERENCES builds(id),
 revision_id TEXT NOT NULL REFERENCES revisions(id),
 object_key TEXT NOT NULL,
 object_kind TEXT NOT NULL CHECK(object_kind IN ('package','database')),
 artifact_sha256 TEXT NOT NULL,
 artifact_filename TEXT NOT NULL,
 manifest_sha256 TEXT NOT NULL,
 status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','signed','failed','expired')),
 signature_key TEXT,
 signature_sha256 TEXT,
 created_at INTEGER NOT NULL,
 consumed_at INTEGER
);
CREATE INDEX signing_intents_build ON signing_intents(build_id, created_at);

CREATE TABLE repository_snapshots (
 id TEXT PRIMARY KEY,
 architecture TEXT NOT NULL CHECK(architecture IN ('x86_64','aarch64')),
 channel TEXT NOT NULL CHECK(channel IN ('dev','stable')),
 db_key TEXT NOT NULL,
 db_signature_key TEXT NOT NULL,
 batch_id TEXT,
 created_at INTEGER NOT NULL,
 active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0,1))
);
CREATE INDEX repository_snapshots_active ON repository_snapshots(channel, architecture, active, created_at);
CREATE UNIQUE INDEX repository_snapshots_one_active ON repository_snapshots(channel, architecture) WHERE active=1;

CREATE TABLE release_rollbacks (
 release_id TEXT PRIMARY KEY REFERENCES releases(id),
 previous_release_id TEXT NOT NULL REFERENCES releases(id),
 manifest_key TEXT NOT NULL,
 created_at INTEGER NOT NULL
);
