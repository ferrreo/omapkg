-- SQLite cannot extend a CHECK constraint in place. No tables reference intents.
CREATE TABLE signing_intents_new (
 id TEXT PRIMARY KEY,
 build_id TEXT NOT NULL REFERENCES builds(id),
 revision_id TEXT NOT NULL REFERENCES revisions(id),
 object_key TEXT NOT NULL,
 object_kind TEXT NOT NULL CHECK(object_kind IN ('package','database','attestation')),
 artifact_sha256 TEXT NOT NULL,
 artifact_filename TEXT NOT NULL,
 manifest_sha256 TEXT NOT NULL,
 status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','signed','failed','expired')),
 signature_key TEXT,
 signature_sha256 TEXT,
 created_at INTEGER NOT NULL,
 consumed_at INTEGER,
 expires_at INTEGER,
 artifact_size INTEGER,
 claimed_at INTEGER,
 claim_expires_at INTEGER,
 key_fingerprint TEXT
);
INSERT INTO signing_intents_new SELECT * FROM signing_intents;
DROP TABLE signing_intents;
ALTER TABLE signing_intents_new RENAME TO signing_intents;
CREATE INDEX signing_intents_build ON signing_intents(build_id, created_at);
CREATE INDEX signing_intents_claims ON signing_intents(status, claim_expires_at, created_at);

ALTER TABLE releases ADD COLUMN attestation_key TEXT;
