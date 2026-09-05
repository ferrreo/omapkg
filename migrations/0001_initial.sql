PRAGMA foreign_keys = ON;

CREATE TABLE user (
 id TEXT PRIMARY KEY, name TEXT NOT NULL, email TEXT NOT NULL UNIQUE, emailVerified INTEGER NOT NULL DEFAULT 0,
 image TEXT, createdAt INTEGER NOT NULL, updatedAt INTEGER NOT NULL
);
CREATE TABLE session (
 id TEXT PRIMARY KEY, expiresAt INTEGER NOT NULL, token TEXT NOT NULL UNIQUE,
 createdAt INTEGER NOT NULL, updatedAt INTEGER NOT NULL, ipAddress TEXT, userAgent TEXT,
 userId TEXT NOT NULL REFERENCES user(id) ON DELETE CASCADE
);
CREATE INDEX session_user ON session(userId);
CREATE TABLE account (
 id TEXT PRIMARY KEY, accountId TEXT NOT NULL, providerId TEXT NOT NULL, userId TEXT NOT NULL REFERENCES user(id) ON DELETE CASCADE,
 accessToken TEXT, refreshToken TEXT, idToken TEXT, accessTokenExpiresAt INTEGER,
 refreshTokenExpiresAt INTEGER, scope TEXT, password TEXT, createdAt INTEGER NOT NULL, updatedAt INTEGER NOT NULL,
 UNIQUE(providerId, accountId)
);
CREATE INDEX account_user ON account(userId);
CREATE TABLE verification (id TEXT PRIMARY KEY, identifier TEXT NOT NULL, value TEXT NOT NULL, expiresAt INTEGER NOT NULL, createdAt INTEGER NOT NULL, updatedAt INTEGER NOT NULL);
CREATE INDEX verification_identifier ON verification(identifier);

CREATE TABLE maintainer_areas (github_id TEXT NOT NULL, area TEXT NOT NULL, PRIMARY KEY(github_id, area));
CREATE TABLE requests (
 id TEXT PRIMARY KEY, name TEXT NOT NULL, upstream_url TEXT NOT NULL, source_kind TEXT NOT NULL CHECK(source_kind IN ('git','archive')),
 area TEXT NOT NULL CHECK(area IN ('desktop','development','gaming','multimedia','productivity','system')),
 requested_by TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','generating','review','queued','building','built','failed','rejected')),
 created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, rejection_reason TEXT
);
CREATE INDEX requests_queue ON requests(status, area, created_at);
CREATE UNIQUE INDEX requests_active_name ON requests(name) WHERE status NOT IN ('built','rejected','failed');
CREATE TABLE revisions (
 id TEXT PRIMARY KEY, request_id TEXT NOT NULL REFERENCES requests(id), version TEXT NOT NULL,
 recipe TEXT NOT NULL, recipe_sha256 TEXT NOT NULL, manifest_sha256 TEXT NOT NULL UNIQUE,
 sources_json TEXT NOT NULL CHECK(json_valid(sources_json)), dependencies_json TEXT NOT NULL CHECK(json_valid(dependencies_json)),
 smoke_commands_json TEXT NOT NULL CHECK(json_valid(smoke_commands_json)), architectures_json TEXT NOT NULL CHECK(json_valid(architectures_json)),
 source_date_epoch INTEGER NOT NULL, image_digest TEXT NOT NULL, license TEXT NOT NULL,
 surface TEXT NOT NULL CHECK(surface IN ('binary','recipe')), explanation TEXT NOT NULL, sbom_json TEXT NOT NULL CHECK(json_valid(sbom_json)),
 lint_json TEXT NOT NULL CHECK(json_valid(lint_json)), upstream_commit TEXT, pr_url TEXT, commit_sha TEXT, created_at INTEGER NOT NULL
);
CREATE TRIGGER revision_immutable_update BEFORE UPDATE ON revisions BEGIN SELECT RAISE(ABORT,'revisions are immutable'); END;
CREATE TRIGGER revision_immutable_delete BEFORE DELETE ON revisions BEGIN SELECT RAISE(ABORT,'revisions are immutable'); END;
CREATE TABLE approvals (
 id TEXT PRIMARY KEY, revision_id TEXT NOT NULL REFERENCES revisions(id), actor TEXT NOT NULL,
 kind TEXT NOT NULL CHECK(kind IN ('area','security')), manifest_sha256 TEXT NOT NULL, created_at INTEGER NOT NULL,
 UNIQUE(revision_id, kind)
);
CREATE TABLE builds (
 id TEXT PRIMARY KEY, revision_id TEXT NOT NULL REFERENCES revisions(id), architecture TEXT NOT NULL CHECK(architecture IN ('x86_64','aarch64')),
 status TEXT NOT NULL CHECK(status IN ('queued','leased','succeeded','failed','cancelled')), worker_id TEXT REFERENCES workers(id),
 lease_token TEXT, lease_expires_at INTEGER, attempt INTEGER NOT NULL DEFAULT 0,
 artifact_key TEXT, artifact_sha256 TEXT, artifact_size INTEGER, artifact_filename TEXT,
 provenance TEXT, provenance_signature TEXT, smoke_passed INTEGER NOT NULL DEFAULT 0,
 error TEXT, created_at INTEGER NOT NULL, started_at INTEGER, finished_at INTEGER,
 UNIQUE(revision_id, architecture)
);
CREATE INDEX build_queue ON builds(status, architecture, created_at);
CREATE TABLE workers (
 id TEXT PRIMARY KEY, name TEXT NOT NULL, architecture TEXT NOT NULL CHECK(architecture IN ('x86_64','aarch64')),
 public_key TEXT NOT NULL UNIQUE, status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','revoked')),
 enrolled_at INTEGER NOT NULL, last_seen_at INTEGER
);
CREATE TABLE enrollment_tokens (
 token_hash TEXT PRIMARY KEY, architecture TEXT NOT NULL CHECK(architecture IN ('x86_64','aarch64')),
 created_by TEXT NOT NULL, expires_at INTEGER NOT NULL, used_at INTEGER, worker_id TEXT
);
CREATE TABLE worker_nonces (worker_id TEXT NOT NULL REFERENCES workers(id), nonce TEXT NOT NULL, created_at INTEGER NOT NULL, PRIMARY KEY(worker_id, nonce));
CREATE INDEX nonce_expiry ON worker_nonces(created_at);
CREATE TABLE build_logs (build_id TEXT NOT NULL REFERENCES builds(id), attempt INTEGER NOT NULL, sequence INTEGER NOT NULL, text TEXT NOT NULL, created_at INTEGER NOT NULL, PRIMARY KEY(build_id, attempt, sequence));
CREATE TABLE audit_events (id INTEGER PRIMARY KEY AUTOINCREMENT, actor TEXT NOT NULL, action TEXT NOT NULL, target TEXT NOT NULL, detail TEXT NOT NULL CHECK(json_valid(detail)), created_at INTEGER NOT NULL);
CREATE INDEX audit_target ON audit_events(target, id);
CREATE TRIGGER audit_no_update BEFORE UPDATE ON audit_events BEGIN SELECT RAISE(ABORT,'audit log is append only'); END;
CREATE TRIGGER audit_no_delete BEFORE DELETE ON audit_events BEGIN SELECT RAISE(ABORT,'audit log is append only'); END;
CREATE TABLE releases (
 id TEXT PRIMARY KEY, build_id TEXT NOT NULL UNIQUE REFERENCES builds(id), name TEXT NOT NULL, version TEXT NOT NULL,
 architecture TEXT NOT NULL CHECK(architecture IN ('x86_64','aarch64')), surface TEXT NOT NULL CHECK(surface IN ('binary','recipe')),
 channel TEXT NOT NULL CHECK(channel IN ('dev','stable','withdrawn')), artifact_key TEXT, signature_key TEXT,
 recipe_key TEXT NOT NULL, sbom_key TEXT NOT NULL, provenance_key TEXT NOT NULL, published_at INTEGER NOT NULL,
 stable_at INTEGER, batch_id TEXT, previous_release_id TEXT REFERENCES releases(id),
 CHECK(surface='recipe' OR (artifact_key IS NOT NULL AND signature_key IS NOT NULL))
);
CREATE INDEX releases_catalog ON releases(channel, name, architecture, published_at);
CREATE TABLE feedback (id TEXT PRIMARY KEY, release_id TEXT NOT NULL REFERENCES releases(id), actor TEXT NOT NULL, works INTEGER NOT NULL CHECK(works IN (0,1)), comment TEXT NOT NULL, created_at INTEGER NOT NULL, UNIQUE(release_id, actor));
CREATE TABLE crash_reports (id TEXT PRIMARY KEY, release_id TEXT NOT NULL REFERENCES releases(id), summary TEXT NOT NULL, consent_version TEXT NOT NULL, created_at INTEGER NOT NULL, resolved_at INTEGER, resolved_by TEXT);
CREATE TABLE promotion_batches (id TEXT PRIMARY KEY, actor TEXT NOT NULL, release_ids_json TEXT NOT NULL, reason TEXT NOT NULL, created_at INTEGER NOT NULL);
CREATE TABLE upstream_checks (request_id TEXT PRIMARY KEY REFERENCES requests(id), last_version TEXT, last_checked_at INTEGER, error TEXT);
CREATE TABLE factory_events (id INTEGER PRIMARY KEY AUTOINCREMENT, request_id TEXT NOT NULL REFERENCES requests(id), stage TEXT NOT NULL, detail TEXT NOT NULL, created_at INTEGER NOT NULL);
