CREATE TABLE catalog_packages (
 pkgbase TEXT PRIMARY KEY,
 current_revision INTEGER NOT NULL CHECK(current_revision > 0),
 admitted_revision INTEGER,
 created_at INTEGER NOT NULL,
 updated_at INTEGER NOT NULL
);
CREATE TABLE catalog_revisions (
 pkgbase TEXT NOT NULL REFERENCES catalog_packages(pkgbase),
 revision INTEGER NOT NULL CHECK(revision > 0),
 manifest_json TEXT NOT NULL CHECK(json_valid(manifest_json)),
 manifest_sha256 TEXT NOT NULL,
 collection TEXT NOT NULL CHECK(collection IN ('core','extra','multilib','omarchy','omapkg')),
 lane TEXT NOT NULL CHECK(lane IN ('system','opr')),
 owner_area TEXT NOT NULL,
 created_by TEXT NOT NULL,
 reason TEXT NOT NULL,
 created_at INTEGER NOT NULL,
 PRIMARY KEY(pkgbase,revision)
);
CREATE TRIGGER catalog_revision_no_update BEFORE UPDATE ON catalog_revisions BEGIN SELECT RAISE(ABORT,'catalog revisions are immutable'); END;
CREATE TRIGGER catalog_revision_no_delete BEFORE DELETE ON catalog_revisions BEGIN SELECT RAISE(ABORT,'catalog revisions are immutable'); END;
CREATE TABLE catalog_reviews (
 pkgbase TEXT NOT NULL,
 revision INTEGER NOT NULL,
 kind TEXT NOT NULL CHECK(kind IN ('area','security')),
 actor TEXT NOT NULL,
 manifest_sha256 TEXT NOT NULL,
 reason TEXT NOT NULL,
 created_at INTEGER NOT NULL,
 PRIMARY KEY(pkgbase,revision,kind),
 FOREIGN KEY(pkgbase,revision) REFERENCES catalog_revisions(pkgbase,revision)
);
CREATE TABLE catalog_outputs (
 name TEXT PRIMARY KEY,
 pkgbase TEXT NOT NULL REFERENCES catalog_packages(pkgbase)
);
CREATE INDEX catalog_revision_collection ON catalog_revisions(collection,lane,owner_area,pkgbase);
CREATE INDEX catalog_output_base ON catalog_outputs(pkgbase);

CREATE TABLE catalog_imports (
 id TEXT PRIMARY KEY,
 manifest_sha256 TEXT NOT NULL UNIQUE,
 manifest_json TEXT NOT NULL CHECK(json_valid(manifest_json)),
 expected_count INTEGER NOT NULL CHECK(expected_count >= 0),
 status TEXT NOT NULL CHECK(status IN ('capturing','captured','reconciled')),
 created_by TEXT NOT NULL,
 created_at INTEGER NOT NULL
);
CREATE TRIGGER import_manifest_immutable BEFORE UPDATE OF manifest_sha256,manifest_json,expected_count,created_by,created_at ON catalog_imports
BEGIN SELECT RAISE(ABORT,'import capture manifests are immutable'); END;
CREATE TABLE catalog_import_entries (
 import_id TEXT NOT NULL REFERENCES catalog_imports(id),
 source_id TEXT NOT NULL,
 name TEXT NOT NULL,
 architecture TEXT NOT NULL CHECK(architecture IN ('x86_64','aarch64','any')),
 target_architecture TEXT NOT NULL CHECK(target_architecture IN ('x86_64','aarch64')),
 collection TEXT NOT NULL CHECK(collection IN ('core','extra','multilib','omarchy','omapkg')),
 pkgbase TEXT NOT NULL,
 entry_json TEXT NOT NULL CHECK(json_valid(entry_json)),
 entry_sha256 TEXT NOT NULL,
 disposition TEXT NOT NULL DEFAULT 'unreviewed' CHECK(disposition IN ('unreviewed','linked','replacement','blocked','excluded')),
 reason TEXT,
 PRIMARY KEY(import_id,source_id,name)
);
CREATE INDEX catalog_import_coverage ON catalog_import_entries(import_id,disposition,architecture,name);
CREATE TABLE catalog_import_jobs (
 id TEXT PRIMARY KEY,
 payload_json TEXT NOT NULL CHECK(json_valid(payload_json)),
 request_sha256 TEXT NOT NULL,
 status TEXT NOT NULL CHECK(status IN ('queued','capturing','uploading','captured','failed')),
 import_id TEXT REFERENCES catalog_imports(id),
 progress_json TEXT NOT NULL DEFAULT '[]' CHECK(json_valid(progress_json)),
 error TEXT,
 created_by TEXT NOT NULL,
 created_at INTEGER NOT NULL,
 updated_at INTEGER NOT NULL
);
CREATE UNIQUE INDEX catalog_capture_active ON catalog_import_jobs(request_sha256) WHERE status IN ('queued','capturing','uploading');
CREATE TABLE catalog_import_reviews (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 import_id TEXT NOT NULL REFERENCES catalog_imports(id),
 source_id TEXT NOT NULL,
 name TEXT NOT NULL,
 disposition TEXT NOT NULL,
 reason TEXT NOT NULL,
 actor TEXT NOT NULL,
 created_at INTEGER NOT NULL
);
CREATE TRIGGER import_entry_content_immutable BEFORE UPDATE OF source_id,name,architecture,target_architecture,collection,pkgbase,entry_json,entry_sha256 ON catalog_import_entries
BEGIN SELECT RAISE(ABORT,'captured import entries are immutable'); END;
CREATE TABLE catalog_reconciliations (
 id TEXT PRIMARY KEY,
 candidate_import_id TEXT NOT NULL REFERENCES catalog_imports(id),
 baseline_import_id TEXT NOT NULL REFERENCES catalog_imports(id),
 report_json TEXT NOT NULL CHECK(json_valid(report_json)),
 report_sha256 TEXT NOT NULL,
 status TEXT NOT NULL DEFAULT 'preparing' CHECK(status IN ('preparing','ready')),
 created_by TEXT NOT NULL,
 created_at INTEGER NOT NULL
);
CREATE TRIGGER import_reconciliation_immutable BEFORE UPDATE OF candidate_import_id,baseline_import_id,report_json,report_sha256,created_by,created_at ON catalog_reconciliations
BEGIN SELECT RAISE(ABORT,'reconciliation reports are immutable'); END;
CREATE TABLE catalog_reconciliation_items (
 report_id TEXT NOT NULL REFERENCES catalog_reconciliations(id),
 package_key TEXT NOT NULL,
 kind TEXT NOT NULL CHECK(kind IN ('missing','extra','version','architecture','artifact','metadata')),
 item_json TEXT NOT NULL CHECK(json_valid(item_json)),
 PRIMARY KEY(report_id,package_key)
);
CREATE TRIGGER import_comparison_item_immutable BEFORE UPDATE ON catalog_reconciliation_items
BEGIN SELECT RAISE(ABORT,'reconciliation items are immutable'); END;

CREATE TABLE dependency_proposals (
 id TEXT PRIMARY KEY,
 proposal_key TEXT NOT NULL,
 revision INTEGER NOT NULL CHECK(revision > 0),
 manifest_json TEXT NOT NULL CHECK(json_valid(manifest_json)),
 manifest_sha256 TEXT NOT NULL,
 status TEXT NOT NULL CHECK(status IN ('proposed','admitted','declined','superseded')),
 dependency_request_id TEXT REFERENCES requests(id),
 created_by TEXT NOT NULL,
 created_at INTEGER NOT NULL,
 decided_by TEXT,
 decided_at INTEGER,
 decision_reason TEXT,
 UNIQUE(proposal_key,revision)
);
CREATE UNIQUE INDEX dependency_proposal_open ON dependency_proposals(proposal_key) WHERE status='proposed';
CREATE TRIGGER dependency_proposal_manifest_immutable BEFORE UPDATE OF proposal_key,revision,manifest_json,manifest_sha256,created_by,created_at ON dependency_proposals
BEGIN SELECT RAISE(ABORT,'dependency proposal revisions are immutable'); END;
CREATE TABLE dependency_proposal_blockers (
 proposal_id TEXT NOT NULL REFERENCES dependency_proposals(id),
 blocker_id TEXT NOT NULL REFERENCES dependency_blockers(id),
 PRIMARY KEY(proposal_id,blocker_id)
);
CREATE INDEX dependency_proposal_parent ON dependency_proposal_blockers(blocker_id);
ALTER TABLE requests ADD COLUMN catalog_pkgbase TEXT REFERENCES catalog_packages(pkgbase);
ALTER TABLE requests ADD COLUMN catalog_revision INTEGER;

CREATE TABLE distribution_control (
 id INTEGER PRIMARY KEY CHECK(id=1),
 mode TEXT NOT NULL CHECK(mode IN ('shadow','owned')),
 revision INTEGER NOT NULL,
 updated_at INTEGER NOT NULL,
 updated_by TEXT NOT NULL
);
INSERT INTO distribution_control VALUES(1,'shadow',1,0,'migration');
