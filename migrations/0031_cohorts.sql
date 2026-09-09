CREATE TABLE team_memberships_next (
 github_id TEXT NOT NULL,
 team TEXT NOT NULL CHECK(team IN ('desktop','development','gaming','multimedia','productivity','system','security','release','admin')),
 PRIMARY KEY(github_id,team)
);
INSERT INTO team_memberships_next SELECT * FROM team_memberships;
DROP TABLE team_memberships;
ALTER TABLE team_memberships_next RENAME TO team_memberships;

CREATE TABLE cohorts (
 id TEXT PRIMARY KEY,
 current_revision INTEGER NOT NULL,
 event_sequence INTEGER NOT NULL DEFAULT 0,
 event_sha256 TEXT,
 phase TEXT NOT NULL CHECK(phase IN ('plan','review','build','verify','stage','approve','publish','observe')),
 condition TEXT NOT NULL CHECK(condition IN ('ready','blocked','held','recovering','complete')),
 created_at INTEGER NOT NULL,
 updated_at INTEGER NOT NULL
);
CREATE TABLE cohort_revisions (
 cohort_id TEXT NOT NULL REFERENCES cohorts(id),
 revision INTEGER NOT NULL CHECK(revision>0),
 manifest_json TEXT NOT NULL CHECK(json_valid(manifest_json)),
 manifest_sha256 TEXT NOT NULL,
 title TEXT NOT NULL,
 lane TEXT NOT NULL CHECK(lane IN ('system','opr')),
 created_by TEXT NOT NULL,
 created_at INTEGER NOT NULL,
 PRIMARY KEY(cohort_id,revision)
);
CREATE INDEX cohort_lane ON cohort_revisions(lane,cohort_id,revision);
CREATE TRIGGER cohort_revision_no_update BEFORE UPDATE ON cohort_revisions BEGIN SELECT RAISE(ABORT,'cohort revisions are immutable'); END;
CREATE TRIGGER cohort_revision_no_delete BEFORE DELETE ON cohort_revisions BEGIN SELECT RAISE(ABORT,'cohort revisions are immutable'); END;
CREATE TABLE cohort_members (
 cohort_id TEXT NOT NULL,
 revision INTEGER NOT NULL,
 pkgbase TEXT NOT NULL,
 catalog_revision INTEGER NOT NULL,
 recipe_revision_id TEXT REFERENCES revisions(id),
 PRIMARY KEY(cohort_id,revision,pkgbase),
 FOREIGN KEY(cohort_id,revision) REFERENCES cohort_revisions(cohort_id,revision),
 FOREIGN KEY(pkgbase,catalog_revision) REFERENCES catalog_revisions(pkgbase,revision)
);
CREATE INDEX cohort_member_recipe ON cohort_members(recipe_revision_id);
CREATE TRIGGER cohort_member_no_update BEFORE UPDATE ON cohort_members BEGIN SELECT RAISE(ABORT,'cohort membership is immutable'); END;
CREATE TRIGGER cohort_member_no_delete BEFORE DELETE ON cohort_members BEGIN SELECT RAISE(ABORT,'cohort membership is immutable'); END;

-- Ownership survives a superseding cohort revision. Removed members cannot leak
-- through the legacy per-build publisher while their replacement is reviewed.
CREATE TABLE cohort_recipe_ownership (
 recipe_revision_id TEXT PRIMARY KEY REFERENCES revisions(id),
 cohort_id TEXT NOT NULL REFERENCES cohorts(id)
);
CREATE TRIGGER cohort_recipe_no_update BEFORE UPDATE ON cohort_recipe_ownership BEGIN SELECT RAISE(ABORT,'recipe cohort ownership is immutable'); END;
CREATE TRIGGER cohort_recipe_no_delete BEFORE DELETE ON cohort_recipe_ownership BEGIN SELECT RAISE(ABORT,'recipe cohort ownership is immutable'); END;
CREATE TRIGGER cohort_recipe_not_published BEFORE INSERT ON cohort_recipe_ownership
WHEN EXISTS(SELECT 1 FROM builds b JOIN releases r ON r.build_id=b.id WHERE b.revision_id=NEW.recipe_revision_id)
BEGIN SELECT RAISE(ABORT,'published legacy builds cannot become cohort candidates'); END;
CREATE TRIGGER cohort_no_legacy_publication BEFORE INSERT ON releases
WHEN EXISTS(SELECT 1 FROM builds b JOIN cohort_recipe_ownership c ON c.recipe_revision_id=b.revision_id WHERE b.id=NEW.build_id)
BEGIN SELECT RAISE(ABORT,'cohort builds require coordinated distribution publication'); END;
CREATE TRIGGER cohort_no_legacy_reassignment BEFORE UPDATE OF build_id ON releases
WHEN EXISTS(SELECT 1 FROM builds b JOIN cohort_recipe_ownership c ON c.recipe_revision_id=b.revision_id WHERE b.id=NEW.build_id)
BEGIN SELECT RAISE(ABORT,'cohort builds require coordinated distribution publication'); END;

CREATE TABLE cohort_events (
 cohort_id TEXT NOT NULL REFERENCES cohorts(id),
 sequence INTEGER NOT NULL,
 revision INTEGER NOT NULL,
 command_sha256 TEXT NOT NULL,
 event_json TEXT NOT NULL CHECK(json_valid(event_json)),
 event_sha256 TEXT NOT NULL,
 created_at INTEGER NOT NULL,
 PRIMARY KEY(cohort_id,sequence),
 UNIQUE(cohort_id,command_sha256),
 FOREIGN KEY(cohort_id,revision) REFERENCES cohort_revisions(cohort_id,revision)
);
CREATE TRIGGER cohort_event_no_update BEFORE UPDATE ON cohort_events BEGIN SELECT RAISE(ABORT,'cohort events are append-only'); END;
CREATE TRIGGER cohort_event_no_delete BEFORE DELETE ON cohort_events BEGIN SELECT RAISE(ABORT,'cohort events are append-only'); END;
CREATE TABLE cohort_changelogs (
 cohort_id TEXT NOT NULL,
 revision INTEGER NOT NULL,
 digest TEXT NOT NULL,
 facts_sha256 TEXT NOT NULL,
 document_json TEXT NOT NULL CHECK(json_valid(document_json)),
 markdown TEXT NOT NULL,
 created_by TEXT NOT NULL,
 created_at INTEGER NOT NULL,
 PRIMARY KEY(cohort_id,revision,digest),
 FOREIGN KEY(cohort_id,revision) REFERENCES cohort_revisions(cohort_id,revision)
);
CREATE TRIGGER cohort_changelog_no_update BEFORE UPDATE ON cohort_changelogs BEGIN SELECT RAISE(ABORT,'cohort changelogs are immutable'); END;
CREATE TRIGGER cohort_changelog_no_delete BEFORE DELETE ON cohort_changelogs BEGIN SELECT RAISE(ABORT,'cohort changelogs are immutable'); END;
CREATE TABLE cohort_changelog_reviews (
 cohort_id TEXT NOT NULL,
 revision INTEGER NOT NULL,
 changelog_sha256 TEXT NOT NULL,
 actor TEXT NOT NULL,
 reason TEXT NOT NULL,
 created_at INTEGER NOT NULL,
 PRIMARY KEY(cohort_id,revision,changelog_sha256,actor),
 FOREIGN KEY(cohort_id,revision,changelog_sha256) REFERENCES cohort_changelogs(cohort_id,revision,digest)
);
CREATE TRIGGER cohort_changelog_review_no_update BEFORE UPDATE ON cohort_changelog_reviews BEGIN SELECT RAISE(ABORT,'changelog reviews are append-only'); END;
CREATE TRIGGER cohort_changelog_review_no_delete BEFORE DELETE ON cohort_changelog_reviews BEGIN SELECT RAISE(ABORT,'changelog reviews are append-only'); END;

CREATE TABLE cohort_checks (
 id TEXT PRIMARY KEY,
 cohort_id TEXT NOT NULL,
 revision INTEGER NOT NULL,
 kind TEXT NOT NULL CHECK(kind IN ('owned-inputs','dependency-closure','abi','reproducibility','install','upgrade','boot','recovery')),
 architecture TEXT NOT NULL CHECK(architecture IN ('x86_64','aarch64')),
 subject_sha256 TEXT NOT NULL,
 report_json TEXT NOT NULL CHECK(json_valid(report_json)),
 report_sha256 TEXT NOT NULL,
 worker_id TEXT NOT NULL REFERENCES workers(id),
 signature TEXT NOT NULL,
 created_at INTEGER NOT NULL,
 FOREIGN KEY(cohort_id,revision) REFERENCES cohort_revisions(cohort_id,revision)
);
CREATE INDEX cohort_check_scope ON cohort_checks(cohort_id,revision,kind,architecture,created_at);
CREATE TRIGGER cohort_check_no_update BEFORE UPDATE ON cohort_checks BEGIN SELECT RAISE(ABORT,'cohort check evidence is immutable'); END;
CREATE TRIGGER cohort_check_no_delete BEFORE DELETE ON cohort_checks BEGIN SELECT RAISE(ABORT,'cohort check evidence is immutable'); END;
