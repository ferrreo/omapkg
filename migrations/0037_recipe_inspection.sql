CREATE TABLE recipe_inspections (
  id TEXT PRIMARY KEY,
  capture_sha256 TEXT NOT NULL REFERENCES recipe_captures(sha256),
  architecture TEXT NOT NULL CHECK(architecture IN ('x86_64','aarch64')),
  image_id TEXT NOT NULL REFERENCES build_images(id),
  image_ref TEXT NOT NULL,
  catalog_revision INTEGER,
  catalog_sha256 TEXT,
  requested_by TEXT NOT NULL,
  reason TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('queued','leased','succeeded','failed','cancelled')),
  attempt INTEGER NOT NULL DEFAULT 0,
  worker_id TEXT REFERENCES workers(id),
  lease_token TEXT,
  lease_expires_at INTEGER,
  error TEXT,
  CHECK((catalog_revision IS NULL)=(catalog_sha256 IS NULL))
);
CREATE INDEX recipe_inspection_queue ON recipe_inspections(architecture,status,created_at);
CREATE INDEX recipe_inspection_capture ON recipe_inspections(capture_sha256,architecture,created_at);
CREATE TRIGGER recipe_inspection_scope BEFORE UPDATE OF capture_sha256,architecture,image_id,image_ref,catalog_revision,catalog_sha256,requested_by,reason,created_at ON recipe_inspections
 BEGIN SELECT RAISE(ABORT,'Recipe inspection scope is immutable'); END;

CREATE VIEW current_recipe_inspections AS
 SELECT i.* FROM recipe_inspections i JOIN recipe_captures c ON c.sha256=i.capture_sha256
 JOIN build_images image ON image.id=i.image_id AND image.architecture=i.architecture AND image.image_ref=i.image_ref AND image.enabled=1
 WHERE EXISTS(SELECT 1 FROM team_memberships t WHERE i.requested_by='github:'||t.github_id AND t.team IN ('system','security','admin'))
 AND ((i.catalog_revision IS NULL AND json_extract(c.summary_json,'$.admissionRequired')=0) OR
   EXISTS(SELECT 1 FROM authorized_catalog_inputs policy JOIN catalog_packages p ON p.pkgbase=policy.pkgbase
    WHERE policy.pkgbase=c.pkgbase AND policy.revision=i.catalog_revision AND policy.manifest_sha256=i.catalog_sha256
      AND p.current_revision=policy.revision AND p.admitted_revision=policy.revision));

CREATE TABLE recipe_inspection_attempts (
  job_id TEXT NOT NULL REFERENCES recipe_inspections(id),
  attempt INTEGER NOT NULL,
  worker_id TEXT NOT NULL REFERENCES workers(id),
  public_key TEXT NOT NULL,
  lease_token_sha256 TEXT NOT NULL,
  lease_expires_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  PRIMARY KEY(job_id,attempt)
);
CREATE TRIGGER recipe_inspection_attempt_immutable BEFORE UPDATE ON recipe_inspection_attempts BEGIN SELECT RAISE(ABORT,'Recipe inspection attempts are immutable'); END;
CREATE TRIGGER recipe_inspection_attempt_preserved BEFORE DELETE ON recipe_inspection_attempts BEGIN SELECT RAISE(ABORT,'Recipe inspection attempts are retained evidence'); END;

CREATE TABLE recipe_inspection_results (
  job_id TEXT NOT NULL,
  attempt INTEGER NOT NULL,
  report_json TEXT NOT NULL CHECK(json_valid(report_json)),
  report_sha256 TEXT NOT NULL,
  signature TEXT NOT NULL,
  metadata_json TEXT CHECK(metadata_json IS NULL OR json_valid(metadata_json)),
  error TEXT,
  created_at INTEGER NOT NULL,
  PRIMARY KEY(job_id,attempt),
  FOREIGN KEY(job_id,attempt) REFERENCES recipe_inspection_attempts(job_id,attempt)
);
CREATE TRIGGER recipe_inspection_result_immutable BEFORE UPDATE ON recipe_inspection_results BEGIN SELECT RAISE(ABORT,'Recipe inspection results are immutable'); END;
CREATE TRIGGER recipe_inspection_result_preserved BEFORE DELETE ON recipe_inspection_results BEGIN SELECT RAISE(ABORT,'Recipe inspection results are retained evidence'); END;

CREATE TRIGGER recipe_inspection_lease_guard BEFORE UPDATE OF status,worker_id,lease_token,lease_expires_at ON recipe_inspections
 WHEN NEW.status='leased' AND (NOT EXISTS(SELECT 1 FROM current_recipe_inspections WHERE id=NEW.id) OR
   NOT EXISTS(SELECT 1 FROM workers WHERE id=NEW.worker_id AND status='active' AND architecture=NEW.architecture AND accepting_jobs=1))
 BEGIN SELECT RAISE(ABORT,'Recipe inspection authority changed'); END;
CREATE TRIGGER recipe_inspection_success_guard BEFORE UPDATE OF status ON recipe_inspections
 WHEN NEW.status='succeeded' AND (NOT EXISTS(SELECT 1 FROM current_recipe_inspections WHERE id=NEW.id) OR
   NOT EXISTS(SELECT 1 FROM workers w JOIN recipe_inspection_attempts a ON a.worker_id=w.id AND a.public_key=w.public_key
    WHERE w.id=NEW.worker_id AND w.status='active' AND a.job_id=NEW.id AND a.attempt=NEW.attempt))
 BEGIN SELECT RAISE(ABORT,'Recipe inspection authority changed'); END;

-- Revocation fences existing tokens. Restoring a role or image cannot revive a lease.
CREATE TRIGGER recipe_inspection_team_fence AFTER DELETE ON team_memberships BEGIN
 UPDATE recipe_inspections SET status='cancelled',lease_token=NULL,lease_expires_at=NULL,error='Source inspection authority changed; request inspection again.'
 WHERE status IN ('queued','leased') AND NOT EXISTS(SELECT 1 FROM current_recipe_inspections current WHERE current.id=recipe_inspections.id);
END;
CREATE TRIGGER recipe_inspection_image_fence AFTER UPDATE OF enabled,image_ref,architecture ON build_images BEGIN
 UPDATE recipe_inspections SET status='cancelled',lease_token=NULL,lease_expires_at=NULL,error='Inspection image authority changed; request inspection again.'
 WHERE image_id=NEW.id AND status IN ('queued','leased') AND NOT EXISTS(SELECT 1 FROM current_recipe_inspections current WHERE current.id=recipe_inspections.id);
END;
CREATE TRIGGER recipe_inspection_catalog_fence AFTER UPDATE OF current_revision,admitted_revision ON catalog_packages BEGIN
 UPDATE recipe_inspections SET status='cancelled',lease_token=NULL,lease_expires_at=NULL,error='Source admission changed; request inspection again.'
 WHERE catalog_revision IS NOT NULL AND status IN ('queued','leased') AND NOT EXISTS(SELECT 1 FROM current_recipe_inspections current WHERE current.id=recipe_inspections.id);
END;
CREATE TRIGGER recipe_inspection_review_delete_fence AFTER DELETE ON catalog_reviews BEGIN
 UPDATE recipe_inspections SET status='cancelled',lease_token=NULL,lease_expires_at=NULL,error='Source admission changed; request inspection again.'
 WHERE catalog_revision IS NOT NULL AND status IN ('queued','leased') AND NOT EXISTS(SELECT 1 FROM current_recipe_inspections current WHERE current.id=recipe_inspections.id);
END;
CREATE TRIGGER recipe_inspection_review_update_fence AFTER UPDATE ON catalog_reviews BEGIN
 UPDATE recipe_inspections SET status='cancelled',lease_token=NULL,lease_expires_at=NULL,error='Source admission changed; request inspection again.'
 WHERE catalog_revision IS NOT NULL AND status IN ('queued','leased') AND NOT EXISTS(SELECT 1 FROM current_recipe_inspections current WHERE current.id=recipe_inspections.id);
END;
CREATE TRIGGER recipe_inspection_worker_fence AFTER UPDATE OF status,public_key,architecture ON workers BEGIN
 UPDATE recipe_inspections SET status='cancelled',lease_token=NULL,lease_expires_at=NULL,error='Inspection worker authority changed; request inspection again.'
 WHERE worker_id=NEW.id AND status='leased' AND (NEW.status<>'active' OR architecture<>NEW.architecture OR
   NOT EXISTS(SELECT 1 FROM recipe_inspection_attempts a WHERE a.job_id=recipe_inspections.id AND a.attempt=recipe_inspections.attempt AND a.public_key=NEW.public_key));
END;
