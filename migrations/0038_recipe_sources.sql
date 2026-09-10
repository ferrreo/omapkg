CREATE TABLE recipe_source_bundles (
  sha256 TEXT PRIMARY KEY REFERENCES input_objects(sha256),
  plan_sha256 TEXT NOT NULL REFERENCES input_objects(sha256),
  capture_sha256 TEXT NOT NULL REFERENCES recipe_captures(sha256),
  inspection_id TEXT NOT NULL,
  inspection_attempt INTEGER NOT NULL,
  architecture TEXT NOT NULL CHECK(architecture IN ('x86_64','aarch64')),
  manifest_json TEXT NOT NULL CHECK(json_valid(manifest_json)),
  created_by TEXT NOT NULL,
  reason TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  FOREIGN KEY(inspection_id,inspection_attempt) REFERENCES recipe_inspection_results(job_id,attempt)
);
CREATE INDEX recipe_source_capture ON recipe_source_bundles(capture_sha256,architecture,created_at);
CREATE TRIGGER recipe_sources_immutable BEFORE UPDATE ON recipe_source_bundles BEGIN SELECT RAISE(ABORT,'Recipe source bundles are immutable'); END;
CREATE TRIGGER recipe_sources_preserved BEFORE DELETE ON recipe_source_bundles BEGIN SELECT RAISE(ABORT,'Recipe source bundles are retained evidence'); END;
CREATE VIEW current_recipe_source_bundles AS
 SELECT b.* FROM recipe_source_bundles b JOIN current_recipe_inspections i ON i.id=b.inspection_id AND i.attempt=b.inspection_attempt
 JOIN recipe_inspection_attempts a ON a.job_id=i.id AND a.attempt=i.attempt JOIN workers w ON w.id=a.worker_id AND w.public_key=a.public_key AND w.status='active'
 JOIN recipe_inspection_results r ON r.job_id=a.job_id AND r.attempt=a.attempt
 WHERE i.capture_sha256=b.capture_sha256 AND i.architecture=b.architecture AND i.status='succeeded' AND r.error IS NULL;
CREATE TRIGGER recipe_sources_current BEFORE INSERT ON recipe_source_bundles
 WHEN NOT EXISTS(SELECT 1 FROM current_recipe_inspections i JOIN recipe_inspection_attempts a ON a.job_id=i.id AND a.attempt=i.attempt
   JOIN workers w ON w.id=a.worker_id AND w.public_key=a.public_key AND w.status='active'
   JOIN recipe_inspection_results r ON r.job_id=a.job_id AND r.attempt=a.attempt
   WHERE i.id=NEW.inspection_id AND i.attempt=NEW.inspection_attempt AND i.capture_sha256=NEW.capture_sha256 AND i.architecture=NEW.architecture AND i.status='succeeded' AND r.error IS NULL)
   OR NOT EXISTS(SELECT 1 FROM team_memberships t WHERE NEW.created_by='github:'||t.github_id AND t.team IN ('system','security','admin'))
 BEGIN SELECT RAISE(ABORT,'Recipe source preparation authority changed'); END;
