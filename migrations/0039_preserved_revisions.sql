ALTER TABLE requests ADD COLUMN preserved_import_id TEXT;

CREATE TABLE preserved_recipe_imports (
  id TEXT PRIMARY KEY,
  request_id TEXT NOT NULL UNIQUE REFERENCES requests(id),
  revision_id TEXT NOT NULL UNIQUE,
  capture_sha256 TEXT NOT NULL REFERENCES recipe_captures(sha256),
  pkgbase TEXT NOT NULL,
  catalog_revision INTEGER NOT NULL,
  catalog_sha256 TEXT NOT NULL,
  evidence_json TEXT NOT NULL CHECK(json_valid(evidence_json)),
  draft_json TEXT NOT NULL CHECK(json_valid(draft_json)),
  created_by TEXT NOT NULL,
  reason TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  FOREIGN KEY(pkgbase,catalog_revision) REFERENCES catalog_revisions(pkgbase,revision)
);
CREATE INDEX preserved_recipe_capture ON preserved_recipe_imports(capture_sha256,created_at);
CREATE TRIGGER preserved_import_immutable BEFORE UPDATE ON preserved_recipe_imports BEGIN SELECT RAISE(ABORT,'Preserved recipe imports are immutable'); END;
CREATE TRIGGER preserved_import_retained BEFORE DELETE ON preserved_recipe_imports BEGIN SELECT RAISE(ABORT,'Preserved recipe imports are retained evidence'); END;
CREATE TRIGGER preserved_request_scope BEFORE UPDATE OF preserved_import_id ON requests
 WHEN OLD.preserved_import_id IS NOT NEW.preserved_import_id BEGIN SELECT RAISE(ABORT,'Preserved request identity is immutable'); END;
CREATE TRIGGER preserved_request_generation BEFORE UPDATE OF factory_run_id ON requests
 WHEN OLD.preserved_import_id IS NOT NULL AND OLD.factory_run_id IS NOT NEW.factory_run_id
 BEGIN SELECT RAISE(ABORT,'Preserved requests cannot enter a different factory generation'); END;

CREATE VIEW current_preserved_recipe_imports AS
 SELECT i.* FROM preserved_recipe_imports i JOIN requests q ON q.id=i.request_id AND q.preserved_import_id=i.id
   AND q.name=i.pkgbase AND q.catalog_pkgbase=i.pkgbase AND q.catalog_revision=i.catalog_revision
 JOIN catalog_packages p ON p.pkgbase=i.pkgbase AND p.current_revision=i.catalog_revision AND p.admitted_revision=i.catalog_revision
 JOIN authorized_catalog_inputs policy ON policy.pkgbase=i.pkgbase AND policy.revision=i.catalog_revision AND policy.manifest_sha256=i.catalog_sha256
 WHERE EXISTS(SELECT 1 FROM team_memberships t WHERE i.created_by='github:'||t.github_id AND t.team IN ('system','security','admin'))
 AND json_array_length(i.draft_json,'$.manifest.architectures')=(SELECT COUNT(*) FROM json_each(i.evidence_json,'$.sources'))
 AND NOT EXISTS(SELECT 1 FROM json_each(i.draft_json,'$.manifest.architectures') target WHERE
   NOT EXISTS(SELECT 1 FROM json_each(i.evidence_json,'$.sources') source JOIN current_recipe_source_bundles b
     ON b.sha256=json_extract(source.value,'$.sha256') AND b.architecture=source.key AND b.capture_sha256=i.capture_sha256
     WHERE source.key=target.value));
CREATE TRIGGER preserved_import_authority AFTER INSERT ON preserved_recipe_imports
 WHEN NOT EXISTS(SELECT 1 FROM current_preserved_recipe_imports WHERE id=NEW.id)
 BEGIN SELECT RAISE(ABORT,'Preserved recipe import authority changed'); END;
CREATE TRIGGER preserved_revision_authority BEFORE INSERT ON revisions
 WHEN EXISTS(SELECT 1 FROM requests q WHERE q.id=NEW.request_id AND q.preserved_import_id IS NOT NULL)
 AND NOT EXISTS(SELECT 1 FROM current_preserved_recipe_imports i WHERE i.request_id=NEW.request_id AND i.revision_id=NEW.id
   AND json_extract(i.draft_json,'$.revision.manifest_sha256')=NEW.manifest_sha256
   AND json_extract(i.draft_json,'$.revision.recipe_sha256')=NEW.recipe_sha256)
 BEGIN SELECT RAISE(ABORT,'Preserved recipe revision differs from current import'); END;
CREATE TRIGGER preserved_approval_authority BEFORE INSERT ON approvals
 WHEN EXISTS(SELECT 1 FROM preserved_recipe_imports i WHERE i.revision_id=NEW.revision_id)
 AND NOT EXISTS(SELECT 1 FROM current_preserved_recipe_imports i WHERE i.revision_id=NEW.revision_id)
 BEGIN SELECT RAISE(ABORT,'Preserved recipe approval authority changed'); END;
CREATE TRIGGER preserved_approval_update_authority BEFORE UPDATE ON approvals
 WHEN NEW.revoked_at IS NULL AND EXISTS(SELECT 1 FROM preserved_recipe_imports i WHERE i.revision_id=NEW.revision_id)
 AND NOT EXISTS(SELECT 1 FROM current_preserved_recipe_imports i WHERE i.revision_id=NEW.revision_id)
 BEGIN SELECT RAISE(ABORT,'Preserved recipe approval authority changed'); END;
CREATE TRIGGER preserved_build_lease BEFORE UPDATE ON builds
 WHEN NEW.status='leased' AND EXISTS(SELECT 1 FROM preserved_recipe_imports i WHERE i.revision_id=NEW.revision_id)
 AND (NEW.input_lock_sha256 IS NULL OR NEW.output_contract_json IS NULL OR
   NOT EXISTS(SELECT 1 FROM current_preserved_recipe_imports i WHERE i.revision_id=NEW.revision_id) OR
   NOT EXISTS(SELECT 1 FROM workers w,json_each(w.capabilities_json) c WHERE w.id=NEW.worker_id AND w.status='active' AND c.value='preserved-recipe-v1'))
 BEGIN SELECT RAISE(ABORT,'Preserved recipe builds require current sources and a capable frozen-input worker'); END;
