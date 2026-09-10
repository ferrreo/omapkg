-- A preserved repair changes only the recipe bytes.  The captured recipe,
-- retained source bundles, license and dependency evidence remain bound to the
-- original imported revision.
ALTER TABLE revisions ADD COLUMN preserved_origin_revision_id TEXT REFERENCES revisions(id);
CREATE INDEX revisions_preserved_origin ON revisions(preserved_origin_revision_id);

DROP TRIGGER preserved_revision_authority;
CREATE TRIGGER preserved_revision_authority BEFORE INSERT ON revisions
 WHEN EXISTS(SELECT 1 FROM requests q WHERE q.id=NEW.request_id AND q.preserved_import_id IS NOT NULL)
 AND NOT EXISTS(SELECT 1 FROM current_preserved_recipe_imports i
   WHERE i.request_id=NEW.request_id AND (i.revision_id=NEW.id OR i.revision_id=NEW.preserved_origin_revision_id)
     AND (i.revision_id=NEW.id OR NEW.preserved_origin_revision_id IS NOT NULL)
     AND (i.revision_id=NEW.id
       AND json_extract(i.draft_json,'$.revision.manifest_sha256')=NEW.manifest_sha256
       AND json_extract(i.draft_json,'$.revision.recipe_sha256')=NEW.recipe_sha256
       OR i.revision_id=NEW.preserved_origin_revision_id))
 BEGIN SELECT RAISE(ABORT,'Preserved recipe revision differs from current import'); END;

DROP VIEW current_preserved_build_inputs;
CREATE VIEW current_preserved_build_inputs AS
 SELECT r.id AS revision_id,target.key AS architecture,
   json_object('capture',json_extract(i.evidence_json,'$.capture'),'sourceBundle',json(target.value)) AS inputs_json
 FROM current_preserved_recipe_imports i
 JOIN revisions r ON r.id=i.revision_id OR r.preserved_origin_revision_id=i.revision_id,
   json_each(i.evidence_json,'$.sources') target;

DROP TRIGGER preserved_build_lease;
CREATE TRIGGER preserved_build_lease BEFORE UPDATE ON builds
 WHEN NEW.status IN ('leased','succeeded') AND
   (NEW.preserved_inputs_json IS NOT NULL OR EXISTS(
     SELECT 1 FROM preserved_recipe_imports i
     WHERE i.revision_id=NEW.revision_id OR i.revision_id=(SELECT preserved_origin_revision_id FROM revisions WHERE id=NEW.revision_id)))
 AND (NEW.input_lock_sha256 IS NULL OR NEW.output_contract_json IS NULL OR NEW.dependency_plan_json IS NOT NULL OR
   NOT EXISTS(SELECT 1 FROM current_preserved_build_inputs i WHERE i.revision_id=NEW.revision_id AND i.architecture=NEW.architecture AND i.inputs_json=NEW.preserved_inputs_json) OR
   NOT EXISTS(SELECT 1 FROM workers w WHERE w.id=NEW.worker_id AND w.status='active' AND w.architecture=NEW.architecture AND
     (SELECT COUNT(DISTINCT value) FROM json_each(w.capabilities_json) WHERE value IN ('preserved-recipe-v1','multi-output-v2','frozen-inputs-v1','runtime-analysis-v1'))=4))
 BEGIN SELECT RAISE(ABORT,'Preserved recipe builds require current sources and a capable frozen-input worker'); END;

DROP TRIGGER preserved_signing_inputs_current;
CREATE TRIGGER preserved_signing_inputs_current BEFORE UPDATE ON signing_intents
 WHEN NEW.status='signed' AND NEW.build_attempt IS NOT NULL AND
   EXISTS(SELECT 1 FROM preserved_recipe_imports i JOIN revisions r ON r.id=i.revision_id OR r.preserved_origin_revision_id=i.revision_id
     WHERE r.id=NEW.revision_id) AND
   NOT EXISTS(SELECT 1 FROM builds b JOIN build_attempts a ON a.build_id=b.id AND a.attempt=b.attempt
     JOIN current_preserved_build_inputs i ON i.revision_id=b.revision_id AND i.architecture=b.architecture
     WHERE b.id=NEW.build_id AND b.attempt=NEW.build_attempt AND i.inputs_json=b.preserved_inputs_json AND a.preserved_inputs_json=b.preserved_inputs_json)
 BEGIN SELECT RAISE(ABORT,'Preserved signing sources are no longer authorized'); END;
