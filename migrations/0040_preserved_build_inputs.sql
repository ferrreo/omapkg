ALTER TABLE builds ADD COLUMN preserved_inputs_json TEXT CHECK(preserved_inputs_json IS NULL OR json_valid(preserved_inputs_json));
ALTER TABLE build_attempts ADD COLUMN preserved_inputs_json TEXT CHECK(preserved_inputs_json IS NULL OR json_valid(preserved_inputs_json));

CREATE VIEW current_preserved_build_inputs AS
 SELECT i.revision_id,target.key AS architecture,
   json_object('capture',json_extract(i.evidence_json,'$.capture'),'sourceBundle',json(target.value)) AS inputs_json
 FROM current_preserved_recipe_imports i,json_each(i.evidence_json,'$.sources') target;

DROP TRIGGER build_attempt_start;
CREATE TRIGGER build_attempt_start AFTER UPDATE ON builds WHEN NEW.status='leased' AND NEW.attempt>OLD.attempt
BEGIN
 INSERT INTO build_attempts(build_id,attempt,revision_id,architecture,worker_id,worker_public_key,started_at,output_contract_json,dependency_plan_json,input_lock_sha256,preserved_inputs_json)
 SELECT NEW.id,NEW.attempt,NEW.revision_id,NEW.architecture,NEW.worker_id,w.public_key,NEW.started_at,NEW.output_contract_json,NEW.dependency_plan_json,NEW.input_lock_sha256,NEW.preserved_inputs_json
 FROM workers w WHERE w.id=NEW.worker_id;
END;
CREATE TRIGGER preserved_build_inputs_immutable BEFORE UPDATE OF preserved_inputs_json ON builds
 WHEN OLD.status='leased' AND OLD.lease_expires_at>unixepoch() AND NEW.status='leased' AND NEW.preserved_inputs_json IS NOT OLD.preserved_inputs_json
 BEGIN SELECT RAISE(ABORT,'Leased recipe source inputs are immutable'); END;

DROP TRIGGER preserved_build_lease;
CREATE TRIGGER preserved_build_lease BEFORE UPDATE ON builds
 WHEN NEW.status IN ('leased','succeeded') AND (NEW.preserved_inputs_json IS NOT NULL OR
   EXISTS(SELECT 1 FROM preserved_recipe_imports i WHERE i.revision_id=NEW.revision_id))
 AND (NEW.input_lock_sha256 IS NULL OR NEW.output_contract_json IS NULL OR NEW.dependency_plan_json IS NOT NULL OR
   NOT EXISTS(SELECT 1 FROM current_preserved_build_inputs i WHERE i.revision_id=NEW.revision_id AND i.architecture=NEW.architecture AND i.inputs_json=NEW.preserved_inputs_json) OR
   NOT EXISTS(SELECT 1 FROM workers w WHERE w.id=NEW.worker_id AND w.status='active' AND w.architecture=NEW.architecture AND
     (SELECT COUNT(DISTINCT value) FROM json_each(w.capabilities_json) WHERE value IN ('preserved-recipe-v1','multi-output-v2','frozen-inputs-v1','runtime-analysis-v1'))=4))
 BEGIN SELECT RAISE(ABORT,'Preserved recipe builds require current sources and a capable frozen-input worker'); END;

CREATE TRIGGER preserved_signing_inputs_current BEFORE UPDATE OF status ON signing_intents
 WHEN NEW.status='signed' AND NEW.build_attempt IS NOT NULL AND
   EXISTS(SELECT 1 FROM preserved_recipe_imports i WHERE i.revision_id=NEW.revision_id) AND
   NOT EXISTS(SELECT 1 FROM builds b JOIN build_attempts a ON a.build_id=b.id AND a.attempt=b.attempt
     JOIN current_preserved_build_inputs i ON i.revision_id=b.revision_id AND i.architecture=b.architecture
     WHERE b.id=NEW.build_id AND b.attempt=NEW.build_attempt AND i.inputs_json=b.preserved_inputs_json AND a.preserved_inputs_json=b.preserved_inputs_json)
 BEGIN SELECT RAISE(ABORT,'Preserved signing sources are no longer authorized'); END;

CREATE VIEW invalid_preserved_leases AS
 SELECT b.id FROM builds b WHERE b.status='leased' AND b.preserved_inputs_json IS NOT NULL AND (
   NOT EXISTS(SELECT 1 FROM current_preserved_build_inputs i WHERE i.revision_id=b.revision_id AND i.architecture=b.architecture AND i.inputs_json=b.preserved_inputs_json) OR
   NOT EXISTS(SELECT 1 FROM workers w WHERE w.id=b.worker_id AND w.status='active' AND w.architecture=b.architecture AND
     (SELECT COUNT(DISTINCT value) FROM json_each(w.capabilities_json) WHERE value IN ('preserved-recipe-v1','multi-output-v2','frozen-inputs-v1','runtime-analysis-v1'))=4));

-- Restoring authority permits a new attempt, never reuse of an old lease token.
CREATE TRIGGER preserved_team_delete_fence AFTER DELETE ON team_memberships BEGIN
 UPDATE builds SET status='queued',worker_id=NULL,lease_token=NULL,lease_expires_at=NULL,preserved_inputs_json=NULL,error='Preserved source authority changed; retry required.'
 WHERE id IN (SELECT id FROM invalid_preserved_leases);
END;
CREATE TRIGGER preserved_team_update_fence AFTER UPDATE ON team_memberships BEGIN
 UPDATE builds SET status='queued',worker_id=NULL,lease_token=NULL,lease_expires_at=NULL,preserved_inputs_json=NULL,error='Preserved source authority changed; retry required.'
 WHERE id IN (SELECT id FROM invalid_preserved_leases);
END;
CREATE TRIGGER preserved_catalog_fence AFTER UPDATE OF current_revision,admitted_revision ON catalog_packages BEGIN
 UPDATE builds SET status='queued',worker_id=NULL,lease_token=NULL,lease_expires_at=NULL,preserved_inputs_json=NULL,error='Preserved source authority changed; retry required.'
 WHERE id IN (SELECT id FROM invalid_preserved_leases);
END;
CREATE TRIGGER preserved_review_delete_fence AFTER DELETE ON catalog_reviews BEGIN
 UPDATE builds SET status='queued',worker_id=NULL,lease_token=NULL,lease_expires_at=NULL,preserved_inputs_json=NULL,error='Preserved source authority changed; retry required.'
 WHERE id IN (SELECT id FROM invalid_preserved_leases);
END;
CREATE TRIGGER preserved_review_update_fence AFTER UPDATE ON catalog_reviews BEGIN
 UPDATE builds SET status='queued',worker_id=NULL,lease_token=NULL,lease_expires_at=NULL,preserved_inputs_json=NULL,error='Preserved source authority changed; retry required.'
 WHERE id IN (SELECT id FROM invalid_preserved_leases);
END;
CREATE TRIGGER preserved_worker_fence AFTER UPDATE OF status,public_key,architecture,capabilities_json ON workers BEGIN
 UPDATE builds SET status='queued',worker_id=NULL,lease_token=NULL,lease_expires_at=NULL,preserved_inputs_json=NULL,error='Preserved source authority changed; retry required.'
 WHERE id IN (SELECT id FROM invalid_preserved_leases);
END;
CREATE TRIGGER preserved_image_fence AFTER UPDATE OF enabled,image_ref,architecture ON build_images BEGIN
 UPDATE builds SET status='queued',worker_id=NULL,lease_token=NULL,lease_expires_at=NULL,preserved_inputs_json=NULL,error='Preserved source authority changed; retry required.'
 WHERE id IN (SELECT id FROM invalid_preserved_leases);
END;
CREATE TRIGGER preserved_inspection_fence AFTER UPDATE OF status,attempt ON recipe_inspections BEGIN
 UPDATE builds SET status='queued',worker_id=NULL,lease_token=NULL,lease_expires_at=NULL,preserved_inputs_json=NULL,error='Preserved source authority changed; retry required.'
 WHERE id IN (SELECT id FROM invalid_preserved_leases);
END;
CREATE TRIGGER preserved_request_fence AFTER UPDATE OF name,catalog_pkgbase,catalog_revision ON requests BEGIN
 UPDATE builds SET status='queued',worker_id=NULL,lease_token=NULL,lease_expires_at=NULL,preserved_inputs_json=NULL,error='Preserved source authority changed; retry required.'
 WHERE id IN (SELECT id FROM invalid_preserved_leases);
END;
