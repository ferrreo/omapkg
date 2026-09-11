-- Recipe overrides retain the original capture and source bundle. Match the
-- same source authority as preserved_build_lease, while attempt bytes stay immutable.
DROP VIEW invalid_preserved_leases;
CREATE VIEW invalid_preserved_leases AS
 SELECT b.id FROM builds b WHERE b.status='leased' AND b.preserved_inputs_json IS NOT NULL AND (
   NOT EXISTS(SELECT 1 FROM current_preserved_build_inputs i WHERE i.revision_id=b.revision_id AND i.architecture=b.architecture
     AND json_extract(i.inputs_json,'$.capture')=json_extract(b.preserved_inputs_json,'$.capture')
     AND json_extract(i.inputs_json,'$.sourceBundle')=json_extract(b.preserved_inputs_json,'$.sourceBundle')) OR
   NOT EXISTS(SELECT 1 FROM workers w WHERE w.id=b.worker_id AND w.status='active' AND w.architecture=b.architecture AND
     (SELECT COUNT(DISTINCT value) FROM json_each(w.capabilities_json) WHERE value IN ('preserved-recipe-v1','multi-output-v2','frozen-inputs-v1','runtime-analysis-v1'))=4));

DROP TRIGGER preserved_signing_inputs_current;
CREATE TRIGGER preserved_signing_inputs_current BEFORE UPDATE ON signing_intents
 WHEN NEW.status='signed' AND NEW.build_attempt IS NOT NULL AND
   EXISTS(SELECT 1 FROM preserved_recipe_imports i JOIN revisions r ON r.id=i.revision_id OR r.preserved_origin_revision_id=i.revision_id
     WHERE r.id=NEW.revision_id) AND
   NOT EXISTS(SELECT 1 FROM builds b JOIN build_attempts a ON a.build_id=b.id AND a.attempt=b.attempt
     JOIN current_preserved_build_inputs i ON i.revision_id=b.revision_id AND i.architecture=b.architecture
     WHERE b.id=NEW.build_id AND b.attempt=NEW.build_attempt
       AND json_extract(i.inputs_json,'$.capture')=json_extract(b.preserved_inputs_json,'$.capture')
       AND json_extract(i.inputs_json,'$.sourceBundle')=json_extract(b.preserved_inputs_json,'$.sourceBundle')
       AND a.preserved_inputs_json=b.preserved_inputs_json)
 BEGIN SELECT RAISE(ABORT,'Preserved signing sources are no longer authorized'); END;
