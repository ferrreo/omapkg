CREATE TRIGGER helper_analysis_lease BEFORE UPDATE ON builds
 WHEN NEW.status IN ('leased','succeeded') AND EXISTS(SELECT 1 FROM input_locks l
   WHERE l.sha256=NEW.input_lock_sha256 AND json_extract(l.manifest_json,'$.shellAnalysis')='helper')
 AND NOT EXISTS(SELECT 1 FROM workers w,json_each(w.capabilities_json) capability
   WHERE w.id=NEW.worker_id AND w.status='active' AND capability.value='helper-shell-analysis-v1')
 BEGIN SELECT RAISE(ABORT,'Selected helper analysis requires a capable native worker'); END;

CREATE TRIGGER helper_analysis_worker_fence AFTER UPDATE OF capabilities_json ON workers
 WHEN NOT EXISTS(SELECT 1 FROM json_each(NEW.capabilities_json) WHERE value='helper-shell-analysis-v1')
 BEGIN
   UPDATE builds SET status='queued',worker_id=NULL,lease_token=NULL,lease_expires_at=NULL,error='Helper analysis capability changed; retry required.'
   WHERE worker_id=NEW.id AND status='leased' AND EXISTS(SELECT 1 FROM input_locks l
     WHERE l.sha256=builds.input_lock_sha256 AND json_extract(l.manifest_json,'$.shellAnalysis')='helper');
 END;
