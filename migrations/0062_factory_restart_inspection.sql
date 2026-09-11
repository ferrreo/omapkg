-- A human-authorized restart may inspect its first fresh candidate before reserving a build.
DROP VIEW current_recipe_inspections;
CREATE VIEW current_recipe_inspections AS
 SELECT i.* FROM recipe_inspections i JOIN recipe_captures c ON c.sha256=i.capture_sha256
 JOIN build_images image ON image.id=i.image_id AND image.architecture=i.architecture AND image.image_ref=i.image_ref AND image.enabled=1
 WHERE EXISTS(SELECT 1 FROM team_memberships t WHERE i.requested_by='github:'||t.github_id AND t.team IN ('system','security','admin'))
 AND (i.factory_run_id IS NULL OR EXISTS(
   SELECT 1 FROM factory_runs run
   WHERE run.id=i.factory_run_id AND run.execution_scope='private' AND (
     (run.status='running' AND run.current_attempt=i.factory_attempt AND run.lease_token IS NOT NULL AND run.lease_expires_at>unixepoch()) OR
     (run.status='queued' AND run.attempt_count=i.factory_attempt-1 AND COALESCE(run.current_attempt,0)=i.factory_attempt-1 AND run.lease_token IS NULL AND run.lease_expires_at IS NULL))))
 AND ((i.catalog_revision IS NULL AND json_extract(c.summary_json,'$.admissionRequired')=0) OR
   EXISTS(SELECT 1 FROM authorized_catalog_inputs policy JOIN catalog_packages p ON p.pkgbase=policy.pkgbase
    WHERE policy.pkgbase=c.pkgbase AND policy.revision=i.catalog_revision AND policy.manifest_sha256=i.catalog_sha256
      AND p.current_revision=policy.revision AND p.admitted_revision=policy.revision));
