-- Historical v1 intents have no attempt binding. Native v2 signing requires it.
ALTER TABLE signing_intents ADD COLUMN build_attempt INTEGER;
CREATE INDEX native_signatures ON signing_intents(build_id,build_attempt,object_kind,artifact_filename,status);
CREATE TRIGGER native_signing_attempt BEFORE INSERT ON signing_intents
WHEN EXISTS(SELECT 1 FROM builds WHERE id=NEW.build_id AND output_contract_json IS NOT NULL)
 AND NOT EXISTS(SELECT 1 FROM builds WHERE id=NEW.build_id AND attempt=NEW.build_attempt AND status='succeeded')
BEGIN SELECT RAISE(ABORT,'native signing requires the completed attempt'); END;
CREATE TRIGGER signing_attempt_immutable BEFORE UPDATE OF build_attempt ON signing_intents
WHEN NEW.build_attempt IS NOT OLD.build_attempt
BEGIN SELECT RAISE(ABORT,'signing attempt is immutable'); END;
CREATE TRIGGER native_signing_inputs_immutable BEFORE UPDATE OF build_id,revision_id,object_key,object_kind,artifact_sha256,artifact_filename,manifest_sha256,artifact_size ON signing_intents
WHEN OLD.build_attempt IS NOT NULL AND (NEW.build_id IS NOT OLD.build_id OR NEW.revision_id IS NOT OLD.revision_id OR NEW.object_key IS NOT OLD.object_key
 OR NEW.object_kind IS NOT OLD.object_kind OR NEW.artifact_sha256 IS NOT OLD.artifact_sha256 OR NEW.artifact_filename IS NOT OLD.artifact_filename
 OR NEW.manifest_sha256 IS NOT OLD.manifest_sha256 OR (OLD.artifact_size IS NOT NULL AND NEW.artifact_size IS NOT OLD.artifact_size))
BEGIN SELECT RAISE(ABORT,'native signing inputs are immutable'); END;
CREATE TRIGGER native_signing_current BEFORE UPDATE OF status ON signing_intents
WHEN NEW.status='signed' AND NEW.build_attempt IS NOT NULL AND NOT EXISTS(
 SELECT 1 FROM builds b JOIN revisions r ON r.id=b.revision_id JOIN requests q ON q.id=r.request_id
 JOIN workers w ON w.id=b.worker_id JOIN build_attempts a ON a.build_id=b.id AND a.attempt=b.attempt
 JOIN build_attempt_results result ON result.build_id=b.id AND result.attempt=b.attempt
 JOIN cohort_members m ON m.recipe_revision_id=r.id JOIN cohorts c ON c.id=m.cohort_id AND c.current_revision=m.revision
 JOIN cohort_revisions scope ON scope.cohort_id=c.id AND scope.revision=c.current_revision
 JOIN catalog_packages p ON p.pkgbase=m.pkgbase AND p.current_revision=m.catalog_revision AND p.admitted_revision=m.catalog_revision
 JOIN catalog_revisions policy ON policy.pkgbase=p.pkgbase AND policy.revision=p.current_revision
 WHERE b.id=NEW.build_id AND r.id=NEW.revision_id AND r.manifest_sha256=NEW.manifest_sha256 AND b.attempt=NEW.build_attempt
  AND b.status='succeeded' AND b.smoke_passed=1 AND result.status='succeeded' AND c.condition!='held'
  AND q.status IN ('queued','building','built') AND w.status='active' AND w.public_key=a.worker_public_key
  AND b.provenance=result.provenance AND b.provenance_signature=result.provenance_signature AND b.installed_size=result.installed_size
  AND b.output_contract_json=a.output_contract_json AND b.dependency_plan_json IS a.dependency_plan_json
  AND json_extract(b.output_contract_json,'$.cohort.id')=c.id AND json_extract(b.output_contract_json,'$.cohort.revision')=c.current_revision
  AND json_extract(b.output_contract_json,'$.cohort.manifestSha256')=scope.manifest_sha256
  AND r.id=(SELECT latest.id FROM revisions latest WHERE latest.request_id=q.id ORDER BY latest.created_at DESC,latest.rowid DESC LIMIT 1)
  AND (SELECT COUNT(DISTINCT review.kind) FROM approvals review WHERE review.revision_id=r.id AND review.manifest_sha256=r.manifest_sha256 AND review.revoked_at IS NULL
   AND EXISTS(SELECT 1 FROM team_memberships t WHERE review.actor='github:'||t.github_id AND (t.team IN ('security','admin') OR (review.kind='area' AND t.team=policy.owner_area))))=2
  AND (SELECT COUNT(DISTINCT review.actor) FROM approvals review WHERE review.revision_id=r.id AND review.manifest_sha256=r.manifest_sha256 AND review.revoked_at IS NULL)=2
  AND (SELECT COUNT(DISTINCT review.kind) FROM catalog_reviews review WHERE review.pkgbase=p.pkgbase AND review.revision=p.current_revision AND review.manifest_sha256=policy.manifest_sha256
   AND EXISTS(SELECT 1 FROM team_memberships t WHERE review.actor='github:'||t.github_id AND (t.team IN ('security','admin') OR (review.kind='area' AND t.team=policy.owner_area))))=2
  AND (SELECT COUNT(DISTINCT review.actor) FROM catalog_reviews review WHERE review.pkgbase=p.pkgbase AND review.revision=p.current_revision AND review.manifest_sha256=policy.manifest_sha256)=2
  AND (NEW.object_kind='attestation' OR (NEW.object_kind='package' AND EXISTS(SELECT 1 FROM build_artifacts artifact
   WHERE artifact.build_id=b.id AND artifact.attempt=b.attempt AND artifact.filename=NEW.artifact_filename AND artifact.artifact_key=NEW.object_key
    AND artifact.sha256=NEW.artifact_sha256 AND artifact.size=NEW.artifact_size)))
)
BEGIN SELECT RAISE(ABORT,'native signing review or attempt changed'); END;
