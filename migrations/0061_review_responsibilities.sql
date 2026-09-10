-- Require both review responsibilities, with current permissions for each.
-- One account may hold and attest both responsibilities.
DROP INDEX input_lock_review_actor;

DROP VIEW authorized_input_reviews;
CREATE VIEW authorized_input_reviews AS
 SELECT review.lock_sha256 FROM input_lock_reviews review JOIN team_memberships t ON review.actor='github:'||t.github_id
 WHERE review.revoked_at IS NULL AND (t.team IN ('admin','security') OR (review.kind='area' AND t.team='system'))
 GROUP BY review.lock_sha256 HAVING COUNT(DISTINCT review.kind)=2;

DROP VIEW authorized_catalog_inputs;
CREATE VIEW authorized_catalog_inputs AS
 SELECT policy.pkgbase,policy.revision,policy.manifest_sha256,policy.owner_area FROM catalog_revisions policy
 JOIN catalog_reviews review ON review.pkgbase=policy.pkgbase AND review.revision=policy.revision AND review.manifest_sha256=policy.manifest_sha256
 JOIN team_memberships t ON review.actor='github:'||t.github_id
 WHERE t.team IN ('admin','security') OR (review.kind='area' AND t.team=policy.owner_area)
 GROUP BY policy.pkgbase,policy.revision HAVING COUNT(DISTINCT review.kind)=2;

DROP VIEW authorized_recipe_inputs;
CREATE VIEW authorized_recipe_inputs AS
 SELECT review.revision_id,review.manifest_sha256,policy.owner_area FROM approvals review
 JOIN cohort_members m ON m.recipe_revision_id=review.revision_id
 JOIN catalog_revisions policy ON policy.pkgbase=m.pkgbase AND policy.revision=m.catalog_revision
 JOIN team_memberships t ON review.actor='github:'||t.github_id
 WHERE review.revoked_at IS NULL AND (t.team IN ('admin','security') OR (review.kind='area' AND t.team=policy.owner_area))
 GROUP BY review.revision_id,review.manifest_sha256,policy.owner_area HAVING COUNT(DISTINCT review.kind)=2;

DROP TRIGGER native_signing_current;
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
  AND (SELECT COUNT(DISTINCT review.kind) FROM catalog_reviews review WHERE review.pkgbase=p.pkgbase AND review.revision=p.current_revision AND review.manifest_sha256=policy.manifest_sha256
   AND EXISTS(SELECT 1 FROM team_memberships t WHERE review.actor='github:'||t.github_id AND (t.team IN ('security','admin') OR (review.kind='area' AND t.team=policy.owner_area))))=2
  AND (NEW.object_kind IN ('attestation','database') OR (NEW.object_kind='package' AND EXISTS(SELECT 1 FROM build_artifacts artifact
   WHERE artifact.build_id=b.id AND artifact.attempt=b.attempt AND artifact.filename=NEW.artifact_filename AND artifact.artifact_key=NEW.object_key
    AND artifact.sha256=NEW.artifact_sha256 AND artifact.size=NEW.artifact_size)))
)
BEGIN SELECT RAISE(ABORT,'native signing review or attempt changed'); END;

CREATE TABLE native_qualification_plan_reviews_next (
  plan_id TEXT NOT NULL REFERENCES native_qualification_plans(id),
  kind TEXT NOT NULL CHECK(kind IN ('area','security')),
  actor TEXT NOT NULL,
  reason TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  PRIMARY KEY(plan_id,kind)
);
INSERT INTO native_qualification_plan_reviews_next SELECT * FROM native_qualification_plan_reviews;
DROP TABLE native_qualification_plan_reviews;
ALTER TABLE native_qualification_plan_reviews_next RENAME TO native_qualification_plan_reviews;
CREATE TRIGGER native_qualification_plan_review_no_update BEFORE UPDATE ON native_qualification_plan_reviews
BEGIN SELECT RAISE(ABORT,'qualification plan reviews are append-only'); END;
CREATE TRIGGER native_qualification_plan_review_no_delete BEFORE DELETE ON native_qualification_plan_reviews
BEGIN SELECT RAISE(ABORT,'qualification plan review history is immutable'); END;
CREATE TRIGGER native_qualification_review_epoch AFTER INSERT ON native_qualification_plan_reviews
BEGIN UPDATE cohort_scope_epochs SET version=version+1 WHERE cohort_id=(SELECT cohort_id FROM native_qualification_plans WHERE id=NEW.plan_id); END;

-- Recompute cached gates under the updated review policy.
UPDATE cohort_evidence_epoch SET version=version+1 WHERE id=1;
UPDATE cohort_scope_epochs SET version=version+1;
