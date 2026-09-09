DROP TRIGGER cohort_no_legacy_publication;
CREATE TRIGGER cohort_no_legacy_publication BEFORE INSERT ON releases
WHEN (SELECT mode FROM distribution_control WHERE id=1)='owned'
  OR EXISTS(SELECT 1 FROM builds b JOIN cohort_recipe_ownership c ON c.recipe_revision_id=b.revision_id WHERE b.id=NEW.build_id)
BEGIN SELECT RAISE(ABORT,'cohort builds require coordinated distribution publication'); END;
CREATE TRIGGER owned_no_legacy_channels BEFORE UPDATE OF channel ON releases
WHEN (SELECT mode FROM distribution_control WHERE id=1)='owned'
BEGIN SELECT RAISE(ABORT,'legacy channel writes are disabled in owned mode'); END;
CREATE TRIGGER owned_no_legacy_snapshots BEFORE INSERT ON repository_snapshots
WHEN (SELECT mode FROM distribution_control WHERE id=1)='owned'
BEGIN SELECT RAISE(ABORT,'legacy snapshot writes are disabled in owned mode'); END;

-- The selector skips held/superseded work; this trigger closes the race between
-- selection and leasing when a maintainer changes cohort scope or condition.
CREATE TRIGGER cohort_lease_phase BEFORE UPDATE OF status,worker_id,lease_token ON builds
WHEN NEW.status='leased' AND EXISTS(
 SELECT 1 FROM cohort_recipe_ownership owned JOIN cohorts cohort ON cohort.id=owned.cohort_id
 WHERE owned.recipe_revision_id=NEW.revision_id AND (
  cohort.phase<>'build' OR cohort.condition NOT IN ('ready','blocked') OR NOT EXISTS(
   SELECT 1 FROM cohort_members member WHERE member.cohort_id=cohort.id
    AND member.revision=cohort.current_revision AND member.recipe_revision_id=NEW.revision_id)))
BEGIN SELECT RAISE(ABORT,'cohort build phase changed before leasing'); END;
CREATE TRIGGER owned_no_legacy_activation BEFORE UPDATE OF active ON repository_snapshots
WHEN (SELECT mode FROM distribution_control WHERE id=1)='owned'
BEGIN SELECT RAISE(ABORT,'legacy snapshot writes are disabled in owned mode'); END;
