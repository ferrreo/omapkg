-- Rejection frees the package identity while retaining its original evidence.
DROP VIEW current_preserved_recipe_imports;
CREATE VIEW current_preserved_recipe_imports AS
 SELECT i.* FROM preserved_recipe_imports i JOIN requests q ON q.id=i.request_id AND q.preserved_import_id=i.id
   AND q.name=i.pkgbase AND q.catalog_pkgbase=i.pkgbase AND q.catalog_revision=i.catalog_revision
 JOIN catalog_packages p ON p.pkgbase=i.pkgbase AND p.current_revision=i.catalog_revision AND p.admitted_revision=i.catalog_revision
 JOIN authorized_catalog_inputs policy ON policy.pkgbase=i.pkgbase AND policy.revision=i.catalog_revision AND policy.manifest_sha256=i.catalog_sha256
 WHERE q.status<>'rejected' AND EXISTS(SELECT 1 FROM team_memberships t WHERE i.created_by='github:'||t.github_id AND t.team IN ('system','security','admin'))
 AND json_array_length(i.draft_json,'$.manifest.architectures')=(SELECT COUNT(*) FROM json_each(i.evidence_json,'$.sources'))
 AND NOT EXISTS(SELECT 1 FROM json_each(i.draft_json,'$.manifest.architectures') target WHERE
   NOT EXISTS(SELECT 1 FROM json_each(i.evidence_json,'$.sources') source JOIN current_recipe_source_bundles b
     ON b.sha256=json_extract(source.value,'$.sha256') AND b.architecture=source.key AND b.capture_sha256=i.capture_sha256
     WHERE source.key=target.value));

CREATE TRIGGER preserved_rejection_terminal BEFORE UPDATE OF status ON requests
 WHEN OLD.preserved_import_id IS NOT NULL AND OLD.status='rejected' AND NEW.status<>'rejected'
 BEGIN SELECT RAISE(ABORT,'Rejected imports require a new reviewed request'); END;
CREATE TRIGGER preserved_rejection_unpublished BEFORE UPDATE OF status ON requests
 WHEN NEW.preserved_import_id IS NOT NULL AND NEW.status='rejected' AND (
   EXISTS(SELECT 1 FROM revisions r JOIN builds b ON b.revision_id=r.id JOIN releases published ON published.build_id=b.id WHERE r.request_id=NEW.id) OR
   EXISTS(SELECT 1 FROM revisions r JOIN cohort_recipe_ownership o ON o.recipe_revision_id=r.id JOIN cohorts c ON c.id=o.cohort_id
     WHERE r.request_id=NEW.id AND c.phase IN ('publish','observe')))
 BEGIN SELECT RAISE(ABORT,'Published imports require release recovery'); END;
CREATE TRIGGER preserved_rejection_cancel_builds AFTER UPDATE OF status ON requests
 WHEN NEW.preserved_import_id IS NOT NULL AND NEW.status='rejected' AND OLD.status<>'rejected'
 BEGIN
   UPDATE builds SET status='cancelled',lease_token=NULL,lease_expires_at=NULL,finished_at=NEW.updated_at,
     error='Recipe import rejected: '||NEW.rejection_reason
   WHERE revision_id IN (SELECT id FROM revisions WHERE request_id=NEW.id) AND status IN ('queued','leased');
 END;
