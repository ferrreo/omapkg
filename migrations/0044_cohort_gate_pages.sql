-- Candidate changes invalidate their own cohort; historical input and reviewer
-- revocations invalidate all verification conservatively.
-- ponytail: revocations use a global epoch; index ancestry if that becomes noisy.
CREATE TRIGGER distribution_assertion_discard AFTER INSERT ON distribution_assertions
 BEGIN DELETE FROM distribution_assertions WHERE rowid=NEW.rowid; END;
CREATE TABLE cohort_evidence_epoch (id INTEGER PRIMARY KEY CHECK(id=1),version INTEGER NOT NULL);
INSERT INTO cohort_evidence_epoch VALUES(1,0);
CREATE TABLE cohort_scope_epochs (cohort_id TEXT PRIMARY KEY REFERENCES cohorts(id),version INTEGER NOT NULL);
INSERT INTO cohort_scope_epochs SELECT id,0 FROM cohorts;
CREATE TRIGGER cohort_scope_epoch_created AFTER INSERT ON cohorts BEGIN INSERT INTO cohort_scope_epochs VALUES(NEW.id,0); END;
CREATE TABLE cohort_gate_pages (
 cohort_id TEXT NOT NULL,
 revision INTEGER NOT NULL,
 phase TEXT NOT NULL,
 epoch TEXT NOT NULL,
 page INTEGER NOT NULL CHECK(page>=0),
 member_count INTEGER NOT NULL CHECK(member_count BETWEEN 1 AND 25),
 blocker_count INTEGER NOT NULL CHECK(blocker_count>=0),
 report_json TEXT NOT NULL CHECK(json_valid(report_json)),
 digest TEXT NOT NULL,
 created_at INTEGER NOT NULL,
 PRIMARY KEY(cohort_id,revision,phase,epoch,page,digest),
 FOREIGN KEY(cohort_id,revision) REFERENCES cohort_revisions(cohort_id,revision),
 CHECK(member_count=json_extract(report_json,'$.memberCount')),
 CHECK(blocker_count=json_array_length(report_json,'$.blockers'))
);
CREATE INDEX cohort_gate_page_latest ON cohort_gate_pages(cohort_id,revision,phase,epoch,page);
CREATE TRIGGER cohort_gate_page_no_update BEFORE UPDATE ON cohort_gate_pages BEGIN SELECT RAISE(ABORT,'cohort page evidence is immutable'); END;
CREATE TRIGGER cohort_gate_page_no_delete BEFORE DELETE ON cohort_gate_pages BEGIN SELECT RAISE(ABORT,'cohort page evidence is immutable'); END;
CREATE TRIGGER cohort_epoch_catalog_revisions_update AFTER UPDATE ON catalog_revisions BEGIN UPDATE cohort_evidence_epoch SET version=version+1 WHERE id=1; END;
CREATE TRIGGER cohort_epoch_catalog_revisions_delete AFTER DELETE ON catalog_revisions BEGIN UPDATE cohort_evidence_epoch SET version=version+1 WHERE id=1; END;
CREATE TRIGGER cohort_epoch_revisions_update AFTER UPDATE ON revisions BEGIN UPDATE cohort_evidence_epoch SET version=version+1 WHERE id=1; END;
CREATE TRIGGER cohort_epoch_revisions_delete AFTER DELETE ON revisions BEGIN UPDATE cohort_evidence_epoch SET version=version+1 WHERE id=1; END;
CREATE TRIGGER cohort_epoch_input_objects_update AFTER UPDATE ON input_objects BEGIN UPDATE cohort_evidence_epoch SET version=version+1 WHERE id=1; END;
CREATE TRIGGER cohort_epoch_input_objects_delete AFTER DELETE ON input_objects BEGIN UPDATE cohort_evidence_epoch SET version=version+1 WHERE id=1; END;
CREATE TRIGGER cohort_epoch_input_documents_update AFTER UPDATE ON input_documents BEGIN UPDATE cohort_evidence_epoch SET version=version+1 WHERE id=1; END;
CREATE TRIGGER cohort_epoch_input_documents_delete AFTER DELETE ON input_documents BEGIN UPDATE cohort_evidence_epoch SET version=version+1 WHERE id=1; END;
CREATE TRIGGER cohort_epoch_input_lock_packages_update AFTER UPDATE ON input_lock_packages BEGIN UPDATE cohort_evidence_epoch SET version=version+1 WHERE id=1; END;
CREATE TRIGGER cohort_epoch_input_lock_packages_delete AFTER DELETE ON input_lock_packages BEGIN UPDATE cohort_evidence_epoch SET version=version+1 WHERE id=1; END;
CREATE TRIGGER cohort_epoch_input_owned_packages_update AFTER UPDATE ON input_owned_packages BEGIN UPDATE cohort_evidence_epoch SET version=version+1 WHERE id=1; END;
CREATE TRIGGER cohort_epoch_input_owned_packages_delete AFTER DELETE ON input_owned_packages BEGIN UPDATE cohort_evidence_epoch SET version=version+1 WHERE id=1; END;
CREATE TRIGGER cohort_epoch_build_attempts_update AFTER UPDATE ON build_attempts BEGIN UPDATE cohort_evidence_epoch SET version=version+1 WHERE id=1; END;
CREATE TRIGGER cohort_epoch_build_attempts_delete AFTER DELETE ON build_attempts BEGIN UPDATE cohort_evidence_epoch SET version=version+1 WHERE id=1; END;
CREATE TRIGGER cohort_epoch_build_attempt_results_update AFTER UPDATE ON build_attempt_results BEGIN UPDATE cohort_evidence_epoch SET version=version+1 WHERE id=1; END;
CREATE TRIGGER cohort_epoch_build_attempt_results_delete AFTER DELETE ON build_attempt_results BEGIN UPDATE cohort_evidence_epoch SET version=version+1 WHERE id=1; END;
CREATE TRIGGER cohort_epoch_recipe_source_bundles_update AFTER UPDATE ON recipe_source_bundles BEGIN UPDATE cohort_evidence_epoch SET version=version+1 WHERE id=1; END;
CREATE TRIGGER cohort_epoch_recipe_source_bundles_delete AFTER DELETE ON recipe_source_bundles BEGIN UPDATE cohort_evidence_epoch SET version=version+1 WHERE id=1; END;
CREATE TRIGGER cohort_epoch_preserved_recipe_imports_update AFTER UPDATE ON preserved_recipe_imports BEGIN UPDATE cohort_evidence_epoch SET version=version+1 WHERE id=1; END;
CREATE TRIGGER cohort_epoch_preserved_recipe_imports_delete AFTER DELETE ON preserved_recipe_imports BEGIN UPDATE cohort_evidence_epoch SET version=version+1 WHERE id=1; END;
CREATE TRIGGER cohort_epoch_input_lock_reviews_update AFTER UPDATE ON input_lock_reviews BEGIN UPDATE cohort_evidence_epoch SET version=version+1 WHERE id=1; END;
CREATE TRIGGER cohort_epoch_input_lock_reviews_delete AFTER DELETE ON input_lock_reviews BEGIN UPDATE cohort_evidence_epoch SET version=version+1 WHERE id=1; END;
CREATE TRIGGER cohort_epoch_approvals_update AFTER UPDATE ON approvals BEGIN UPDATE cohort_evidence_epoch SET version=version+1 WHERE id=1; END;
CREATE TRIGGER cohort_epoch_approvals_delete AFTER DELETE ON approvals BEGIN UPDATE cohort_evidence_epoch SET version=version+1 WHERE id=1; END;
CREATE TRIGGER cohort_epoch_catalog_reviews_update AFTER UPDATE ON catalog_reviews BEGIN UPDATE cohort_evidence_epoch SET version=version+1 WHERE id=1; END;
CREATE TRIGGER cohort_epoch_catalog_reviews_delete AFTER DELETE ON catalog_reviews BEGIN UPDATE cohort_evidence_epoch SET version=version+1 WHERE id=1; END;
CREATE TRIGGER cohort_epoch_team_memberships_update AFTER UPDATE ON team_memberships BEGIN UPDATE cohort_evidence_epoch SET version=version+1 WHERE id=1; END;
CREATE TRIGGER cohort_epoch_team_memberships_delete AFTER DELETE ON team_memberships BEGIN UPDATE cohort_evidence_epoch SET version=version+1 WHERE id=1; END;
CREATE TRIGGER cohort_epoch_workers_update AFTER UPDATE ON workers WHEN NEW.status IS NOT OLD.status OR NEW.public_key IS NOT OLD.public_key OR NEW.architecture IS NOT OLD.architecture OR NEW.capabilities_json IS NOT OLD.capabilities_json BEGIN UPDATE cohort_evidence_epoch SET version=version+1 WHERE id=1; END;
CREATE TRIGGER cohort_epoch_workers_delete AFTER DELETE ON workers BEGIN UPDATE cohort_evidence_epoch SET version=version+1 WHERE id=1; END;
CREATE TRIGGER cohort_epoch_build_images_update AFTER UPDATE ON build_images WHEN NEW.enabled IS NOT OLD.enabled OR NEW.image_ref IS NOT OLD.image_ref OR NEW.architecture IS NOT OLD.architecture BEGIN UPDATE cohort_evidence_epoch SET version=version+1 WHERE id=1; END;
CREATE TRIGGER cohort_epoch_build_images_delete AFTER DELETE ON build_images BEGIN UPDATE cohort_evidence_epoch SET version=version+1 WHERE id=1; END;
CREATE TRIGGER cohort_epoch_recipe_inspections_update AFTER UPDATE ON recipe_inspections WHEN NEW.status IS NOT OLD.status OR NEW.attempt IS NOT OLD.attempt BEGIN UPDATE cohort_evidence_epoch SET version=version+1 WHERE id=1; END;
CREATE TRIGGER cohort_epoch_recipe_inspections_delete AFTER DELETE ON recipe_inspections BEGIN UPDATE cohort_evidence_epoch SET version=version+1 WHERE id=1; END;
CREATE TRIGGER cohort_epoch_signing_intents_update AFTER UPDATE ON signing_intents WHEN OLD.status='signed' BEGIN UPDATE cohort_evidence_epoch SET version=version+1 WHERE id=1; END;
CREATE TRIGGER cohort_epoch_signing_intents_delete AFTER DELETE ON signing_intents WHEN OLD.status='signed' BEGIN UPDATE cohort_evidence_epoch SET version=version+1 WHERE id=1; END;
CREATE TRIGGER cohort_epoch_input_locks_update AFTER UPDATE ON input_locks WHEN OLD.status='ready' AND NEW.status IS NOT OLD.status BEGIN UPDATE cohort_evidence_epoch SET version=version+1 WHERE id=1; END;
CREATE TRIGGER cohort_epoch_input_locks_delete AFTER DELETE ON input_locks BEGIN UPDATE cohort_evidence_epoch SET version=version+1 WHERE id=1; END;
CREATE TRIGGER cohort_local_builds_insert AFTER INSERT ON builds BEGIN UPDATE cohort_scope_epochs SET version=version+1 WHERE cohort_id IN (SELECT cohort_id FROM cohort_recipe_ownership WHERE recipe_revision_id IN (NEW.revision_id)); END;
CREATE TRIGGER cohort_local_build_artifacts_insert AFTER INSERT ON build_artifacts BEGIN UPDATE cohort_scope_epochs SET version=version+1 WHERE cohort_id IN (SELECT o.cohort_id FROM builds b JOIN cohort_recipe_ownership o ON o.recipe_revision_id=b.revision_id WHERE b.id IN (NEW.build_id)); END;
CREATE TRIGGER cohort_local_requests_insert AFTER INSERT ON requests BEGIN UPDATE cohort_scope_epochs SET version=version+1 WHERE cohort_id IN (SELECT m.cohort_id FROM cohort_members m JOIN cohorts c ON c.id=m.cohort_id AND c.current_revision=m.revision JOIN revisions r ON r.id=m.recipe_revision_id WHERE r.request_id IN (NEW.id)); END;
CREATE TRIGGER cohort_local_catalog_packages_insert AFTER INSERT ON catalog_packages BEGIN UPDATE cohort_scope_epochs SET version=version+1 WHERE cohort_id IN (SELECT m.cohort_id FROM cohort_members m JOIN cohorts c ON c.id=m.cohort_id AND c.current_revision=m.revision WHERE m.pkgbase IN (NEW.pkgbase)); END;
CREATE TRIGGER cohort_local_build_input_selections_insert AFTER INSERT ON build_input_selections BEGIN UPDATE cohort_scope_epochs SET version=version+1 WHERE cohort_id IN (SELECT id FROM cohorts WHERE id IN (NEW.cohort_id)); END;
CREATE TRIGGER cohort_local_cohort_checks_insert AFTER INSERT ON cohort_checks BEGIN UPDATE cohort_scope_epochs SET version=version+1 WHERE cohort_id IN (SELECT id FROM cohorts WHERE id IN (NEW.cohort_id)); END;
CREATE TRIGGER cohort_local_builds_update AFTER UPDATE ON builds WHEN NEW.status IS NOT OLD.status OR NEW.attempt IS NOT OLD.attempt OR NEW.revision_id IS NOT OLD.revision_id OR NEW.architecture IS NOT OLD.architecture OR NEW.worker_id IS NOT OLD.worker_id OR NEW.smoke_passed IS NOT OLD.smoke_passed OR NEW.artifact_sha256 IS NOT OLD.artifact_sha256 OR NEW.provenance IS NOT OLD.provenance OR NEW.provenance_signature IS NOT OLD.provenance_signature OR NEW.installed_size IS NOT OLD.installed_size OR NEW.output_contract_json IS NOT OLD.output_contract_json OR NEW.input_lock_sha256 IS NOT OLD.input_lock_sha256 OR NEW.dependency_plan_json IS NOT OLD.dependency_plan_json OR NEW.preserved_inputs_json IS NOT OLD.preserved_inputs_json BEGIN UPDATE cohort_scope_epochs SET version=version+1 WHERE cohort_id IN (SELECT cohort_id FROM cohort_recipe_ownership WHERE recipe_revision_id IN (OLD.revision_id,NEW.revision_id)); END;
CREATE TRIGGER cohort_local_build_artifacts_update AFTER UPDATE ON build_artifacts BEGIN UPDATE cohort_scope_epochs SET version=version+1 WHERE cohort_id IN (SELECT o.cohort_id FROM builds b JOIN cohort_recipe_ownership o ON o.recipe_revision_id=b.revision_id WHERE b.id IN (OLD.build_id,NEW.build_id)); END;
CREATE TRIGGER cohort_local_requests_update AFTER UPDATE ON requests WHEN NEW.name IS NOT OLD.name OR NEW.upstream_url IS NOT OLD.upstream_url OR NEW.source_kind IS NOT OLD.source_kind OR NEW.area IS NOT OLD.area OR NEW.status IS NOT OLD.status OR NEW.catalog_pkgbase IS NOT OLD.catalog_pkgbase OR NEW.catalog_revision IS NOT OLD.catalog_revision OR NEW.preserved_import_id IS NOT OLD.preserved_import_id BEGIN UPDATE cohort_scope_epochs SET version=version+1 WHERE cohort_id IN (SELECT m.cohort_id FROM cohort_members m JOIN cohorts c ON c.id=m.cohort_id AND c.current_revision=m.revision JOIN revisions r ON r.id=m.recipe_revision_id WHERE r.request_id IN (OLD.id,NEW.id)); END;
CREATE TRIGGER cohort_local_catalog_packages_update AFTER UPDATE ON catalog_packages WHEN NEW.current_revision IS NOT OLD.current_revision OR NEW.admitted_revision IS NOT OLD.admitted_revision BEGIN UPDATE cohort_scope_epochs SET version=version+1 WHERE cohort_id IN (SELECT m.cohort_id FROM cohort_members m JOIN cohorts c ON c.id=m.cohort_id AND c.current_revision=m.revision WHERE m.pkgbase IN (OLD.pkgbase,NEW.pkgbase)); END;
CREATE TRIGGER cohort_local_build_input_selections_update AFTER UPDATE ON build_input_selections BEGIN UPDATE cohort_scope_epochs SET version=version+1 WHERE cohort_id IN (SELECT id FROM cohorts WHERE id IN (OLD.cohort_id,NEW.cohort_id)); END;
CREATE TRIGGER cohort_local_cohort_checks_update AFTER UPDATE ON cohort_checks BEGIN UPDATE cohort_scope_epochs SET version=version+1 WHERE cohort_id IN (SELECT id FROM cohorts WHERE id IN (OLD.cohort_id,NEW.cohort_id)); END;
CREATE TRIGGER cohort_local_builds_delete AFTER DELETE ON builds BEGIN UPDATE cohort_scope_epochs SET version=version+1 WHERE cohort_id IN (SELECT cohort_id FROM cohort_recipe_ownership WHERE recipe_revision_id IN (OLD.revision_id)); END;
CREATE TRIGGER cohort_local_build_artifacts_delete AFTER DELETE ON build_artifacts BEGIN UPDATE cohort_scope_epochs SET version=version+1 WHERE cohort_id IN (SELECT o.cohort_id FROM builds b JOIN cohort_recipe_ownership o ON o.recipe_revision_id=b.revision_id WHERE b.id IN (OLD.build_id)); END;
CREATE TRIGGER cohort_local_requests_delete AFTER DELETE ON requests BEGIN UPDATE cohort_scope_epochs SET version=version+1 WHERE cohort_id IN (SELECT m.cohort_id FROM cohort_members m JOIN cohorts c ON c.id=m.cohort_id AND c.current_revision=m.revision JOIN revisions r ON r.id=m.recipe_revision_id WHERE r.request_id IN (OLD.id)); END;
CREATE TRIGGER cohort_local_catalog_packages_delete AFTER DELETE ON catalog_packages BEGIN UPDATE cohort_scope_epochs SET version=version+1 WHERE cohort_id IN (SELECT m.cohort_id FROM cohort_members m JOIN cohorts c ON c.id=m.cohort_id AND c.current_revision=m.revision WHERE m.pkgbase IN (OLD.pkgbase)); END;
CREATE TRIGGER cohort_local_build_input_selections_delete AFTER DELETE ON build_input_selections BEGIN UPDATE cohort_scope_epochs SET version=version+1 WHERE cohort_id IN (SELECT id FROM cohorts WHERE id IN (OLD.cohort_id)); END;
CREATE TRIGGER cohort_local_cohort_checks_delete AFTER DELETE ON cohort_checks BEGIN UPDATE cohort_scope_epochs SET version=version+1 WHERE cohort_id IN (SELECT id FROM cohorts WHERE id IN (OLD.cohort_id)); END;
CREATE TRIGGER cohort_local_revisions_insert AFTER INSERT ON revisions BEGIN UPDATE cohort_scope_epochs SET version=version+1 WHERE cohort_id IN (SELECT m.cohort_id FROM cohort_members m JOIN cohorts c ON c.id=m.cohort_id AND c.current_revision=m.revision JOIN revisions r ON r.id=m.recipe_revision_id WHERE r.request_id IN (NEW.request_id)); END;
CREATE TRIGGER cohort_local_catalog_reviews_insert AFTER INSERT ON catalog_reviews BEGIN UPDATE cohort_scope_epochs SET version=version+1 WHERE cohort_id IN (SELECT m.cohort_id FROM cohort_members m JOIN cohorts c ON c.id=m.cohort_id AND c.current_revision=m.revision WHERE m.pkgbase IN (NEW.pkgbase)); END;
CREATE TRIGGER cohort_local_approvals_insert AFTER INSERT ON approvals BEGIN UPDATE cohort_scope_epochs SET version=version+1 WHERE cohort_id IN (SELECT cohort_id FROM cohort_recipe_ownership WHERE recipe_revision_id IN (NEW.revision_id)); END;
CREATE TRIGGER cohort_local_input_lock_reviews_insert AFTER INSERT ON input_lock_reviews BEGIN UPDATE cohort_scope_epochs SET version=version+1 WHERE cohort_id IN (SELECT cohort_id FROM input_locks WHERE sha256=NEW.lock_sha256); END;
CREATE TRIGGER cohort_local_build_attempts_insert AFTER INSERT ON build_attempts BEGIN UPDATE cohort_scope_epochs SET version=version+1 WHERE cohort_id IN (SELECT cohort_id FROM cohort_recipe_ownership WHERE recipe_revision_id IN (NEW.revision_id)); END;
CREATE TRIGGER cohort_local_build_attempt_results_insert AFTER INSERT ON build_attempt_results BEGIN UPDATE cohort_scope_epochs SET version=version+1 WHERE cohort_id IN (SELECT o.cohort_id FROM builds b JOIN cohort_recipe_ownership o ON o.recipe_revision_id=b.revision_id WHERE b.id=NEW.build_id); END;
CREATE TRIGGER cohort_local_preserved_recipe_imports_insert AFTER INSERT ON preserved_recipe_imports BEGIN UPDATE cohort_scope_epochs SET version=version+1 WHERE cohort_id IN (SELECT cohort_id FROM cohort_recipe_ownership WHERE recipe_revision_id IN (NEW.revision_id)); END;
CREATE TRIGGER cohort_local_cohorts_update AFTER UPDATE ON cohorts WHEN NEW.current_revision IS NOT OLD.current_revision OR (NEW.condition IN ('ready','blocked'))<>(OLD.condition IN ('ready','blocked')) BEGIN UPDATE cohort_scope_epochs SET version=version+1 WHERE cohort_id IN (SELECT NEW.id); END;
CREATE TRIGGER cohort_epoch_audit_events_update AFTER UPDATE ON audit_events WHEN NEW.action='revision.approved' OR OLD.action='revision.approved' BEGIN UPDATE cohort_evidence_epoch SET version=version+1 WHERE id=1; END;
CREATE TRIGGER cohort_epoch_audit_events_delete AFTER DELETE ON audit_events WHEN OLD.action='revision.approved' BEGIN UPDATE cohort_evidence_epoch SET version=version+1 WHERE id=1; END;
CREATE TRIGGER cohort_local_audit_events_insert AFTER INSERT ON audit_events WHEN NEW.action='revision.approved' BEGIN UPDATE cohort_scope_epochs SET version=version+1 WHERE cohort_id IN (SELECT cohort_id FROM cohort_recipe_ownership WHERE recipe_revision_id=json_extract(NEW.detail,'$.revisionId')); END;
CREATE TRIGGER cohort_local_dependency_blockers_insert AFTER INSERT ON dependency_blockers BEGIN UPDATE cohort_scope_epochs SET version=version+1 WHERE cohort_id IN (SELECT m.cohort_id FROM cohort_members m JOIN cohorts c ON c.id=m.cohort_id AND c.current_revision=m.revision JOIN revisions r ON r.id=m.recipe_revision_id WHERE r.request_id IN (NEW.request_id)); END;
CREATE TRIGGER cohort_local_dependency_blockers_update AFTER UPDATE ON dependency_blockers BEGIN UPDATE cohort_scope_epochs SET version=version+1 WHERE cohort_id IN (SELECT m.cohort_id FROM cohort_members m JOIN cohorts c ON c.id=m.cohort_id AND c.current_revision=m.revision JOIN revisions r ON r.id=m.recipe_revision_id WHERE r.request_id IN (OLD.request_id,NEW.request_id)); END;
CREATE TRIGGER cohort_local_dependency_blockers_delete AFTER DELETE ON dependency_blockers BEGIN UPDATE cohort_scope_epochs SET version=version+1 WHERE cohort_id IN (SELECT m.cohort_id FROM cohort_members m JOIN cohorts c ON c.id=m.cohort_id AND c.current_revision=m.revision JOIN revisions r ON r.id=m.recipe_revision_id WHERE r.request_id IN (OLD.request_id)); END;
