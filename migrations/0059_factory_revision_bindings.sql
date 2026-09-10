-- A repaired recipe revision derives immutable native input authority from its
-- reviewed parent. The binding is pending until human review; no approvals are
-- copied and publication must require status='reviewed'.
CREATE TABLE factory_revision_bindings (
  revision_id TEXT PRIMARY KEY REFERENCES revisions(id),
  source_revision_id TEXT NOT NULL REFERENCES revisions(id),
  cohort_id TEXT NOT NULL REFERENCES cohorts(id),
  status TEXT NOT NULL CHECK(status IN ('pending','reviewed')),
  created_by TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  reviewed_by TEXT,
  reviewed_at INTEGER,
  reason TEXT NOT NULL
);
CREATE INDEX factory_revision_bindings_source ON factory_revision_bindings(source_revision_id,cohort_id);
CREATE TRIGGER factory_revision_binding_identity_immutable BEFORE UPDATE ON factory_revision_bindings
WHEN NEW.revision_id IS NOT OLD.revision_id OR NEW.source_revision_id IS NOT OLD.source_revision_id OR NEW.cohort_id IS NOT OLD.cohort_id OR
 NEW.created_by IS NOT OLD.created_by OR NEW.created_at IS NOT OLD.created_at OR NEW.reason IS NOT OLD.reason
BEGIN SELECT RAISE(ABORT,'factory revision binding identity is immutable'); END;
CREATE TRIGGER factory_revision_binding_no_delete BEFORE DELETE ON factory_revision_bindings
BEGIN SELECT RAISE(ABORT,'factory revision bindings are retained evidence'); END;

CREATE TABLE factory_derived_input_locks (
  revision_id TEXT NOT NULL REFERENCES revisions(id),
  source_lock_sha256 TEXT NOT NULL REFERENCES input_locks(sha256),
  derived_lock_sha256 TEXT PRIMARY KEY REFERENCES input_locks(sha256),
  created_by TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  UNIQUE(revision_id,source_lock_sha256)
);
CREATE INDEX factory_derived_input_source ON factory_derived_input_locks(source_lock_sha256);
CREATE TRIGGER factory_derived_input_no_update BEFORE UPDATE ON factory_derived_input_locks
BEGIN SELECT RAISE(ABORT,'derived factory input bindings are immutable'); END;
CREATE TRIGGER factory_derived_input_no_delete BEFORE DELETE ON factory_derived_input_locks
BEGIN SELECT RAISE(ABORT,'derived factory input bindings are retained evidence'); END;

DROP TRIGGER input_selection_insert;
CREATE TRIGGER input_selection_insert BEFORE INSERT ON build_input_selections WHEN NOT EXISTS(
 SELECT 1 FROM current_input_locks l WHERE l.sha256=NEW.lock_sha256 AND l.recipe_revision_id=NEW.recipe_revision_id
 AND l.architecture=NEW.architecture AND l.cohort_id=NEW.cohort_id AND l.cohort_revision=NEW.cohort_revision)
 OR (NEW.selected_by<>'factory' AND NOT EXISTS(SELECT 1 FROM team_memberships WHERE 'github:'||github_id=NEW.selected_by AND team IN ('system','security','admin')))
 OR (NEW.selected_by='factory' AND NOT EXISTS(SELECT 1 FROM factory_revision_bindings WHERE revision_id=NEW.recipe_revision_id AND status IN ('pending','reviewed')))
 OR NOT EXISTS(SELECT 1 FROM cohorts WHERE id=NEW.cohort_id AND current_revision=NEW.cohort_revision AND phase IN ('plan','review','build'))
 OR EXISTS(SELECT 1 FROM builds WHERE revision_id=NEW.recipe_revision_id AND architecture=NEW.architecture AND status='leased' AND lease_expires_at>unixepoch())
BEGIN SELECT RAISE(ABORT,'input selection requires current approved lock'); END;

DROP TRIGGER input_selection_update;
CREATE TRIGGER input_selection_update BEFORE UPDATE ON build_input_selections WHEN
 NEW.recipe_revision_id IS NOT OLD.recipe_revision_id OR NEW.architecture IS NOT OLD.architecture OR NEW.cohort_id IS NOT OLD.cohort_id
 OR NEW.cohort_revision IS NOT OLD.cohort_revision OR NOT EXISTS(SELECT 1 FROM current_input_locks l WHERE l.sha256=NEW.lock_sha256
  AND l.recipe_revision_id=NEW.recipe_revision_id AND l.architecture=NEW.architecture AND l.cohort_id=NEW.cohort_id AND l.cohort_revision=NEW.cohort_revision)
 OR (NEW.selected_by<>'factory' AND NOT EXISTS(SELECT 1 FROM team_memberships WHERE 'github:'||github_id=NEW.selected_by AND team IN ('system','security','admin')))
 OR (NEW.selected_by='factory' AND NOT EXISTS(SELECT 1 FROM factory_revision_bindings WHERE revision_id=NEW.recipe_revision_id AND status IN ('pending','reviewed')))
 OR NOT EXISTS(SELECT 1 FROM cohorts WHERE id=NEW.cohort_id AND current_revision=NEW.cohort_revision AND phase IN ('plan','review','build'))
 OR EXISTS(SELECT 1 FROM builds WHERE revision_id=NEW.recipe_revision_id AND architecture=NEW.architecture AND status='leased' AND lease_expires_at>unixepoch())
BEGIN SELECT RAISE(ABORT,'input selection is unavailable or leased'); END;

DROP VIEW current_input_locks;
CREATE VIEW current_input_locks AS
 SELECT l.* FROM input_locks l JOIN revisions r ON r.id=l.recipe_revision_id JOIN requests q ON q.id=r.request_id
 JOIN cohorts c ON c.id=l.cohort_id AND c.current_revision=l.cohort_revision
 JOIN cohort_revisions scope ON scope.cohort_id=c.id AND scope.revision=c.current_revision
 JOIN cohort_members m ON m.cohort_id=c.id AND m.revision=c.current_revision AND m.recipe_revision_id=r.id
 JOIN catalog_packages p ON p.pkgbase=m.pkgbase AND p.current_revision=m.catalog_revision AND p.admitted_revision=m.catalog_revision
 JOIN authorized_catalog_inputs policy ON policy.pkgbase=p.pkgbase AND policy.revision=p.current_revision
 JOIN authorized_recipe_inputs reviewed ON reviewed.revision_id=r.id AND reviewed.manifest_sha256=r.manifest_sha256 AND reviewed.owner_area=policy.owner_area
 JOIN authorized_input_reviews inputs ON inputs.lock_sha256=l.sha256
 WHERE l.status='ready' AND c.condition IN ('ready','blocked') AND q.status IN ('review','queued','building','built','failed')
 AND json_extract(l.manifest_json,'$.recipeSha256')=r.recipe_sha256 AND json_extract(l.manifest_json,'$.cohortSha256')=scope.manifest_sha256
 AND r.id=(SELECT latest.id FROM revisions latest WHERE latest.request_id=q.id ORDER BY latest.created_at DESC,latest.rowid DESC LIMIT 1)
 AND NOT EXISTS(SELECT 1 FROM input_lock_packages pkg WHERE pkg.lock_sha256=l.sha256 AND l.purpose='owned' AND pkg.origin!='owned-build')
 AND NOT EXISTS(
  WITH RECURSIVE ancestry(digest) AS (
   SELECT l.sha256 UNION SELECT source.input_lock_sha256 FROM ancestry a JOIN input_lock_packages pkg ON pkg.lock_sha256=a.digest
    JOIN input_owned_packages source ON source.package_sha256=pkg.package_sha256 AND source.origin_evidence=pkg.origin_evidence
    WHERE pkg.origin='owned-build' LIMIT 4097
  )
  SELECT 1 WHERE (SELECT COUNT(*) FROM ancestry)>4096 OR EXISTS(
   SELECT 1 FROM ancestry a JOIN input_lock_packages pkg ON pkg.lock_sha256=a.digest WHERE pkg.origin='owned-build'
    AND NOT EXISTS(SELECT 1 FROM eligible_owned_inputs source WHERE source.package_sha256=pkg.package_sha256 AND source.origin_evidence=pkg.origin_evidence
     AND source.package_json=pkg.package_json))
 )
 UNION ALL
 SELECT l.* FROM input_locks l
 JOIN factory_revision_bindings binding ON binding.source_revision_id=l.recipe_revision_id AND binding.status IN ('pending','reviewed')
 JOIN revisions target ON target.id=binding.revision_id JOIN requests q ON q.id=target.request_id
 JOIN revisions source ON source.id=binding.source_revision_id
 JOIN cohorts c ON c.id=binding.cohort_id AND c.current_revision=l.cohort_revision
 JOIN cohort_revisions scope ON scope.cohort_id=c.id AND scope.revision=c.current_revision
 JOIN cohort_members m ON m.cohort_id=c.id AND m.revision=c.current_revision AND m.recipe_revision_id=source.id
 JOIN catalog_packages p ON p.pkgbase=m.pkgbase AND p.current_revision=m.catalog_revision AND p.admitted_revision=m.catalog_revision
 JOIN authorized_catalog_inputs policy ON policy.pkgbase=p.pkgbase AND policy.revision=p.current_revision
 JOIN authorized_recipe_inputs reviewed ON reviewed.revision_id=source.id AND reviewed.manifest_sha256=source.manifest_sha256 AND reviewed.owner_area=policy.owner_area
 JOIN authorized_input_reviews inputs ON inputs.lock_sha256=l.sha256
 WHERE l.status='ready' AND c.condition IN ('ready','blocked') AND q.status IN ('generating','review','queued','building','built','failed')
 AND json_extract(l.manifest_json,'$.recipeSha256')=source.recipe_sha256 AND json_extract(l.manifest_json,'$.cohortSha256')=scope.manifest_sha256
 AND target.id=(SELECT latest.id FROM revisions latest WHERE latest.request_id=q.id ORDER BY latest.created_at DESC,latest.rowid DESC LIMIT 1)
 AND NOT EXISTS(SELECT 1 FROM input_lock_packages pkg WHERE pkg.lock_sha256=l.sha256 AND l.purpose='owned' AND pkg.origin!='owned-build')
 AND NOT EXISTS(
  WITH RECURSIVE ancestry(digest) AS (
   SELECT l.sha256 UNION SELECT parent.input_lock_sha256 FROM ancestry a JOIN input_lock_packages pkg ON pkg.lock_sha256=a.digest
    JOIN input_owned_packages parent ON parent.package_sha256=pkg.package_sha256 AND parent.origin_evidence=pkg.origin_evidence
    WHERE pkg.origin='owned-build' LIMIT 4097
  )
  SELECT 1 WHERE (SELECT COUNT(*) FROM ancestry)>4096 OR EXISTS(
   SELECT 1 FROM ancestry a JOIN input_lock_packages pkg ON pkg.lock_sha256=a.digest WHERE pkg.origin='owned-build'
    AND NOT EXISTS(SELECT 1 FROM eligible_owned_inputs source WHERE source.package_sha256=pkg.package_sha256 AND source.origin_evidence=pkg.origin_evidence
     AND source.package_json=pkg.package_json)))
 UNION ALL
 SELECT l.* FROM input_locks l
 JOIN factory_derived_input_locks derived ON derived.derived_lock_sha256=l.sha256
 JOIN factory_revision_bindings binding ON binding.revision_id=derived.revision_id AND binding.status IN ('pending','reviewed')
 JOIN revisions target ON target.id=binding.revision_id
 JOIN revisions source ON source.id=binding.source_revision_id
 JOIN input_locks parent ON parent.sha256=derived.source_lock_sha256
 JOIN requests q ON q.id=target.request_id
 JOIN cohorts c ON c.id=l.cohort_id AND c.current_revision=l.cohort_revision
 JOIN cohort_revisions scope ON scope.cohort_id=c.id AND scope.revision=c.current_revision
 JOIN cohort_members m ON m.cohort_id=c.id AND m.revision=c.current_revision AND m.recipe_revision_id=source.id
 JOIN catalog_packages p ON p.pkgbase=m.pkgbase AND p.current_revision=m.catalog_revision AND p.admitted_revision=m.catalog_revision
 JOIN authorized_catalog_inputs policy ON policy.pkgbase=p.pkgbase AND policy.revision=p.current_revision
 JOIN authorized_recipe_inputs reviewed ON reviewed.revision_id=source.id AND reviewed.manifest_sha256=source.manifest_sha256 AND reviewed.owner_area=policy.owner_area
 JOIN authorized_input_reviews inputs ON inputs.lock_sha256=parent.sha256
 WHERE l.status='ready' AND parent.status='ready' AND c.condition IN ('ready','blocked') AND q.status IN ('generating','review','queued','building','built','failed')
 AND json_extract(l.manifest_json,'$.recipeSha256')=target.recipe_sha256 AND json_extract(l.manifest_json,'$.cohortSha256')=scope.manifest_sha256
 AND target.id=(SELECT latest.id FROM revisions latest WHERE latest.request_id=q.id ORDER BY latest.created_at DESC,latest.rowid DESC LIMIT 1)
 AND NOT EXISTS(SELECT 1 FROM input_lock_packages pkg WHERE pkg.lock_sha256=l.sha256 AND l.purpose='owned' AND pkg.origin!='owned-build')
 AND NOT EXISTS(
  WITH RECURSIVE ancestry(digest) AS (
   SELECT l.sha256 UNION SELECT ancestor.input_lock_sha256 FROM ancestry a JOIN input_lock_packages pkg ON pkg.lock_sha256=a.digest
    JOIN input_owned_packages ancestor ON ancestor.package_sha256=pkg.package_sha256 AND ancestor.origin_evidence=pkg.origin_evidence
    WHERE pkg.origin='owned-build' LIMIT 4097
  )
  SELECT 1 WHERE (SELECT COUNT(*) FROM ancestry)>4096 OR EXISTS(
   SELECT 1 FROM ancestry a JOIN input_lock_packages pkg ON pkg.lock_sha256=a.digest WHERE pkg.origin='owned-build'
    AND NOT EXISTS(SELECT 1 FROM eligible_owned_inputs source WHERE source.package_sha256=pkg.package_sha256 AND source.origin_evidence=pkg.origin_evidence
     AND source.package_json=pkg.package_json))
 );

DROP TRIGGER build_input_lock_current;
CREATE TRIGGER build_input_lock_current BEFORE UPDATE ON builds
WHEN NEW.status IN ('leased','succeeded') AND (
 NEW.input_lock_sha256 IS NOT NULL OR EXISTS(SELECT 1 FROM build_input_selections s WHERE
 (s.recipe_revision_id=NEW.revision_id OR s.recipe_revision_id=(SELECT source_revision_id FROM factory_revision_bindings WHERE revision_id=NEW.revision_id))
 AND s.architecture=NEW.architecture AND s.cohort_id=json_extract(NEW.output_contract_json,'$.cohort.id')
 AND s.cohort_revision=json_extract(NEW.output_contract_json,'$.cohort.revision')))
AND NOT EXISTS(SELECT 1 FROM current_input_locks l JOIN build_input_selections s ON s.lock_sha256=l.sha256
 WHERE l.sha256=NEW.input_lock_sha256 AND
 (s.recipe_revision_id=NEW.revision_id OR s.recipe_revision_id=(SELECT source_revision_id FROM factory_revision_bindings WHERE revision_id=NEW.revision_id))
 AND s.architecture=NEW.architecture AND s.cohort_id=json_extract(NEW.output_contract_json,'$.cohort.id')
 AND s.cohort_revision=json_extract(NEW.output_contract_json,'$.cohort.revision') AND NEW.dependency_plan_json IS NULL)
BEGIN SELECT RAISE(ABORT,'frozen input review or selection changed'); END;

DROP TRIGGER native_input_signing_current;
CREATE TRIGGER native_input_signing_current BEFORE UPDATE OF status ON signing_intents
WHEN NEW.status='signed' AND NEW.build_attempt IS NOT NULL AND EXISTS(SELECT 1 FROM builds b WHERE b.id=NEW.build_id AND b.input_lock_sha256 IS NOT NULL)
AND NOT EXISTS(SELECT 1 FROM builds b JOIN build_attempts a ON a.build_id=b.id AND a.attempt=b.attempt
 JOIN current_input_locks l ON l.sha256=b.input_lock_sha256 JOIN build_input_selections s ON s.lock_sha256=l.sha256
 WHERE b.id=NEW.build_id AND b.attempt=NEW.build_attempt AND a.input_lock_sha256=b.input_lock_sha256
 AND (s.recipe_revision_id=b.revision_id OR s.recipe_revision_id=(SELECT source_revision_id FROM factory_revision_bindings WHERE revision_id=b.revision_id))
 AND s.architecture=b.architecture AND s.cohort_id=l.cohort_id AND s.cohort_revision=l.cohort_revision)
BEGIN SELECT RAISE(ABORT,'frozen signing inputs are no longer authorized'); END;

DROP TRIGGER cohort_lease_phase;
CREATE TRIGGER cohort_lease_phase BEFORE UPDATE OF status,worker_id,lease_token ON builds
WHEN NEW.status='leased' AND EXISTS(
 SELECT 1 FROM cohort_recipe_ownership owned JOIN cohorts cohort ON cohort.id=owned.cohort_id
 WHERE owned.recipe_revision_id=NEW.revision_id AND (
  cohort.phase<>'build' OR cohort.condition NOT IN ('ready','blocked') OR NOT EXISTS(
   SELECT 1 FROM cohort_members member WHERE member.cohort_id=cohort.id
    AND member.revision=cohort.current_revision AND
    (member.recipe_revision_id=NEW.revision_id OR member.recipe_revision_id=(SELECT source_revision_id FROM factory_revision_bindings WHERE revision_id=NEW.revision_id)))))
BEGIN SELECT RAISE(ABORT,'cohort build phase changed before leasing'); END;

DROP TRIGGER preserved_build_lease;
CREATE TRIGGER preserved_build_lease BEFORE UPDATE ON builds
 WHEN NEW.status IN ('leased','succeeded') AND
   (NEW.preserved_inputs_json IS NOT NULL OR EXISTS(
     SELECT 1 FROM preserved_recipe_imports i
     WHERE i.revision_id=NEW.revision_id OR i.revision_id=(SELECT preserved_origin_revision_id FROM revisions WHERE id=NEW.revision_id)))
 AND (NEW.input_lock_sha256 IS NULL OR NEW.output_contract_json IS NULL OR NEW.dependency_plan_json IS NOT NULL OR
   NOT EXISTS(SELECT 1 FROM current_preserved_build_inputs i WHERE i.revision_id=NEW.revision_id AND i.architecture=NEW.architecture
     AND json_extract(i.inputs_json,'$.capture')=json_extract(NEW.preserved_inputs_json,'$.capture')
     AND json_extract(i.inputs_json,'$.sourceBundle')=json_extract(NEW.preserved_inputs_json,'$.sourceBundle')) OR
   NOT EXISTS(SELECT 1 FROM workers w WHERE w.id=NEW.worker_id AND w.status='active' AND w.architecture=NEW.architecture AND
     (SELECT COUNT(DISTINCT value) FROM json_each(w.capabilities_json) WHERE value IN ('preserved-recipe-v1','multi-output-v2','frozen-inputs-v1','runtime-analysis-v1'))=4))
 BEGIN SELECT RAISE(ABORT,'Preserved recipe builds require current sources and a capable frozen-input worker'); END;
