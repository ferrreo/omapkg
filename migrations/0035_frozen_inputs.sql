CREATE TABLE input_objects (
 sha256 TEXT PRIMARY KEY CHECK(length(sha256)=64), size INTEGER NOT NULL CHECK(size>0 AND size<=34359738368),
 object_key TEXT NOT NULL UNIQUE, created_by TEXT NOT NULL, created_at INTEGER NOT NULL
);
CREATE TRIGGER input_objects_no_update BEFORE UPDATE ON input_objects BEGIN SELECT RAISE(ABORT,'input objects are immutable'); END;
CREATE TRIGGER input_objects_no_delete BEFORE DELETE ON input_objects BEGIN SELECT RAISE(ABORT,'input objects are immutable'); END;
CREATE TABLE input_documents (
 sha256 TEXT PRIMARY KEY REFERENCES input_objects(sha256), canonical_json TEXT NOT NULL CHECK(length(CAST(canonical_json AS BLOB))<=1048576)
);
CREATE TRIGGER input_documents_no_update BEFORE UPDATE ON input_documents BEGIN SELECT RAISE(ABORT,'input documents are immutable'); END;
CREATE TRIGGER input_documents_no_delete BEFORE DELETE ON input_documents BEGIN SELECT RAISE(ABORT,'input documents are immutable'); END;

CREATE TABLE input_uploads (
 id TEXT PRIMARY KEY, sha256 TEXT NOT NULL, size INTEGER NOT NULL, object_key TEXT NOT NULL UNIQUE, r2_upload_id TEXT NOT NULL,
 created_by TEXT NOT NULL, created_at INTEGER NOT NULL, status TEXT NOT NULL CHECK(status IN ('active','verifying','complete','failed')),
 expires_at INTEGER NOT NULL
);
CREATE UNIQUE INDEX input_upload_active ON input_uploads(sha256,created_by) WHERE status IN ('active','verifying');
CREATE TABLE input_upload_parts (
 upload_id TEXT NOT NULL REFERENCES input_uploads(id), part_number INTEGER NOT NULL CHECK(part_number BETWEEN 1 AND 4096),
 size INTEGER NOT NULL, sha256 TEXT NOT NULL, etag TEXT NOT NULL, PRIMARY KEY(upload_id,part_number)
);
CREATE TRIGGER input_upload_parts_no_update BEFORE UPDATE ON input_upload_parts BEGIN SELECT RAISE(ABORT,'input upload parts are immutable'); END;

CREATE TABLE input_locks (
 sha256 TEXT PRIMARY KEY REFERENCES input_objects(sha256), recipe_revision_id TEXT NOT NULL REFERENCES revisions(id),
 cohort_id TEXT NOT NULL, cohort_revision INTEGER NOT NULL, architecture TEXT NOT NULL CHECK(architecture IN ('x86_64','aarch64')),
 purpose TEXT NOT NULL CHECK(purpose IN ('bootstrap','owned')), manifest_json TEXT NOT NULL,
 object_count INTEGER NOT NULL, package_count INTEGER NOT NULL, transfer_bytes INTEGER NOT NULL,
 status TEXT NOT NULL CHECK(status IN ('preparing','ready')), created_by TEXT NOT NULL, created_at INTEGER NOT NULL, reason TEXT NOT NULL,
 FOREIGN KEY(cohort_id,cohort_revision) REFERENCES cohort_revisions(cohort_id,revision)
);
CREATE TABLE input_lock_objects (
 lock_sha256 TEXT NOT NULL REFERENCES input_locks(sha256), object_sha256 TEXT NOT NULL REFERENCES input_objects(sha256),
 PRIMARY KEY(lock_sha256,object_sha256)
);
CREATE TABLE input_lock_packages (
 lock_sha256 TEXT NOT NULL REFERENCES input_locks(sha256), package_sha256 TEXT NOT NULL REFERENCES input_objects(sha256),
 origin TEXT NOT NULL CHECK(origin IN ('external-bootstrap','owned-build')), origin_evidence TEXT NOT NULL REFERENCES input_objects(sha256),
 package_json TEXT NOT NULL, PRIMARY KEY(lock_sha256,package_sha256,origin_evidence)
);
CREATE INDEX input_package_identity ON input_lock_packages(lock_sha256,json_extract(package_json,'$.name'),json_extract(package_json,'$.version'),json_extract(package_json,'$.architecture'));
CREATE TRIGGER input_lock_header_immutable BEFORE UPDATE ON input_locks
WHEN OLD.status='ready' OR NEW.sha256 IS NOT OLD.sha256 OR NEW.recipe_revision_id IS NOT OLD.recipe_revision_id
 OR NEW.cohort_id IS NOT OLD.cohort_id OR NEW.cohort_revision IS NOT OLD.cohort_revision OR NEW.architecture IS NOT OLD.architecture
 OR NEW.purpose IS NOT OLD.purpose OR NEW.manifest_json IS NOT OLD.manifest_json OR NEW.object_count IS NOT OLD.object_count
 OR NEW.package_count IS NOT OLD.package_count OR NEW.transfer_bytes IS NOT OLD.transfer_bytes OR NEW.created_by IS NOT OLD.created_by
 OR NEW.created_at IS NOT OLD.created_at OR NEW.reason IS NOT OLD.reason
BEGIN SELECT RAISE(ABORT,'input lock is immutable'); END;
CREATE TRIGGER input_lock_no_delete BEFORE DELETE ON input_locks BEGIN SELECT RAISE(ABORT,'input lock is immutable'); END;
CREATE TRIGGER input_lock_objects_insert BEFORE INSERT ON input_lock_objects WHEN (SELECT status FROM input_locks WHERE sha256=NEW.lock_sha256)!='preparing'
BEGIN SELECT RAISE(ABORT,'input lock is sealed'); END;
CREATE TRIGGER input_lock_objects_update BEFORE UPDATE ON input_lock_objects BEGIN SELECT RAISE(ABORT,'input lock objects are immutable'); END;
CREATE TRIGGER input_lock_objects_delete BEFORE DELETE ON input_lock_objects BEGIN SELECT RAISE(ABORT,'input lock objects are immutable'); END;
CREATE TRIGGER input_lock_packages_insert BEFORE INSERT ON input_lock_packages WHEN (SELECT status FROM input_locks WHERE sha256=NEW.lock_sha256)!='preparing'
BEGIN SELECT RAISE(ABORT,'input lock is sealed'); END;
CREATE TRIGGER input_lock_packages_update BEFORE UPDATE ON input_lock_packages BEGIN SELECT RAISE(ABORT,'input lock packages are immutable'); END;
CREATE TRIGGER input_lock_packages_delete BEFORE DELETE ON input_lock_packages BEGIN SELECT RAISE(ABORT,'input lock packages are immutable'); END;
CREATE TRIGGER input_lock_seal BEFORE UPDATE OF status ON input_locks WHEN NEW.status='ready' AND (
 NEW.object_count!=(SELECT COUNT(*) FROM input_lock_objects WHERE lock_sha256=NEW.sha256)
 OR NEW.package_count!=(SELECT COUNT(*) FROM input_lock_packages WHERE lock_sha256=NEW.sha256))
BEGIN SELECT RAISE(ABORT,'input lock index is incomplete'); END;

CREATE TABLE input_lock_reviews (
 id TEXT PRIMARY KEY, lock_sha256 TEXT NOT NULL REFERENCES input_locks(sha256), kind TEXT NOT NULL CHECK(kind IN ('area','security')),
 actor TEXT NOT NULL, reason TEXT NOT NULL, created_at INTEGER NOT NULL, revoked_at INTEGER, revoke_reason TEXT
);
CREATE UNIQUE INDEX input_lock_review_kind ON input_lock_reviews(lock_sha256,kind) WHERE revoked_at IS NULL;
CREATE UNIQUE INDEX input_lock_review_actor ON input_lock_reviews(lock_sha256,actor) WHERE revoked_at IS NULL;
CREATE TRIGGER input_review_immutable BEFORE UPDATE ON input_lock_reviews
WHEN NEW.id IS NOT OLD.id OR NEW.lock_sha256 IS NOT OLD.lock_sha256 OR NEW.kind IS NOT OLD.kind OR NEW.actor IS NOT OLD.actor
 OR NEW.reason IS NOT OLD.reason OR NEW.created_at IS NOT OLD.created_at OR OLD.revoked_at IS NOT NULL OR NEW.revoked_at IS NULL
BEGIN SELECT RAISE(ABORT,'input review is immutable except revocation'); END;
CREATE TRIGGER input_review_no_delete BEFORE DELETE ON input_lock_reviews BEGIN SELECT RAISE(ABORT,'input review history is immutable'); END;
CREATE TRIGGER input_review_authorized BEFORE INSERT ON input_lock_reviews WHEN
 NOT EXISTS(SELECT 1 FROM input_locks WHERE sha256=NEW.lock_sha256 AND status='ready') OR
 NOT EXISTS(SELECT 1 FROM team_memberships t WHERE NEW.actor='github:'||t.github_id AND
 (t.team IN ('admin','security') OR (NEW.kind='area' AND t.team='system')))
BEGIN SELECT RAISE(ABORT,'input review requires current human authority'); END;

-- Aggregate views keep authorization below D1's expression-depth limit even
-- when a claim or trigger validates a retained input's native ancestry.
CREATE VIEW authorized_input_reviews AS
 SELECT review.lock_sha256 FROM input_lock_reviews review JOIN team_memberships t ON review.actor='github:'||t.github_id
 WHERE review.revoked_at IS NULL AND (t.team IN ('admin','security') OR (review.kind='area' AND t.team='system'))
 GROUP BY review.lock_sha256 HAVING COUNT(DISTINCT review.kind)=2 AND COUNT(DISTINCT review.actor)=2;
CREATE VIEW authorized_catalog_inputs AS
 SELECT policy.pkgbase,policy.revision,policy.manifest_sha256,policy.owner_area FROM catalog_revisions policy
 JOIN catalog_reviews review ON review.pkgbase=policy.pkgbase AND review.revision=policy.revision AND review.manifest_sha256=policy.manifest_sha256
 JOIN team_memberships t ON review.actor='github:'||t.github_id
 WHERE t.team IN ('admin','security') OR (review.kind='area' AND t.team=policy.owner_area)
 GROUP BY policy.pkgbase,policy.revision HAVING COUNT(DISTINCT review.kind)=2 AND COUNT(DISTINCT review.actor)=2;
CREATE VIEW authorized_recipe_inputs AS
 SELECT review.revision_id,review.manifest_sha256,policy.owner_area FROM approvals review
 JOIN cohort_members m ON m.recipe_revision_id=review.revision_id
 JOIN catalog_revisions policy ON policy.pkgbase=m.pkgbase AND policy.revision=m.catalog_revision
 JOIN team_memberships t ON review.actor='github:'||t.github_id
 WHERE review.revoked_at IS NULL AND (t.team IN ('admin','security') OR (review.kind='area' AND t.team=policy.owner_area))
 GROUP BY review.revision_id,review.manifest_sha256,policy.owner_area HAVING COUNT(DISTINCT review.kind)=2 AND COUNT(DISTINCT review.actor)=2;

-- Current identity and review authority are checked again at lease and signing time.
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
 );

CREATE TABLE build_input_selections (
 recipe_revision_id TEXT NOT NULL REFERENCES revisions(id), architecture TEXT NOT NULL,
 cohort_id TEXT NOT NULL, cohort_revision INTEGER NOT NULL, lock_sha256 TEXT NOT NULL REFERENCES input_locks(sha256),
 selected_by TEXT NOT NULL, selected_at INTEGER NOT NULL,
 PRIMARY KEY(recipe_revision_id,architecture,cohort_id,cohort_revision)
);
CREATE TRIGGER input_selection_insert BEFORE INSERT ON build_input_selections WHEN NOT EXISTS(
 SELECT 1 FROM current_input_locks l WHERE l.sha256=NEW.lock_sha256 AND l.recipe_revision_id=NEW.recipe_revision_id
 AND l.architecture=NEW.architecture AND l.cohort_id=NEW.cohort_id AND l.cohort_revision=NEW.cohort_revision)
 OR NOT EXISTS(SELECT 1 FROM team_memberships WHERE 'github:'||github_id=NEW.selected_by AND team IN ('system','security','admin'))
 OR NOT EXISTS(SELECT 1 FROM cohorts WHERE id=NEW.cohort_id AND current_revision=NEW.cohort_revision AND phase IN ('plan','review','build'))
 OR EXISTS(SELECT 1 FROM builds WHERE revision_id=NEW.recipe_revision_id AND architecture=NEW.architecture AND status='leased' AND lease_expires_at>unixepoch())
BEGIN SELECT RAISE(ABORT,'input selection requires current approved lock'); END;
CREATE TRIGGER input_selection_update BEFORE UPDATE ON build_input_selections WHEN
 NEW.recipe_revision_id IS NOT OLD.recipe_revision_id OR NEW.architecture IS NOT OLD.architecture OR NEW.cohort_id IS NOT OLD.cohort_id
 OR NEW.cohort_revision IS NOT OLD.cohort_revision OR NOT EXISTS(SELECT 1 FROM current_input_locks l WHERE l.sha256=NEW.lock_sha256
  AND l.recipe_revision_id=NEW.recipe_revision_id AND l.architecture=NEW.architecture AND l.cohort_id=NEW.cohort_id AND l.cohort_revision=NEW.cohort_revision)
 OR NOT EXISTS(SELECT 1 FROM team_memberships WHERE 'github:'||github_id=NEW.selected_by AND team IN ('system','security','admin'))
 OR NOT EXISTS(SELECT 1 FROM cohorts WHERE id=NEW.cohort_id AND current_revision=NEW.cohort_revision AND phase IN ('plan','review','build'))
 OR EXISTS(SELECT 1 FROM builds WHERE revision_id=NEW.recipe_revision_id AND architecture=NEW.architecture AND status='leased' AND lease_expires_at>unixepoch())
BEGIN SELECT RAISE(ABORT,'input selection is unavailable or leased'); END;
CREATE TRIGGER input_selection_no_delete BEFORE DELETE ON build_input_selections BEGIN SELECT RAISE(ABORT,'input selection cannot fall back to live inputs'); END;

ALTER TABLE builds ADD COLUMN input_lock_sha256 TEXT REFERENCES input_locks(sha256);
ALTER TABLE build_attempts ADD COLUMN input_lock_sha256 TEXT REFERENCES input_locks(sha256);
DROP TRIGGER build_attempt_start;
CREATE TRIGGER build_attempt_start AFTER UPDATE ON builds WHEN NEW.status='leased' AND NEW.attempt>OLD.attempt
BEGIN
 INSERT INTO build_attempts(build_id,attempt,revision_id,architecture,worker_id,worker_public_key,started_at,output_contract_json,dependency_plan_json,input_lock_sha256)
 SELECT NEW.id,NEW.attempt,NEW.revision_id,NEW.architecture,NEW.worker_id,w.public_key,NEW.started_at,NEW.output_contract_json,NEW.dependency_plan_json,NEW.input_lock_sha256
 FROM workers w WHERE w.id=NEW.worker_id;
END;
CREATE TRIGGER build_input_lock_fenced BEFORE UPDATE OF input_lock_sha256 ON builds
WHEN OLD.status='leased' AND OLD.lease_expires_at>unixepoch() AND NEW.status='leased' AND NEW.input_lock_sha256 IS NOT OLD.input_lock_sha256
BEGIN SELECT RAISE(ABORT,'leased input lock is immutable'); END;
CREATE TRIGGER build_input_lock_current BEFORE UPDATE ON builds
WHEN NEW.status IN ('leased','succeeded') AND (
 NEW.input_lock_sha256 IS NOT NULL OR EXISTS(SELECT 1 FROM build_input_selections s WHERE s.recipe_revision_id=NEW.revision_id
 AND s.architecture=NEW.architecture AND s.cohort_id=json_extract(NEW.output_contract_json,'$.cohort.id')
 AND s.cohort_revision=json_extract(NEW.output_contract_json,'$.cohort.revision')))
AND NOT EXISTS(SELECT 1 FROM current_input_locks l JOIN build_input_selections s ON s.lock_sha256=l.sha256
 WHERE l.sha256=NEW.input_lock_sha256 AND s.recipe_revision_id=NEW.revision_id AND s.architecture=NEW.architecture
 AND s.cohort_id=json_extract(NEW.output_contract_json,'$.cohort.id') AND s.cohort_revision=json_extract(NEW.output_contract_json,'$.cohort.revision')
 AND NEW.dependency_plan_json IS NULL)
BEGIN SELECT RAISE(ABORT,'frozen input review or selection changed'); END;
CREATE TRIGGER native_input_signing_current BEFORE UPDATE OF status ON signing_intents
WHEN NEW.status='signed' AND NEW.build_attempt IS NOT NULL AND EXISTS(SELECT 1 FROM builds b WHERE b.id=NEW.build_id AND b.input_lock_sha256 IS NOT NULL)
AND NOT EXISTS(SELECT 1 FROM builds b JOIN build_attempts a ON a.build_id=b.id AND a.attempt=b.attempt
 JOIN current_input_locks l ON l.sha256=b.input_lock_sha256 JOIN build_input_selections s ON s.lock_sha256=l.sha256
 WHERE b.id=NEW.build_id AND b.attempt=NEW.build_attempt AND a.input_lock_sha256=b.input_lock_sha256
 AND s.recipe_revision_id=b.revision_id AND s.architecture=b.architecture AND s.cohort_id=l.cohort_id AND s.cohort_revision=l.cohort_revision)
BEGIN SELECT RAISE(ABORT,'frozen signing inputs are no longer authorized'); END;

-- Only the native-signing service can mint this registry entry. Old signed
-- versions remain usable after a newer recipe is proposed; revocations do not.
CREATE TABLE input_owned_packages (
 package_sha256 TEXT NOT NULL REFERENCES input_objects(sha256), origin_evidence TEXT NOT NULL REFERENCES input_objects(sha256),
 package_json TEXT NOT NULL, build_id TEXT NOT NULL, attempt INTEGER NOT NULL,
 input_lock_sha256 TEXT NOT NULL REFERENCES input_locks(sha256), package_intent_id TEXT NOT NULL REFERENCES signing_intents(id),
 statement_intent_id TEXT NOT NULL REFERENCES signing_intents(id), created_by TEXT NOT NULL, created_at INTEGER NOT NULL,
 revoked_at INTEGER, revoke_reason TEXT, PRIMARY KEY(package_sha256,origin_evidence),
 FOREIGN KEY(build_id,attempt) REFERENCES build_attempts(build_id,attempt)
);
CREATE INDEX owned_package_identity ON input_owned_packages(json_extract(package_json,'$.name'),json_extract(package_json,'$.version'),json_extract(package_json,'$.architecture'));
CREATE TRIGGER owned_input_immutable BEFORE UPDATE ON input_owned_packages
WHEN NEW.package_sha256 IS NOT OLD.package_sha256 OR NEW.origin_evidence IS NOT OLD.origin_evidence OR NEW.package_json IS NOT OLD.package_json
 OR NEW.build_id IS NOT OLD.build_id OR NEW.attempt IS NOT OLD.attempt OR NEW.input_lock_sha256 IS NOT OLD.input_lock_sha256
 OR NEW.package_intent_id IS NOT OLD.package_intent_id OR NEW.statement_intent_id IS NOT OLD.statement_intent_id
 OR NEW.created_by IS NOT OLD.created_by OR NEW.created_at IS NOT OLD.created_at OR OLD.revoked_at IS NOT NULL OR NEW.revoked_at IS NULL
BEGIN SELECT RAISE(ABORT,'owned input origin is immutable except revocation'); END;
CREATE TRIGGER owned_input_no_delete BEFORE DELETE ON input_owned_packages BEGIN SELECT RAISE(ABORT,'owned input origin is immutable'); END;
CREATE VIEW eligible_owned_inputs AS
 SELECT p.* FROM input_owned_packages p JOIN build_attempts a ON a.build_id=p.build_id AND a.attempt=p.attempt AND a.input_lock_sha256=p.input_lock_sha256
 JOIN build_attempt_results result ON result.build_id=a.build_id AND result.attempt=a.attempt AND result.status='succeeded'
 JOIN workers w ON w.id=a.worker_id AND w.public_key=a.worker_public_key AND w.status='active'
 JOIN revisions r ON r.id=a.revision_id JOIN cohort_members m ON m.recipe_revision_id=r.id
  AND m.cohort_id=json_extract(a.output_contract_json,'$.cohort.id') AND m.revision=json_extract(a.output_contract_json,'$.cohort.revision')
 JOIN authorized_catalog_inputs policy ON policy.pkgbase=m.pkgbase AND policy.revision=m.catalog_revision
 JOIN authorized_recipe_inputs reviewed ON reviewed.revision_id=r.id AND reviewed.manifest_sha256=r.manifest_sha256 AND reviewed.owner_area=policy.owner_area
 JOIN input_locks l ON l.sha256=a.input_lock_sha256 AND l.status='ready'
 JOIN authorized_input_reviews inputs ON inputs.lock_sha256=l.sha256
 JOIN signing_intents pkg ON pkg.id=p.package_intent_id AND pkg.status='signed' AND pkg.object_kind='package'
  AND pkg.build_id=a.build_id AND pkg.build_attempt=a.attempt AND pkg.artifact_sha256=p.package_sha256
 JOIN signing_intents statement ON statement.id=p.statement_intent_id AND statement.status='signed' AND statement.object_kind='attestation'
  AND statement.build_id=a.build_id AND statement.build_attempt=a.attempt
 WHERE p.revoked_at IS NULL
;
CREATE TRIGGER owned_input_authorized AFTER INSERT ON input_owned_packages
WHEN NOT EXISTS(SELECT 1 FROM eligible_owned_inputs WHERE package_sha256=NEW.package_sha256 AND origin_evidence=NEW.origin_evidence)
BEGIN SELECT RAISE(ABORT,'owned input requires signed native frozen output'); END;
