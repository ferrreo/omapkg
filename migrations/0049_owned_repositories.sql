-- Owned repository objects are immutable package/database records. Channel
-- membership is a separate append-only relation so promotion never rewrites
-- an artifact or database that another release already references.
CREATE TABLE owned_repository_artifacts (
  id TEXT PRIMARY KEY,
  collection TEXT NOT NULL CHECK(collection IN ('core','extra','multilib','omarchy','omapkg')),
  target_architecture TEXT NOT NULL CHECK(target_architecture IN ('x86_64','aarch64')),
  name TEXT NOT NULL,
  version TEXT NOT NULL,
  architecture TEXT NOT NULL CHECK(architecture IN ('x86_64','aarch64','any')),
  pkgbase TEXT NOT NULL,
  filename TEXT NOT NULL,
  artifact_key TEXT NOT NULL,
  artifact_sha256 TEXT NOT NULL CHECK(length(artifact_sha256)=64),
  artifact_size INTEGER NOT NULL CHECK(artifact_size>0),
  metadata_json TEXT NOT NULL CHECK(json_valid(metadata_json)),
  description TEXT NOT NULL,
  license TEXT NOT NULL,
  upstream_url TEXT NOT NULL,
  source_date_epoch INTEGER NOT NULL,
  rebuild_on_json TEXT NOT NULL CHECK(json_valid(rebuild_on_json)),
  abi_inventory_ref TEXT,
  signature_key TEXT NOT NULL,
  signature_sha256 TEXT NOT NULL CHECK(length(signature_sha256)=64),
  attestation_key TEXT NOT NULL,
  attestation_sha256 TEXT NOT NULL CHECK(length(attestation_sha256)=64),
  attestation_size INTEGER NOT NULL CHECK(attestation_size>0),
  attestation_signature_key TEXT NOT NULL,
  attestation_signature_sha256 TEXT NOT NULL CHECK(length(attestation_signature_sha256)=64),
  build_id TEXT NOT NULL,
  build_attempt INTEGER NOT NULL CHECK(build_attempt>0),
  revision_id TEXT NOT NULL,
  cohort_id TEXT NOT NULL,
  cohort_revision INTEGER NOT NULL CHECK(cohort_revision>0),
  created_at INTEGER NOT NULL,
  UNIQUE(target_architecture,filename)
);
CREATE INDEX owned_repository_artifact_identity ON owned_repository_artifacts(target_architecture,name,version,architecture);
CREATE INDEX owned_repository_artifact_collection ON owned_repository_artifacts(collection,target_architecture,created_at);
CREATE TRIGGER owned_repository_artifact_no_update BEFORE UPDATE ON owned_repository_artifacts
BEGIN SELECT RAISE(ABORT,'owned repository artifacts are immutable'); END;
CREATE TRIGGER owned_repository_artifact_no_delete BEFORE DELETE ON owned_repository_artifacts
BEGIN SELECT RAISE(ABORT,'owned repository artifacts are immutable'); END;

CREATE TABLE owned_repository_snapshots (
  id TEXT PRIMARY KEY,
  lane TEXT NOT NULL CHECK(lane IN ('system','opr')),
  release_id TEXT NOT NULL,
  architecture TEXT NOT NULL CHECK(architecture IN ('x86_64','aarch64')),
  collection TEXT NOT NULL CHECK(collection IN ('core','extra','multilib','omarchy','omapkg')),
  db_filename TEXT NOT NULL,
  db_key TEXT NOT NULL UNIQUE,
  db_sha256 TEXT NOT NULL CHECK(length(db_sha256)=64),
  db_size INTEGER NOT NULL CHECK(db_size>0),
  db_signature_key TEXT NOT NULL,
  db_signature_sha256 TEXT NOT NULL CHECK(length(db_signature_sha256)=64),
  filename_map_key TEXT NOT NULL UNIQUE,
  filename_map_sha256 TEXT NOT NULL CHECK(length(filename_map_sha256)=64),
  filename_map_size INTEGER NOT NULL CHECK(filename_map_size>0),
  package_count INTEGER NOT NULL CHECK(package_count>=0),
  status TEXT NOT NULL DEFAULT 'prepared' CHECK(status IN ('prepared','published','superseded')),
  created_at INTEGER NOT NULL,
  UNIQUE(lane,release_id,architecture,collection)
);
CREATE INDEX owned_repository_snapshot_lookup ON owned_repository_snapshots(lane,release_id,architecture,collection,status);
CREATE TRIGGER owned_repository_snapshot_no_update BEFORE UPDATE ON owned_repository_snapshots
WHEN NEW.id IS NOT OLD.id OR NEW.lane IS NOT OLD.lane OR NEW.release_id IS NOT OLD.release_id OR
 NEW.architecture IS NOT OLD.architecture OR NEW.collection IS NOT OLD.collection OR NEW.db_filename IS NOT OLD.db_filename OR
 NEW.db_key IS NOT OLD.db_key OR NEW.db_sha256 IS NOT OLD.db_sha256 OR NEW.db_size IS NOT OLD.db_size OR
 NEW.db_signature_key IS NOT OLD.db_signature_key OR NEW.db_signature_sha256 IS NOT OLD.db_signature_sha256 OR
 NEW.filename_map_key IS NOT OLD.filename_map_key OR NEW.filename_map_sha256 IS NOT OLD.filename_map_sha256 OR
 NEW.filename_map_size IS NOT OLD.filename_map_size OR NEW.package_count IS NOT OLD.package_count OR NEW.created_at IS NOT OLD.created_at OR
 OLD.status NOT IN ('prepared') OR NEW.status NOT IN ('published','superseded')
BEGIN SELECT RAISE(ABORT,'owned repository snapshots are immutable'); END;
CREATE TRIGGER owned_repository_snapshot_no_delete BEFORE DELETE ON owned_repository_snapshots
BEGIN SELECT RAISE(ABORT,'owned repository snapshots are immutable'); END;

CREATE TABLE owned_repository_snapshot_packages (
  snapshot_id TEXT NOT NULL REFERENCES owned_repository_snapshots(id),
  artifact_id TEXT NOT NULL REFERENCES owned_repository_artifacts(id),
  ordinal INTEGER NOT NULL CHECK(ordinal>=0),
  filename TEXT NOT NULL,
  artifact_sha256 TEXT NOT NULL CHECK(length(artifact_sha256)=64),
  PRIMARY KEY(snapshot_id,artifact_id),
  UNIQUE(snapshot_id,ordinal),
  UNIQUE(snapshot_id,filename)
);
CREATE INDEX owned_repository_snapshot_packages_artifact ON owned_repository_snapshot_packages(artifact_id);
CREATE TRIGGER owned_repository_snapshot_package_no_update BEFORE UPDATE ON owned_repository_snapshot_packages
BEGIN SELECT RAISE(ABORT,'owned repository snapshot membership is immutable'); END;
CREATE TRIGGER owned_repository_snapshot_package_no_delete BEFORE DELETE ON owned_repository_snapshot_packages
BEGIN SELECT RAISE(ABORT,'owned repository snapshot membership is immutable'); END;

CREATE TABLE owned_repository_memberships (
  id TEXT PRIMARY KEY,
  snapshot_id TEXT NOT NULL REFERENCES owned_repository_snapshots(id),
  lane TEXT NOT NULL CHECK(lane IN ('system','opr')),
  release_id TEXT NOT NULL,
  channel TEXT NOT NULL CHECK(channel IN ('edge','rc','stable','quarantine')),
  status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','superseded','withdrawn')),
  created_at INTEGER NOT NULL,
  UNIQUE(snapshot_id,release_id,channel)
);
CREATE INDEX owned_repository_membership_current ON owned_repository_memberships(lane,release_id,channel,status);
CREATE TRIGGER owned_repository_membership_no_update BEFORE UPDATE ON owned_repository_memberships
BEGIN SELECT RAISE(ABORT,'owned repository channel membership is immutable'); END;
CREATE TRIGGER owned_repository_membership_no_delete BEFORE DELETE ON owned_repository_memberships
BEGIN SELECT RAISE(ABORT,'owned repository channel membership is immutable'); END;

CREATE TABLE owned_repository_package_chunks (
  id TEXT PRIMARY KEY,
  lane TEXT NOT NULL CHECK(lane IN ('system','opr')),
  release_id TEXT NOT NULL,
  chunk_index INTEGER NOT NULL CHECK(chunk_index>=0),
  chunk_count INTEGER NOT NULL CHECK(chunk_count>0),
  package_count INTEGER NOT NULL CHECK(package_count>0),
  object_key TEXT NOT NULL UNIQUE,
  object_sha256 TEXT NOT NULL CHECK(length(object_sha256)=64),
  object_size INTEGER NOT NULL CHECK(object_size>0),
  status TEXT NOT NULL DEFAULT 'prepared' CHECK(status IN ('prepared','published','superseded')),
  created_at INTEGER NOT NULL,
  UNIQUE(lane,release_id,chunk_index)
);
CREATE INDEX owned_repository_package_chunk_lookup ON owned_repository_package_chunks(lane,release_id,status,chunk_index);
CREATE TRIGGER owned_repository_package_chunk_no_update BEFORE UPDATE ON owned_repository_package_chunks
WHEN NEW.id IS NOT OLD.id OR NEW.lane IS NOT OLD.lane OR NEW.release_id IS NOT OLD.release_id OR NEW.chunk_index IS NOT OLD.chunk_index OR
 NEW.chunk_count IS NOT OLD.chunk_count OR NEW.package_count IS NOT OLD.package_count OR NEW.object_key IS NOT OLD.object_key OR
 NEW.object_sha256 IS NOT OLD.object_sha256 OR NEW.object_size IS NOT OLD.object_size OR NEW.created_at IS NOT OLD.created_at OR
 OLD.status NOT IN ('prepared') OR NEW.status NOT IN ('published','superseded')
BEGIN SELECT RAISE(ABORT,'owned repository package chunks are immutable'); END;
CREATE TRIGGER owned_repository_package_chunk_no_delete BEFORE DELETE ON owned_repository_package_chunks
BEGIN SELECT RAISE(ABORT,'owned repository package chunks are immutable'); END;

CREATE TABLE owned_repository_universes (
  id TEXT PRIMARY KEY,
  lane TEXT NOT NULL CHECK(lane IN ('system','opr')),
  release_id TEXT NOT NULL UNIQUE,
  root_sha256 TEXT NOT NULL CHECK(length(root_sha256)=64),
  package_count INTEGER NOT NULL CHECK(package_count>=0),
  status TEXT NOT NULL DEFAULT 'prepared' CHECK(status IN ('prepared','published','superseded')),
  created_at INTEGER NOT NULL
);
CREATE INDEX owned_repository_universe_lookup ON owned_repository_universes(lane,release_id,status);
CREATE TRIGGER owned_repository_universe_no_update BEFORE UPDATE ON owned_repository_universes
WHEN NEW.id IS NOT OLD.id OR NEW.lane IS NOT OLD.lane OR NEW.release_id IS NOT OLD.release_id OR NEW.root_sha256 IS NOT OLD.root_sha256 OR
 NEW.package_count IS NOT OLD.package_count OR NEW.created_at IS NOT OLD.created_at OR OLD.status NOT IN ('prepared') OR NEW.status NOT IN ('published','superseded')
BEGIN SELECT RAISE(ABORT,'owned repository universes are immutable'); END;
CREATE TRIGGER owned_repository_universe_no_delete BEFORE DELETE ON owned_repository_universes
BEGIN SELECT RAISE(ABORT,'owned repository universes are immutable'); END;

CREATE TABLE owned_repository_universe_packages (
  universe_id TEXT NOT NULL REFERENCES owned_repository_universes(id),
  ordinal INTEGER NOT NULL CHECK(ordinal>=0),
  artifact_id TEXT NOT NULL REFERENCES owned_repository_artifacts(id),
  collection TEXT NOT NULL CHECK(collection IN ('core','extra','multilib','omarchy','omapkg')),
  target_architecture TEXT NOT NULL CHECK(target_architecture IN ('x86_64','aarch64')),
  PRIMARY KEY(universe_id,ordinal),
  UNIQUE(universe_id,artifact_id)
);
CREATE TRIGGER owned_repository_universe_package_no_update BEFORE UPDATE ON owned_repository_universe_packages
BEGIN SELECT RAISE(ABORT,'owned repository universes are immutable'); END;
CREATE TRIGGER owned_repository_universe_package_no_delete BEFORE DELETE ON owned_repository_universe_packages
BEGIN SELECT RAISE(ABORT,'owned repository universes are immutable'); END;

-- Repository databases may be signed from a v2 native build, but they still
-- use that build's current review/worker/attempt fence. The earlier trigger
-- only admitted package and attestation subjects for v2 attempts.
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
  AND (SELECT COUNT(DISTINCT review.actor) FROM approvals review WHERE review.revision_id=r.id AND review.manifest_sha256=r.manifest_sha256 AND review.revoked_at IS NULL)=2
  AND (SELECT COUNT(DISTINCT review.kind) FROM catalog_reviews review WHERE review.pkgbase=p.pkgbase AND review.revision=p.current_revision AND review.manifest_sha256=policy.manifest_sha256
   AND EXISTS(SELECT 1 FROM team_memberships t WHERE review.actor='github:'||t.github_id AND (t.team IN ('security','admin') OR (review.kind='area' AND t.team=policy.owner_area))))=2
  AND (SELECT COUNT(DISTINCT review.actor) FROM catalog_reviews review WHERE review.pkgbase=p.pkgbase AND review.revision=p.current_revision AND review.manifest_sha256=policy.manifest_sha256)=2
  AND (NEW.object_kind IN ('attestation','database') OR (NEW.object_kind='package' AND EXISTS(SELECT 1 FROM build_artifacts artifact
   WHERE artifact.build_id=b.id AND artifact.attempt=b.attempt AND artifact.filename=NEW.artifact_filename AND artifact.artifact_key=NEW.object_key
    AND artifact.sha256=NEW.artifact_sha256 AND artifact.size=NEW.artifact_size)))
)
BEGIN SELECT RAISE(ABORT,'native signing review or attempt changed'); END;
