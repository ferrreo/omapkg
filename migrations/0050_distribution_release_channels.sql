-- Release channels are independent activation lanes. Existing pre-channel
-- release rows are retained as stable records during additive migration.
ALTER TABLE distribution_release_candidates ADD COLUMN channel TEXT NOT NULL DEFAULT 'stable'
  CHECK(channel IN ('edge','rc','stable','quarantine'));
CREATE INDEX distribution_release_candidates_lane_channel ON distribution_release_candidates(lane,channel,status,sequence);
DROP INDEX IF EXISTS distribution_release_candidates_identity;
CREATE UNIQUE INDEX distribution_release_candidates_signed_identity ON distribution_release_candidates(kind,release_id,channel)
  WHERE status IN ('signed','active');
DROP TRIGGER distribution_release_manifest_immutable;
CREATE TRIGGER distribution_release_manifest_immutable
BEFORE UPDATE OF kind,lane,channel,release_id,sequence,parent_digest,parent_sequence,manifest_json,manifest_sha256,manifest_key,manifest_size,changelog_key,changelog_sha256,created_by,created_at
ON distribution_release_candidates
BEGIN SELECT RAISE(ABORT,'distribution release manifest is immutable'); END;

CREATE TABLE distribution_activation_pointers_channels (
  lane TEXT NOT NULL CHECK(lane IN ('system','opr','transaction')),
  channel TEXT NOT NULL CHECK(channel IN ('edge','rc','stable','quarantine')),
  release_id TEXT,
  manifest_sha256 TEXT,
  sequence INTEGER NOT NULL DEFAULT 0,
  system_manifest_sha256 TEXT,
  opr_manifest_sha256 TEXT,
  updated_at INTEGER NOT NULL,
  PRIMARY KEY(lane,channel),
  CHECK((lane='system' AND channel IN ('edge','rc','stable')) OR
    (lane='opr' AND channel IN ('quarantine','stable')) OR
    (lane='transaction' AND channel IN ('edge','rc','stable')))
);
INSERT INTO distribution_activation_pointers_channels(lane,channel,release_id,manifest_sha256,sequence,system_manifest_sha256,opr_manifest_sha256,updated_at)
  SELECT lane,'stable',release_id,manifest_sha256,sequence,system_manifest_sha256,opr_manifest_sha256,updated_at
  FROM distribution_activation_pointers;
INSERT INTO distribution_activation_pointers_channels(lane,channel,updated_at) VALUES
  ('system','edge',0),('system','rc',0),('opr','quarantine',0),('transaction','edge',0),('transaction','rc',0);
DROP TABLE distribution_activation_pointers;
ALTER TABLE distribution_activation_pointers_channels RENAME TO distribution_activation_pointers;
CREATE INDEX distribution_activation_pointers_channel ON distribution_activation_pointers(lane,channel,sequence);
