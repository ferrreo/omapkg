-- Better Auth 1.7 scopes OAuth account identity by issuer.
ALTER TABLE account ADD COLUMN issuer TEXT NOT NULL DEFAULT 'local:oauth:github';
UPDATE account SET issuer = CASE WHEN providerId = 'github' THEN 'local:oauth:github' ELSE 'local:' || providerId END;
CREATE UNIQUE INDEX account_issuer_account ON account(issuer, accountId);

-- A role change must invalidate approvals before queued work can run.
ALTER TABLE approvals ADD COLUMN revoked_at INTEGER;
ALTER TABLE approvals ADD COLUMN revoked_by TEXT;
CREATE INDEX approvals_current ON approvals(revision_id, kind, revoked_at);
