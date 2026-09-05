-- Claim leases let the private signer retry after a crashed or timed-out
-- request without making signing intent records mutable by callers.
ALTER TABLE signing_intents ADD COLUMN expires_at INTEGER;
ALTER TABLE signing_intents ADD COLUMN artifact_size INTEGER;
ALTER TABLE signing_intents ADD COLUMN claimed_at INTEGER;
ALTER TABLE signing_intents ADD COLUMN claim_expires_at INTEGER;
ALTER TABLE signing_intents ADD COLUMN key_fingerprint TEXT;
CREATE INDEX signing_intents_claims ON signing_intents(status, claim_expires_at, created_at);
