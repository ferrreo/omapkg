-- Requester declarations are untrusted hints; generated revisions retain independently verified licenses.
ALTER TABLE requests ADD COLUMN declared_license TEXT NOT NULL DEFAULT 'unknown';
