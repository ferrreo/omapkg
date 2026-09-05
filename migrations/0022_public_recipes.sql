-- Surface B may keep an internal worker recipe while publishing a public recipe
-- that recreates upstream and locked dependency bytes without private cache URLs.
ALTER TABLE revisions ADD COLUMN public_recipe TEXT;
ALTER TABLE revisions ADD COLUMN public_recipe_sha256 TEXT;
