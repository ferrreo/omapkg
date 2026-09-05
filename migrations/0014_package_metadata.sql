-- Keep runtime and build-only Arch dependencies distinct in generated recipes.
-- pkgrel is part of the immutable package identity while Revision.version stays
-- the upstream pkgver used by release detection.
ALTER TABLE revisions ADD COLUMN make_dependencies_json TEXT NOT NULL DEFAULT '[]' CHECK(json_valid(make_dependencies_json));
ALTER TABLE revisions ADD COLUMN pkgrel INTEGER NOT NULL DEFAULT 1 CHECK(pkgrel BETWEEN 1 AND 9999);
