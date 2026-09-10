-- Captures retain source evidence only. They cannot approve or queue recipes.
CREATE TABLE recipe_captures (
  sha256 TEXT PRIMARY KEY REFERENCES input_objects(sha256),
  pkgbase TEXT NOT NULL,
  manifest_json TEXT NOT NULL CHECK(json_valid(manifest_json)),
  summary_json TEXT NOT NULL CHECK(json_valid(summary_json)),
  created_by TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE INDEX recipe_captures_package ON recipe_captures(pkgbase,created_at);
CREATE TRIGGER recipe_capture_immutable BEFORE UPDATE ON recipe_captures BEGIN SELECT RAISE(ABORT,'Recipe captures are immutable'); END;
CREATE TRIGGER recipe_capture_preserved BEFORE DELETE ON recipe_captures BEGIN SELECT RAISE(ABORT,'Recipe captures are retained evidence'); END;

CREATE TABLE recipe_capture_links (
  import_id TEXT NOT NULL REFERENCES catalog_imports(id),
  source_id TEXT NOT NULL,
  pkgbase TEXT NOT NULL,
  capture_sha256 TEXT NOT NULL REFERENCES recipe_captures(sha256),
  comparison_json TEXT NOT NULL CHECK(json_valid(comparison_json)),
  actor TEXT NOT NULL,
  reason TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  PRIMARY KEY(import_id,source_id,pkgbase,capture_sha256)
);
CREATE TRIGGER recipe_capture_link_immutable BEFORE UPDATE ON recipe_capture_links BEGIN SELECT RAISE(ABORT,'Recipe capture links are immutable'); END;
CREATE TRIGGER recipe_capture_link_preserved BEFORE DELETE ON recipe_capture_links BEGIN SELECT RAISE(ABORT,'Recipe capture links are retained evidence'); END;
