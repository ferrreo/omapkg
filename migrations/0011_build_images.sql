-- Builder images are approved by digest. Identity fields stay immutable;
-- administrators may only change availability and the per-architecture default.
CREATE TABLE build_images (
  id TEXT PRIMARY KEY,
  label TEXT NOT NULL CHECK(length(label) BETWEEN 1 AND 120),
  image_ref TEXT NOT NULL CHECK(
    length(image_ref) BETWEEN 1 AND 512
    AND image_ref GLOB '*@sha256:*'
    AND length(substr(image_ref,instr(image_ref,'@sha256:') + 8)) = 64
    AND substr(image_ref,instr(image_ref,'@sha256:') + 8) NOT GLOB '*[^0-9a-f]*'
  ),
  architecture TEXT NOT NULL CHECK(architecture IN ('x86_64','aarch64')),
  mirror TEXT NOT NULL CHECK(mirror IN ('stable','rc','edge','custom')),
  enabled INTEGER NOT NULL DEFAULT 0 CHECK(enabled IN (0,1)),
  is_default INTEGER NOT NULL DEFAULT 0 CHECK(is_default IN (0,1) AND (is_default=0 OR enabled=1)),
  created_actor TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE UNIQUE INDEX build_images_digest_architecture ON build_images(image_ref, architecture);
CREATE UNIQUE INDEX build_images_one_default_per_architecture ON build_images(architecture) WHERE is_default=1;
CREATE TRIGGER build_images_identity_immutable
BEFORE UPDATE OF id,label,image_ref,architecture,mirror,created_actor,created_at ON build_images
BEGIN SELECT RAISE(ABORT,'build image identity is immutable'); END;
CREATE TRIGGER build_images_no_delete
BEFORE DELETE ON build_images
BEGIN SELECT RAISE(ABORT,'build image records are immutable'); END;

ALTER TABLE revisions ADD COLUMN build_images_json TEXT NOT NULL DEFAULT '{}' CHECK(json_valid(build_images_json));
