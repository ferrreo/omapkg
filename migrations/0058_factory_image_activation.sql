-- Builder/runtime OCI image rows produced before factory evidence remain
-- honestly marked legacy. Factory-origin rows retain the exact private run
-- contract that authorized their activation.
ALTER TABLE build_images ADD COLUMN origin TEXT NOT NULL DEFAULT 'legacy' CHECK(origin IN ('legacy','factory'));
ALTER TABLE build_images ADD COLUMN factory_run_id TEXT;
ALTER TABLE build_images ADD COLUMN factory_attempt INTEGER;
ALTER TABLE build_images ADD COLUMN factory_input_sha256 TEXT CHECK(factory_input_sha256 IS NULL OR length(factory_input_sha256)=64);
ALTER TABLE build_images ADD COLUMN factory_output_sha256 TEXT CHECK(factory_output_sha256 IS NULL OR length(factory_output_sha256)=64);
ALTER TABLE build_images ADD COLUMN factory_output_size INTEGER CHECK(factory_output_size IS NULL OR factory_output_size>0);
ALTER TABLE build_images ADD COLUMN factory_artifact_key TEXT;
ALTER TABLE build_images ADD COLUMN factory_evidence_sha256 TEXT CHECK(factory_evidence_sha256 IS NULL OR length(factory_evidence_sha256)=64);
CREATE INDEX build_images_factory_run ON build_images(factory_run_id,factory_attempt) WHERE origin='factory';
