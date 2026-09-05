-- Worker runtime metadata is informational and never grants capabilities.
ALTER TABLE workers ADD COLUMN daemon_version TEXT CHECK(daemon_version IS NULL OR length(daemon_version) BETWEEN 1 AND 64);
ALTER TABLE workers ADD COLUMN runtime TEXT CHECK(runtime IS NULL OR runtime IN ('podman','docker'));
ALTER TABLE workers ADD COLUMN capabilities_json TEXT CHECK(capabilities_json IS NULL OR json_valid(capabilities_json));
