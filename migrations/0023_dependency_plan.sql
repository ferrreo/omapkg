-- Freeze exact signed OPR dependency artifacts for each worker lease attempt.
ALTER TABLE builds ADD COLUMN dependency_plan_json TEXT CHECK(dependency_plan_json IS NULL OR json_valid(dependency_plan_json));
