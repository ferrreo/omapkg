ALTER TABLE requests ADD COLUMN factory_run_id TEXT;
CREATE INDEX requests_factory_run ON requests(factory_run_id);
