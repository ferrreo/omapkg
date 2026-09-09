ALTER TABLE builds ADD COLUMN dependency_blockers_json TEXT CHECK(dependency_blockers_json IS NULL OR json_valid(dependency_blockers_json));
CREATE TABLE dependency_blockers (
 id TEXT PRIMARY KEY,
 request_id TEXT NOT NULL REFERENCES requests(id),
 scope_id TEXT NOT NULL,
 revision_id TEXT REFERENCES revisions(id),
 architecture TEXT NOT NULL CHECK(architecture IN ('x86_64','aarch64')),
 relation TEXT,
 phase TEXT NOT NULL CHECK(phase IN ('factory','build','runtime')),
 resolution TEXT NOT NULL CHECK(resolution IN ('dependency','recipe','exception')),
 finding_sha256 TEXT,
 detail TEXT NOT NULL,
 dependency_request_id TEXT REFERENCES requests(id),
 status TEXT NOT NULL DEFAULT 'open' CHECK(status IN ('open','resolved','superseded')),
 created_at INTEGER NOT NULL,
 resolved_at INTEGER
);
CREATE INDEX dependency_blockers_request ON dependency_blockers(request_id,status);
CREATE INDEX dependency_blockers_provider ON dependency_blockers(dependency_request_id,status);
CREATE TABLE dependency_graph_state (id INTEGER PRIMARY KEY CHECK(id=1), version INTEGER NOT NULL);
INSERT INTO dependency_graph_state VALUES(1,0);
CREATE TRIGGER dependency_graph_changed AFTER UPDATE OF dependency_request_id,status ON dependency_blockers
WHEN OLD.dependency_request_id IS NOT NULL OR NEW.dependency_request_id IS NOT NULL
BEGIN UPDATE dependency_graph_state SET version=version+1 WHERE id=1; END;
