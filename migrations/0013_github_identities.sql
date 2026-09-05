-- Display data follows verified GitHub profiles; authorization still uses github_id.
ALTER TABLE user ADD COLUMN githubUsername TEXT;

CREATE TABLE github_identities (
  github_id TEXT PRIMARY KEY CHECK(length(github_id) BETWEEN 1 AND 20 AND github_id GLOB '[1-9]*' AND github_id NOT GLOB '*[^0-9]*'),
  username TEXT NOT NULL,
  display_name TEXT,
  avatar_url TEXT,
  last_login_at INTEGER,
  updated_at INTEGER NOT NULL
);
CREATE INDEX github_identities_last_login ON github_identities(last_login_at DESC, github_id);
