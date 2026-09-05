CREATE TABLE team_memberships (
  github_id TEXT NOT NULL,
  team TEXT NOT NULL CHECK (team IN ('desktop','development','gaming','multimedia','productivity','system','security','admin')),
  PRIMARY KEY (github_id, team)
);

INSERT INTO team_memberships(github_id, team)
SELECT github_id, area FROM maintainer_areas
WHERE area IN ('desktop','development','gaming','multimedia','productivity','system');
