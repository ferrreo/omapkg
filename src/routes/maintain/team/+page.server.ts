import { areas, teams, type Team } from '$lib/model';
import { githubAccessTokenForActor } from '$lib/server/auth';
import { id, now, query } from '$lib/server/db';
import { environment, field, formAction, maintainer } from '$lib/server/http';
import { PolicyError } from '$lib/server/policy';
import {
  cachedGithubIdentity,
  githubIdentitySuggestions,
  normalizeGithubAccountId,
  normalizeGithubUsername,
  resolveGithubUsernameForGrant,
} from '$lib/server/identities';
import type { Actions, PageServerLoad } from './$types';

type MemberRow = { accountId: string; github_username: string | null; avatar_url: string | null; team: Team };

const teamNames = teams as readonly string[];
const fenceReason = 'Reviewer access was removed; generate a new revision before building again.';

function validTeam(value: string): value is Team {
  return teamNames.includes(value);
}

function grantTeams(form: FormData): Team[] {
  const values = form.getAll('teams')
    .filter((value): value is string => typeof value === 'string')
    .map((value) => value.trim());
  if (!values.length) {
    const legacyArea = field(form, 'area').trim();
    if (legacyArea) values.push(legacyArea);
  }
  const selected = [...new Set(values)];
  if (!selected.length || selected.some((value) => !validTeam(value))) {
    throw new PolicyError(400, 'Choose one or more valid teams.');
  }
  return selected as Team[];
}

function revokeTeam(form: FormData): Team {
  const value = (field(form, 'team') || field(form, 'area')).trim();
  if (!validTeam(value)) throw new PolicyError(400, 'Choose a valid team.');
  return value;
}

export const load: PageServerLoad = async (event) => {
  const actor = maintainer(event);
  const DB = environment(event).DB;
  const [members, adminCount] = await Promise.all([
    query<MemberRow>(DB, `SELECT m.github_id AS accountId,i.username AS github_username,i.avatar_url,m.team
      FROM team_memberships m LEFT JOIN github_identities i ON i.github_id=m.github_id
      ORDER BY lower(COALESCE(i.username,'')),m.team`),
    DB.prepare("SELECT COUNT(*) AS count FROM team_memberships WHERE team='admin'").first<{ count: number }>(),
  ]);
  return {
    areas,
    teams,
    members: members.map((member) => ({
      ...member,
      github_username: member.github_username ?? 'GitHub user',
      canRevoke: actor.role === 'admin' && !(member.team === 'admin' && (adminCount?.count ?? 0) <= 1),
    })),
    suggestions: actor.role === 'admin' ? await githubIdentitySuggestions(DB) : [],
  };
};

const changeMembership = (grant: boolean): NonNullable<Actions[string]> => (event) => formAction(event, async (form) => {
  const actor = maintainer(event);
  if (actor.role !== 'admin') throw new PolicyError(403, 'Administrator access is required to change team memberships.');
  const env = environment(event);
  const DB = env.DB;

  if (grant) {
    const selectedTeams = grantTeams(form);
    const identity = await resolveGithubUsernameForGrant(DB, field(form, 'github_username'), await githubAccessTokenForActor(env, actor) ?? undefined);
    const target = `github:${identity.githubId}`;
    const timestamp = now();
    await DB.batch([
      ...selectedTeams.flatMap((team) => [
        DB.prepare('INSERT INTO team_memberships(github_id,team) VALUES(?,?) ON CONFLICT DO NOTHING')
          .bind(identity.githubId, team),
        DB.prepare(`INSERT INTO audit_events(actor,action,target,detail,created_at)
          SELECT ?,?,?,?,? WHERE changes()=1`)
          .bind(actor.id, 'team.membership_granted', target, JSON.stringify({ username: identity.username, team }), timestamp),
      ]),
    ]);
    return;
  }

  const expectedGithubId = normalizeGithubAccountId(field(form, 'expected_github_id'));
  const team = revokeTeam(form);
  const submittedUsername = field(form, 'github_username');
  if (submittedUsername !== 'GitHub user') normalizeGithubUsername(submittedUsername);
  const assignment = await DB.prepare('SELECT 1 AS present FROM team_memberships WHERE github_id=? AND team=?')
    .bind(expectedGithubId, team).first<{ present: number }>();
  if (!assignment) throw new PolicyError(409, 'Team membership changed. Refresh and retry.');
  if (team === 'admin' && !await DB.prepare("SELECT 1 FROM team_memberships WHERE team='admin' AND github_id<>? LIMIT 1")
    .bind(expectedGithubId).first()) {
    throw new PolicyError(409, 'At least one administrator must remain.');
  }

  const identity = await cachedGithubIdentity(DB, expectedGithubId);
  const target = `github:${expectedGithubId}`;
  const displayUsername = identity?.username ?? (submittedUsername === 'GitHub user'
    ? 'GitHub user'
    : normalizeGithubUsername(submittedUsername));
  const timestamp = now();
  const changeId = id();
  const detail = JSON.stringify({ username: displayUsername, team, changeId, reason: fenceReason });
  const marker = `EXISTS (
    SELECT 1 FROM audit_events marker
    WHERE marker.action='team.membership_revoked' AND marker.target=?
      AND json_extract(marker.detail,'$.changeId')=?
  )`;
  const capabilityLost = `(
    (a.kind='security' AND NOT EXISTS (
      SELECT 1 FROM team_memberships retained
      WHERE retained.github_id=? AND retained.team IN ('security','admin')
    )) OR
    (a.kind='area' AND NOT EXISTS (
      SELECT 1 FROM team_memberships retained
      WHERE retained.github_id=? AND (retained.team IN ('security','admin') OR retained.team=q.area)
    ))
  )`;

  const result = await DB.batch([
    DB.prepare(`INSERT INTO audit_events(actor,action,target,detail,created_at)
      SELECT ?,?,?,?,?
      WHERE EXISTS (SELECT 1 FROM team_memberships WHERE github_id=? AND team=?)
        AND (?<>'admin' OR (SELECT COUNT(*) FROM team_memberships WHERE team='admin')>1)`)
      .bind(actor.id, 'team.membership_revoked', target, detail, timestamp, expectedGithubId, team, team),
    DB.prepare(`DELETE FROM team_memberships
      WHERE github_id=? AND team=? AND ${marker}
        AND (?<>'admin' OR (SELECT COUNT(*) FROM team_memberships WHERE team='admin')>1)`)
      .bind(expectedGithubId, team, target, changeId, team),
    DB.prepare(`UPDATE approvals AS a SET revoked_at=?,revoked_by=?
      WHERE a.actor=? AND a.revoked_at IS NULL
        AND NOT EXISTS (
          SELECT 1 FROM releases published JOIN builds published_build ON published_build.id=published.build_id
          WHERE published_build.revision_id=a.revision_id
        )
        AND EXISTS (
          SELECT 1 FROM revisions r JOIN requests q ON q.id=r.request_id
          WHERE r.id=a.revision_id AND ${capabilityLost}
        )
        AND ${marker}`)
      .bind(timestamp, actor.id, target, expectedGithubId, expectedGithubId, target, changeId),
    DB.prepare(`UPDATE builds AS b SET status='cancelled',worker_id=NULL,lease_token=NULL,lease_expires_at=NULL,
        error=?,finished_at=?
      WHERE b.status IN ('queued','leased') AND ${marker}
        AND EXISTS (
          SELECT 1 FROM approvals AS a
          JOIN revisions r ON r.id=a.revision_id JOIN requests q ON q.id=r.request_id
          WHERE a.revision_id=b.revision_id AND a.actor=?
            AND (a.revoked_at IS NULL OR (a.revoked_at=? AND a.revoked_by=?))
            AND ${capabilityLost}
        )`)
      .bind(fenceReason, timestamp, target, changeId, target, timestamp, actor.id, expectedGithubId, expectedGithubId),
    DB.prepare(`UPDATE requests AS request SET
        status=CASE WHEN EXISTS (
          SELECT 1 FROM revisions published_revision
          JOIN builds published_build ON published_build.revision_id=published_revision.id
          JOIN releases published ON published.build_id=published_build.id
          JOIN builds cancelled ON cancelled.revision_id=published_revision.id
          WHERE published_revision.request_id=request.id
            AND published_revision.id=(SELECT current.id FROM revisions current WHERE current.request_id=request.id ORDER BY current.created_at DESC,current.rowid DESC LIMIT 1)
            AND cancelled.status='cancelled'
            AND cancelled.error=? AND cancelled.finished_at=?
        ) THEN 'failed' ELSE 'review' END,
        rejection_reason=CASE WHEN EXISTS (
          SELECT 1 FROM revisions published_revision
          JOIN builds published_build ON published_build.revision_id=published_revision.id
          JOIN releases published ON published.build_id=published_build.id
          JOIN builds cancelled ON cancelled.revision_id=published_revision.id
          WHERE published_revision.request_id=request.id
            AND published_revision.id=(SELECT current.id FROM revisions current WHERE current.request_id=request.id ORDER BY current.created_at DESC,current.rowid DESC LIMIT 1)
            AND cancelled.status='cancelled'
            AND cancelled.error=? AND cancelled.finished_at=?
        ) THEN ? ELSE rejection_reason END,
        updated_at=?
      WHERE request.status IN ('queued','building') AND ${marker}
        AND EXISTS (
          SELECT 1 FROM revisions latest
          WHERE latest.request_id=request.id
            AND latest.id=(SELECT current.id FROM revisions current WHERE current.request_id=request.id ORDER BY current.created_at DESC,current.rowid DESC LIMIT 1)
            AND (
              EXISTS (
                SELECT 1 FROM approvals revoked
                WHERE revoked.revision_id=latest.id AND revoked.actor=?
                  AND revoked.revoked_at=? AND revoked.revoked_by=?
              ) OR EXISTS (
                SELECT 1 FROM builds cancelled
                WHERE cancelled.revision_id=latest.id AND cancelled.status='cancelled'
                  AND cancelled.error=? AND cancelled.finished_at=?
              )
            )
        )`)
      .bind(fenceReason, timestamp, fenceReason, timestamp, fenceReason, timestamp,
        target, changeId, target, timestamp, actor.id, fenceReason, timestamp),
  ]);
  if (!result[1] || (result[1] as { meta?: { changes?: number } }).meta?.changes !== 1) {
    throw new PolicyError(409, 'Team membership changed. Refresh and retry.');
  }
});

export const actions: Actions = { grant: changeMembership(true), revoke: changeMembership(false) };
