import { describe, expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import { GET } from '../src/routes/api/admin/github-users/+server';
import { actions, load } from '../src/routes/maintain/team/+page.server';
import type { Actor } from '../src/lib/model';
import { actorFor } from '../src/lib/server/auth';
import {
  backfillGithubIdentity,
  cachedGithubIdentity,
  githubIdentitySuggestions,
  normalizeGithubUsername,
  recordGithubOAuthProfile,
  resolveGithubUsernameForGrant,
  syncGithubUserField,
} from '../src/lib/server/identities';
import { asD1, TestD1 } from './d1';
import { symmetricEncrypt } from 'better-auth/crypto';

const schema = readFileSync(new URL('../migrations/0001_initial.sql', import.meta.url), 'utf8') +
  readFileSync(new URL('../migrations/0007_core_guards.sql', import.meta.url), 'utf8') +
  readFileSync(new URL('../migrations/0013_github_identities.sql', import.meta.url), 'utf8') +
  readFileSync(new URL('../migrations/0025_team_memberships.sql', import.meta.url), 'utf8');

const profile = {
  login: 'fixture-user', id: 12345, type: 'User', name: 'Fixture User', avatar_url: 'https://avatars.githubusercontent.com/u/12345?v=4',
};

function event(db: TestD1, url: string, actor: Actor = { id: 'github:1', role: 'admin', areas: [] }, envOverrides: Record<string, unknown> = {}) {
  return {
    request: new Request(`https://omapkg.example${url}`),
    url: new URL(`https://omapkg.example${url}`),
    locals: { actor },
    platform: { env: { DB: asD1(db), ...envOverrides } },
  } as any;
}

function formEvent(db: TestD1, values: Record<string, string | string[]>, envOverrides: Record<string, unknown> = {}) {
  const body = new URLSearchParams();
  for (const [key, value] of Object.entries(values)) {
    for (const item of Array.isArray(value) ? value : [value]) body.append(key, item);
  }
  return {
    request: new Request('https://omapkg.example/maintain/team', { method: 'POST', body }),
    locals: { actor: { id: 'github:1', role: 'admin' as const, areas: [] } },
    platform: { env: { DB: asD1(db), ...envOverrides } },
  } as any;
}

describe('GitHub identity directory', () => {
  test('profile lookup rejects redirects without forwarding OAuth credentials', async () => {
    const db = new TestD1(schema);
    const previous = globalThis.fetch;
    let calls = 0;
    globalThis.fetch = (async (input, init) => {
      calls++;
      expect(String(input)).toBe('https://api.github.com/user/12345');
      expect(init?.redirect).toBe('manual');
      return new Response(null, { status: 302, headers: { Location: 'https://untrusted.example/' } });
    }) as typeof globalThis.fetch;
    try {
      await expect(backfillGithubIdentity(asD1(db), '12345', 'test-oauth-token')).rejects.toThrow('unexpectedly redirected');
      expect(calls).toBe(1);
      expect(await cachedGithubIdentity(asD1(db), '12345')).toBeNull();
    } finally {
      globalThis.fetch = previous;
      db.close();
    }
  });

  test('normalizes usernames without making them authorization keys', () => {
    expect(normalizeGithubUsername('@FixtureUser')).toBe('FixtureUser');
    expect(() => normalizeGithubUsername('@')).toThrow();
    expect(() => normalizeGithubUsername('bad name')).toThrow();
    expect(() => normalizeGithubUsername('a'.repeat(40))).toThrow();
  });

  test('grant resolves live profile and cached rows retain immutable IDs', async () => {
    const db = new TestD1(schema);
    const calls: string[] = [];
    const previous = globalThis.fetch;
    globalThis.fetch = (async (input, init) => {
      calls.push(`${String(input)} ${init?.headers instanceof Headers ? init.headers.get('Authorization') ?? '' : ''}`);
      return Response.json(profile);
    }) as typeof globalThis.fetch;
    try {
      const granted = await resolveGithubUsernameForGrant(asD1(db), '@FixtureUser');
      expect(granted.githubId).toBe('12345');
      expect(granted.username).toBe('fixture-user');
      expect(calls[0]).toContain('/users/FixtureUser');
      expect(calls[0]).not.toContain('Bearer');
      globalThis.fetch = (async () => { throw new Error('cached revoke must not call GitHub'); }) as unknown as typeof globalThis.fetch;
      const cached = await cachedGithubIdentity(asD1(db), '12345');
      expect(cached?.githubId).toBe('12345');
    } finally {
      globalThis.fetch = previous;
      db.close();
    }
  });

  test('missing directory rows backfill through the durable GitHub ID endpoint', async () => {
    const db = new TestD1(schema);
    const calls: string[] = [];
    const previous = globalThis.fetch;
    globalThis.fetch = (async (input: RequestInfo | URL) => {
      calls.push(String(input));
      return Response.json(profile);
    }) as unknown as typeof globalThis.fetch;
    try {
      const identity = await backfillGithubIdentity(asD1(db), '12345');
      expect(identity?.username).toBe('fixture-user');
      expect(calls).toEqual(['https://api.github.com/user/12345']);
      expect((await backfillGithubIdentity(asD1(db), '12345'))?.username).toBe('fixture-user');
      expect(calls).toHaveLength(1);
    } finally {
      globalThis.fetch = previous;
      db.close();
    }
  });

  test('existing sessions backfill through encrypted OAuth credentials when anonymous lookup is limited', async () => {
    const db = new TestD1(schema);
    const secret = 'identity-test-secret-with-enough-length-123';
    const token = 'oauth-fixture-token';
    const encryptedToken = await symmetricEncrypt({ key: secret, data: token });
    const previous = globalThis.fetch;
    const calls: Array<{ url: string; authorization: string | null }> = [];
    globalThis.fetch = (async (input, init) => {
      calls.push({ url: String(input), authorization: new Headers(init?.headers).get('Authorization') });
      return Response.json({ ...profile, id: 12345, login: 'fixture-user' });
    }) as typeof globalThis.fetch;
    try {
      db.prepare('INSERT INTO user(id,name,email,createdAt,updatedAt) VALUES(?,?,?,?,?)').bind('user-existing', 'Fixture User', 'existing@example.com', 1, 1).run();
      db.prepare("INSERT INTO account(id,accountId,providerId,issuer,userId,accessToken,createdAt,updatedAt) VALUES(?,?,?,?,?,?,?,?)")
        .bind('account-existing', '12345', 'github', 'local:oauth:github', 'user-existing', encryptedToken, 1, 1).run();
      const actor = await actorFor({
        DB: asD1(db), ARTIFACTS: {} as R2Bucket, PUBLIC_ORIGIN: 'https://omapkg.example',
        BETTER_AUTH_SECRET: secret, GITHUB_CLIENT_ID: 'client', GITHUB_CLIENT_SECRET: 'secret',
        MAINTAINER_GITHUB_IDS: '12345', SECURITY_GITHUB_IDS: '12345', QUARANTINE_HOURS: '48',
      }, 'user-existing');
      expect(actor.id).toBe('github:12345');
      expect(calls).toEqual([{ url: 'https://api.github.com/user/12345', authorization: `Bearer ${token}` }]);
      expect((await cachedGithubIdentity(asD1(db), '12345'))?.username).toBe('fixture-user');
    } finally {
      globalThis.fetch = previous;
      db.close();
    }
  });

  test('verified OAuth profile refreshes directory, user field and suggestions', async () => {
    const db = new TestD1(schema);
    try {
      db.prepare('INSERT INTO user(id,name,email,createdAt,updatedAt) VALUES(?,?,?,?,?)').bind('user-1', 'Fixture User', 'fixture-user@example.com', 1, 1).run();
      db.prepare("INSERT INTO account(id,accountId,providerId,issuer,userId,createdAt,updatedAt) VALUES(?,?,?,?,?,?,?)")
        .bind('account-1', '12345', 'github', 'local:oauth:github', 'user-1', 1, 1).run();
      await recordGithubOAuthProfile(asD1(db), profile);
      await syncGithubUserField(asD1(db), 'user-1');
      expect(db.prepare('SELECT githubUsername FROM user WHERE id=?').bind('user-1').first<{ githubUsername: string }>()?.githubUsername).toBe('fixture-user');
      const suggestions = await githubIdentitySuggestions(asD1(db));
      expect(suggestions).toEqual([{ username: 'fixture-user', name: 'Fixture User', avatarUrl: profile.avatar_url }]);
      expect(suggestions[0]).not.toHaveProperty('githubId');
    } finally {
      db.close();
    }
  });

  test('admin validation returns profile labels, rejects unknown users, and hides IDs', async () => {
    const db = new TestD1(schema);
    const previous = globalThis.fetch;
    globalThis.fetch = (async (input) => {
      const url = String(input);
      if (url.endsWith('/users/fixture-user')) return Response.json(profile);
      if (url.endsWith('/users/organization')) return Response.json({ ...profile, type: 'Organization' });
      return new Response('missing', { status: 404 });
    }) as typeof globalThis.fetch;
    try {
      const valid = await GET(event(db, '/api/admin/github-users?username=%40fixture-user'));
      expect(valid.status).toBe(200);
      const validBody = await valid.json() as Record<string, unknown>;
      expect(validBody).toEqual({ exists: true, username: 'fixture-user', name: 'Fixture User', avatarUrl: profile.avatar_url });
      expect(validBody.githubId).toBeUndefined();
      const missing = await GET(event(db, '/api/admin/github-users?username=missing'));
      expect(missing.status).toBe(404);
      expect(await missing.json() as Record<string, unknown>).toEqual({ exists: false, username: 'missing' });
      const organization = await GET(event(db, '/api/admin/github-users?username=organization'));
      expect(organization.status).toBe(422);
      const denied = await GET(event(db, '/api/admin/github-users?username=fixture-user', { id: 'github:2', role: 'maintainer', areas: ['system'] }));
      expect(denied.status).toBe(403);
    } finally {
      globalThis.fetch = previous;
      db.close();
    }
  });

  test('authenticated admin validation and grants use encrypted OAuth access without exposing it', async () => {
    const db = new TestD1(schema);
    const secret = 'identity-test-secret-with-enough-length-123';
    const token = 'oauth-admin-token';
    const encryptedToken = await symmetricEncrypt({ key: secret, data: token });
    const previous = globalThis.fetch;
    const calls: Array<{ url: string; authorization: string | null; redirect: RequestRedirect | undefined }> = [];
    globalThis.fetch = (async (input, init) => {
      calls.push({ url: String(input), authorization: new Headers(init?.headers).get('Authorization'), redirect: init?.redirect });
      return Response.json(profile);
    }) as typeof globalThis.fetch;
    try {
      db.prepare('INSERT INTO user(id,name,email,createdAt,updatedAt) VALUES(?,?,?,?,?)').bind('admin-user', 'Admin', 'admin@example.com', 1, 1).run();
      db.prepare("INSERT INTO account(id,accountId,providerId,issuer,userId,accessToken,createdAt,updatedAt) VALUES(?,?,?,?,?,?,?,?)")
        .bind('admin-account', '1', 'github', 'local:oauth:github', 'admin-user', encryptedToken, 1, 1).run();
      const env = { BETTER_AUTH_SECRET: secret };
      const valid = await GET(event(db, '/api/admin/github-users?username=%40fixture-user', undefined, env));
      expect(valid.status).toBe(200);
      const body = await valid.text();
      expect(body).not.toContain(token);
      const grant = await actions.grant(formEvent(db, { github_username: '@fixture-user', teams: ['system'] }, env));
      expect(grant).toMatchObject({ success: true });
      expect(calls).toHaveLength(2);
      expect(calls.every((call) => call.authorization === `Bearer ${token}` && call.redirect === 'manual')).toBe(true);
      const serviceToken = 'profile-integration-fixture';
      const serviceLookup = await GET(event(db, '/api/admin/github-users?username=fixture-user', undefined,
        { ...env, GITHUB_REPO_TOKEN: serviceToken }));
      expect(serviceLookup.status).toBe(200);
      expect(calls.at(-1)?.authorization).toBe(`Bearer ${serviceToken}`);
      expect(await serviceLookup.text()).not.toContain(serviceToken);
    } finally {
      globalThis.fetch = previous;
      db.close();
    }
  });

  test('team grant and revoke accept usernames while revoking current approvals', async () => {
    const db = new TestD1(schema);
    const previous = globalThis.fetch;
    globalThis.fetch = (async () => Response.json(profile)) as unknown as typeof globalThis.fetch;
    try {
      const grant = await actions.grant(formEvent(db, { github_username: '@fixture-user', area: 'system' }));
      expect(grant).toMatchObject({ success: true });
      const revision = {
        id: 'revision-1', requestId: 'request-1', manifest: 'a'.repeat(64),
      };
      db.prepare(`INSERT INTO requests(id,name,upstream_url,source_kind,area,requested_by,status,created_at,updated_at)
        VALUES(?,?,?,?,?,?,?,?,?)`).bind('request-1', 'hello', 'https://example.com/hello.tar.gz', 'archive', 'system', 'github:9', 'queued', 1, 1).run();
      db.prepare(`INSERT INTO revisions(id,request_id,version,recipe,recipe_sha256,manifest_sha256,sources_json,dependencies_json,smoke_commands_json,architectures_json,
        source_date_epoch,image_digest,license,surface,explanation,sbom_json,lint_json,created_at)
        VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).bind(
        revision.id, revision.requestId, '1.0.0', 'pkgname=hello', 'b'.repeat(64), revision.manifest, '[]', '[]', '[]', '["x86_64"]', 1,
        'ghcr.io/example/builder@sha256:' + 'c'.repeat(64), 'MIT', 'binary', '', '{}', '{"passed":true}', 1,
      ).run();
      db.prepare('INSERT INTO approvals(id,revision_id,actor,kind,manifest_sha256,created_at) VALUES(?,?,?,?,?,?)')
        .bind('approval-1', revision.id, 'github:12345', 'area', revision.manifest, 1).run();
      db.prepare('INSERT INTO builds(id,revision_id,architecture,status,created_at) VALUES(?,?,?,?,?)')
        .bind('build-1', revision.id, 'x86_64', 'queued', 1).run();
      const revoke = await actions.revoke(formEvent(db, { expected_github_id: '12345', github_username: 'fixture-user', area: 'system' }));
      expect(revoke).toMatchObject({ success: true });
      expect(db.prepare('SELECT COUNT(*) AS count FROM team_memberships WHERE github_id=?').bind('12345').first<{ count: number }>()?.count).toBe(0);
      expect(db.prepare('SELECT revoked_at FROM approvals WHERE id=?').bind('approval-1').first<{ revoked_at: number | null }>()?.revoked_at).not.toBeNull();
      expect(db.prepare('SELECT status FROM requests WHERE id=?').bind('request-1').first<{ status: string }>()?.status).toBe('review');
      expect(db.prepare('SELECT status FROM builds WHERE id=?').bind('build-1').first<{ status: string }>()?.status).toBe('cancelled');
    } finally {
      globalThis.fetch = previous;
      db.close();
    }
  });

  test('revoke uses hidden expected ID for recycled usernames and deleted profiles', async () => {
    const db = new TestD1(schema);
    const previous = globalThis.fetch;
    globalThis.fetch = (async () => { throw new Error('revoke must not resolve a cached username through GitHub'); }) as unknown as typeof globalThis.fetch;
    try {
      db.prepare('INSERT INTO github_identities(github_id,username,display_name,avatar_url,last_login_at,updated_at) VALUES(?,?,?,?,?,?)')
        .bind('111', 'shared-name', 'First', null, null, 1).run();
      db.prepare('INSERT INTO github_identities(github_id,username,display_name,avatar_url,last_login_at,updated_at) VALUES(?,?,?,?,?,?)')
        .bind('222', 'shared-name', 'Second', null, null, 2).run();
      db.prepare('INSERT INTO team_memberships(github_id,team) VALUES(?,?),(?,?),(?,?)')
        .bind('111', 'system', '222', 'system', '333', 'system').run();
      const page = await load(event(db, '/maintain/team')) as any;
      expect(page.members).toEqual(expect.arrayContaining([
        expect.objectContaining({ accountId: '111', github_username: 'shared-name', canRevoke: true }),
        expect.objectContaining({ accountId: '333', github_username: 'GitHub user', canRevoke: true }),
      ]));
      await actions.revoke(formEvent(db, { expected_github_id: '111', github_username: 'shared-name', area: 'system' }));
      expect(db.prepare('SELECT 1 FROM team_memberships WHERE github_id=?').bind('111').first()).toBeNull();
      expect(db.prepare('SELECT 1 FROM team_memberships WHERE github_id=?').bind('222').first()).not.toBeNull();
      await actions.revoke(formEvent(db, { expected_github_id: '333', github_username: 'GitHub user', area: 'system' }));
      expect(db.prepare('SELECT 1 FROM team_memberships WHERE github_id=?').bind('333').first()).toBeNull();
    } finally {
      globalThis.fetch = previous;
      db.close();
    }
  });

  test('grants multiple teams and keeps final administrator protected', async () => {
    const db = new TestD1(schema);
    const previous = globalThis.fetch;
    globalThis.fetch = (async () => Response.json(profile)) as unknown as typeof globalThis.fetch;
    try {
      const grant = await actions.grant(formEvent(db, { github_username: '@fixture-user', teams: ['system', 'security', 'admin'] }));
      expect(grant).toMatchObject({ success: true });
      expect(db.prepare('SELECT team FROM team_memberships WHERE github_id=? ORDER BY team').bind('12345').all<{ team: string }>().results.map((row) => row.team))
        .toEqual(['admin', 'security', 'system']);
      expect(db.prepare("SELECT COUNT(*) AS count FROM audit_events WHERE action='team.membership_granted'").first<{ count: number }>()?.count).toBe(3);

      const page = await load(event(db, '/maintain/team')) as any;
      expect(page.teams).toContain('security');
      expect(page.members.find((member: any) => member.team === 'admin')?.canRevoke).toBe(false);

      const blocked = await actions.revoke(formEvent(db, { expected_github_id: '12345', github_username: 'fixture-user', team: 'admin' }));
      expect((blocked as any).data).toMatchObject({ success: false, error: 'At least one administrator must remain.' });
      expect(db.prepare("SELECT 1 FROM team_memberships WHERE github_id='12345' AND team='admin'").first()).not.toBeNull();

      db.prepare("INSERT INTO team_memberships(github_id,team) VALUES('99999','admin')").run();
      const revoke = await actions.revoke(formEvent(db, { expected_github_id: '12345', github_username: 'fixture-user', team: 'admin' }));
      expect(revoke).toMatchObject({ success: true });
      const lastBlocked = await actions.revoke(formEvent(db, { expected_github_id: '99999', github_username: 'GitHub user', team: 'admin' }));
      expect((lastBlocked as any).data).toMatchObject({ success: false, error: 'At least one administrator must remain.' });
    } finally {
      globalThis.fetch = previous;
      db.close();
    }
  });

  test('fences unpublished work only when no retained team covers approvals', async () => {
    const db = new TestD1(schema);
    const previous = globalThis.fetch;
    globalThis.fetch = (async () => Response.json(profile)) as unknown as typeof globalThis.fetch;
    try {
      await actions.grant(formEvent(db, { github_username: '@fixture-user', teams: ['system', 'security'] }));
      db.prepare(`INSERT INTO requests(id,name,upstream_url,source_kind,area,requested_by,status,created_at,updated_at)
        VALUES('request-teams','hello-teams','https://example.com/hello.tar.gz','archive','system','github:9','queued',1,1)`).run();
      db.prepare(`INSERT INTO revisions(id,request_id,version,recipe,recipe_sha256,manifest_sha256,sources_json,dependencies_json,smoke_commands_json,architectures_json,
        source_date_epoch,image_digest,license,surface,explanation,sbom_json,lint_json,created_at)
        VALUES('revision-teams','request-teams','1.0.0','pkgname=hello','${'b'.repeat(64)}','${'a'.repeat(64)}','[]','[]','[]','["x86_64"]',1,
        'ghcr.io/example/builder@sha256:${'c'.repeat(64)}','MIT','binary','','{}','{"passed":true}',1)`).run();
      db.prepare('INSERT INTO approvals(id,revision_id,actor,kind,manifest_sha256,created_at) VALUES(?,?,?,?,?,?),(?,?,?,?,?,?)')
        .bind('approval-teams-area', 'revision-teams', 'github:12345', 'area', 'a'.repeat(64), 1,
          'approval-teams-security', 'revision-teams', 'github:12345', 'security', 'a'.repeat(64), 1).run();
      db.prepare("INSERT INTO builds(id,revision_id,architecture,status,created_at) VALUES('build-teams','revision-teams','x86_64','queued',1)").run();

      const areaRevoke = await actions.revoke(formEvent(db, { expected_github_id: '12345', github_username: 'fixture-user', team: 'system' }));
      expect(areaRevoke).toMatchObject({ success: true });
      expect(db.prepare("SELECT revoked_at FROM approvals WHERE id='approval-teams-area'").first<{ revoked_at: number | null }>()?.revoked_at).toBeNull();
      expect(db.prepare("SELECT revoked_at FROM approvals WHERE id='approval-teams-security'").first<{ revoked_at: number | null }>()?.revoked_at).toBeNull();
      expect(db.prepare("SELECT status FROM builds WHERE id='build-teams'").first<{ status: string }>()?.status).toBe('queued');
      expect(db.prepare("SELECT status FROM requests WHERE id='request-teams'").first<{ status: string }>()?.status).toBe('queued');

      const securityRevoke = await actions.revoke(formEvent(db, { expected_github_id: '12345', github_username: 'fixture-user', team: 'security' }));
      expect(securityRevoke).toMatchObject({ success: true });
      expect(db.prepare("SELECT revoked_at FROM approvals WHERE id='approval-teams-area'").first<{ revoked_at: number | null }>()?.revoked_at).not.toBeNull();
      expect(db.prepare("SELECT revoked_at FROM approvals WHERE id='approval-teams-security'").first<{ revoked_at: number | null }>()?.revoked_at).not.toBeNull();
      expect(db.prepare("SELECT status FROM builds WHERE id='build-teams'").first<{ status: string }>()?.status).toBe('cancelled');
      expect(db.prepare("SELECT status FROM requests WHERE id='request-teams'").first<{ status: string }>()?.status).toBe('review');
    } finally {
      globalThis.fetch = previous;
      db.close();
    }
  });

  test('preserves published approvals but fails and fences an active sibling', async () => {
    const db = new TestD1(schema);
    const previous = globalThis.fetch;
    globalThis.fetch = (async () => Response.json(profile)) as unknown as typeof globalThis.fetch;
    try {
      await actions.grant(formEvent(db, { github_username: '@fixture-user', teams: ['system'] }));
      db.prepare(`INSERT INTO requests(id,name,upstream_url,source_kind,area,requested_by,status,created_at,updated_at)
        VALUES('request-published','hello-published','https://example.com/hello.tar.gz','archive','system','github:9','building',1,1)`).run();
      db.prepare(`INSERT INTO revisions(id,request_id,version,recipe,recipe_sha256,manifest_sha256,sources_json,dependencies_json,smoke_commands_json,architectures_json,
        source_date_epoch,image_digest,license,surface,explanation,sbom_json,lint_json,created_at)
        VALUES('revision-published','request-published','1.0.0','pkgname=hello','${'b'.repeat(64)}','${'d'.repeat(64)}','[]','[]','[]','["x86_64","aarch64"]',1,
        'ghcr.io/example/builder@sha256:${'c'.repeat(64)}','MIT','binary','','{}','{"passed":true}',1)`).run();
      db.prepare('INSERT INTO approvals(id,revision_id,actor,kind,manifest_sha256,created_at) VALUES(?,?,?,?,?,?),(?,?,?,?,?,?)')
        .bind('approval-published-area', 'revision-published', 'github:12345', 'area', 'd'.repeat(64), 1,
          'approval-published-security', 'revision-published', 'github:9', 'security', 'd'.repeat(64), 1).run();
      db.prepare(`INSERT INTO builds(id,revision_id,architecture,status,artifact_key,artifact_sha256,artifact_size,artifact_filename,smoke_passed,created_at)
        VALUES('build-published','revision-published','x86_64','succeeded','builds/published.pkg','${'e'.repeat(64)}',10,'hello.pkg.tar.zst',1,1),
        ('build-sibling','revision-published','aarch64','queued',NULL,NULL,NULL,NULL,0,1)`).run();
      db.prepare(`INSERT INTO releases(id,build_id,name,version,architecture,surface,channel,artifact_key,signature_key,recipe_key,sbom_key,provenance_key,published_at)
        VALUES('release-published','build-published','hello','1.0.0-1','x86_64','binary','dev','packages/hello.pkg','signatures/hello.sig','recipes/hello','metadata/sbom','metadata/provenance',1)`).run();

      const revoke = await actions.revoke(formEvent(db, { expected_github_id: '12345', github_username: 'fixture-user', team: 'system' }));
      expect(revoke).toMatchObject({ success: true });
      expect(db.prepare("SELECT revoked_at FROM approvals WHERE id='approval-published-area'").first<{ revoked_at: number | null }>()?.revoked_at).toBeNull();
      expect(db.prepare("SELECT 1 FROM releases WHERE id='release-published'").first()).not.toBeNull();
      expect(db.prepare("SELECT status,error FROM builds WHERE id='build-sibling'").first<{ status: string; error: string }>()?.status).toBe('cancelled');
      expect(db.prepare("SELECT status,rejection_reason FROM requests WHERE id='request-published'").first<{ status: string; rejection_reason: string }>()?.status).toBe('failed');
      expect(db.prepare("SELECT rejection_reason FROM requests WHERE id='request-published'").first<{ rejection_reason: string }>()?.rejection_reason).toContain('generate a new revision');
    } finally {
      globalThis.fetch = previous;
      db.close();
    }
  });
});
