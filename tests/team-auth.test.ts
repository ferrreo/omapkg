import { expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import { areas } from '../src/lib/model';
import { actorFor } from '../src/lib/server/auth';
import { recordGithubOAuthProfile } from '../src/lib/server/identities';
import { requireMaintainer, requireSecurity } from '../src/lib/server/policy';
import { promoteBatch } from '../src/lib/server/releases';
import type { Env } from '../src/lib/server/env';
import { asD1, TestD1 } from './d1';

const schema = ['0001_initial.sql', '0007_core_guards.sql', '0013_github_identities.sql', '0025_team_memberships.sql']
  .map((file) => readFileSync(new URL(`../migrations/${file}`, import.meta.url), 'utf8')).join('\n');

test('team membership grants all-area security, admin hierarchy, and immediate role removal', async () => {
  const db = new TestD1(schema);
  const env: Env = { DB: asD1(db), ARTIFACTS: {} as R2Bucket, PUBLIC_ORIGIN: 'https://omapkg.example',
    MAINTAINER_GITHUB_IDS: '101', SECURITY_GITHUB_IDS: '101', QUARANTINE_HOURS: '48' };
  try {
    db.prepare('INSERT INTO user(id,name,email,createdAt,updatedAt) VALUES(?,?,?,?,?)').bind('team-user', 'Test user', 'team@example.com', 1, 1).run();
    db.prepare('INSERT INTO account(id,accountId,providerId,issuer,userId,createdAt,updatedAt) VALUES(?,?,?,?,?,?,?)')
      .bind('team-account', '101', 'github', 'local:oauth:github', 'team-user', 1, 1).run();
    await recordGithubOAuthProfile(asD1(db), { id: 101, login: 'team-user', type: 'User' });
    db.prepare("INSERT INTO team_memberships VALUES('101','desktop'),('101','gaming')").run();
    const areaActor = await actorFor(env, 'team-user');
    expect(areaActor.role).toBe('maintainer');
    expect(new Set(areaActor.areas)).toEqual(new Set(['desktop', 'gaming']));
    expect(() => requireMaintainer(areaActor, 'system')).toThrow();
    expect(() => requireSecurity(areaActor)).toThrow();
    db.prepare("INSERT INTO team_memberships VALUES('101','security')").run();
    const security = await actorFor(env, 'team-user');
    expect(security.role).toBe('security');
    expect(security.areas).toEqual(areas);
    for (const area of areas) expect(requireMaintainer(security, area)).toBe(security);
    expect(requireSecurity(security)).toBe(security);
    await expect(promoteBatch(env, security, [], 'Review test')).rejects.toMatchObject({ status: 400 });
    db.prepare("INSERT INTO team_memberships VALUES('101','admin')").run();
    expect((await actorFor(env, 'team-user')).role).toBe('admin');
    db.prepare("DELETE FROM team_memberships WHERE github_id='101' AND team='admin'").run();
    expect((await actorFor(env, 'team-user')).role).toBe('security');
    db.prepare("DELETE FROM team_memberships WHERE github_id='101'").run();
    expect((await actorFor(env, 'team-user')).role).toBe('public');
  } finally { db.close(); }
});
