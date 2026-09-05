import { betterAuth } from 'better-auth';
import { symmetricDecrypt } from 'better-auth/crypto';
import { areas, type Actor, type Team } from '../model';
import type { Env } from './env';
import { audit } from './db';
import { backfillGithubIdentity, recordGithubOAuthProfile, syncGithubUserField } from './identities';

export const authReady = (env: Env) => Boolean(env.BETTER_AUTH_SECRET && env.GITHUB_CLIENT_ID && env.GITHUB_CLIENT_SECRET);

async function storedGithubAccessToken(stored: string | null | undefined, secret: string | undefined): Promise<string | null> {
  if (!stored) return null;
  const encrypted = stored.startsWith('$ba$') || (stored.length % 2 === 0 && /^[0-9a-f]+$/i.test(stored));
  if (!encrypted) return stored;
  if (!secret) return null;
  try { return await symmetricDecrypt({ key: secret, data: stored }); }
  catch { return null; }
}

export async function githubAccessTokenForActor(env: Env, actor: Pick<Actor, 'id'>): Promise<string | null> {
  if (!actor.id.startsWith('github:')) return null;
  const githubId = actor.id.slice('github:'.length);
  if (!/^[1-9][0-9]{0,19}$/.test(githubId)) return null;
  if (env.GITHUB_REPO_TOKEN) return env.GITHUB_REPO_TOKEN;
  const account = await env.DB.prepare("SELECT accessToken FROM account WHERE accountId=? AND providerId='github' AND issuer='local:oauth:github' LIMIT 1")
    .bind(githubId).first<{ accessToken: string | null }>();
  return storedGithubAccessToken(account?.accessToken, env.BETTER_AUTH_SECRET);
}

export function createAuth(env: Env) {
  if (!authReady(env)) throw new Error('GitHub authentication has not been configured.');
  return betterAuth({
    appName: 'omapkg', baseURL: env.PUBLIC_ORIGIN, secret: env.BETTER_AUTH_SECRET,
    database: env.DB,
    trustedOrigins: [env.PUBLIC_ORIGIN],
    user: { additionalFields: { githubUsername: { type: 'string', required: false, input: false } } },
    socialProviders: { github: {
      clientId: env.GITHUB_CLIENT_ID!, clientSecret: env.GITHUB_CLIENT_SECRET!, scope: ['read:user', 'user:email'],
      mapProfileToUser: async (profile) => {
        const identity = await recordGithubOAuthProfile(env.DB, profile);
        return { githubUsername: identity.username };
      },
    } },
    account: { encryptOAuthTokens: true },
    databaseHooks: {
      session: {
        create: { after: async (session) => {
          const actor = await actorFor(env, session.userId);
          await syncGithubUserField(env.DB, session.userId);
          await audit(env.DB, actor.id, 'auth.signed_in', `session:${session.id}`).run();
        } },
        delete: { after: async (session) => {
          const actor = await actorFor(env, session.userId);
          await audit(env.DB, actor.id, 'auth.signed_out', `session:${session.id}`).run();
        } }
      }
    },
    session: { expiresIn: 60 * 60 * 24 * 7, updateAge: 60 * 60 * 24 },
    advanced: { useSecureCookies: env.PUBLIC_ORIGIN.startsWith('https:') },
    rateLimit: { enabled: true, storage: 'database' }
  });
}
export async function actorFor(env: Env, userId: string): Promise<Actor> {
  const account = await env.DB.prepare("SELECT accountId,accessToken FROM account WHERE userId=? AND providerId='github' AND issuer='local:oauth:github'").bind(userId).first<{ accountId: string; accessToken: string | null }>();
  const githubId = account?.accountId ?? '';
  if (githubId) {
    try {
      const accessToken = await storedGithubAccessToken(account?.accessToken, env.BETTER_AUTH_SECRET);
      await backfillGithubIdentity(env.DB, githubId, accessToken ?? undefined);
    } catch { /* profile display must not change immutable ID authorization */ }
  }
  const rows = await env.DB.prepare('SELECT team FROM team_memberships WHERE github_id=?').bind(githubId).all<{ team: Team }>();
  const memberships = rows.results.map((row) => row.team);
  const role = memberships.includes('admin') ? 'admin' : memberships.includes('security') ? 'security' : memberships.length ? 'maintainer' : 'public';
  return { id: githubId ? `github:${githubId}` : `user:${userId}`, role,
    areas: role === 'admin' || role === 'security' ? areas : memberships.filter((team) => areas.includes(team as typeof areas[number])) };
}
