import { PolicyError } from './policy';
import { now } from './db';

const GITHUB_API = 'https://api.github.com';
const USERNAME = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$/;
const GITHUB_ID = /^[1-9][0-9]{0,19}$/;
const AVATAR = /^https:\/\/(?:avatars\.githubusercontent\.com|github\.com)\//i;

export interface GithubIdentity {
  githubId: string;
  username: string;
  name: string | null;
  avatarUrl: string | null;
  lastLoginAt: number | null;
}

export interface GithubIdentityPreview {
  username: string;
  name: string | null;
  avatarUrl: string | null;
}

export function normalizeGithubUsername(input: unknown): string {
  if (typeof input !== 'string') throw new PolicyError(400, 'Enter a GitHub username.');
  const value = input.trim().replace(/^@/, '');
  if (!USERNAME.test(value)) throw new PolicyError(400, 'Enter a valid GitHub username.');
  return value;
}

export function normalizeGithubAccountId(input: unknown): string {
  const value = String(input ?? '');
  if (!GITHUB_ID.test(value)) throw new PolicyError(400, 'Maintainer account is invalid.');
  return value;
}

function githubId(input: unknown): string {
  const value = String(input ?? '');
  if (!GITHUB_ID.test(value)) throw new Error('GitHub profile ID is invalid.');
  return value;
}

function profileName(input: unknown): string | null {
  if (input === null || input === undefined || input === '') return null;
  if (typeof input !== 'string' || input.length > 256 || /[\u0000\r\n]/.test(input)) throw new Error('GitHub profile name is invalid.');
  return input;
}

function avatarUrl(input: unknown): string | null {
  if (input === null || input === undefined || input === '') return null;
  if (typeof input !== 'string' || input.length > 512 || !AVATAR.test(input)) throw new Error('GitHub avatar URL is invalid.');
  return input;
}

export function parseGithubProfile(input: unknown): GithubIdentity {
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw new Error('GitHub profile is invalid.');
  const profile = input as Record<string, unknown>;
  if (profile.type !== 'User') throw new PolicyError(422, 'GitHub account must be a user.');
  const username = normalizeGithubUsername(profile.login);
  return {
    githubId: githubId(profile.id),
    username,
    name: profileName(profile.name),
    avatarUrl: avatarUrl(profile.avatar_url),
    lastLoginAt: null,
  };
}

function apiHeaders(accessToken?: string): Headers {
  const headers = new Headers({
    Accept: 'application/vnd.github+json',
    'User-Agent': 'omarpkg',
    'X-GitHub-Api-Version': '2022-11-28',
  });
  if (accessToken) headers.set('Authorization', `Bearer ${accessToken}`);
  return headers;
}

async function githubGet(path: string, accessToken?: string): Promise<Record<string, unknown> | null> {
  const response = await fetch(`${GITHUB_API}${path}`, { headers: apiHeaders(accessToken), redirect: 'manual' });
  if (response.status >= 300 && response.status < 400) throw new PolicyError(502, 'GitHub profile lookup unexpectedly redirected.');
  if (response.status === 404) return null;
  if (!response.ok) throw new PolicyError(502, 'GitHub profile lookup failed.');
  let body: unknown;
  try { body = await response.json(); } catch { throw new PolicyError(502, 'GitHub returned an invalid profile.'); }
  if (!body || typeof body !== 'object' || Array.isArray(body)) throw new PolicyError(502, 'GitHub returned an invalid profile.');
  return body as Record<string, unknown>;
}

export async function githubUserByUsername(input: unknown, accessToken?: string): Promise<GithubIdentity | null> {
  const username = normalizeGithubUsername(input);
  const profile = await githubGet(`/users/${encodeURIComponent(username)}`, accessToken);
  return profile ? parseGithubProfile(profile) : null;
}

export async function githubUserById(input: string, accessToken?: string): Promise<GithubIdentity | null> {
  const id = githubId(input);
  const profile = await githubGet(`/user/${encodeURIComponent(id)}`, accessToken);
  if (!profile) return null;
  const identity = parseGithubProfile(profile);
  if (identity.githubId !== id) throw new PolicyError(502, 'GitHub profile identity did not match its account ID.');
  return identity;
}

export async function upsertGithubIdentity(db: D1Database, identity: GithubIdentity, lastLoginAt: number | null = identity.lastLoginAt): Promise<GithubIdentity> {
  const updatedAt = now();
  await db.prepare(`INSERT INTO github_identities(github_id,username,display_name,avatar_url,last_login_at,updated_at)
    VALUES(?,?,?,?,?,?)
    ON CONFLICT(github_id) DO UPDATE SET username=excluded.username,
      display_name=COALESCE(excluded.display_name,github_identities.display_name),
      avatar_url=COALESCE(excluded.avatar_url,github_identities.avatar_url),
      last_login_at=COALESCE(excluded.last_login_at,github_identities.last_login_at),updated_at=excluded.updated_at`)
    .bind(identity.githubId, identity.username, identity.name, identity.avatarUrl, lastLoginAt, updatedAt).run();
  return { ...identity, lastLoginAt };
}

export async function recordGithubOAuthProfile(db: D1Database, profile: unknown): Promise<GithubIdentity> {
  const identity = parseGithubProfile(profile);
  return upsertGithubIdentity(db, identity, now());
}

export async function backfillGithubIdentity(db: D1Database, githubId: string, accessToken?: string): Promise<GithubIdentity | null> {
  const cached = await cachedGithubIdentity(db, githubId);
  if (cached) return cached;
  const identity = await githubUserById(githubId, accessToken);
  return identity ? upsertGithubIdentity(db, identity, now()) : null;
}

export async function cachedGithubIdentity(db: D1Database, githubId: string): Promise<GithubIdentity | null> {
  const cached = await db.prepare(`SELECT github_id,username,display_name,avatar_url,last_login_at
    FROM github_identities WHERE github_id=?`).bind(githubId)
    .first<{ github_id: string; username: string; display_name: string | null; avatar_url: string | null; last_login_at: number | null }>();
  return cached ? { githubId: cached.github_id, username: cached.username, name: cached.display_name, avatarUrl: cached.avatar_url, lastLoginAt: cached.last_login_at } : null;
}

export async function syncGithubUserField(db: D1Database, userId: string): Promise<void> {
  const row = await db.prepare(`SELECT a.accountId AS github_id,i.username
    FROM account a JOIN github_identities i ON i.github_id=a.accountId
    WHERE a.userId=? AND a.providerId='github' AND a.issuer='local:oauth:github' LIMIT 1`)
    .bind(userId).first<{ github_id: string; username: string }>();
  if (!row) return;
  await db.prepare('UPDATE user SET githubUsername=?,updatedAt=? WHERE id=?').bind(row.username, Date.now(), userId).run();
}

export async function resolveGithubUsernameForGrant(db: D1Database, input: unknown, accessToken?: string): Promise<GithubIdentity> {
  const identity = await githubUserByUsername(input, accessToken);
  if (!identity) throw new PolicyError(404, 'GitHub user not found.');
  return upsertGithubIdentity(db, identity, null);
}

export async function validateGithubUsername(input: unknown, accessToken?: string): Promise<GithubIdentityPreview | null> {
  const identity = await githubUserByUsername(input, accessToken);
  return identity ? { username: identity.username, name: identity.name, avatarUrl: identity.avatarUrl } : null;
}

export async function githubIdentitySuggestions(db: D1Database, limit = 50): Promise<GithubIdentityPreview[]> {
  const boundedLimit = Number.isSafeInteger(limit) ? Math.min(Math.max(limit, 1), 100) : 50;
  const rows = await db.prepare(`SELECT username,display_name,avatar_url FROM github_identities
    WHERE last_login_at IS NOT NULL ORDER BY last_login_at DESC,lower(username) LIMIT ?`)
    .bind(boundedLimit).all<{ username: string; display_name: string | null; avatar_url: string | null }>();
  return rows.results.map((row) => ({ username: row.username, name: row.display_name, avatarUrl: row.avatar_url }));
}

export async function githubActorNames(db: D1Database): Promise<Record<string, string>> {
  const rows = await db.prepare('SELECT github_id,username FROM github_identities').all<{ github_id: string; username: string }>();
  return Object.fromEntries(rows.results.map((row) => [`github:${row.github_id}`, row.username]));
}
