import { createPrivateKey, sign } from 'node:crypto';

const API_ORIGIN = 'https://api.github.com';
const API_VERSION = '2022-11-28';

export interface GitHubEnv {
  GITHUB_APP_ID?: string;
  GITHUB_APP_INSTALLATION_ID?: string;
  GITHUB_APP_PRIVATE_KEY?: string;
  GITHUB_REPOSITORY?: string;
  /** Fine-grained PAT fallback for local/test deployments only. */
  GITHUB_REPO_TOKEN?: string;
}

function base64Url(value: string | Uint8Array): string {
  return Buffer.from(value).toString('base64url');
}

function requiredRepository(env: GitHubEnv): { owner: string; name: string } {
  const fullName = env.GITHUB_REPOSITORY?.trim() ?? '';
  const match = fullName.match(/^([^/]+)\/([^/]+)$/);
  if (!match || !match[1] || !match[2] || /[^A-Za-z0-9_.-]/.test(match[1] + match[2])) {
    throw new Error('GITHUB_REPOSITORY must be owner/name.');
  }
  return { owner: match[1], name: match[2] };
}

function appConfigured(env: GitHubEnv): boolean {
  return Boolean(env.GITHUB_APP_ID || env.GITHUB_APP_INSTALLATION_ID || env.GITHUB_APP_PRIVATE_KEY);
}

async function appJwt(env: GitHubEnv): Promise<string> {
  const appId = env.GITHUB_APP_ID?.trim();
  const privateKey = env.GITHUB_APP_PRIVATE_KEY;
  if (!appId || !privateKey) throw new Error('GitHub App credentials are incomplete.');

  const now = Math.floor(Date.now() / 1_000);
  const header = base64Url(JSON.stringify({ alg: 'RS256', typ: 'JWT' }));
  const payload = base64Url(JSON.stringify({ iat: now - 60, exp: now + 9 * 60, iss: appId }));
  const signingInput = `${header}.${payload}`;
  return `${signingInput}.${base64Url(sign('RSA-SHA256', signingInput, createPrivateKey(privateKey)))}`;
}

async function installationToken(env: GitHubEnv): Promise<string> {
  const installationId = env.GITHUB_APP_INSTALLATION_ID?.trim();
  if (!installationId || !/^\d+$/.test(installationId)) throw new Error('GITHUB_APP_INSTALLATION_ID must be numeric.');
  const repository = requiredRepository(env);
  const response = await fetch(`${API_ORIGIN}/app/installations/${installationId}/access_tokens`, {
    method: 'POST',
    headers: {
      Accept: 'application/vnd.github+json',
      Authorization: `Bearer ${await appJwt(env)}`,
      'Content-Type': 'application/json',
      'User-Agent': 'omarpkg',
      'X-GitHub-Api-Version': API_VERSION,
    },
    body: JSON.stringify({
      repositories: [repository.name],
      permissions: { checks: 'read', contents: 'write', metadata: 'read', pull_requests: 'write' },
    }),
  });
  if (!response.ok) throw new Error(`GitHub App installation token request failed (${response.status}).`);
  const body = await response.json() as { token?: unknown };
  if (typeof body.token !== 'string' || !body.token) throw new Error('GitHub App returned no installation token.');
  return body.token;
}

export async function githubAccessToken(env: GitHubEnv): Promise<string> {
  if (appConfigured(env)) return installationToken(env);
  const token = env.GITHUB_REPO_TOKEN?.trim();
  if (token?.startsWith('github_pat_')) return token;
  throw new Error('GitHub repository integration is not configured.');
}

export async function githubFetch(env: GitHubEnv, input: string | URL, init: RequestInit = {}): Promise<Response> {
  const url = new URL(input.toString());
  if (url.origin !== API_ORIGIN) throw new Error('GitHub API requests must target api.github.com.');
  const repository = requiredRepository(env);
  const path = `/repos/${encodeURIComponent(repository.owner)}/${encodeURIComponent(repository.name)}`;
  if (url.pathname !== path && !url.pathname.startsWith(`${path}/`)) throw new Error('GitHub API request is outside the configured repository.');
  const headers = new Headers(init.headers);
  headers.set('Accept', 'application/vnd.github+json');
  headers.set('Authorization', `Bearer ${await githubAccessToken(env)}`);
  headers.set('User-Agent', 'omarpkg');
  headers.set('X-GitHub-Api-Version', API_VERSION);
  const response = await fetch(url, { ...init, headers, redirect: 'manual' });
  if (response.status >= 300 && response.status < 400) throw new Error('GitHub API redirects are not allowed.');
  return response;
}
