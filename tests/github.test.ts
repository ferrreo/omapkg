import { expect, test } from 'bun:test';
import { generateKeyPairSync, verify } from 'node:crypto';
import { githubAccessToken, githubFetch } from '../src/lib/server/github';

test('GitHub App signs short-lived JWTs and requests access only to recipe repository', async () => {
  const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const env = {
    GITHUB_APP_ID: '123', GITHUB_APP_INSTALLATION_ID: '456', GITHUB_REPOSITORY: 'owner/recipes',
    GITHUB_APP_PRIVATE_KEY: privateKey.export({ format: 'pem', type: 'pkcs1' }).toString()
  };
  const previous = globalThis.fetch;
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    expect(String(input)).toBe('https://api.github.com/app/installations/456/access_tokens');
    const token = new Headers(init?.headers).get('Authorization')!.slice('Bearer '.length);
    const [header, payload, signature] = token.split('.');
    expect(verify('RSA-SHA256', Buffer.from(`${header}.${payload}`), publicKey, Buffer.from(signature, 'base64url'))).toBe(true);
    const claims = JSON.parse(Buffer.from(payload, 'base64url').toString());
    expect(claims.iss).toBe('123');
    expect(claims.exp - claims.iat).toBeLessThanOrEqual(600);
    expect(JSON.parse(String(init?.body)).repositories).toEqual(['recipes']);
    return Response.json({ token: 'installation-test-token' });
  }) as typeof fetch;
  try { expect(await githubAccessToken(env)).toBe('installation-test-token'); }
  finally { globalThis.fetch = previous; }
});

test('GitHub helper rejects credential leakage and broad classic tokens', async () => {
  const env = { GITHUB_REPOSITORY: 'owner/recipes', GITHUB_REPO_TOKEN: 'github_pat_test' };
  const classicToken = ['gho', 'classic'].join('_');
  await expect(githubFetch(env, 'https://example.org/repos/owner/recipes')).rejects.toThrow();
  await expect(githubFetch(env, 'https://api.github.com/repos/owner/other')).rejects.toThrow();
  await expect(githubAccessToken({ ...env, GITHUB_REPO_TOKEN: classicToken })).rejects.toThrow();
});

test('GitHub helper rejects redirects at the edge', async () => {
  const previous = globalThis.fetch;
  globalThis.fetch = (async () => new Response(null, { status: 302, headers: { location: 'https://example.org' } })) as unknown as typeof fetch;
  try {
    await expect(githubFetch({ GITHUB_REPOSITORY: 'owner/recipes', GITHUB_REPO_TOKEN: 'github_pat_test' }, 'https://api.github.com/repos/owner/recipes')).rejects.toThrow('redirects are not allowed');
  } finally {
    globalThis.fetch = previous;
  }
});
