import type { FactoryEnv, FactoryRevisionDraft } from './types';
import { githubFetch } from '../../src/lib/server/github';

interface GithubRepository {
  default_branch: string;
}

interface GithubRef {
  object: { sha: string };
}

interface GithubContent {
  sha?: string;
  content?: string;
}

interface GithubCommitResponse {
  commit?: { sha?: string };
}

interface GithubPullRequest {
  number: number;
  html_url: string;
  head: { sha: string };
}

function repositoryPath(value: string): string {
  if (!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(value)) throw new Error('GITHUB_REPOSITORY must be owner/repository');
  return value;
}

function encodeBase64(value: string): string {
  const bytes = new TextEncoder().encode(value);
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function branchName(requestId: string, revisionId: string): string {
  return `opr/factory-${requestId.replace(/[^A-Za-z0-9_.-]/g, '')}-${revisionId.replace(/[^A-Za-z0-9_.-]/g, '')}`;
}

async function github<T>(env: FactoryEnv, url: string, init: RequestInit = {}, expected: number | number[] = 200): Promise<T> {
  const response = await githubFetch(env, url, init);
  const accepted = Array.isArray(expected) ? expected : [expected];
  if (!accepted.includes(response.status)) {
    const detail = (await response.text()).slice(0, 500);
    throw new Error(`GitHub API ${response.status}: ${detail}`);
  }
  return await response.json() as T;
}

async function putFile(
  env: FactoryEnv,
  api: string,
  repo: string,
  branch: string,
  path: string,
  content: string,
): Promise<string> {
  let sha: string | undefined;
  try {
    const existing = await github<GithubContent>(env, `${api}/repos/${repo}/contents/${path}?ref=${encodeURIComponent(branch)}`);
    sha = existing.sha;
    if (sha && existing.content && existing.content.replaceAll(/\s/g, '') === encodeBase64(content)) return sha;
  } catch (cause) {
    if (!(cause instanceof Error && /GitHub API 404/.test(cause.message))) throw cause;
  }
  const result = await github<GithubCommitResponse>(env, `${api}/repos/${repo}/contents/${path}`, {
    method: 'PUT',
    body: JSON.stringify({
      message: `factory: generate ${path.split('/').at(-1) ?? path}`,
      content: encodeBase64(content),
      branch,
      ...(sha ? { sha } : {}),
    }),
  }, [200, 201]);
  const commitSha = result.commit?.sha;
  if (!commitSha) throw new Error('GitHub did not return the generated commit SHA');
  return commitSha;
}

export async function createFactoryPullRequest(env: FactoryEnv, draft: FactoryRevisionDraft): Promise<{ url: string; commitSha: string; branch: string }> {
  if (!env.GITHUB_REPOSITORY) throw new Error('GitHub source-of-truth integration is not configured');
  const repo = repositoryPath(env.GITHUB_REPOSITORY);
  const api = 'https://api.github.com';
  const repository = await github<GithubRepository>(env, `${api}/repos/${repo}`);
  const base = repository.default_branch;
  const branch = branchName(draft.revision.request_id, draft.revision.id);
  let headSha: string;
  try {
    headSha = (await github<GithubRef>(env, `${api}/repos/${repo}/git/ref/heads/${encodeURIComponent(branch)}`)).object.sha;
  } catch (cause) {
    if (!(cause instanceof Error && /GitHub API 404/.test(cause.message))) throw cause;
    const baseRef = await github<GithubRef>(env, `${api}/repos/${repo}/git/ref/heads/${encodeURIComponent(base)}`);
    await github(env, `${api}/repos/${repo}/git/refs`, {
      method: 'POST',
      body: JSON.stringify({ ref: `refs/heads/${branch}`, sha: baseRef.object.sha }),
    }, 201);
    headSha = baseRef.object.sha;
  }

  const packagePath = `packages/${draft.manifest.packageName}`;
  if (draft.revision.public_recipe && draft.revision.public_recipe !== draft.revision.recipe) {
    headSha = await putFile(env, api, repo, branch, `${packagePath}/PKGBUILD`, draft.revision.public_recipe);
    headSha = await putFile(env, api, repo, branch, `${packagePath}/opr-build.PKGBUILD`, draft.revision.recipe);
  } else {
    headSha = await putFile(env, api, repo, branch, `${packagePath}/PKGBUILD`, draft.revision.recipe);
  }
  headSha = await putFile(env, api, repo, branch, `${packagePath}/opr-manifest.json`, JSON.stringify(draft.manifest, null, 2) + '\n');
  headSha = await putFile(env, api, repo, branch, `${packagePath}/opr-lint.json`, draft.revision.lint_json + '\n');
  headSha = await putFile(env, api, repo, branch, `${packagePath}/opr-sbom.json`, draft.revision.sbom_json + '\n');

  const openPulls = await github<GithubPullRequest[]>(env, `${api}/repos/${repo}/pulls?state=open&head=${encodeURIComponent(repo.split('/')[0] + ':' + branch)}`);
  const existing = openPulls[0];
  if (existing) return { url: existing.html_url, commitSha: existing.head.sha, branch };

  const pull = await github<GithubPullRequest>(env, `${api}/repos/${repo}/pulls`, {
    method: 'POST',
    body: JSON.stringify({
      title: `factory: ${draft.manifest.packageName} ${draft.manifest.version}-${draft.manifest.pkgrel}`,
      head: branch,
      base,
      body: [
        'Generated by OPR factory. Maintainer review is required before build.',
        '',
        `- request: ${draft.manifest.requestId}`,
        `- recipe SHA-256: ${draft.revision.recipe_sha256}`,
        `- manifest SHA-256: ${draft.revision.manifest_sha256}`,
        `- source kind: ${draft.manifest.sourceKind}`,
        `- surface: ${draft.manifest.surface}`,
        ...(draft.revision.public_recipe_sha256 ? [`- public recipe SHA-256: ${draft.revision.public_recipe_sha256}`] : []),
      ].join('\n'),
    }),
  }, 201);
  return { url: pull.html_url, commitSha: pull.head.sha || headSha, branch };
}
