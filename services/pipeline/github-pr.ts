import type { FactoryEnv, FactoryRevisionDraft } from './types';
import { githubFetch } from '../../src/lib/server/github';
import { revisionRecipePolicy } from './recipe-policy';
import { revisionPackagePath } from '../../src/lib/server/catalog-recipe';
import { createHash } from 'node:crypto';
import { packagePath, recipeFilePath, type Collection } from '../../src/lib/distribution';
import { preservedRecipe } from '../../src/lib/preserved-recipe';
import { getRecipeCapture, recipeCaptureBytes } from '../../src/lib/server/recipe-captures';
import { verifyRecipeCapture } from '../../src/lib/recipe-capture';
import { reviewedPackageVersion } from '../../src/lib/server/build-outputs';
import type { Revision } from '../../src/lib/model';

interface GithubRepository {
  default_branch: string;
}

interface GithubRef {
  object: { sha: string };
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

export type RecipeTreeFile = { path: string; bytes: Uint8Array; mode?: '100644' | '100755' | '120000' };

/** Publish all files with one ref update; failed uploads cannot expose a partial recipe. */
export async function commitRecipeTree(env: FactoryEnv, branch: string, parent: string, files: RecipeTreeFile[], message: string, roots: string[]): Promise<string> {
  const repo = repositoryPath(env.GITHUB_REPOSITORY ?? '');
  const api = `https://api.github.com/repos/${repo}/git`;
  if (!/^[a-f0-9]{40}$/.test(parent) || !files.length || files.length > 4096 ||
      new Set(files.map((file) => file.path)).size !== files.length ||
      files.reduce((size, file) => size + file.bytes.length, 0) > 36 * 1024 * 1024) throw new Error('Invalid or oversized recipe tree');
  if (!roots.length || new Set(roots).size !== roots.length || roots.some((root) => roots.some((other) => root !== other && root.startsWith(other + '/')))) throw new Error('Recipe directories overlap');
  for (const root of roots) {
    const parts = root.split('/');
    if (parts.length < 2 || parts.length > 3 || root !== packagePath(parts.at(-1)!, parts.length === 3 ? parts[1] as Collection : null)) throw new Error('Invalid recipe directory');
  }
  for (const file of files) {
    recipeFilePath(file.path);
    if (!roots.some((root) => file.path.startsWith(root + '/'))) throw new Error('Recipe file is outside its package directory');
    if (file.mode !== undefined && file.mode !== '100644' && file.mode !== '100755' && file.mode !== '120000') throw new Error('Unsafe recipe tree mode');
  }
  const before = await github<GithubRef>(env, `${api}/ref/heads/${encodeURIComponent(branch)}`);
  if (before.object.sha !== parent) throw new Error('Recipe branch changed; refresh before retrying');
  const base = await github<{ tree: { sha: string } }>(env, `${api}/commits/${parent}`);
  const directories = new Map<string, Array<{ path: string; mode: string; type: string; sha: string }>>();
  for (const file of [...files].sort((a, b) => a.path < b.path ? -1 : 1)) {
    const expected = createHash('sha1').update(`blob ${file.bytes.length}\0`).update(file.bytes).digest('hex');
    const blob = await github<{ sha: string }>(env, `${api}/blobs`, {
      method: 'POST', body: JSON.stringify({ encoding: 'base64', content: Buffer.from(file.bytes).toString('base64') }),
    }, 201);
    if (blob.sha !== expected) throw new Error('GitHub recipe blob differs from retained bytes');
    const directory = roots.find((root) => file.path.startsWith(root + '/'))!;
    const entries = directories.get(directory) ?? [];
    entries.push({ path: file.path.slice(directory.length + 1), mode: file.mode ?? '100644', type: 'blob', sha: blob.sha });
    directories.set(directory, entries);
  }
  const tree = [];
  for (const [path, entries] of directories) {
    // Replacing the complete directory also removes obsolete hooks or patches.
    const directory = await github<{ sha: string }>(env, `${api}/trees`, { method: 'POST', body: JSON.stringify({ tree: entries }) }, 201);
    if (!/^[a-f0-9]{40}$/.test(directory.sha)) throw new Error('GitHub returned an invalid recipe directory');
    tree.push({ path, mode: '040000', type: 'tree', sha: directory.sha });
  }
  const created = await github<{ sha: string }>(env, `${api}/trees`, {
    method: 'POST', body: JSON.stringify({ base_tree: base.tree.sha, tree }),
  }, 201);
  if (!/^[a-f0-9]{40}$/.test(created.sha)) throw new Error('GitHub returned an invalid tree');
  // An identical retry returns the commit, never the last file's blob identity.
  if (created.sha === base.tree.sha) return parent;
  const commit = await github<{ sha: string }>(env, `${api}/commits`, {
    method: 'POST', body: JSON.stringify({ message, tree: created.sha, parents: [parent] }),
  }, 201);
  if (!/^[a-f0-9]{40}$/.test(commit.sha)) throw new Error('GitHub returned an invalid commit');
  await github(env, `${api}/refs/heads/${encodeURIComponent(branch)}`, {
    method: 'PATCH', body: JSON.stringify({ sha: commit.sha, force: false }),
  });
  return commit.sha;
}

type RecipeFileDraft = { manifest: Record<string, unknown> & { packageName: string };
  revision: Pick<Revision, 'id' | 'sbom_json' | 'architectures_json' | 'public_recipe' | 'recipe' | 'lint_json'> };

export function factoryRecipeFiles(draft: RecipeFileDraft, originals?: RecipeTreeFile[]): RecipeTreeFile[] {
  const path = revisionPackagePath(draft.manifest.packageName, draft.revision.sbom_json);
  const preserved = preservedRecipe(draft.revision);
  if (Boolean(preserved) !== Boolean(originals)) throw new Error('Preserved revisions require the complete original recipe tree');
  const metadata = preserved ? preserved.metadataDirectory + '/' : '';
  const contents: Record<string, string> = {
    ...(!preserved ? { PKGBUILD: draft.revision.public_recipe ?? draft.revision.recipe } : {}),
    [metadata + 'opr-manifest.json']: JSON.stringify(draft.manifest, null, 2) + '\n',
    [metadata + 'opr-lint.json']: draft.revision.lint_json + '\n',
    [metadata + 'opr-sbom.json']: draft.revision.sbom_json + '\n',
  };
  if (draft.revision.public_recipe && draft.revision.public_recipe !== draft.revision.recipe) contents['opr-build.PKGBUILD'] = draft.revision.recipe;
  return [...(originals ?? []), ...Object.entries(contents).map(([name, content]) => ({ path: `${path}/${name}`, bytes: new TextEncoder().encode(content) }))];
}

export async function revisionRecipeFiles(env: FactoryEnv, draft: RecipeFileDraft): Promise<RecipeTreeFile[]> {
  const preserved = preservedRecipe(draft.revision);
  if (!preserved) return factoryRecipeFiles(draft);
  if (draft.revision.public_recipe != null) throw new Error('A preserved recipe cannot replace original public bytes');
  const capture = await getRecipeCapture(env, preserved.capture.sha256);
  if (capture.reference.size !== preserved.capture.size || capture.manifest.pkgbase !== draft.manifest.packageName) throw new Error('Recipe capture differs from reviewed scope');
  const inspected = await verifyRecipeCapture(capture.manifest, (ref) => recipeCaptureBytes(env, ref));
  if (new TextDecoder('utf-8', { fatal: true }).decode(inspected.get('PKGBUILD')) !== draft.revision.recipe) throw new Error('Preserved PKGBUILD differs from reviewed bytes');
  const path = revisionPackagePath(draft.manifest.packageName, draft.revision.sbom_json), originals = [];
  for (const file of capture.manifest.files) {
    if (file.path === preserved.metadataDirectory || file.path.startsWith(preserved.metadataDirectory + '/')) throw new Error('Review metadata collides with original recipe files');
    originals.push({ path: `${path}/${file.path}`, bytes: await recipeCaptureBytes(env, file.object), mode: file.mode });
  }
  return factoryRecipeFiles(draft, originals);
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

  const files = await revisionRecipeFiles(env, draft), preserved = preservedRecipe(draft.revision);
  const version = reviewedPackageVersion(draft.revision);
  headSha = await commitRecipeTree(env, branch, headSha, files,
    `Update ${draft.manifest.packageName} ${version}`,
    [revisionPackagePath(draft.manifest.packageName, draft.revision.sbom_json)]);

  const openPulls = await github<GithubPullRequest[]>(env, `${api}/repos/${repo}/pulls?state=open&head=${encodeURIComponent(repo.split('/')[0] + ':' + branch)}`);
  const existing = openPulls[0];
  if (existing) {
    if (existing.head.sha !== headSha) throw new Error('Recipe pull request changed during creation');
    return { url: existing.html_url, commitSha: headSha, branch };
  }

  const pull = await github<GithubPullRequest>(env, `${api}/repos/${repo}/pulls`, {
    method: 'POST',
    body: JSON.stringify({
      title: `${preserved ? 'import' : 'factory'}: ${draft.manifest.packageName} ${version}`,
      head: branch,
      base,
      body: [
        preserved ? 'Preserves the complete captured recipe directory, including file bytes, Git modes, hooks and patches. Independent recipe and security review is required before build.' : 'Generated by OPR factory. Maintainer review is required before build.',
        '',
        `- request: ${draft.manifest.requestId}`,
        `- recipe SHA-256: ${draft.revision.recipe_sha256}`,
        `- manifest SHA-256: ${draft.revision.manifest_sha256}`,
        `- source kind: ${draft.manifest.sourceKind}`,
        `- surface: ${draft.manifest.surface}`,
        `- recipe mode: ${revisionRecipePolicy(draft.revision.sbom_json).mode}`,
        ...(preserved ? [`- original capture SHA-256: ${preserved.capture.sha256}`, `- review metadata: ${preserved.metadataDirectory}/`,
          ...Object.entries(preserved.sources).map(([target, ref]) => `- ${target} source bundle SHA-256: ${ref.sha256}`)] : []),
        ...(revisionRecipePolicy(draft.revision.sbom_json).mode === 'custom-shell' ? ['- Custom shell: review preparation, build, packaging, public recipe, and smoke commands explicitly.'] : []),
        ...(draft.revision.public_recipe_sha256 ? [`- public recipe SHA-256: ${draft.revision.public_recipe_sha256}`] : []),
      ].join('\n'),
    }),
  }, 201);
  if (pull.head.sha !== headSha) throw new Error('Recipe pull request changed during creation');
  return { url: pull.html_url, commitSha: headSha, branch };
}
