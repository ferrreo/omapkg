import { audit, now, sha256 } from '../../src/lib/server/db';
import { githubFetch } from '../../src/lib/server/github';
import type { FactoryEnv } from './types';
import { redactText } from './security';

interface Repository {
  default_branch: string;
}

interface Branch {
  commit?: { sha?: string };
}

interface ContentsFile {
  type?: string;
  encoding?: string;
  content?: string;
}

interface CanonicalRevision {
  id: string;
  request_id: string;
  name: string;
  source_kind: 'git' | 'archive';
  status: string;
  version: string;
  recipe: string;
  recipe_sha256: string;
  public_recipe: string | null;
  public_recipe_sha256: string | null;
  manifest_sha256: string;
  sources_json: string;
  dependencies_json: string;
  make_dependencies_json: string;
  smoke_commands_json: string;
  architectures_json: string;
  build_images_json: string;
  pkgrel: number;
  source_date_epoch: number;
  image_digest: string;
  license: string;
  surface: 'binary' | 'recipe';
  description?: string | null;
  lint_json: string;
  sbom_json: string;
  commit_sha: string;
}

export interface IntegrityIssue {
  revisionId: string;
  requestId: string;
  packageName: string;
  reason: string;
  paths: string[];
  approvedCommitSha: string;
  currentHeadSha: string;
  frozen: boolean;
}

export interface SourceTruthCheckResult {
  repository: string;
  branch: string;
  headSha: string;
  checked: number;
  passed: boolean;
  issues: IntegrityIssue[];
  frozenRequestIds: string[];
}

function repositoryPath(value: string): string {
  if (!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(value)) throw new Error('GITHUB_REPOSITORY must be owner/repository');
  return value;
}

function pathForApi(path: string): string {
  return path.split('/').map(encodeURIComponent).join('/');
}

async function github<T>(env: FactoryEnv, url: string, init: RequestInit = {}): Promise<T> {
  const response = await githubFetch(env, url, init);
  if (!response.ok) {
    // Keep upstream response bodies out of audit events. They can contain
    // repository content or URLs that are not safe to retain verbatim.
    const detail = redactText((await response.text()).slice(0, 160));
    throw new Error(`source-of-truth GitHub request failed (${response.status})${detail ? `: ${detail}` : ''}`);
  }
  return await response.json() as T;
}

async function readFile(
  api: string,
  repository: string,
  path: string,
  ref: string,
  env: FactoryEnv,
): Promise<string | null> {
  const response = await githubFetch(
    env,
    `${api}/repos/${repository}/contents/${pathForApi(path)}?ref=${encodeURIComponent(ref)}`,
    { method: 'GET' },
  );
  if (response.status === 404) return null;
  if (!response.ok) throw new Error(`source-of-truth file request failed (${response.status})`);
  const file = await response.json() as ContentsFile;
  if (file.type !== 'file' || file.encoding !== 'base64' || !file.content) return null;
  const binary = atob(file.content.replaceAll(/\s/g, ''));
  const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
  return new TextDecoder().decode(bytes);
}

function parseJson(value: string, field: string): unknown {
  try {
    return JSON.parse(value);
  } catch {
    throw new Error(`${field} is not valid JSON`);
  }
}

function expectedManifest(revision: CanonicalRevision): Record<string, unknown> {
  const manifest: Record<string, unknown> = {
    requestId: revision.request_id,
    packageName: revision.name,
    version: revision.version,
    sourceKind: revision.source_kind,
    sources: parseJson(revision.sources_json, 'sources_json'),
    dependencies: parseJson(revision.dependencies_json, 'dependencies_json'),
    makeDependencies: parseJson(revision.make_dependencies_json, 'make_dependencies_json'),
    smokeCommands: parseJson(revision.smoke_commands_json, 'smoke_commands_json'),
    architectures: parseJson(revision.architectures_json, 'architectures_json'),
    buildImages: parseJson(revision.build_images_json, 'build_images_json'),
    pkgrel: revision.pkgrel,
    sourceDateEpoch: revision.source_date_epoch,
    imageDigest: revision.image_digest,
    license: revision.license,
    surface: revision.surface,
    ...(revision.description != null ? { description: revision.description } : {}),
    publicRecipeSha256: revision.public_recipe_sha256,
  };
  return manifest;
}

function expectedFiles(revision: CanonicalRevision): Record<string, string> {
  const packagePath = `packages/${revision.name}`;
  const files: Record<string, string> = {
    [`${packagePath}/PKGBUILD`]: revision.public_recipe ?? revision.recipe,
    [`${packagePath}/opr-manifest.json`]: `${JSON.stringify(expectedManifest(revision), null, 2)}\n`,
    [`${packagePath}/opr-lint.json`]: `${revision.lint_json}\n`,
    [`${packagePath}/opr-sbom.json`]: `${revision.sbom_json}\n`,
  };
  if (revision.public_recipe !== null && revision.public_recipe !== revision.recipe) files[`${packagePath}/opr-build.PKGBUILD`] = revision.recipe;
  return files;
}

async function checkRevision(
  api: string,
  repository: string,
  revision: CanonicalRevision,
  headSha: string,
  env: FactoryEnv,
): Promise<{ paths: string[]; reason: string }> {
  const expected = expectedFiles(revision);
  const entries = await Promise.all(Object.entries(expected).map(async ([path, content]) => {
    const actual = await readFile(api, repository, path, headSha, env);
    if (actual === null) return [path, 'missing'] as const;
    const [actualDigest, expectedDigest] = await Promise.all([sha256(actual), sha256(content)]);
    if (actualDigest !== expectedDigest) return [path, 'hash mismatch'] as const;
    return null;
  }));
  const mismatches: Array<readonly [string, string]> = [];
  for (const entry of entries) if (entry !== null) mismatches.push(entry);
  if (!mismatches.length) return { paths: [], reason: '' };
  return {
    paths: mismatches.map(([path]) => path),
    reason: mismatches.map(([path, reason]) => `${path}: ${reason}`).join('; '),
  };
}

async function freezeRequest(env: Pick<FactoryEnv, 'DB'>, issue: Omit<IntegrityIssue, 'frozen'>): Promise<boolean> {
  const reason = `Source-of-truth integrity check failed: ${issue.reason}`.slice(0, 2_000);
  const timestamp = now();
  const result = await env.DB.batch([
    env.DB.prepare(`UPDATE requests SET status='failed', rejection_reason=?, updated_at=?
      WHERE id=? AND status IN ('review','queued','building')`).bind(reason, timestamp, issue.requestId),
    env.DB.prepare(`UPDATE builds SET status='cancelled', error=?
      WHERE revision_id=? AND status IN ('queued','leased')`).bind(reason, issue.revisionId),
    env.DB.prepare(`INSERT INTO factory_events(request_id,stage,detail,created_at)
      VALUES(?,?,?,?)`).bind(issue.requestId, 'source_integrity_failed', JSON.stringify({
        revisionId: issue.revisionId,
        paths: issue.paths,
        approvedCommitSha: issue.approvedCommitSha,
        currentHeadSha: issue.currentHeadSha,
      }), timestamp),
    audit(env.DB, 'system:integrity-check', 'source_of_truth.integrity_failed', issue.requestId, {
      revisionId: issue.revisionId,
      reason,
      paths: issue.paths,
      approvedCommitSha: issue.approvedCommitSha,
      currentHeadSha: issue.currentHeadSha,
    }),
  ]);
  return result[0].meta.changes > 0;
}

/**
 * Verify approved revisions against the current canonical repository tree.
 * A mismatch is frozen before another worker can claim queued work. Manual
 * repository changes are recorded; they never become a new approved revision.
 */
export async function checkSourceOfTruth(env: FactoryEnv): Promise<SourceTruthCheckResult> {
  if (!env.GITHUB_REPOSITORY) throw new Error('GitHub source-of-truth integration is not configured');
  const repository = repositoryPath(env.GITHUB_REPOSITORY);
  const api = 'https://api.github.com';
  const repo = await github<Repository>(env, `${api}/repos/${repository}`);
  const branch = repo.default_branch;
  const branchInfo = await github<Branch>(env, `${api}/repos/${repository}/branches/${encodeURIComponent(branch)}`);
  const headSha = branchInfo.commit?.sha;
  if (!headSha || !/^[0-9a-f]{40}$/i.test(headSha)) throw new Error('source-of-truth branch did not return a commit SHA');

  const rows = await env.DB.prepare(`
    SELECT r.id,r.request_id,q.name,q.source_kind,q.status,r.version,r.recipe,r.recipe_sha256,r.public_recipe,r.public_recipe_sha256,
      r.manifest_sha256,r.sources_json,r.dependencies_json,r.make_dependencies_json,r.smoke_commands_json,r.architectures_json,
      r.build_images_json,r.pkgrel,r.source_date_epoch,r.image_digest,r.license,r.surface,r.description,r.lint_json,r.sbom_json,r.commit_sha
    FROM revisions r
    JOIN requests q ON q.id=r.request_id
    WHERE q.status IN ('queued','building','built')
      AND r.pr_url IS NOT NULL AND r.commit_sha IS NOT NULL
      AND EXISTS (SELECT 1 FROM builds b WHERE b.revision_id=r.id AND b.status IN ('queued','leased','succeeded'))
      AND EXISTS (SELECT 1 FROM approvals a WHERE a.revision_id=r.id AND a.kind='area' AND a.manifest_sha256=r.manifest_sha256 AND a.revoked_at IS NULL)
      AND EXISTS (SELECT 1 FROM approvals a WHERE a.revision_id=r.id AND a.kind='security' AND a.manifest_sha256=r.manifest_sha256 AND a.revoked_at IS NULL)
      AND NOT EXISTS (
        SELECT 1 FROM revisions newer
        JOIN requests newer_request ON newer_request.id=newer.request_id
        WHERE newer_request.name=q.name
          AND newer_request.status IN ('queued','building','built')
          AND newer.pr_url IS NOT NULL AND newer.commit_sha IS NOT NULL
          AND EXISTS (SELECT 1 FROM builds newer_build WHERE newer_build.revision_id=newer.id AND newer_build.status IN ('queued','leased','succeeded'))
          AND EXISTS (SELECT 1 FROM approvals newer_area WHERE newer_area.revision_id=newer.id AND newer_area.kind='area' AND newer_area.manifest_sha256=newer.manifest_sha256 AND newer_area.revoked_at IS NULL)
          AND EXISTS (SELECT 1 FROM approvals newer_security WHERE newer_security.revision_id=newer.id AND newer_security.kind='security' AND newer_security.manifest_sha256=newer.manifest_sha256 AND newer_security.revoked_at IS NULL)
          AND (newer.created_at>r.created_at OR (newer.created_at=r.created_at AND newer.rowid>r.rowid))
      )
    ORDER BY r.created_at ASC,r.id ASC`).all<CanonicalRevision>();

  const issues: IntegrityIssue[] = [];
  for (const revision of rows.results) {
    const checked = await checkRevision(api, repository, revision, headSha, env);
    if (!checked.paths.length) continue;
    const issueBase = {
      revisionId: revision.id,
      requestId: revision.request_id,
      packageName: revision.name,
      reason: checked.reason,
      paths: checked.paths,
      approvedCommitSha: revision.commit_sha,
      currentHeadSha: headSha,
    };
    const frozen = await freezeRequest(env, issueBase);
    issues.push({ ...issueBase, frozen });
  }

  return {
    repository,
    branch,
    headSha,
    checked: rows.results.length,
    passed: issues.length === 0,
    issues,
    frozenRequestIds: [...new Set(issues.filter((issue) => issue.frozen).map((issue) => issue.requestId))],
  };
}
