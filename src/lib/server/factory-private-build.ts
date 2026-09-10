import type { Architecture, Revision } from '../model';
import { now, sha256 } from './db';
import { attachFactoryAttemptBuilds, type FactoryAttempt, FactoryRunError } from './factory-runs';
import type { FactoryEnv } from '../../../services/pipeline/types';
import { packageFilename, parseOutputContract } from './build-outputs';

export interface PrivateFactoryBuild { id: string; architecture: Architecture }
export interface PrivateFactoryBuildResult {
  status: 'pending' | 'succeeded' | 'failed' | 'ambiguous';
  builds: PrivateFactoryBuild[];
  artifacts: Array<{ buildId: string; architecture: Architecture; key: string; sha256: string; size: number; filename: string }>;
  inputLocks: string[];
  dependencyPlans: string[];
  failure?: { buildId: string; architecture: Architecture; message: string };
}

export type PrivateFactoryBuildStatus = 'pending' | 'succeeded' | 'failed';

function architecture(value: string): value is Architecture { return value === 'x86_64' || value === 'aarch64'; }

async function savedPrivateBuilds(env: Pick<FactoryEnv, 'DB'>, runId: string, attempt: number) {
  return env.DB.prepare(`SELECT id,revision_id,architecture FROM builds WHERE factory_run_id=? AND factory_attempt=? AND private_candidate=1 ORDER BY architecture`)
    .bind(runId, attempt).all<{ id: string; revision_id: string; architecture: Architecture }>();
}

export async function queuePrivateFactoryBuilds(env: Pick<FactoryEnv, 'DB'>, runId: string, attempt: FactoryAttempt, revision: Pick<Revision, 'id' | 'architectures_json'>): Promise<PrivateFactoryBuild[]> {
  if (attempt.status !== 'running' || attempt.runId !== runId) throw new FactoryRunError('attempt-complete', 'Factory attempt is not executable.');
  const raw = JSON.parse(revision.architectures_json) as unknown;
  if (!Array.isArray(raw) || !raw.length || raw.some((value) => typeof value !== 'string' || !architecture(value))) throw new FactoryRunError('invalid-input', 'Private factory candidate has invalid target architectures.');
  const selected = [...new Set(raw)] as Architecture[];
  const existing = await savedPrivateBuilds(env, runId, attempt.attempt);
  if (existing.results.length) {
    if (existing.results.length !== selected.length || existing.results.some((row) => row.revision_id !== revision.id || !selected.includes(row.architecture))) throw new FactoryRunError('reservation-conflict', 'Private factory attempt is bound to different build inputs.');
    const builds = existing.results.map((row) => ({ id: row.id, architecture: row.architecture }));
    await attachFactoryAttemptBuilds(env.DB, runId, attempt.attempt, attempt.leaseToken, builds.map((build) => build.id));
    return builds;
  }
  const proposed = await Promise.all(selected.map(async (target) => ({ id: `factory-${(await sha256(`${runId}:${attempt.attempt}:${target}`)).slice(0, 48)}`, architecture: target })));
  const timestamp = now();
  const buildIds = JSON.stringify(proposed.map((build) => build.id).sort());
  await env.DB.batch([
    ...proposed.map((build) => env.DB.prepare(`INSERT INTO builds(id,revision_id,architecture,status,created_at,factory_run_id,factory_attempt,private_candidate)
    SELECT ?,?,?, 'queued',?,?,?,1 WHERE EXISTS (SELECT 1 FROM factory_runs r JOIN factory_run_attempts a ON a.run_id=r.id AND a.attempt=?
      WHERE r.id=? AND r.status='running' AND r.current_attempt=? AND r.lease_token=? AND r.lease_expires_at>unixepoch() AND a.status='running' AND a.lease_token=? AND a.lease_expires_at>unixepoch() AND a.candidate_revision_id=?) ON CONFLICT DO NOTHING`)
    .bind(build.id, revision.id, build.architecture, timestamp, runId, attempt.attempt, attempt.attempt, runId, attempt.attempt, attempt.leaseToken, attempt.leaseToken, revision.id)),
    env.DB.prepare(`UPDATE factory_run_attempts SET build_ids_json=?,updated_at=? WHERE run_id=? AND attempt=? AND status='running' AND lease_token=? AND lease_expires_at>? AND build_ids_json='[]'`)
      .bind(buildIds, timestamp, runId, attempt.attempt, attempt.leaseToken, timestamp),
  ]);
  const saved = await savedPrivateBuilds(env, runId, attempt.attempt);
  if (saved.results.length !== selected.length || saved.results.some((row) => row.revision_id !== revision.id || !selected.includes(row.architecture))) throw new FactoryRunError('lease-fenced', 'Factory attempt changed while queueing private builds.');
  const builds = saved.results.map((row) => ({ id: row.id, architecture: row.architecture }));
  await env.DB.prepare(`INSERT INTO audit_events(actor,action,target,detail,created_at) VALUES('factory','factory.private_builds_queued',?,?,?)`)
    .bind(runId, JSON.stringify({ attempt: attempt.attempt, revisionId: revision.id, builds }), timestamp).run();
  await attachFactoryAttemptBuilds(env.DB, runId, attempt.attempt, attempt.leaseToken, builds.map((build) => build.id));
  return builds;
}

export async function privateFactoryBuildResult(env: Pick<FactoryEnv, 'DB'>, runId: string, attempt: number, buildIds: readonly string[]): Promise<PrivateFactoryBuildResult> {
  if (!buildIds.length) throw new FactoryRunError('invalid-input', 'Private factory attempt has no builds.');
  const rows = await env.DB.prepare(`SELECT b.id,b.architecture,b.status,b.error,b.artifact_key,b.artifact_sha256,b.artifact_size,b.artifact_filename,b.input_lock_sha256,b.dependency_plan_json,b.output_contract_json,r.surface
    FROM builds b JOIN revisions r ON r.id=b.revision_id
    WHERE b.factory_run_id=? AND b.factory_attempt=? AND b.private_candidate=1 AND b.id IN (SELECT value FROM json_each(?)) ORDER BY b.id`)
    .bind(runId, attempt, JSON.stringify(buildIds)).all<{ id: string; architecture: Architecture; status: 'queued' | 'leased' | 'succeeded' | 'failed' | 'cancelled'; error: string | null; artifact_key: string | null; artifact_sha256: string | null; artifact_size: number | null; artifact_filename: string | null; input_lock_sha256: string | null; dependency_plan_json: string | null; output_contract_json: string | null; surface: 'binary' | 'recipe' }>();
  if (rows.results.length !== buildIds.length) throw new FactoryRunError('storage', 'Private factory build records are incomplete.');
  const builds = rows.results.map(({ id: buildId, architecture: target }) => ({ id: buildId, architecture: target }));
  const failed = rows.results.find((row) => row.status === 'failed' || row.status === 'cancelled');
  const inputLocks = [...new Set(rows.results.map((row) => row.input_lock_sha256).filter((value): value is string => Boolean(value)))].sort();
  const dependencyPlans = [...new Set(rows.results.map((row) => row.dependency_plan_json).filter((value): value is string => Boolean(value)))].sort();
  if (failed) return { status: 'failed', builds, artifacts: [], inputLocks, dependencyPlans, failure: { buildId: failed.id, architecture: failed.architecture, message: failed.error ?? `private build ${failed.status}` } };
  if (rows.results.some((row) => row.status !== 'succeeded')) return { status: 'pending', builds, artifacts: [], inputLocks, dependencyPlans };
  const artifacts = [] as PrivateFactoryBuildResult['artifacts'];
  for (const row of rows.results) {
    if (row.surface === 'recipe') continue;
    const outputs = await env.DB.prepare('SELECT filename,artifact_key,sha256,size FROM build_artifacts WHERE build_id=? AND attempt=(SELECT attempt FROM builds WHERE id=?) ORDER BY filename').bind(row.id, row.id).all<{ filename: string; artifact_key: string; sha256: string; size: number }>();
    let expectedNames: string[] | null = null;
    if (row.output_contract_json) {
      try { expectedNames = parseOutputContract(JSON.parse(row.output_contract_json), row.architecture).outputs.map(packageFilename).sort(); }
      catch { return { status: 'failed', builds, artifacts, inputLocks, dependencyPlans, failure: { buildId: row.id, architecture: row.architecture, message: 'Private build output contract is invalid.' } }; }
    }
    const expectedCount = expectedNames?.length ?? 1;
    if (outputs.results.length) artifacts.push(...outputs.results.map((output) => ({ buildId: row.id, architecture: row.architecture, key: output.artifact_key, sha256: output.sha256, size: output.size, filename: output.filename })));
    else if (row.artifact_key && row.artifact_sha256 && row.artifact_size !== null && row.artifact_filename) artifacts.push({ buildId: row.id, architecture: row.architecture, key: row.artifact_key, sha256: row.artifact_sha256, size: row.artifact_size, filename: row.artifact_filename });
    const targetArtifacts = artifacts.filter((artifact) => artifact.buildId === row.id);
    if (targetArtifacts.length !== expectedCount || (expectedNames && JSON.stringify(targetArtifacts.map((artifact) => artifact.filename).sort()) !== JSON.stringify(expectedNames))) return { status: 'failed', builds, artifacts, inputLocks, dependencyPlans, failure: { buildId: row.id, architecture: row.architecture, message: `Private build output set differs from declared outputs (${expectedCount} expected).` } };
  }
  if (rows.results.every((row) => row.surface === 'recipe')) return { status: 'succeeded', builds, artifacts, inputLocks, dependencyPlans };
  return { status: 'succeeded', builds, artifacts, inputLocks, dependencyPlans };
}

export async function privateFactoryBuildStatus(env: Pick<FactoryEnv, 'DB'>, runId: string, attempt: number, buildIds: readonly string[]): Promise<PrivateFactoryBuildStatus> {
  if (!buildIds.length) throw new FactoryRunError('invalid-input', 'Private factory attempt has no builds.');
  const rows = await env.DB.prepare(`SELECT id,status FROM builds
    WHERE factory_run_id=? AND factory_attempt=? AND private_candidate=1 AND id IN (SELECT value FROM json_each(?))`)
    .bind(runId, attempt, JSON.stringify(buildIds)).all<{ id: string; status: 'queued' | 'leased' | 'succeeded' | 'failed' | 'cancelled' }>();
  if (rows.results.length !== buildIds.length) throw new FactoryRunError('storage', 'Private factory build records are incomplete.');
  if (rows.results.some((row) => row.status === 'failed' || row.status === 'cancelled')) return 'failed';
  if (rows.results.some((row) => row.status !== 'succeeded')) return 'pending';
  return 'succeeded';
}

export async function waitForPrivateFactoryBuilds(env: Pick<FactoryEnv, 'DB'>, runId: string, attempt: FactoryAttempt, options: { timeoutMs?: number; pollMs?: number } = {}): Promise<PrivateFactoryBuildResult> {
  const timeoutMs = options.timeoutMs ?? 150 * 60_000, pollMs = options.pollMs ?? 30_000;
  if (!attempt.buildIds.length) throw new FactoryRunError('invalid-input', 'Private factory attempt has no queued builds.');
  const deadline = Date.now() + timeoutMs;
  while (Date.now() <= deadline) {
    const status = await privateFactoryBuildStatus(env, runId, attempt.attempt, attempt.buildIds);
    if (status !== 'pending') return privateFactoryBuildResult(env, runId, attempt.attempt, attempt.buildIds);
    await new Promise((resolve) => setTimeout(resolve, pollMs));
  }
  const status = await privateFactoryBuildStatus(env, runId, attempt.attempt, attempt.buildIds);
  const result = await privateFactoryBuildResult(env, runId, attempt.attempt, attempt.buildIds);
  return status === 'pending' && result.status === 'pending' ? { ...result, status: 'ambiguous', failure: { buildId: result.builds[0].id, architecture: result.builds[0].architecture, message: 'Private factory build timed out; execution status is ambiguous.' } } : result;
}
