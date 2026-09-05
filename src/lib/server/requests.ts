import type { Actor, Approval, Architecture, PackageRequest, Revision } from '../model';
import type { Env } from './env';
import { githubFetch } from './github';
import { audit, id, now, query } from './db';
import { parseRequest, PolicyError, requireMaintainer, requireSecurity, validateRevision } from './policy';

export async function submitRequest(env: Env, actor: Actor | null, input: unknown) {
  if (!actor) throw new PolicyError(401, 'Sign in with GitHub to request a package.');
  const value = parseRequest(input);
  const existing = await env.DB.prepare("SELECT id FROM requests WHERE name=? AND status NOT IN ('built','rejected','failed')")
    .bind(value.name).first<{ id: string }>();
  if (existing) throw new PolicyError(409, 'An active request for this package already exists.');
  const timestamp = now();
  const requestId = id();
  const rateKey = `request:${actor.id}`;
  let result: D1Result[];
  try {
    result = await env.DB.batch([
      env.DB.prepare(`INSERT INTO rateLimit(id,key,count,lastRequest) VALUES(?,?,1,?)
        ON CONFLICT(key) DO UPDATE SET
          count=CASE WHEN rateLimit.lastRequest<=? THEN 1 WHEN rateLimit.count<10 THEN rateLimit.count+1 ELSE 11 END,
          lastRequest=CASE WHEN rateLimit.lastRequest<=? OR rateLimit.count<10 THEN ? ELSE rateLimit.lastRequest END`)
        .bind(id(), rateKey, timestamp, timestamp - 3_600, timestamp - 3_600, timestamp),
      env.DB.prepare(`INSERT INTO requests(id,name,description,upstream_url,source_kind,area,declared_license,requested_by,status,created_at,updated_at)
        SELECT ?,?,?,?,?,?,?,?,'pending',?,? FROM rateLimit WHERE key=? AND count BETWEEN 1 AND 10`)
        .bind(requestId, value.name, value.description, value.upstream_url, value.source_kind, value.area, value.declared_license, actor.id, timestamp, timestamp, rateKey),
      env.DB.prepare(`INSERT INTO audit_events(actor,action,target,detail,created_at)
        SELECT ?,?,?,?,? WHERE changes()=1`)
        .bind(actor.id, 'request.created', requestId, JSON.stringify(value), timestamp)
    ]);
  } catch (cause) {
    if (cause instanceof Error && /UNIQUE constraint failed: requests\.name/i.test(cause.message)) {
      throw new PolicyError(409, 'An active request for this package already exists.');
    }
    throw cause;
  }
  if (!result[1]?.meta.changes) throw new PolicyError(429, 'Request limit reached. Try again in one hour.');
  return requestId;
}
export async function getRequest(env: Env, requestId: string) {
  const request = await env.DB.prepare('SELECT * FROM requests WHERE id=?').bind(requestId).first<PackageRequest>();
  if (!request) throw new PolicyError(404, 'Package request not found.');
  return request;
}
export async function startFactory(env: Env, actor: Actor | null, requestId: string, reason?: string) {
  const request = await getRequest(env, requestId) as PackageRequest & { factory_run_id?: string | null };
  const reviewer = requireMaintainer(actor, request.area);
  if (reason !== undefined && (typeof reason !== 'string' || !reason.trim() || reason.length > 2_000)) {
    throw new PolicyError(400, 'Provide a regeneration reason, up to 2,000 characters.');
  }
  if (!['pending', 'failed', 'review'].includes(request.status)) throw new PolicyError(409, 'This request cannot start factory generation in its current state.');
  if (!env.PIPELINE) throw new PolicyError(503, 'Factory service is not configured.');
  const generationId = id();
  const result = await env.DB.batch([
    env.DB.prepare('UPDATE requests SET status=\'generating\',factory_run_id=?,updated_at=? WHERE id=? AND status=?').bind(generationId, now(), requestId, request.status),
    env.DB.prepare('INSERT INTO audit_events(actor,action,target,detail,created_at) SELECT ?,?,?,?,? WHERE changes()=1')
      .bind(reviewer.id, request.status === 'pending' ? 'request.approved' : 'factory.regenerated', requestId, JSON.stringify({ previousStatus: request.status, generationId, ...(reason === undefined ? {} : { reason: reason.trim() }) }), now())
  ]);
  if (!result[0].meta.changes) throw new PolicyError(409, 'Request changed. Refresh and retry.');
  try {
    const response = await env.PIPELINE.fetch('https://pipeline.internal/factory', {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ requestId, generationId })
    });
    if (!response.ok) throw new Error(`Factory dispatch failed (${response.status}).`);
  } catch (cause) {
    const failure = await env.DB.batch([
      env.DB.prepare("UPDATE requests SET status='failed',updated_at=? WHERE id=? AND status='generating' AND factory_run_id=?").bind(now(), requestId, generationId),
      env.DB.prepare(`INSERT INTO audit_events(actor,action,target,detail,created_at)
        SELECT ?,?,?,?,? WHERE changes()=1`).bind('system', 'factory.dispatch_failed', requestId, '{}', now())
    ]);
    if (!failure[0]?.meta.changes) throw new PolicyError(409, 'Request changed. Refresh and retry.');
    throw new PolicyError(503, cause instanceof Error ? cause.message : 'Factory dispatch failed.');
  }
}
export async function rejectRequest(env: Env, actor: Actor | null, requestId: string, reason: string) {
  const request = await getRequest(env, requestId) as PackageRequest & { factory_run_id?: string | null };
  const reviewer = requireMaintainer(actor, request.area);
  if (!reason.trim() || reason.length > 2000) throw new PolicyError(400, 'Provide a reason, up to 2,000 characters.');
  if (!['pending', 'review', 'failed'].includes(request.status)) throw new PolicyError(409, 'Only pending, failed or review requests can be rejected.');
  const generationId = request.factory_run_id ?? null;
  const result = await env.DB.batch([
    env.DB.prepare("UPDATE requests SET status='rejected', rejection_reason=?,updated_at=? WHERE id=? AND status=? AND factory_run_id IS ?").bind(reason.trim(), now(), requestId, request.status, generationId),
    env.DB.prepare('INSERT INTO audit_events(actor,action,target,detail,created_at) SELECT ?,?,?,?,? WHERE changes()=1')
      .bind(reviewer.id, 'request.rejected', requestId, JSON.stringify({ reason: reason.trim() }), now())
  ]);
  if (!result[0]?.meta.changes) throw new PolicyError(409, 'Request changed. Refresh and retry.');
}
export async function approveRevision(env: Env, actor: Actor | null, requestId: string, revisionId: string, kind: string, reason?: string) {
  if (!['area', 'security'].includes(kind)) throw new PolicyError(400, 'Choose area or security approval.');
  if (reason !== undefined && (typeof reason !== 'string' || !reason.trim() || reason.length > 2_000)) throw new PolicyError(400, 'Provide a review reason, up to 2,000 characters.');
  const reviewReason = reason?.trim();
  const request = await getRequest(env, requestId) as PackageRequest & { factory_run_id?: string | null };
  const reviewer = kind === 'security' ? requireSecurity(actor) : requireMaintainer(actor, request.area);
  if (!['review', 'queued'].includes(request.status)) throw new PolicyError(409, 'This request is not awaiting review.');
  const revision = await env.DB.prepare('SELECT * FROM revisions WHERE request_id=? ORDER BY created_at DESC,rowid DESC LIMIT 1')
    .bind(requestId).first<Revision>();
  if (!revision || revision.id !== revisionId) throw new PolicyError(409, 'Only the latest revision can be approved.');
  await validateRevision(revision);
  const generationId = request.factory_run_id ?? null;
  const timestamp = now();
  if (request.status === 'queued' && await env.DB.prepare(`SELECT 1 FROM builds WHERE revision_id=? AND status IN ('queued','leased','succeeded') LIMIT 1`).bind(revisionId).first()) {
    throw new PolicyError(409, 'This request is already queued for a worker.');
  }
  const result = await env.DB.batch([
    env.DB.prepare(`INSERT INTO approvals(id,revision_id,actor,kind,manifest_sha256,created_at)
      SELECT ?,?,?,?,?,? FROM requests q
      WHERE q.id=? AND (q.status='review' OR (q.status='queued' AND NOT EXISTS (
        SELECT 1 FROM builds b WHERE b.revision_id=? AND b.status IN ('queued','leased','succeeded')))) AND q.factory_run_id IS ?
        AND ?=(SELECT latest.id FROM revisions latest WHERE latest.request_id=q.id ORDER BY latest.created_at DESC,latest.rowid DESC LIMIT 1)
      ON CONFLICT(revision_id,kind) DO UPDATE SET actor=excluded.actor,manifest_sha256=excluded.manifest_sha256,
        created_at=excluded.created_at,revoked_at=NULL,revoked_by=NULL WHERE approvals.revoked_at IS NOT NULL`)
      .bind(id(), revisionId, reviewer.id, kind, revision.manifest_sha256, timestamp, requestId, revisionId, generationId, revisionId),
    env.DB.prepare('INSERT INTO audit_events(actor,action,target,detail,created_at) SELECT ?,?,?,?,? WHERE changes()=1')
      .bind(reviewer.id, 'revision.approved', requestId, JSON.stringify({ revisionId, kind, manifestSha256: revision.manifest_sha256, reason: reviewReason }), timestamp)
  ]);
  const state = await env.DB.prepare(`SELECT status,factory_run_id,
      (SELECT latest.id FROM revisions latest WHERE latest.request_id=requests.id ORDER BY latest.created_at DESC,latest.rowid DESC LIMIT 1) AS latest_revision_id
    FROM requests WHERE id=?`).bind(requestId).first<{ status: string; factory_run_id: string | null; latest_revision_id: string | null }>();
  if (!state || !['review', 'queued'].includes(state.status) || state.latest_revision_id !== revisionId || (state.factory_run_id ?? null) !== generationId) {
    throw new PolicyError(409, 'Request changed. Refresh and retry.');
  }
  if (state.status === 'queued' && await env.DB.prepare(`SELECT 1 FROM builds WHERE revision_id=? AND status IN ('queued','leased','succeeded') LIMIT 1`).bind(revisionId).first()) {
    throw new PolicyError(409, 'This request is already queued for a worker.');
  }
  // Repeating approval retries PR merge/queueing after a transient GitHub failure.
  const approvals = await query<Approval>(env.DB, 'SELECT * FROM approvals WHERE revision_id=? AND manifest_sha256=? AND revoked_at IS NULL', revisionId, revision.manifest_sha256);
  if (approvals.length === 2) {
    // Lock review finalization before the external GitHub merge. No normal reject or regenerate action accepts queued state.
    const finalizingAt = now();
    const finalizing = state.status === 'review'
      ? await env.DB.batch([
        env.DB.prepare(`UPDATE requests SET status='queued',updated_at=? WHERE id=? AND status='review' AND factory_run_id IS ?
          AND ?=(SELECT latest.id FROM revisions latest WHERE latest.request_id=requests.id ORDER BY latest.created_at DESC,latest.rowid DESC LIMIT 1)
          AND EXISTS (SELECT 1 FROM approvals a WHERE a.revision_id=? AND a.kind='area' AND a.manifest_sha256=? AND a.revoked_at IS NULL)
          AND EXISTS (SELECT 1 FROM approvals a WHERE a.revision_id=? AND a.kind='security' AND a.manifest_sha256=? AND a.revoked_at IS NULL)`)
          .bind(finalizingAt, requestId, generationId, revisionId, revisionId, revision.manifest_sha256, revisionId, revision.manifest_sha256),
        env.DB.prepare(`INSERT INTO audit_events(actor,action,target,detail,created_at)
          SELECT ?,?,?,?,? WHERE changes()=1`)
          .bind(reviewer.id, 'revision.finalizing', requestId, JSON.stringify({ revisionId, manifestSha256: revision.manifest_sha256 }), finalizingAt),
      ])
      : await env.DB.batch([
        env.DB.prepare(`UPDATE requests SET updated_at=? WHERE id=? AND status='queued' AND factory_run_id IS ?
          AND ?=(SELECT latest.id FROM revisions latest WHERE latest.request_id=requests.id ORDER BY latest.created_at DESC,latest.rowid DESC LIMIT 1)
          AND NOT EXISTS (SELECT 1 FROM builds b WHERE b.revision_id=? AND b.status IN ('queued','leased','succeeded'))
          AND EXISTS (SELECT 1 FROM approvals a WHERE a.revision_id=? AND a.kind='area' AND a.manifest_sha256=? AND a.revoked_at IS NULL)
          AND EXISTS (SELECT 1 FROM approvals a WHERE a.revision_id=? AND a.kind='security' AND a.manifest_sha256=? AND a.revoked_at IS NULL)`)
          .bind(finalizingAt, requestId, generationId, revisionId, revisionId, revisionId, revision.manifest_sha256, revisionId, revision.manifest_sha256),
        env.DB.prepare(`INSERT INTO audit_events(actor,action,target,detail,created_at)
          SELECT ?,?,?,?,? WHERE changes()=1`)
          .bind(reviewer.id, 'revision.finalizing', requestId, JSON.stringify({ revisionId, manifestSha256: revision.manifest_sha256, resumed: true }), finalizingAt),
      ]);
    if (!finalizing[0]?.meta.changes) throw new PolicyError(409, 'Request changed. Refresh and retry.');

    // Queue only after the exact reviewed commit is merged into the source of truth.
    try {
      await mergeRecipePR(env, revision);
    } catch (cause) {
      await reopenFinalization(env, requestId, generationId, revisionId, 'recipe merge failed');
      throw cause;
    }
    const architectures = [...new Set(JSON.parse(revision.architectures_json) as Architecture[])];
    try {
      await env.DB.batch([
        ...architectures.map((architecture) => env.DB.prepare(`INSERT INTO builds(id,revision_id,architecture,status,created_at)
          SELECT ?,?,?,'queued',? FROM requests q
          WHERE q.id=? AND q.status='queued' AND q.factory_run_id IS ?
            AND ?=(SELECT latest.id FROM revisions latest WHERE latest.request_id=q.id ORDER BY latest.created_at DESC,latest.rowid DESC LIMIT 1)
            AND EXISTS (SELECT 1 FROM approvals a WHERE a.revision_id=? AND a.kind='area' AND a.manifest_sha256=? AND a.revoked_at IS NULL)
            AND EXISTS (SELECT 1 FROM approvals a WHERE a.revision_id=? AND a.kind='security' AND a.manifest_sha256=? AND a.revoked_at IS NULL)
          ON CONFLICT(revision_id,architecture) DO UPDATE SET
            status=CASE WHEN status='cancelled' THEN 'queued' ELSE status END,
            worker_id=CASE WHEN status='cancelled' THEN NULL ELSE worker_id END,
            lease_token=CASE WHEN status='cancelled' THEN NULL ELSE lease_token END,
            lease_expires_at=CASE WHEN status='cancelled' THEN NULL ELSE lease_expires_at END,
            error=CASE WHEN status='cancelled' THEN NULL ELSE error END,
            finished_at=CASE WHEN status='cancelled' THEN NULL ELSE finished_at END`)
          .bind(id(), revisionId, architecture, timestamp, requestId, generationId, revisionId, revisionId, revision.manifest_sha256, revisionId, revision.manifest_sha256)),
        env.DB.prepare(`UPDATE requests SET updated_at=? WHERE id=? AND status='queued' AND factory_run_id IS ?
          AND ?=(SELECT latest.id FROM revisions latest WHERE latest.request_id=requests.id ORDER BY latest.created_at DESC,latest.rowid DESC LIMIT 1)
          AND EXISTS (SELECT 1 FROM approvals a WHERE a.revision_id=? AND a.kind='area' AND a.manifest_sha256=? AND a.revoked_at IS NULL)
          AND EXISTS (SELECT 1 FROM approvals a WHERE a.revision_id=? AND a.kind='security' AND a.manifest_sha256=? AND a.revoked_at IS NULL)`)
          .bind(now(), requestId, generationId, revisionId, revisionId, revision.manifest_sha256, revisionId, revision.manifest_sha256),
        env.DB.prepare(`INSERT INTO audit_events(actor,action,target,detail,created_at)
          SELECT ?,?,?,?,? WHERE changes()=1`)
          .bind(reviewer.id, 'builds.queued', requestId, JSON.stringify({ revisionId, architectures }), now()),
      ]);
    } catch (cause) {
      await reopenFinalization(env, requestId, generationId, revisionId, 'build queue failed');
      throw cause;
    }
    const settled = await env.DB.prepare(`SELECT status,
        EXISTS (SELECT 1 FROM builds b WHERE b.revision_id=? AND b.status IN ('queued','leased','succeeded')) AS has_jobs
      FROM requests WHERE id=? AND factory_run_id IS ?
        AND ?=(SELECT latest.id FROM revisions latest WHERE latest.request_id=requests.id ORDER BY latest.created_at DESC,latest.rowid DESC LIMIT 1)`)
      .bind(revisionId, requestId, generationId, revisionId)
      .first<{ status: string; has_jobs: number }>();
    if (!settled || settled.status !== 'queued') throw new PolicyError(409, 'Request changed. Refresh and retry.');
    if (!settled.has_jobs) {
      await reopenFinalization(env, requestId, generationId, revisionId, 'approval changed during finalization');
      throw new PolicyError(409, 'Approval changed while the recipe was finalizing. Review and approve the current revision again.');
    }
  }
}

async function reopenFinalization(env: Env, requestId: string, generationId: string | null, revisionId: string, reason: string) {
  const timestamp = now();
  await env.DB.batch([
    env.DB.prepare(`UPDATE requests SET status='review',updated_at=? WHERE id=? AND status='queued' AND factory_run_id IS ?
      AND ?=(SELECT latest.id FROM revisions latest WHERE latest.request_id=requests.id ORDER BY latest.created_at DESC,latest.rowid DESC LIMIT 1)
      AND NOT EXISTS (SELECT 1 FROM builds b WHERE b.revision_id=? AND b.status IN ('queued','leased','succeeded'))`)
      .bind(timestamp, requestId, generationId, revisionId, revisionId),
    env.DB.prepare(`INSERT INTO audit_events(actor,action,target,detail,created_at)
      SELECT 'system','revision.finalization_reopened',?,?,? WHERE changes()=1`)
      .bind(requestId, JSON.stringify({ revisionId, reason }), timestamp),
  ]);
}
async function mergeRecipePR(env: Env, revision: Revision) {
  if (!env.GITHUB_REPOSITORY) throw new PolicyError(503, 'GitHub repository integration is not configured.');
  const prefix = `https://github.com/${env.GITHUB_REPOSITORY}/pull/`;
  if (!revision.pr_url?.startsWith(prefix)) throw new PolicyError(409, 'Recipe PR is outside the configured source-of-truth repository.');
  const number = revision.pr_url.slice(prefix.length);
  if (!/^\d+$/.test(number)) throw new PolicyError(409, 'Invalid recipe pull request.');
  const url = `https://api.github.com/repos/${env.GITHUB_REPOSITORY}/pulls/${number}`;
  const response = await githubFetch(env, url);
  if (!response.ok) throw new PolicyError(502, 'Could not verify the recipe pull request.');
  const pr = await response.json() as { head: { sha: string }; merged: boolean };
  if (pr.head.sha !== revision.commit_sha) throw new PolicyError(409, 'Recipe PR changed after generation. Generate and review a new revision.');
  if (pr.merged) return;
  const merged = await githubFetch(env, `${url}/merge`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ sha: revision.commit_sha, merge_method: 'squash' }) });
  if (!merged.ok || !(await merged.json() as { merged?: boolean }).merged) throw new PolicyError(409, 'GitHub could not merge the reviewed recipe. Resolve PR checks, then retry.');
}
