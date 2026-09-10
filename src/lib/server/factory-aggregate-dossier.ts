import { canonicalJson } from '../canonical-json';
import type { Architecture } from '../model';
import type { Env } from './env';
import { audit, query, sha256 } from './db';
import { PolicyError } from './policy';
import { buildArtifacts } from './build-outputs';

const ID = /^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,255}$/;
const SHA256 = /^[a-f0-9]{64}$/;

export type AggregateDossierKind = 'cohort' | 'image';

export interface AggregateConstituent {
  key: string;
  pkgbase: string | null;
  revisionId: string | null;
  dossierId: string | null;
  status: 'succeeded' | 'failed' | 'pending' | 'missing-dossier' | 'missing-revision';
  architectures: Architecture[];
  outputs: Array<{ filename: string; sha256: string; size: number | null; architecture: Architecture }>;
  error: string | null;
}

export interface FactoryAggregateDossier {
  schemaVersion: 1;
  kind: 'factory-cohort-dossier' | 'factory-image-dossier';
  id: string;
  identity: { targetKind: AggregateDossierKind; targetId: string; runId: string; createdAt: number };
  status: 'succeeded' | 'failed' | 'pending' | 'incomplete';
  constituents: AggregateConstituent[];
  image?: { architecture: Architecture | null; imageKind: 'oci' | 'system' | null; jobs: Array<Record<string, unknown>> };
  evidence: { complete: boolean; latestRecordedAt: number; links: string[] };
}

export interface StoredFactoryAggregateDossier {
  dossier: FactoryAggregateDossier;
  canonicalJson: string;
  canonicalSha256: string;
  markdown: string;
  markdownSha256: string;
}

function parseJson(value: string | null | undefined): unknown {
  if (!value) return null;
  try { return JSON.parse(value); } catch { return null; }
}

function statusForBuilds(rows: Array<{ status: string }>, dossierId: string | null): AggregateConstituent['status'] {
  if (rows.some((row) => row.status === 'failed' || row.status === 'cancelled')) return 'failed';
  if (!dossierId) return 'missing-dossier';
  if (!rows.length || rows.some((row) => row.status !== 'succeeded')) return 'pending';
  return 'succeeded';
}

function aggregateStatus(constituents: AggregateConstituent[], jobs: Array<{ status: string }>): FactoryAggregateDossier['status'] {
  if (constituents.some((item) => item.status === 'failed') || jobs.some((job) => job.status === 'failed' || job.status === 'cancelled')) return 'failed';
  if (constituents.some((item) => item.status === 'pending' || item.status === 'missing-dossier' || item.status === 'missing-revision') || jobs.some((job) => job.status !== 'succeeded')) return 'incomplete';
  return 'succeeded';
}

async function runIdFor(env: Env, kind: AggregateDossierKind, targetId: string, runId?: string): Promise<string> {
  if (runId) {
    if (!ID.test(runId)) throw new PolicyError(400, 'Aggregate dossier run identity is invalid.');
    const row = kind === 'cohort'
      ? await env.DB.prepare("SELECT id FROM factory_runs WHERE id=? AND target_kind IN ('cohort','cohort-member') AND target_id=?").bind(runId, targetId).first<{ id: string }>()
      : await env.DB.prepare('SELECT id FROM factory_runs WHERE id=? AND target_kind=? AND target_id=?').bind(runId, kind, targetId).first<{ id: string }>();
    if (!row) throw new PolicyError(409, 'Factory run does not match aggregate target.');
    return row.id;
  }
  const matches = kind === 'cohort'
    ? await env.DB.prepare("SELECT id FROM factory_runs WHERE target_kind IN ('cohort','cohort-member') AND target_id=? ORDER BY created_at DESC").bind(targetId).all<{ id: string }>()
    : await env.DB.prepare('SELECT id FROM factory_runs WHERE target_kind=? AND target_id=? ORDER BY created_at DESC').bind(kind, targetId).all<{ id: string }>();
  if (matches.results.length > 1) throw new PolicyError(409, 'Multiple aggregate factory runs match; provide the exact run identity.');
  return matches.results[0]?.id ?? `${kind}:${targetId}`;
}

async function latestPackageDossier(env: Env, revisionId: string): Promise<string | null> {
  return (await env.DB.prepare('SELECT id FROM factory_dossiers WHERE revision_id=? ORDER BY created_at DESC,id DESC LIMIT 1').bind(revisionId).first<{ id: string }>())?.id ?? null;
}

async function cohortDossier(env: Env, targetId: string, runId?: string): Promise<FactoryAggregateDossier> {
  const cohort = await env.DB.prepare('SELECT id,current_revision,updated_at FROM cohorts WHERE id=?').bind(targetId).first<{ id: string; current_revision: number; updated_at: number }>();
  if (!cohort) throw new PolicyError(404, 'Cohort not found.');
  const resolvedRunId = await runIdFor(env, 'cohort', targetId, runId);
  let revision = cohort.current_revision;
  if (runId) {
    const run = await env.DB.prepare(`SELECT target_kind,target_id,CAST(json_extract(policy_json,'$.cohortRevision') AS INTEGER) AS cohort_revision
      FROM factory_runs WHERE id=?`).bind(resolvedRunId).first<{ target_kind: string; target_id: string; cohort_revision: number | null }>();
    if (!run || run.target_id !== targetId || !['cohort', 'cohort-member'].includes(run.target_kind)) throw new PolicyError(409, 'Factory run does not match cohort target.');
    if (run.cohort_revision) revision = run.cohort_revision;
  }
  const members = await query<{ pkgbase: string; recipe_revision_id: string | null }>(env.DB, 'SELECT pkgbase,recipe_revision_id FROM cohort_members WHERE cohort_id=? AND revision=? ORDER BY pkgbase', targetId, revision);
  const constituents: AggregateConstituent[] = [];
  let latest = cohort.updated_at;
  for (const member of members) {
    if (!member.recipe_revision_id) {
      constituents.push({ key: member.pkgbase, pkgbase: member.pkgbase, revisionId: null, dossierId: null, status: 'missing-revision', architectures: [], outputs: [], error: null });
      continue;
    }
    const builds = await query<{ id: string; attempt: number; status: string; architecture: Architecture; artifact_filename: string | null; artifact_sha256: string | null; artifact_size: number | null; created_at: number }>(env.DB,
      'SELECT id,attempt,status,architecture,artifact_filename,artifact_sha256,artifact_size,created_at FROM builds WHERE revision_id=? ORDER BY architecture', member.recipe_revision_id);
    latest = Math.max(latest, ...builds.map((build) => build.created_at));
    const dossierId = await latestPackageDossier(env, member.recipe_revision_id);
    const retained = (await Promise.all(builds.map(async (build) => ({ build, artifacts: await buildArtifacts(env.DB, { id: build.id, attempt: build.attempt }) })))).flatMap((item) => item.artifacts.map((artifact) => ({ ...artifact, architecture: item.build.architecture })));
    const outputs = retained.length ? retained.map((artifact) => ({ filename: artifact.filename, sha256: artifact.sha256, size: artifact.size, architecture: artifact.architecture })) : builds.filter((build) => build.artifact_filename && build.artifact_sha256 && SHA256.test(build.artifact_sha256)).map((build) => ({ filename: build.artifact_filename!, sha256: build.artifact_sha256!, size: build.artifact_size, architecture: build.architecture }));
    constituents.push({ key: member.pkgbase, pkgbase: member.pkgbase, revisionId: member.recipe_revision_id, dossierId, status: statusForBuilds(builds, dossierId),
      architectures: [...new Set(builds.map((build) => build.architecture))].sort(), outputs, error: builds.find((build) => build.status === 'failed') ? 'Constituent build failed; inspect its package dossier.' : null });
  }
  const runStatus = await env.DB.prepare('SELECT status FROM factory_runs WHERE id=?').bind(resolvedRunId).first<{ status: string }>();
  const membersComplete = constituents.length === members.length && constituents.every((item) => item.status === 'succeeded');
  const status = runStatus?.status === 'succeeded' && membersComplete ? 'succeeded' : runStatus?.status === 'needs-human-intervention' ? 'failed' : runStatus?.status === 'queued' || runStatus?.status === 'running' ? 'pending' : aggregateStatus(constituents, []);
  return { schemaVersion: 1, kind: 'factory-cohort-dossier', id: `aggregate-${await sha256(`cohort\u0000${targetId}\u0000${resolvedRunId}\u0000${revision}`).then((value) => value.slice(0, 48))}`,
    identity: { targetKind: 'cohort', targetId, runId: resolvedRunId, createdAt: cohort.updated_at }, status, constituents,
    evidence: { complete: constituents.length === members.length && constituents.every((item) => item.status === 'succeeded'), latestRecordedAt: latest, links: constituents.filter((item) => item.dossierId).map((item) => `/maintain/dossiers/${encodeURIComponent(item.dossierId!)}`) } };
}

async function imageDossier(env: Env, targetId: string, runId?: string): Promise<FactoryAggregateDossier> {
  const resolvedRunId = await runIdFor(env, 'image', targetId, runId);
  const jobs = await query<{ id: string; attempt: number; architecture: Architecture; kind: 'oci' | 'system'; status: string; input_sha256: string; artifact_key: string | null; artifact_sha256: string | null; artifact_size: number | null; artifact_filename: string | null; error: string | null; candidate_json: string; created_at: number }>(env.DB,
    'SELECT id,attempt,architecture,kind,status,input_sha256,artifact_key,artifact_sha256,artifact_size,artifact_filename,error,candidate_json,created_at FROM factory_image_jobs WHERE run_id=? ORDER BY attempt', resolvedRunId);
  if (!jobs.length) throw new PolicyError(404, 'Image factory run has no jobs.');
  const latest = Math.max(...jobs.map((job) => job.created_at));
  const run = await env.DB.prepare('SELECT status,successful_attempt FROM factory_runs WHERE id=?').bind(resolvedRunId).first<{ status: string; successful_attempt: number | null }>();
  const constituents: AggregateConstituent[] = jobs.map((job) => ({ key: job.id, pkgbase: null, revisionId: null, dossierId: null, status: job.status === 'succeeded' ? 'succeeded' : job.status === 'failed' || job.status === 'cancelled' ? 'failed' : 'pending', architectures: [job.architecture], outputs: job.artifact_filename && job.artifact_sha256 ? [{ filename: job.artifact_filename, sha256: job.artifact_sha256, size: job.artifact_size, architecture: job.architecture }] : [], error: job.error }));
  const packageRevisionIds = new Set<string>();
  for (const job of jobs) {
    const candidate = parseJson(job.candidate_json);
    const object = candidate && typeof candidate === 'object' && !Array.isArray(candidate) ? candidate as Record<string, unknown> : {};
    for (const key of ['packageRevisionIds', 'constituentRevisionIds']) for (const value of Array.isArray(object[key]) ? object[key] : []) if (typeof value === 'string' && ID.test(value)) packageRevisionIds.add(value);
  }
  if (packageRevisionIds.size) {
    const ids = [...packageRevisionIds]; const placeholders = ids.map(() => '?').join(',');
    const revisions = await query<{ id: string; name: string }>(env.DB, `SELECT r.id,q.name FROM revisions r JOIN requests q ON q.id=r.request_id WHERE r.id IN (${placeholders}) ORDER BY r.id`, ...ids);
    const found = new Set(revisions.map((revision) => revision.id));
    for (const missing of ids.filter((id) => !found.has(id))) constituents.push({ key: `package:${missing}`, pkgbase: null, revisionId: missing, dossierId: null, status: 'missing-revision', architectures: [], outputs: [], error: 'Referenced package revision is missing.' });
    for (const revision of revisions) {
      const dossierId = await latestPackageDossier(env, revision.id);
      const builds = await query<{ status: string; architecture: Architecture; artifact_filename: string | null; artifact_sha256: string | null; artifact_size: number | null }>(env.DB, 'SELECT status,architecture,artifact_filename,artifact_sha256,artifact_size FROM builds WHERE revision_id=? ORDER BY architecture', revision.id);
      constituents.push({ key: `package:${revision.id}`, pkgbase: revision.name, revisionId: revision.id, dossierId, status: statusForBuilds(builds, dossierId), architectures: [...new Set(builds.map((build) => build.architecture))].sort(), outputs: builds.filter((build) => build.artifact_filename && build.artifact_sha256).map((build) => ({ filename: build.artifact_filename!, sha256: build.artifact_sha256!, size: build.artifact_size, architecture: build.architecture })), error: builds.find((build) => build.status === 'failed') ? 'Constituent package build failed; inspect its dossier.' : null });
    }
  }
  const imageJobs = jobs.map((job) => {
    const candidate = parseJson(job.candidate_json); const object = candidate && typeof candidate === 'object' && !Array.isArray(candidate) ? candidate as Record<string, unknown> : {};
    return { id: job.id, attempt: job.attempt, status: job.status, architecture: job.architecture, imageKind: job.kind, candidateId: typeof object.id === 'string' ? object.id : null,
      profileId: typeof object.profileId === 'string' ? object.profileId : null, profileSha256: typeof object.profileSha256 === 'string' ? object.profileSha256 : null,
      inputSha256: job.input_sha256, artifactSha256: job.artifact_sha256, artifactSize: job.artifact_size, error: job.error };
  });
  const finalJobIds = new Set(jobs.filter((job) => job.attempt === run?.successful_attempt).map((job) => job.id));
  const membersComplete = constituents.every((item) => item.key.startsWith('package:') ? item.status === 'succeeded' : !finalJobIds.has(item.key) || item.status === 'succeeded');
  const status = run?.status === 'succeeded' && membersComplete ? 'succeeded' : run?.status === 'needs-human-intervention' ? 'failed' : run?.status === 'queued' || run?.status === 'running' ? 'pending' : aggregateStatus(constituents, jobs);
  return { schemaVersion: 1, kind: 'factory-image-dossier', id: `aggregate-${await sha256(`image\u0000${targetId}\u0000${resolvedRunId}`).then((value) => value.slice(0, 48))}`,
    identity: { targetKind: 'image', targetId, runId: resolvedRunId, createdAt: latest }, status, constituents,
    image: { architecture: jobs[0].architecture, imageKind: jobs[0].kind, jobs: imageJobs },
    evidence: { complete: run?.status === 'succeeded' && run.successful_attempt !== null && membersComplete, latestRecordedAt: latest, links: [] } };
}

export async function buildFactoryAggregateDossier(env: Env, input: { targetKind: AggregateDossierKind; targetId: string; runId?: string }): Promise<FactoryAggregateDossier> {
  if (!ID.test(input.targetId)) throw new PolicyError(400, 'Aggregate dossier target identity is invalid.');
  return input.targetKind === 'cohort' ? cohortDossier(env, input.targetId, input.runId) : imageDossier(env, input.targetId, input.runId);
}

export function factoryAggregateDossierMarkdown(dossier: FactoryAggregateDossier): string {
  return `# ${dossier.kind}\n\n- Target: \`${dossier.identity.targetId}\`\n- Run: \`${dossier.identity.runId}\`\n- Status: **${dossier.status}**\n- Constituent dossiers: ${dossier.constituents.filter((item) => item.dossierId).length}/${dossier.constituents.length}\n\n| Member | Revision | Status | Dossier |\n| --- | --- | --- | --- |\n${dossier.constituents.map((item) => `| ${item.key} | ${item.revisionId ?? '—'} | ${item.status} | ${item.dossierId ?? 'missing'} |`).join('\n')}\n`;
}

export async function createFactoryAggregateDossier(env: Env, actor: string, input: { targetKind: AggregateDossierKind; targetId: string; runId?: string }): Promise<StoredFactoryAggregateDossier> {
  let dossier = await buildFactoryAggregateDossier(env, input);
  for (let collision = 0; collision < 2; collision += 1) {
    const canonical = canonicalJson(dossier); const markdown = factoryAggregateDossierMarkdown(dossier);
    const canonicalSha256 = await sha256(canonical); const markdownSha256 = await sha256(markdown);
    try {
      await env.DB.batch([
        env.DB.prepare(`INSERT INTO factory_aggregate_dossiers(id,target_kind,target_id,run_id,canonical_json,canonical_sha256,markdown,markdown_sha256,created_by,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)`)
          .bind(dossier.id, input.targetKind, input.targetId, dossier.identity.runId, canonical, canonicalSha256, markdown, markdownSha256, actor, dossier.identity.createdAt),
        audit(env.DB, actor, 'factory.aggregate_dossier_created', dossier.id, { targetKind: input.targetKind, targetId: input.targetId, runId: dossier.identity.runId, canonicalSha256 }),
      ]);
      return { dossier, canonicalJson: canonical, canonicalSha256, markdown, markdownSha256 };
    } catch (cause) {
      const existing = await env.DB.prepare('SELECT canonical_json,canonical_sha256,markdown,markdown_sha256 FROM factory_aggregate_dossiers WHERE target_kind=? AND target_id=? AND run_id=? AND canonical_sha256=? LIMIT 1')
        .bind(input.targetKind, input.targetId, dossier.identity.runId, canonicalSha256).first<{ canonical_json: string; canonical_sha256: string; markdown: string; markdown_sha256: string }>();
      if (existing) {
        const parsed = parseJson(existing.canonical_json);
        if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new PolicyError(409, 'Stored aggregate dossier is invalid.');
        return { dossier: parsed as FactoryAggregateDossier, canonicalJson: existing.canonical_json, canonicalSha256: existing.canonical_sha256, markdown: existing.markdown, markdownSha256: existing.markdown_sha256 };
      }
      if (!(cause instanceof Error && /UNIQUE|constraint/i.test(cause.message)) || collision === 1) throw cause;
      dossier = { ...dossier, id: `aggregate-${canonicalSha256.slice(0, 48)}` };
    }
  }
  throw new PolicyError(409, 'Aggregate dossier could not be persisted.');
}

export async function storedFactoryAggregateDossier(env: Env, id: string): Promise<StoredFactoryAggregateDossier> {
  if (!/^aggregate-[A-Za-z0-9_-]{8,128}$/.test(id)) throw new PolicyError(404, 'Aggregate dossier not found.');
  const row = await env.DB.prepare('SELECT canonical_json,canonical_sha256,markdown,markdown_sha256 FROM factory_aggregate_dossiers WHERE id=?').bind(id)
    .first<{ canonical_json: string; canonical_sha256: string; markdown: string; markdown_sha256: string }>();
  if (!row) throw new PolicyError(404, 'Aggregate dossier not found.');
  if (await sha256(row.canonical_json) !== row.canonical_sha256 || await sha256(row.markdown) !== row.markdown_sha256) throw new PolicyError(409, 'Aggregate dossier digest does not match its bytes.');
  const parsed = parseJson(row.canonical_json);
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new PolicyError(409, 'Stored aggregate dossier is invalid.');
  return { dossier: parsed as FactoryAggregateDossier, canonicalJson: row.canonical_json, canonicalSha256: row.canonical_sha256, markdown: row.markdown, markdownSha256: row.markdown_sha256 };
}
