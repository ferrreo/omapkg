import type { Architecture } from '$lib/model';
import type { ReleaseManifest, ReleaseRepositoryRef } from '$lib/distribution-release';
import type { DistributionReleaseChannel, DistributionReleaseKind } from '$lib/distribution-release';
import {
  type ReleaseBlocker,
  type ReleaseCheck,
  type ReleaseRepository,
  type ReleaseStatus,
  type ReleaseView,
  type ReleaseWorkbenchView,
} from '$lib/release-workbench';
import { now, query } from './db';
import type { Env } from './env';
import { getActiveDistributionRelease } from './distribution-releases';

type CandidateRow = {
  id: string;
  kind: 'system' | 'opr' | 'resolved-transaction';
  lane: 'system' | 'opr' | 'transaction';
  channel: 'edge' | 'rc' | 'stable' | 'quarantine';
  release_id: string;
  sequence: number;
  parent_digest: string | null;
  parent_sequence: number | null;
  manifest_json: string;
  manifest_sha256: string;
  status: 'candidate' | 'signed' | 'active' | 'superseded' | 'held';
  created_at: number;
  activated_at: number | null;
};

type ApprovalRow = { candidate_id: string; kind: 'release' | 'base'; area: string | null };

type PointerRow = { lane: 'system' | 'opr' | 'transaction'; channel: 'edge' | 'rc' | 'stable' | 'quarantine'; manifest_sha256: string | null; sequence: number; system_manifest_sha256: string | null; opr_manifest_sha256: string | null };

function manifest(row: CandidateRow): ReleaseManifest {
  return JSON.parse(row.manifest_json) as ReleaseManifest;
}

function statusFor(row: CandidateRow, value: ReleaseManifest): ReleaseStatus {
  if (row.status === 'superseded') return 'superseded';

  switch (row.status) {
    case 'active': return value.channel === 'stable' ? 'stable' : 'testing';
    case 'held': return 'blocked';
    case 'signed': return 'testing';
    default: return 'candidate';
  }
}

function summaryFor(value: ReleaseManifest): string {
  if (value.kind === 'system') return `Omarchy ${value.identity.version ?? 'system'} system manifest with ${value.packageCount} package${value.packageCount === 1 ? '' : 's'}.`;

  if (value.kind === 'opr') return `Independent OPR generation ${value.identity.generation ?? 'not recorded'} with ${value.packageCount} package${value.packageCount === 1 ? '' : 's'}.`;

  return `Resolved transaction for system ${value.identity.version ?? 'not recorded'} and OPR ${value.identity.generation ?? 'not recorded'}.`;
}

function repositoryRefs(value: ReleaseManifest, selectedArchitecture: Architecture | null): ReleaseRepository[] {
  const grouped = new Map<Architecture, ReleaseRepositoryRef[]>();

  for (const repository of value.repositories) {
    if (selectedArchitecture && repository.architecture !== selectedArchitecture) continue;
    const rows = grouped.get(repository.architecture) ?? [];
    rows.push(repository); grouped.set(repository.architecture, rows);
  }

  return [...grouped.entries()].map(([architecture, rows]) => ({
    name: rows.map((row) => row.name).join(', '), architecture, channel: value.kind === 'system' ? 'system' : 'opr', state: 'available',
    packageCount: value.packageCount, databaseUrl: rows[0]?.dbUrl ?? null, signatureUrl: rows[0]?.signatureUrl ?? null,
    digest: rows.map((row) => row.snapshotDigest).join(','),
  }));
}

function checks(value: ReleaseManifest, selectedArchitecture: Architecture | null): ReleaseCheck[] {
  return value.architectures.filter((architecture) => !selectedArchitecture || architecture === selectedArchitecture).map((architecture) => ({
    architecture, status: 'passed', label: 'Published manifest', detail: 'Active immutable release record; package and target gates were checked before activation.', checkedAt: value.createdAt,
  }));
}

function blockersFor(row: CandidateRow, value: ReleaseManifest, approvals: ApprovalRow[], pointers: PointerRow[]): ReleaseBlocker[] {
  if (row.status === 'active' || row.status === 'superseded') return [];
  const blockers: ReleaseBlocker[] = [];

  if (row.status === 'candidate') blockers.push({ code: 'signature-pending', reason: 'Manifest has not reached signed candidate state.' });

  if (!approvals.some((approval) => approval.candidate_id === row.id && approval.kind === 'release')) blockers.push({ code: 'release-review', reason: 'Release-team approval is missing for this exact manifest digest.', owner: 'release team' });
  const requiredAreas = value.approvals.baseOwners;

  for (const area of requiredAreas) if (!approvals.some((approval) => approval.candidate_id === row.id && approval.kind === 'base' && approval.area === area)) blockers.push({ code: 'base-review', reason: `Base-owner approval is missing for ${area}.`, owner: area });
  const pointer = pointers.find((item) => item.lane === row.lane && item.channel === row.channel);

  if (pointer && (pointer.manifest_sha256 !== row.parent_digest || (row.parent_sequence ?? null) !== (pointer.sequence || null))) blockers.push({ code: 'parent-race', reason: 'Activation parent changed since this candidate was prepared. Rebase and review the candidate.' });

  if (!value.changelog.approvedBy) blockers.push({ code: 'changelog-review', reason: 'Changelog approval is not recorded for this candidate.' });

  for (const architecture of ['x86_64', 'aarch64'] as const) {
    if (!value.architectures.includes(architecture)) blockers.push({ code: 'target-missing', reason: `Required ${architecture} evidence is missing.`, architecture });
  }

  return blockers;
}

function toView(row: CandidateRow, value: ReleaseManifest, historical: CandidateRow[], approvals: ApprovalRow[], pointers: PointerRow[], selectedArchitecture: Architecture | null): ReleaseView {
  const status = statusFor(row, value);

  const history = historical.flatMap((item) => item.kind === row.kind && item.release_id === row.release_id ? [{
    label: `${item.release_id} · sequence ${item.sequence}`, status: item.status, timestamp: item.activated_at ?? item.created_at, digest: item.manifest_sha256,
  }] : []);

  const systemCompatibility = value.kind === 'system'
    ? []
    : value.systemManifest?.version ? [value.systemManifest.version]
      : value.compatibility.systemManifestDigest ? [`manifest ${value.compatibility.systemManifestDigest}`] : [];

  return {
    id: row.release_id, candidateId: row.id, manifestDigest: row.manifest_sha256, parentDigest: row.parent_digest, parentSequence: row.parent_sequence,
    kind: value.kind, channel: value.channel, identity: value.identity, sequence: value.sequence, createdAt: value.createdAt, expiresAt: value.expiresAt,
    status, phase: row.status === 'active' ? 'published' : row.status, condition: row.status === 'held' ? 'held' : null,
    summary: summaryFor(value),
    systemCompatibility, architectures: selectedArchitecture ? value.architectures.filter((item) => item === selectedArchitecture) : value.architectures,
    repositories: repositoryRefs(value, selectedArchitecture), packageChunks: value.packageChunks.length,
    packageName: null, packageVersion: null,
    blockers: blockersFor(row, value, approvals, pointers), checks: row.status === 'active' ? checks(value, selectedArchitecture) : [],
    changelog: { digest: value.changelog.sha256, summary: 'Immutable changelog object is linked to this manifest digest.', comparison: value.parent.digest ? `parent ${value.parent.digest}` : 'initial release', approved: Boolean(value.changelog.approvedBy), markdownUrl: value.changelog.url, jsonUrl: null },
    recovery: { predecessor: value.recovery.fromDigest, manifestUrl: value.recovery.target?.url ?? null, instructions: value.recovery.authorized ? value.recovery.reason : 'Recovery is retained as evidence and requires an explicit authorized client action.' },
    history,
    href: `/releases/${encodeURIComponent(value.kind)}/${encodeURIComponent(value.releaseId)}?channel=${value.channel}`,
  };
}

async function candidateRows(env: Env, publishedOnly = false): Promise<CandidateRow[]> {
  return query<CandidateRow>(env.DB, `SELECT id,kind,lane,channel,release_id,sequence,parent_digest,parent_sequence,manifest_json,manifest_sha256,status,created_at,activated_at
    FROM distribution_release_candidates WHERE ${publishedOnly ? "status IN ('active','superseded') AND signature_key IS NOT NULL AND signature_sha256 IS NOT NULL" : "status IN ('active','superseded','signed','candidate','held')"} ORDER BY sequence DESC,created_at DESC LIMIT 200`);
}

export async function listDistributionReleaseCandidates(env: Env, selectedArchitecture: Architecture | null = null): Promise<ReleaseView[]> {
  const [rows, approvals, pointers] = await Promise.all([
    candidateRows(env),
    query<ApprovalRow>(env.DB, 'SELECT candidate_id,kind,area FROM distribution_release_approvals WHERE candidate_id IN (SELECT id FROM distribution_release_candidates WHERE status IN (\'active\',\'superseded\',\'signed\',\'candidate\',\'held\'))'),
    query<PointerRow>(env.DB, 'SELECT lane,channel,manifest_sha256,sequence,system_manifest_sha256,opr_manifest_sha256 FROM distribution_activation_pointers'),
  ]);

  return rows.map((row) => toView(row, manifest(row), rows, approvals, pointers, selectedArchitecture));
}

export async function getDistributionReleaseView(env: Env, kind: DistributionReleaseKind, releaseId: string, selectedArchitecture: Architecture | null = null, channel: DistributionReleaseChannel = 'stable'): Promise<ReleaseView | null> {
  const row = await env.DB.prepare(`SELECT id,kind,lane,channel,release_id,sequence,parent_digest,parent_sequence,manifest_json,manifest_sha256,status,created_at,activated_at
    FROM distribution_release_candidates WHERE kind=? AND release_id=? AND channel=? AND status IN ('active','superseded') AND signature_key IS NOT NULL AND signature_sha256 IS NOT NULL ORDER BY sequence DESC LIMIT 1`)
    .bind(kind, releaseId, channel).first<CandidateRow>();

  if (!row) return null;

  const [rows, approvals, pointers] = await Promise.all([
    candidateRows(env, true),
    query<ApprovalRow>(env.DB, 'SELECT candidate_id,kind,area FROM distribution_release_approvals WHERE candidate_id=?', row.id),
    query<PointerRow>(env.DB, 'SELECT lane,channel,manifest_sha256,sequence,system_manifest_sha256,opr_manifest_sha256 FROM distribution_activation_pointers'),
  ]);

  return toView(row, manifest(row), rows, approvals, pointers, selectedArchitecture);
}

export async function distributionReleaseWorkbench(env: Env, selectedSystemVersion: string | null, selectedArchitecture: Architecture | null): Promise<ReleaseWorkbenchView> {
  const [system, opr, transaction, rows] = await Promise.all([
    getActiveDistributionRelease(env.DB, 'system'), getActiveDistributionRelease(env.DB, 'opr'), getActiveDistributionRelease(env.DB, 'transaction'), candidateRows(env, true),
  ]);

  const approvals = await query<ApprovalRow>(env.DB, 'SELECT candidate_id,kind,area FROM distribution_release_approvals');
  const pointers = await query<PointerRow>(env.DB, 'SELECT lane,channel,manifest_sha256,sequence,system_manifest_sha256,opr_manifest_sha256 FROM distribution_activation_pointers');
  const activeRows = rows.filter((row) => row.status === 'active' || row.status === 'superseded');
  const lookup = new Map(activeRows.map((row) => [row.id, row]));
  const active = [system, opr, transaction].filter((value): value is NonNullable<typeof value> => Boolean(value));
  const views = active.map((entry) => toView(lookup.get(entry.candidate.id) ?? entry.candidate as CandidateRow, entry.manifest, activeRows, approvals, pointers, selectedArchitecture));
  const systemDigest = system?.candidate.manifest_sha256 ?? null;
  const activeSystemVersion = system?.manifest.identity.version ?? null;

  const compatibleViews = views.map((view) => view.kind === 'opr' && systemDigest && activeSystemVersion && view.systemCompatibility.includes(`manifest ${systemDigest}`)
    ? { ...view, systemCompatibility: [activeSystemVersion, `manifest ${systemDigest}`] } : view);

  const filteredSystem = compatibleViews.filter((view) => view.kind === 'system' && (!selectedSystemVersion || view.identity.version === selectedSystemVersion));
  const filteredOpr = compatibleViews.filter((view) => view.kind === 'opr' && (!selectedSystemVersion || view.systemCompatibility.includes(selectedSystemVersion))) as ReleaseView[];
  const filteredTransactions = compatibleViews.filter((view) => view.kind === 'resolved-transaction' && (!selectedSystemVersion || view.identity.version === selectedSystemVersion));

  return {
    engine: views.length ? 'published' : 'empty', source: 'distribution',
    notice: views.length ? null : 'No active system, OPR, or resolved-transaction manifest is published for this selection. Candidate, test, and review work remains private until activation.',
    checkedAt: now(), selectedSystemVersion, selectedArchitecture,
    systemReleases: filteredSystem, oprReleases: filteredOpr, transactions: filteredTransactions,
  };
}
