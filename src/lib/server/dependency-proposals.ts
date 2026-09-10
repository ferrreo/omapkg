import * as v from 'valibot';
import type { Actor } from '../model';
import { canonicalJson } from '../canonical-json';
import { audit, id, now, query, sha256 } from './db';
import { parseArchRelation } from './arch';
import { parseDeclaredLicense, parseRequest, PolicyError, publicSourceURL } from './policy';
import { checkDependencyLinks, type DependencyBlocker } from './dependency-blockers';
import { humanMaintainer, reviewReason } from './catalog-ownership';
import { externalPackageSource } from '../distribution';
import { pendingRequestStatements } from './requests';

const packageName = v.pipe(v.string(), v.regex(/^[a-z0-9][a-z0-9@._+-]{0,63}$/));

const proposalSchema = v.strictObject({
  schemaVersion: v.literal(1), relation: v.pipe(v.string(), v.maxLength(256)), architecture: v.picklist(['x86_64', 'aarch64']),
  name: packageName, upstreamUrl: v.nullable(v.string()), sourceKind: v.nullable(v.picklist(['git', 'archive'])),
  license: v.string(), origin: v.picklist(['unknown', 'upstream', 'aur-reference', 'alarm-reference']),
  referenceUrl: v.nullable(v.string()), targetPkgbase: v.nullable(packageName),
});

export type DependencyProposalManifest = v.InferOutput<typeof proposalSchema>;

export type DependencyProposal = {
  id: string; proposal_key: string; revision: number; manifest_json: string; manifest_sha256: string;
  status: 'proposed' | 'admitted' | 'declined' | 'superseded'; dependency_request_id: string | null;
  created_by: string; created_at: number; decided_by: string | null; decided_at: number | null; decision_reason: string | null;
};

type ProposalParent = DependencyBlocker & { name: string; area: string; request_status: string };

export function parseDependencyProposal(input: unknown): DependencyProposalManifest {
  const parsed = v.safeParse(proposalSchema, input);

  if (!parsed.success || !parseArchRelation(parsed.output.relation)) throw new PolicyError(400, 'Invalid dependency proposal.');
  const value = parsed.output;

  if ((value.upstreamUrl === null) !== (value.sourceKind === null)) throw new PolicyError(400, 'Provide both source URL and source kind, or leave both pending.');

  if (value.upstreamUrl) {
    value.upstreamUrl = publicSourceURL(value.upstreamUrl);

    if (externalPackageSource(value.upstreamUrl)) throw new PolicyError(400, 'AUR/ALARM is reference evidence. Choose the authoritative upstream source for the OPR package.');
  }

  if (value.referenceUrl) value.referenceUrl = publicSourceURL(value.referenceUrl);

  if (['aur-reference', 'alarm-reference'].includes(value.origin) && !value.referenceUrl) throw new PolicyError(400, 'Retain the AUR/ALARM reference used for this proposal.');
  value.license = parseDeclaredLicense(value.license);

  return value;
}

export async function getDependencyProposal(db: D1Database, proposalId: string) {
  const proposal = await db.prepare('SELECT * FROM dependency_proposals WHERE id=?').bind(proposalId).first<DependencyProposal>();

  if (!proposal) throw new PolicyError(404, 'Dependency proposal not found.');

  if (await sha256(proposal.manifest_json) !== proposal.manifest_sha256) throw new PolicyError(409, 'Dependency proposal integrity check failed.');

  const parents = await query<ProposalParent>(db, `SELECT d.*,q.name,q.area,q.status AS request_status FROM dependency_proposal_blockers p
    JOIN dependency_blockers d ON d.id=p.blocker_id JOIN requests q ON q.id=d.request_id WHERE p.proposal_id=? ORDER BY q.name,d.id`, proposalId);

  return { proposal, manifest: parseDependencyProposal(JSON.parse(proposal.manifest_json)), parents };
}

function authorizeParents(actor: Actor | null, parents: ProposalParent[]) {
  const reviewer = humanMaintainer(actor);

  for (const parent of parents) humanMaintainer(reviewer, parent.area);

  return reviewer;
}

export async function reviseDependencyProposal(db: D1Database, actor: Actor | null, proposalId: string, expectedDigest: string, input: unknown, message: string) {
  const { proposal, manifest: previous, parents } = await getDependencyProposal(db, proposalId);
  const reviewer = authorizeParents(actor, parents);

  if (!['proposed', 'declined'].includes(proposal.status) || proposal.manifest_sha256 !== expectedDigest) throw new PolicyError(409, 'Proposal changed. Review its current state.');
  const manifest = parseDependencyProposal(input);

  if (manifest.relation !== previous.relation || manifest.architecture !== previous.architecture) throw new PolicyError(400, 'A replacement must preserve the blocked relation and target architecture.');

  if (manifest.targetPkgbase && !await db.prepare('SELECT 1 FROM catalog_packages WHERE pkgbase=?').bind(manifest.targetPkgbase).first()) throw new PolicyError(404, 'Target catalog package not found.');
  const clean = reviewReason(message);
  const json = canonicalJson(manifest); const digest = await sha256(json);

  if (digest === expectedDigest && proposal.status === 'proposed') return { proposalId, manifestSha256: digest };
  const nextId = id(); const timestamp = now();

  try {
    await db.batch([
      db.prepare(`UPDATE dependency_proposals SET status='superseded' WHERE id=? AND status=? AND manifest_sha256=?
        AND NOT EXISTS (SELECT 1 FROM dependency_proposals newer WHERE newer.proposal_key=? AND newer.revision>?)`)
        .bind(proposalId, proposal.status, expectedDigest, proposal.proposal_key, proposal.revision),
      db.prepare('INSERT INTO distribution_assertions(expected,actual) VALUES(1,changes())'),
      db.prepare(`INSERT INTO dependency_proposals(id,proposal_key,revision,manifest_json,manifest_sha256,status,created_by,created_at)
        VALUES(?,?,?,?,?,'proposed',?,?)`).bind(nextId, proposal.proposal_key, proposal.revision + 1, json, digest, reviewer.id, timestamp),
      db.prepare('INSERT INTO dependency_proposal_blockers(proposal_id,blocker_id) SELECT ?,blocker_id FROM dependency_proposal_blockers WHERE proposal_id=?').bind(nextId, proposalId),
      audit(db, reviewer.id, 'dependency.proposal_revised', nextId, { previousProposalId: proposalId, manifestSha256: digest, reason: clean }),
    ]);
  } catch (cause) { return proposalConflict(cause); }

  return { proposalId: nextId, manifestSha256: digest };
}

export async function decideDependencyProposal(db: D1Database, actor: Actor | null, proposalId: string, expectedDigest: string,
  decision: 'admit' | 'decline', message: string, existingRequestId?: string) {
  const { proposal, manifest, parents } = await getDependencyProposal(db, proposalId);
  const reviewer = authorizeParents(actor, parents);
  const clean = reviewReason(message);

  if (!['admit', 'decline'].includes(decision)) throw new PolicyError(400, 'Choose admit or decline.');

  if (proposal.manifest_sha256 !== expectedDigest) throw new PolicyError(409, 'Proposal changed. Review its current revision.');

  if (proposal.status === 'admitted' && decision === 'admit') return { requestId: proposal.dependency_request_id, admitted: true };

  if (proposal.status !== 'proposed') throw new PolicyError(409, 'Proposal already has a decision.');
  const timestamp = now();

  if (decision === 'decline') {
    const result = await db.batch([
      db.prepare(`UPDATE dependency_proposals SET status='declined',decided_by=?,decided_at=?,decision_reason=? WHERE id=? AND status='proposed' AND manifest_sha256=?`)
        .bind(reviewer.id, timestamp, clean, proposalId, expectedDigest),
      db.prepare(`INSERT INTO audit_events(actor,action,target,detail,created_at) SELECT ?,'dependency.proposal_declined',?,?,? WHERE changes()=1`)
        .bind(reviewer.id, proposalId, JSON.stringify({ manifestSha256: expectedDigest, reason: clean }), timestamp),
    ]);

    if (!result[0]?.meta.changes) throw new PolicyError(409, 'Proposal changed. Refresh before deciding.');

    return { requestId: null, admitted: false };
  }

  const open = parents.filter((parent) => parent.status === 'open' && parent.request_status === 'blocked');

  if (!open.length) throw new PolicyError(409, 'No current blocked parents need this proposal.');
  let requestId = existingRequestId || id();
  let request: ReturnType<typeof parseRequest> | null = null;

  if (existingRequestId) {
    const existing = await db.prepare('SELECT * FROM requests WHERE id=?').bind(existingRequestId).first<{ id: string; area: string; name: string; status: string }>();

    if (!existing || existing.status === 'rejected') throw new PolicyError(409, 'Choose an existing non-rejected package request.');
    humanMaintainer(actor, existing.area);
  } else {
    if (!manifest.upstreamUrl || !manifest.sourceKind) throw new PolicyError(400, 'Review the authoritative upstream URL and source kind before admission.');
    request = parseRequest({ name: manifest.name, upstream_url: manifest.upstreamUrl, source_kind: manifest.sourceKind,
      description: `Provide ${manifest.relation} on ${manifest.architecture}`, declared_license: manifest.license, area: open[0].area });

    if (manifest.targetPkgbase) {
      const catalog = await db.prepare(`SELECT r.manifest_json FROM catalog_packages p JOIN catalog_revisions r ON r.pkgbase=p.pkgbase AND r.revision=p.admitted_revision
        WHERE p.pkgbase=?`).bind(manifest.targetPkgbase).first<{ manifest_json: string }>();

      if (!catalog) throw new PolicyError(409, 'Admit the target catalog policy before requesting its ARM variant.');
      const target = JSON.parse(catalog.manifest_json) as { pkgbase: string; upstreamUrl: string; sourceKind: string; outputs: string[] };

      if (target.pkgbase !== manifest.name || target.upstreamUrl !== manifest.upstreamUrl || target.sourceKind !== manifest.sourceKind) throw new PolicyError(409, 'Variant identity and source must match the admitted catalog package.');
    }
  }

  const links = open.map((parent) => ({ parent: parent.request_id, child: requestId, blockerId: parent.id }));
  const graphVersion = await checkDependencyLinks(db, links);

  const statements: D1PreparedStatement[] = [
    db.prepare(`INSERT INTO distribution_assertions(expected,actual) SELECT 1,COUNT(*) FROM dependency_proposals WHERE id=? AND status='proposed' AND manifest_sha256=?`).bind(proposalId, expectedDigest),
    db.prepare('INSERT INTO distribution_assertions(expected,actual) SELECT ?,version FROM dependency_graph_state WHERE id=1').bind(graphVersion),
  ];

  if (request) {
    statements.push(...pendingRequestStatements(db, reviewer, request, requestId, timestamp));
    statements.push(db.prepare("INSERT INTO distribution_assertions(expected,actual) SELECT 1,COUNT(*) FROM requests WHERE id=? AND status='pending'").bind(requestId));

    if (manifest.targetPkgbase) statements.push(db.prepare(`UPDATE requests SET catalog_pkgbase=?,catalog_revision=(SELECT admitted_revision FROM catalog_packages WHERE pkgbase=?) WHERE id=?`)
      .bind(manifest.targetPkgbase, manifest.targetPkgbase, requestId));
  }

  for (const parent of open) {
    statements.push(db.prepare(`UPDATE dependency_blockers SET dependency_request_id=? WHERE id=? AND status='open'
      AND EXISTS (SELECT 1 FROM requests WHERE id=dependency_blockers.request_id AND status='blocked')`).bind(requestId, parent.id));
    statements.push(db.prepare('INSERT INTO distribution_assertions(expected,actual) VALUES(1,changes())'));
    statements.push(audit(db, reviewer.id, 'dependency.request_linked', parent.request_id, { blockerId: parent.id, dependencyRequestId: requestId, proposalId }));
  }

  statements.push(db.prepare(`UPDATE dependency_proposals SET status='admitted',dependency_request_id=?,decided_by=?,decided_at=?,decision_reason=? WHERE id=?`)
    .bind(requestId, reviewer.id, timestamp, clean, proposalId));
  statements.push(audit(db, reviewer.id, 'dependency.proposal_admitted', proposalId, { requestId, manifestSha256: expectedDigest, reason: clean, parentIds: [...new Set(open.map((parent) => parent.request_id))] }));

  try { await db.batch(statements); } catch (cause) { return proposalConflict(cause); }

  return { requestId, admitted: true };
}

function proposalConflict(cause: unknown): never {
  if (cause instanceof Error && /constraint|unique/i.test(cause.message)) throw new PolicyError(409, 'Proposal, request budget or dependency graph changed. Refresh and review before retrying; link an existing request when appropriate.');
  throw cause;
}

export async function listDependencyProposals(db: D1Database, input: { status?: string; after?: string; limit?: number } = {}) {
  return query<DependencyProposal & { parents: number }>(db, `SELECT p.*,(SELECT COUNT(*) FROM dependency_proposal_blockers b WHERE b.proposal_id=p.id) AS parents
    FROM dependency_proposals p WHERE p.status=? AND p.id>? ORDER BY p.id LIMIT ?`, input.status ?? 'proposed', input.after ?? '', Math.min(100, Math.max(1, Math.floor(input.limit ?? 50))));
}
