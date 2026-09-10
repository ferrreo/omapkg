import * as v from 'valibot';
import type { Actor, Architecture } from '../model';
import type { Env } from './env';
import { audit, now, query, sha256 } from './db';
import { parseArchRelation, parsePackageMetadata, satisfiesArchRelation } from './arch';
import { PolicyError, requireMaintainer } from './policy';
import { submitRequest } from './requests';
import { canonicalJson } from '../canonical-json';

export type DependencyBlockerInput = {
  relation: string | null;
  phase: 'factory' | 'build' | 'runtime';
  resolution: 'dependency' | 'recipe' | 'exception';
  detail: string;
  findingSha256?: string;
};

export type DependencyBlocker = {
  id: string; request_id: string; scope_id: string; revision_id: string | null; architecture: Architecture;
  relation: string | null; phase: DependencyBlockerInput['phase']; resolution: DependencyBlockerInput['resolution'];
  detail: string; finding_sha256: string | null; dependency_request_id: string | null;
  status: 'open' | 'resolved' | 'superseded'; created_at: number; resolved_at: number | null;
};

const blockerSchema = v.strictObject({
  relation: v.nullable(v.string()),
  phase: v.picklist(['factory', 'build', 'runtime']),
  resolution: v.picklist(['dependency', 'recipe', 'exception']),
  detail: v.pipe(v.string(), v.trim(), v.minLength(1), v.maxLength(4096), v.check((value) => !value.includes('\u0000') && !value.includes('\r'), 'Control characters are not allowed.')),
  findingSha256: v.optional(v.pipe(v.string(), v.regex(/^[a-f0-9]{64}$/))),
});

export function parseDependencyBlockers(value: unknown): DependencyBlockerInput[] {
  if (value === undefined) return [];

  const parsed = v.safeParse(v.pipe(v.array(blockerSchema), v.minLength(1), v.maxLength(16)), value);

  if (!parsed.success) throw new Error('Report between 1 and 16 dependency blockers');

  return parsed.output.map((item) => {
    if ((item.relation !== null && (item.relation.length > 256 || !parseArchRelation(item.relation))) ||
        (item.resolution === 'dependency' && !item.relation)) {
      throw new Error('Invalid dependency blocker; report evidence without executable input or admission authority');
    }

    const result = { relation: item.relation ?? null, phase: item.phase, resolution: item.resolution, detail: item.detail };

    if (item.findingSha256 !== undefined) Object.assign(result, { findingSha256: item.findingSha256 });

    return result;
  });
}

export async function blockerStatements(db: D1Database, context: {
  requestId: string; scopeId: string; revisionId: string | null; architecture: Architecture;
  buildId?: string; leaseToken?: string; timestamp: number;
}, blockers: DependencyBlockerInput[], actor: string): Promise<D1PreparedStatement[]> {
  const guard = context.buildId
    ? `EXISTS (SELECT 1 FROM builds b JOIN revisions v ON v.id=b.revision_id WHERE b.id=? AND b.lease_token=? AND b.status='failed' AND b.finished_at=?
        AND v.request_id=q.id AND v.id=(SELECT latest.id FROM revisions latest WHERE latest.request_id=q.id ORDER BY latest.created_at DESC,latest.rowid DESC LIMIT 1))`
    : `q.status='generating' AND q.factory_run_id=?`;

  const guardValues = context.buildId ? [context.buildId, context.leaseToken, context.timestamp] : [context.scopeId];
  const statements: D1PreparedStatement[] = [];

  for (const blocker of blockers) {
    const key = await sha256(JSON.stringify([context.requestId, context.scopeId, context.architecture, blocker]));
    statements.push(db.prepare(`INSERT INTO dependency_blockers(id,request_id,scope_id,revision_id,architecture,relation,phase,resolution,finding_sha256,detail,created_at)
      SELECT ?,q.id,?,?,?,?,?,?,?,?,? FROM requests q WHERE q.id=? AND ${guard}
      ON CONFLICT(id) DO NOTHING`).bind(key, context.scopeId, context.revisionId, context.architecture, blocker.relation, blocker.phase,
        blocker.resolution, blocker.findingSha256 ?? null, blocker.detail, context.timestamp, context.requestId, ...guardValues));

    if (blocker.resolution === 'dependency' && blocker.relation) {
      const proposalKey = await sha256(canonicalJson([blocker.relation, context.architecture]));

      const draft = canonicalJson({ schemaVersion: 1, relation: blocker.relation, architecture: context.architecture,
        name: parseArchRelation(blocker.relation)!.name.toLowerCase().replace(/[^a-z0-9@._+-]/g, '-').slice(0, 64), upstreamUrl: null, sourceKind: null, license: 'unknown',
        origin: 'unknown', referenceUrl: null, targetPkgbase: null });

      statements.push(db.prepare(`INSERT INTO dependency_proposals(id,proposal_key,revision,manifest_json,manifest_sha256,status,created_by,created_at)
        SELECT ?,?,1,?,?,'proposed',?,? WHERE EXISTS (SELECT 1 FROM dependency_blockers WHERE id=? AND status='open')
          AND NOT EXISTS (SELECT 1 FROM dependency_proposals WHERE proposal_key=?) ON CONFLICT DO NOTHING`)
        .bind(proposalKey, proposalKey, draft, await sha256(draft), actor, context.timestamp, key, proposalKey));
      statements.push(db.prepare(`INSERT INTO dependency_proposal_blockers(proposal_id,blocker_id)
        SELECT p.id,? FROM dependency_proposals p WHERE p.proposal_key=?
          AND p.revision=(SELECT MAX(revision) FROM dependency_proposals WHERE proposal_key=?)
          AND EXISTS (SELECT 1 FROM dependency_blockers WHERE id=? AND status='open') ON CONFLICT DO NOTHING`)
        .bind(key, proposalKey, proposalKey, key));
    }
  }

  statements.push(
    db.prepare(`UPDATE requests SET status='blocked',updated_at=? WHERE id=? AND status IN ('generating','queued','building','failed')
      AND EXISTS (SELECT 1 FROM dependency_blockers d WHERE d.request_id=requests.id AND d.scope_id=? AND d.status='open')`)
      .bind(context.timestamp, context.requestId, context.scopeId),
    db.prepare(`INSERT INTO audit_events(actor,action,target,detail,created_at) SELECT ?,'request.blocked',?,?,? WHERE changes()=1`)
      .bind(actor, context.requestId, JSON.stringify({ scopeId: context.scopeId, architecture: context.architecture, blockers }), context.timestamp),
  );

  if (context.revisionId) statements.push(db.prepare(`UPDATE builds SET status='cancelled',error='request blocked by dependency evidence',finished_at=?,lease_expires_at=?
    WHERE revision_id=? AND status IN ('queued','leased') AND EXISTS (SELECT 1 FROM requests WHERE id=? AND status='blocked')`)
    .bind(context.timestamp, context.timestamp, context.revisionId, context.requestId));

  return statements;
}

export async function getDependencyBlockers(db: D1Database, requestId: string): Promise<DependencyBlocker[]> {
  return query<DependencyBlocker>(db, 'SELECT * FROM dependency_blockers WHERE request_id=? ORDER BY status,created_at DESC LIMIT 100', requestId);
}

async function currentBlocker(env: Env, actor: Actor | null, requestId: string, blockerId: string): Promise<DependencyBlocker> {
  const request = await env.DB.prepare('SELECT area,status FROM requests WHERE id=?').bind(requestId).first<{ area: string; status: string }>();

  if (!request) throw new PolicyError(404, 'Request not found.');
  requireMaintainer(actor, request.area);

  const blocker = await env.DB.prepare("SELECT * FROM dependency_blockers WHERE id=? AND request_id=? AND status='open'")
    .bind(blockerId, requestId).first<DependencyBlocker>();

  if (request.status !== 'blocked' || !blocker || blocker.resolution !== 'dependency') throw new PolicyError(409, 'This blocker needs recipe review rather than a new dependency request.');

  return blocker;
}

async function checkDependencyGraph(db: D1Database, parent: string, child: string, replacing: string): Promise<number> {
  return checkDependencyLinks(db, [{ parent, child, blockerId: replacing }]);
}

export async function checkDependencyLinks(db: D1Database, links: Array<{ parent: string; child: string; blockerId: string }>): Promise<number> {
  if (!links.length || links.length > 64) throw new PolicyError(409, 'Link between 1 and 64 dependency requests per decision.');

  if (links.some(({ parent, child }) => parent === child)) throw new PolicyError(409, 'A request cannot depend on itself.');
  const version = (await db.prepare('SELECT version FROM dependency_graph_state WHERE id=1').first<{ version: number }>())!.version;

  const edges = await query<{ request_id: string; dependency_request_id: string }>(db,
    `SELECT DISTINCT request_id,dependency_request_id FROM dependency_blockers WHERE status='open' AND dependency_request_id IS NOT NULL
      AND id NOT IN (${links.map(() => '?').join(',')}) LIMIT 4097`, ...links.map((link) => link.blockerId));

  edges.push(...links.map(({ parent, child }) => ({ request_id: parent, dependency_request_id: child })));

  if (edges.length > 4096) throw new PolicyError(409, 'Dependency request graph exceeds its admission budget.');
  const children = new Map<string, Set<string>>();

  for (const edge of edges) {
    if (!children.has(edge.request_id)) children.set(edge.request_id, new Set());
    children.get(edge.request_id)!.add(edge.dependency_request_id);
  }

  type DependencyExpansion = { depth: number; nodes: Set<string> };

  const memo = new Map<string, DependencyExpansion>();

  const visit = (node: string, path: Set<string>): DependencyExpansion => {
    if (path.has(node)) throw new PolicyError(409, 'Dependency request cycle detected.');

    if (path.size >= 8) throw new PolicyError(409, 'Dependency request expansion exceeds 8 levels or 64 requests.');
    const cached = memo.get(node);

    if (cached) return cached;
    const next = new Set(path).add(node);
    const result = { depth: 1, nodes: new Set([node]) };

    for (const child of children.get(node) ?? []) {
      const subtree = visit(child, next);
      result.depth = Math.max(result.depth, subtree.depth + 1);

      for (const descendant of subtree.nodes) result.nodes.add(descendant);

      if (result.depth > 8 || result.nodes.size > 64) throw new PolicyError(409, 'Dependency request expansion exceeds 8 levels or 64 requests.');
    }

    memo.set(node, result);

    return result;
  };

  // Check ancestors as well: adding a child must not deepen an existing root past its budget.
  for (const root of children.keys()) visit(root, new Set());

  return version;
}

export async function linkDependencyRequest(env: Env, actor: Actor | null, requestId: string, blockerId: string, dependencyRequestId: string): Promise<void> {
  const blocker = await currentBlocker(env, actor, requestId, blockerId);

  if (!await env.DB.prepare('SELECT id FROM requests WHERE id=?').bind(dependencyRequestId).first()) throw new PolicyError(404, 'Dependency request not found.');
  const version = await checkDependencyGraph(env.DB, requestId, dependencyRequestId, blockerId);

  const results = await env.DB.batch([
    env.DB.prepare("UPDATE dependency_blockers SET dependency_request_id=? WHERE id=? AND status='open' AND (SELECT version FROM dependency_graph_state WHERE id=1)=?").bind(dependencyRequestId, blocker.id, version),
    env.DB.prepare("INSERT INTO audit_events(actor,action,target,detail,created_at) SELECT ?,'dependency.request_linked',?,?,? WHERE changes()=1")
      .bind(actor!.id, requestId, JSON.stringify({ blockerId, dependencyRequestId }), now()),
  ]);

  if (!results[0]?.meta.changes) throw new PolicyError(409, 'Dependency graph changed; refresh and retry linking.');
  await resolveDependencyBlockers(env, requestId);
}

export async function createDependencyRequest(env: Env, actor: Actor | null, requestId: string, blockerId: string, input: unknown): Promise<string> {
  await currentBlocker(env, actor, requestId, blockerId);
  // Check the expansion budget before admitting another upstream URL.
  await checkDependencyGraph(env.DB, requestId, `new:${blockerId}`, blockerId);
  const child = await submitRequest(env, actor, input);
  await linkDependencyRequest(env, actor, requestId, blockerId, child);

  return child;
}

export async function resolveDependencyBlockers(env: Pick<Env, 'DB'>, requestId?: string): Promise<void> {
  const blockers = await query<DependencyBlocker>(env.DB, `SELECT d.* FROM dependency_blockers d JOIN requests q ON q.id=d.request_id
    WHERE d.status='open' AND d.resolution='dependency' AND q.status='blocked' ${requestId ? 'AND q.id=?' : ''} LIMIT 256`, ...(requestId ? [requestId] : []));

  if (!blockers.length) return;

  const releases = await query<{ id: string; request_id: string; architecture: Architecture; provenance: string }>(env.DB, `SELECT r.id,v.request_id,r.architecture,b.provenance
    FROM releases r JOIN builds b ON b.id=r.build_id JOIN revisions v ON v.id=b.revision_id
    WHERE r.surface='binary' AND r.channel IN ('stable','dev') AND b.status='succeeded' AND r.signature_key IS NOT NULL
      AND EXISTS (SELECT 1 FROM approvals a WHERE a.revision_id=v.id AND a.kind='area' AND a.manifest_sha256=v.manifest_sha256 AND a.revoked_at IS NULL)
      AND EXISTS (SELECT 1 FROM approvals a WHERE a.revision_id=v.id AND a.kind='security' AND a.manifest_sha256=v.manifest_sha256 AND a.revoked_at IS NULL)`);

  const timestamp = now();

  for (const blocker of blockers) {
    const relation = parseArchRelation(blocker.relation ?? '');

    const provider = releases.find((release) => {
      if (!relation || release.architecture !== blocker.architecture || (blocker.dependency_request_id && release.request_id !== blocker.dependency_request_id)) return false;

      try { const metadata = parsePackageMetadata(JSON.parse(release.provenance).packageMetadata);

 return metadata && satisfiesArchRelation(relation, metadata); }
      catch { return false; }
    });

    if (!provider) continue;
    await env.DB.batch([
      env.DB.prepare("UPDATE dependency_blockers SET status='resolved',resolved_at=? WHERE id=? AND status='open'").bind(timestamp, blocker.id),
      audit(env.DB, 'system', 'dependency.resolved', blocker.request_id, { blockerId: blocker.id, releaseId: provider.id }),
    ]);
  }

  for (const parent of new Set(blockers.map((item) => item.request_id))) {
    // Resume through the normal review/generation path. Never manufacture approvals.
    await env.DB.batch([
      env.DB.prepare(`UPDATE requests SET status=CASE WHEN EXISTS (SELECT 1 FROM revisions WHERE request_id=requests.id) THEN 'review' ELSE 'pending' END,updated_at=?
        WHERE id=? AND status='blocked' AND NOT EXISTS (SELECT 1 FROM dependency_blockers WHERE request_id=requests.id AND status='open')`).bind(timestamp, parent),
      env.DB.prepare(`INSERT INTO audit_events(actor,action,target,detail,created_at) SELECT 'system','dependency.ready_for_review',?,'{}',? WHERE changes()=1`).bind(parent, timestamp),
    ]);
  }
}
