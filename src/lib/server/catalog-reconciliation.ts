import { createHash } from 'node:crypto';
import type { Actor } from '../model';
import type { ImportEntry, ImportManifest } from '../imports';
import { canonicalJson } from '../canonical-json';
import { query, now, sha256 } from './db';
import { PolicyError } from './policy';
import { humanMaintainer } from './catalog-ownership';
import { getCatalogImport } from './catalog-imports';
import { externalPackageSource } from '../distribution';

export type ImportDifference = {
  key: string; name: string; target: string; collection: string;
  kind: 'missing' | 'extra' | 'version' | 'architecture' | 'artifact' | 'metadata';
  baseline: { version: string; sha256: string; architecture: string } | null;
  candidate: { version: string; sha256: string; architecture: string } | null;
};
export type CatalogReconciliationReport = {
  schemaVersion: number; candidateId: string; baselineId: string; baselineChannel: string; scope: string[];
  candidatePackages: number; baselinePackages: number; differences: number;
  counts: Record<ImportDifference['kind'], number>; sourceGaps: string[]; sourceWarnings: string[];
  qualificationNotes: string[]; newTargets: Array<{ collection: string; target: string; referencePackages: number }>;
  requiredNativeTargets: string[]; matchesBaseline: boolean; coverageComplete: boolean; itemsSha256: string; releaseReady: false;
};

const packageKey = (entry: ImportEntry) => `${entry.collection}/${entry.target}/${entry.name}`;
const identity = (entry: ImportEntry | undefined) => entry ? { version: entry.version, sha256: entry.sha256, architecture: entry.architecture } : null;

export function compareImportEntries(candidate: ImportEntry[], baseline: ImportEntry[], scope: string[]): ImportDifference[] {
  const index = (entries: ImportEntry[]) => {
    const result = new Map<string, ImportEntry>();
    for (const entry of entries.filter((entry) => scope.includes(entry.collection))) {
      const key = packageKey(entry);
      if (result.has(key)) throw new PolicyError(409, `Captured sources overlap for ${key}; choose a non-overlapping baseline.`);
      result.set(key, entry);
    }
    return result;
  };
  const proposed = index(candidate); const reference = index(baseline); const differences: ImportDifference[] = [];
  for (const key of [...new Set([...proposed.keys(), ...reference.keys()])].sort()) {
    const next = proposed.get(key); const old = reference.get(key); const entry = next ?? old!;
    const relations = (item: ImportEntry) => canonicalJson([item.surface ?? 'binary', item.dependencies.toSorted(), item.makeDependencies.toSorted(),
      item.checkDependencies.toSorted(), item.provides.toSorted(), item.conflicts.toSorted(), item.replaces.toSorted(), item.licenses.toSorted()]);
    const kind = !next ? 'missing' : !old ? 'extra' : next.version !== old.version ? 'version' :
      next.architecture !== old.architecture ? 'architecture' : next.sha256 !== old.sha256 ? 'artifact' : relations(next) !== relations(old) ? 'metadata' : null;
    if (kind) differences.push({ key, name: entry.name, target: entry.target, collection: entry.collection, kind, baseline: identity(old), candidate: identity(next) });
  }
  return differences;
}

function sourceCoverage(candidate: ImportManifest, baseline: ImportManifest, scope: string[]) {
  const gaps: string[] = [];
  const notes: string[] = [];
  const newTargets: Array<{ collection: string; target: string; referencePackages: number }> = [];
  for (const collection of scope.filter((collection) => collection !== 'multilib')) {
    const source = baseline.sources.find((source) => source.collection === collection && source.target === 'aarch64');
    const absent = !source || (source.status === 'unavailable' && !source.sha256 && /\bHTTP(?: Error)? 404\b/.test(source.error ?? ''));
    if ((baseline.kind === 'omarchy' || baseline.kind === 'opr') && absent) {
      newTargets.push({ collection, target: 'aarch64', referencePackages: candidate.sources.filter((source) => source.collection === collection && source.target === 'aarch64').reduce((total, source) => total + source.entries, 0) });
      notes.push(`No existing ${baseline.kind === 'opr' ? 'OPR' : 'Omarchy'} ARM baseline for ${collection}. Qualify our own ARM target; an upstream ARM mirror is not required.`);
    }
  }
  const isNewTarget = (collection: string, target: string) => newTargets.some((item) => item.collection === collection && item.target === target);
  for (const [label, manifest] of [['Candidate', candidate], ['Baseline', baseline]] as const) {
    for (const source of manifest.sources.filter((source) => scope.includes(source.collection))) {
      const reference = manifest.kind === 'arch' && externalPackageSource(source.url);
      const destination = isNewTarget(source.collection, source.target) || reference ? notes : gaps;
      if (source.status !== 'captured') destination.push(`${label}: ${source.id} unavailable — ${source.error}${reference ? ' (reference only; use owned OPR builds)' : ''}`);
      if (source.signature === 'failed') destination.push(`${label}: ${source.id} signature verification failed`);
    }
    for (const collection of scope) for (const target of collection === 'multilib' ? ['x86_64'] : ['x86_64', 'aarch64']) {
      if (!manifest.sources.some((source) => source.collection === collection && source.target === target)) {
        (isNewTarget(collection, target) ? notes : gaps).push(`${label}: ${collection}/${target} was not captured`);
      }
    }
  }
  return { sourceGaps: [...new Set(gaps)].sort(), qualificationNotes: [...new Set(notes)].sort(), newTargets };
}

export async function reconcileCatalogImports(db: D1Database, actor: Actor | null, candidateId: string, baselineId: string) {
  const reviewer = humanMaintainer(actor, 'system');
  if (candidateId === baselineId) throw new PolicyError(400, 'Compare an import with a separately captured baseline.');
  const [candidate, baseline] = await Promise.all([getCatalogImport(db, candidateId), getCatalogImport(db, baselineId)]);
  if (candidate.record.status === 'capturing' || baseline.record.status === 'capturing') throw new PolicyError(409, 'Seal both captures before comparison.');
  const scope = [...new Set(candidate.manifest.sources.map((source) => source.collection))].sort();
  if (!baseline.manifest.sources.some((source) => scope.includes(source.collection))) throw new PolicyError(409, 'The baseline has no matching repository scope. Capture the matching Omarchy or OPR repositories.');
  const { sourceGaps, qualificationNotes, newTargets } = sourceCoverage(candidate.manifest, baseline.manifest, scope);
  const counts = { missing: 0, extra: 0, version: 0, architecture: 0, artifact: 0, metadata: 0 };
  const reportId = await sha256(canonicalJson(['catalog-reconciliation-3', candidateId, baselineId]));
  const existing = await db.prepare("SELECT report_json,report_sha256 FROM catalog_reconciliations WHERE id=? AND status='ready'").bind(reportId).first<{ report_json: string; report_sha256: string }>();
  if (existing) {
    if (await sha256(existing.report_json) !== existing.report_sha256) throw new PolicyError(409, 'Stored reconciliation integrity check failed.');
    return { reportId, report: JSON.parse(existing.report_json) as CatalogReconciliationReport };
  }
  const pending = canonicalJson({ candidateId, baselineId, status: 'preparing' });
  await db.prepare(`INSERT INTO catalog_reconciliations(id,candidate_import_id,baseline_import_id,report_json,report_sha256,created_by,created_at)
    VALUES(?,?,?,?,?,?,?) ON CONFLICT(id) DO NOTHING`).bind(reportId, candidateId, baselineId, pending, await sha256(pending), reviewer.id, now()).run();

  const filter = `import_id IN (?,?) AND collection IN (SELECT value FROM json_each(?))
    AND NOT EXISTS (SELECT 1 FROM json_each(?) target WHERE json_extract(target.value,'$.collection')=collection AND json_extract(target.value,'$.target')=target_architecture)`;
  const bindings = [candidateId, baselineId, canonicalJson(scope), canonicalJson(newTargets)];
  const duplicate = await db.prepare(`SELECT name FROM catalog_import_entries WHERE ${filter}
    GROUP BY import_id,collection,target_architecture,name HAVING COUNT(*)>1 LIMIT 1`).bind(...bindings).first<{ name: string }>();
  if (duplicate) throw new PolicyError(409, `Captured sources overlap for ${duplicate.name}; choose non-overlapping repository sources.`);
  // Keep full metadata in SQLite. Stream only comparison rows through the Worker.
  const arrays = ['dependencies', 'makeDependencies', 'checkDependencies', 'provides', 'conflicts', 'replaces', 'licenses'];
  const relations = `json_array(COALESCE(json_extract(entry_json,'$.surface'),'binary'),${arrays.map((field) =>
    `(SELECT json_group_array(value) FROM (SELECT value FROM json_each(json_extract(entry_json,'$.${field}')) ORDER BY value))`).join(',')})`;
  const packageSet = `WITH entries AS MATERIALIZED (
    SELECT import_id,name,collection,target_architecture,architecture,
      collection||'/'||target_architecture||'/'||name AS package_key,
      json_extract(entry_json,'$.version') AS version,json_extract(entry_json,'$.sha256') AS artifact_sha256,${relations} AS relations
    FROM catalog_import_entries WHERE ${filter}
  ), baseline AS (SELECT * FROM entries WHERE import_id=?), candidate AS (SELECT * FROM entries WHERE import_id=?)`;
  await db.prepare(`${packageSet}, pairs AS (
    SELECT b.package_key,b.name,b.collection,b.target_architecture,b.version AS old_version,b.architecture AS old_arch,b.artifact_sha256 AS old_sha,
      c.version AS new_version,c.architecture AS new_arch,c.artifact_sha256 AS new_sha,
      CASE WHEN c.name IS NULL THEN 'missing' WHEN c.version<>b.version THEN 'version' WHEN c.architecture<>b.architecture THEN 'architecture'
        WHEN c.artifact_sha256<>b.artifact_sha256 THEN 'artifact' WHEN c.relations<>b.relations THEN 'metadata' ELSE NULL END AS kind
    FROM baseline b LEFT JOIN candidate c USING(package_key)
    UNION ALL
    SELECT c.package_key,c.name,c.collection,c.target_architecture,NULL,NULL,NULL,c.version,c.architecture,c.artifact_sha256,'extra'
    FROM candidate c LEFT JOIN baseline b USING(package_key) WHERE b.name IS NULL
  ) INSERT INTO catalog_reconciliation_items(report_id,package_key,kind,item_json)
    SELECT ?,package_key,kind,json_object('key',package_key,'name',name,'target',target_architecture,'collection',collection,'kind',kind,
      'baseline',json(CASE WHEN old_version IS NULL THEN NULL ELSE json_object('version',old_version,'sha256',old_sha,'architecture',old_arch) END),
      'candidate',json(CASE WHEN new_version IS NULL THEN NULL ELSE json_object('version',new_version,'sha256',new_sha,'architecture',new_arch) END))
    FROM pairs WHERE kind IS NOT NULL ON CONFLICT DO NOTHING`).bind(...bindings, baselineId, candidateId, reportId).run();
  const countRows = await query<{ kind: keyof typeof counts; count: number }>(db, 'SELECT kind,COUNT(*) AS count FROM catalog_reconciliation_items WHERE report_id=? GROUP BY kind', reportId);
  for (const row of countRows) counts[row.kind] = row.count;
  const sizes = await query<{ import_id: string; count: number }>(db, `SELECT import_id,COUNT(*) AS count FROM catalog_import_entries WHERE ${filter} GROUP BY import_id`, ...bindings);
  const hasher = createHash('sha256');
  hasher.update('[');
  let cursor = ''; let differences = 0;
  for (;;) {
    const page = await query<{ package_key: string; item_json: string }>(db, 'SELECT package_key,item_json FROM catalog_reconciliation_items WHERE report_id=? AND package_key>? ORDER BY package_key LIMIT 250', reportId, cursor);
    if (!page.length) break;
    for (const item of page) { if (differences++) hasher.update(','); hasher.update(canonicalJson(JSON.parse(item.item_json))); }
    cursor = page.at(-1)!.package_key;
  }
  hasher.update(']');
  const sourceWarnings = [...candidate.manifest.sources, ...baseline.manifest.sources].filter((source) => source.status === 'captured' && source.signature !== 'verified')
    .map((source) => `${source.id}: source signature ${source.signature}; metadata equality is not trust approval`);
  const report: CatalogReconciliationReport = {
    schemaVersion: 2, candidateId, baselineId, baselineChannel: baseline.manifest.channel, scope,
    candidatePackages: sizes.find((row) => row.import_id === candidateId)?.count ?? 0,
    baselinePackages: sizes.find((row) => row.import_id === baselineId)?.count ?? 0,
    differences, counts, sourceGaps, sourceWarnings, qualificationNotes, newTargets, requiredNativeTargets: ['x86_64', 'aarch64'],
    matchesBaseline: differences === 0 && sourceGaps.length === 0, coverageComplete: counts.missing === 0 && sourceGaps.length === 0,
    itemsSha256: hasher.digest('hex'), releaseReady: false,
  };
  const json = canonicalJson(report);
  await db.batch([
    db.prepare('INSERT INTO distribution_assertions(expected,actual) SELECT ?,COUNT(*) FROM catalog_reconciliation_items WHERE report_id=?').bind(differences, reportId),
    db.prepare("UPDATE catalog_reconciliations SET report_json=?,report_sha256=?,status='ready' WHERE id=? AND status='preparing'").bind(json, await sha256(json), reportId),
    db.prepare(`INSERT INTO audit_events(actor,action,target,detail,created_at) SELECT ?,'catalog.reconciled',?,?,? WHERE changes()=1`)
      .bind(reviewer.id, candidateId, json, now()),
  ]);
  return { reportId, report };
}

export async function importBuildCoverage(db: D1Database, importId: string) {
  const result = await db.prepare(`SELECT COUNT(*) AS captured,
    SUM(CASE WHEN EXISTS (SELECT 1 FROM catalog_outputs o JOIN catalog_packages p ON p.pkgbase=o.pkgbase WHERE o.name=e.name AND p.admitted_revision IS NOT NULL) THEN 1 ELSE 0 END) AS admitted,
    SUM(CASE WHEN EXISTS (SELECT 1 FROM catalog_outputs o JOIN catalog_packages p ON p.pkgbase=o.pkgbase
      JOIN requests q ON q.catalog_pkgbase=p.pkgbase AND q.catalog_revision=p.admitted_revision
      JOIN revisions v ON v.request_id=q.id JOIN builds b ON b.revision_id=v.id
      WHERE o.name=e.name AND b.architecture=e.target_architecture AND b.status='succeeded' AND b.smoke_passed=1
        AND b.provenance_signature IS NOT NULL AND (
          (b.output_contract_json IS NULL AND json_extract(b.provenance,'$.packageMetadata.name')=e.name
            AND json_extract(b.provenance,'$.packageMetadata.fullVersion')=json_extract(e.entry_json,'$.version')) OR
          (b.output_contract_json IS NOT NULL AND json_extract(b.provenance,'$.schemaVersion')=2 AND EXISTS (
            SELECT 1 FROM json_each(b.provenance,'$.outputs') output JOIN build_artifacts artifact
              ON artifact.build_id=b.id AND artifact.attempt=b.attempt AND artifact.filename=json_extract(output.value,'$.filename')
              AND artifact.sha256=json_extract(output.value,'$.artifactSha256')
            WHERE json_extract(output.value,'$.packageMetadata.name')=e.name
              AND json_extract(output.value,'$.packageMetadata.fullVersion')=json_extract(e.entry_json,'$.version'))))
        AND EXISTS (SELECT 1 FROM approvals a WHERE a.revision_id=v.id AND a.kind='area' AND a.revoked_at IS NULL AND a.manifest_sha256=v.manifest_sha256)
        AND EXISTS (SELECT 1 FROM approvals a WHERE a.revision_id=v.id AND a.kind='security' AND a.revoked_at IS NULL AND a.manifest_sha256=v.manifest_sha256)) THEN 1 ELSE 0 END) AS built
    FROM catalog_import_entries e WHERE e.import_id=?`).bind(importId).first<{ captured: number; admitted: number | null; built: number | null }>();
  return { captured: result?.captured ?? 0, admitted: result?.admitted ?? 0, built: result?.built ?? 0 };
}
