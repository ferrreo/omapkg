import { packagePath, type Collection } from '../distribution';
import { readOprEvidence } from './sbom';

/** The path is part of immutable SBOM review evidence, never current catalog state. */
export function revisionPackagePath(name: string, sbom: string): string {
  const value = readOprEvidence(JSON.parse(sbom))?.catalogPath;
  if (value === undefined) return packagePath(name);
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Invalid reviewed catalog path');
  const path = value as Record<string, unknown>;
  if (Object.keys(path).sort().join(',') !== 'collection,pkgbase' || path.pkgbase !== name ||
      (path.collection !== null && typeof path.collection !== 'string')) throw new Error('Invalid reviewed catalog path');
  return packagePath(name, path.collection as Collection | null);
}

export function recipeGitUrl(repository: string | undefined, commit: string | null, name: string, sbom: string): string | null {
  if (!repository || !/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repository) || !commit || !/^[a-f0-9]{40}$/.test(commit)) return null;
  return `https://github.com/${repository}/tree/${commit}/${revisionPackagePath(name, sbom).split('/').map(encodeURIComponent).join('/')}`;
}

export async function factoryCatalogPath(db: D1Database, requestId: string): Promise<{ pkgbase: string; collection: Collection | null }> {
  const request = await db.prepare(`SELECT q.name,c.collection FROM requests q LEFT JOIN catalog_revisions c
    ON c.pkgbase=q.catalog_pkgbase AND c.revision=q.catalog_revision WHERE q.id=?`).bind(requestId).first<{ name: string; collection: Collection | null }>();
  if (!request) throw new Error('Request not found');
  const previous = await db.prepare(`SELECT r.sbom_json FROM revisions r JOIN requests q ON q.id=r.request_id
    WHERE q.name=? ORDER BY r.created_at DESC,r.rowid DESC LIMIT 1`).bind(request.name).first<{ sbom_json: string }>();
  const path = previous ? revisionPackagePath(request.name, previous.sbom_json) : packagePath(request.name, request.collection ?? 'omapkg');
  return { pkgbase: request.name, collection: path.split('/').length === 3 ? path.split('/')[1] as Collection : null };
}
