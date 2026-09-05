import type { FactoryEnv } from './types';

export async function nextPackageRelease(env: Pick<FactoryEnv, 'DB'>, packageName: string, version: string): Promise<number> {
  const row = await env.DB.prepare(`SELECT MAX(COALESCE(r.pkgrel,1)) AS pkgrel
    FROM revisions r JOIN requests q ON q.id=r.request_id
    WHERE q.name=? AND r.version=?`).bind(packageName, version).first<{ pkgrel: number | null }>();
  const next = row?.pkgrel == null ? 1 : row.pkgrel + 1;
  if (!Number.isSafeInteger(next) || next < 1 || next > 9_999) throw new Error('package release number is exhausted');
  return next;
}
