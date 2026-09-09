import { requiredArchitectures } from '../distribution';
import type { Architecture } from '../model';
import { now, query } from './db';
import type { Env } from './env';

export async function repositoryStatus(env: Env) {
  const [snapshots, counts] = await Promise.all([
    query<{ id: string; architecture: Architecture; channel: 'stable' | 'dev'; created_at: number; db_key: string; db_signature_key: string }>(env.DB,
      'SELECT id,architecture,channel,created_at,db_key,db_signature_key FROM repository_snapshots WHERE active=1 ORDER BY channel,architecture'),
    query<{ architecture: Architecture; channel: 'stable' | 'dev'; surface: string; packages: number }>(env.DB, `
      SELECT architecture,channel,surface,COUNT(*) AS packages FROM (
        SELECT architecture,channel,surface,ROW_NUMBER() OVER(PARTITION BY name,architecture,channel ORDER BY published_at DESC,id DESC) AS rank
        FROM releases WHERE channel IN ('stable','dev')
      ) WHERE rank=1 GROUP BY architecture,channel,surface`),
  ]);
  const repositories = await Promise.all((['stable', 'dev'] as const).flatMap((channel) => requiredArchitectures.map(async (architecture) => {
    const snapshot = snapshots.find((row) => row.architecture === architecture && row.channel === channel);
    let available = false;
    if (snapshot) {
      try {
        const [database, signature] = await Promise.all([env.ARTIFACTS.head(snapshot.db_key), env.ARTIFACTS.head(snapshot.db_signature_key)]);
        available = Boolean(database?.size && signature?.size);
      } catch { /* Public status exposes availability, not private storage diagnostics. */ }
    }
    return { channel, architecture, state: snapshot ? available ? 'available' as const : 'unavailable' as const : 'not-published' as const,
      publishedAt: snapshot?.created_at ?? null, snapshotId: snapshot?.id ?? null,
      binaryPackages: counts.find((row) => row.architecture === architecture && row.channel === channel && row.surface === 'binary')?.packages ?? 0,
      recipePackages: counts.find((row) => row.architecture === architecture && row.channel === channel && row.surface === 'recipe')?.packages ?? 0,
      databaseUrl: snapshot ? `/repo/${channel === 'dev' ? 'dev/' : ''}${architecture}/opr.db` : null,
      signatureUrl: snapshot ? `/repo/${channel === 'dev' ? 'dev/' : ''}${architecture}/opr.db.sig` : null,
    };
  })));
  return { checkedAt: now(), repositories };
}
