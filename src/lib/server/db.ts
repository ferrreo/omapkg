import { Effect } from 'effect';

export const now = () => Math.floor(Date.now() / 1000);
export const id = () => crypto.randomUUID();
export const query = <T>(db: D1Database, sql: string, ...values: unknown[]) =>
  Effect.runPromise(Effect.tryPromise({
    try: async () => (await db.prepare(sql).bind(...values).all<T>()).results,
    catch: (cause) => new Error('Database query failed', { cause })
  }));
export const audit = (db: D1Database, actor: string, action: string, target: string, detail: unknown = {}) =>
  db.prepare('INSERT INTO audit_events(actor,action,target,detail,created_at) VALUES(?,?,?,?,?)')
    .bind(actor, action, target, JSON.stringify(detail), now());
export async function sha256(value: string | Uint8Array): Promise<string> {
  const bytes = typeof value === 'string' ? new TextEncoder().encode(value) : value;
  return Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes as BufferSource)), (b) => b.toString(16).padStart(2, '0')).join('');
}
