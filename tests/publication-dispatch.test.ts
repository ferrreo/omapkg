import { expect, test } from 'bun:test';
import type { Env } from '../src/lib/server/env';
import { asD1, TestD1 } from './d1';
import { enqueuePublication } from '../services/pipeline/publication-dispatch';

const schema = `
CREATE TABLE publication_jobs (
  build_id TEXT PRIMARY KEY,
  status TEXT NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0,
  next_attempt_at INTEGER NOT NULL,
  last_error TEXT,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);`;

function service(db: TestD1, create: () => Promise<{ id: string }>): Env {
  return {
    DB: asD1(db),
    ARTIFACTS: {} as R2Bucket,
    PUBLIC_ORIGIN: 'https://opr.example',
    MAINTAINER_GITHUB_IDS: '',
    SECURITY_GITHUB_IDS: '',
    QUARANTINE_HOURS: '48',
    PUBLICATION: { create, get: async () => { throw new Error('missing workflow'); } },
  } as Env;
}

test('publication dispatch cannot overwrite a workflow that completed during enqueue', async () => {
  const db = new TestD1(schema);
  const env = service(db, async () => {
    await db.prepare("UPDATE publication_jobs SET status='completed',last_error=NULL WHERE build_id=?").bind('build-race').run();
    return { id: 'publish-build-race' };
  });
  const result = await enqueuePublication(env, 'build-race');
  expect(result.dispatched).toBe(true);
  expect(db.prepare('SELECT status FROM publication_jobs WHERE build_id=?').bind('build-race').first<{ status: string }>()?.status).toBe('completed');
  db.close();
});

test('dispatch failure cannot overwrite a completed workflow', async () => {
  const db = new TestD1(schema);
  const env = service(db, async () => {
    await db.prepare("UPDATE publication_jobs SET status='completed',last_error=NULL WHERE build_id=?").bind('build-failure-race').run();
    throw new Error('workflow create failed');
  });
  await expect(enqueuePublication(env, 'build-failure-race')).rejects.toThrow('workflow create failed');
  expect(db.prepare('SELECT status,last_error FROM publication_jobs WHERE build_id=?').bind('build-failure-race').first<{ status: string; last_error: string | null }>()).toEqual({ status: 'completed', last_error: null });
  db.close();
});
