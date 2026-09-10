import { expect, test } from 'bun:test';
import { canonicalJson } from '../src/lib/canonical-json';
import { sha256 } from '../src/lib/server/db';
import { prepareReleaseSelection } from '../src/lib/server/release-preparation';
import { env } from './release-fixtures';
import { TestD1 } from './d1';

test('release selection rejects invalid, stale and held changes before preparing any objects', async () => {
  const db = new TestD1(`
    CREATE TABLE cohorts(id TEXT,current_revision INTEGER,phase TEXT,condition TEXT);
    CREATE TABLE cohort_revisions(cohort_id TEXT,revision INTEGER,manifest_json TEXT,manifest_sha256 TEXT,title TEXT,lane TEXT);
  `);
  const manifest = canonicalJson({ schemaVersion: 1, title: 'Terminal updates', lane: 'system', systemVersion: '4.0.3-rc1', parentSnapshot: null, compatibleSystems: [], members: [] });
  const digest = await sha256(manifest);
  db.prepare("INSERT INTO cohorts VALUES('terminal',1,'verify','held')").run();
  db.prepare("INSERT INTO cohort_revisions VALUES('terminal',1,?,?, 'Terminal updates','system')").bind(manifest, digest).run();
  const service = env(db);
  const actor = { id: 'github:1', role: 'admin' as const, areas: [] };
  const form = new FormData(); form.set('lane', 'system'); form.set('channel', 'rc');
  try {
    await expect(prepareReleaseSelection(service, actor, form)).rejects.toThrow('Select the changes');
    form.append('changes', 'terminal@' + 'a'.repeat(64));
    await expect(prepareReleaseSelection(service, actor, form)).rejects.toThrow('changed. Refresh');
    form.set('changes', 'terminal@' + digest);
    await expect(prepareReleaseSelection(service, actor, form)).rejects.toThrow('not available for this release');
    form.set('channel', 'quarantine');
    await expect(prepareReleaseSelection(service, actor, form)).rejects.toThrow('Choose a channel');
    form.set('channel', 'rc');
    await expect(prepareReleaseSelection(service, { ...actor, id: 'agent:factory' }, form)).rejects.toThrow('signed-in human');
    expect(service.ARTIFACTS).toBeDefined();
  } finally { db.close(); }
});
