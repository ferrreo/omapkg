import { expect, test } from 'bun:test';
import { readFileSync, readdirSync } from 'node:fs';
import { asD1, TestD1 } from './d1';
import { blockerStatements } from '../src/lib/server/dependency-blockers';
import { decideDependencyProposal, getDependencyProposal, listDependencyProposals, reviseDependencyProposal } from '../src/lib/server/dependency-proposals';

const schema = readdirSync(new URL('../migrations', import.meta.url)).filter((file) => file.endsWith('.sql')).sort()
  .map((file) => readFileSync(new URL(`../migrations/${file}`, import.meta.url), 'utf8')).join('\n');
const owner = { id: 'github:1', role: 'maintainer' as const, areas: ['development'] };
async function block(db: TestD1, name: string, relation = 'needed>=2') {
  db.prepare(`INSERT INTO requests(id,name,upstream_url,source_kind,area,requested_by,status,created_at,updated_at,factory_run_id)
    VALUES(?,?,'https://example.org/source.git','git','development','github:1','generating',1,1,?)`).bind(name, name, `run-${name}`).run();
  await asD1(db).batch(await blockerStatements(asD1(db), { requestId: name, scopeId: `run-${name}`, revisionId: null, architecture: 'aarch64', timestamp: 2 },
    [{ relation, phase: 'factory', resolution: 'dependency', detail: 'No owned ARM provider exists' }], 'factory'));
}

test('missing providers create shared inert proposals; human admission creates only a pending request and preserves parent blockers', async () => {
  const db = new TestD1(schema); const d1 = asD1(db);
  try {
    await block(db, 'first'); await block(db, 'second');
    const proposals = await listDependencyProposals(d1);
    expect(proposals).toHaveLength(1); expect(proposals[0].parents).toBe(2);
    const { proposal, manifest } = await getDependencyProposal(d1, proposals[0].id);
    expect(manifest.upstreamUrl).toBeNull();
    expect(db.prepare('SELECT COUNT(*) AS n FROM requests').first<{ n: number }>()?.n).toBe(2);
    await expect(decideDependencyProposal(d1, owner, proposal.id, proposal.manifest_sha256, 'admit', 'Needs a source')).rejects.toThrow('upstream URL');
    await expect(reviseDependencyProposal(d1, owner, proposal.id, proposal.manifest_sha256,
      { ...manifest, upstreamUrl: 'https://aur.archlinux.org/needed.git', sourceKind: 'git' }, 'Use AUR')).rejects.toThrow('reference evidence');
    const revised = await reviseDependencyProposal(d1, owner, proposal.id, proposal.manifest_sha256,
      { ...manifest, upstreamUrl: 'https://example.org/needed.git', sourceKind: 'git', origin: 'alarm-reference', referenceUrl: 'https://archlinuxarm.org/packages/needed' }, 'Review source and ARM adaptation');
    await expect(decideDependencyProposal(d1, { ...owner, id: 'factory' }, revised.proposalId, revised.manifestSha256, 'admit', 'Agent decision')).rejects.toMatchObject({ status: 403 });
    await expect(decideDependencyProposal(d1, owner, proposal.id, proposal.manifest_sha256, 'admit', 'Stale source')).rejects.toMatchObject({ status: 409 });
    const result = await decideDependencyProposal(d1, owner, revised.proposalId, revised.manifestSha256, 'admit', 'Admit upstream for normal packaging review');
    expect(db.prepare('SELECT status FROM requests WHERE id=?').bind(result.requestId).first<Record<string, unknown>>()).toEqual({ status: 'pending' });
    expect(db.prepare("SELECT COUNT(*) AS n FROM requests WHERE status='blocked'").first<Record<string, unknown>>()).toEqual({ n: 2 });
    expect(db.prepare('SELECT COUNT(*) AS n FROM approvals').first<Record<string, unknown>>()).toEqual({ n: 0 });
    expect(db.prepare('SELECT COUNT(*) AS n FROM builds').first<Record<string, unknown>>()).toEqual({ n: 0 });
    expect(db.prepare('SELECT COUNT(*) AS n FROM dependency_blockers WHERE dependency_request_id=?').bind(result.requestId).first<Record<string, unknown>>()).toEqual({ n: 2 });
    expect(await decideDependencyProposal(d1, owner, revised.proposalId, revised.manifestSha256, 'admit', 'Retry same decision')).toEqual(result);
    expect(() => db.exec("UPDATE dependency_proposals SET manifest_json='{}'")).toThrow('immutable');
  } finally { db.close(); }
});

test('declined proposals stay blocked; a multi-parent cycle cannot partially create a request or link', async () => {
  const db = new TestD1(schema); const d1 = asD1(db);
  try {
    await block(db, 'parent');
    const draft = (await listDependencyProposals(d1))[0];
    await decideDependencyProposal(d1, owner, draft.id, draft.manifest_sha256, 'decline', 'Source cannot be maintained');
    expect(db.prepare("SELECT status FROM requests WHERE id='parent'").first<Record<string, unknown>>()).toEqual({ status: 'blocked' });
    await block(db, 'another');
    expect(await listDependencyProposals(d1)).toEqual([]);
    expect(await listDependencyProposals(d1, { status: 'declined' })).toHaveLength(1);
    const { manifest } = await getDependencyProposal(d1, draft.id);
    const alternative = await reviseDependencyProposal(d1, owner, draft.id, draft.manifest_sha256, manifest, 'Reconsider with existing package');
    await expect(decideDependencyProposal(d1, owner, alternative.proposalId, alternative.manifestSha256, 'admit', 'Link parent to itself', 'parent')).rejects.toThrow('itself');
    expect(db.prepare('SELECT COUNT(*) AS n FROM dependency_blockers WHERE dependency_request_id IS NOT NULL').first<Record<string, unknown>>()).toEqual({ n: 0 });
  } finally { db.close(); }
});
