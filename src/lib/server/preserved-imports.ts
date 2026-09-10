import type { Actor, Architecture, Revision } from '../model';
import { canonicalJson } from '../canonical-json';
import { parseInputObject, type InputObject } from '../frozen-inputs';
import { preservedRecipe } from '../preserved-recipe';
import { createPreservedRevision, preservedCatalog } from '../../../services/pipeline/preserved-revision';
import { createFactoryPullRequest } from '../../../services/pipeline/github-pr';
import { persistFactoryRevision } from '../../../services/pipeline/revision';
import type { FactoryEnv, FactoryRevisionDraft } from '../../../services/pipeline/types';
import { inputAuthority, inputObject } from './input-objects';
import { getRecipeCapture } from './recipe-captures';
import { reviewReason } from './catalog-ownership';
import { audit, now, sha256 } from './db';
import { PolicyError } from './policy';

export type PreservedImport = { id: string; request_id: string; revision_id: string; capture_sha256: string; pkgbase: string;
  catalog_revision: number; catalog_sha256: string; evidence_json: string; draft_json: string; created_by: string; reason: string; created_at: number };

export async function reservePreservedImport(env: FactoryEnv, actor: Actor | null, captureSha: string, sources: Partial<Record<Architecture, InputObject>>, smokeCommands: string[], reason: string) {
  const human = await inputAuthority(env.DB, actor), message = reviewReason(reason);
  const capture = await getRecipeCapture(env, captureSha), catalog = await preservedCatalog(env.DB, capture.manifest.pkgbase);
  for (const [target, ref] of Object.entries(sources)) {
    if (target !== 'x86_64' && target !== 'aarch64') throw new PolicyError(400, 'Unsupported source bundle target.');
    parseInputObject(ref, 2 * 1024 * 1024);
  }
  const operation = await sha256(canonicalJson({ capture: capture.reference, sources, smokeCommands, reason: message,
    catalogRevision: catalog.record.revision, catalogSha256: catalog.record.manifest_sha256, createdBy: human.id }));
  const existing = await env.DB.prepare('SELECT * FROM preserved_recipe_imports WHERE id=?').bind(operation).first<PreservedImport>();
  if (existing) return existing;
  const requestId = crypto.randomUUID(), revisionId = crypto.randomUUID();
  const { draft, catalog: checked } = await createPreservedRevision(env, { requestId, revisionId, capture: capture.reference, sources, smokeCommands, reason: message });
  if (checked.record.manifest_sha256 !== catalog.record.manifest_sha256) throw new PolicyError(409, 'Catalog changed before recipe import.');
  const timestamp = now(), policy = checked.policy;
  const row: PreservedImport = { id: operation, request_id: requestId, revision_id: revisionId, capture_sha256: captureSha, pkgbase: policy.pkgbase,
    catalog_revision: checked.record.revision, catalog_sha256: checked.record.manifest_sha256, evidence_json: canonicalJson(preservedRecipe(draft.revision)),
    draft_json: canonicalJson(draft), created_by: human.id, reason: message, created_at: timestamp };
  await inputAuthority(env.DB, actor);
  try { await env.DB.batch([
    env.DB.prepare(`INSERT INTO requests(id,name,description,upstream_url,source_kind,area,declared_license,requested_by,status,created_at,updated_at,
      factory_run_id,catalog_pkgbase,catalog_revision,preserved_import_id) VALUES(?,?,?,?,?,?,?,?,'generating',?,?,?,?,?,?)`)
      .bind(requestId, policy.pkgbase, draft.revision.description, policy.upstreamUrl, policy.sourceKind, policy.ownerArea, policy.license, human.id,
        timestamp, timestamp, revisionId, policy.pkgbase, checked.record.revision, operation),
    env.DB.prepare(`INSERT INTO preserved_recipe_imports(id,request_id,revision_id,capture_sha256,pkgbase,catalog_revision,catalog_sha256,evidence_json,draft_json,created_by,reason,created_at)
      VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`).bind(row.id, row.request_id, row.revision_id, row.capture_sha256, row.pkgbase, row.catalog_revision, row.catalog_sha256,
        row.evidence_json, row.draft_json, row.created_by, row.reason, row.created_at),
    audit(env.DB, human.id, 'recipe.import_reserved', requestId, { importId: operation, captureSha256: captureSha, revisionId, reason: message }),
  ]); } catch (cause) {
    // An identical concurrent submission shares the stored draft and Git branch.
    const retry = await env.DB.prepare('SELECT * FROM preserved_recipe_imports WHERE id=?').bind(operation).first<PreservedImport>();
    if (retry) return retry;
    if (cause instanceof Error && /constraint|authority/i.test(cause.message)) throw new PolicyError(409, 'Active package request or source authority changed before import.');
    throw cause;
  }
  return row;
}

export async function assertPreservedImportCurrent(db: D1Database, revision: Pick<Revision, 'id' | 'sbom_json' | 'architectures_json' | 'manifest_sha256'>) {
  const evidence = preservedRecipe(revision);
  if (!evidence) return;
  const row = await db.prepare('SELECT evidence_json,draft_json FROM current_preserved_recipe_imports WHERE revision_id=?')
    .bind(revision.id).first<{ evidence_json: string; draft_json: string }>();
  if (!row || row.evidence_json !== canonicalJson(evidence) || (JSON.parse(row.draft_json) as FactoryRevisionDraft).revision.manifest_sha256 !== revision.manifest_sha256) {
    throw new PolicyError(409, 'Preserved recipe import or source authority changed.');
  }
}

export async function resumePreservedImport(env: FactoryEnv, actor: Actor | null, captureSha: string, importId: string) {
  await inputAuthority(env.DB, actor);
  const row = await env.DB.prepare('SELECT * FROM preserved_recipe_imports WHERE id=? AND capture_sha256=?').bind(importId, captureSha).first<PreservedImport>();
  if (!row) throw new PolicyError(404, 'Preserved recipe import not found.');
  const draft = JSON.parse(row.draft_json) as FactoryRevisionDraft;
  await assertPreservedImportCurrent(env.DB, draft.revision);
  const request = await env.DB.prepare('SELECT status,factory_run_id FROM requests WHERE id=?').bind(row.request_id).first<{ status: string; factory_run_id: string | null }>();
  const stored = await env.DB.prepare('SELECT * FROM revisions WHERE id=? AND request_id=?').bind(row.revision_id, row.request_id).first<Revision>();
  if (stored && request?.factory_run_id === row.revision_id) return { requestId: row.request_id, revisionId: stored.id, prUrl: stored.pr_url };
  if (request?.status !== 'generating' || request.factory_run_id !== row.revision_id) throw new PolicyError(409, 'Recipe import request is no longer accepting this revision.');
  let pull: Awaited<ReturnType<typeof createFactoryPullRequest>>;
  try { pull = await createFactoryPullRequest(env, draft); }
  catch {
    await env.DB.batch([audit(env.DB, row.created_by, 'recipe.import_upload_failed', row.request_id, { importId: row.id })]);
    throw new PolicyError(503, 'Recipe pull request upload did not finish. Retry this import from its saved draft.');
  }
  draft.revision.pr_url = pull.url; draft.revision.commit_sha = pull.commitSha;
  await inputAuthority(env.DB, actor);
  await assertPreservedImportCurrent(env.DB, draft.revision);
  const persisted = await persistFactoryRevision(env, draft, row.created_by, row.revision_id);
  return { requestId: row.request_id, revisionId: persisted.revision.id, prUrl: persisted.revision.pr_url };
}

export async function cancelPreservedImport(db: D1Database, actor: Actor | null, captureSha: string, importId: string, reason: string) {
  const human = await inputAuthority(db, actor), message = reviewReason(reason);
  const result = await db.batch([
    db.prepare(`UPDATE requests SET status='rejected',rejection_reason=?,updated_at=? WHERE status='generating'
      AND preserved_import_id=? AND EXISTS(SELECT 1 FROM preserved_recipe_imports i WHERE i.id=requests.preserved_import_id AND i.capture_sha256=?
        AND NOT EXISTS(SELECT 1 FROM revisions r WHERE r.id=i.revision_id))`).bind(message, now(), importId, captureSha),
    db.prepare(`INSERT INTO audit_events(actor,action,target,detail,created_at) SELECT ?,'recipe.import_cancelled',?,?,? WHERE changes()=1`)
      .bind(human.id, importId, canonicalJson({ reason: message }), now()),
  ]);
  if (!result[0].meta.changes) throw new PolicyError(409, 'Only an unfinished recipe import can be cancelled.');
}

export async function importPreservedRecipe(env: FactoryEnv, actor: Actor | null, captureSha: string, bundleDigests: string[], smokeCommands: string[], reason: string) {
  await inputAuthority(env.DB, actor);
  if (!bundleDigests.length || bundleDigests.length > 2 || bundleDigests.some((digest) => !/^[a-f0-9]{64}$/.test(digest))) throw new PolicyError(400, 'Select one retained source bundle per catalog target.');
  const sources: Partial<Record<Architecture, InputObject>> = {};
  for (const digest of bundleDigests) {
    const row = await env.DB.prepare('SELECT architecture FROM recipe_source_bundles WHERE sha256=? AND capture_sha256=?').bind(digest, captureSha).first<{ architecture: Architecture }>();
    if (!row || sources[row.architecture]) throw new PolicyError(409, 'Source selection repeats a target or belongs to another capture.');
    const ref = await inputObject(env.DB, digest); sources[row.architecture] = { sha256: ref.sha256, size: ref.size };
  }
  const row = await reservePreservedImport(env, actor, captureSha, sources, smokeCommands, reason);
  return resumePreservedImport(env, actor, captureSha, row.id);
}
