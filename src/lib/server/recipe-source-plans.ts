import type { Architecture } from '../model';
import { canonicalJson } from '../canonical-json';
import { parseSrcinfo } from '../srcinfo';
import { parseRecipeSourceBundle, recipeSourceObjects, recipeSources, type RecipeSourcePlan } from '../recipe-sources';
import type { Env } from './env';
import { getRecipeCapture } from './recipe-captures';
import { audit, now, query, sha256 } from './db';
import { PolicyError } from './policy';
import { decodeBase64, verifyEd25519 } from './worker-protocol';
import type { Actor } from '../model';
import type { InputObject } from '../frozen-inputs';
import { inputAuthority, inputJson } from './input-objects';
import { reviewReason } from './catalog-ownership';

export async function recipeSourcePlan(env: Pick<Env, 'DB' | 'ARTIFACTS' | 'GITHUB_REPOSITORY'>, captureSha: string, job: string, attempt: number) {
  const capture = await getRecipeCapture(env, captureSha);
  const evidence = await env.DB.prepare(`SELECT i.architecture,r.report_json,r.report_sha256,r.signature,r.metadata_json,a.public_key FROM current_recipe_inspections i
    JOIN recipe_inspection_results r ON r.job_id=i.id AND r.attempt=i.attempt
    JOIN recipe_inspection_attempts a ON a.job_id=r.job_id AND a.attempt=r.attempt
    JOIN workers w ON w.id=a.worker_id AND w.public_key=a.public_key AND w.status='active'
    WHERE i.capture_sha256=? AND i.id=? AND i.attempt=? AND i.status='succeeded' AND r.error IS NULL`)
    .bind(captureSha, job, attempt).first<{ architecture: Architecture; report_json: string; report_sha256: string; signature: string; metadata_json: string; public_key: string }>();
  if (!evidence) throw new PolicyError(409, 'A current successful native inspection is required for source preparation.');
  if (await sha256(evidence.report_json) !== evidence.report_sha256 || !await verifyEd25519(decodeBase64(evidence.public_key, 'inspection public key'),
    new TextEncoder().encode(evidence.report_json), decodeBase64(evidence.signature, 'inspection signature'))) throw new PolicyError(409, 'Inspection evidence verification failed.');
  const report = JSON.parse(evidence.report_json), metadata = parseSrcinfo(report.srcinfo);
  if (canonicalJson(metadata) !== evidence.metadata_json || report.srcinfoSha256 !== await sha256(report.srcinfo) || report.capture.sha256 !== captureSha ||
      report.architecture !== evidence.architecture || report.jobId !== job || report.attempt !== attempt) throw new PolicyError(409, 'Inspected source metadata differs from retained evidence.');
  let sources: Pick<RecipeSourcePlan, 'sources' | 'validpgpkeys'>;
  try { sources = recipeSources(capture.manifest, metadata, evidence.architecture); }
  catch (cause) { throw new PolicyError(409, cause instanceof Error ? cause.message : 'Source plan requires recipe adaptation.'); }
  const plan: RecipeSourcePlan = { schemaVersion: 1, kind: 'recipe-source-plan', capture: capture.reference,
    inspection: { jobId: job, attempt, reportSha256: evidence.report_sha256, srcinfoSha256: report.srcinfoSha256 },
    pkgbase: metadata.pkgbase, version: metadata.version, architecture: evidence.architecture, ...sources };
  if (new TextEncoder().encode(canonicalJson(plan)).length > 2 * 1024 * 1024) throw new PolicyError(409, 'Source plan exceeds its 2 MiB metadata budget.');
  return plan;
}

export async function retainRecipeSources(env: Pick<Env, 'DB' | 'ARTIFACTS' | 'GITHUB_REPOSITORY'>, actor: Actor | null, capture: string, ref: InputObject, reason: string) {
  const human = await inputAuthority(env.DB, actor), message = reviewReason(reason);
  let manifest: ReturnType<typeof parseRecipeSourceBundle>;
  try { manifest = parseRecipeSourceBundle(await inputJson(env, ref, 2 * 1024 * 1024)); }
  catch (cause) { if (cause instanceof PolicyError) throw cause; throw new PolicyError(400, 'Invalid source bundle, object budget or inventory.'); }
  const retainedPlan = await inputJson(env, manifest.plan, 2 * 1024 * 1024).catch((cause) => {
    if (cause instanceof PolicyError) throw cause; throw new PolicyError(400, 'Invalid retained source plan.');
  }) as RecipeSourcePlan;
  if (!retainedPlan || retainedPlan.kind !== 'recipe-source-plan' || retainedPlan.capture?.sha256 !== capture ||
      typeof retainedPlan.inspection?.jobId !== 'string' || !Number.isSafeInteger(retainedPlan.inspection?.attempt)) throw new PolicyError(409, 'Source plan does not belong to this captured recipe.');
  const plan = await recipeSourcePlan(env, capture, retainedPlan.inspection.jobId, retainedPlan.inspection.attempt);
  if (canonicalJson(plan) !== canonicalJson(retainedPlan)) throw new PolicyError(409, 'Source plan differs from current signed native inspection.');
  const expected = plan.sources.filter((source) => source.kind !== 'local');
  if (expected.length !== manifest.sources.length || expected.some((source, index) => {
    const entry = manifest.sources[index];
    return entry.name !== source.name || entry.kind !== source.kind || (entry.kind === 'file' && source.kind === 'file' && entry.redirects[0] !== source.url) ||
      (entry.kind === 'git' && source.kind === 'git' && source.ref.kind === 'commit' && entry.commit !== source.ref.value.toLowerCase());
  }) || plan.validpgpkeys.some((fingerprint) => !manifest.keys.some((key) => key.fingerprint === fingerprint))) throw new PolicyError(409, 'Prepared sources or signing keys differ from inspected scope.');
  const refs = [...new Map(recipeSourceObjects(manifest).filter((ref) => ref.size).map((ref) => [ref.sha256, ref])).values()];
  for (let offset = 0; offset < refs.length; offset += 64) {
    const batch = refs.slice(offset, offset + 64);
    const rows = await query<InputObject>(env.DB, 'SELECT sha256,size FROM input_objects WHERE sha256 IN (SELECT value FROM json_each(?))', canonicalJson(batch.map((ref) => ref.sha256)));
    if (rows.length !== batch.length || batch.some((ref) => !rows.some((row) => row.sha256 === ref.sha256 && row.size === ref.size))) throw new PolicyError(409, 'Prepared source objects must be completely retained before import.');
  }
  await inputAuthority(env.DB, actor);
  try { await env.DB.batch([
    env.DB.prepare(`INSERT OR IGNORE INTO recipe_source_bundles(sha256,plan_sha256,capture_sha256,inspection_id,inspection_attempt,architecture,manifest_json,created_by,reason,created_at)
      VALUES(?,?,?,?,?,?,?,?,?,?)`).bind(ref.sha256, manifest.plan.sha256, capture, plan.inspection.jobId, plan.inspection.attempt, plan.architecture, canonicalJson(manifest), human.id, message, now()),
    audit(env.DB, human.id, 'recipe.sources_retained', ref.sha256, { captureSha256: capture, planSha256: manifest.plan.sha256, reason: message }),
  ]); } catch (cause) {
    if (cause instanceof Error && /constraint|authority/i.test(cause.message)) throw new PolicyError(409, 'Source preparation authority changed before retention.');
    throw cause;
  }
  return { sha256: ref.sha256 };
}
