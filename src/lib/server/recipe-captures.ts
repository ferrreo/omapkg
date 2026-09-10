import type { Actor } from '../model';
import type { ImportEntry } from '../imports';
import type { InputObject } from '../frozen-inputs';
import { canonicalJson } from '../canonical-json';
import { parseRecipeCapture, verifyRecipeCapture, type RecipeCapture } from '../recipe-capture';
import { parseSrcinfo, srcinfoField, type Srcinfo } from '../srcinfo';
import { now, query, sha256 } from './db';
import { inputAuthority, inputJson, inputObject } from './input-objects';
import { reviewReason } from './catalog-ownership';
import { getCatalogImport } from './catalog-imports';
import { PolicyError } from './policy';
import type { Env } from './env';

type CaptureEnv = Pick<Env, 'DB' | 'ARTIFACTS' | 'GITHUB_REPOSITORY'>;
export type RecipeSummary = { files: number; bytes: number; executableFiles: string[]; installFiles: string[];
  metadata: Srcinfo | null; metadataError: string | null; omarchy: Record<string, unknown> | null;
  rebuildOn: string[]; admissionRequired: boolean; reviewNotes: string[] };
export type RecipeCaptureRow = { sha256: string; pkgbase: string; manifest_json: string; summary_json: string; created_by: string; created_at: number };
export type RecipeComparison = { metadataPresent: boolean; matches: boolean; differences: string[]; capturedOutputs: string[] };

function describeRecipe(value: RecipeCapture, files: Map<string, Uint8Array>): RecipeSummary {
  const text = (path: string) => new TextDecoder('utf-8', { fatal: true }).decode(files.get(path));
  let metadata: Srcinfo | null = null, metadataError: string | null = null, omarchy: Record<string, unknown> | null = null;
  const reviewNotes = ['Custom shell requires independent recipe and security review.', 'Repository attribution and retained commit must be checked during source review.'];
  if (files.has('.SRCINFO')) {
    try { metadata = parseSrcinfo(text('.SRCINFO')); if (metadata.pkgbase !== value.pkgbase) throw new Error('.SRCINFO package base differs from capture'); }
    catch (cause) { metadata = null; metadataError = cause instanceof Error ? cause.message : 'Invalid .SRCINFO'; }
  } else metadataError = '.SRCINFO is absent; metadata inspection is required in an untrusted sandbox.';
  if (metadataError) reviewNotes.push(metadataError);
  if (files.has('.omarchy/package.json')) {
    try {
      const parsed = JSON.parse(text('.omarchy/package.json'));
      if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error('Invalid Omarchy metadata');
      omarchy = parsed;
      const retained = ['source', 'upstream_commit', 'pinned', 'channels', 'release_ring', 'rebuild_on', 'rebuilt_against'];
      for (const key of Object.keys(parsed)) if (!retained.includes(key)) reviewNotes.push(`Unsupported Omarchy field requires review: ${key}`);
      if (parsed.pinned !== undefined) reviewNotes.push('Retained upstream pin requires an explicit local update policy.');
      if (parsed.channels !== undefined || parsed.release_ring !== undefined) reviewNotes.push('Upstream channels and release ring are reference policy; local release approval is required.');
      if (parsed.rebuilt_against !== undefined) reviewNotes.push('Upstream rebuilt_against is reference evidence; owned rebuild evidence is still required.');
    } catch { reviewNotes.push('Omarchy metadata could not be parsed as an object. Original bytes are retained.'); }
  }
  const rebuildOn = Array.isArray(omarchy?.rebuild_on) && omarchy.rebuild_on.every((name) => typeof name === 'string' && /^[a-z0-9][a-z0-9@._+-]{0,63}$/.test(name))
    ? [...new Set(omarchy.rebuild_on as string[])].sort() : [];
  if (omarchy?.rebuild_on !== undefined && !rebuildOn.length) reviewNotes.push('Review unsupported or empty rebuild_on policy.');
  const admissionRequired = ['aur-reference', 'alarm-reference'].includes(value.origin) ||
    (omarchy?.source !== undefined && !['local', 'arch'].includes(String(omarchy.source).toLowerCase()));
  if (admissionRequired) reviewNotes.push('AUR/ALARM reference needs human OPR admission before adaptation or execution.');
  const installFiles = metadata ? [...new Set(metadata.outputs.flatMap((output) => srcinfoField(metadata!, output, 'install')))].sort() : [];
  for (const path of installFiles) if (!value.files.some((file) => file.path === path)) reviewNotes.push(`Install script is missing from captured directory: ${path}`);
  return { files: value.files.length, bytes: value.files.reduce((sum, file) => sum + file.object.size, 0),
    executableFiles: value.files.filter((file) => file.mode === '100755' || file.path.endsWith('.install') || file.path.endsWith('.hook')).map((file) => file.path),
    installFiles, metadata, metadataError, omarchy, rebuildOn, admissionRequired, reviewNotes };
}

export async function getRecipeCapture(env: CaptureEnv, digest: string) {
  const ref = await inputObject(env.DB, digest);
  const record = await env.DB.prepare('SELECT * FROM recipe_captures WHERE sha256=?').bind(digest).first<RecipeCaptureRow>();
  if (!record) throw new PolicyError(404, 'Recipe capture not found.');
  if (await sha256(record.manifest_json) !== digest) throw new PolicyError(409, 'Recipe capture checksum changed.');
  return { record, reference: { sha256: digest, size: ref.size }, manifest: parseRecipeCapture(JSON.parse(record.manifest_json), env.GITHUB_REPOSITORY), summary: JSON.parse(record.summary_json) as RecipeSummary };
}

export async function retainRecipeCapture(env: CaptureEnv, actor: Actor | null, ref: InputObject, importId: string, sourceId: string, reason: string) {
  const human = await inputAuthority(env.DB, actor), message = reviewReason(reason);
  const captured = await getCatalogImport(env.DB, importId);
  if (captured.record.status === 'capturing') throw new PolicyError(409, 'Seal the inventory before attaching source evidence.');
  let manifest: RecipeCapture;
  try { manifest = parseRecipeCapture(await inputJson(env, ref, 512 * 1024), env.GITHUB_REPOSITORY); }
  catch (cause) { throw new PolicyError(400, cause instanceof Error ? cause.message : 'Invalid recipe capture'); }
  if (!captured.manifest.sources.some((source) => source.id === sourceId && source.status === 'captured')) throw new PolicyError(400, 'Select a captured source.');
  const entries = await recipeCapturedEntries(env.DB, importId, sourceId, manifest.pkgbase);
  let files: Map<string, Uint8Array>;
  try {
    files = await verifyRecipeCapture(manifest, async (ref) => {
      const object = await inputObject(env.DB, ref.sha256);
      if (object.size !== ref.size) throw new Error('Recipe object size changed');
      const body = await env.ARTIFACTS.get(object.object_key);
      if (!body || body.size !== ref.size) throw new Error('Retained recipe object is unavailable');
      return new Uint8Array(await body.arrayBuffer());
    });
  } catch (cause) { throw new PolicyError(409, cause instanceof Error ? cause.message : 'Recipe proof failed'); }
  const summary = describeRecipe(manifest, files), metadata = summary.metadata;
  const comparison = compareRecipeMetadata(metadata, entries);
  const timestamp = now();
  await env.DB.batch([
    env.DB.prepare('INSERT OR IGNORE INTO recipe_captures(sha256,pkgbase,manifest_json,summary_json,created_by,created_at) VALUES(?,?,?,?,?,?)')
      .bind(ref.sha256, manifest.pkgbase, canonicalJson(manifest), canonicalJson(summary), human.id, timestamp),
    env.DB.prepare('INSERT OR IGNORE INTO recipe_capture_links(import_id,source_id,pkgbase,capture_sha256,comparison_json,actor,reason,created_at) VALUES(?,?,?,?,?,?,?,?)')
      .bind(importId, sourceId, manifest.pkgbase, ref.sha256, canonicalJson(comparison), human.id, message, timestamp),
    env.DB.prepare(`INSERT INTO audit_events(actor,action,target,detail,created_at) SELECT ?,'recipe.capture_retained',?,?,? WHERE changes()=1`)
      .bind(human.id, ref.sha256, canonicalJson({ importId, sourceId, pkgbase: manifest.pkgbase, matches: comparison.matches, reason: message }), timestamp),
  ]);
  return { sha256: ref.sha256, comparison };
}

export function compareRecipeMetadata(metadata: Srcinfo | null, entries: ImportEntry[]): RecipeComparison {
  const differences: string[] = [];
  for (const entry of entries) {
    const output = metadata?.outputs.find((output) => output.name === entry.name);
    if (!output) { differences.push(`No inspected recipe output for ${entry.name}.`); continue; }
    if (metadata!.version !== entry.version) differences.push(`${entry.name}: recipe ${metadata!.version}; captured ${entry.version}.`);
    const architectures = srcinfoField(metadata!, output, 'arch');
    if (!architectures.includes(entry.architecture)) differences.push(`${entry.name}: captured architecture ${entry.architecture} is absent from recipe metadata.`);
    for (const [field, actual] of [['depends', entry.dependencies], ['provides', entry.provides], ['conflicts', entry.conflicts], ['replaces', entry.replaces]] as const) {
      const declared = srcinfoField(metadata!, output, field, entry.target).sort();
      if (canonicalJson(declared) !== canonicalJson([...actual].sort())) differences.push(`${entry.name}: ${field} differs; inspect generated sonames and recipe changes.`);
    }
  }
  for (const output of metadata?.outputs ?? []) if (!entries.some((entry) => entry.name === output.name)) differences.push(`Recipe output ${output.name} is absent from this captured source.`);
  return { metadataPresent: metadata !== null, matches: metadata !== null && differences.length === 0, differences, capturedOutputs: entries.map((entry) => entry.name) };
}

export async function recipeCapturedEntries(db: D1Database, importId: string, sourceId: string, pkgbase: string): Promise<ImportEntry[]> {
  const size = await db.prepare(`SELECT COUNT(*) AS count,COALESCE(SUM(length(CAST(entry_json AS BLOB))),0) AS bytes FROM catalog_import_entries
    WHERE import_id=? AND source_id=? AND pkgbase=?`).bind(importId, sourceId, pkgbase).first<{ count: number; bytes: number }>();
  if (!size?.count || size.count > 256 || size.bytes > 4 * 1024 * 1024) throw new PolicyError(409, 'Captured recipe mapping must contain 1–256 outputs within its 4 MiB metadata budget.');
  const rows = await query<{ entry_json: string }>(db, 'SELECT entry_json FROM catalog_import_entries WHERE import_id=? AND source_id=? AND pkgbase=? ORDER BY name', importId, sourceId, pkgbase);
  return rows.map((row) => JSON.parse(row.entry_json) as ImportEntry);
}
