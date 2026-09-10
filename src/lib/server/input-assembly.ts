import type { Actor } from '../model';
import type { FrozenManifest, FrozenPackage } from '../frozen-inputs';
import { canonicalJson } from '../canonical-json';
import type { Env } from './env';
import { inputAuthority, inputObject, retainInputBytes } from './input-objects';
import { inspectRetainedLock, proposeInputLock, requireCurrentInputLock } from './input-locks';
import { query } from './db';
import { PolicyError } from './policy';

export type OwnedInputChoice = { source: FrozenPackage; candidates: { package: FrozenPackage; buildId: string; attempt: number }[] };

type InputEnv = Pick<Env, 'DB' | 'ARTIFACTS'>;

// Preserve the captured closure's exact versions. Upgrading the closure belongs
// to dependency/cohort planning; it cannot be hidden inside bootstrap removal.
export async function ownedInputChoices(db: D1Database, digest: string): Promise<OwnedInputChoice[]> {
  const rows = await query<{ package_json: string }>(db, 'SELECT package_json FROM input_lock_packages WHERE lock_sha256=? ORDER BY package_sha256,origin_evidence', digest);

  const sources = new Map(rows.map((row) => { const pkg = JSON.parse(row.package_json) as FrozenPackage;

 return [pkg.package.sha256, pkg]; }));

  const candidates = await query<{ package_json: string; build_id: string; attempt: number }>(db, `SELECT DISTINCT p.package_json,p.build_id,p.attempt,p.origin_evidence FROM input_lock_packages source
    JOIN eligible_owned_inputs p ON json_extract(source.package_json,'$.name')=json_extract(p.package_json,'$.name')
      AND json_extract(source.package_json,'$.version')=json_extract(p.package_json,'$.version')
      AND json_extract(source.package_json,'$.architecture')=json_extract(p.package_json,'$.architecture') WHERE source.lock_sha256=?
    ORDER BY p.origin_evidence LIMIT 8193`, digest);

  if (candidates.length > 8192) throw new PolicyError(409, 'Too many native input candidates. Revoke superseded inputs before assembly.');
  const parsed = candidates.map((row) => ({ package: JSON.parse(row.package_json) as FrozenPackage, buildId: row.build_id, attempt: row.attempt }));
  const identity = (pkg: FrozenPackage) => `${pkg.name} ${pkg.version} ${pkg.architecture}`;
  const byIdentity = new Map<string, typeof parsed>();

  for (const candidate of parsed) {
    const key = identity(candidate.package); const group = byIdentity.get(key) ?? [];
    group.push(candidate); byIdentity.set(key, group);
  }

  return [...sources.values()].sort((a, b) => a.name < b.name ? -1 : a.name > b.name ? 1 : a.version.localeCompare(b.version)).map((source) => {
    const matching = byIdentity.get(identity(source)) ?? [];
    // Identical bytes can have several signed reproductions; retain the first
    // origin in digest order. Different bytes require an explicit human choice.
    const unique = new Map<string, typeof matching[number]>();

    for (const candidate of matching) if (!unique.has(candidate.package.package.sha256)) unique.set(candidate.package.package.sha256, candidate);

    return { source, candidates: [...unique.values()] };
  });
}

export async function assembleOwnedInputLock(env: InputEnv, actor: Actor | null, digest: string, selected: Record<string, string>, reason: string) {
  const human = await inputAuthority(env.DB, actor); const baseline = await requireCurrentInputLock(env, digest);
  const choices = await ownedInputChoices(env.DB, digest);

  if (Object.keys(selected).some((key) => !choices.some((choice) => choice.source.package.sha256 === key))) throw new PolicyError(400, 'Provider choice is outside this input lock.');
  const packages = new Map<string, FrozenPackage>();

  for (const choice of choices) {
    if (!choice.candidates.length) throw new PolicyError(409, `Native input still missing: ${choice.source.name} ${choice.source.version} (${choice.source.architecture}).`);
    const chosen = selected[choice.source.package.sha256];
    const candidate = chosen ? choice.candidates.find((item) => item.package.originEvidence === chosen) : choice.candidates.length === 1 ? choice.candidates[0] : null;

    if (!candidate) throw new PolicyError(409, `Choose an exact package archive for ${choice.source.name}; matching versions have different checksums.`);
    packages.set(choice.source.package.sha256, candidate.package);
  }

  const object = await inputObject(env.DB, digest); const inspection = await inspectRetainedLock(env, { sha256: digest, size: object.size });
  const manifest: FrozenManifest = { ...inspection.manifest, purpose: 'owned', environments: [] };

  for (const [index, environment] of inspection.environments.entries()) {
    const native = environment.packages.map((pkg) => packages.get(pkg.package.sha256)!);
    const chunks = [];

    for (let offset = 0; offset < native.length; offset += 64) chunks.push(await retainInputBytes(env, human, new TextEncoder().encode(canonicalJson(native.slice(offset, offset + 64)))));
    manifest.environments.push({ ...inspection.manifest.environments[index], totalBytes: native.reduce((size, pkg) => size + pkg.package.size, 0), chunks });
  }

  const ref = await retainInputBytes(env, human, new TextEncoder().encode(canonicalJson(manifest)));

  return proposeInputLock(env, human, baseline.recipe_revision_id, ref, reason);
}
