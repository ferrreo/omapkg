import type { Actor } from '../model';
import type { Env } from './env';
import { canonicalJson } from '../canonical-json';
import type { FrozenPackage, InputObject } from '../frozen-inputs';
import { inputAuthority, retainInputBytes } from './input-objects';
import { currentNativeBuild, nativeBuildStatement } from './native-signing';
import { assertOutputEvidence } from './output-evidence';
import { reviewedRuntimeExceptions } from './runtime-evidence';
import { reviewReason } from './catalog-ownership';
import { PolicyError, requireSecurity } from './policy';
import { audit, now, sha256 } from './db';
import { hashObject } from './worker-uploads';
import { fenceFrozenLeases } from './input-locks';

type SignedObject = { id: string; object_key: string; artifact_sha256: string; artifact_size: number; signature_key: string;
  signature_sha256: string; key_fingerprint: string };

async function retainSmall(env: Env, actor: Actor, key: string, expected?: string): Promise<InputObject> {
  const object = await env.ARTIFACTS.get(key);
  if (!object || object.size < 1 || object.size > 1024 * 1024) throw new PolicyError(409, 'Signed native input evidence is unavailable or oversized.');
  const bytes = new Uint8Array(await object.arrayBuffer());
  if (bytes.byteLength !== object.size || (expected && await sha256(bytes) !== expected)) throw new PolicyError(409, 'Signed native input evidence changed.');
  return retainInputBytes(env, actor, bytes);
}

export async function retainNativeInput(env: Env, actor: Actor | null, buildId: string, attempt: number, filename: string): Promise<FrozenPackage> {
  const human = await inputAuthority(env.DB, actor);
  const context = await currentNativeBuild(env, buildId);
  if (context.build.attempt !== attempt || !context.build.input_lock_sha256) throw new PolicyError(409, 'Only a signed native output from a frozen attempt can become an owned build input.');
  const report = await assertOutputEvidence(JSON.parse(context.build.provenance!), reviewedRuntimeExceptions(context.revision.sbom_json));
  const output = report.outputs.find((item) => item.filename === filename);
  const artifact = context.artifacts.find((item) => item.filename === filename);
  if (!output || !artifact || !report.frozenInputs) throw new PolicyError(409, 'Choose a completed frozen package output.');
  async function signed(kind: 'package' | 'attestation', name: string): Promise<SignedObject> {
    const row = await env.DB.prepare(`SELECT id,object_key,artifact_sha256,artifact_size,signature_key,signature_sha256,key_fingerprint
      FROM signing_intents WHERE build_id=? AND build_attempt=? AND object_kind=? AND artifact_filename=? AND status='signed' ORDER BY created_at DESC LIMIT 1`)
      .bind(buildId, attempt, kind, name).first<SignedObject>();
    if (!row?.signature_key || !row.signature_sha256 || row.key_fingerprint?.toLowerCase() !== (env.PACKAGE_SIGNING_FINGERPRINT ?? env.SIGNING_FINGERPRINT ?? '').toLowerCase()) {
      throw new PolicyError(409, 'Package and native statement must both be signed with the configured key.');
    }
    return row;
  }
  const pkg = await signed('package', filename); const statement = await signed('attestation', 'attestation.json');
  if (pkg.object_key !== artifact.key || pkg.artifact_sha256 !== artifact.sha256 || pkg.artifact_size !== artifact.size ||
      statement.artifact_sha256 !== await sha256(await nativeBuildStatement(context))) throw new PolicyError(409, 'Native signatures differ from completed output or statement.');
  const actual = await hashObject(env.ARTIFACTS, artifact.key);
  if (actual.sha256 !== artifact.sha256 || actual.size !== artifact.size) throw new PolicyError(409, 'Signed package bytes changed.');
  await env.DB.prepare('INSERT OR IGNORE INTO input_objects(sha256,size,object_key,created_by,created_at) VALUES(?,?,?,?,?)')
    .bind(actual.sha256, actual.size, artifact.key, human.id, now()).run();
  const signature = await retainSmall(env, human, pkg.signature_key, pkg.signature_sha256);
  const publicKey = await retainSmall(env, human, env.PACKAGE_SIGNING_PUBLIC_KEY_R2_KEY ?? 'keys/opr-package-signing.asc');
  const origin = await retainInputBytes(env, human, new TextEncoder().encode(canonicalJson({ schemaVersion: 1, kind: 'native-build', buildId, attempt,
    inputLock: report.frozenInputs.lock, statement: await retainSmall(env, human, statement.object_key, statement.artifact_sha256),
    signature: await retainSmall(env, human, statement.signature_key, statement.signature_sha256), publicKey, fingerprint: pkg.key_fingerprint.toUpperCase() })));
  const metadata = output.packageMetadata;
  const entry: FrozenPackage = { name: metadata.name, version: metadata.fullVersion, architecture: metadata.architecture, filename,
    package: actual, signature, publicKey, fingerprint: pkg.key_fingerprint.toUpperCase(), origin: 'owned-build', originEvidence: origin.sha256 };
  await currentNativeBuild(env, buildId);
  await inputAuthority(env.DB, actor);
  await env.DB.batch([
    env.DB.prepare(`INSERT OR IGNORE INTO input_owned_packages(package_sha256,origin_evidence,package_json,build_id,attempt,input_lock_sha256,
      package_intent_id,statement_intent_id,created_by,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)`)
      .bind(actual.sha256, origin.sha256, canonicalJson(entry), buildId, attempt, context.build.input_lock_sha256, pkg.id, statement.id, human.id, now()),
    audit(env.DB, human.id, 'input.native_retained', actual.sha256, { buildId, attempt, filename, originEvidence: origin.sha256 }),
  ]);
  const eligible = await env.DB.prepare('SELECT package_json FROM eligible_owned_inputs WHERE package_sha256=? AND origin_evidence=?')
    .bind(actual.sha256, origin.sha256).first<{ package_json: string }>();
  if (eligible?.package_json !== canonicalJson(entry)) throw new PolicyError(409, 'Native input origin was revoked or changed.');
  return entry;
}

export async function revokeNativeInput(env: Env, actor: Actor | null, digest: string, originEvidence: string, reason: string) {
  const human = await inputAuthority(env.DB, actor); requireSecurity(human); const clean = reviewReason(reason);
  const existing = await env.DB.prepare('SELECT revoked_at FROM input_owned_packages WHERE package_sha256=? AND origin_evidence=?')
    .bind(digest, originEvidence).first<{ revoked_at: number | null }>();
  if (!existing) throw new PolicyError(404, 'Native input origin not found.');
  if (existing.revoked_at !== null) return;
  await env.DB.batch([
    env.DB.prepare('UPDATE input_owned_packages SET revoked_at=?,revoke_reason=? WHERE package_sha256=? AND origin_evidence=? AND revoked_at IS NULL')
      .bind(now(), clean, digest, originEvidence),
    fenceFrozenLeases(env.DB),
    audit(env.DB, human.id, 'input.native_revoked', digest, { originEvidence, reason: clean }),
  ]);
}
