import type { Actor, Architecture, Revision } from '../model';
import type { OutputContract } from '../output-contract';
import { canonicalJson } from '../canonical-json';
import { inspectFrozenInputs, INPUT_HASH, MAX_INPUT_METADATA, parseFrozenManifest, parseInputObject, type FrozenManifest, type FrozenPackage, type InputObject } from '../frozen-inputs';
import type { Env } from './env';
import { cohortOutputContract } from './build-outputs';
import { inputAuthority, inputDocuments, inputJson, inputObject, type InputObjectRow } from './input-objects';
import { reviewReason } from './catalog-ownership';
import { audit, id, now, query } from './db';
import { PolicyError, publicSourceURL, requireSecurity, revisionImage } from './policy';

type InputEnv = Pick<Env, 'DB' | 'ARTIFACTS'>;

export type InputLockRow = {
  sha256: string; recipe_revision_id: string; cohort_id: string; cohort_revision: number; architecture: Architecture;
  purpose: 'bootstrap' | 'owned'; manifest_json: string; object_count: number; package_count: number; transfer_bytes: number;
  status: 'preparing' | 'ready'; created_by: string; created_at: number; reason: string;
};

export async function getInputLock(db: D1Database, digest: string): Promise<InputLockRow> {
  if (!INPUT_HASH.test(digest)) throw new PolicyError(400, 'Invalid input lock checksum.');
  const row = await db.prepare('SELECT * FROM input_locks WHERE sha256=?').bind(digest).first<InputLockRow>();

  if (!row) throw new PolicyError(404, 'Input lock not found.');

  return row;
}

export async function inspectRetainedLock(env: InputEnv, ref: InputObject) {
  try {
    const manifest = parseFrozenManifest(await inputJson(env, ref, 128 * 1024));
    const pages = await inputDocuments(env, manifest.environments.flatMap((env) => env.chunks.map((ref) => ref.sha256)), 1024 * 1024, MAX_INPUT_METADATA);

    const inspection = await inspectFrozenInputs(ref, manifest, async (page) => {
      const document = pages.get(page.sha256)!;

      if (document.ref.size !== page.size) throw new Error('Frozen package page size differs from lock');

      return document.value;
    });

    const references = new Map(inspection.objects.map((ref) => [ref.sha256, ref]));
    const origins = new Map<string, Record<string, any>>();

    function retain(ref: InputObject) {
      const previous = references.get(ref.sha256);

      if (previous && previous.size !== ref.size) throw new Error('Origin evidence has conflicting object sizes');
      references.set(ref.sha256, ref);
    }

    // Origin records are retained for independent audit, although workers only download execution inputs.
    for (const [digest, document] of await inputDocuments(env, inspection.origins, 1024 * 1024, MAX_INPUT_METADATA)) {
      retain(document.ref);
      const evidence = document.value as Record<string, any>;

      if (!evidence || typeof evidence !== 'object' || Array.isArray(evidence)) throw new Error('Input origin must be a retained JSON record');
      origins.set(digest, evidence);

      if (evidence.kind === 'external-bootstrap-capture') {
        if (Object.keys(evidence).sort().join(',') !== 'architecture,databases,helperImage,kind,packages,pacmanConfig,schemaVersion,targets' ||
            evidence.schemaVersion !== 1 || evidence.architecture !== inspection.manifest.architecture || evidence.helperImage !== inspection.manifest.helperImage ||
            !Array.isArray(evidence.databases) || !evidence.databases.length || evidence.databases.length > 32 ||
            !Array.isArray(evidence.targets) || !evidence.targets.length || evidence.targets.length > 4096 || evidence.targets.some((target: unknown) => typeof target !== 'string' || !target || target.length > 256) ||
            !Array.isArray(evidence.packages) || !evidence.packages.length || evidence.packages.length > 4096) throw new Error('Bootstrap capture evidence is incomplete');
        retain(parseInputObject(evidence.pacmanConfig, 64 * 1024));

        for (const database of evidence.databases) {
          if (!database || Object.keys(database).sort().join(',') !== 'name,object' || typeof database.name !== 'string' || !/^[a-z0-9._-]{1,128}\.db$/.test(database.name)) throw new Error('Invalid captured repository database');
          retain(parseInputObject(database.object, 32 * 1024 * 1024));
        }

        for (const record of evidence.packages) {
          if (!record || Object.keys(record).sort().join(',') !== 'architecture,filename,name,repository,sha256,size,url,version' ||
              typeof record.repository !== 'string' || !/^[a-z0-9._-]{1,128}$/.test(record.repository) ||
              !evidence.databases.some((database: { name: string }) => database.name === `${record.repository}.db`)) throw new Error('Invalid captured package source');
          publicSourceURL(record.url);
        }
      } else if (evidence.kind === 'native-build') {
        if (Object.keys(evidence).sort().join(',') !== 'attempt,buildId,fingerprint,inputLock,kind,publicKey,schemaVersion,signature,statement' || evidence.schemaVersion !== 1) throw new Error('Invalid native origin record');

        for (const field of ['statement', 'signature', 'publicKey']) retain(parseInputObject(evidence[field], 1024 * 1024));
        retain(parseInputObject(evidence.inputLock, 128 * 1024));
      } else {
        throw new Error('Unknown input origin record');
      }
    }

    const refs = [...references.values()];

    for (let offset = 0; offset < refs.length; offset += 256) {
      const chunk = refs.slice(offset, offset + 256);
      const rows = await query<InputObjectRow>(env.DB, 'SELECT * FROM input_objects WHERE sha256 IN (SELECT value FROM json_each(?))', JSON.stringify(chunk.map((ref) => ref.sha256)));

      if (rows.length !== chunk.length || rows.some((row) => row.size !== references.get(row.sha256)!.size)) throw new Error('Frozen closure has missing objects or conflicting sizes');
    }

    const packages = new Map<string, FrozenPackage>();

    for (const environment of inspection.environments) for (const pkg of environment.packages) {
      const key = `${pkg.package.sha256}:${pkg.originEvidence}`;
      const existing = packages.get(key);

      if (existing && canonicalJson(existing) !== canonicalJson(pkg)) throw new Error('One package checksum has conflicting frozen metadata');
      packages.set(key, pkg);
    }

    const owned = [...packages.values()].filter((pkg) => pkg.origin === 'owned-build');
    const eligible = new Map<string, string>();

    for (let offset = 0; offset < owned.length; offset += 32) {
      const chunk = owned.slice(offset, offset + 32);

      const rows = await query<{ package_sha256: string; origin_evidence: string; package_json: string }>(env.DB,
        `SELECT package_sha256,origin_evidence,package_json FROM eligible_owned_inputs WHERE ${chunk.map(() => '(package_sha256=? AND origin_evidence=?)').join(' OR ')}`,
        ...chunk.flatMap((pkg) => [pkg.package.sha256, pkg.originEvidence]));

      for (const row of rows) eligible.set(`${row.package_sha256}:${row.origin_evidence}`, row.package_json);
    }

    for (const pkg of packages.values()) {
      if (pkg.origin === 'external-bootstrap') {
        const origin = origins.get(pkg.originEvidence)!;

        const matches = origin.kind === 'external-bootstrap-capture' ? origin.packages.filter((record: Record<string, unknown>) =>
          record.name === pkg.name && record.version === pkg.version && record.architecture === pkg.architecture && record.filename === pkg.filename &&
          record.sha256 === pkg.package.sha256 && record.size === pkg.package.size) : [];

        if (matches.length !== 1) throw new Error(`Package differs from captured bootstrap source: ${pkg.name}`);
        continue;
      }

      if (eligible.get(`${pkg.package.sha256}:${pkg.originEvidence}`) !== canonicalJson(pkg)) throw new Error(`Owned input lacks verified native origin: ${pkg.name}`);
    }

    return { ...inspection, objects: refs, packages: [...packages.values()] };
  } catch (cause) {
    if (cause instanceof PolicyError) throw cause;
    throw new PolicyError(409, cause instanceof Error ? cause.message : 'Invalid retained input lock.');
  }
}

async function lockScope(env: InputEnv, revisionId: string, manifest: FrozenManifest) {
  const revision = await env.DB.prepare('SELECT * FROM revisions WHERE id=?').bind(revisionId).first<Revision>();

  if (!revision || revision.surface !== 'binary' || revision.recipe_sha256 !== manifest.recipeSha256 || revision.source_date_epoch !== manifest.sourceDateEpoch ||
      revisionImage(revision, manifest.architecture) !== manifest.helperImage) throw new PolicyError(409, 'Input lock differs from recipe revision or reviewed helper image.');
  const contract = await cohortOutputContract(env.DB, { ...revision, pkgrel: revision.pkgrel ?? 1 }, manifest.architecture);

  if (!contract || contract.cohort.manifestSha256 !== manifest.cohortSha256 || contract.runtimeGroups.length + 1 !== manifest.environments.length) {
    throw new PolicyError(409, 'Input lock differs from current cohort or installation matrix.');
  }

  return contract;
}

export async function proposeInputLock(env: InputEnv, actor: Actor | null, revisionId: string, ref: InputObject, reason: string) {
  const human = await inputAuthority(env.DB, actor); const clean = reviewReason(reason);
  const inspected = await inspectRetainedLock(env, ref);
  const contract = await lockScope(env, revisionId, inspected.manifest);
  const existing = await env.DB.prepare('SELECT * FROM input_locks WHERE sha256=?').bind(ref.sha256).first<InputLockRow>();

  if (existing && (existing.recipe_revision_id !== revisionId || existing.cohort_id !== contract.cohort.id || existing.cohort_revision !== contract.cohort.revision)) {
    throw new PolicyError(409, 'Lock already belongs to a different recipe revision or cohort.');
  }

  if (existing?.status === 'ready') return existing;

  if (!existing) await env.DB.prepare(`INSERT INTO input_locks(sha256,recipe_revision_id,cohort_id,cohort_revision,architecture,purpose,manifest_json,
    object_count,package_count,transfer_bytes,status,created_by,created_at,reason) VALUES(?,?,?,?,?,?,?,?,?,?,'preparing',?,?,?)`)
    .bind(ref.sha256, revisionId, contract.cohort.id, contract.cohort.revision, inspected.manifest.architecture, inspected.manifest.purpose,
      canonicalJson(inspected.manifest), inspected.objects.length, inspected.packages.length, inspected.transferBytes, human.id, now(), clean).run();
  const statements: D1PreparedStatement[] = [];

  for (let offset = 0; offset < inspected.objects.length; offset += 256) statements.push(env.DB.prepare(`INSERT OR IGNORE INTO input_lock_objects(lock_sha256,object_sha256)
    SELECT ?,value FROM json_each(?)`).bind(ref.sha256, JSON.stringify(inspected.objects.slice(offset, offset + 256).map((object) => object.sha256))));

  for (let offset = 0; offset < inspected.packages.length; offset += 256) statements.push(env.DB.prepare(`INSERT OR IGNORE INTO input_lock_packages(lock_sha256,package_sha256,origin,origin_evidence,package_json)
    SELECT ?,json_extract(value,'$.package.sha256'),json_extract(value,'$.origin'),json_extract(value,'$.originEvidence'),json(value) FROM json_each(?)`)
    .bind(ref.sha256, canonicalJson(inspected.packages.slice(offset, offset + 256))));

  for (let offset = 0; offset < statements.length; offset += 64) await env.DB.batch(statements.slice(offset, offset + 64));
  await lockScope(env, revisionId, inspected.manifest);
  await inputAuthority(env.DB, actor);
  await env.DB.batch([
    env.DB.prepare("UPDATE input_locks SET status='ready' WHERE sha256=? AND status='preparing'").bind(ref.sha256),
    audit(env.DB, human.id, 'input.lock_proposed', ref.sha256, { revisionId, purpose: inspected.manifest.purpose, packages: inspected.packages.length, reason: clean }),
  ]);

  return getInputLock(env.DB, ref.sha256);
}

export async function reviewInputLock(env: InputEnv, actor: Actor | null, digest: string, kind: 'area' | 'security', reason: string) {
  const human = await inputAuthority(env.DB, actor); const clean = reviewReason(reason);

  if (!['area', 'security'].includes(kind)) throw new PolicyError(400, 'Choose system or security review.');

  if (kind === 'security') requireSecurity(human);
  const row = await getInputLock(env.DB, digest);

  if (row.status !== 'ready') throw new PolicyError(409, 'Input lock must finish retention before review.');
  const ref = await inputObject(env.DB, digest);
  await inspectRetainedLock(env, { sha256: digest, size: ref.size });
  await lockScope(env, row.recipe_revision_id, JSON.parse(row.manifest_json));
  const reviews = await query<{ kind: string; actor: string }>(env.DB, 'SELECT kind,actor FROM input_lock_reviews WHERE lock_sha256=? AND revoked_at IS NULL', digest);

  if (reviews.some((review) => review.kind === kind && review.actor === human.id)) return;

  if (reviews.some((review) => review.kind === kind || review.actor === human.id)) throw new PolicyError(409, 'System and security reviews require two independent people.');
  await env.DB.batch([
    env.DB.prepare('INSERT INTO input_lock_reviews(id,lock_sha256,kind,actor,reason,created_at) VALUES(?,?,?,?,?,?)').bind(id(), digest, kind, human.id, clean, now()),
    audit(env.DB, human.id, 'input.lock_reviewed', digest, { kind, reason: clean, purpose: row.purpose }),
  ]);
}

export async function revokeInputReview(env: InputEnv, actor: Actor | null, digest: string, reviewId: string, reason: string) {
  const human = await inputAuthority(env.DB, actor); const clean = reviewReason(reason);

  const review = await env.DB.prepare('SELECT actor FROM input_lock_reviews WHERE id=? AND lock_sha256=? AND revoked_at IS NULL')
    .bind(reviewId, digest).first<{ actor: string }>();

  if (!review) throw new PolicyError(409, 'Active input review not found.');

  if (human.id !== review.actor) requireSecurity(human);
  await env.DB.batch([
    env.DB.prepare('UPDATE input_lock_reviews SET revoked_at=?,revoke_reason=? WHERE id=? AND lock_sha256=? AND revoked_at IS NULL').bind(now(), clean, reviewId, digest),
    fenceFrozenLeases(env.DB),
    audit(env.DB, human.id, 'input.review_revoked', digest, { reviewId, reason: clean }),
  ]);
}

export function fenceFrozenLeases(db: D1Database) {
  return db.prepare(`UPDATE builds SET status='queued',worker_id=NULL,lease_token=NULL,lease_expires_at=NULL,input_lock_sha256=NULL,
    artifact_key=NULL,artifact_sha256=NULL,artifact_size=NULL,artifact_filename=NULL,installed_size=NULL,dependency_plan_json=NULL,
    provenance=NULL,provenance_signature=NULL,smoke_passed=0,error='Frozen input authority revoked'
    WHERE status='leased' AND input_lock_sha256 IS NOT NULL AND NOT EXISTS(SELECT 1 FROM current_input_locks l WHERE l.sha256=builds.input_lock_sha256)`);
}

export async function selectInputLock(env: InputEnv, actor: Actor | null, digest: string, reason: string) {
  const human = await inputAuthority(env.DB, actor); const clean = reviewReason(reason);
  const row = await requireCurrentInputLock(env, digest);

  try {
    await env.DB.batch([
      env.DB.prepare(`INSERT INTO build_input_selections(recipe_revision_id,architecture,cohort_id,cohort_revision,lock_sha256,selected_by,selected_at)
        VALUES(?,?,?,?,?,?,?) ON CONFLICT(recipe_revision_id,architecture,cohort_id,cohort_revision)
        DO UPDATE SET lock_sha256=excluded.lock_sha256,selected_by=excluded.selected_by,selected_at=excluded.selected_at`)
        .bind(row.recipe_revision_id, row.architecture, row.cohort_id, row.cohort_revision, row.sha256, human.id, now()),
      env.DB.prepare(`UPDATE builds SET status='queued',worker_id=NULL,lease_token=NULL,lease_expires_at=NULL,input_lock_sha256=NULL,
        artifact_key=NULL,artifact_sha256=NULL,artifact_size=NULL,artifact_filename=NULL,installed_size=NULL,dependency_plan_json=NULL,
        provenance=NULL,provenance_signature=NULL,smoke_passed=0,error=NULL,started_at=NULL,finished_at=NULL
        WHERE revision_id=? AND architecture=? AND status IN ('succeeded','failed') AND input_lock_sha256 IS NOT ?`)
        .bind(row.recipe_revision_id, row.architecture, row.sha256),
      env.DB.prepare(`UPDATE requests SET status=CASE WHEN EXISTS(SELECT 1 FROM builds b WHERE b.revision_id=? AND b.status='leased') THEN 'building' ELSE 'queued' END,
        updated_at=? WHERE id=(SELECT request_id FROM revisions WHERE id=?) AND status IN ('queued','building','built','failed')
        AND EXISTS(SELECT 1 FROM builds WHERE revision_id=? AND architecture=? AND status='queued')`)
        .bind(row.recipe_revision_id, now(), row.recipe_revision_id, row.recipe_revision_id, row.architecture),
      audit(env.DB, human.id, 'input.lock_selected', digest, { reason: clean }),
    ]);
  } catch (cause) {
    if (cause instanceof Error && /input selection/.test(cause.message)) throw new PolicyError(409, 'Lock reviews changed, build still holds a lease, or cohort has left its build phase.');
    throw cause;
  }
}

export async function requireCurrentInputLock(env: InputEnv, digest: string): Promise<InputLockRow> {
  const row = await env.DB.prepare('SELECT * FROM current_input_locks WHERE sha256=?').bind(digest).first<InputLockRow>();

  if (!row) throw new PolicyError(409, 'Frozen input lock, recipe, cohort, human reviews or input ancestry are no longer current.');
  const object = await inputObject(env.DB, digest);
  const inspection = await inspectRetainedLock(env, { sha256: digest, size: object.size });

  if (canonicalJson(inspection.manifest) !== row.manifest_json || inspection.packages.length !== row.package_count || inspection.objects.length !== row.object_count ||
      inspection.transferBytes !== row.transfer_bytes) throw new PolicyError(409, 'Retained input index differs from sealed lock.');
  await lockScope(env, row.recipe_revision_id, inspection.manifest);

  return row;
}

export async function selectedInputLock(env: InputEnv, revisionId: string, architecture: Architecture, contract: OutputContract): Promise<InputObject | null> {
  const selected = await env.DB.prepare('SELECT lock_sha256 FROM build_input_selections WHERE recipe_revision_id=? AND architecture=? AND cohort_id=? AND cohort_revision=?')
    .bind(revisionId, architecture, contract.cohort.id, contract.cohort.revision).first<{ lock_sha256: string }>();

  if (!selected) return null;
  await requireCurrentInputLock(env, selected.lock_sha256);
  const row = await inputObject(env.DB, selected.lock_sha256);

  return { sha256: row.sha256, size: row.size };
}
