import type { Env } from './env';
import type { Actor, Release, Architecture } from '../model';
import { PolicyError, requireMaintainer } from './policy';
import { audit, id, now, query, sha256 } from './db';
import {
  fail,
  safeId,
  SHA256,
  packageKey,
  copyVerifiedObject,
  recipeKey,
  metadataKey,
  immutableText,
  verifyR2Object,
  verifySignatureObject,
  publicOrigin,
  segment,
  immutableBytes,
} from './release-storage';
import {
  joinedBuild,
  assertReviewed,
  assertAttestation,
  packageVersion,
  signingRequest,
  hasPrivateSource,
  hasPrivateSourceReference,
  assertCurrentApprovals,
} from './release-evidence';
import {
  PACKAGE_FILENAME,
  currentDev,
  type ReleaseRow,
  latestPerPackage,
  binaryReleases,
  snapshot,
  currentStable,
  finalStable,
  assertDependencyGraph,
  releaseRows,
  type RepositorySnapshot,
} from './repository';

const DEFAULT_QUARANTINE_HOURS = 48;

function cleanReason(reason: string): string {
  if (typeof reason !== 'string') fail(400, 'Provide a release reason.');
  const value = reason.replace(/[\u0000\r\n]/g, ' ').trim();
  if (!value || value.length > 2_000) fail(400, 'Provide a reason, up to 2,000 characters.');
  return value;
}

async function recordDenied(env: Env, actor: Actor | null, action: string, target: string, cause: unknown) {
  const detail = { reason: cause instanceof PolicyError ? cause.message : 'request rejected' };
  try {
    await audit(env.DB, actor?.id ?? 'anonymous', action, target, detail).run();
  } catch {
    throw new PolicyError(503, 'Denied action could not be recorded.');
  }
}

async function loadReleaseByBuild(env: Env, buildId: string): Promise<Release | null> {
  return env.DB.prepare('SELECT * FROM releases WHERE build_id=?').bind(buildId).first<Release>();
}

async function publishBuildInner(env: Env, actor: Actor, buildId: string): Promise<Release> {
  const existing = await loadReleaseByBuild(env, buildId);
  if (existing) return existing;
  const build = await joinedBuild(env, safeId(buildId, 'build ID'));
  if (build.build_status !== 'succeeded' || build.smoke_passed !== 1) fail(409, 'Only a successful build with passing smoke tests can enter quarantine.');
  if (build.surface === 'binary' && !(env.SIGNER || env.SIGNER_URL)) fail(503, 'Package signing service is not configured; binary publication is blocked.');
  if (!['queued', 'building', 'built'].includes(build.request_status)) fail(409, 'The package request is no longer publishable.');
  await assertReviewed(build, env);
  await assertAttestation(build, env);
  const releaseId = id();
  const publicationBatchId = id();
  const architecture = build.build_architecture;
  let artifact: { key: string; sha256: string; size: number; filename: string } | null = null;
  let signatureKey: string | null = null;
  let releaseVersion: string;
  if (build.surface === 'binary') {
    if (!build.artifact_key || !build.artifact_sha256 || !SHA256.test(build.artifact_sha256) || !build.artifact_size || !build.artifact_filename || !PACKAGE_FILENAME.test(build.artifact_filename)) {
      fail(409, 'A valid immutable package artifact is required for Surface A.');
    }
    releaseVersion = packageVersion(build, build.artifact_filename);
    const publishedKey = packageKey(architecture, build.artifact_filename);
    await copyVerifiedObject(env, build.artifact_key, publishedKey, build.artifact_sha256, build.artifact_size, 'application/octet-stream');
    artifact = { key: publishedKey, sha256: build.artifact_sha256, size: build.artifact_size, filename: build.artifact_filename };
    const signed = await signingRequest(env, {
      buildId: build.build_id, revisionId: build.revision_id, manifestSha256: build.manifest_sha256,
      objectKey: publishedKey, objectKind: 'package', artifactSha256: build.artifact_sha256, artifactSize: build.artifact_size, artifactFilename: build.artifact_filename,
    });
    signatureKey = signed.signatureKey;
  } else if (build.artifact_key || build.artifact_sha256 || build.artifact_size !== null || build.artifact_filename) {
    fail(409, 'Surface B builds must never publish or retain a binary artifact.');
  } else {
    releaseVersion = packageVersion(build, null);
  }

  const releaseRecipe = build.surface === 'recipe' ? build.public_recipe ?? build.recipe : build.recipe;
  if (build.surface === 'recipe' && hasPrivateSource(env, build.sources_json) && !build.public_recipe) {
    fail(409, 'A public recipe is required when reviewed sources use private sealed storage.');
  }
  if (build.surface === 'recipe' && hasPrivateSourceReference(env, releaseRecipe)) {
    fail(409, 'Published recipe cannot reference private sealed storage.');
  }

  const publishedAt = now();
  const recipe = recipeKey(build.request_name, releaseVersion, architecture);
  const sbom = metadataKey(releaseId, 'sbom');
  const provenance = metadataKey(releaseId, 'provenance');
  await immutableText(env, recipe, releaseRecipe, 'text/plain; charset=utf-8');
  await immutableText(env, sbom, build.sbom_json, 'application/json');
  await immutableText(env, provenance, build.provenance!, 'application/json');
  const release: Release = {
    id: releaseId, build_id: build.build_id, name: build.request_name, version: releaseVersion,
    architecture, surface: build.surface, channel: 'dev', artifact_key: artifact?.key ?? null,
    signature_key: signatureKey, recipe_key: recipe, sbom_key: sbom, provenance_key: provenance,
    published_at: publishedAt, stable_at: null, batch_id: null, previous_release_id: null,
  };
  const devCurrent = await currentDev(env);
  const candidate: ReleaseRow = {
    ...release, revision_id: build.revision_id,
    manifest_sha256: build.manifest_sha256, recipe_sha256: build.recipe_sha256,
    source_date_epoch: build.source_date_epoch, artifact_sha256: artifact?.sha256 ?? null,
    artifact_size: artifact?.size ?? null, artifact_filename: artifact?.filename ?? null,
    installed_size: build.installed_size, license: build.license, recipe: build.recipe,
    description: build.description, explanation: build.explanation,
    dependencies_json: build.dependencies_json, upstream_url: build.upstream_url, provenance: build.provenance,
  };
  const devFinal = latestPerPackage([...devCurrent, candidate]);
  const context = binaryReleases([candidate, ...devCurrent]).find((row) => row.architecture === architecture);
  const devSnapshot = context ? await snapshot(env, devFinal, architecture, context, publicationBatchId, 'dev') : null;
  const statements: D1PreparedStatement[] = [
    env.DB.prepare(`INSERT INTO releases
      (id,build_id,name,version,architecture,surface,channel,artifact_key,signature_key,recipe_key,sbom_key,provenance_key,published_at)
      VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`).bind(
      release.id, release.build_id, release.name, release.version, release.architecture, release.surface,
      release.channel, release.artifact_key, release.signature_key, release.recipe_key, release.sbom_key,
      release.provenance_key, release.published_at,
    ),
    env.DB.prepare(`UPDATE requests SET status=CASE
        WHEN EXISTS (SELECT 1 FROM builds active WHERE active.revision_id=? AND active.status='leased') THEN 'building'
        WHEN EXISTS (SELECT 1 FROM builds queued WHERE queued.revision_id=? AND queued.status='queued') THEN 'queued'
        WHEN EXISTS (SELECT 1 FROM builds failed WHERE failed.revision_id=? AND failed.status='failed') THEN 'failed'
        WHEN EXISTS (
          SELECT 1 FROM json_each((SELECT architectures_json FROM revisions WHERE id=?)) architecture
          WHERE NOT EXISTS (
            SELECT 1 FROM builds complete JOIN releases published ON published.build_id=complete.id
            WHERE complete.revision_id=? AND complete.architecture=architecture.value AND complete.status='succeeded'
          )
        ) THEN 'building'
        ELSE 'built'
      END,updated_at=?
      WHERE id=? AND status IN ('queued','building','built','failed')
        AND ?=(SELECT latest.id FROM revisions latest WHERE latest.request_id=requests.id ORDER BY latest.created_at DESC,latest.rowid DESC LIMIT 1)`)
      .bind(build.revision_id, build.revision_id, build.revision_id, build.revision_id, build.revision_id, publishedAt, build.request_id, build.revision_id),
    env.DB.prepare('INSERT INTO distribution_assertions(expected,actual) SELECT 1,changes()'),
  ];
  if (devSnapshot) {
    statements.push(env.DB.prepare("UPDATE repository_snapshots SET active=0 WHERE channel='dev' AND architecture=? AND active=1").bind(architecture));
    statements.push(env.DB.prepare(`INSERT INTO repository_snapshots
      (id,architecture,channel,db_key,db_signature_key,batch_id,created_at,active) VALUES(?,?,?,?,?,?,?,1)`)
      .bind(devSnapshot.id, devSnapshot.architecture, devSnapshot.channel, devSnapshot.dbKey, devSnapshot.dbSignatureKey, devSnapshot.batchId, now()));
    statements.push(env.DB.prepare("INSERT INTO distribution_assertions(expected,actual) SELECT 1,COUNT(*) FROM repository_snapshots WHERE id=? AND channel='dev' AND architecture=? AND active=1")
      .bind(devSnapshot.id, architecture));
    for (const row of devCurrent) {
      if (row.name !== release.name || row.architecture !== release.architecture) {
        statements.push(env.DB.prepare("INSERT INTO distribution_assertions(expected,actual) SELECT 1,COUNT(*) FROM releases WHERE id=? AND channel='dev'").bind(row.id));
      }
    }
    const existingForPackage = devCurrent.filter((row) => row.name === release.name && row.architecture === release.architecture).length;
    statements.push(env.DB.prepare("INSERT INTO distribution_assertions(expected,actual) SELECT ?,COUNT(*) FROM releases WHERE name=? AND architecture=? AND channel='dev'")
      .bind(existingForPackage + 1, release.name, release.architecture));
    statements.push(env.DB.prepare("INSERT INTO distribution_assertions(expected,actual) SELECT ?,COUNT(*) FROM releases WHERE channel='dev'")
      .bind(devCurrent.length + 1));
  }
  statements.push(env.DB.prepare('DELETE FROM distribution_assertions'));
  statements.push(audit(env.DB, actor.id, 'release.published_dev', release.id, {
    buildId: build.build_id, surface: build.surface, artifactSha256: artifact?.sha256 ?? null,
    manifestSha256: build.manifest_sha256, channel: 'dev', devSnapshot: devSnapshot ? { id: devSnapshot.id, sha256: devSnapshot.dbSha256 } : null,
  }));
  await env.DB.batch(statements);
  return release;
}

export async function publishBuild(env: Env, actor: Actor | null, buildId: string): Promise<Release> {
  try {
    return await publishBuildInner(env, requireMaintainer(actor), buildId);
  } catch (cause) {
    if (cause instanceof PolicyError) await recordDenied(env, actor, 'release.publish_denied', buildId, cause);
    throw cause;
  }
}

async function promoteBatchInner(env: Env, actor: Actor, releaseIds: string[], reason: string) {
  const clean = cleanReason(reason);
  const ids = [...new Set(releaseIds.map((value) => safeId(value)))];
  if (!ids.length || ids.length > 100) fail(400, 'Select between one and 100 releases.');
  const placeholders = ids.map(() => '?').join(',');
  const candidateRows = await query<ReleaseRow & { channel: string; surface: string; smoke_passed: number; build_status: string; dependencies_json: string; request_status: string; latest_revision_id: string | null }>(
    env.DB, `SELECT r.*,
      b.status AS build_status, b.smoke_passed, r.artifact_key, r.signature_key, b.artifact_sha256, b.artifact_size, b.installed_size,
      b.artifact_filename, b.provenance, b.revision_id, v.manifest_sha256, v.recipe, v.description, v.recipe_sha256, v.source_date_epoch, v.license, v.explanation, v.dependencies_json, q.upstream_url,
      q.status AS request_status,
      (SELECT latest.id FROM revisions latest WHERE latest.request_id=v.request_id ORDER BY latest.created_at DESC, latest.rowid DESC LIMIT 1) AS latest_revision_id,
      r.published_at
      FROM releases r JOIN builds b ON b.id=r.build_id JOIN revisions v ON v.id=b.revision_id JOIN requests q ON q.id=v.request_id
      WHERE r.id IN (${placeholders})`, ...ids,
  );
  if (candidateRows.length !== ids.length) fail(404, 'One or more releases were not found.');
  const seen = new Set<string>();
  for (const row of candidateRows) {
    if (row.channel !== 'dev') fail(409, `Release ${row.id} is not in quarantine.`);
    if (!['queued', 'building', 'built'].includes(row.request_status) || row.latest_revision_id !== row.revision_id) fail(409, `Release ${row.id} is no longer the current reviewed revision.`);
    await assertCurrentApprovals(env, row.revision_id, row.manifest_sha256);
    if (row.surface === 'recipe') {
      const evidence = await joinedBuild(env, row.build_id);
      if (evidence.revision_id !== row.revision_id) fail(409, `Release ${row.id} build evidence changed.`);
      await assertAttestation(evidence, env);
    }
    const key = `${row.name}:${row.architecture}`;
    if (seen.has(key)) fail(409, `Batch contains multiple versions of ${row.name} for ${row.architecture}.`);
    seen.add(key);
    if (row.build_status !== 'succeeded' || row.smoke_passed !== 1) fail(409, `Release ${row.id} has not passed build and smoke gates.`);
    const quarantineHours = Number((env as Env & { QUARANTINE_HOURS?: string }).QUARANTINE_HOURS ?? DEFAULT_QUARANTINE_HOURS);
    const hours = Number.isFinite(quarantineHours) && quarantineHours >= 0 ? quarantineHours : DEFAULT_QUARANTINE_HOURS;
    if (row.published_at + Math.floor(hours * 3_600) > now()) fail(409, `Release ${row.id} is still in quarantine.`);
    const crash = await env.DB.prepare('SELECT COUNT(*) AS count FROM crash_reports WHERE release_id=? AND resolved_at IS NULL').bind(row.id).first<{ count: number }>();
    if ((crash?.count ?? 0) > 0) fail(409, `Release ${row.id} has unresolved crash reports.`);
    if (row.surface === 'binary' && (!row.artifact_key || !row.signature_key)) fail(409, `Release ${row.id} has no package signature.`);
    if (row.surface === 'recipe' && (row.artifact_key || row.signature_key)) fail(409, `Surface B release ${row.id} contains a binary artifact.`);
  }
  const current = await currentStable(env);
  const batchId = id();
  const candidates: ReleaseRow[] = candidateRows;
  const final = finalStable(current, candidates);
  assertDependencyGraph(candidates, current, final);
  const candidateKeys = new Set(candidates.map((row) => `${row.name}:${row.architecture}`));
  const architectures = [...new Set([
    ...binaryReleases(candidates).map((row) => row.architecture),
    ...binaryReleases(current).filter((row) => candidateKeys.has(`${row.name}:${row.architecture}`)).map((row) => row.architecture),
  ])];
  const snapshots = [];
  for (const architecture of architectures) {
    const context = binaryReleases([...final, ...current, ...candidates]).find((row) => row.architecture === architecture);
    if (!context) fail(409, `No signed repository context for ${architecture}.`);
    snapshots.push(await snapshot(env, final, architecture, context, batchId));
  }
  const devCurrent = await currentDev(env);
  const devFinal = latestPerPackage(devCurrent.filter((row) => !ids.includes(row.id)));
  const devArchitectures = [...new Set([
    ...binaryReleases(candidates).map((row) => row.architecture),
    ...binaryReleases(devCurrent).filter((row) => candidateKeys.has(`${row.name}:${row.architecture}`)).map((row) => row.architecture),
    ...binaryReleases(current).filter((row) => candidateKeys.has(`${row.name}:${row.architecture}`)).map((row) => row.architecture),
  ])];
  const devSnapshots = [];
  for (const architecture of devArchitectures) {
    const context = binaryReleases([...devFinal, ...candidates, ...devCurrent, ...current]).find((row) => row.architecture === architecture);
    if (!context) fail(409, `No signed development repository context for ${architecture}.`);
    devSnapshots.push(await snapshot(env, devFinal, architecture, context, batchId, 'dev'));
  }
  const statements: D1PreparedStatement[] = [];
  for (const row of candidateRows) {
    const predecessors = current.filter((item) => item.name === row.name && item.architecture === row.architecture);
    const previous = latestPerPackage(predecessors)[0];
    for (const predecessor of predecessors) {
      statements.push(env.DB.prepare("UPDATE releases SET channel='withdrawn',batch_id=? WHERE id=? AND channel='stable'").bind(batchId, predecessor.id));
      statements.push(env.DB.prepare('INSERT INTO distribution_assertions(expected,actual) SELECT 1,changes()'));
    }
    statements.push(env.DB.prepare(`UPDATE releases SET channel='stable',stable_at=?,batch_id=?,previous_release_id=?
      WHERE id=? AND channel='dev'
        AND NOT EXISTS (SELECT 1 FROM crash_reports WHERE release_id=releases.id AND resolved_at IS NULL)
        AND EXISTS (
          SELECT 1 FROM builds b JOIN revisions v ON v.id=b.revision_id JOIN requests q ON q.id=v.request_id
          WHERE b.id=releases.build_id AND b.status='succeeded' AND b.smoke_passed=1
            AND q.status IN ('queued','building','built')
            AND v.id=(SELECT latest.id FROM revisions latest WHERE latest.request_id=q.id ORDER BY latest.created_at DESC,latest.rowid DESC LIMIT 1)
            AND EXISTS (SELECT 1 FROM approvals a WHERE a.revision_id=v.id AND a.kind='area' AND a.manifest_sha256=v.manifest_sha256 AND a.revoked_at IS NULL)
            AND EXISTS (SELECT 1 FROM approvals a WHERE a.revision_id=v.id AND a.kind='security' AND a.manifest_sha256=v.manifest_sha256 AND a.revoked_at IS NULL)
        )`)
      .bind(now(), batchId, previous?.id ?? null, row.id));
    statements.push(env.DB.prepare('INSERT INTO distribution_assertions(expected,actual) SELECT 1,changes()'));
  }
  for (const item of snapshots) {
    statements.push(env.DB.prepare("UPDATE repository_snapshots SET active=0 WHERE channel='stable' AND architecture=? AND active=1").bind(item.architecture));
    statements.push(env.DB.prepare(`INSERT INTO repository_snapshots
      (id,architecture,channel,db_key,db_signature_key,batch_id,created_at,active) VALUES(?,?,?,?,?,?,?,1)`)
      .bind(item.id, item.architecture, item.channel, item.dbKey, item.dbSignatureKey, item.batchId, now()));
  }
  for (const item of devSnapshots) {
    statements.push(env.DB.prepare("UPDATE repository_snapshots SET active=0 WHERE channel='dev' AND architecture=? AND active=1").bind(item.architecture));
    statements.push(env.DB.prepare(`INSERT INTO repository_snapshots
      (id,architecture,channel,db_key,db_signature_key,batch_id,created_at,active) VALUES(?,?,?,?,?,?,?,1)`)
      .bind(item.id, item.architecture, item.channel, item.dbKey, item.dbSignatureKey, item.batchId, now()));
    statements.push(env.DB.prepare("INSERT INTO distribution_assertions(expected,actual) SELECT 1,COUNT(*) FROM repository_snapshots WHERE id=? AND channel='dev' AND architecture=? AND active=1")
      .bind(item.id, item.architecture));
  }
  statements.push(env.DB.prepare('INSERT INTO promotion_batches(id,actor,release_ids_json,reason,created_at) VALUES(?,?,?,?,?)')
    .bind(batchId, actor.id, JSON.stringify(ids), clean, now()));
  statements.push(env.DB.prepare(`INSERT INTO distribution_assertions(expected,actual)
    SELECT ?,COUNT(*) FROM releases WHERE id IN (${placeholders}) AND channel='stable' AND batch_id=?`)
    .bind(candidateRows.length, ...ids, batchId));
  for (const row of current) {
    if (!candidateKeys.has(`${row.name}:${row.architecture}`)) {
      statements.push(env.DB.prepare("INSERT INTO distribution_assertions(expected,actual) SELECT 1,COUNT(*) FROM releases WHERE id=? AND channel='stable'").bind(row.id));
    }
  }
  for (const row of candidates) {
    statements.push(env.DB.prepare("INSERT INTO distribution_assertions(expected,actual) SELECT 1,COUNT(*) FROM releases WHERE id=? AND channel='stable' AND batch_id=?")
      .bind(row.id, batchId));
  }
  for (const row of candidates) {
    statements.push(env.DB.prepare("INSERT INTO distribution_assertions(expected,actual) SELECT 0,COUNT(*) FROM releases WHERE id=? AND channel='dev'").bind(row.id));
  }
  for (const row of devCurrent) {
    if (!ids.includes(row.id)) {
      statements.push(env.DB.prepare("INSERT INTO distribution_assertions(expected,actual) SELECT 1,COUNT(*) FROM releases WHERE id=? AND channel='dev'").bind(row.id));
    }
  }
  statements.push(env.DB.prepare("INSERT INTO distribution_assertions(expected,actual) SELECT ?,COUNT(*) FROM releases WHERE channel='stable'").bind(final.length));
  statements.push(env.DB.prepare("INSERT INTO distribution_assertions(expected,actual) SELECT ?,COUNT(*) FROM releases WHERE channel='dev'").bind(devCurrent.length - candidates.length));
  statements.push(env.DB.prepare('DELETE FROM distribution_assertions'));
  statements.push(audit(env.DB, actor.id, 'release.batch_promoted', batchId, {
    releaseIds: ids, reason: clean,
    snapshots: snapshots.map((item) => ({ id: item.id, sha256: item.dbSha256 })),
    devSnapshots: devSnapshots.map((item) => ({ id: item.id, sha256: item.dbSha256 })),
  }));
  const result = await env.DB.batch(statements);
  if (!result.length) fail(503, 'Release batch transaction returned no result.');
  return { batchId, releaseIds: ids, snapshots };
}

export async function promoteBatch(env: Env, actor: Actor | null, releaseIds: string[], reason: string) {
  try {
    return await promoteBatchInner(env, requireMaintainer(actor), releaseIds, reason);
  } catch (cause) {
    if (cause instanceof PolicyError) await recordDenied(env, actor, 'release.batch_promote_denied', 'batch', cause);
    throw cause;
  }
}

async function rollbackInner(env: Env, actor: Actor, releaseId: string, reason: string) {
  const clean = cleanReason(reason);
  const [target] = await releaseRows(env, 'r.id=?', safeId(releaseId));
  if (!target) fail(404, 'Release not found.');
  if (target.channel !== 'stable') fail(409, 'Only stable releases can be rolled back.');
  const [previous] = target.previous_release_id
    ? await releaseRows(env, 'r.id=?', target.previous_release_id)
    : await releaseRows(env, "r.name=? AND r.architecture=? AND r.channel='withdrawn' AND r.published_at<? ORDER BY r.published_at DESC,r.id DESC LIMIT 1", target.name, target.architecture, target.published_at);
  if (!previous || previous.name !== target.name || previous.architecture !== target.architecture || previous.surface !== target.surface) {
    fail(409, 'No compatible previous release is available for downgrade.');
  }
  if (previous.channel !== 'withdrawn') fail(409, 'Previous release is not available for downgrade.');
  await assertCurrentApprovals(env, previous.revision_id, previous.manifest_sha256);
  if (target.surface === 'binary' && (!previous.artifact_key || !previous.signature_key || !previous.artifact_sha256 || !previous.artifact_filename)) {
    fail(409, 'Previous binary release is missing immutable package evidence.');
  }
  if (target.surface === 'binary' && previous.artifact_key !== packageKey(previous.architecture, previous.artifact_filename ?? '')) {
    fail(409, 'Previous binary release is outside the published package namespace.');
  }
  const current = await currentStable(env);
  const final = finalStable(current, [previous]);
  if (target.surface === 'binary') {
    const binary = binaryReleases([previous])[0];
    await verifyR2Object(env, binary.artifact_key, binary.artifact_sha256, binary.artifact_size);
    await verifySignatureObject(env, binary.signature_key);
    assertDependencyGraph([], current, final);
  }
  const batchId = id();
  const origin = publicOrigin(env);
  const publicBase = `${origin}/repo/${target.architecture}`;
  const previousRecipeUrl = `${origin}/repo/recipes/${segment(previous.name)}/${segment(previous.version)}/${previous.architecture}/PKGBUILD`;
  let recipeSha256: string | null = null;
  if (previous.surface === 'recipe') {
    const object = await env.ARTIFACTS.get(previous.recipe_key);
    if (!object || object.size > 2 * 1024 * 1024) fail(409, 'Previous public recipe is missing or too large.');
    recipeSha256 = await sha256(new Uint8Array(await object.arrayBuffer()));
  }
  const manifest = {
    schemaVersion: 1,
    kind: 'opr-downgrade',
    clientUrl: `${origin}/repo/rollback/client.sh`,
    publicKeyUrl: `${origin}/repo/key.asc`,
    package: { name: target.name, architecture: target.architecture },
    from: { releaseId: target.id, version: target.version },
    to: { releaseId: previous.id, version: previous.version },
    reason: clean,
    issuedAt: now(),
    command: target.surface === 'binary'
      ? `sudo pacman -U '${publicBase}/${previous.artifact_filename}'`
      : `curl --fail --location --proto '=https' --proto-redir '=https' --output PKGBUILD '${previousRecipeUrl}' && makepkg -si -f`,
    artifact: target.surface === 'binary' ? {
      url: `${publicBase}/${previous.artifact_filename}`, signatureUrl: `${publicBase}/${previous.artifact_filename}.sig`, sha256: previous.artifact_sha256,
    } : null,
    recipe: target.surface === 'recipe' ? { url: previousRecipeUrl, sha256: recipeSha256 } : null,
  };
  const manifestBytes = new TextEncoder().encode(JSON.stringify(manifest));
  const manifestPath = `rollback/${target.id}/${batchId}.json`;
  await immutableBytes(env, manifestPath, manifestBytes, await sha256(manifestBytes), 'application/json');
  const snapshots = target.surface === 'binary' ? [await snapshot(env, final, target.architecture, binaryReleases([previous])[0], batchId)] : [];
  const statements: D1PreparedStatement[] = [
    env.DB.prepare("UPDATE releases SET channel='withdrawn',batch_id=? WHERE id=? AND channel='stable'").bind(batchId, target.id),
    env.DB.prepare('INSERT INTO distribution_assertions(expected,actual) SELECT 1,changes()'),
    env.DB.prepare("UPDATE releases SET channel='stable',stable_at=?,batch_id=? WHERE id=? AND channel='withdrawn'").bind(now(), batchId, previous.id),
    env.DB.prepare('INSERT INTO distribution_assertions(expected,actual) SELECT 1,changes()'),
    env.DB.prepare('INSERT INTO release_rollbacks(release_id,previous_release_id,manifest_key,created_at) VALUES(?,?,?,?)')
      .bind(target.id, previous.id, manifestPath, now()),
  ];
  for (const item of snapshots) {
    statements.push(env.DB.prepare("UPDATE repository_snapshots SET active=0 WHERE channel='stable' AND architecture=? AND active=1").bind(item.architecture));
    statements.push(env.DB.prepare(`INSERT INTO repository_snapshots
      (id,architecture,channel,db_key,db_signature_key,batch_id,created_at,active) VALUES(?,?,?,?,?,?,?,1)`)
      .bind(item.id, item.architecture, item.channel, item.dbKey, item.dbSignatureKey, item.batchId, now()));
  }
  statements.push(env.DB.prepare(`INSERT INTO distribution_assertions(expected,actual)
    SELECT 2,COUNT(*) FROM releases WHERE id IN (?,?) AND batch_id=? AND ((id=? AND channel='withdrawn') OR (id=? AND channel='stable'))`)
    .bind(target.id, previous.id, batchId, target.id, previous.id));
  for (const row of current) {
    if (row.id !== target.id) {
      statements.push(env.DB.prepare("INSERT INTO distribution_assertions(expected,actual) SELECT 1,COUNT(*) FROM releases WHERE id=? AND channel='stable'").bind(row.id));
    }
  }
  statements.push(env.DB.prepare(`INSERT INTO distribution_assertions(expected,actual)
    SELECT ?,COUNT(*) FROM releases WHERE channel='stable'`)
    .bind(current.length));
  statements.push(env.DB.prepare('DELETE FROM distribution_assertions'));
  statements.push(audit(env.DB, actor.id, 'release.rolled_back', target.id, {
    previousReleaseId: previous.id, reason: clean, manifestKey: manifestPath, batchId,
    snapshots: snapshots.map((item) => ({ id: item.id, sha256: item.dbSha256 })),
  }));
  const result = await env.DB.batch(statements);
  if (!result[0].meta.changes || !result[1].meta.changes) fail(409, 'Release changed while rollback was being prepared; retry after refreshing.');
  return { releaseId: target.id, previousReleaseId: previous.id, manifestKey: manifestPath, batchId, snapshots };
}

export async function rollbackRelease(env: Env, actor: Actor | null, releaseId: string, reason: string) {
  try {
    return await rollbackInner(env, requireMaintainer(actor), releaseId, reason);
  } catch (cause) {
    if (cause instanceof PolicyError) await recordDenied(env, actor, 'release.rollback_denied', releaseId, cause);
    throw cause;
  }
}

/** Move a stable release back to quarantine after a policy-defined crash signal. */
export async function quarantineRelease(env: Env, releaseId: string, reason: string, minimumConfirmedCrashes?: number) {
  const [target] = await releaseRows(env, 'r.id=?', safeId(releaseId));
  if (!target || target.channel !== 'stable') return false;
  const clean = cleanReason(reason);
  const batchId = id();
  const current = await currentStable(env);
  const final = current.filter((row) => row.id !== target.id);
  let snapshots: RepositorySnapshot[] = [];
  if (target.surface === 'binary') {
    assertDependencyGraph([], current, final);
    const context = binaryReleases([...final, target]).find((row) => row.architecture === target.architecture)!;
    await assertCurrentApprovals(env, context.revision_id, context.manifest_sha256);
    snapshots = [await snapshot(env, final, target.architecture, context, batchId)];
  }
  const devCurrent = await currentDev(env);
  const devFinal = latestPerPackage([...devCurrent, target]);
  const devSnapshots = target.surface === 'binary'
    ? [await snapshot(env, devFinal, target.architecture, binaryReleases([...final, target]).find((row) => row.architecture === target.architecture)!, batchId, 'dev')]
    : [];
  const statements: D1PreparedStatement[] = [
    env.DB.prepare(`UPDATE releases SET channel='dev',batch_id=? WHERE id=? AND channel='stable'
      AND (? IS NULL OR (SELECT COUNT(*) FROM crash_reports WHERE release_id=? AND confirmed_at IS NOT NULL AND resolved_at IS NULL)>=?)`)
      .bind(batchId, target.id, minimumConfirmedCrashes ?? null, target.id, minimumConfirmedCrashes ?? null),
    env.DB.prepare('INSERT INTO distribution_assertions(expected,actual) SELECT 1,changes()'),
  ];
  for (const item of snapshots) {
    statements.push(env.DB.prepare("UPDATE repository_snapshots SET active=0 WHERE channel='stable' AND architecture=? AND active=1").bind(item.architecture));
    statements.push(env.DB.prepare(`INSERT INTO repository_snapshots
      (id,architecture,channel,db_key,db_signature_key,batch_id,created_at,active) VALUES(?,?,?,?,?,?,?,1)`)
      .bind(item.id, item.architecture, item.channel, item.dbKey, item.dbSignatureKey, item.batchId, now()));
  }
  for (const item of devSnapshots) {
    statements.push(env.DB.prepare("UPDATE repository_snapshots SET active=0 WHERE channel='dev' AND architecture=? AND active=1").bind(item.architecture));
    statements.push(env.DB.prepare(`INSERT INTO repository_snapshots
      (id,architecture,channel,db_key,db_signature_key,batch_id,created_at,active) VALUES(?,?,?,?,?,?,?,1)`)
      .bind(item.id, item.architecture, item.channel, item.dbKey, item.dbSignatureKey, item.batchId, now()));
    statements.push(env.DB.prepare("INSERT INTO distribution_assertions(expected,actual) SELECT 1,COUNT(*) FROM repository_snapshots WHERE id=? AND channel='dev' AND architecture=? AND active=1")
      .bind(item.id, item.architecture));
  }
  for (const row of current) {
    if (row.id !== target.id) {
      statements.push(env.DB.prepare("INSERT INTO distribution_assertions(expected,actual) SELECT 1,COUNT(*) FROM releases WHERE id=? AND channel='stable'").bind(row.id));
    }
  }
  for (const row of devCurrent) {
    statements.push(env.DB.prepare("INSERT INTO distribution_assertions(expected,actual) SELECT 1,COUNT(*) FROM releases WHERE id=? AND channel='dev'").bind(row.id));
  }
  statements.push(env.DB.prepare(`INSERT INTO distribution_assertions(expected,actual)
    SELECT 1,COUNT(*) FROM releases WHERE id=? AND channel='dev' AND batch_id=?`).bind(target.id, batchId));
  statements.push(env.DB.prepare(`INSERT INTO distribution_assertions(expected,actual)
    SELECT ?,COUNT(*) FROM releases WHERE channel='stable'`)
    .bind(final.length));
  statements.push(env.DB.prepare(`INSERT INTO distribution_assertions(expected,actual)
    SELECT ?,COUNT(*) FROM releases WHERE channel='dev'`)
    .bind(devCurrent.length + 1));
  statements.push(env.DB.prepare('DELETE FROM distribution_assertions'));
  statements.push(audit(env.DB, 'system', 'release.quarantined', target.id, {
    reason: clean, batchId,
    snapshots: snapshots.map((item) => ({ id: item.id, sha256: item.dbSha256 })),
    devSnapshots: devSnapshots.map((item) => ({ id: item.id, sha256: item.dbSha256 })),
  }));
  await env.DB.batch(statements);
  return true;
}

export type PublicRelease = {
  id: string;
  name: string;
  version: string;
  architecture: Architecture;
  surface: 'binary' | 'recipe';
  channel: 'stable' | 'withdrawn' | 'dev';
  publishedAt: number;
  stableAt: number | null;
  artifact: { url: string; filename: string; sha256: string; size: number; signatureUrl: string } | null;
  recipeUrl: string;
  sbomUrl: string;
  provenanceUrl: string;
  rollbackUrl: string;
  rollbackClientUrl: string;
};

export function publicRelease(release: Release & { artifact_filename?: string | null; artifact_sha256?: string | null; artifact_size?: number | null }, origin = '', includeDev = false): PublicRelease | null {
  if (release.channel !== 'stable' && release.channel !== 'withdrawn' && !(includeDev && release.channel === 'dev')) return null;
  const base = origin.replace(/\/$/, '');
  const routeBase = release.channel === 'dev' ? `${base}/repo/dev` : `${base}/repo`;
  const artifact = release.surface === 'binary' && release.artifact_key && release.signature_key && release.artifact_filename && release.artifact_sha256 && release.artifact_size
    ? {
        url: `${routeBase}/${release.architecture}/${encodeURIComponent(release.artifact_filename)}`,
        filename: release.artifact_filename, sha256: release.artifact_sha256, size: release.artifact_size,
        signatureUrl: `${routeBase}/${release.architecture}/${encodeURIComponent(release.artifact_filename)}.sig`,
      }
    : null;
  return {
    id: release.id, name: release.name, version: release.version, architecture: release.architecture,
    surface: release.surface, channel: release.channel, publishedAt: release.published_at, stableAt: release.stable_at,
    artifact, recipeUrl: `${routeBase}/recipes/${segment(release.name)}/${segment(release.version)}/${release.architecture}/PKGBUILD`,
    sbomUrl: `${base}/repo/metadata/${release.id}/sbom.json`, provenanceUrl: `${base}/repo/metadata/${release.id}/provenance.json`,
    rollbackUrl: `${base}/repo/rollback/${release.id}.json`, rollbackClientUrl: `${base}/repo/rollback/client.sh`,
  };
}
