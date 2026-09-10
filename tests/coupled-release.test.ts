import { expect, test } from 'bun:test';
import { readFileSync, readdirSync } from 'node:fs';
import { canonicalJson } from '../src/lib/canonical-json';
import type { CatalogManifest } from '../src/lib/distribution';
import type { ReleaseManifest } from '../src/lib/distribution-release';
import { releaseManifestDigest } from '../src/lib/distribution-release';
import { qualifyCandidateUniverse, type QualificationPackage } from '../src/lib/server/cohort-qualification';
import { proposeCatalogPackage } from '../src/lib/server/catalog-ownership';
import { activateDistributionRelease, approveDistributionRelease, getActiveDistributionRelease, renewResolvedTransaction, signDistributionRelease } from '../src/lib/server/distribution-releases';
import { sha256 } from '../src/lib/server/db';
import type { Env } from '../src/lib/server/env';
import { proposeCohort } from '../src/lib/server/cohorts';
import { MemoryR2 } from './release-fixtures';
import { asD1, TestD1 } from './d1';

const schema = readdirSync(new URL('../migrations', import.meta.url)).filter((name) => name.endsWith('.sql')).sort()
  .map((name) => readFileSync(new URL(`../migrations/${name}`, import.meta.url), 'utf8')).join('\n');

const release = { id: 'github:3', role: 'maintainer' as const, areas: ['system', 'development'] as const };

function service(db: TestD1, artifacts: MemoryR2, beforeManifestSignature?: () => void): Env {
  let signed = false;

  const signer = { fetch: async (request: Request) => {
    const { intentId } = await request.json() as { intentId: string };
    const intent = db.prepare('SELECT object_key FROM distribution_manifest_signing_intents WHERE id=?').bind(intentId).first<{ object_key: string }>();

    if (!intent) return new Response('missing intent', { status: 404 });

    if (!signed) { signed = true; beforeManifestSignature?.(); }

    const bytes = new Uint8Array([1, 2, 3]);
    artifacts.objects.set(`${intent.object_key}.sig`, bytes);

    return new Response(JSON.stringify({ signatureKey: `${intent.object_key}.sig`, signatureSha256: await sha256(bytes) }), { headers: { 'content-type': 'application/json' } });
  } };

  return { DB: asD1(db), ARTIFACTS: artifacts as unknown as R2Bucket, PUBLIC_ORIGIN: 'https://repo.test', QUARANTINE_HOURS: '48', SIGNER: signer as unknown as Fetcher } as Env;
}

function catalog(pkgbase: string, lane: 'system' | 'opr', ownerArea: 'system' | 'development'): CatalogManifest {
  return { schemaVersion: 1, pkgbase, outputs: [pkgbase], collection: lane === 'system' ? 'core' : 'omapkg', lane,
    role: lane === 'system' ? 'base-system' : 'optional', origin: 'upstream', upstreamUrl: `https://example.org/${pkgbase}.git`, sourceKind: 'git',
    description: pkgbase, license: 'MIT', ownerArea, architectures: ['x86_64', 'aarch64'], artifactArchitecture: 'native', architectureExceptions: [], sourceReference: null, rebuildOn: [] };
}

test('one closed system cohort retains system and OPR ownership slices', async () => {
  const db = new TestD1(schema); const d1 = asD1(db);

  try {
    const providerCatalog = await proposeCatalogPackage(d1, release, catalog('abi-provider', 'system', 'system'), null, 'Own provider.');
    const consumerCatalog = await proposeCatalogPackage(d1, release, catalog('abi-consumer', 'opr', 'development'), null, 'Own consumer.');

    const cohort = await proposeCohort(d1, release, 'abi-transition', null, {
      title: 'Provider ABI transition', lane: 'system', systemVersion: '4.0.4-rc1', parentSnapshot: null, compatibleSystems: [],
      members: [
        { pkgbase: providerCatalog.pkgbase, catalogRevision: 1, recipeRevisionId: null, cause: 'abi', reason: 'Provider changes ABI.' },
        { pkgbase: consumerCatalog.pkgbase, catalogRevision: 1, recipeRevisionId: null, cause: 'abi', reason: 'OPR consumer rebuilds against provider.' },
      ],
    }, 'Close provider and consumer scope.');

    const manifest = JSON.parse(cohort.manifest_json) as { members: Array<{ pkgbase: string; policy: CatalogManifest }> };
    expect(manifest.members.map((member) => member.policy.lane).sort()).toEqual(['opr', 'system']);

    const provider = (origin: QualificationPackage['origin'], artifactSha256: string): QualificationPackage => ({
      pkgbase: 'abi-provider', name: 'abi-provider', fullVersion: '2.0-1', architecture: 'x86_64', artifactSha256, artifactSize: 1,
      metadata: { name: 'abi-provider', fullVersion: '2.0-1', installedSize: 1, depends: [], provides: [], conflicts: [], replaces: [] },
      abi: { artifactSha256, typeAbi: 'not-checked', records: [] }, origin, rebuildOn: [], buildId: null, attempt: null,
    });

    const consumer = (origin: QualificationPackage['origin'], artifactSha256: string): QualificationPackage => ({
      pkgbase: 'abi-consumer', name: 'abi-consumer', fullVersion: '2.0-1', architecture: 'x86_64', artifactSha256, artifactSize: 1,
      metadata: { name: 'abi-consumer', fullVersion: '2.0-1', installedSize: 1, depends: ['abi-provider'], provides: [], conflicts: [], replaces: [] },
      abi: { artifactSha256, typeAbi: 'not-checked', records: [] }, origin, rebuildOn: [], buildId: null, attempt: null,
    });

    const qualification = qualifyCandidateUniverse({ cohortId: cohort.id, revision: cohort.current_revision, manifestSha256: cohort.manifest_sha256, architecture: 'x86_64',
      candidate: [provider('candidate', 'a'.repeat(64)), consumer('candidate', 'b'.repeat(64))], baseline: [provider('owned', 'c'.repeat(64)), consumer('owned', 'd'.repeat(64))] });

    expect(qualification.findings).toEqual([]);
  } finally { db.close(); }
});

function manifest(kind: 'system' | 'opr', releaseId: string, channel: 'edge' | 'rc' | 'stable' | 'quarantine', parent: { digest: string | null; sequence: number | null }, systemDigest: string | null, oprDigest: string | null): ReleaseManifest {
  return { schemaVersion: 1, kind, lane: kind, channel,
    identity: { version: kind === 'system' ? releaseId : null, generation: kind === 'opr' ? releaseId : null }, releaseId, parent,
    createdAt: 1_700_000_000, expiresAt: 1_800_000_000, sequence: (parent.sequence ?? 0) + 1, architectures: ['x86_64', 'aarch64'], sourceRefs: [],
    repositories: [{ name: kind === 'system' ? 'core' : 'omapkg', architecture: 'x86_64', snapshotDigest: 'a'.repeat(64), dbUrl: `https://repo.test/${releaseId}.db`, signatureUrl: `https://repo.test/${releaseId}.db.sig`, packageBaseUrl: `https://repo.test/${releaseId}/` }],
    packageChunks: [{ url: `https://repo.test/${releaseId}.json`, sha256: 'b'.repeat(64), size: 1, index: 0, count: 1, packageCount: 1 }], packageCount: 1,
    compatibility: { systemManifestDigest: systemDigest, systemSnapshotDigests: [], oprManifestDigest: oprDigest }, systemManifest: null, oprManifest: null,
    changelog: { url: `https://repo.test/${releaseId}.changelog`, sha256: 'c'.repeat(64), size: 1, approvedBy: 'github:3', cohortDigests: [] },
    approvals: { releaseTeam: ['github:3'], baseOwners: [] }, recovery: { fromDigest: parent.digest, target: null, authorized: false, reason: null, constraints: [] },
    policy: { schemaVersion: 1, version: 'distribution-release-v1' },
  };
}

async function seedCandidateGate(db: TestD1, artifacts: MemoryR2, value: ReleaseManifest): Promise<void> {
  if (value.kind === 'resolved-transaction') return;
  const token = `${value.kind}-${value.releaseId}`.replace(/[^A-Za-z0-9_-]/g, '-').slice(0, 72);
  const cohortId = `gate-${token}`;
  const names = value.kind === 'system' ? ['omarchy', 'omarchy-settings'] : [`gate-opr-${token}`];
  const architectures = value.kind === 'system' ? ['x86_64', 'aarch64'] as const : ['x86_64'] as const;
  const packages: Array<{ name: string; architecture: 'x86_64' | 'aarch64'; collection: 'omarchy' | 'omapkg'; version: string; artifactId: string; artifactSha: string; signatureSha: string; attestationSha: string; filename: string; artifactKey: string; signatureKey: string; attestationKey: string; attestationSignatureKey: string; revisionId: string; buildId?: string }> = [];

  for (const name of names) for (const architecture of architectures) {
    const version = value.kind === 'system' ? `${value.releaseId}-1` : '1.0-1'; const artifactId = `gate-artifact-${token}-${name}-${architecture}`;
    const filename = `${name}-${version}-${architecture}.pkg.tar.zst`; const artifactKey = `gate/${token}/${filename}`; const signatureKey = `${artifactKey}.sig`; const attestationKey = `gate/${token}/${filename}.attestation`; const attestationSignatureKey = `${attestationKey}.sig`;
    const artifactBytes = new Uint8Array([1]); const signatureBytes = new Uint8Array([2]); const attestationBytes = new Uint8Array([3]); const attestationSignatureBytes = new Uint8Array([4]);
    const artifactSha = await sha256(artifactBytes); const signatureSha = await sha256(signatureBytes); const attestationSha = await sha256(attestationBytes);
    artifacts.objects.set(artifactKey, artifactBytes); artifacts.objects.set(signatureKey, signatureBytes); artifacts.objects.set(attestationKey, attestationBytes); artifacts.objects.set(attestationSignatureKey, attestationSignatureBytes);
    const revisionId = `gate-revision-${token}-${name}-${architecture}`; const requestId = `gate-request-${token}-${name}-${architecture}`; const commit = 'a'.repeat(40);
    db.prepare(`INSERT OR IGNORE INTO requests(id,name,upstream_url,source_kind,area,requested_by,status,created_at,updated_at,upstream_ref) VALUES(?,?,?,?,?,?,?,?,?,?)`).bind(requestId, name, 'https://example.org/omarchy.git', 'git', 'system', 'github:3', 'built', 1, 1, commit).run();
    db.prepare(`INSERT OR IGNORE INTO revisions(id,request_id,version,recipe,recipe_sha256,manifest_sha256,sources_json,dependencies_json,smoke_commands_json,architectures_json,source_date_epoch,image_digest,license,surface,explanation,sbom_json,lint_json,upstream_commit,created_at,pkgrel) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).bind(revisionId, requestId, value.kind === 'system' ? value.releaseId : '1.0', 'pkgname=' + name + '\n', '1'.repeat(64), `gate-manifest-${revisionId}`, '[]', '[]', '[]', '["x86_64","aarch64"]', 1, 'sha256:image', 'MIT', 'binary', '', '{}', '{}', commit, 1, 1).run();
    packages.push({ name, architecture, collection: value.kind === 'system' ? 'omarchy' : 'omapkg', version, artifactId, artifactSha, signatureSha, attestationSha, filename, artifactKey, signatureKey, attestationKey, attestationSignatureKey, revisionId });
  }

  const ownerArea = value.kind === 'system' ? 'system' : 'development';
  const policyFor = (pkg: typeof packages[number]) => ({ schemaVersion: 1, pkgbase: pkg.name, outputs: [pkg.name], collection: pkg.collection, lane: value.kind, role: value.kind === 'system' ? 'omarchy-default' : 'optional', origin: 'upstream', upstreamUrl: `https://example.org/${pkg.name}.git`, sourceKind: 'git', description: pkg.name, license: 'MIT', ownerArea, architectures: ['x86_64', 'aarch64'], artifactArchitecture: 'native', architectureExceptions: [], sourceReference: null, rebuildOn: [] });
  const policies = [...new Map(packages.map((pkg) => [pkg.name, policyFor(pkg)])).values()];

  for (const policy of policies) {
    const json = canonicalJson(policy); const pkgbase = policy.pkgbase;
    db.prepare('INSERT OR IGNORE INTO catalog_packages(pkgbase,current_revision,admitted_revision,created_at,updated_at) VALUES(?,1,1,1,1)').bind(pkgbase).run();
    db.prepare('INSERT OR IGNORE INTO catalog_revisions(pkgbase,revision,manifest_json,manifest_sha256,collection,lane,owner_area,created_by,reason,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)').bind(pkgbase, 1, json, await sha256(json), policy.collection, policy.lane, policy.ownerArea, 'github:3', 'Gate fixture', 1).run();
    db.prepare('INSERT OR IGNORE INTO catalog_outputs(name,pkgbase) VALUES(?,?)').bind(pkgbase, pkgbase).run();
  }

  const parentRoot = `${'1'.repeat(63)}${value.kind === 'system' ? '1' : '2'}`; const finalRoot = `${'2'.repeat(63)}${value.kind === 'system' ? '1' : '2'}`; const parentRelease = value.kind === 'system' ? `4.0.${([...token].reduce((total, char) => total + char.charCodeAt(0), 0) % 900) + 1}` : `opr-base-${token}`;
  const cohortManifest = { schemaVersion: 1, title: `Gate ${token}`, lane: value.kind, systemVersion: value.kind === 'system' ? '4.0.3-rc1' : null, parentSnapshot: parentRoot, compatibleSystems: [], members: policies.map((policy) => ({ pkgbase: policy.pkgbase, catalogRevision: 1, catalogSha256: '', policy, recipe: null, cause: 'abi', reason: 'Gate fixture.' })) };

  for (const member of cohortManifest.members) member.catalogSha256 = await sha256(canonicalJson(member.policy));
  const cohortJson = canonicalJson(cohortManifest); const cohortSha = await sha256(cohortJson); const changelogDigest = `${'3'.repeat(63)}${value.kind === 'system' ? '1' : '2'}`;
  db.prepare(`INSERT OR IGNORE INTO cohorts(id,current_revision,event_sequence,phase,condition,created_at,updated_at) VALUES(?,1,0,'approve','ready',1,1)`).bind(cohortId).run();
  db.prepare(`INSERT OR IGNORE INTO cohort_revisions(cohort_id,revision,manifest_json,manifest_sha256,title,lane,created_by,created_at) VALUES(?,?,?,?,?,?,?,?)`).bind(cohortId, 1, cohortJson, cohortSha, cohortManifest.title, cohortManifest.lane, 'github:3', 1).run();

  for (const policy of policies) db.prepare('INSERT OR IGNORE INTO cohort_members(cohort_id,revision,pkgbase,catalog_revision,recipe_revision_id) VALUES(?,?,?,?,NULL)').bind(cohortId, 1, policy.pkgbase, 1).run();
  db.prepare('INSERT OR IGNORE INTO cohort_changelogs(cohort_id,revision,digest,facts_sha256,document_json,markdown,created_by,created_at) VALUES(?,?,?,?,?,?,?,?)').bind(cohortId, 1, changelogDigest, '4'.repeat(64), '{}', 'fixture', 'github:3', 1).run();
  db.prepare('INSERT OR IGNORE INTO cohort_changelog_reviews(cohort_id,revision,changelog_sha256,actor,reason,created_at) VALUES(?,?,?,?,?,?)').bind(cohortId, 1, changelogDigest, 'github:3', 'Reviewed fixture.', 1).run();
  const metadata = (pkg: typeof packages[number]) => canonicalJson({ name: pkg.name, fullVersion: pkg.version, architecture: pkg.architecture, installedSize: 1, depends: [], provides: [], conflicts: [], replaces: [] });

  for (const pkg of packages) db.prepare(`INSERT OR IGNORE INTO owned_repository_artifacts
    (id,collection,target_architecture,name,version,architecture,pkgbase,filename,artifact_key,artifact_sha256,artifact_size,metadata_json,description,license,upstream_url,source_date_epoch,rebuild_on_json,abi_inventory_ref,signature_key,signature_sha256,attestation_key,attestation_sha256,attestation_size,attestation_signature_key,attestation_signature_sha256,build_id,build_attempt,revision_id,cohort_id,cohort_revision,created_at)
    VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).bind(pkg.artifactId, pkg.collection, pkg.architecture, pkg.name, pkg.version, pkg.architecture, pkg.name, pkg.filename, pkg.artifactKey, pkg.artifactSha, 1, metadata(pkg), pkg.name, 'MIT', `https://example.org/${pkg.name}`, 1, '[]', null, pkg.signatureKey, pkg.signatureSha, pkg.attestationKey, pkg.attestationSha, 1, pkg.attestationSignatureKey, await sha256(new Uint8Array([4])), `gate-build-${pkg.artifactId}`, 1, pkg.revisionId, cohortId, 1, 1).run();
  const baseArtifacts = packages.filter((pkg) => pkg.architecture === 'x86_64');
  let armBase = packages.find((pkg) => pkg.architecture === 'aarch64');

  if (!armBase) {
    const source = baseArtifacts[0]; const artifactId = `${source.artifactId}-arm-base`; const artifactKey = `${source.artifactKey}-arm-base`; const signatureKey = `${artifactKey}.sig`; const attestationKey = `${artifactKey}.attestation`; const attestationSignatureKey = `${attestationKey}.sig`; const artifactSha = await sha256(new Uint8Array([11])); const signatureSha = await sha256(new Uint8Array([12])); const attestationSha = await sha256(new Uint8Array([13])); artifacts.objects.set(artifactKey, new Uint8Array([11])); artifacts.objects.set(signatureKey, new Uint8Array([12])); artifacts.objects.set(attestationKey, new Uint8Array([13])); artifacts.objects.set(attestationSignatureKey, new Uint8Array([14])); armBase = { ...source, artifactId, architecture: 'aarch64', filename: `${source.name}-${source.version}-aarch64-base.pkg.tar.zst`, artifactKey, signatureKey, attestationKey, attestationSignatureKey, artifactSha, signatureSha, attestationSha };
    db.prepare(`INSERT OR IGNORE INTO owned_repository_artifacts
      (id,collection,target_architecture,name,version,architecture,pkgbase,filename,artifact_key,artifact_sha256,artifact_size,metadata_json,description,license,upstream_url,source_date_epoch,rebuild_on_json,abi_inventory_ref,signature_key,signature_sha256,attestation_key,attestation_sha256,attestation_size,attestation_signature_key,attestation_signature_sha256,build_id,build_attempt,revision_id,cohort_id,cohort_revision,created_at)
      VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).bind(artifactId, source.collection, 'aarch64', source.name, source.version, 'aarch64', source.name, armBase.filename, artifactKey, artifactSha, 1, metadata(source), source.name, 'MIT', `https://example.org/${source.name}`, 1, '[]', null, signatureKey, signatureSha, attestationKey, attestationSha, 1, attestationSignatureKey, await sha256(new Uint8Array([14])), `gate-build-${artifactId}`, 1, source.revisionId, cohortId, 1, 1).run();
  }

  const universeArtifacts = [baseArtifacts[0], armBase];

  for (const [release, root, status] of [[parentRelease, parentRoot, 'prepared'], [value.releaseId, finalRoot, 'prepared']] as const) {
    if (value.kind === 'opr' && release === value.releaseId) continue;
    const universeId = `gate-universe-${token}-${release}`;
    db.prepare('INSERT OR IGNORE INTO owned_repository_universes(id,lane,release_id,root_sha256,package_count,status,created_at) VALUES(?,?,?,?,?,?,?)').bind(universeId, value.kind, release, root, universeArtifacts.length, status, 1).run();

    for (const [ordinal, pkg] of universeArtifacts.entries()) db.prepare('INSERT OR IGNORE INTO owned_repository_universe_packages(universe_id,ordinal,artifact_id,collection,target_architecture) VALUES(?,?,?,?,?)').bind(universeId, ordinal, pkg.artifactId, pkg.collection, pkg.architecture).run();
  }

  const packageItems = packages.map((pkg) => ({ releaseId: pkg.artifactId, name: pkg.name, version: pkg.version, architecture: pkg.architecture, artifactUrl: `https://repo.test/${value.kind === 'system' ? 'repo/releases' : 'repo/opr'}/${encodeURIComponent(value.releaseId)}/${pkg.collection}/${pkg.architecture}/${encodeURIComponent(pkg.filename)}`, artifactSha256: pkg.artifactSha, artifactSignatureUrl: `https://repo.test/${value.kind === 'system' ? 'repo/releases' : 'repo/opr'}/${encodeURIComponent(value.releaseId)}/${pkg.collection}/${pkg.architecture}/${encodeURIComponent(pkg.filename)}.sig`, artifactSignatureSha256: pkg.signatureSha, cohortId, evidence: [{ url: `https://repo.test/repo/owned-attestations/gate-build-${pkg.artifactId}/1`, sha256: pkg.attestationSha, size: 1 }] }));
  const chunkValue = { schemaVersion: 1, index: 0, count: 1, packages: packageItems }; const chunkBytes = new TextEncoder().encode(canonicalJson(chunkValue)); const chunkSha = await sha256(chunkBytes); const chunkKey = `gate/${token}/chunk.json`; artifacts.objects.set(chunkKey, chunkBytes);
  value.packageChunks = [{ url: `https://repo.test/${chunkKey}`, sha256: chunkSha, size: chunkBytes.byteLength, index: 0, count: 1, packageCount: packageItems.length }]; value.packageCount = packageItems.length;
  db.prepare('INSERT OR IGNORE INTO owned_repository_package_chunks(id,lane,release_id,chunk_index,chunk_count,package_count,object_key,object_sha256,object_size,status,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)').bind(`gate-chunk-${token}`, value.kind, value.releaseId, 0, 1, packageItems.length, chunkKey, chunkSha, chunkBytes.byteLength, 'prepared', 1).run();
  const changelogValue = { schemaVersion: 1, cohorts: [{ cohortId, revision: 1, digest: changelogDigest }] }; const changelogBytes = new TextEncoder().encode(canonicalJson(changelogValue)); const changelogSha = await sha256(changelogBytes); const changelogKey = `gate/${token}/changelog.json`; artifacts.objects.set(changelogKey, changelogBytes); value.changelog = { ...value.changelog, url: `https://repo.test/${changelogKey}`, sha256: changelogSha, size: changelogBytes.byteLength, cohortDigests: [{ cohortId, revision: 1, digest: changelogDigest }] };
  const candidateSha = cohortSha; const workerByArch = new Map<string, string>();

  for (const architecture of ['x86_64', 'aarch64'] as const) { const workerId = `gate-worker-${token}-${architecture}`; workerByArch.set(architecture, workerId); db.prepare('INSERT OR IGNORE INTO workers(id,name,architecture,public_key,status,enrolled_at) VALUES(?,?,?,?,?,?)').bind(workerId, workerId, architecture, `gate-key-${token}-${architecture}`, 'active', 1).run(); }

  const operations = ['reproducibility', 'install', 'upgrade', 'recovery', ...(value.kind === 'system' ? ['boot'] : [])] as const;

  for (const architecture of ['x86_64', 'aarch64'] as const) for (const operation of operations) {
    const scopes = operation === 'reproducibility' || value.kind === 'opr' ? cohortManifest.members.map((member) => ({ kind: 'member', pkgbase: member.pkgbase, root: null, release: value.releaseId })) : [{ kind: 'system', pkgbase: null, root: finalRoot, release: value.releaseId }];

    for (const scope of scopes) { const planId = `gate-plan-${token}-${architecture}-${operation}-${scope.pkgbase ?? 'system'}`; const coverage = { kind: scope.kind, pkgbase: scope.pkgbase, rootSha256: scope.root, releaseId: scope.release, members: scope.pkgbase ? [scope.pkgbase] : cohortManifest.members.map((member) => member.pkgbase), sha256: '5'.repeat(64) }; db.prepare(`INSERT INTO native_qualification_plans(id,cohort_id,revision,operation,architecture,candidate_sha256,input_sha256,artifact_sha256,environment_sha256,profile_id,profile_sha256,coverage_kind,coverage_pkgbase,coverage_root_sha256,coverage_release_id,coverage_sha256,coverage_json,plan_json,plan_sha256,created_by,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).bind(planId, cohortId, 1, operation, architecture, candidateSha, '6'.repeat(64), '7'.repeat(64), '8'.repeat(64), 'gate', '9'.repeat(64), scope.kind, scope.pkgbase, scope.root, scope.release, coverage.sha256, canonicalJson(coverage), '{}', await sha256(planId), 'github:3', 1).run(); db.prepare(`INSERT INTO native_qualification_evidence(id,plan_id,cohort_id,revision,operation,architecture,candidate_sha256,input_sha256,artifact_sha256,environment_sha256,profile_id,profile_sha256,coverage_kind,coverage_pkgbase,coverage_release_id,coverage_root_sha256,coverage_sha256,coverage_json,observed_sha256,status,reproducibility_status,worker_id,worker_public_key,report_json,report_sha256,signature,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).bind(`gate-evidence-${planId}`, planId, cohortId, 1, operation, architecture, candidateSha, '6'.repeat(64), '7'.repeat(64), '8'.repeat(64), 'gate', '9'.repeat(64), scope.kind, scope.pkgbase, scope.release, scope.root, coverage.sha256, canonicalJson(coverage), 'b'.repeat(64), 'passed', operation === 'reproducibility' ? 'verified-reproducible' : null, workerByArch.get(architecture), `gate-key-${token}-${architecture}`, '{}', 'c'.repeat(64), 'sig', 1).run(); }
  }
}

async function signedCandidate(db: TestD1, artifacts: MemoryR2, value: ReleaseManifest, status: 'candidate' | 'signed' | 'active' = 'signed', withApproval = true): Promise<string> {
  await seedCandidateGate(db, artifacts, value);
  const digest = await releaseManifestDigest(value); const bytes = new TextEncoder().encode(canonicalJson(value));
  const id = `${value.kind}-${value.releaseId}`; const key = `distribution/${value.kind}/${value.channel}/${value.releaseId}/manifest.json`;
  const objectPrefix = `${value.kind}-${value.releaseId}`.replace(/[^A-Za-z0-9_-]/g, '-').slice(0, 72);
  artifacts.objects.set(key, bytes); artifacts.objects.set(`${key}.sig`, new Uint8Array([9]));
  db.prepare(`INSERT INTO distribution_release_candidates
    (id,kind,lane,channel,release_id,sequence,parent_digest,parent_sequence,manifest_json,manifest_sha256,manifest_key,manifest_size,signature_key,signature_sha256,signature_intent_id,changelog_key,changelog_sha256,status,created_by,created_at,activated_at)
    VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).bind(id, value.kind, value.lane, value.channel, value.releaseId, value.sequence, value.parent.digest, value.parent.sequence,
      canonicalJson(value), digest, key, bytes.byteLength, status === 'candidate' ? null : `${key}.sig`, status === 'candidate' ? null : 'd'.repeat(64), status === 'candidate' ? null : `intent-${id}`, `gate/${objectPrefix}/changelog.json`, value.changelog.sha256, status, 'github:3', value.createdAt, status === 'active' ? value.createdAt : null).run();
  db.prepare('INSERT OR IGNORE INTO distribution_release_objects(candidate_id,kind,digest,object_key,size) VALUES(?,?,?,?,?)').bind(id, 'package-chunk', value.packageChunks[0].sha256, `gate/${objectPrefix}/chunk.json`, value.packageChunks[0].size).run(); db.prepare('INSERT OR IGNORE INTO distribution_release_objects(candidate_id,kind,digest,object_key,size) VALUES(?,?,?,?,?)').bind(id, 'changelog', value.changelog.sha256, `gate/${objectPrefix}/changelog.json`, value.changelog.size).run();

  if (withApproval) db.prepare(`INSERT INTO distribution_release_approvals(id,candidate_id,manifest_sha256,kind,actor,area,reason,created_at) VALUES(?,?,?,?,?,?,?,?)`)
    .bind(`approval-${id}`, id, digest, 'release', 'github:3', null, 'Reviewed exact immutable candidate.', value.createdAt).run();

  return digest;
}

function pointer(db: TestD1, lane: 'system' | 'opr' | 'transaction', channel: 'edge' | 'rc' | 'stable' | 'quarantine', digest: string | null, sequence: number, systemDigest: string | null, oprDigest: string | null) {
  db.prepare(`UPDATE distribution_activation_pointers SET release_id=?,manifest_sha256=?,sequence=?,system_manifest_sha256=?,opr_manifest_sha256=?,updated_at=? WHERE lane=? AND channel=?`)
    .bind(digest ? `${lane}-${digest.slice(0, 8)}` : null, digest, sequence, systemDigest, oprDigest, 1, lane, channel).run();
}

function ownedObjects(db: TestD1, lane: 'system' | 'opr', releaseId: string) {
  const collection = lane === 'system' ? 'core' : 'omapkg'; const snapshot = `${lane}-${releaseId}-snapshot`;
  db.prepare(`INSERT OR IGNORE INTO owned_repository_snapshots
    (id,lane,release_id,architecture,collection,db_filename,db_key,db_sha256,db_size,db_signature_key,db_signature_sha256,filename_map_key,filename_map_sha256,filename_map_size,package_count,status,created_at)
    VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).bind(snapshot, lane, releaseId, 'x86_64', collection, `${snapshot}.db`, `${snapshot}.db`, 'e'.repeat(64), 1, `${snapshot}.sig`, 'f'.repeat(64), `${snapshot}.map`, 'a'.repeat(64), 1, 1, 'prepared', 1).run();
  db.prepare(`INSERT OR IGNORE INTO owned_repository_package_chunks
    (id,lane,release_id,chunk_index,chunk_count,package_count,object_key,object_sha256,object_size,status,created_at)
    VALUES(?,?,?,?,?,?,?,?,?,?,?)`).bind(`${lane}-${releaseId}-chunk`, lane, releaseId, 0, 1, 1, `${lane}/${releaseId}.json`, 'b'.repeat(64), 1, 'prepared', 1).run();
  db.prepare(`INSERT OR IGNORE INTO owned_repository_universes(id,lane,release_id,root_sha256,package_count,status,created_at)
    VALUES(?,?,?,?,?,?,?)`).bind(`${lane}-${releaseId}-universe`, lane, releaseId, 'c'.repeat(64), 1, 'prepared', 1).run();
}

function resolvedTransaction(system: ReleaseManifest, opr: ReleaseManifest, systemDigest: string, oprDigest: string, expiresAt = 1): ReleaseManifest {
  return { ...system, kind: 'resolved-transaction', lane: 'transaction', releaseId: `txn-${system.releaseId}-${opr.releaseId}`,
    identity: { version: system.identity.version, generation: opr.identity.generation }, parent: { digest: null, sequence: null }, sequence: 1,
    expiresAt, compatibility: { systemManifestDigest: systemDigest, systemSnapshotDigests: [], oprManifestDigest: oprDigest },
    systemManifest: { url: 'https://repo.test/system.json', digest: systemDigest, signatureUrl: 'https://repo.test/system.json.sig', channel: system.channel, sequence: system.sequence, version: system.identity.version, generation: null },
    oprManifest: { url: 'https://repo.test/opr.json', digest: oprDigest, signatureUrl: 'https://repo.test/opr.json.sig', channel: opr.channel, sequence: opr.sequence, version: null, generation: opr.identity.generation },
  };
}

test('RC coupled activation publishes both lane pointers and repositories atomically', async () => {
  const db = new TestD1(schema); const artifacts = new MemoryR2(); const env = service(db, artifacts); db.prepare("INSERT INTO team_memberships(github_id,team) VALUES('3','release')").run();

  try {
    const system = manifest('system', '4.0.4-rc1', 'rc', { digest: null, sequence: null }, null, null);
    const finalSystemDigest = await signedCandidate(db, artifacts, system);
    const opr = manifest('opr', 'opr-20260910-1', 'stable', { digest: null, sequence: null }, finalSystemDigest, null);
    await signedCandidate(db, artifacts, opr);
    const finalSystem = system;
    db.prepare('UPDATE distribution_activation_pointers SET sequence=0,manifest_sha256=NULL,release_id=NULL,system_manifest_sha256=NULL,opr_manifest_sha256=NULL WHERE lane=? AND channel=?').bind('system', 'rc').run();
    db.prepare('UPDATE distribution_activation_pointers SET sequence=0,manifest_sha256=NULL,release_id=NULL,system_manifest_sha256=NULL,opr_manifest_sha256=NULL WHERE lane=? AND channel=?').bind('opr', 'stable').run();
    db.prepare('UPDATE distribution_activation_pointers SET sequence=0,manifest_sha256=NULL,release_id=NULL,system_manifest_sha256=NULL,opr_manifest_sha256=NULL WHERE lane=? AND channel=?').bind('transaction', 'rc').run();
    ownedObjects(db, 'system', finalSystem.releaseId); ownedObjects(db, 'opr', opr.releaseId);
    const candidateId = `system-${finalSystem.releaseId}`;
    const result = await activateDistributionRelease(env, release, candidateId);
    expect(result.transactionManifestSha256).toMatch(/^[a-f0-9]{64}$/);
    expect((await getActiveDistributionRelease(env.DB, 'system', 'rc'))?.candidate.release_id).toBe(finalSystem.releaseId);
    expect((await getActiveDistributionRelease(env.DB, 'opr', 'stable'))?.candidate.release_id).toBe(opr.releaseId);
    expect((await getActiveDistributionRelease(env.DB, 'transaction', 'rc'))?.manifest.compatibility.systemManifestDigest).toBe(finalSystemDigest);
    expect(db.prepare("SELECT status FROM owned_repository_universes WHERE lane='system' AND release_id=?").bind(finalSystem.releaseId).first<{ status: string }>()?.status).toBe('published');
    expect(db.prepare("SELECT status FROM owned_repository_universes WHERE lane='opr' AND release_id=?").bind(opr.releaseId).first<{ status: string }>()?.status).toBe('published');
    expect(await getActiveDistributionRelease(env.DB, 'system', 'stable')).toBeNull();
  } finally { db.close(); }
});

test('unsigned candidates approve and sign into a finalized coupled pair before activation', async () => {
  const db = new TestD1(schema); const artifacts = new MemoryR2(); const env = service(db, artifacts); db.prepare("INSERT INTO team_memberships(github_id,team) VALUES('3','release')").run();

  try {
    const system = { ...manifest('system', '4.0.6-rc1', 'rc', { digest: null, sequence: null }, null, null), approvals: { releaseTeam: [], baseOwners: [] } };
    const unsignedSystemDigest = await signedCandidate(db, artifacts, system, 'candidate', false);
    const approvedSystem = await approveDistributionRelease(env.DB, release, { candidateId: `system-${system.releaseId}`, kind: 'release', reason: 'Review exact system candidate.' });
    expect(approvedSystem.manifestSha256).toBe(unsignedSystemDigest);
    const signedSystem = await signDistributionRelease(env, release, `system-${system.releaseId}`);
    expect(signedSystem.manifestSha256).not.toBe(unsignedSystemDigest);
    expect(db.prepare('SELECT status FROM distribution_release_candidates WHERE id=?').bind(`system-${system.releaseId}`).first<{ status: string }>()?.status).toBe('superseded');
    expect(db.prepare('SELECT status FROM distribution_release_candidates WHERE id=?').bind(signedSystem.candidateId).first<{ status: string }>()?.status).toBe('signed');
    const finalizedSystem = await getActiveDistributionRelease(env.DB, 'system', 'rc');
    expect(finalizedSystem).toBeNull();
    const opr = { ...manifest('opr', 'opr-20260910-4', 'stable', { digest: null, sequence: null }, signedSystem.manifestSha256, null), approvals: { releaseTeam: [], baseOwners: [] } };
    await signedCandidate(db, artifacts, opr, 'candidate', false);
    await approveDistributionRelease(env.DB, release, { candidateId: `opr-${opr.releaseId}`, kind: 'release', reason: 'Review OPR consumer against finalized system.' });
    const signedOpr = await signDistributionRelease(env, release, `opr-${opr.releaseId}`);
    expect(JSON.parse((await db.prepare('SELECT manifest_json FROM distribution_release_candidates WHERE id=?').bind(signedOpr.candidateId).first<{ manifest_json: string }>())!.manifest_json).compatibility.systemManifestDigest).toBe(signedSystem.manifestSha256);
    ownedObjects(db, 'system', system.releaseId); ownedObjects(db, 'opr', opr.releaseId);
    const activation = await activateDistributionRelease(env, release, signedSystem.candidateId);
    expect(activation.manifestSha256).toBe(signedSystem.manifestSha256);
    expect((await getActiveDistributionRelease(env.DB, 'opr', 'stable'))?.candidate.manifest_sha256).toBe(signedOpr.manifestSha256);
  } finally { db.close(); }
});

test('system activation exposes a missing OPR counterpart without moving pointers', async () => {
  const db = new TestD1(schema); const artifacts = new MemoryR2(); const env = service(db, artifacts); db.prepare("INSERT INTO team_memberships(github_id,team) VALUES('3','release')").run();

  try {
    const system = manifest('system', '4.0.5-rc1', 'rc', { digest: null, sequence: null }, null, null);
    await signedCandidate(db, artifacts, system); ownedObjects(db, 'system', system.releaseId);
    await expect(activateDistributionRelease(env, release, `system-${system.releaseId}`)).rejects.toThrow('counterpart');
    expect(await getActiveDistributionRelease(env.DB, 'system', 'rc')).toBeNull();
    expect(db.prepare("SELECT status FROM owned_repository_universes WHERE lane='system' AND release_id=?").bind(system.releaseId).first<{ status: string }>()?.status).toBe('prepared');
  } finally { db.close(); }
});

test('solo OPR activation advances OPR and transaction only', async () => {
  const db = new TestD1(schema); const artifacts = new MemoryR2(); const env = service(db, artifacts); db.prepare("INSERT INTO team_memberships(github_id,team) VALUES('3','release')").run();

  try {
    const system = manifest('system', '4.0.3', 'stable', { digest: null, sequence: null }, null, null); const systemDigest = await signedCandidate(db, artifacts, system, 'active');
    const oldOpr = manifest('opr', 'opr-20260909-1', 'stable', { digest: null, sequence: null }, systemDigest, null); const oldOprDigest = await signedCandidate(db, artifacts, oldOpr, 'active');
    pointer(db, 'system', 'stable', systemDigest, 1, systemDigest, oldOprDigest); pointer(db, 'opr', 'stable', oldOprDigest, 1, systemDigest, oldOprDigest);
    const next = manifest('opr', 'opr-20260910-1', 'stable', { digest: oldOprDigest, sequence: 1 }, systemDigest, null); const nextDigest = await signedCandidate(db, artifacts, next); ownedObjects(db, 'opr', next.releaseId);
    const result = await activateDistributionRelease(env, release, `opr-${next.releaseId}`);
    expect(result.manifestSha256).toBe(nextDigest);
    expect((await getActiveDistributionRelease(env.DB, 'system', 'stable'))?.candidate.release_id).toBe(system.releaseId);
    expect((await getActiveDistributionRelease(env.DB, 'opr', 'stable'))?.candidate.release_id).toBe(next.releaseId);
    expect((await getActiveDistributionRelease(env.DB, 'transaction', 'stable'))?.manifest.compatibility.oprManifestDigest).toBe(nextDigest);
  } finally { db.close(); }
});

test('solo OPR activation aborts when active system pointer moves during signing', async () => {
  const db = new TestD1(schema); const artifacts = new MemoryR2(); let env: Env;
  const mutateSystem = () => db.prepare("UPDATE distribution_activation_pointers SET sequence=2 WHERE lane='system' AND channel='stable'").run();
  env = service(db, artifacts, mutateSystem); db.prepare("INSERT INTO team_memberships(github_id,team) VALUES('3','release')").run();

  try {
    const system = manifest('system', '4.0.3', 'stable', { digest: null, sequence: null }, null, null); const systemDigest = await signedCandidate(db, artifacts, system, 'active');
    const oldOpr = manifest('opr', 'opr-20260909-1', 'stable', { digest: null, sequence: null }, systemDigest, null); const oldOprDigest = await signedCandidate(db, artifacts, oldOpr, 'active');
    pointer(db, 'system', 'stable', systemDigest, 1, systemDigest, oldOprDigest); pointer(db, 'opr', 'stable', oldOprDigest, 1, systemDigest, oldOprDigest);
    const next = manifest('opr', 'opr-20260910-2', 'stable', { digest: oldOprDigest, sequence: 1 }, systemDigest, null); await signedCandidate(db, artifacts, next); ownedObjects(db, 'opr', next.releaseId);
    await expect(activateDistributionRelease(env, release, `opr-${next.releaseId}`)).rejects.toThrow('parent changed');
    expect(db.prepare("SELECT manifest_sha256,sequence FROM distribution_activation_pointers WHERE lane='opr' AND channel='stable'").first<{ manifest_sha256: string; sequence: number }>()).toEqual({ manifest_sha256: oldOprDigest, sequence: 1 });
    expect(await getActiveDistributionRelease(env.DB, 'transaction', 'stable')).toBeNull();
  } finally { db.close(); }
});

test('system activation aborts when active OPR pointer moves during signing', async () => {
  const db = new TestD1(schema); const artifacts = new MemoryR2(); let env: Env;
  const mutateOpr = () => db.prepare("UPDATE distribution_activation_pointers SET sequence=2 WHERE lane='opr' AND channel='stable'").run();
  env = service(db, artifacts, mutateOpr); db.prepare("INSERT INTO team_memberships(github_id,team) VALUES('3','release')").run();

  try {
    const oldSystem = manifest('system', '4.0.3', 'stable', { digest: null, sequence: null }, null, null); await signedCandidate(db, artifacts, oldSystem, 'active');
    const candidate = manifest('system', '4.0.4-rc1', 'rc', { digest: null, sequence: null }, null, null); const candidateDigest = await signedCandidate(db, artifacts, candidate);
    const opr = manifest('opr', 'opr-20260909-1', 'stable', { digest: null, sequence: null }, candidateDigest, null); const oprDigest = await signedCandidate(db, artifacts, opr, 'active');
    pointer(db, 'system', 'rc', null, 0, null, null); pointer(db, 'opr', 'stable', oprDigest, 1, candidateDigest, oprDigest);
    ownedObjects(db, 'system', candidate.releaseId);
    await expect(activateDistributionRelease(env, release, `system-${candidate.releaseId}`)).rejects.toThrow('parent changed');
    expect(db.prepare("SELECT manifest_sha256,sequence FROM distribution_activation_pointers WHERE lane='system' AND channel='rc'").first<{ manifest_sha256: string | null; sequence: number }>()).toEqual({ manifest_sha256: null, sequence: 0 });
    expect(await getActiveDistributionRelease(env.DB, 'transaction', 'rc')).toBeNull();
  } finally { db.close(); }
});

test('renewal refuses to replace OPR selected by exact active transaction pair', async () => {
  const db = new TestD1(schema); const artifacts = new MemoryR2(); const env = service(db, artifacts); db.prepare("INSERT INTO team_memberships(github_id,team) VALUES('3','release')").run();

  try {
    const system = manifest('system', '4.0.3', 'stable', { digest: null, sequence: null }, null, null); const systemDigest = await signedCandidate(db, artifacts, system, 'active');
    const oldOpr = manifest('opr', 'opr-20260909-1', 'stable', { digest: null, sequence: null }, systemDigest, null); const oldOprDigest = await signedCandidate(db, artifacts, oldOpr, 'active');
    const nextOpr = manifest('opr', 'opr-20260910-3', 'stable', { digest: oldOprDigest, sequence: 1 }, systemDigest, null); const nextOprDigest = await signedCandidate(db, artifacts, nextOpr, 'active');
    const tx = resolvedTransaction(system, oldOpr, systemDigest, oldOprDigest); const txDigest = await signedCandidate(db, artifacts, tx, 'active');
    pointer(db, 'system', 'stable', systemDigest, 1, systemDigest, oldOprDigest); pointer(db, 'opr', 'stable', nextOprDigest, 2, systemDigest, nextOprDigest); pointer(db, 'transaction', 'stable', txDigest, 1, systemDigest, oldOprDigest);
    await expect(renewResolvedTransaction(env, release, 'stable')).rejects.toThrow('pair changed');
  } finally { db.close(); }
});

test('active OPR quarantine retry returns its RC transaction', async () => {
  const db = new TestD1(schema); const artifacts = new MemoryR2(); const env = service(db, artifacts); db.prepare("INSERT INTO team_memberships(github_id,team) VALUES('3','release')").run();

  try {
    const system = manifest('system', '4.0.4-rc1', 'rc', { digest: null, sequence: null }, null, null); const systemDigest = await signedCandidate(db, artifacts, system, 'active');
    pointer(db, 'system', 'rc', systemDigest, 1, systemDigest, null); pointer(db, 'transaction', 'rc', null, 0, null, null);
    const opr = manifest('opr', 'opr-20260910-quarantine', 'quarantine', { digest: null, sequence: null }, systemDigest, null); await signedCandidate(db, artifacts, opr); ownedObjects(db, 'opr', opr.releaseId);
    const first = await activateDistributionRelease(env, release, `opr-${opr.releaseId}`);
    const second = await activateDistributionRelease(env, release, `opr-${opr.releaseId}`);
    expect(second.transactionManifestSha256).toBe(first.transactionManifestSha256);
    expect(second.transactionManifestSha256).not.toBe(first.manifestSha256);
  } finally { db.close(); }
});
