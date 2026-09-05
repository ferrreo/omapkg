import type { Approval, Architecture, BuildImageMap, Revision } from '../../src/lib/model';
import { audit, now, sha256 } from '../../src/lib/server/db';
import { manifestDigest, parseDeclaredLicense } from '../../src/lib/server/policy';
import { encodeOprEvidence } from '../../src/lib/server/sbom';
import type { FactoryCandidate, FactoryEnv, FactoryRevisionDraft } from './types';
import {
  assertCommand,
  assertImageDigest,
  assertPackageName,
  assertSha256,
  assertSmokeCommand,
  assertVersion,
  classifySourceUrl,
  normalizeSourceUrl,
} from './security';
import { lintRecipe, renderRecipe } from './recipe';
import { constrainVendorArtifactArchitectures } from './artifacts';
import { parseArchDependency } from '../../src/lib/server/arch';

function assertSourceName(value: string): string {
  if (!/^[A-Za-z0-9][A-Za-z0-9._+-]{0,150}$/.test(value) || value === '.' || value === '..') {
    throw new Error('invalid source name');
  }
  return value;
}

function assertCommit(value: string | null | undefined): string | null {
  if (value == null) return null;
  if (!/^[0-9a-f]{40}(?:[0-9a-f]{24})?$/i.test(value)) throw new Error('invalid upstream commit');
  return value.toLowerCase();
}

function assertSourceRoot(value: string | undefined, sourceKind: FactoryCandidate['request']['sourceKind']): string | undefined {
  if (!value) return undefined;
  if (sourceKind !== 'archive' || !/^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$/.test(value)) throw new Error('invalid archive source root');
  return value;
}

function normalizeDependencies(values: string[], label: string): string[] {
  return values.map((value) => {
    if (!parseArchDependency(value)) throw new Error(`invalid Arch ${label}: ${value}`);
    return value;
  });
}

export function normalizeCandidate(candidate: FactoryCandidate): FactoryCandidate {
  assertPackageName(candidate.request.name);
  assertVersion(candidate.version);
  assertImageDigest(candidate.imageDigest);
  if (!candidate.request.id || !candidate.request.area) throw new Error('request identity is required');
  if (candidate.request.sourceKind !== 'git' && candidate.request.sourceKind !== 'archive') {
    throw new Error('invalid source kind');
  }
  const sourceRoot = assertSourceRoot(candidate.sourceRoot, candidate.request.sourceKind);

  const sources = candidate.sources.map((source) => {
    assertSourceName(source.name);
    const url = normalizeSourceUrl(source.url).toString();
    assertSha256(source.sha256);
    return { name: source.name, url, sha256: source.sha256 };
  });
  if (!sources.length) throw new Error('at least one source is required');
  if (new Set(sources.map((source) => source.name)).size !== sources.length) throw new Error('source names must be unique');
  if (candidate.request.sourceKind === 'git' && !assertCommit(candidate.upstreamCommit)) {
    throw new Error('git revisions require an immutable upstream commit');
  }
  if (candidate.request.sourceKind === 'archive' && candidate.upstreamCommit != null) {
    assertCommit(candidate.upstreamCommit);
  }

  const dependencies = normalizeDependencies(candidate.dependencies, 'dependency');
  const makeDependencies = normalizeDependencies(candidate.makeDependencies ?? [], 'build dependency');
  const smokeCommands = candidate.smokeCommands.map(assertSmokeCommand);
  const buildCommands = candidate.buildCommands.map((command) => assertCommand(command, 'build command'));
  const packageCommands = candidate.packageCommands.map((command) => assertCommand(command, 'package command'));
  let architectures = [...new Set(candidate.architectures)].filter((architecture) => architecture === 'x86_64' || architecture === 'aarch64');
  if (!architectures.length) throw new Error('at least one architecture is required');
  if (candidate.vendorArtifact) architectures = constrainVendorArtifactArchitectures(architectures, candidate.vendorArtifact);
  const buildImages = normalizeBuildImages(candidate.buildImages, architectures);
  if (!Number.isSafeInteger(candidate.sourceDateEpoch) || candidate.sourceDateEpoch < 0) {
    throw new Error('sourceDateEpoch must be a non-negative integer');
  }
  const pkgrel = candidate.pkgrel ?? 1;
  if (!Number.isSafeInteger(pkgrel) || pkgrel < 1 || pkgrel > 9_999) throw new Error('pkgrel must be an integer between 1 and 9999');
  const license = candidate.license.replace(/[\r\n]/g, ' ').trim();
  if (!license || license.length > 128) throw new Error('invalid license');
  const description = candidate.description.replace(/[\r\n]/g, ' ').trim();
  if (!description || description.length > 160) throw new Error('invalid package description');
  if (candidate.surface !== 'binary' && candidate.surface !== 'recipe') throw new Error('invalid surface');
  if (candidate.publicRecipe != null && (candidate.surface !== 'recipe' || !candidate.publicRecipe.length || candidate.publicRecipe.length > 2 * 1024 * 1024)) {
    throw new Error('invalid public recipe');
  }

  return {
    ...candidate,
    request: { ...candidate.request, upstreamUrl: normalizeSourceUrl(candidate.request.upstreamUrl).toString() },
    version: candidate.version,
    sources,
    sourceRoot,
    dependencies,
    makeDependencies,
    smokeCommands,
    buildCommands,
    packageCommands,
    architectures,
    buildImages,
    pkgrel,
    imageDigest: buildImages[architectures[0]] ?? candidate.imageDigest,
    license,
    description,
    upstreamCommit: assertCommit(candidate.upstreamCommit),
    prUrl: candidate.prUrl ? normalizeSourceUrl(candidate.prUrl).toString() : null,
    commitSha: candidate.commitSha ? assertCommit(candidate.commitSha) : null,
  };
}

function normalizeBuildImages(value: BuildImageMap | undefined, architectures: Architecture[]): BuildImageMap {
  const entries = Object.entries(value ?? {});
  if (!entries.length) return {};
  if (entries.some(([architecture, image]) =>
    (architecture !== 'x86_64' && architecture !== 'aarch64') || typeof image !== 'string')) {
    throw new Error('build image map contains an unsupported architecture or image');
  }
  const normalized: BuildImageMap = {};
  for (const architecture of architectures) {
    const image = value?.[architecture];
    if (!image) throw new Error(`build image is missing for ${architecture}`);
    assertImageDigest(image);
    normalized[architecture] = image;
  }
  return normalized;
}

function buildManifest(candidate: FactoryCandidate, publicRecipeSha256: string | null) {
  return {
    requestId: candidate.request.id,
    packageName: candidate.request.name,
    version: candidate.version,
    sourceKind: candidate.request.sourceKind,
    sources: candidate.sources,
    dependencies: candidate.dependencies,
    makeDependencies: candidate.makeDependencies ?? [],
    smokeCommands: candidate.smokeCommands,
    architectures: candidate.architectures,
    buildImages: candidate.buildImages ?? {},
    pkgrel: candidate.pkgrel ?? 1,
    sourceDateEpoch: candidate.sourceDateEpoch,
    imageDigest: candidate.imageDigest,
    license: candidate.license,
    surface: candidate.surface,
    description: candidate.description,
    publicRecipeSha256,
  };
}

export async function createFactoryRevision(input: FactoryCandidate, repairAttempts = 0, revisionId?: string): Promise<FactoryRevisionDraft> {
  const candidate = normalizeCandidate(input);
  const recipe = renderRecipe(candidate);
  const lint = lintRecipe(recipe, repairAttempts);
  if (!lint.passed) throw new Error(`generated recipe failed lint: ${lint.checks.filter((check) => !check.passed).map((check) => check.name).join(', ')}`);

  const publicRecipeSha256 = candidate.publicRecipe == null ? null : await sha256(candidate.publicRecipe);
  const manifest = buildManifest(candidate, publicRecipeSha256);
  const stableRevisionId = revisionId ?? crypto.randomUUID();
  const createdAt = now();
  const sbom = standardSbom(candidate, stableRevisionId, createdAt);
  const revision: Revision = {
    id: stableRevisionId,
    request_id: candidate.request.id,
    version: candidate.version,
    recipe,
    recipe_sha256: await sha256(recipe),
    public_recipe: candidate.publicRecipe ?? null,
    public_recipe_sha256: publicRecipeSha256,
    manifest_sha256: '',
    sources_json: JSON.stringify(candidate.sources),
    dependencies_json: JSON.stringify(candidate.dependencies),
    make_dependencies_json: JSON.stringify(candidate.makeDependencies ?? []),
    smoke_commands_json: JSON.stringify(candidate.smokeCommands),
    architectures_json: JSON.stringify(candidate.architectures),
    build_images_json: JSON.stringify(candidate.buildImages ?? {}),
    pkgrel: candidate.pkgrel ?? 1,
    source_date_epoch: candidate.sourceDateEpoch,
    image_digest: candidate.imageDigest,
    license: candidate.license,
    surface: candidate.surface,
    description: candidate.description,
    explanation: candidate.explanation.slice(0, 8_192),
    sbom_json: JSON.stringify(sbom),
    lint_json: JSON.stringify(lint),
    upstream_commit: candidate.upstreamCommit ?? null,
    pr_url: candidate.prUrl ?? null,
    commit_sha: candidate.commitSha ?? null,
    created_at: createdAt,
  };
  revision.manifest_sha256 = await manifestDigest(revision);
  return { revision, manifest, lint };
}

function standardSbom(candidate: FactoryCandidate, revisionId: string, createdAt: number): Record<string, unknown> {
  const packages: Array<Record<string, unknown>> = [];
  const relationships: Array<Record<string, string>> = [];
  type PackageChecksum = { algorithm: 'SHA1' | 'SHA256' | 'SHA512'; checksumValue: string };
  const spdxLicense = (value: unknown): string => {
    if (typeof value !== 'string') return 'NOASSERTION';
    const normalized = value.trim();
    if (!normalized || normalized.toLowerCase() === 'unknown' || normalized.toLowerCase() === 'proprietary' || /(?:^|\b)(?:DocumentRef|LicenseRef)-/i.test(normalized)) return 'NOASSERTION';
    try { return parseDeclaredLicense(normalized); }
    catch { return 'NOASSERTION'; }
  };
  const sriChecksum = (value: unknown): PackageChecksum | undefined => {
    if (typeof value !== 'string') return undefined;
    const match = /^(sha1|sha512)-([A-Za-z0-9+/=]+)$/.exec(value);
    if (!match) return undefined;
    try {
      const bytes = Uint8Array.from(atob(match[2]), (character) => character.charCodeAt(0));
      const algorithm = match[1] === 'sha1' ? 'SHA1' : 'SHA512';
      if ((algorithm === 'SHA1' && bytes.byteLength !== 20) || (algorithm === 'SHA512' && bytes.byteLength !== 64)) return undefined;
      return { algorithm, checksumValue: Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('') };
    } catch { return undefined; }
  };
  const archPurl = (dependency: string): { name: string; version: string; location: string; comment?: string } => {
    const parsed = parseArchDependency(dependency);
    if (!parsed) return { name: dependency, version: 'NOASSERTION', location: 'NOASSERTION' };
    const location = `pkg:alpm/arch/${encodeURIComponent(parsed.name)}${parsed.version ? `@${encodeURIComponent(parsed.version)}` : ''}`;
    return { name: parsed.name, version: parsed.version ?? 'NOASSERTION', location, ...(parsed.operator ? { comment: `OPR Arch dependency constraint: ${dependency}` } : {}) };
  };
  const npmReference = (name: string, version: string): Array<Record<string, string>> => [{
    referenceCategory: 'PACKAGE-MANAGER', referenceType: 'npm',
    referenceLocator: `${name.startsWith('@') ? `%40${name.slice(1)}` : name}@${version}`,
  }];
  const packageId = (): string => {
    const id = `SPDXRef-Package-${packages.length + 1}`;
    return id;
  };
  const addPackage = (input: {
    name: string;
    version: string;
    downloadLocation: string;
    license?: string;
    comment?: string;
    checksum?: PackageChecksum;
    externalRefs?: Array<Record<string, string>>;
  }): string => {
    const id = packageId();
    packages.push({
      SPDXID: id,
      name: input.name,
      versionInfo: input.version,
      downloadLocation: input.downloadLocation,
      filesAnalyzed: false,
      licenseConcluded: spdxLicense(input.license),
      licenseDeclared: spdxLicense(input.license),
      copyrightText: 'NOASSERTION',
      checksums: input.checksum ? [input.checksum] : [],
      ...(input.comment ? { comment: input.comment } : {}),
      ...(input.externalRefs ? { externalRefs: input.externalRefs } : {}),
    });
    return id;
  };

  const mainId = addPackage({
    name: candidate.request.name,
    version: `${candidate.version}-${candidate.pkgrel ?? 1}`,
    downloadLocation: 'NOASSERTION',
    license: candidate.license,
  });
  for (const source of candidate.sources) {
    const sourceId = addPackage({ name: source.name, version: 'NOASSERTION', downloadLocation: source.url, checksum: { algorithm: 'SHA256', checksumValue: source.sha256 } });
    relationships.push({ spdxElementId: mainId, relationshipType: 'GENERATED_FROM', relatedSpdxElement: sourceId });
  }
  for (const dependency of candidate.dependencies) {
    const dependencyValue = archPurl(dependency);
    const dependencyId = addPackage({ name: dependencyValue.name, version: dependencyValue.version, downloadLocation: dependencyValue.location, comment: dependencyValue.comment });
    relationships.push({ spdxElementId: mainId, relationshipType: 'DEPENDS_ON', relatedSpdxElement: dependencyId });
  }
  for (const dependency of candidate.makeDependencies ?? []) {
    const dependencyValue = archPurl(dependency);
    const dependencyId = addPackage({ name: dependencyValue.name, version: dependencyValue.version, downloadLocation: dependencyValue.location, comment: dependencyValue.comment });
    relationships.push({ spdxElementId: dependencyId, relationshipType: 'BUILD_DEPENDENCY_OF', relatedSpdxElement: mainId });
  }

  const supplied = candidate.sbom;
  const vendor = supplied?.vendorBundle;
  if (vendor && typeof vendor === 'object' && !Array.isArray(vendor)) {
    const components = (vendor as { components?: unknown }).components;
    if (Array.isArray(components)) {
      for (const value of components) {
        if (!value || typeof value !== 'object' || Array.isArray(value)) continue;
        const component = value as Record<string, unknown>;
        if (typeof component.name !== 'string' || typeof component.version !== 'string' || typeof component.source !== 'string') continue;
        const checksum = component.checksumAlgorithm === 'SHA256' && typeof component.checksum === 'string' && /^[0-9a-f]{64}$/.test(component.checksum)
          ? { algorithm: 'SHA256' as const, checksumValue: component.checksum } : sriChecksum(component.integrity);
        const comment = component.checksumAlgorithm === 'GO-H1' && typeof component.checksum === 'string'
          ? `OPR Go module checksum (go.sum): ${component.checksum}` : undefined;
        const externalRefs = typeof component.integrity === 'string' ? npmReference(component.name, component.version) : undefined;
        const componentId = addPackage({ name: component.name, version: component.version, downloadLocation: component.source, comment, checksum, externalRefs });
        relationships.push({ spdxElementId: mainId, relationshipType: 'DEPENDS_ON', relatedSpdxElement: componentId });
      }
    }
  }
  const candidateLicense = typeof candidate.license === 'string' ? candidate.license.trim() : '';
  const evidence = {
    ...(supplied ?? {}),
    ...(candidateLicense && spdxLicense(candidateLicense) === 'NOASSERTION' ? { license: candidateLicense } : {}),
    ...(candidate.makeDependencies?.length ? { makeDependencies: candidate.makeDependencies } : {}),
  };
  const comment = Object.keys(evidence).length ? encodeOprEvidence(evidence) : undefined;
  return {
    spdxVersion: 'SPDX-2.3',
    dataLicense: 'CC0-1.0',
    SPDXID: 'SPDXRef-DOCUMENT',
    name: `${candidate.request.name}-${candidate.version}-${candidate.pkgrel ?? 1}`,
    documentNamespace: `https://omapkg.example/spdx/${encodeURIComponent(candidate.request.id)}/${encodeURIComponent(revisionId)}`,
    creationInfo: { created: new Date(createdAt * 1_000).toISOString(), creators: ['Tool: omapkg-factory-0.1.0'] },
    documentDescribes: [mainId],
    packages,
    relationships,
    ...(comment ? { comment } : {}),
  };
}

export async function persistFactoryRevision(
  env: FactoryEnv,
  draft: FactoryRevisionDraft,
  actor = 'factory',
  generationId?: string,
): Promise<FactoryRevisionDraft> {
  const revision = draft.revision;
  if (!revision.pr_url || !revision.commit_sha) {
    throw new Error('generated revision must include its reviewed pull request and head commit');
  }
  const request = await env.DB.prepare('SELECT id, status, factory_run_id FROM requests WHERE id = ?').bind(revision.request_id).first<{ id: string; status: string; factory_run_id: string | null }>();
  if (!request) throw new Error('request not found');
  if (!['pending', 'generating', 'review'].includes(request.status)) throw new Error('request is not accepting a factory revision');
  if (generationId === undefined || request.factory_run_id !== generationId || request.status !== 'generating') {
    const existing = await env.DB.prepare('SELECT * FROM revisions WHERE id=?').bind(revision.id).first<Revision>();
    if (request.status === 'review' && existing && existing.request_id === revision.request_id && existing.manifest_sha256 === revision.manifest_sha256 && existing.recipe_sha256 === revision.recipe_sha256) {
      return { ...draft, revision: existing };
    }
    throw new Error('factory run is no longer current');
  }
  const existing = await env.DB.prepare('SELECT * FROM revisions WHERE id=?').bind(revision.id).first<Revision>();
  if (existing) {
    if (existing.request_id !== revision.request_id || existing.manifest_sha256 !== revision.manifest_sha256 || existing.recipe_sha256 !== revision.recipe_sha256) {
      throw new Error('revision identity is already bound to different content');
    }
    return { ...draft, revision: existing };
  }

  await env.DB.batch([
    env.DB.prepare(`INSERT INTO revisions (
      id, request_id, version, recipe, recipe_sha256, public_recipe, public_recipe_sha256, manifest_sha256, sources_json,
      dependencies_json, make_dependencies_json, smoke_commands_json, architectures_json, build_images_json, pkgrel, source_date_epoch,
      image_digest, license, surface, description, explanation, sbom_json, lint_json,
      upstream_commit, pr_url, commit_sha, created_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
      .bind(
        revision.id, revision.request_id, revision.version, revision.recipe, revision.recipe_sha256,
        revision.public_recipe ?? null, revision.public_recipe_sha256 ?? null, revision.manifest_sha256, revision.sources_json, revision.dependencies_json, revision.make_dependencies_json ?? '[]',
        revision.smoke_commands_json, revision.architectures_json, revision.build_images_json ?? '{}', revision.pkgrel ?? 1, revision.source_date_epoch,
        revision.image_digest, revision.license, revision.surface, revision.description ?? null, revision.explanation,
        revision.sbom_json, revision.lint_json, revision.upstream_commit, revision.pr_url,
        revision.commit_sha, revision.created_at,
      ),
    env.DB.prepare("UPDATE requests SET status = 'review', updated_at = ? WHERE id = ? AND status IN ('pending', 'generating', 'review')")
      .bind(revision.created_at, revision.request_id),
    audit(env.DB, actor, 'factory_revision_created', revision.id, {
      requestId: revision.request_id,
      manifestSha256: revision.manifest_sha256,
      recipeSha256: revision.recipe_sha256,
    }),
  ]);
  return draft;
}

export function assertReviewedRevision(revision: Revision, approvals: readonly Approval[]): void {
  const kinds = new Set(
    approvals
      .filter((approval) => approval.revision_id === revision.id && approval.manifest_sha256 === revision.manifest_sha256 &&
        (approval as Approval & { revoked_at?: number | null }).revoked_at == null)
      .map((approval) => approval.kind),
  );
  if (!kinds.has('area') || !kinds.has('security')) throw new Error('revision requires current area and security approvals');
}

export function sourceKindMatchesUrl(sourceKind: 'git' | 'archive', url: string): boolean {
  return sourceKind === classifySourceUrl(url);
}
