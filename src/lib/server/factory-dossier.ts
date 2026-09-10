import { canonicalJson } from '../canonical-json';
import type { Architecture, Revision } from '../model';
import type { Env } from './env';
import { audit, query, sha256 } from './db';
import { PolicyError } from './policy';
import { redactText } from '../../../services/pipeline/security';
import { assertOutputEvidence, assertStandaloneReproducibilityContract, requireReproducibilityContract, type OutputEvidence } from './output-evidence';
import { reviewedRuntimeExceptions } from './runtime-evidence';
import { decodeBase64, verifyEd25519 } from './worker-protocol';

const SHA256 = /^[a-f0-9]{64}$/;

const RUN_ID = /^[A-Za-z0-9_-]{1,128}$/;

const MAX_EVENTS = 2_000;
const MAX_LOG_ROWS = 2_000;
const MAX_ARTIFACT_ROWS = 4_096;

const MAX_ATTEMPTS = 128;

const MAX_LOG_BYTES = 8_192;

const MAX_JSON_BYTES = 1_048_576;

type JsonObject = Record<string, unknown>;

export type DossierCheckStatus = 'passed' | 'failed' | 'missing' | 'not-applicable';

export interface DossierCheck {
  name: string;
  status: DossierCheckStatus;
  detail: string;
  evidence: string[];
}

export interface DossierOutput {
  filename: string;
  sha256: string | null;
  size: number | null;
  artifactKey: string | null;
  architecture: Architecture;
  attempt: number;
  buildId: string;
  factoryAttemptId?: string;
  evidenceUrl: string;
}

export interface DossierAttempt {
  attempt: number;
  buildIds: string[];
  architectures: Architecture[];
  revisionIds: string[];
  recipeDigests: string[];
  result: 'succeeded' | 'failed' | 'cancelled' | 'in-progress' | 'unknown';
  trigger: string | null;
  changedInputs: string[];
  findings: string[];
  workerIds: string[];
  builderImages: string[];
  runtimeImages: string[];
  outputs: DossierOutput[];
  logs: Array<{ url: string; lines: number; sample: string | null; truncated: boolean }>;
  startedAt: number | null;
  finishedAt: number | null;
}

export interface DossierImageDefinition {
  id: string | null;
  architecture: Architecture;
  imageRef: string;
  digest: string;
  enabled: boolean | null;
  isDefault: boolean | null;
  createdAt: number | null;
}

export interface FactoryDossier {
  schemaVersion: 1;
  kind: 'factory-package-dossier';
  id: string;
  identity: {
    requestId: string;
    runId: string;
    revisionId: string;
    recipeSha256: string;
    manifestSha256: string;
    createdAt: number;
  };
  request: {
    id: string;
    name: string;
    status: string;
    area: string;
    sourceKind: string;
    upstreamUrl: string;
    upstreamRef: string | null;
    requestedBy: string;
  };
  revision: {
    id: string;
    version: string;
    pkgrel: number | null;
    recipe: string;
    recipeSha256: string;
    manifestSha256: string;
    sources: unknown[];
    dependencies: unknown[];
    makeDependencies: unknown[];
    smokeCommands: unknown[];
    architectures: string[];
    buildImages: JsonObject;
    sourceDateEpoch: number;
    imageDigest: string;
    license: string;
    surface: string;
    description: string | null;
    explanation: string;
    sbom: unknown;
    lint: unknown;
    upstreamCommit: string | null;
    pullRequestUrl: string | null;
    commitSha: string | null;
  };
  authoring: {
    buildSystem: string | null;
    template: string | null;
    templateVersion: string | number | null;
    rationale: string;
  };
  imageDefinitions: DossierImageDefinition[];
  inputs: {
    sourceDigests: string[];
    dependencyLocks: string[];
    builderImages: JsonObject;
    supportingFilesDigest: string;
  };
  attempts: DossierAttempt[];
  outputs: DossierOutput[];
  checks: DossierCheck[];
  rationale: Array<{ attributedTo: string; text: string }>;
  modelUsage: {
    model: string | null;
    durationMs: number | null;
    inputTokens: number | null;
    outputTokens: number | null;
    cost: number | null;
    availability: 'measured' | 'unavailable';
  };
  reviews: Array<{ kind: string; actor: string; manifestSha256: string; currentAtSnapshot: boolean; evidenceAsOfAt: number; createdAt: number; revokedAt: number | null }>;
  blockers: Array<{ id: string; status: string; reason: string }>;
  publication: {
    published: boolean;
    releases: Array<{ id: string; channel: string; architecture: string; artifactSha256: string | null; publishedAt: number }>;
  };
  evidence: {
    evidenceAsOfAt: number;
    latestRecordedAt: number;
    reviewsAuthority: 'historical-snapshot';
    eventCount: number;
    eventsTruncated: boolean;
    events: Array<{ stage: string; createdAt: number; detail: JsonObject }>;
    auditUrl: string;
    attemptEvidenceComplete: boolean;
  };
}

export interface StoredFactoryDossier {
  dossier: FactoryDossier;
  canonicalJson: string;
  canonicalSha256: string;
  markdown: string;
  markdownSha256: string;
}

interface RequestRow {
  id: string;
  name: string;
  status: string;
  area: string;
  source_kind: string;
  upstream_url: string;
  upstream_ref?: string | null;
  requested_by: string;
  factory_run_id: string | null;
}

interface RevisionRow extends Revision {
  make_dependencies_json?: string | null;
  build_images_json?: string | null;
  pkgrel?: number | null;
  public_recipe?: string | null;
  public_recipe_sha256?: string | null;
}

interface BuildRow {
  id: string;
  revision_id: string;
  architecture: Architecture;
  status: 'queued' | 'leased' | 'succeeded' | 'failed' | 'cancelled';
  worker_id: string | null;
  attempt: number;
  artifact_key: string | null;
  artifact_sha256: string | null;
  artifact_size: number | null;
  artifact_filename: string | null;
  provenance: string | null;
  provenance_signature?: string | null;
  factory_run_id?: string | null;
  factory_attempt?: number | null;
  smoke_passed: number;
  error: string | null;
  created_at: number;
  started_at: number | null;
  finished_at: number | null;
  input_lock_sha256?: string | null;
  output_contract_json?: string | null;
}

interface AttemptRow {
  build_id: string;
  attempt: number;
  revision_id: string;
  architecture: Architecture;
  started_at: number;
  input_lock_sha256?: string | null;
}

interface AttemptResultRow {
  build_id: string;
  attempt: number;
  status: 'succeeded' | 'failed';
  error: string | null;
  finished_at: number;
}

interface FactoryRunAttemptRow {
  id: string;
  attempt: number;
  status: 'running' | 'succeeded' | 'failed';
  candidate_revision_id: string | null;
  candidate_recipe_sha256: string | null;
  candidate_sha256: string;
  input_sha256: string;
  architecture: Architecture | null;
  candidate_json: string;
  failure_kind: string | null;
  failure_json: string | null;
  artifact_json: string | null;
  started_at: number;
  finished_at: number | null;
  created_at: number;
  updated_at: number;
}

interface ArtifactRow {
  build_id: string;
  attempt: number;
  filename: string;
  artifact_key: string;
  sha256: string;
  size: number;
}

interface LogRow {
  build_id: string;
  attempt: number;
  sequence: number;
  text: string;
}

interface EventRow {
  stage: string;
  detail: string;
  created_at: number;
}

interface ApprovalRow {
  kind: string;
  actor: string;
  manifest_sha256: string;
  revoked_at?: number | null;
  created_at: number;
}

interface ReleaseRow {
  id: string;
  channel: string;
  architecture: string;
  artifact_sha256: string | null;
  published_at: number;
}

function parseValue(value: string | null | undefined, fallback: unknown): unknown {
  if (!value) return fallback;

  try { return JSON.parse(value); } catch { return fallback; }
}

function objectValue(value: unknown): JsonObject {
  return value && typeof value === 'object' && !Array.isArray(value) ? value as JsonObject : {};
}

function arrayValue(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

function textValue(value: unknown, fallback = ''): string {
  return typeof value === 'string' ? redactText(value).slice(0, 8_192) : fallback;
}

function boundedInteger(value: unknown): number | null {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 ? value : null;
}

function digest(value: unknown): string | null {
  return typeof value === 'string' && SHA256.test(value) ? value : null;
}

function safeDetail(value: unknown, depth = 0): unknown {
  if (depth > 4) return '[redacted: depth limit]';

  if (typeof value === 'string') return redactText(value).slice(0, 2_000);

  if (Array.isArray(value)) return value.slice(0, 64).map((item) => safeDetail(item, depth + 1));

  if (!value || typeof value !== 'object') return value;
  const output: JsonObject = {};

  for (const key of Object.keys(value as JsonObject).sort()) {
    if (/prompt|credential|secret|password|token|authorization|private.?key|source.?content|raw.?log/i.test(key)) continue;
    output[key] = safeDetail((value as JsonObject)[key], depth + 1);
  }

  return output;
}

function parseDetail(value: string): JsonObject {
  const parsed = parseValue(value, { message: value });
  const safe = safeDetail(parsed);

  return objectValue(safe);
}

function evidenceLink(buildId: string, attempt: number, filename?: string): string {
  const suffix = filename ? `?attempt=${attempt}&filename=${encodeURIComponent(filename)}` : `?attempt=${attempt}`;

  return `/maintain/builds/${encodeURIComponent(buildId)}${suffix}`;
}

function markdownText(value: unknown): string {
  return String(value ?? '—').replace(/[\\`*_{}[\]()#+!|<>]/g, '\\$&').replace(/[\r\n]+/g, ' ');
}

function markdownCode(value: string): string {
  const longest = Math.max(2, ...value.match(/`+/g)?.map((run) => run.length + 1) ?? [3]);
  const fence = '`'.repeat(longest);

  return `${fence}\n${value}\n${fence}`;
}

function check(name: string, status: DossierCheckStatus, detail: string, evidence: string[] = []): DossierCheck {
  return { name, status, detail: redactText(detail).slice(0, 2_000), evidence: [...new Set(evidence)].sort() };
}

function resultStatus(build: BuildRow | undefined, result: AttemptResultRow | undefined): DossierAttempt['result'] {
  if (result) return result.status;

  if (build?.status === 'cancelled') return 'cancelled';

  if (build?.status === 'leased' || build?.status === 'queued') return 'in-progress';

  return build?.status ?? 'unknown';
}

async function provenanceChecks(env: Env, build: BuildRow, output: DossierOutput[], revision: RevisionRow): Promise<DossierCheck[]> {
  const provenance = objectValue(parseValue(build.provenance, null));
  const evidence = [evidenceLink(build.id, build.attempt)];
  let report: OutputEvidence | null = null;
  let standaloneValid = false;
  let evidenceError = '';
  try {
    if (build.provenance && provenance.schemaVersion === 2) report = await assertOutputEvidence(JSON.parse(build.provenance), reviewedRuntimeExceptions(revision.sbom_json));
    else if (build.provenance && build.status === 'succeeded') {
      const factoryInput = build.factory_run_id && build.factory_attempt ? await env.DB.prepare('SELECT input_sha256 FROM factory_run_attempts WHERE run_id=? AND attempt=?').bind(build.factory_run_id, build.factory_attempt).first<{ input_sha256: string }>() : null;
      const artifact = output.length === 1 && output[0].sha256 && output[0].size !== null ? { filename: output[0].filename, size: output[0].size!, sha256: output[0].sha256 } : undefined;
      await assertStandaloneReproducibilityContract(provenance.reproducibility, {
        architecture: build.architecture, recipeSha256: revision.recipe_sha256, imageDigest: String(provenance.imageDigest), sourceDateEpoch: revision.source_date_epoch,
        sources: parseValue(revision.sources_json, []), inputLockSha256: build.input_lock_sha256 ?? '', dependencyPlan: provenance.dependencyPlan ?? undefined,
        ...(artifact ? { output: artifact } : {}), ...(build.factory_run_id && build.factory_attempt && factoryInput ? { factoryRunId: build.factory_run_id, factoryAttempt: build.factory_attempt, factoryInputSha256: factoryInput.input_sha256 } : {}),
      });
      standaloneValid = true;
    }
  } catch (cause) { evidenceError = cause instanceof Error ? cause.message : 'Build evidence is invalid.'; }
  let signed = false;
  if ((report || standaloneValid) && build.provenance_signature && build.worker_id) {
    try {
      const worker = await env.DB.prepare('SELECT public_key,status FROM workers WHERE id=?').bind(build.worker_id).first<{ public_key: string; status: string }>();
      signed = Boolean(worker && worker.status === 'active' && await verifyEd25519(decodeBase64(worker.public_key, 'worker public key'), new TextEncoder().encode(build.provenance!), decodeBase64(build.provenance_signature, 'provenance signature')));
    } catch { signed = false; }
  }
  const factualEvidence = Boolean((report || standaloneValid) && signed);
  let reproducibilityVerified = false;
  if (report) {
    try { await requireReproducibilityContract(report); reproducibilityVerified = true; } catch { reproducibilityVerified = false; }
  }
  const artifactEvidenceMatches = standaloneValid || Boolean(report && report.outputs.length === output.length && report.outputs.every((item) => {
    const artifact = output.find((candidate) => candidate.filename === item.filename);
    return Boolean(artifact && artifact.sha256 === item.artifactSha256 && (artifact.size === null || artifact.size === item.packageMetadata.installedSize || artifact.size > 0));
  }));
  if (!artifactEvidenceMatches) evidenceError ||= 'Signed output evidence does not match retained artifact records.';
  const signedEvidence = factualEvidence && artifactEvidenceMatches;
  const packageEvidence = Boolean(report?.outputs.length || (standaloneValid && Object.keys(objectValue(provenance.packageMetadata)).length));
  const runtimeEvidence = Boolean(report?.runtimeTests.length || (standaloneValid && provenance.runtimeEnvironment && provenance.runtimeAnalysis));
  const smokeEvidence = standaloneValid ? build.smoke_passed === 1 : Boolean(report?.runtimeTests.length && report.runtimeTests.every((test) => test.smokePassed === true));

  const checks: DossierCheck[] = [
    check('build', build.status === 'succeeded' ? 'passed' : build.status === 'failed' || build.status === 'cancelled' ? 'failed' : 'missing',
      build.status === 'succeeded' ? 'Worker reported a successful build.' : build.error ?? `Build is ${build.status}.`, evidence),
    check('worker-attestation', signedEvidence ? 'passed' : build.status === 'succeeded' ? 'missing' : 'failed', signedEvidence ? 'Worker-signed output evidence is valid.' : evidenceError || 'Worker-signed output evidence is unavailable.', evidence),
    check('package-analysis', signedEvidence && packageEvidence ? 'passed' : 'missing',
      signedEvidence && packageEvidence ? 'Worker evidence contains package metadata for every output.' : 'Package-analysis evidence is unavailable or invalid.', evidence),
    check('clean-install', signedEvidence && runtimeEvidence ? 'passed' : 'missing',
      signedEvidence && runtimeEvidence ? 'Worker evidence contains the runtime test matrix.' : 'Clean-install evidence is unavailable or invalid.', evidence),
    check('smoke', signedEvidence && runtimeEvidence && smokeEvidence ? 'passed' : build.status === 'succeeded' ? 'missing' : 'failed',
      signedEvidence && runtimeEvidence && smokeEvidence ? 'Recorded smoke checks passed in signed worker evidence.' : 'Smoke result is missing or invalid.', evidence),
    check('reproducibility-contract', signedEvidence && (reproducibilityVerified || standaloneValid) ? 'passed' : 'missing',
      signedEvidence && (reproducibilityVerified || standaloneValid) ? 'Signed single-build reproducibility contract evidence is valid.' : 'Reproducibility-contract evidence is unavailable or invalid.', evidence),
  ];

  const contract = objectValue(parseValue(build.output_contract_json, null));
  const expectedOutputs = arrayValue(contract.outputs).map((value) => {
    const item = objectValue(value);

    return typeof item.name === 'string' && typeof item.fullVersion === 'string' && typeof item.architecture === 'string'
      ? `${item.name}-${item.fullVersion}-${item.architecture}.pkg.tar.zst` : null;
  }).filter((value): value is string => value !== null);

  if (expectedOutputs.length) {
    const actual = new Set(output.map((item) => item.filename));
    const complete = expectedOutputs.length === actual.size && expectedOutputs.every((filename) => actual.has(filename));
    checks.push(check('output-set', complete ? 'passed' : 'missing', complete ? 'Every declared split output was retained.' : 'Declared split outputs and retained artifacts differ.', evidence));
  } else {
    checks.push(check('output-set', 'not-applicable', 'No multi-output contract was recorded.', evidence));
  }

  if (!output.length && build.status === 'succeeded') checks[1] = check('package-analysis', 'missing', 'No output records were retained.', evidence);

  return checks;
}

function modelUsage(events: FactoryDossier['evidence']['events']): FactoryDossier['modelUsage'] {
  const values = events.map((event) => event.detail).filter((detail) => detail.model || detail.modelId || detail.requestedModel);
  const detail = values.at(-1) ?? {};
  const model = typeof detail.model === 'string' ? detail.model : typeof detail.modelId === 'string' ? detail.modelId : typeof detail.requestedModel === 'string' ? detail.requestedModel : null;
  const durationMs = boundedInteger(detail.durationMs ?? detail.duration);
  const inputTokens = boundedInteger(detail.inputTokens ?? detail.promptTokens);
  const outputTokens = boundedInteger(detail.outputTokens ?? detail.completionTokens);
  const cost = typeof detail.cost === 'number' && Number.isFinite(detail.cost) && detail.cost >= 0 ? detail.cost : null;

  return { model, durationMs, inputTokens, outputTokens, cost, availability: model || durationMs !== null || inputTokens !== null || outputTokens !== null || cost !== null ? 'measured' : 'unavailable' };
}

function publicProjection(dossier: FactoryDossier): Record<string, unknown> {
  const publishedHashes = new Set(dossier.publication.releases.map((release) => release.artifactSha256).filter((value): value is string => Boolean(value)));
  const publicOutput = (output: DossierOutput) => ({ filename: output.filename, sha256: output.sha256, size: output.size, architecture: output.architecture, attempt: output.attempt,
    ...(output.buildId ? { buildId: output.buildId } : {}) });
  const publicOutputs = (outputs: DossierOutput[]) => publishedHashes.size ? outputs.filter((output) => output.sha256 !== null && publishedHashes.has(output.sha256)).map(publicOutput) : [];
  const publicSource = (source: unknown) => {
    const item = objectValue(source);
    return { ...(typeof item.name === 'string' ? { name: item.name } : {}), ...(digest(item.sha256) ? { sha256: item.sha256 } : {}) };
  };
  return {
    schemaVersion: dossier.schemaVersion,
    kind: dossier.kind,
    id: dossier.id,
    identity: dossier.identity,
    request: {
      id: dossier.request.id,
      name: dossier.request.name,
      area: dossier.request.area,
      sourceKind: dossier.request.sourceKind,
      upstreamUrl: dossier.request.upstreamUrl,
      upstreamRef: dossier.request.upstreamRef,
    },
    revision: {
      id: dossier.revision.id,
      version: dossier.revision.version,
      pkgrel: dossier.revision.pkgrel,
      recipeSha256: dossier.revision.recipeSha256,
      manifestSha256: dossier.revision.manifestSha256,
      sources: dossier.revision.sources.map(publicSource),
      dependencies: dossier.revision.dependencies.filter((value) => typeof value === 'string' && !/https?:\/\//i.test(value)),
      architectures: dossier.revision.architectures,
      sourceDateEpoch: dossier.revision.sourceDateEpoch,
      imageDigest: dossier.revision.imageDigest,
      license: dossier.revision.license,
      surface: dossier.revision.surface,
      description: dossier.revision.description,
      upstreamCommit: dossier.revision.upstreamCommit,
    },
    authoring: {
      buildSystem: dossier.authoring.buildSystem,
      template: dossier.authoring.template,
      templateVersion: dossier.authoring.templateVersion,
    },
    imageDefinitions: dossier.imageDefinitions.map(({ architecture, digest }) => ({ architecture, digest })),
    attempts: dossier.attempts.map(({ attempt, architectures, result, outputs, startedAt, finishedAt }) => ({
      attempt, architectures, result,
      outputs: publicOutputs(outputs),
      startedAt, finishedAt,
    })),
    outputs: publicOutputs(dossier.outputs),
    checks: dossier.checks.map(({ name, status }) => ({ name, status })),
    reviews: dossier.reviews.map(({ kind, manifestSha256, currentAtSnapshot, evidenceAsOfAt, createdAt, revokedAt }) => ({ kind, manifestSha256, currentAtSnapshot, evidenceAsOfAt, createdAt, revokedAt, authority: 'historical-snapshot' })),
    publication: dossier.publication,
    evidence: { evidenceAsOfAt: dossier.evidence.evidenceAsOfAt, latestRecordedAt: dossier.evidence.latestRecordedAt, reviewsAuthority: dossier.evidence.reviewsAuthority, eventCount: dossier.evidence.eventCount, eventsTruncated: dossier.evidence.eventsTruncated, attemptEvidenceComplete: dossier.evidence.attemptEvidenceComplete },
  };
}

export function factoryDossierPublicProjection(dossier: FactoryDossier): Record<string, unknown> {
  if (!dossier.publication.published) throw new PolicyError(404, 'Public dossier is unavailable until publication.');

  return publicProjection(dossier);
}

export async function publishedFactoryDossier(env: Env, stored: StoredFactoryDossier): Promise<FactoryDossier> {
  const releases = await query<ReleaseRow>(env.DB, `SELECT DISTINCT r.id,r.channel,r.architecture,b.artifact_sha256,r.published_at
    FROM releases r JOIN builds b ON b.id=r.build_id WHERE b.revision_id=? AND r.channel IN ('stable','withdrawn') ORDER BY r.published_at,r.id`, stored.dossier.identity.revisionId);
  if (!releases.length) throw new PolicyError(404, 'Public dossier is unavailable until publication.');
  return { ...stored.dossier, publication: { published: true, releases: releases.map((release) => ({ id: release.id, channel: release.channel, architecture: release.architecture,
    artifactSha256: release.artifact_sha256, publishedAt: release.published_at })) } };
}

export function factoryDossierCanonicalJson(dossier: FactoryDossier): string {
  const json = canonicalJson(dossier);

  if (new TextEncoder().encode(json).byteLength > MAX_JSON_BYTES) throw new PolicyError(413, 'Factory dossier exceeds the export size limit.');

  return json;
}

export function factoryDossierPublicCanonicalJson(dossier: FactoryDossier): string {
  return canonicalJson(factoryDossierPublicProjection(dossier));
}

export function factoryDossierMarkdown(dossier: FactoryDossier, publicOnly = false): string {
  const value: Record<string, unknown> = publicOnly ? factoryDossierPublicProjection(dossier) : dossier as unknown as Record<string, unknown>;
  const revision = objectValue(value.revision);
  const images = arrayValue(value.imageDefinitions).map(objectValue);
  const identity = objectValue(value.identity);
  const attempts = arrayValue(value.attempts).map(objectValue);
  const outputs = arrayValue(value.outputs).map(objectValue);
  const checks = arrayValue(value.checks).map(objectValue);

  const lines = [
    `# Factory dossier: ${markdownText(objectValue(value.request).name ?? identity.revisionId)}`,
    '',
    `- Dossier: \`${markdownText(value.id)}\``,
    `- Request: \`${markdownText(identity.requestId)}\``,
    `- Run: \`${markdownText(identity.runId)}\``,
    `- Revision: \`${markdownText(identity.revisionId)}\``,
    `- Recipe SHA-256: \`${markdownText(identity.recipeSha256)}\``,
    `- Manifest SHA-256: \`${markdownText(identity.manifestSha256)}\``,
    '',
    '## Revision',
    '',
    `- Version: ${markdownText(revision.version)}`,
    `- License: ${markdownText(revision.license)}`,
    `- Surface: ${markdownText(revision.surface)}`,
    `- Architectures: ${arrayValue(revision.architectures).map(markdownText).join(', ') || '—'}`,
    `- Upstream commit: ${markdownText(revision.upstreamCommit)}`,
    '',
    '## Builder images',
    '',
    '| Architecture | Image | Digest |',
    '| --- | --- | --- |',
    ...images.map((image) => `| ${markdownText(image.architecture)} | ${markdownText(image.imageRef)} | ${markdownText(image.digest)} |`),
    ...(images.length ? [] : ['| — | unavailable | — |']),
    '',
    '## Attempts',
    '',
    '| Attempt | Result | Revisions | Architectures | Outputs |',
    '| ---: | --- | --- | --- | ---: |',
    ...attempts.map((attempt) => `| ${markdownText(attempt.attempt)} | ${markdownText(attempt.result)} | ${arrayValue(attempt.revisionIds).map(markdownText).join(', ') || '—'} | ${arrayValue(attempt.architectures).map(markdownText).join(', ') || '—'} | ${arrayValue(attempt.outputs).length} |`),
    ...(attempts.length ? [] : ['| — | missing | — | — | 0 |']),
    '',
    '## Outputs',
    '',
    '| File | Architecture | Attempt | SHA-256 | Size |',
    '| --- | --- | ---: | --- | ---: |',
    ...outputs.map((output) => `| ${markdownText(output.filename)} | ${markdownText(output.architecture)} | ${markdownText(output.attempt)} | ${markdownText(output.sha256)} | ${markdownText(output.size)} |`),
    ...(outputs.length ? [] : ['| — | — | — | missing | — |']),
    '',
    '## Checks',
    '',
    ...checks.map((item) => `- ${markdownText(item.name)}: **${markdownText(item.status)}** — ${markdownText(item.detail)}`),
    ...(checks.length ? [] : ['- No check records were retained.']),
  ];

  if (!publicOnly) {
    lines.push('', '## Recipe', '', markdownCode(dossier.revision.recipe), '', '## Rationale', '',
      ...dossier.rationale.map((item) => `- ${markdownText(item.attributedTo)}: ${markdownText(item.text)}`),
      ...(dossier.rationale.length ? [] : ['- unavailable']),
      '', '## Evidence links', '', `- Audit: ${markdownText(dossier.evidence.auditUrl)}`);
  }

  return `${lines.join('\n')}\n`;
}

async function loadDossierRows(env: Env, requestId: string, revisionId: string) {
  const request = await env.DB.prepare(`SELECT id,name,status,area,source_kind,upstream_url,upstream_ref,requested_by,factory_run_id
    FROM requests WHERE id=?`).bind(requestId).first<RequestRow>();

  if (!request) throw new PolicyError(404, 'Factory request not found.');
  const revision = await env.DB.prepare('SELECT * FROM revisions WHERE id=? AND request_id=?').bind(revisionId, requestId).first<RevisionRow>();

  if (!revision) throw new PolicyError(404, 'Factory revision not found.');
  const builds = await query<BuildRow>(env.DB, 'SELECT * FROM builds WHERE revision_id=? ORDER BY architecture,id', revisionId);
  const attempts = await query<AttemptRow>(env.DB, 'SELECT build_id,attempt,revision_id,architecture,started_at,input_lock_sha256 FROM build_attempts WHERE build_id IN (SELECT id FROM builds WHERE revision_id=?) ORDER BY attempt,architecture,build_id', revisionId);
  const results = await query<AttemptResultRow>(env.DB, 'SELECT build_id,attempt,status,error,finished_at FROM build_attempt_results WHERE build_id IN (SELECT id FROM builds WHERE revision_id=?) ORDER BY attempt,build_id', revisionId);
  const artifacts = await query<ArtifactRow>(env.DB, 'SELECT build_id,attempt,filename,artifact_key,sha256,size FROM build_artifacts WHERE build_id IN (SELECT id FROM builds WHERE revision_id=?) ORDER BY attempt,build_id,filename LIMIT ?', revisionId, MAX_ARTIFACT_ROWS);
  const logs = await query<LogRow>(env.DB, 'SELECT build_id,attempt,sequence,text FROM build_logs WHERE build_id IN (SELECT id FROM builds WHERE revision_id=?) ORDER BY attempt,build_id,sequence LIMIT ?', revisionId, MAX_LOG_ROWS);
  const events = await query<EventRow>(env.DB, 'SELECT stage,detail,created_at FROM factory_events WHERE request_id=? ORDER BY id LIMIT ?', requestId, MAX_EVENTS);
  const approvals = await query<ApprovalRow>(env.DB, 'SELECT kind,actor,manifest_sha256,revoked_at,created_at FROM approvals WHERE revision_id=? ORDER BY created_at,kind,actor', revisionId);

  const releases = await query<ReleaseRow>(env.DB, `SELECT DISTINCT r.id,r.channel,r.architecture,b.artifact_sha256,r.published_at
    FROM releases r JOIN builds b ON b.id=r.build_id WHERE b.revision_id=? ORDER BY r.published_at,r.id`, revisionId);

  const blockers = await query<{ id: string; status: string; reason: string }>(env.DB, 'SELECT id,status,COALESCE(detail,\'\') AS reason FROM dependency_blockers WHERE request_id=? ORDER BY id', requestId);

  return { request, revision, builds, attempts, results, artifacts, logs, events, approvals, releases, blockers };
}

function dossierAttemptData(rows: Awaited<ReturnType<typeof loadDossierRows>>, runAttempts: FactoryRunAttemptRow[] = [], fallbackEvidenceUrl = '/maintain/dossiers'): DossierAttempt[] {
  const byAttempt = new Map<number, DossierAttempt>();
  const builds = new Map(rows.builds.map((build) => [build.id, build]));
  const results = new Map(rows.results.map((result) => [`${result.build_id}:${result.attempt}`, result]));
  const artifactsByBuild = new Map<string, DossierOutput[]>();

  for (const artifact of rows.artifacts) {
    const build = builds.get(artifact.build_id);

    if (!build || !SHA256.test(artifact.sha256)) continue;

    const output: DossierOutput = { filename: artifact.filename, sha256: artifact.sha256, size: artifact.size, artifactKey: artifact.artifact_key,
      architecture: build.architecture, attempt: artifact.attempt, buildId: artifact.build_id, evidenceUrl: evidenceLink(artifact.build_id, artifact.attempt, artifact.filename) };

    const list = artifactsByBuild.get(artifact.build_id) ?? []; list.push(output); artifactsByBuild.set(artifact.build_id, list);
  }

  for (const build of rows.builds) {
    if (build.attempt <= 0) continue;
    const key = `${build.id}:${build.attempt}`;

    if (!artifactsByBuild.has(build.id) && build.artifact_filename && digest(build.artifact_sha256)) {
      artifactsByBuild.set(build.id, [{ filename: build.artifact_filename, sha256: build.artifact_sha256, size: build.artifact_size, artifactKey: build.artifact_key,
        architecture: build.architecture, attempt: build.attempt, buildId: build.id, evidenceUrl: evidenceLink(build.id, build.attempt, build.artifact_filename) }]);
    }

    const attempt = byAttempt.get(build.attempt) ?? { attempt: build.attempt, buildIds: [], architectures: [], revisionIds: [], recipeDigests: [], result: 'unknown', trigger: null,
      changedInputs: [], findings: [], workerIds: [], builderImages: [], runtimeImages: [], outputs: [], logs: [], startedAt: null, finishedAt: null };

    attempt.buildIds.push(build.id);

 if (!attempt.architectures.includes(build.architecture)) attempt.architectures.push(build.architecture);

    if (!attempt.revisionIds.includes(build.revision_id)) attempt.revisionIds.push(build.revision_id);
    const result = results.get(key);
    attempt.result = resultStatus(build, result);
    attempt.startedAt = attempt.startedAt === null ? build.started_at : Math.min(attempt.startedAt ?? build.started_at ?? Infinity, build.started_at ?? Infinity);

    if (result?.finished_at !== undefined) attempt.finishedAt = Math.max(attempt.finishedAt ?? 0, result.finished_at);
    attempt.outputs.push(...(artifactsByBuild.get(build.id) ?? []));

    if (build.worker_id) attempt.workerIds.push(build.worker_id);
    const provenance = objectValue(parseValue(build.provenance, null));
    const builder = objectValue(provenance.buildEnvironment);
    const runtime = objectValue(provenance.runtimeEnvironment);

    if (typeof builder.baseImage === 'string') attempt.builderImages.push(builder.baseImage);

    if (typeof runtime.baseImage === 'string') attempt.runtimeImages.push(runtime.baseImage);
    byAttempt.set(build.attempt, attempt);
  }

  for (const row of rows.attempts) {
    if (row.attempt <= 0 || row.attempt > MAX_ATTEMPTS) continue;

    const attempt = byAttempt.get(row.attempt) ?? { attempt: row.attempt, buildIds: [], architectures: [], revisionIds: [], recipeDigests: [], result: 'unknown', trigger: null,
      changedInputs: [], findings: [], workerIds: [], builderImages: [], runtimeImages: [], outputs: [], logs: [], startedAt: row.started_at, finishedAt: null };

    if (!attempt.buildIds.includes(row.build_id)) attempt.buildIds.push(row.build_id);

    if (!attempt.architectures.includes(row.architecture)) attempt.architectures.push(row.architecture);

    if (!attempt.revisionIds.includes(row.revision_id)) attempt.revisionIds.push(row.revision_id);

    if (row.input_lock_sha256) attempt.changedInputs.push(row.input_lock_sha256);
    attempt.startedAt = attempt.startedAt ?? row.started_at;
    byAttempt.set(row.attempt, attempt);
  }

  for (const row of runAttempts) {
    if (row.attempt <= 0 || row.attempt > MAX_ATTEMPTS) continue;

    const attempt = byAttempt.get(row.attempt) ?? { attempt: row.attempt, buildIds: [], architectures: [], revisionIds: [], recipeDigests: [], result: 'unknown', trigger: null,
      changedInputs: [], findings: [], workerIds: [], builderImages: [], runtimeImages: [], outputs: [], logs: [], startedAt: row.started_at, finishedAt: row.finished_at };

    attempt.result = row.status === 'running' ? 'in-progress' : row.status;
    attempt.startedAt = attempt.startedAt ?? row.started_at;
    attempt.finishedAt = row.finished_at ?? attempt.finishedAt;

    if (row.architecture && !attempt.architectures.includes(row.architecture)) attempt.architectures.push(row.architecture);

    if (row.candidate_revision_id) attempt.revisionIds.push(row.candidate_revision_id);

    if (SHA256.test(row.candidate_recipe_sha256 ?? '')) attempt.recipeDigests.push(row.candidate_recipe_sha256 as string);
    else if (SHA256.test(row.candidate_sha256)) attempt.recipeDigests.push(row.candidate_sha256);

    if (SHA256.test(row.input_sha256)) attempt.changedInputs.push(row.input_sha256);
    attempt.trigger ??= row.failure_kind;
    const failure = objectValue(parseValue(row.failure_json, null));

    for (const key of ['reason', 'error', 'message', 'detail']) if (typeof failure[key] === 'string') attempt.findings.push(textValue(failure[key]));
    const artifact = objectValue(parseValue(row.artifact_json, null));
    const artifactValues = arrayValue(artifact.outputs ?? artifact.output ?? (artifact.filename ? [artifact] : []));

    for (const value of artifactValues) {
      const item = objectValue(value);

      const artifactDigest = digest(item.sha256);
      if (typeof item.filename !== 'string' || !artifactDigest || typeof item.size !== 'number' || !Number.isSafeInteger(item.size) || item.size < 1) continue;
      const architecture = item.architecture === 'aarch64' ? 'aarch64' : 'x86_64';
      attempt.outputs.push({ filename: item.filename, sha256: artifactDigest, size: item.size, artifactKey: typeof item.artifactKey === 'string' ? item.artifactKey : null,
        architecture, attempt: row.attempt, buildId: '', factoryAttemptId: row.id, evidenceUrl: fallbackEvidenceUrl });
    }

    byAttempt.set(row.attempt, attempt);
  }

  for (const event of rows.events) {
    const detail = parseDetail(event.detail);
    const attemptNumber = boundedInteger(detail.attempt);

    if (!attemptNumber || attemptNumber <= 0 || attemptNumber > MAX_ATTEMPTS) continue;

    const attempt = byAttempt.get(attemptNumber) ?? { attempt: attemptNumber, buildIds: [], architectures: [], revisionIds: [], recipeDigests: [], result: 'unknown', trigger: null,
      changedInputs: [], findings: [], workerIds: [], builderImages: [], runtimeImages: [], outputs: [], logs: [], startedAt: null, finishedAt: null };

    attempt.trigger ??= event.stage;

    for (const key of ['reason', 'error', 'finding', 'message']) if (typeof detail[key] === 'string') attempt.findings.push(textValue(detail[key]));

    for (const key of ['inputLockSha256', 'manifestSha256', 'sourceSha256']) if (digest(detail[key])) attempt.changedInputs.push(detail[key] as string);

    for (const key of ['revisionId', 'candidateRevisionId']) if (typeof detail[key] === 'string') attempt.revisionIds.push(detail[key] as string);

    for (const key of ['recipeSha256', 'candidateRecipeSha256']) if (digest(detail[key])) attempt.recipeDigests.push(detail[key] as string);
    byAttempt.set(attemptNumber, attempt);
  }

  for (const log of rows.logs) {
    const attempt = byAttempt.get(log.attempt);

 if (!attempt) continue;
    const sample = redactText(log.text).slice(0, MAX_LOG_BYTES);
    const current = attempt.logs.find((item) => item.url === evidenceLink(log.build_id, log.attempt));

    if (current) {
      current.lines += 1;

      if (current.sample && current.sample.length < MAX_LOG_BYTES) current.sample = `${current.sample}\n${sample}`.slice(0, MAX_LOG_BYTES);
      current.truncated ||= sample.length < log.text.length;
    } else {
      attempt.logs.push({ url: evidenceLink(log.build_id, log.attempt), lines: 1, sample, truncated: sample.length < log.text.length });
    }
  }

  return [...byAttempt.values()].sort((a, b) => a.attempt - b.attempt).map((attempt) => ({
    ...attempt,
    buildIds: [...new Set(attempt.buildIds)].sort(), architectures: [...new Set(attempt.architectures)].sort(), revisionIds: [...new Set(attempt.revisionIds)].sort(),
    recipeDigests: [...new Set(attempt.recipeDigests)].sort(), changedInputs: [...new Set(attempt.changedInputs)].sort(), findings: [...new Set(attempt.findings)].sort(),
    workerIds: [...new Set(attempt.workerIds)].sort(), builderImages: [...new Set(attempt.builderImages)].sort(), runtimeImages: [...new Set(attempt.runtimeImages)].sort(),
    outputs: attempt.outputs.sort((a, b) => a.filename.localeCompare(b.filename) || a.buildId.localeCompare(b.buildId)),
    logs: attempt.logs.sort((a, b) => a.url.localeCompare(b.url)),
  }));
}

async function resolveFactoryDossierRunId(env: Env, request: RequestRow, revisionId: string): Promise<string> {
  const candidates = new Set<string>();
  const rows = await query<{ id: string }>(env.DB, `SELECT DISTINCT r.id FROM factory_runs r
    LEFT JOIN factory_run_attempts a ON a.run_id=r.id
    WHERE r.requested_revision_id=? OR (r.target_id=? AND a.candidate_revision_id=?)`, revisionId, request.id, revisionId);
  rows.forEach((row) => candidates.add(row.id));
  if (candidates.size > 1) throw new PolicyError(409, 'Multiple factory runs match this revision; provide the exact run identity.');
  if (candidates.size === 1) return [...candidates][0];
  return revisionId;
}

async function assertExplicitFactoryDossierRun(env: Env, request: RequestRow, revisionId: string, runId: string): Promise<void> {
  const row = await env.DB.prepare(`SELECT r.id FROM factory_runs r LEFT JOIN factory_run_attempts a ON a.run_id=r.id
    WHERE r.id=? AND (r.requested_revision_id=? OR (r.target_id=? AND a.candidate_revision_id=?)) LIMIT 1`).bind(runId, revisionId, request.id, revisionId).first<{ id: string }>();
  if (!row) throw new PolicyError(409, 'Factory run does not match this revision.');
}

export async function buildFactoryDossier(env: Env, input: { requestId?: string; revisionId: string; runId?: string; id?: string }): Promise<FactoryDossier> {
  if ((input.requestId !== undefined && !RUN_ID.test(input.requestId)) || !RUN_ID.test(input.revisionId)) throw new PolicyError(400, 'Request and revision identifiers are invalid.');
  if (input.id !== undefined && !/^dossier-[A-Za-z0-9_-]{8,128}$/.test(input.id)) throw new PolicyError(400, 'Dossier identifier is invalid.');
  const requestId = input.requestId ?? (await env.DB.prepare('SELECT request_id FROM revisions WHERE id=?').bind(input.revisionId).first<{ request_id: string }>())?.request_id;
  if (!requestId || !RUN_ID.test(requestId)) throw new PolicyError(404, 'Factory request not found.');
  const rows = await loadDossierRows(env, requestId, input.revisionId);
  const runId = input.runId ?? await resolveFactoryDossierRunId(env, rows.request, rows.revision.id);

  if (!RUN_ID.test(runId)) throw new PolicyError(409, 'Factory run identity is missing or invalid.');
  if (input.runId) await assertExplicitFactoryDossierRun(env, rows.request, rows.revision.id, runId);
  const identityDigest = await sha256(`${runId}\u0000${rows.revision.id}`);
  const dossierId = input.id ?? `dossier-${identityDigest.slice(0, 48)}`;
  const eventRecords: FactoryDossier['evidence']['events'] = [];
  let eventBytes = 0;
  for (const event of rows.events) {
    const record = { stage: event.stage, createdAt: event.created_at, detail: parseDetail(event.detail) };
    const size = new TextEncoder().encode(canonicalJson(record)).byteLength;
    if (eventBytes + size > 128 * 1024) break;
    eventRecords.push(record);
    eventBytes += size;
  }
  const runAttempts = await query<FactoryRunAttemptRow>(env.DB, 'SELECT a.id,a.attempt,a.status,a.candidate_revision_id,r.recipe_sha256 AS candidate_recipe_sha256,a.candidate_sha256,a.input_sha256,a.architecture,a.candidate_json,a.failure_kind,a.failure_json,a.artifact_json,a.started_at,a.finished_at,a.created_at,a.updated_at FROM factory_run_attempts a LEFT JOIN revisions r ON r.id=a.candidate_revision_id WHERE a.run_id=? ORDER BY a.attempt', runId);

  const extraRevisionIds = [...new Set(runAttempts.map((attempt) => attempt.candidate_revision_id).filter((id): id is string => Boolean(id) && id !== rows.revision.id))];

  if (extraRevisionIds.length) {
    const placeholders = extraRevisionIds.map(() => '?').join(',');
    const extraBuilds = await query<BuildRow>(env.DB, `SELECT * FROM builds WHERE revision_id IN (${placeholders}) ORDER BY architecture,id`, ...extraRevisionIds);
    const buildIds = extraBuilds.map((build) => build.id);
    rows.builds.push(...extraBuilds);

    if (buildIds.length) {
      const buildPlaceholders = buildIds.map(() => '?').join(',');
      rows.attempts.push(...await query<AttemptRow>(env.DB, `SELECT build_id,attempt,revision_id,architecture,started_at,input_lock_sha256 FROM build_attempts WHERE build_id IN (${buildPlaceholders}) ORDER BY attempt,architecture,build_id`, ...buildIds));
      rows.results.push(...await query<AttemptResultRow>(env.DB, `SELECT build_id,attempt,status,error,finished_at FROM build_attempt_results WHERE build_id IN (${buildPlaceholders}) ORDER BY attempt,build_id`, ...buildIds));
      rows.artifacts.push(...await query<ArtifactRow>(env.DB, `SELECT build_id,attempt,filename,artifact_key,sha256,size FROM build_artifacts WHERE build_id IN (${buildPlaceholders}) ORDER BY attempt,build_id,filename LIMIT ?`, ...buildIds, MAX_ARTIFACT_ROWS));
      rows.logs.push(...await query<LogRow>(env.DB, `SELECT build_id,attempt,sequence,text FROM build_logs WHERE build_id IN (${buildPlaceholders}) ORDER BY attempt,build_id,sequence LIMIT ?`, ...buildIds, MAX_LOG_ROWS));
    }
  }

  const recordedTimes = [
    rows.revision.created_at,
    ...rows.builds.flatMap((build) => [build.created_at, build.started_at, build.finished_at]),
    ...rows.attempts.map((attempt) => attempt.started_at),
    ...rows.results.map((result) => result.finished_at),
    ...runAttempts.flatMap((attempt) => [attempt.started_at, attempt.finished_at, attempt.created_at, attempt.updated_at]),
    ...rows.events.map((event) => event.created_at),
    ...rows.approvals.flatMap((approval) => [approval.created_at, approval.revoked_at]),
    ...rows.releases.map((release) => release.published_at),
  ].filter((value): value is number => typeof value === 'number' && Number.isFinite(value));
  const latestRecordedAt = Math.max(rows.revision.created_at, ...recordedTimes);
  const attempts = dossierAttemptData(rows, runAttempts, `/maintain/dossiers/${encodeURIComponent(dossierId)}`);
  const outputs = attempts.flatMap((attempt) => attempt.outputs).sort((a, b) => a.architecture.localeCompare(b.architecture) || a.attempt - b.attempt || a.filename.localeCompare(b.filename));
  const sourceList = arrayValue(parseValue(rows.revision.sources_json, []));
  const sourceDigests = sourceList.map((source) => objectValue(source).sha256).filter((value): value is string => digest(value) !== null).sort();
  const dependencyLocks = [...new Set(rows.builds.flatMap((build) => build.input_lock_sha256 ? [build.input_lock_sha256] : []).filter((value): value is string => SHA256.test(value)))].sort();
  const buildImages = objectValue(parseValue(rows.revision.build_images_json, {}));
  let imageDefinitions: DossierImageDefinition[] = Object.entries(buildImages).flatMap(([architecture, imageRef]) => {
    if ((architecture !== 'x86_64' && architecture !== 'aarch64') || typeof imageRef !== 'string') return [];
    const digestValue = imageRef.split('@sha256:').at(-1);
    return digestValue && SHA256.test(digestValue) ? [{ id: null, architecture, imageRef, digest: `sha256:${digestValue}`, enabled: null, isDefault: null, createdAt: null }] : [];
  });
  const refs = Object.values(buildImages).filter((value): value is string => typeof value === 'string');
  if (refs.length) {
    const placeholders = refs.map(() => '?').join(',');
    const configuredImages = await query<{ id: string; architecture: Architecture; image_ref: string; enabled: number; is_default: number; created_at: number }>(env.DB,
      `SELECT id,architecture,image_ref,enabled,is_default,created_at FROM build_images WHERE image_ref IN (${placeholders}) ORDER BY architecture,id`, ...refs);
    imageDefinitions = configuredImages.map((image) => ({ id: image.id, architecture: image.architecture, imageRef: image.image_ref, digest: `sha256:${image.image_ref.split('@sha256:').at(-1)}`,
      enabled: image.enabled === 1, isDefault: image.is_default === 1, createdAt: image.created_at }));
  }

  const checks = (await Promise.all(rows.builds.map(async (build) => {
    const buildOutputs = outputs.filter((output) => output.buildId === build.id);
    return (await provenanceChecks(env, build, buildOutputs, rows.revision)).map((item) => ({ ...item, name: `${build.architecture}/${item.name}` }));
  }))).flat();
  const lint = objectValue(parseValue(rows.revision.lint_json, null));
  checks.push(check('source-identity', sourceList.length > 0 && sourceDigests.length === sourceList.length ? 'passed' : 'missing',
    sourceList.length > 0 && sourceDigests.length === sourceList.length ? 'Every declared source has a recorded SHA-256 identity; byte verification evidence remains separate.' : 'Source identity evidence is incomplete.'));
  checks.push(check('license-decision', rows.revision.license.trim() && ['binary', 'recipe'].includes(rows.revision.surface) ? 'passed' : 'missing',
    rows.revision.license.trim() && ['binary', 'recipe'].includes(rows.revision.surface) ? `License ${rows.revision.license} and ${rows.revision.surface} redistribution decision are recorded; verification evidence remains separate.` : 'License or redistribution surface is missing.'));
  checks.push(check('lint', lint.passed === true ? 'passed' : lint.passed === false ? 'failed' : 'missing',
    lint.passed === true ? 'Recipe lint passed.' : lint.passed === false ? 'Recipe lint failed.' : 'Recipe lint evidence is unavailable.'));

  const expectedArchitectures = arrayValue(parseValue(rows.revision.architectures_json, [])).filter((value): value is string => typeof value === 'string').sort();

  for (const architecture of expectedArchitectures) {
    if (!rows.builds.some((build) => build.architecture === architecture)) checks.push(check(`${architecture}/build`, 'missing', 'No build record exists for this required architecture.'));
  }

  const reviews = rows.approvals.map((approval) => ({ kind: approval.kind, actor: approval.actor, manifestSha256: approval.manifest_sha256,
    currentAtSnapshot: approval.manifest_sha256 === rows.revision.manifest_sha256 && approval.revoked_at == null,
    evidenceAsOfAt: latestRecordedAt, createdAt: approval.created_at, revokedAt: approval.revoked_at ?? null }));

  const rationale = [{ attributedTo: 'factory', text: textValue(rows.revision.explanation, 'unavailable') }];
  const sbom = safeDetail(parseValue(rows.revision.sbom_json, {}));
  const sbomObject = objectValue(sbom);
  const authoring = objectValue(sbomObject.authoring ?? sbomObject.recipe ?? sbomObject.template);
  const dossier: FactoryDossier = {
    schemaVersion: 1, kind: 'factory-package-dossier', id: dossierId,
    identity: { requestId: rows.request.id, runId, revisionId: rows.revision.id, recipeSha256: rows.revision.recipe_sha256, manifestSha256: rows.revision.manifest_sha256, createdAt: rows.revision.created_at },
    request: { id: rows.request.id, name: rows.request.name, status: rows.request.status, area: rows.request.area, sourceKind: rows.request.source_kind,
      upstreamUrl: redactText(rows.request.upstream_url), upstreamRef: rows.request.upstream_ref ?? null, requestedBy: rows.request.requested_by },
    revision: { id: rows.revision.id, version: rows.revision.version, pkgrel: rows.revision.pkgrel ?? null, recipe: rows.revision.recipe,
      recipeSha256: rows.revision.recipe_sha256, manifestSha256: rows.revision.manifest_sha256, sources: sourceList, dependencies: arrayValue(parseValue(rows.revision.dependencies_json, [])),
      makeDependencies: arrayValue(parseValue(rows.revision.make_dependencies_json, [])), smokeCommands: arrayValue(parseValue(rows.revision.smoke_commands_json, [])),
      architectures: expectedArchitectures, buildImages, sourceDateEpoch: rows.revision.source_date_epoch, imageDigest: rows.revision.image_digest, license: rows.revision.license,
      surface: rows.revision.surface, description: rows.revision.description ?? null, explanation: textValue(rows.revision.explanation), sbom,
      lint: parseValue(rows.revision.lint_json, {}), upstreamCommit: rows.revision.upstream_commit, pullRequestUrl: rows.revision.pr_url, commitSha: rows.revision.commit_sha },
    authoring: { buildSystem: typeof authoring.buildSystem === 'string' ? authoring.buildSystem : typeof sbomObject.buildSystem === 'string' ? sbomObject.buildSystem : null,
      template: typeof authoring.template === 'string' ? authoring.template : typeof sbomObject.template === 'string' ? sbomObject.template : null,
      templateVersion: typeof authoring.templateVersion === 'string' || typeof authoring.templateVersion === 'number' ? authoring.templateVersion : typeof sbomObject.templateVersion === 'string' || typeof sbomObject.templateVersion === 'number' ? sbomObject.templateVersion : null,
      rationale: textValue(rows.revision.explanation, 'unavailable') },
    imageDefinitions,
    inputs: { sourceDigests, dependencyLocks, builderImages: buildImages, supportingFilesDigest: rows.revision.manifest_sha256 },
    attempts, outputs, checks, rationale, modelUsage: modelUsage(eventRecords), reviews, blockers: rows.blockers.map((blocker) => ({ ...blocker, reason: textValue(blocker.reason) })),
    publication: { published: rows.releases.length > 0, releases: rows.releases.map((release) => ({ id: release.id, channel: release.channel, architecture: release.architecture,
      artifactSha256: release.artifact_sha256, publishedAt: release.published_at })) },
    evidence: { evidenceAsOfAt: latestRecordedAt, latestRecordedAt, reviewsAuthority: 'historical-snapshot', eventCount: rows.events.length, eventsTruncated: eventRecords.length < rows.events.length, events: eventRecords, auditUrl: `/maintain/audit?request=${encodeURIComponent(rows.request.id)}`,
      attemptEvidenceComplete: attempts.length > 0 && attempts.every((attempt) => attempt.result !== 'unknown' &&
        (attempt.buildIds.length > 0 || attempt.outputs.length > 0 || (attempt.result === 'failed' && (attempt.findings.length > 0 || attempt.trigger !== null)))) },
  };

  return dossier;
}

export async function renderFactoryDossier(env: Env, input: { requestId?: string; revisionId: string; runId?: string; id?: string }): Promise<StoredFactoryDossier> {
  const dossier = await buildFactoryDossier(env, input);
  const canonical = factoryDossierCanonicalJson(dossier);
  const markdown = factoryDossierMarkdown(dossier);

  return { dossier, canonicalJson: canonical, canonicalSha256: await sha256(canonical), markdown, markdownSha256: await sha256(markdown) };
}

export async function createFactoryDossier(env: Env, actor: string, input: { requestId?: string; revisionId: string; runId?: string; id?: string }): Promise<StoredFactoryDossier> {
  let rendered = await renderFactoryDossier(env, input);
  for (let collision = 0; collision < 2; collision += 1) {
    const createdAt = rendered.dossier.identity.createdAt;
    try {
      await env.DB.batch([
        env.DB.prepare(`INSERT INTO factory_dossiers(id,request_id,revision_id,run_id,canonical_json,canonical_sha256,markdown,markdown_sha256,created_by,created_at)
          VALUES(?,?,?,?,?,?,?,?,?,?)`).bind(rendered.dossier.id, rendered.dossier.identity.requestId, input.revisionId, rendered.dossier.identity.runId, rendered.canonicalJson,
          rendered.canonicalSha256, rendered.markdown, rendered.markdownSha256, actor, createdAt),
        audit(env.DB, actor, 'factory.dossier_created', rendered.dossier.id, { requestId: rendered.dossier.identity.requestId, revisionId: input.revisionId, runId: rendered.dossier.identity.runId, canonicalSha256: rendered.canonicalSha256 }),
      ]);
      return rendered;
    } catch (cause) {
      const existing = await env.DB.prepare(`SELECT id,canonical_json,canonical_sha256,markdown,markdown_sha256 FROM factory_dossiers
        WHERE request_id=? AND revision_id=? AND run_id=? AND canonical_sha256=? LIMIT 1`).bind(rendered.dossier.identity.requestId, input.revisionId, rendered.dossier.identity.runId, rendered.canonicalSha256)
        .first<{ id: string; canonical_json: string; canonical_sha256: string; markdown: string; markdown_sha256: string }>();
      if (existing) {
        const parsed = parseValue(existing.canonical_json, null);
        if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new PolicyError(409, 'Stored factory dossier is invalid.');
        return { dossier: parsed as FactoryDossier, canonicalJson: existing.canonical_json, canonicalSha256: existing.canonical_sha256, markdown: existing.markdown, markdownSha256: existing.markdown_sha256 };
      }
      if (!(cause instanceof Error && /UNIQUE|constraint/i.test(cause.message)) || input.id || collision === 1) {
        throw cause instanceof Error && /UNIQUE|constraint/i.test(cause.message) ? new PolicyError(409, 'Factory dossier content is already bound to a different immutable ID.') : cause;
      }
      const contentId = `dossier-${rendered.canonicalSha256.slice(0, 48)}`;
      rendered = await renderFactoryDossier(env, { ...input, id: contentId });
    }
  }
  throw new PolicyError(409, 'Factory dossier could not be persisted.');
}

export async function storedFactoryDossier(env: Env, id: string): Promise<StoredFactoryDossier> {
  if (!/^dossier-[A-Za-z0-9_-]{8,128}$/.test(id)) throw new PolicyError(404, 'Factory dossier not found.');

  const row = await env.DB.prepare('SELECT canonical_json,canonical_sha256,markdown,markdown_sha256 FROM factory_dossiers WHERE id=?').bind(id)
    .first<{ canonical_json: string; canonical_sha256: string; markdown: string; markdown_sha256: string }>();

  if (!row) throw new PolicyError(404, 'Factory dossier not found.');
  if (await sha256(row.canonical_json) !== row.canonical_sha256 || await sha256(row.markdown) !== row.markdown_sha256) throw new PolicyError(409, 'Stored factory dossier digest does not match its bytes.');
  const parsed = parseValue(row.canonical_json, null);

  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new PolicyError(409, 'Stored factory dossier is invalid.');

  return { dossier: parsed as FactoryDossier, canonicalJson: row.canonical_json, canonicalSha256: row.canonical_sha256, markdown: row.markdown, markdownSha256: row.markdown_sha256 };
}

export async function listFactoryDossiers(env: Env, requestId?: string): Promise<Array<{ id: string; request_id: string; revision_id: string; run_id: string; canonical_sha256: string; created_at: number }>> {
  if (requestId && !RUN_ID.test(requestId)) throw new PolicyError(400, 'Request identifier is invalid.');

  return query(env.DB, `SELECT id,request_id,revision_id,run_id,canonical_sha256,created_at FROM factory_dossiers
    ${requestId ? 'WHERE request_id=?' : ''} ORDER BY created_at DESC,id DESC LIMIT 200`, ...(requestId ? [requestId] : []));
}
