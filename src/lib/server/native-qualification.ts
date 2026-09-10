import type { Actor, Architecture, Worker } from '../model';
import { canonicalJson } from '../canonical-json';
import type { Env } from './env';
import { audit, id, now, query, sha256 } from './db';
import { humanMaintainer } from './catalog-ownership';
import { PolicyError, requireSecurity } from './policy';
import { decodeBase64, safeFilenamePattern, type AuthenticatedWorker, verifyEd25519 } from './worker-protocol';
import { verifyR2Object } from './release-storage';

export const qualificationOperations = ['install', 'upgrade', 'recovery', 'boot', 'reproducibility'] as const;

export type QualificationOperation = (typeof qualificationOperations)[number];

// `verified-reproducible` is retained for historical reports. New worker
// reports use `independently-reproduced`; one normal build uses the separate
// `reproducibility-contract-verified` output evidence status.
export const reproducibilityStatuses = ['independently-reproduced', 'verified-reproducible', 'mismatch', 'not-checked'] as const;

export type ReproducibilityStatus = (typeof reproducibilityStatuses)[number];

export type QualificationStatus = 'passed' | 'failed' | 'not-checked';

const digest = /^[a-f0-9]{64}$/;

const identifier = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;

const architectures: readonly Architecture[] = ['x86_64', 'aarch64'];

export interface QualificationCommand {
  name: string;
  executable: string;
  arguments: string[];
  workingDirectory?: string;
  timeoutSeconds?: number;
}

export interface QualificationObservation {
  name: string;
  path: string;
  kind: 'package-state' | 'manifest' | 'boot-state' | 'recovery-state' | 'text';
}

export interface QualificationPlanPayload {
  schemaVersion: 1;
  cohortId: string;
  revision: number;
  operation: QualificationOperation;
  architecture: Architecture;
  candidateSha256: string;
  inputSha256: string;
  artifactSha256: string;
  environmentSha256: string;
  profile: { id: string; sha256: string };
  coverage: { kind: 'member' | 'system'; pkgbase: string | null; rootSha256: string | null; releaseId: string | null; members: string[]; sha256: string };
  commands: QualificationCommand[];
  observations: QualificationObservation[];
  expectedObservationSha256: string;
  expected: Record<string, unknown>;
}

export interface QualificationPlan extends QualificationPlanPayload {
  id: string;
  planSha256: string;
  createdBy: string;
  createdAt: number;
}

export interface QualificationResultCommand {
  name: string;
  exitCode: number;
  passed: boolean;
  stdoutSha256: string;
  stderrSha256: string;
}

export interface QualificationEvidence {
  schemaVersion: 1;
  planId: string;
  testPlanSha256: string;
  cohortId: string;
  revision: number;
  operation: QualificationOperation;
  architecture: Architecture;
  candidate: { sha256: string };
  input: { sha256: string };
  artifact: { sha256: string };
  environment: { sha256: string; machine: { architecture: Architecture; goarch: string; goos: string; runtime: string }; details: Record<string, unknown> };
  profile: { id: string; sha256: string };
  coverage: { kind: 'member' | 'system'; pkgbase: string | null; rootSha256: string | null; releaseId: string | null; members: string[]; sha256: string };
  command: { sha256: string };
  result: { startedAt: string; finishedAt: string; exitCode: number; commands: QualificationResultCommand[] };
  observed: Record<string, unknown>;
  observedSha256: string;
  reproducibility?: ReproducibilityReport;
  workerId: string;
  workerPublicKey: string;
  signature: string;
}

export interface ReproducibilityOutput { filename: string; sha256: string }

export interface ReproducibilityAttempt {
  buildId: string;
  attempt: number;
  workerId: string;
  artifactSha256: string;
  outputs: ReproducibilityOutput[];
}

export interface ReproducibilityReport {
  status: ReproducibilityStatus;
  primary: ReproducibilityAttempt;
  secondary: ReproducibilityAttempt;
}

export interface QualificationRow {
  id: string;
  plan_id: string;
  cohort_id: string;
  revision: number;
  operation: QualificationOperation;
  architecture: Architecture;
  candidate_sha256: string;
  input_sha256: string;
  artifact_sha256: string;
  environment_sha256: string;
  profile_id: string;
  profile_sha256: string;
  coverage_kind: 'member' | 'system'; coverage_pkgbase: string | null; coverage_release_id: string | null; coverage_sha256: string; coverage_json: string;
  observed_sha256: string;
  status: QualificationStatus;
  reproducibility_status: ReproducibilityStatus | null;
  worker_id: string;
  worker_public_key: string;
  report_json: string;
  report_sha256: string;
  signature: string;
  created_at: number;
}

function record(value: unknown, field: string): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new PolicyError(400, `Invalid ${field}.`);

  return value as Record<string, unknown>;
}

function text(value: unknown, field: string, max = 512): string {
  if (typeof value !== 'string' || value.length === 0 || value.length > max || /[\u0000-\u001f\u007f]/.test(value)) throw new PolicyError(400, `Invalid ${field}.`);

  return value;
}

function hash(value: unknown, field: string): string {
  const result = text(value, field, 64);

  if (!digest.test(result)) throw new PolicyError(400, `Invalid ${field}.`);

  return result;
}

function integer(value: unknown, field: string, min = 0, max = 1_000_000): number {
  if (!Number.isSafeInteger(value) || (value as number) < min || (value as number) > max) throw new PolicyError(400, `Invalid ${field}.`);

  return value as number;
}

function exactKeys(value: Record<string, unknown>, expected: readonly string[], field: string): void {
  const keys = Object.keys(value).sort(); const allowed = [...expected].sort();

  if (keys.length !== allowed.length || keys.some((key, index) => key !== allowed[index])) throw new PolicyError(400, `Invalid ${field}.`);
}

function operation(value: unknown): QualificationOperation {
  if (!qualificationOperations.includes(value as QualificationOperation)) throw new PolicyError(400, 'Invalid qualification operation.');

  return value as QualificationOperation;
}

function architecture(value: unknown): Architecture {
  if (!architectures.includes(value as Architecture)) throw new PolicyError(400, 'Invalid qualification architecture.');

  return value as Architecture;
}

function safePath(value: unknown, field: string): string {
  const path = text(value, field, 512);

  if (path.startsWith('/') || path.split('/').some((part) => !part || part === '.' || part === '..')) throw new PolicyError(400, `Invalid ${field}.`);

  return path;
}

function timestamp(value: unknown, field: string): string {
  const result = text(value, field, 64);

  if (!Number.isFinite(Date.parse(result))) throw new PolicyError(400, `Invalid ${field}.`);

  return result;
}

function parseCommand(value: unknown): QualificationCommand {
  const item = record(value, 'qualification command');

  if (Object.keys(item).some((key) => !['name', 'executable', 'arguments', 'workingDirectory', 'timeoutSeconds'].includes(key)) ||
      !Object.hasOwn(item, 'name') || !Object.hasOwn(item, 'executable') || !Object.hasOwn(item, 'arguments')) throw new PolicyError(400, 'Invalid qualification command.');
  const name = text(item.name, 'command name', 128);

  if (!identifier.test(name)) throw new PolicyError(400, 'Invalid command name.');
  const executable = text(item.executable, 'command executable', 256);

  if (!executable.startsWith('/')) throw new PolicyError(400, 'Qualification commands must use an absolute executable.');

  if (!Array.isArray(item.arguments) || item.arguments.length > 64 || item.arguments.some((arg) => typeof arg !== 'string' || arg.length > 4096 || /\u0000/.test(arg))) throw new PolicyError(400, 'Invalid command arguments.');
  const result: QualificationCommand = { name, executable, arguments: [...item.arguments] };

  if (item.workingDirectory !== undefined) result.workingDirectory = safePath(item.workingDirectory, 'working directory');

  if (item.timeoutSeconds !== undefined) result.timeoutSeconds = integer(item.timeoutSeconds, 'command timeout', 1, 3600);

  return result;
}

function parseObservation(value: unknown): QualificationObservation {
  const item = record(value, 'qualification observation');
  exactKeys(item, ['name', 'path', 'kind'], 'qualification observation');
  const name = text(item.name, 'observation name', 128);

  if (!identifier.test(name)) throw new PolicyError(400, 'Invalid observation name.');
  const path = safePath(item.path, 'observation path');

  if (!['package-state', 'manifest', 'boot-state', 'recovery-state', 'text'].includes(item.kind as string)) throw new PolicyError(400, 'Invalid observation kind.');

  return { name, path, kind: item.kind as QualificationObservation['kind'] };
}

function parseProfile(value: unknown): { id: string; sha256: string } {
  const item = record(value, 'qualification profile'); exactKeys(item, ['id', 'sha256'], 'qualification profile');
  const idValue = text(item.id, 'profile id', 128);

 if (!identifier.test(idValue)) throw new PolicyError(400, 'Invalid profile id.');

  return { id: idValue, sha256: hash(item.sha256, 'profile digest') };
}

function parseCoverage(value: unknown): QualificationPlanPayload['coverage'] {
  const item = record(value, 'qualification coverage'); exactKeys(item, ['kind', 'pkgbase', 'rootSha256', 'releaseId', 'members', 'sha256'], 'qualification coverage');

  if (item.kind !== 'member' && item.kind !== 'system') throw new PolicyError(400, 'Invalid qualification coverage kind.');
  const pkgbase = item.pkgbase === null ? null : text(item.pkgbase, 'coverage package', 64);
  const rootSha256 = item.rootSha256 === null ? null : hash(item.rootSha256, 'coverage universe root');
  const releaseId = item.releaseId === null ? null : text(item.releaseId, 'coverage release', 128);

  if (!releaseId || item.kind === 'member' && (!pkgbase || rootSha256 !== null) || item.kind === 'system' && (pkgbase !== null || rootSha256 === null)) throw new PolicyError(400, 'Qualification coverage scope is invalid.');

  if (!Array.isArray(item.members) || item.members.length < 1 || item.members.length > 100000 || item.members.some((member) => typeof member !== 'string' || !/^[a-z0-9][a-z0-9@._+-]{0,63}$/.test(member))) throw new PolicyError(400, 'Qualification coverage members are invalid.');
  const members = [...new Set(item.members as string[])].sort();

  if (members.length !== (item.members as unknown[]).length) throw new PolicyError(400, 'Qualification coverage members must be unique.');

  return { kind: item.kind, pkgbase, rootSha256, releaseId, members, sha256: hash(item.sha256, 'coverage digest') };
}

export function qualificationPlanDigest(plan: QualificationPlanPayload): Promise<string> {
  return sha256(canonicalJson(plan));
}

export async function parseQualificationPlan(value: unknown): Promise<QualificationPlanPayload> {
  const item = record(value, 'qualification plan');
  exactKeys(item, ['schemaVersion', 'cohortId', 'revision', 'operation', 'architecture', 'candidateSha256', 'inputSha256', 'artifactSha256', 'environmentSha256', 'profile', 'coverage', 'commands', 'observations', 'expectedObservationSha256', 'expected'], 'qualification plan');

  if (item.schemaVersion !== 1) throw new PolicyError(400, 'Unsupported qualification plan schema.');
  const commands = item.commands;

 if (!Array.isArray(commands) || commands.length < 1 || commands.length > 32) throw new PolicyError(400, 'Qualification plan needs bounded commands.');
  const observations = item.observations;

 if (!Array.isArray(observations) || observations.length < 1 || observations.length > 32) throw new PolicyError(400, 'Qualification plan needs bounded observations.');
  const parsedCommands = commands.map(parseCommand); const parsedObservations = observations.map(parseObservation);

  if (new Set(parsedCommands.map((command) => command.name)).size !== parsedCommands.length || new Set(parsedObservations.map((observation) => observation.name)).size !== parsedObservations.length) throw new PolicyError(400, 'Qualification plan names must be unique.');
  const expected = record(item.expected, 'qualification expectations');

  if (Object.keys(expected).length > 64) throw new PolicyError(400, 'Qualification expectations are too large.');

  if (item.operation === 'reproducibility' && (typeof expected.primaryBuildId !== 'string' || typeof expected.secondaryBuildId !== 'string' ||
      !Number.isSafeInteger(expected.primaryAttempt) || !Number.isSafeInteger(expected.secondaryAttempt))) throw new PolicyError(400, 'Reproducibility plans must name both retained build attempts.');

  return { schemaVersion: 1, cohortId: text(item.cohortId, 'cohort id', 128), revision: integer(item.revision, 'cohort revision', 1), operation: operation(item.operation), architecture: architecture(item.architecture),
    candidateSha256: hash(item.candidateSha256, 'candidate digest'), inputSha256: hash(item.inputSha256, 'input digest'), artifactSha256: hash(item.artifactSha256, 'artifact digest'), environmentSha256: hash(item.environmentSha256, 'environment digest'), profile: parseProfile(item.profile), coverage: parseCoverage(item.coverage),
    commands: parsedCommands, observations: parsedObservations, expectedObservationSha256: hash(item.expectedObservationSha256, 'expected observation digest'), expected };
}

async function currentPlan(db: D1Database, planId: string): Promise<{ plan: QualificationPlanPayload; row: { id: string; plan_sha256: string; created_by: string; created_at: number; cohort_id: string; revision: number; operation: QualificationOperation; architecture: Architecture } } | null> {
  const row = await db.prepare('SELECT id,plan_json,plan_sha256,created_by,created_at,cohort_id,revision,operation,architecture FROM native_qualification_plans WHERE id=?').bind(planId).first<{ id: string; plan_json: string; plan_sha256: string; created_by: string; created_at: number; cohort_id: string; revision: number; operation: QualificationOperation; architecture: Architecture }>();

  if (!row) return null;
  const plan = await parseQualificationPlan(JSON.parse(row.plan_json));

  if (await qualificationPlanDigest(plan) !== row.plan_sha256) throw new PolicyError(409, 'Qualification plan digest changed.');

  return { plan, row };
}

async function assertPlanReview(db: D1Database, planId: string): Promise<void> {
  const reviews = await query<{ kind: string; actor: string }>(db, 'SELECT kind,actor FROM native_qualification_plan_reviews WHERE plan_id=?', planId);

  if (new Set(reviews.map((review) => review.kind)).size !== 2 || new Set(reviews.map((review) => review.actor)).size !== 2) throw new PolicyError(409, 'Independent area and security review of the qualification plan is required.');

  for (const review of reviews) {
    const githubId = review.actor.startsWith('github:') ? review.actor.slice(7) : '';
    const authority = review.kind === 'security' ? "team IN ('security','admin')" : "team IN ('desktop','development','gaming','multimedia','productivity','system','admin')";

    if (!githubId || !(await db.prepare(`SELECT 1 FROM team_memberships WHERE github_id=? AND ${authority} LIMIT 1`).bind(githubId).first())) throw new PolicyError(409, 'Qualification plan review authority is no longer current.');
  }
}

async function assertCandidate(db: D1Database, plan: QualificationPlanPayload): Promise<void> {
  const candidate = await db.prepare('SELECT manifest_sha256,lane FROM cohort_revisions WHERE cohort_id=? AND revision=?').bind(plan.cohortId, plan.revision).first<{ manifest_sha256: string; lane: string }>();
  const current = await db.prepare('SELECT current_revision FROM cohorts WHERE id=?').bind(plan.cohortId).first<{ current_revision: number }>();

  if (!candidate || !current || current.current_revision !== plan.revision || candidate.manifest_sha256 !== plan.candidateSha256) throw new PolicyError(409, 'Qualification plan does not target the current cohort candidate.');
  const members = (await query<{ pkgbase: string }>(db, 'SELECT pkgbase FROM cohort_members WHERE cohort_id=? AND revision=? ORDER BY pkgbase', plan.cohortId, plan.revision)).map((row) => row.pkgbase);

  if (plan.coverage.kind === 'member' && (!plan.coverage.pkgbase || plan.coverage.members.length !== 1 || plan.coverage.members[0] !== plan.coverage.pkgbase) ||
      plan.coverage.kind === 'system' && (plan.coverage.members.length !== members.length || plan.coverage.members.some((member, index) => member !== members[index]))) throw new PolicyError(409, 'Qualification plan coverage does not match the current cohort scope.');

  if (plan.coverage.kind === 'system' && plan.artifactSha256 !== plan.coverage.rootSha256) throw new PolicyError(409, 'System qualification artifact must bind the final owned universe root.');

  if (await sha256(canonicalJson({ kind: plan.coverage.kind, pkgbase: plan.coverage.pkgbase, rootSha256: plan.coverage.rootSha256, releaseId: plan.coverage.releaseId, members: plan.coverage.members, artifactSha256: plan.artifactSha256 })) !== plan.coverage.sha256) throw new PolicyError(409, 'Qualification coverage digest is invalid.');

  if (plan.coverage.kind === 'system' && !await db.prepare("SELECT 1 FROM owned_repository_universes WHERE lane='system' AND release_id=? AND root_sha256=? AND status IN ('prepared','published') LIMIT 1").bind(plan.coverage.releaseId, plan.coverage.rootSha256).first()) throw new PolicyError(409, 'Qualification plan must bind the selected final owned repository universe.');
  const input = await db.prepare(`SELECT 1 FROM input_locks WHERE sha256=? AND cohort_id=? AND cohort_revision=? AND architecture=? AND status='ready'`).bind(plan.inputSha256, plan.cohortId, plan.revision, plan.architecture).first();

  if (!input) throw new PolicyError(409, 'Qualification plan must bind a current ready input lock.');

  if (plan.operation !== 'reproducibility' && !(await candidateArtifactBinding(db, plan))) throw new PolicyError(409, 'Qualification plan must bind a registered native artifact set.');
}

async function candidateArtifactRows(db: D1Database, plan: QualificationPlanPayload) {
  if (plan.coverage.kind === 'system') {
    const baseline = await query<{ filename: string; sha256: string; size: number }>(db, `SELECT a.filename,a.artifact_sha256 AS sha256,a.artifact_size AS size
      FROM owned_repository_universe_packages u JOIN owned_repository_artifacts a ON a.id=u.artifact_id JOIN owned_repository_universes v ON v.id=u.universe_id
      WHERE v.lane='system' AND v.release_id=? AND v.root_sha256=? AND v.status IN ('prepared','published') AND u.target_architecture=?`, plan.coverage.releaseId, plan.coverage.rootSha256, plan.architecture);

    // Coupled cohorts can carry OPR consumers. Their current native outputs are
    // part of the final system transaction even though they are outside the
    // system repository universe.
    const candidate = await query<{ filename: string; sha256: string; size: number }>(db, `SELECT a.filename,a.sha256,a.size
      FROM build_artifacts a JOIN builds b ON b.id=a.build_id AND b.attempt=a.attempt JOIN workers w ON w.id=b.worker_id AND w.status='active'
      JOIN revisions r ON r.id=b.revision_id JOIN cohort_members m ON m.recipe_revision_id=r.id
      WHERE b.architecture=? AND m.cohort_id=? AND m.revision=? AND b.status='succeeded'`, plan.architecture, plan.cohortId, plan.revision);

    const byFilename = new Map(baseline.map((artifact) => [artifact.filename, artifact]));

    for (const artifact of candidate) byFilename.set(artifact.filename, artifact);

    return [...byFilename.values()].sort((left, right) => left.filename.localeCompare(right.filename));
  }

  return query<{ filename: string; sha256: string; size: number }>(db, `SELECT a.filename,a.sha256,a.size FROM build_artifacts a JOIN builds b ON b.id=a.build_id AND b.attempt=a.attempt
    JOIN workers w ON w.id=b.worker_id AND w.status='active'
    JOIN revisions r ON r.id=b.revision_id JOIN cohort_members m ON m.recipe_revision_id=r.id
    WHERE b.architecture=? AND m.cohort_id=? AND m.revision=? AND b.status='succeeded' AND (? IS NULL OR m.pkgbase=?) ORDER BY a.filename`, plan.architecture, plan.cohortId, plan.revision, plan.coverage.pkgbase, plan.coverage.pkgbase);
}

async function candidateArtifactBinding(db: D1Database, plan: QualificationPlanPayload): Promise<boolean> {
  const artifacts = await candidateArtifactRows(db, plan);

  if (plan.coverage.kind === 'system') return artifacts.length > 0;

  if (artifacts.some((artifact) => artifact.sha256 === plan.artifactSha256)) return true;

  return artifacts.length > 0 && await outputSetDigest(artifacts.map(({ filename, sha256 }) => ({ filename, sha256 }))) === plan.artifactSha256;
}

export async function createQualificationPlan(env: Env, actor: Actor | null, input: unknown): Promise<QualificationPlan> {
  humanMaintainer(actor);
  const plan = await parseQualificationPlan(input);
  await assertCandidate(env.DB, plan);
  const createdAt = now(); const planSha256 = await qualificationPlanDigest(plan); const planId = id();
  await env.DB.batch([
    env.DB.prepare(`INSERT INTO native_qualification_plans(id,cohort_id,revision,operation,architecture,candidate_sha256,input_sha256,artifact_sha256,environment_sha256,profile_id,profile_sha256,coverage_kind,coverage_pkgbase,coverage_root_sha256,coverage_release_id,coverage_sha256,coverage_json,plan_json,plan_sha256,created_by,created_at)
      VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).bind(planId, plan.cohortId, plan.revision, plan.operation, plan.architecture, plan.candidateSha256, plan.inputSha256, plan.artifactSha256, plan.environmentSha256, plan.profile.id, plan.profile.sha256, plan.coverage.kind, plan.coverage.pkgbase, plan.coverage.rootSha256, plan.coverage.releaseId, plan.coverage.sha256, canonicalJson(plan.coverage), canonicalJson(plan), planSha256, actor!.id, createdAt),
    audit(env.DB, actor!.id, 'qualification.plan.created', planId, { planSha256, cohortId: plan.cohortId, revision: plan.revision, operation: plan.operation, architecture: plan.architecture })
  ]);

  return { ...plan, id: planId, planSha256, createdBy: actor!.id, createdAt };
}

export async function reviewQualificationPlan(env: Env, actor: Actor | null, planId: string, kind: 'area' | 'security', reason: string) {
  humanMaintainer(actor);

 if (!['area', 'security'].includes(kind)) throw new PolicyError(400, 'Choose an area or security review.');

  if (kind === 'security' && !['security', 'admin'].includes(actor!.role)) throw new PolicyError(403, 'Security review requires security authority.');
  const plan = await currentPlan(env.DB, planId);

 if (!plan) throw new PolicyError(404, 'Qualification plan not found.');
  const cleanReason = text(reason, 'review reason', 2000);

  try {
    await env.DB.batch([
      env.DB.prepare('INSERT INTO native_qualification_plan_reviews(plan_id,kind,actor,reason,created_at) VALUES(?,?,?,?,?)').bind(planId, kind, actor!.id, cleanReason, now()),
      audit(env.DB, actor!.id, 'qualification.plan.reviewed', planId, { kind, planSha256: plan.row.plan_sha256 })
    ]);
  } catch (cause) { if (String(cause).includes('UNIQUE')) throw new PolicyError(409, 'This qualification review already exists.'); throw cause; }

  return { planId, kind, planSha256: plan.row.plan_sha256 };
}

function parseResult(value: unknown): QualificationEvidence['result'] {
  const item = record(value, 'qualification result'); exactKeys(item, ['startedAt', 'finishedAt', 'exitCode', 'commands'], 'qualification result');
  const startedAt = timestamp(item.startedAt, 'result start'); const finishedAt = timestamp(item.finishedAt, 'result finish');

  if (Date.parse(finishedAt) < Date.parse(startedAt)) throw new PolicyError(400, 'Qualification result timestamps are reversed.');

  if (!Array.isArray(item.commands) || item.commands.length > 32) throw new PolicyError(400, 'Invalid qualification command results.');

  const commands = item.commands.map((value) => { const command = record(value, 'qualification command result'); exactKeys(command, ['name', 'exitCode', 'passed', 'stdoutSha256', 'stderrSha256'], 'qualification command result');
    const name = text(command.name, 'result command name', 128);

 if (!identifier.test(name)) throw new PolicyError(400, 'Invalid result command name.');

    if (typeof command.passed !== 'boolean') throw new PolicyError(400, 'Invalid command result status.');

    return { name, exitCode: integer(command.exitCode, 'command exit code', -1, 255), passed: command.passed, stdoutSha256: hash(command.stdoutSha256, 'stdout digest'), stderrSha256: hash(command.stderrSha256, 'stderr digest') };
  });

  return { startedAt, finishedAt, exitCode: integer(item.exitCode, 'qualification exit code', -1, 255), commands };
}

function parseEvidence(value: unknown): QualificationEvidence {
  const item = record(value, 'qualification evidence');

  if (Object.keys(item).some((key) => !['schemaVersion', 'planId', 'testPlanSha256', 'cohortId', 'revision', 'operation', 'architecture', 'candidate', 'input', 'artifact', 'environment', 'profile', 'coverage', 'command', 'result', 'observed', 'observedSha256', 'reproducibility', 'workerId', 'workerPublicKey', 'signature'].includes(key)) ||
      ['schemaVersion', 'planId', 'testPlanSha256', 'cohortId', 'revision', 'operation', 'architecture', 'candidate', 'input', 'artifact', 'environment', 'profile', 'coverage', 'command', 'result', 'observed', 'observedSha256', 'workerId', 'workerPublicKey', 'signature'].some((key) => !Object.hasOwn(item, key))) throw new PolicyError(400, 'Invalid qualification evidence.');

  if (item.schemaVersion !== 1) throw new PolicyError(400, 'Unsupported qualification evidence schema.');
  const candidate = record(item.candidate, 'candidate'); exactKeys(candidate, ['sha256'], 'candidate');
  const input = record(item.input, 'input'); exactKeys(input, ['sha256'], 'input');
  const artifact = record(item.artifact, 'artifact'); exactKeys(artifact, ['sha256'], 'artifact');
  const environment = record(item.environment, 'environment');

  if (Object.keys(environment).some((key) => !['sha256', 'machine', 'details'].includes(key)) || !Object.hasOwn(environment, 'sha256') || !Object.hasOwn(environment, 'machine') || !Object.hasOwn(environment, 'details')) throw new PolicyError(400, 'Invalid environment.');
  const environmentDetails = record(environment.details, 'environment details');

 if (Object.keys(environmentDetails).length > 128) throw new PolicyError(400, 'Environment details are too large.');
  const machine = record(environment.machine, 'native machine'); exactKeys(machine, ['architecture', 'goarch', 'goos', 'runtime'], 'native machine');
  const profile = parseProfile(item.profile); const coverage = parseCoverage(item.coverage); const command = record(item.command, 'qualification command'); exactKeys(command, ['sha256'], 'qualification command');

  if (!digest.test(String(command.sha256 ?? ''))) throw new PolicyError(400, 'Invalid command digest.');
  const result = parseResult(item.result); const observed = record(item.observed, 'qualification observations');
  const workerId = text(item.workerId, 'worker id', 128);

 if (!identifier.test(workerId)) throw new PolicyError(400, 'Invalid worker id.');
  const publicKey = text(item.workerPublicKey, 'worker public key', 128); const signature = text(item.signature, 'qualification signature', 256);
  const operationValue = operation(item.operation); const arch = architecture(item.architecture);
  const machineArchitecture = text(machine.architecture, 'machine architecture', 32); const machineGoarch = text(machine.goarch, 'machine goarch', 32);
  const machineGoos = text(machine.goos, 'machine goos', 32); const machineRuntime = text(machine.runtime, 'machine runtime', 128);

  if (machineArchitecture !== arch || machineGoos !== 'linux' || !['amd64', 'arm64'].includes(machineGoarch)) throw new PolicyError(400, 'Native machine does not identify a supported Linux target.');

  const evidence: QualificationEvidence = { schemaVersion: 1, planId: text(item.planId, 'plan id', 128), testPlanSha256: hash(item.testPlanSha256, 'test plan digest'), cohortId: text(item.cohortId, 'cohort id', 128), revision: integer(item.revision, 'cohort revision', 1), operation: operationValue, architecture: arch,
    candidate: { sha256: hash(candidate.sha256, 'candidate digest') }, input: { sha256: hash(input.sha256, 'input digest') }, artifact: { sha256: hash(artifact.sha256, 'artifact digest') }, environment: { sha256: hash(environment.sha256, 'environment digest'), machine: { architecture: arch, goarch: machineGoarch, goos: machineGoos, runtime: machineRuntime }, details: environmentDetails }, profile, coverage,
    command: { sha256: String(command.sha256) }, result, observed, observedSha256: hash(item.observedSha256, 'observed digest'), workerId, workerPublicKey: publicKey, signature };

  if (item.reproducibility !== undefined) evidence.reproducibility = parseReproducibility(item.reproducibility);

  if ((operationValue === 'reproducibility') !== Boolean(evidence.reproducibility)) throw new PolicyError(400, 'Reproducibility evidence is required only for the reproducibility operation.');

  return evidence;
}

function assertOperationObservation(operationValue: QualificationOperation, observed: Record<string, unknown>): void {
  const states = observed.states;

  if (!states || typeof states !== 'object' || Array.isArray(states)) throw new PolicyError(409, 'Native qualification did not retain typed state observations.');
  const values = Object.values(states as Record<string, unknown>);

  if (!values.length) throw new PolicyError(409, 'Native qualification did not observe a system state.');

  if (operationValue === 'install' || operationValue === 'upgrade') {
    if (!values.some((value) => Array.isArray(value) && value.length > 0 && value.every((item) => item && typeof item === 'object'))) throw new PolicyError(409, 'Install and upgrade qualification require a non-empty installed package state.');
  } else if (operationValue === 'boot') {
    if (!values.some((value) => value && typeof value === 'object' && !Array.isArray(value) && (value as Record<string, unknown>).booted === true && (value as Record<string, unknown>).login === true)) throw new PolicyError(409, 'Boot qualification requires observed boot and login state.');
  } else if (operationValue === 'recovery') {
    if (!values.some((value) => value && typeof value === 'object' && !Array.isArray(value) && (value as Record<string, unknown>).restored === true && typeof (value as Record<string, unknown>).manifestSha256 === 'string' && digest.test((value as Record<string, unknown>).manifestSha256 as string))) throw new PolicyError(409, 'Recovery qualification requires an observed restored manifest.');
  }
}

function parseReproducibility(value: unknown): ReproducibilityReport {
  const item = record(value, 'reproducibility report'); exactKeys(item, ['status', 'primary', 'secondary'], 'reproducibility report');

  if (!reproducibilityStatuses.includes(item.status as ReproducibilityStatus)) throw new PolicyError(400, 'Invalid reproducibility status.');

  const parseAttempt = (value: unknown): ReproducibilityAttempt => { const attempt = record(value, 'reproducibility attempt'); exactKeys(attempt, ['buildId', 'attempt', 'workerId', 'artifactSha256', 'outputs'], 'reproducibility attempt');

    if (!identifier.test(String(attempt.buildId)) || !identifier.test(String(attempt.workerId))) throw new PolicyError(400, 'Invalid reproducibility attempt identity.');

    if (!Array.isArray(attempt.outputs) || attempt.outputs.length > 256) throw new PolicyError(400, 'Invalid reproducibility outputs.');
    const outputs = attempt.outputs.map((value) => { const output = record(value, 'reproducibility output'); exactKeys(output, ['filename', 'sha256'], 'reproducibility output');

 return { filename: text(output.filename, 'output filename', 256), sha256: hash(output.sha256, 'output digest') }; }).sort((a, b) => a.filename.localeCompare(b.filename));

    return { buildId: String(attempt.buildId), attempt: integer(attempt.attempt, 'build attempt', 1), workerId: String(attempt.workerId), artifactSha256: hash(attempt.artifactSha256, 'attempt artifact digest'), outputs };
  };

  return { status: item.status as ReproducibilityStatus, primary: parseAttempt(item.primary), secondary: parseAttempt(item.secondary) };
}

function signedPayload(evidence: QualificationEvidence): Omit<QualificationEvidence, 'signature'> {
  const { signature: _signature, ...payload } = evidence;

 return payload;
}

export function outputSetDigest(outputs: ReproducibilityOutput[]): Promise<string> {
  return sha256(canonicalJson([...outputs].sort((a, b) => a.filename.localeCompare(b.filename))));
}

async function registeredArtifact(db: D1Database, digestValue: string, architectureValue: Architecture, cohortId: string, revision: number): Promise<boolean> {
  const row = await db.prepare(`SELECT 1 FROM build_artifacts a JOIN builds b ON b.id=a.build_id AND b.attempt=a.attempt JOIN workers w ON w.id=b.worker_id AND w.status='active'
    JOIN revisions r ON r.id=b.revision_id JOIN cohort_members m ON m.recipe_revision_id=r.id
    WHERE a.sha256=? AND b.architecture=? AND m.cohort_id=? AND m.revision=? AND b.status='succeeded'`).bind(digestValue, architectureValue, cohortId, revision).first();

  if (row) return true;

  const artifacts = await query<{ filename: string; sha256: string }>(db, `SELECT a.filename,a.sha256 FROM build_artifacts a JOIN builds b ON b.id=a.build_id AND b.attempt=a.attempt JOIN workers w ON w.id=b.worker_id AND w.status='active'
    JOIN revisions r ON r.id=b.revision_id JOIN cohort_members m ON m.recipe_revision_id=r.id WHERE b.architecture=? AND m.cohort_id=? AND m.revision=? AND b.status='succeeded' ORDER BY a.filename`, architectureValue, cohortId, revision);

  return artifacts.length > 0 && await outputSetDigest(artifacts) === digestValue;
}

async function assertSelectedInput(db: D1Database, plan: QualificationPlanPayload): Promise<void> {
  const row = await db.prepare(`SELECT 1 FROM current_input_locks l JOIN build_input_selections s ON s.lock_sha256=l.sha256
    WHERE l.sha256=? AND l.recipe_revision_id IN (SELECT recipe_revision_id FROM cohort_members WHERE cohort_id=? AND revision=? AND recipe_revision_id IS NOT NULL)
      AND l.cohort_id=? AND l.cohort_revision=? AND l.architecture=? AND s.architecture=? AND s.cohort_id=? AND s.cohort_revision=?`).bind(
    plan.inputSha256, plan.cohortId, plan.revision, plan.cohortId, plan.revision, plan.architecture, plan.architecture, plan.cohortId, plan.revision).first();

  if (!row) throw new PolicyError(409, 'Qualification input lock is not the current selected reviewed lock.');
}

async function actualReproducibility(env: Env, plan: QualificationPlanPayload, report: ReproducibilityReport): Promise<ReproducibilityStatus> {
  const db = env.DB;
  const attempts = [report.primary, report.secondary];

  if (report.primary.workerId === report.secondary.workerId || (report.primary.buildId === report.secondary.buildId && report.primary.attempt === report.secondary.attempt)) throw new PolicyError(409, 'Reproducibility must compare two attempts from distinct native workers.');

  if (plan.expected.primaryBuildId !== report.primary.buildId || plan.expected.secondaryBuildId !== report.secondary.buildId || plan.expected.primaryAttempt !== report.primary.attempt || plan.expected.secondaryAttempt !== report.secondary.attempt) throw new PolicyError(409, 'Reproducibility attempts differ from the reviewed test plan.');

  if (report.status === 'not-checked') return 'not-checked';

  const rows = await Promise.all(attempts.map((attempt) => db.prepare(`SELECT a.build_id,a.attempt,a.revision_id,a.architecture,a.worker_id,a.worker_public_key,a.input_lock_sha256,a.output_contract_json,r.recipe_sha256,
      result.status,result.provenance,result.provenance_signature,w.status AS worker_status
      FROM build_attempts a JOIN revisions r ON r.id=a.revision_id JOIN build_attempt_results result ON result.build_id=a.build_id AND result.attempt=a.attempt
      JOIN workers w ON w.id=a.worker_id WHERE a.build_id=? AND a.attempt=?`).bind(attempt.buildId, attempt.attempt).first<{ build_id: string; attempt: number; revision_id: string; architecture: Architecture; worker_id: string; worker_public_key: string; input_lock_sha256: string | null; output_contract_json: string | null; recipe_sha256: string; status: string; provenance: string | null; provenance_signature: string | null; worker_status: string }>()));

  if (!rows[0] || !rows[1] || rows[0].worker_id !== report.primary.workerId || rows[1].worker_id !== report.secondary.workerId || rows[0].worker_status !== 'active' || rows[1].worker_status !== 'active') throw new PolicyError(409, 'Reproducibility workers are not current registered workers.');

  if (rows.some((row) => row!.status !== 'succeeded' || !row!.provenance || !row!.provenance_signature || !row!.input_lock_sha256 || row!.architecture !== plan.architecture)) throw new PolicyError(409, 'Reproducibility requires successful signed native attempts with frozen inputs.');

  if (rows[0].revision_id !== rows[1].revision_id || rows[0].recipe_sha256 !== rows[1].recipe_sha256 || rows[0].input_lock_sha256 !== rows[1].input_lock_sha256) throw new PolicyError(409, 'Reproducibility attempts do not share exact recipe and input lock.');
  let contracts: Array<Record<string, unknown>>;

  try { contracts = rows.map((row) => row!.output_contract_json ? JSON.parse(row!.output_contract_json) as Record<string, unknown> : {}); }
  catch { throw new PolicyError(409, 'Reproducibility output contracts are invalid.'); }

  if (rows[0].input_lock_sha256 !== plan.inputSha256 || contracts.some((contract) => {
    const cohort = contract.cohort;

 return !cohort || typeof cohort !== 'object' || Array.isArray(cohort) || (cohort as Record<string, unknown>).id !== plan.cohortId || (cohort as Record<string, unknown>).revision !== plan.revision || (cohort as Record<string, unknown>).manifestSha256 !== plan.candidateSha256;
  })) throw new PolicyError(409, 'Reproducibility attempts do not bind the reviewed candidate and input lock.');

  for (const row of rows) {
    const publicKey = decodeBase64(row!.worker_public_key, 'worker public key'); const signature = decodeBase64(row!.provenance_signature!, 'native provenance signature');

    if (!await verifyEd25519(publicKey, new TextEncoder().encode(row!.provenance!), signature)) throw new PolicyError(409, 'Reproducibility attempt provenance signature is invalid.');
  }

  const actual = await Promise.all(attempts.map((attempt) => query<{ filename: string; sha256: string; artifact_key: string; size: number }>(db, 'SELECT filename,sha256,artifact_key,size FROM build_artifacts WHERE build_id=? AND attempt=? ORDER BY filename', attempt.buildId, attempt.attempt)));

  for (let index = 0; index < actual.length; index++) {
    const expected = attempts[index].outputs; const outputRefs = actual[index].map(({ filename, sha256 }) => ({ filename, sha256 }));

    if (canonicalJson(outputRefs) !== canonicalJson(expected)) throw new PolicyError(409, 'Reproducibility output bytes do not match retained attempt artifacts.');

    for (const output of actual[index]) await verifyR2Object(env, output.artifact_key, output.sha256, output.size);

    if (await outputSetDigest(expected) !== attempts[index].artifactSha256) throw new PolicyError(409, 'Reproducibility artifact set digest is invalid.');

    if (index === 0 && attempts[index].artifactSha256 !== plan.artifactSha256) throw new PolicyError(409, 'Reviewed reproducibility artifact set differs from the primary attempt.');

    const signed = await query<{ filename: string; artifact_key: string; signature_key: string | null; signature_sha256: string | null }>(db, `SELECT a.filename,a.artifact_key,s.signature_key,s.signature_sha256 FROM build_artifacts a JOIN signing_intents s ON s.build_id=a.build_id AND s.build_attempt=a.attempt
      AND s.object_kind='package' AND s.status='signed' AND s.artifact_filename=a.filename AND s.artifact_sha256=a.sha256
      WHERE a.build_id=? AND a.attempt=? ORDER BY a.filename`, attempts[index].buildId, attempts[index].attempt);

    const statement = await db.prepare("SELECT object_key,signature_key,signature_sha256 FROM signing_intents WHERE build_id=? AND build_attempt=? AND object_kind='attestation' AND status='signed' LIMIT 1").bind(attempts[index].buildId, attempts[index].attempt).first<{ object_key: string; signature_key: string | null; signature_sha256: string | null }>();

    if (signed.length !== expected.length || !statement?.signature_key || !statement.signature_sha256 || signed.some((item) => !item.signature_key || !item.signature_sha256 || item.signature_key !== `${item.artifact_key}.sig`) || statement.signature_key !== `${statement.object_key}.sig`) throw new PolicyError(409, 'Reproducibility requires signed package outputs and a signed native statement for both attempts.');

    for (const signature of [...signed, statement]) await verifyRetainedSignature(env, signature.signature_key!, signature.signature_sha256!);
  }

  const equal = canonicalJson(actual[0].map(({ filename, sha256 }) => ({ filename, sha256 }))) === canonicalJson(actual[1].map(({ filename, sha256 }) => ({ filename, sha256 })));

  if (['independently-reproduced', 'verified-reproducible'].includes(report.status) && !equal) throw new PolicyError(409, 'Reproducibility report claims equal bytes for mismatched artifacts.');

  if (report.status === 'mismatch' && equal) throw new PolicyError(409, 'Reproducibility report claims mismatch for equal artifacts.');

  return report.status;
}

async function verifyRetainedSignature(env: Env, key: string, digestValue: string): Promise<void> {
  if (!/^[a-f0-9]{64}$/.test(digestValue) || key.length > 1024 || /[\u0000\r\n]/.test(key)) throw new PolicyError(409, 'Retained native signature identity is invalid.');
  const object = await env.ARTIFACTS.get(key);

 if (!object || object.size <= 0 || object.size > 16 * 1024) throw new PolicyError(409, 'Retained native signature object is unavailable.');
  const bytes = new Uint8Array(await object.arrayBuffer());

 if (bytes.byteLength !== object.size || await sha256(bytes) !== digestValue) throw new PolicyError(409, 'Retained native signature bytes changed.');
}

export async function recordNativeQualification(env: Env, auth: AuthenticatedWorker, value: unknown): Promise<{ id: string; duplicate: boolean; status: QualificationStatus; reproducibilityStatus: ReproducibilityStatus | null; reportSha256: string }> {
  const evidence = parseEvidence(value); const planRecord = await currentPlan(env.DB, evidence.planId);

  if (!planRecord) throw new PolicyError(404, 'Qualification plan not found.');
  const { plan, row: planRow } = planRecord; await assertPlanReview(env.DB, evidence.planId);

  if (evidence.testPlanSha256 !== planRow.plan_sha256 || evidence.cohortId !== plan.cohortId || evidence.revision !== plan.revision || evidence.operation !== plan.operation || evidence.architecture !== plan.architecture || evidence.candidate.sha256 !== plan.candidateSha256 || evidence.input.sha256 !== plan.inputSha256 || evidence.artifact.sha256 !== plan.artifactSha256 || evidence.environment.sha256 !== plan.environmentSha256 || evidence.profile.id !== plan.profile.id || evidence.profile.sha256 !== plan.profile.sha256 || canonicalJson(evidence.coverage) !== canonicalJson(plan.coverage)) throw new PolicyError(409, 'Qualification evidence does not match its reviewed test plan.');

  if (evidence.workerId !== auth.worker.id || auth.worker.status !== 'active' || evidence.workerPublicKey !== auth.worker.public_key || auth.worker.architecture !== evidence.architecture) throw new PolicyError(403, 'Qualification evidence worker identity is not current.');
  await assertCandidate(env.DB, plan); await assertSelectedInput(env.DB, plan);
  const signedBytes = new TextEncoder().encode(canonicalJson(signedPayload(evidence))); const reportSha256 = await sha256(signedBytes);
  const publicKey = decodeBase64(auth.worker.public_key, 'worker public key'); const signature = decodeBase64(evidence.signature, 'qualification signature');

  if (!await verifyEd25519(publicKey, signedBytes, signature)) throw new PolicyError(401, 'Invalid qualification evidence signature.');

  if (await sha256(canonicalJson(plan.commands)) !== evidence.command.sha256) throw new PolicyError(409, 'Qualification command digest is invalid.');

  if (await sha256(canonicalJson({ machine: evidence.environment.machine, details: evidence.environment.details })) !== evidence.environment.sha256) throw new PolicyError(409, 'Environment evidence digest is invalid.');

  if (await sha256(canonicalJson(evidence.observed)) !== evidence.observedSha256) throw new PolicyError(409, 'Observed qualification evidence digest is invalid.');

  if (evidence.operation !== 'reproducibility' && evidence.result.exitCode === 0) assertOperationObservation(evidence.operation, evidence.observed);

  if (evidence.result.commands.length !== plan.commands.length || evidence.result.commands.some((result, index) => result.name !== plan.commands[index].name || result.exitCode !== 0 || !result.passed)) {
    if (evidence.operation !== 'reproducibility' && evidence.result.exitCode === 0) throw new PolicyError(409, 'Qualification pass requires every planned command to pass.');
  }

  let status: QualificationStatus = 'not-checked'; let reproducibilityStatus: ReproducibilityStatus | null = null;
  const allCommandsPassed = evidence.result.exitCode === 0 && evidence.result.commands.length === plan.commands.length && evidence.result.commands.every((result) => result.exitCode === 0 && result.passed);

  if (evidence.operation === 'reproducibility') {
    if (!evidence.reproducibility) throw new PolicyError(400, 'Reproducibility comparison is required.');

    if (evidence.reproducibility.secondary.workerId !== auth.worker.id) throw new PolicyError(403, 'The second native worker must submit the reproducibility comparison.');
    reproducibilityStatus = await actualReproducibility(env, plan, evidence.reproducibility);
    status = ['independently-reproduced', 'verified-reproducible'].includes(reproducibilityStatus) ? 'passed' : reproducibilityStatus === 'mismatch' ? 'failed' : 'not-checked';
  } else if (allCommandsPassed && evidence.observedSha256 === plan.expectedObservationSha256) status = 'passed';
  else if (evidence.result.exitCode !== 0 || evidence.result.commands.some((result) => result.exitCode !== 0 || !result.passed)) status = 'failed';

  const artifactRegistered = evidence.operation === 'reproducibility' ? true : evidence.coverage.kind === 'system'
    ? Boolean(await env.DB.prepare("SELECT 1 FROM owned_repository_universes WHERE lane='system' AND release_id=? AND root_sha256=? AND status IN ('prepared','published') LIMIT 1").bind(evidence.coverage.releaseId, evidence.artifact.sha256).first())
    : await registeredArtifact(env.DB, evidence.artifact.sha256, evidence.architecture, evidence.cohortId, evidence.revision);

  if (!artifactRegistered) throw new PolicyError(409, 'Qualification evidence artifact is not a registered native candidate output.');
  const duplicate = await env.DB.prepare('SELECT id,status,reproducibility_status,report_sha256 FROM native_qualification_evidence WHERE plan_id=? AND report_sha256=?').bind(evidence.planId, reportSha256).first<{ id: string; status: QualificationStatus; reproducibility_status: ReproducibilityStatus | null; report_sha256: string }>();

  if (duplicate) return { id: duplicate.id, duplicate: true, status: duplicate.status, reproducibilityStatus: duplicate.reproducibility_status, reportSha256: duplicate.report_sha256 };
  const evidenceId = id(); const createdAt = now(); const reportJson = canonicalJson(evidence);

  try {
    await env.DB.batch([
      env.DB.prepare(`INSERT INTO native_qualification_evidence(id,plan_id,cohort_id,revision,operation,architecture,candidate_sha256,input_sha256,artifact_sha256,environment_sha256,profile_id,profile_sha256,coverage_kind,coverage_pkgbase,coverage_root_sha256,coverage_release_id,coverage_sha256,coverage_json,observed_sha256,status,reproducibility_status,worker_id,worker_public_key,report_json,report_sha256,signature,created_at)
        VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).bind(evidenceId, evidence.planId, evidence.cohortId, evidence.revision, evidence.operation, evidence.architecture, evidence.candidate.sha256, evidence.input.sha256, evidence.artifact.sha256, evidence.environment.sha256, evidence.profile.id, evidence.profile.sha256, evidence.coverage.kind, evidence.coverage.pkgbase, evidence.coverage.rootSha256, evidence.coverage.releaseId, evidence.coverage.sha256, canonicalJson(evidence.coverage), evidence.observedSha256, status, reproducibilityStatus, evidence.workerId, evidence.workerPublicKey, reportJson, reportSha256, evidence.signature, createdAt),
      audit(env.DB, `worker:${auth.worker.id}`, 'qualification.evidence.recorded', evidenceId, { planId: evidence.planId, reportSha256, status, reproducibilityStatus })
    ]);
  } catch (cause) {
    if (String(cause).includes('UNIQUE')) {
      const existing = await env.DB.prepare('SELECT id,status,reproducibility_status,report_sha256 FROM native_qualification_evidence WHERE plan_id=? AND report_sha256=?').bind(evidence.planId, reportSha256).first<{ id: string; status: QualificationStatus; reproducibility_status: ReproducibilityStatus | null; report_sha256: string }>();

      if (existing) return { id: existing.id, duplicate: true, status: existing.status, reproducibilityStatus: existing.reproducibility_status, reportSha256: existing.report_sha256 };
    }

    throw cause;
  }

  return { id: evidenceId, duplicate: false, status, reproducibilityStatus, reportSha256 };
}

export async function addQualificationException(env: Env, actor: Actor | null, input: { evidenceId: string; subjectSha256: string; reason: string; expiresAt: number }) {
  humanMaintainer(actor); requireSecurity(actor); const evidence = await env.DB.prepare('SELECT * FROM native_qualification_evidence WHERE id=?').bind(input.evidenceId).first<QualificationRow>();

  if (!evidence) throw new PolicyError(404, 'Qualification evidence not found.');
  const subject = hash(input.subjectSha256, 'exception subject'); const reason = text(input.reason, 'exception reason', 2000); const expiresAt = integer(input.expiresAt, 'exception expiry', now() + 1, now() + 366 * 24 * 60 * 60);

  if (evidence.operation !== 'reproducibility') throw new PolicyError(409, 'Install, upgrade, recovery and boot failures cannot be waived by a qualification exception.');

  if (evidence.status === 'passed' || ['independently-reproduced', 'verified-reproducible'].includes(evidence.reproducibility_status ?? '')) throw new PolicyError(409, 'A passing qualification does not need an exception.');
  let report: QualificationEvidence;

  try { report = parseEvidence(JSON.parse(evidence.report_json)); } catch { throw new PolicyError(409, 'Qualification report is invalid.'); }

  const comparison = report.reproducibility;
  const subjects = new Set<string>([report.observedSha256, report.artifact.sha256]);

  for (const output of [...(comparison?.primary.outputs ?? []), ...(comparison?.secondary.outputs ?? [])]) subjects.add(output.sha256);

  if (!subjects.has(subject)) throw new PolicyError(409, 'Exception subject is not an exact output or diagnostic from this mismatch report.');
  const exceptionId = id(); const createdAt = now();
  await env.DB.batch([
    env.DB.prepare(`INSERT INTO native_qualification_exceptions(id,evidence_id,cohort_id,revision,operation,architecture,candidate_sha256,subject_sha256,reason,actor,created_at,expires_at)
      VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`).bind(exceptionId, evidence.id, evidence.cohort_id, evidence.revision, evidence.operation, evidence.architecture, evidence.candidate_sha256, subject, reason, actor!.id, createdAt, expiresAt),
    audit(env.DB, actor!.id, 'qualification.exception.created', exceptionId, { evidenceId: evidence.id, subjectSha256: subject, expiresAt })
  ]);

  return { id: exceptionId, evidenceId: evidence.id, expiresAt };
}

export async function qualificationEvidenceForGate(db: D1Database, input: { cohortId: string; revision: number; operation: QualificationOperation; architecture: Architecture; pkgbase?: string; coverageKind?: 'member' | 'system'; coverageReleaseId?: string; coverageRootSha256?: string }) {
  const scopeParts: string[] = [];
  const values: unknown[] = [input.cohortId, input.revision, input.operation, input.architecture];

  if (input.pkgbase) { scopeParts.push("e.coverage_kind='member'", 'e.coverage_pkgbase=?'); values.push(input.pkgbase); }
  else if (input.coverageKind) { scopeParts.push('e.coverage_kind=?'); values.push(input.coverageKind); }

  if (input.coverageReleaseId) { scopeParts.push('e.coverage_release_id=?'); values.push(input.coverageReleaseId); }

  if (input.coverageRootSha256) { scopeParts.push('e.coverage_root_sha256=?'); values.push(input.coverageRootSha256); }

  const scope = scopeParts.length ? ` AND ${scopeParts.join(' AND ')}` : '';

  const rows = await query<QualificationRow & { exception_id: string | null }>(db, `SELECT e.*,x.id AS exception_id FROM native_qualification_evidence e
    LEFT JOIN native_qualification_exceptions x ON x.evidence_id=e.id AND x.expires_at>unixepoch()
    WHERE e.cohort_id=? AND e.revision=? AND e.operation=? AND e.architecture=?${scope} ORDER BY e.created_at DESC,e.rowid DESC LIMIT 32`, ...values);

  const latest = rows[0];

  return latest && (latest.status === 'passed' || (input.operation === 'reproducibility' && latest.exception_id !== null)) ? latest : null;
}

export async function hasPassingQualification(db: D1Database, input: { cohortId: string; revision: number; operation: QualificationOperation; architecture: Architecture; pkgbase?: string; coverageKind?: 'member' | 'system'; coverageReleaseId?: string; coverageRootSha256?: string }): Promise<boolean> {
  return Boolean(await qualificationEvidenceForGate(db, input));
}

export async function qualificationEvidencePage(db: D1Database, cohortId: string, revision: number, operation?: QualificationOperation, architecture?: Architecture) {
  const values: unknown[] = [cohortId, revision]; let where = 'e.cohort_id=? AND e.revision=?';

  if (operation) { where += ' AND e.operation=?'; values.push(operation); }

  if (architecture) { where += ' AND e.architecture=?'; values.push(architecture); }

  return query<QualificationRow & { exception_id: string | null }>(db, `SELECT e.*,x.id AS exception_id,x.reason AS exception_reason,x.expires_at FROM native_qualification_evidence e
    LEFT JOIN native_qualification_exceptions x ON x.evidence_id=e.id AND x.expires_at>unixepoch() WHERE ${where} ORDER BY e.created_at DESC,e.rowid DESC LIMIT 256`, ...values);
}

export async function qualificationPlanForWorker(env: Env, auth: AuthenticatedWorker, planId: string) {
  const current = await currentPlan(env.DB, planId);

  if (!current) throw new PolicyError(404, 'Qualification plan not found.');
  await assertPlanReview(env.DB, planId);

  if (current.plan.architecture !== auth.worker.architecture || auth.worker.status !== 'active') throw new PolicyError(403, 'Qualification plan target does not match this worker.');
  await assertCandidate(env.DB, current.plan); await assertSelectedInput(env.DB, current.plan);
  const allArtifacts = current.plan.operation === 'reproducibility' ? [] : await candidateArtifactRows(env.DB, current.plan);
  const artifactSet = current.plan.operation === 'reproducibility' ? [] : current.plan.coverage.kind === 'system' ? allArtifacts : (allArtifacts.length > 0 && await outputSetDigest(allArtifacts.map(({ filename, sha256 }) => ({ filename, sha256 }))) === current.plan.artifactSha256 ? allArtifacts : allArtifacts.filter((artifact) => artifact.sha256 === current.plan.artifactSha256));
  const artifacts = artifactSet;

  return { planId: current.row.id, testPlanSha256: current.row.plan_sha256, plan: current.plan, artifacts: artifacts.map((artifact) => ({ ...artifact, path: `/api/worker/qualification/artifacts/${encodeURIComponent(planId)}/${encodeURIComponent(artifact.filename)}` })) };
}

export async function qualificationArtifactForWorker(env: Env, auth: AuthenticatedWorker, planId: string, filename: string) {
  const current = await currentPlan(env.DB, planId);

  if (!current) throw new PolicyError(404, 'Qualification plan not found.');
  await assertPlanReview(env.DB, planId);

  if (current.plan.architecture !== auth.worker.architecture || !safeFilenamePattern.test(filename)) throw new PolicyError(403, 'Qualification artifact target is unavailable to this worker.');
  await assertCandidate(env.DB, current.plan); await assertSelectedInput(env.DB, current.plan);

  let artifact = current.plan.coverage.kind === 'system'
    ? await env.DB.prepare(`SELECT a.artifact_key,a.sha256,a.size,a.filename FROM build_artifacts a JOIN builds b ON b.id=a.build_id AND b.attempt=a.attempt JOIN workers w ON w.id=b.worker_id AND w.status='active'
      JOIN revisions r ON r.id=b.revision_id JOIN cohort_members m ON m.recipe_revision_id=r.id
      WHERE a.filename=? AND b.architecture=? AND m.cohort_id=? AND m.revision=? AND b.status='succeeded' ORDER BY b.id DESC LIMIT 1`).bind(filename, auth.worker.architecture, current.plan.cohortId, current.plan.revision).first<{ artifact_key: string; sha256: string; size: number; filename: string }>()
    : await env.DB.prepare(`SELECT a.artifact_key,a.sha256,a.size,a.filename FROM build_artifacts a JOIN builds b ON b.id=a.build_id AND b.attempt=a.attempt JOIN workers w ON w.id=b.worker_id AND w.status='active'
      JOIN revisions r ON r.id=b.revision_id JOIN cohort_members m ON m.recipe_revision_id=r.id
      WHERE a.filename=? AND b.architecture=? AND m.cohort_id=? AND m.revision=? AND b.status='succeeded'`).bind(filename, auth.worker.architecture, current.plan.cohortId, current.plan.revision).first<{ artifact_key: string; sha256: string; size: number; filename: string }>();

  if (!artifact && current.plan.coverage.kind === 'system') artifact = await env.DB.prepare(`SELECT a.artifact_key,a.artifact_sha256 AS sha256,a.artifact_size AS size,a.filename FROM owned_repository_universe_packages u
      JOIN owned_repository_artifacts a ON a.id=u.artifact_id JOIN owned_repository_universes v ON v.id=u.universe_id
      WHERE a.filename=? AND v.lane='system' AND v.release_id=? AND v.root_sha256=? AND v.status IN ('prepared','published') AND u.target_architecture=?`).bind(filename, current.plan.coverage.releaseId, current.plan.coverage.rootSha256, auth.worker.architecture).first<{ artifact_key: string; sha256: string; size: number; filename: string }>();

  if (!artifact) throw new PolicyError(404, 'Qualification artifact not found.');
  const allArtifacts = await candidateArtifactRows(env.DB, current.plan); const artifactSet = allArtifacts.length > 0 && await outputSetDigest(allArtifacts.map(({ filename, sha256 }) => ({ filename, sha256 }))) === current.plan.artifactSha256;

  if (current.plan.coverage.kind === 'member' && !artifactSet && artifact.sha256 !== current.plan.artifactSha256) throw new PolicyError(404, 'Qualification artifact not found.');
  const object = await env.ARTIFACTS.get(artifact.artifact_key);

  if (!object || object.size !== artifact.size) throw new PolicyError(409, 'Qualification artifact storage changed.');

  return { filename: artifact.filename, sha256: artifact.sha256, size: artifact.size, body: object.body };
}
