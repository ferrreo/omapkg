import { canonicalJson } from '../canonical-json';
import { cohortMemberCount, type CohortManifest, type CohortMember } from '../cohorts';
import { requiredArchitectures } from '../distribution';
import type { Actor, Architecture } from '../model';
import { parseCatalogManifest, type CatalogRecord } from './catalog-ownership';
import { cohortMembers, readCohortManifest } from './cohort-members';
import { appendCohortScope, beginCohortScope, sealCohortScope } from './cohort-scope-uploads';
import { getCohort } from './cohorts';
import { now, query, sha256 } from './db';
import { PolicyError } from './policy';

const name = /^[a-z0-9][a-z0-9@._+-]{0,63}$/;
const digest = /^[a-f0-9]{64}$/;
const architectures = new Set<Architecture>(requiredArchitectures);

type RawPlanMember = { pkgbase: string; changed: boolean; removed: boolean; affectedBy: string[] };
type RawPlan = {
  architecture: Architecture;
  missingSeeds: string[];
  unappliedRules: string[];
  sourceGaps: Array<{ snapshot: string; source: string; reason: string | null }>;
  plan: {
    architecture: Architecture;
    seeds: string[];
    members: RawPlanMember[];
    buildGroups: Array<{ members: string[]; requiresBootstrapReview: boolean }>;
    findings: Array<{ snapshot: string; pkgbase: string; output: string; relation: string; providers: string[] }>;
    unresolvedCandidateRelations: number;
    ambiguousCandidateRelations: number;
  } | null;
};

export interface RebuildScopeReport {
  schemaVersion: 1;
  kind: 'rebuild-scope-proposal';
  baseline: string;
  candidate: string;
  requiredArchitectures: Architecture[];
  repositoryOrder: string[];
  shadowed: unknown[];
  rules: Array<{ pkgbase: string; rebuildOn: string[] }>;
  plans: RawPlan[];
  limits: string[];
}

export interface RebuildScopeBlocker {
  code: 'catalog-mapping' | 'recipe-mapping' | 'native-target' | 'source-gap' | 'bootstrap' | 'report' | 'scope';
  pkgbase: string | null;
  architecture: Architecture | null;
  reason: string;
}

export interface RebuildScopeMember {
  pkgbase: string;
  catalogRevision: number | null;
  catalogSha256: string | null;
  recipeRevisionId: string | null;
  changed: boolean;
  removed: boolean;
  affectedBy: string[];
  targets: Architecture[];
  cause: 'source-update' | 'rebuild';
  reason: string;
}

export interface RebuildScopePreview {
  reportSha256: string;
  cohortId: string;
  expectedRevision: number;
  title: string;
  lane: CohortManifest['lane'];
  systemVersion: string | null;
  parentSnapshot: string | null;
  compatibleSystems: string[];
  members: RebuildScopeMember[];
  blockers: RebuildScopeBlocker[];
  complete: boolean;
  targetPlans: Array<{ architecture: Architecture; members: number; missingSeeds: string[]; sourceGaps: number }>;
}

function object(input: unknown): Record<string, unknown> {
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw new PolicyError(400, 'Rebuild report must be a JSON object.');
  return input as Record<string, unknown>;
}

function string(input: unknown, label: string, max = 4096): string {
  if (typeof input !== 'string' || !input || input.length > max || /[\x00-\x1f\x7f]/.test(input)) throw new PolicyError(400, `Rebuild report has an invalid ${label}.`);
  return input;
}

function list(input: unknown, label: string, max = 100000): unknown[] {
  if (!Array.isArray(input) || input.length > max) throw new PolicyError(400, `Rebuild report has an invalid ${label}.`);
  return input;
}

function packageName(input: unknown, label = 'package name'): string {
  const value = string(input, label, 64);
  if (!name.test(value)) throw new PolicyError(400, `Rebuild report has an invalid ${label}.`);
  return value;
}

function target(input: unknown): Architecture {
  if (typeof input !== 'string' || !architectures.has(input as Architecture)) throw new PolicyError(400, 'Rebuild report has an invalid native target.');
  return input as Architecture;
}

function parseMember(input: unknown): RawPlanMember {
  const value = object(input);
  if (typeof value.changed !== 'boolean' || typeof value.removed !== 'boolean') throw new PolicyError(400, 'Rebuild report has an invalid member state.');
  const affectedBy = list(value.affectedBy, 'member causes', 256).map((item) => packageName(item, 'member cause'));
  return { pkgbase: packageName(value.pkgbase), changed: value.changed, removed: value.removed, affectedBy };
}

function parsePlan(input: unknown): RawPlan['plan'] {
  if (input === null) return null;
  const value = object(input);
  const unresolvedCandidateRelations = value.unresolvedCandidateRelations;
  const ambiguousCandidateRelations = value.ambiguousCandidateRelations;
  if (typeof unresolvedCandidateRelations !== 'number' || typeof ambiguousCandidateRelations !== 'number' ||
      !Number.isSafeInteger(unresolvedCandidateRelations) || !Number.isSafeInteger(ambiguousCandidateRelations) ||
      unresolvedCandidateRelations < 0 || ambiguousCandidateRelations < 0) throw new PolicyError(400, 'Rebuild report has invalid unresolved relation counts.');
  const parsed = {
    architecture: target(value.architecture),
    seeds: list(value.seeds, 'plan seeds', 100000).map((item) => packageName(item)),
    members: list(value.members, 'plan members', 100000).map(parseMember),
    buildGroups: list(value.buildGroups, 'build groups', 100000).map((item) => {
      const group = object(item);
      if (typeof group.requiresBootstrapReview !== 'boolean') throw new PolicyError(400, 'Rebuild report has an invalid build group.');
      return { members: list(group.members, 'build group members', 100000).map((member) => packageName(member)), requiresBootstrapReview: group.requiresBootstrapReview };
    }),
    findings: list(value.findings, 'plan findings', 100000).map((item) => {
      const finding = object(item);
      return { snapshot: string(finding.snapshot, 'finding snapshot', 32), pkgbase: packageName(finding.pkgbase), output: packageName(finding.output, 'finding output'),
        relation: string(finding.relation, 'finding relation', 256), providers: list(finding.providers, 'finding providers', 256).map((provider) => packageName(provider)) };
    }),
    unresolvedCandidateRelations, ambiguousCandidateRelations,
  };
  return parsed;
}

function parsePlanEnvelope(input: unknown): RawPlan {
  const value = object(input);
  const sourceGaps = list(value.sourceGaps, 'source gaps', 100000).map((item) => {
    const gap = object(item);
    return { snapshot: string(gap.snapshot, 'source gap snapshot', 32), source: string(gap.source, 'source gap source', 256), reason: gap.reason === null ? null : string(gap.reason, 'source gap reason', 2000) };
  });
  const architecture = target(value.architecture); const plan = parsePlan(value.plan);
  if (plan && plan.architecture !== architecture) throw new PolicyError(400, 'Rebuild report plan target does not match its envelope.');
  if (new Set(plan?.members.map((member) => member.pkgbase) ?? []).size !== (plan?.members.length ?? 0)) {
    throw new PolicyError(400, 'Rebuild report repeats a package in one target plan.');
  }
  return { architecture, missingSeeds: list(value.missingSeeds, 'missing seeds', 100000).map((item) => packageName(item)),
    unappliedRules: list(value.unappliedRules, 'unapplied rules', 100000).map((item) => packageName(item)), sourceGaps, plan };
}

/** Structural validation only. Catalog policy and recipe identity always come from D1 below. */
export function parseRebuildScopeReport(input: unknown): RebuildScopeReport {
  const value = object(input);
  if (value.schemaVersion !== 1 || value.kind !== 'rebuild-scope-proposal') throw new PolicyError(400, 'Use a version 1 rebuild-scope-proposal report.');
  const requiredArchitectures = list(value.requiredArchitectures, 'required architectures', 2).map(target);
  if (!requiredArchitectures.length || new Set(requiredArchitectures).size !== requiredArchitectures.length) throw new PolicyError(400, 'Rebuild report must select at least one native target.');
  const plans = list(value.plans, 'target plans', 2).map(parsePlanEnvelope);
  if (new Set(plans.map((plan) => plan.architecture)).size !== plans.length || plans.length !== requiredArchitectures.length ||
      plans.some((plan) => !requiredArchitectures.includes(plan.architecture))) throw new PolicyError(400, 'Rebuild report must have one plan per required target.');
  const rules = list(value.rules, 'rebuild rules', 100000).map((item) => {
    const rule = object(item);
    return { pkgbase: packageName(rule.pkgbase), rebuildOn: list(rule.rebuildOn, 'rebuild triggers', 256).map((name) => packageName(name, 'rebuild trigger')) };
  });
  const report = {
    schemaVersion: 1 as const,
    kind: 'rebuild-scope-proposal' as const,
    baseline: string(value.baseline, 'baseline digest', 64), candidate: string(value.candidate, 'candidate digest', 64),
    requiredArchitectures: requiredArchitectures.sort(), repositoryOrder: list(value.repositoryOrder, 'repository order', 32).map((item) => string(item, 'repository name', 32)),
    shadowed: list(value.shadowed, 'shadowed records', 100000), rules, plans,
    limits: list(value.limits, 'planner limits', 32).map((item) => string(item, 'planner limit', 2000)),
  };
  if (!digest.test(report.baseline) || !digest.test(report.candidate)) throw new PolicyError(400, 'Rebuild report has invalid inventory digests.');
  return report;
}

function planFor(report: RebuildScopeReport, architecture: Architecture) {
  return report.plans.find((plan) => plan.architecture === architecture)!;
}

function reportMembers(report: RebuildScopeReport) {
  const byName = new Map<string, { changed: boolean; removed: boolean; affectedBy: Set<string>; targets: Set<Architecture> }>();
  for (const plan of report.plans) for (const member of plan.plan?.members ?? []) {
    const existing = byName.get(member.pkgbase) ?? { changed: false, removed: false, affectedBy: new Set<string>(), targets: new Set<Architecture>() };
    existing.changed ||= member.changed; existing.removed ||= member.removed; member.affectedBy.forEach((cause) => existing.affectedBy.add(cause)); existing.targets.add(plan.architecture); byName.set(member.pkgbase, existing);
  }
  return [...byName.entries()].sort(([a], [b]) => a.localeCompare(b));
}

async function currentScope(db: D1Database, cohortId: string) {
  const cohort = await getCohort(db, cohortId);
  const manifest = await readCohortManifest(cohort);
  const members = [] as CohortMember[];
  if (manifest.schemaVersion === 1) members.push(...manifest.members);
  else for (let offset = 0; offset < cohortMemberCount(manifest); offset += 512) members.push(...await cohortMembers(db, cohort, offset, Math.min(512, cohortMemberCount(manifest) - offset)));
  return { cohort, manifest, members };
}

async function catalogRows(db: D1Database, names: string[]) {
  const rows: CatalogRecord[] = [];
  for (let offset = 0; offset < names.length; offset += 500) rows.push(...await query<CatalogRecord>(db, `SELECT p.pkgbase,p.current_revision,p.admitted_revision,r.*
    FROM catalog_packages p JOIN catalog_revisions r ON r.pkgbase=p.pkgbase AND r.revision=p.current_revision
    WHERE p.pkgbase IN (SELECT value FROM json_each(?))`, JSON.stringify(names.slice(offset, offset + 500))));
  return rows;
}

type RecipeRecord = { id: string; manifest_sha256: string; name: string; upstream_url: string; source_kind: string; area: string; status: string; latest_id: string; kinds: number; actors: number };
async function recipeRows(db: D1Database, ids: string[]) {
  const rows: RecipeRecord[] = [];
  for (let offset = 0; offset < ids.length; offset += 500) rows.push(...await query<RecipeRecord>(db, `SELECT r.id,r.manifest_sha256,q.name,q.upstream_url,q.source_kind,q.area,q.status,
      (SELECT latest.id FROM revisions latest WHERE latest.request_id=q.id ORDER BY latest.created_at DESC,latest.rowid DESC LIMIT 1) AS latest_id,
      COUNT(DISTINCT CASE WHEN a.revoked_at IS NULL THEN a.kind END) AS kinds,
      COUNT(DISTINCT CASE WHEN a.revoked_at IS NULL THEN a.actor END) AS actors
    FROM revisions r JOIN requests q ON q.id=r.request_id LEFT JOIN approvals a ON a.revision_id=r.id AND a.manifest_sha256=r.manifest_sha256
    WHERE r.id IN (SELECT value FROM json_each(?)) GROUP BY r.id`, JSON.stringify(ids.slice(offset, offset + 500))));
  return rows;
}

function targetBlockers(report: RebuildScopeReport, pkgbase: string, policyTargets: Architecture[], exceptions: Architecture[]) {
  const blockers: RebuildScopeBlocker[] = [];
  for (const architecture of report.requiredArchitectures) {
    const plan = planFor(report, architecture);
    if (policyTargets.includes(architecture) && !exceptions.includes(architecture) && !(plan.plan?.members.some((member) => member.pkgbase === pkgbase))) {
      blockers.push({ code: 'native-target', pkgbase, architecture, reason: `Planner report has no ${architecture} member for a package requiring that target.` });
    }
  }
  return blockers;
}

/** Resolve report names against current admitted policies and the selected cohort's current recipe scope. */
export async function previewRebuildCohort(db: D1Database, cohortId: string, input: unknown): Promise<RebuildScopePreview> {
  const report = parseRebuildScopeReport(input); const reportSha256 = await sha256(canonicalJson(report));
  const { cohort, manifest, members: scopedMembers } = await currentScope(db, cohortId);
  const scopeByName = new Map(scopedMembers.map((member) => [member.pkgbase, member]));
  const reportMemberRows = reportMembers(report);
  const catalogByName = new Map((await catalogRows(db, reportMemberRows.map(([pkgbase]) => pkgbase))).map((row) => [row.pkgbase, row]));
  const recipeIds = [...new Set(reportMemberRows.map(([pkgbase]) => scopeByName.get(pkgbase)?.recipe?.id).filter((id): id is string => Boolean(id)))];
  const recipeById = new Map((await recipeRows(db, recipeIds)).map((row) => [row.id, row]));
  const blockers: RebuildScopeBlocker[] = [];
  for (const architecture of requiredArchitectures.filter((item) => !report.requiredArchitectures.includes(item))) {
    blockers.push({ code: 'native-target', pkgbase: null, architecture, reason: `Planner report omits the required ${architecture} target; run a complete all-target plan.` });
  }
  const members: RebuildScopeMember[] = [];
  for (const [pkgbase, detail] of reportMemberRows) {
    const catalog = catalogByName.get(pkgbase);
    if (!catalog || catalog.current_revision !== catalog.admitted_revision) {
      blockers.push({ code: 'catalog-mapping', pkgbase, architecture: null, reason: `${pkgbase}: current catalog policy is missing or not independently admitted.` });
      members.push({ pkgbase, catalogRevision: null, catalogSha256: null, recipeRevisionId: null, changed: detail.changed, removed: detail.removed,
        affectedBy: [...detail.affectedBy].sort(), targets: [...detail.targets].sort(), cause: detail.changed ? 'source-update' : 'rebuild', reason: 'Current admitted catalog mapping is required.' });
      continue;
    }
    const policy = parseCatalogManifest(JSON.parse(catalog.manifest_json));
    const scope = scopeByName.get(pkgbase);
    if (!scope || scope.catalogRevision !== catalog.revision || scope.catalogSha256 !== catalog.manifest_sha256) {
      blockers.push({ code: 'catalog-mapping', pkgbase, architecture: null, reason: `${pkgbase}: cohort scope does not bind the current admitted catalog revision.` });
    }
    if (!scope?.recipe?.id) blockers.push({ code: 'recipe-mapping', pkgbase, architecture: null, reason: `${pkgbase}: current cohort scope has no reviewed recipe binding.` });
    else {
      const recipe = recipeById.get(scope.recipe.id);
      const recipeMatches = recipe?.manifest_sha256 === scope.recipe.manifestSha256 && recipe.latest_id === scope.recipe.id && recipe.name === pkgbase &&
        recipe.upstream_url === policy.upstreamUrl && recipe.source_kind === policy.sourceKind && recipe.area === policy.ownerArea &&
        !['blocked', 'rejected', 'generating'].includes(recipe.status);
      const reviews = recipeMatches ? recipe : null;
      if (!recipeMatches || !reviews || reviews.kinds < 2 || reviews.actors < 2) blockers.push({ code: 'recipe-mapping', pkgbase, architecture: null, reason: `${pkgbase}: current recipe binding is stale or lacks independent area and security review.` });
    }
    blockers.push(...targetBlockers(report, pkgbase, policy.architectures, policy.architectureExceptions.map((item) => item.architecture)));
    members.push({ pkgbase, catalogRevision: catalog.revision, catalogSha256: catalog.manifest_sha256, recipeRevisionId: scope?.recipe?.id ?? null, changed: detail.changed,
      removed: detail.removed, affectedBy: [...detail.affectedBy].sort(), targets: [...detail.targets].sort(), cause: detail.changed ? 'source-update' : 'rebuild',
      reason: detail.affectedBy.size ? `Rebuild scope affected by ${[...detail.affectedBy].sort().join(', ')}.` : 'Changed package is a direct rebuild seed.' });
  }
  for (const plan of report.plans) {
    if (!plan.plan) blockers.push({ code: 'native-target', pkgbase: null, architecture: plan.architecture, reason: `Planner report has no complete ${plan.architecture} plan.` });
    for (const seed of plan.missingSeeds) blockers.push({ code: 'native-target', pkgbase: seed, architecture: plan.architecture, reason: `Changed package is absent from the ${plan.architecture} inventory.` });
    for (const rule of plan.unappliedRules) blockers.push({ code: 'report', pkgbase: rule, architecture: plan.architecture, reason: `Catalog rebuild rule for ${rule} was not present in the ${plan.architecture} inventory.` });
    for (const gap of plan.sourceGaps) blockers.push({ code: 'source-gap', pkgbase: null, architecture: plan.architecture, reason: `${gap.snapshot} source ${gap.source} is unavailable${gap.reason ? `: ${gap.reason}` : '.'}` });
    for (const group of plan.plan?.buildGroups.filter((group) => group.requiresBootstrapReview) ?? []) {
      blockers.push({ code: 'bootstrap', pkgbase: group.members.join(', '), architecture: plan.architecture, reason: `Cyclic build group requires reviewed bootstrap inputs: ${group.members.join(', ')}.` });
    }
    if ((plan.plan?.unresolvedCandidateRelations ?? 0) > 0) blockers.push({ code: 'report', pkgbase: null, architecture: plan.architecture, reason: `${plan.plan!.unresolvedCandidateRelations} candidate dependency relation(s) have no provider.` });
    if ((plan.plan?.ambiguousCandidateRelations ?? 0) > 0) blockers.push({ code: 'report', pkgbase: null, architecture: plan.architecture, reason: `${plan.plan!.ambiguousCandidateRelations} candidate dependency relation(s) have multiple providers.` });
  }
  if (members.length > 100000) blockers.push({ code: 'scope', pkgbase: null, architecture: null, reason: 'Complete scope exceeds the 100,000-member cohort limit.' });
  return { reportSha256, cohortId, expectedRevision: cohort.current_revision, title: manifest.title, lane: manifest.lane, systemVersion: manifest.systemVersion,
    parentSnapshot: manifest.parentSnapshot, compatibleSystems: manifest.compatibleSystems, members, blockers,
    complete: members.length > 0 && blockers.every((blocker) => !['catalog-mapping', 'recipe-mapping', 'native-target', 'scope'].includes(blocker.code)),
    targetPlans: requiredArchitectures.map((architecture) => { const plan = report.plans.find((item) => item.architecture === architecture); return {
      architecture, members: plan?.plan?.members.length ?? 0, missingSeeds: plan?.missingSeeds ?? [], sourceGaps: plan?.sourceGaps.length ?? 0,
    }; }) };
}

/** Create one explicit plan-phase scope revision. This never inserts or queues a build. */
export async function createRebuildCohortDraft(db: D1Database, actor: Actor | null, cohortId: string, report: unknown, reason: string) {
  const preview = await previewRebuildCohort(db, cohortId, report);
  if (!preview.complete) throw new PolicyError(409, 'Resolve current catalog, recipe and native-target mappings before creating the cohort draft.');
  const metadata = { title: preview.title, lane: preview.lane, systemVersion: preview.systemVersion, parentSnapshot: preview.parentSnapshot, compatibleSystems: preview.compatibleSystems };
  const upload = await beginCohortScope(db, actor, cohortId, preview.expectedRevision, metadata, preview.members.length, `rebuild-${preview.reportSha256.slice(0, 32)}`);
  for (let offset = 0; offset < preview.members.length; offset += 100) {
    await appendCohortScope(db, actor, upload.id, offset / 100, preview.members.slice(offset, offset + 100).map((member) => ({
      pkgbase: member.pkgbase, catalogRevision: member.catalogRevision!, recipeRevisionId: member.recipeRevisionId,
      cause: member.cause, reason: member.reason,
    })));
  }
  const result = await sealCohortScope(db, actor, upload.id, reason);
  return { ...preview, result, buildsCreated: 0 };
}

export interface RebuildCoverage {
  generatedAt: number;
  queue: Array<{ architecture: Architecture; queued: number; oldestAgeSeconds: number | null }>;
  targetParity: Array<{ architecture: Architecture; expected: number; succeeded: number; measured: boolean }>;
  checks: { measured: boolean; records: number; byKind: Array<{ kind: string; architecture: Architecture; records: number }> };
  catalog: { total: number; admitted: number };
}

/** Operational measurements from persisted rows. Empty measurements stay explicitly unknown. */
export async function rebuildCoverage(db: D1Database, at = now()): Promise<RebuildCoverage> {
  const queueRows = await query<{ architecture: Architecture; queued: number; oldest: number | null }>(db, `SELECT architecture,COUNT(*) AS queued,MIN(created_at) AS oldest
    FROM builds WHERE status IN ('queued','leased') GROUP BY architecture`);
  const queue = requiredArchitectures.map((architecture) => { const row = queueRows.find((item) => item.architecture === architecture); return {
    architecture, queued: Number(row?.queued ?? 0), oldestAgeSeconds: row?.oldest === null || row?.oldest === undefined ? null : Math.max(0, at - row.oldest),
  }; });
  const targetParity = await Promise.all(requiredArchitectures.map(async (architecture) => {
    const row = await db.prepare(`SELECT COUNT(DISTINCT m.cohort_id||':'||m.pkgbase) AS expected,
      COUNT(DISTINCT CASE WHEN EXISTS(SELECT 1 FROM builds b WHERE b.revision_id=m.recipe_revision_id AND b.architecture=? AND b.status='succeeded') THEN m.cohort_id||':'||m.pkgbase END) AS succeeded
      FROM cohorts c JOIN cohort_members m ON m.cohort_id=c.id AND m.revision=c.current_revision
      JOIN catalog_revisions r ON r.pkgbase=m.pkgbase AND r.revision=m.catalog_revision,json_each(r.manifest_json,'$.architectures') target
      WHERE target.value=? AND m.recipe_revision_id IS NOT NULL`).bind(architecture, architecture).first<{ expected: number; succeeded: number }>();
    const expected = Number(row?.expected ?? 0); return { architecture, expected, succeeded: Number(row?.succeeded ?? 0), measured: expected > 0 };
  }));
  const checkRows = await query<{ kind: string; architecture: Architecture; records: number }>(db,
    'SELECT kind,architecture,COUNT(*) AS records FROM cohort_checks GROUP BY kind,architecture ORDER BY kind,architecture');
  const catalog = await db.prepare(`SELECT COUNT(*) AS total,SUM(CASE WHEN admitted_revision=current_revision THEN 1 ELSE 0 END) AS admitted FROM catalog_packages`)
    .first<{ total: number; admitted: number }>();
  return { generatedAt: at, queue, targetParity, checks: { measured: checkRows.length > 0, records: checkRows.reduce((sum, row) => sum + Number(row.records), 0), byKind: checkRows },
    catalog: { total: Number(catalog?.total ?? 0), admitted: Number(catalog?.admitted ?? 0) } };
}

export const parseRebuildReport = parseRebuildScopeReport;
