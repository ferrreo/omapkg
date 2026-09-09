import type { Revision } from '../../src/lib/model';
import { sha256 } from '../../src/lib/server/db';
import { readOprEvidence } from '../../src/lib/server/sbom';
import { renderPublicRecipe, renderRecipe, type PublicRecipeOptions } from './recipe';
import { templateCommands, TEMPLATE_DEFINITIONS, type RecipeTemplate } from './recipe-template';
import type { FactoryCandidate } from './types';

export function revisionRecipePolicy(sbom: string): { mode: 'template' | 'custom-shell'; recorded: boolean } {
  const policy = readOprEvidence(JSON.parse(sbom))?.recipePolicy as { mode?: unknown } | undefined;
  return { mode: policy?.mode === 'template' ? 'template' : 'custom-shell', recorded: Boolean(policy) };
}

export async function validateRecipePolicy(revision: Revision): Promise<void> {
  const policy = readOprEvidence(JSON.parse(revision.sbom_json))?.recipePolicy as {
    version: number; mode: string; rendererVersion: number; template: RecipeTemplate; templateSha256: string;
    packageName: string; sourceKind: 'git' | 'archive'; sourceRoot?: string; publicOptions?: PublicRecipeOptions;
  } | undefined;
  // Historical evidence remains readable; it never becomes a template by inference.
  if (!policy) return;
  if (policy.version !== 1 || !['template', 'custom-shell'].includes(policy.mode)) throw new Error('Unknown recipe policy');
  if (policy.mode === 'custom-shell') return;
  const commands = templateCommands(policy.template);
  if (policy.rendererVersion !== 1 || policy.templateSha256 !== await sha256(JSON.stringify(TEMPLATE_DEFINITIONS[policy.template.id]))) {
    throw new Error('Recipe template version or digest mismatch');
  }
  const candidate: FactoryCandidate = {
    request: { id: revision.request_id, name: policy.packageName, sourceKind: policy.sourceKind, upstreamUrl: '', area: 'development', declaredLicense: revision.license },
    version: revision.version, pkgrel: revision.pkgrel ?? 1, sources: JSON.parse(revision.sources_json), sourceRoot: policy.sourceRoot,
    dependencies: JSON.parse(revision.dependencies_json), makeDependencies: JSON.parse(revision.make_dependencies_json ?? '[]'),
    architectures: JSON.parse(revision.architectures_json), imageDigest: revision.image_digest, sourceDateEpoch: revision.source_date_epoch,
    license: revision.license, surface: revision.surface, description: revision.description ?? '', explanation: '',
    recipeMode: 'template', template: policy.template, buildCommands: [], packageCommands: [], smokeCommands: [],
  };
  if (renderRecipe(candidate) !== revision.recipe || JSON.stringify(commands.smoke) !== revision.smoke_commands_json) {
    throw new Error('Template recipe or smoke commands differ from deterministic rendering');
  }
  const publicRecipe = policy.publicOptions ? renderPublicRecipe(candidate, policy.publicOptions) : null;
  if (publicRecipe !== (revision.public_recipe ?? null)) throw new Error('Public recipe differs from deterministic rendering');
}

export async function assertExplicitReview(db: D1Database, revisionId: string, manifestSha256: string, sbom: string): Promise<void> {
  const policy = revisionRecipePolicy(sbom);
  const exceptions = (readOprEvidence(JSON.parse(sbom))?.runtimeExceptions as unknown[] | undefined) ?? [];
  if ((!policy.recorded || policy.mode !== 'custom-shell') && !exceptions.length) return;
  const rows = await db.prepare(`SELECT a.kind FROM approvals a WHERE a.revision_id=? AND a.manifest_sha256=? AND a.revoked_at IS NULL
    AND EXISTS (SELECT 1 FROM audit_events e WHERE e.action='revision.approved' AND e.actor=a.actor AND e.created_at=a.created_at
      AND json_extract(e.detail,'$.revisionId')=a.revision_id AND json_extract(e.detail,'$.kind')=a.kind
      AND json_extract(e.detail,'$.manifestSha256')=a.manifest_sha256
      AND (?=0 OR json_extract(e.detail,'$.customShellAcknowledged')=1)
      AND (?=0 OR json_extract(e.detail,'$.runtimeExceptionsAcknowledged')=1))`)
    .bind(revisionId, manifestSha256, policy.mode === 'custom-shell' ? 1 : 0, exceptions.length ? 1 : 0).all<{ kind: string }>();
  const kinds = new Set(rows.results.map((row) => row.kind));
  if (!kinds.has('area') || !kinds.has('security')) throw new Error('Both reviewers must explicitly acknowledge custom shell and runtime exceptions for this manifest.');
}
