import type { Architecture } from '../../src/lib/model';
import type { CatalogManifest } from '../../src/lib/distribution';
import type { InputObject } from '../../src/lib/frozen-inputs';
import { canonicalJson } from '../../src/lib/canonical-json';
import { preservedRecipe, type PreservedRecipe } from '../../src/lib/preserved-recipe';
import { verifyRecipeCapture } from '../../src/lib/recipe-capture';
import { srcinfoField } from '../../src/lib/srcinfo';
import { getCatalogPackage, parseCatalogManifest } from '../../src/lib/server/catalog-ownership';
import { getRecipeCapture, recipeCaptureBytes } from '../../src/lib/server/recipe-captures';
import { retainedRecipeSources } from '../../src/lib/server/recipe-source-plans';
import { catalogRecipePath } from '../../src/lib/server/catalog-recipe';
import { PolicyError } from '../../src/lib/server/policy';
import { assembleRecipeRevision } from './revision';
import { assertSmokeCommand } from './security';
import type { FactoryCandidate, FactoryEnv } from './types';

export type PreservedRevisionInput = { requestId: string; revisionId: string; capture: InputObject;
  sources: Partial<Record<Architecture, InputObject>>; smokeCommands: string[]; reason: string };

export async function preservedCatalog(db: D1Database, pkgbase: string) {
  const record = await getCatalogPackage(db, pkgbase);
  if (!record || record.admitted_revision !== record.current_revision ||
      !await db.prepare('SELECT 1 FROM authorized_catalog_inputs WHERE pkgbase=? AND revision=? AND manifest_sha256=?')
        .bind(pkgbase, record.revision, record.manifest_sha256).first()) throw new PolicyError(409, 'Current, independently reviewed catalog admission is required before recipe import.');
  return { record, policy: parseCatalogManifest(JSON.parse(record.manifest_json)) };
}

/** Original shell is neither evaluated nor rendered in the coordinator. */
export async function createPreservedRevision(env: FactoryEnv, input: PreservedRevisionInput) {
  const capture = await getRecipeCapture(env, input.capture.sha256);
  if (canonicalJson(capture.reference) !== canonicalJson(input.capture)) throw new PolicyError(409, 'Recipe capture reference changed.');
  const catalog = await preservedCatalog(env.DB, capture.manifest.pkgbase), policy: CatalogManifest = catalog.policy;
  if (canonicalJson(Object.keys(input.sources).sort()) !== canonicalJson([...policy.architectures].sort())) throw new PolicyError(409, 'Select a retained source bundle for every admitted catalog target.');
  if (!input.smokeCommands.length || input.smokeCommands.length > 64) throw new PolicyError(400, 'Provide 1–64 maintainer smoke commands.');
  let smokeCommands: string[];
  try { smokeCommands = input.smokeCommands.map(assertSmokeCommand); }
  catch (cause) { throw new PolicyError(400, cause instanceof Error ? cause.message : 'Invalid smoke commands.'); }
  const inspected = await verifyRecipeCapture(capture.manifest, (ref) => recipeCaptureBytes(env, ref));
  const recipe = new TextDecoder('utf-8', { fatal: true }).decode(inspected.get('PKGBUILD'));
  const metadataDirectory = `.opr-review-${input.revisionId}`;
  if (capture.manifest.files.some((file) => file.path === metadataDirectory || file.path.startsWith(metadataDirectory + '/'))) throw new PolicyError(409, 'Review metadata directory collides with an original recipe path.');
  const evidence: PreservedRecipe = { schemaVersion: 1, capture: capture.reference, sources: input.sources, dependencies: {}, metadataDirectory };
  const prepared = [];
  for (const target of policy.architectures) {
    const source = await retainedRecipeSources(env, capture.reference.sha256, input.sources[target]!);
    const metadata = source.metadata;
    if (source.plan.architecture !== target || metadata.pkgbase !== policy.pkgbase ||
        canonicalJson(metadata.outputs.map((output) => output.name).sort()) !== canonicalJson(policy.outputs) ||
        (prepared.length && prepared[0].metadata.version !== metadata.version)) throw new PolicyError(409, 'Native recipe identity, full version or split outputs differ from catalog scope.');
    for (const output of metadata.outputs) {
      const architectures = srcinfoField(metadata, output, 'arch');
      const portable = policy.artifactArchitecture === 'any' || policy.portableOutputs?.includes(output.name);
      if ((portable && (architectures.length !== 1 || architectures[0] !== 'any')) || (!portable && (!architectures.includes(target) || architectures.includes('any')))) {
        throw new PolicyError(409, `Inspected output architecture differs from catalog policy: ${output.name} on ${target}.`);
      }
    }
    const relations = (keys: string[]) => [...new Set(metadata.outputs.flatMap((output) => keys.flatMap((key) => srcinfoField(metadata, output, key, target))))].sort();
    evidence.dependencies[target] = { runtime: relations(['depends']), build: relations(['makedepends', 'checkdepends']) };
    prepared.push(source);
  }
  const metadata = prepared[0].metadata;
  const buildImages = Object.fromEntries(prepared.map((source) => [source.plan.architecture, source.imageRef]));
  const description = metadata.base.pkgdesc?.[0] ?? policy.description;
  if (!description.trim() || description.length > 160 || /[\x00\r\n]/.test(description)) throw new PolicyError(409, 'Recipe description exceeds reviewed package metadata limits.');
  // SOURCE_DATE_EPOCH comes from the captured recipe commit, not wall-clock import time.
  const commit = new TextDecoder('utf-8', { fatal: true }).decode(await recipeCaptureBytes(env, capture.manifest.git.commit));
  const timestamp = /^committer .* (\d{1,15}) [+-]\d{4}$/m.exec(commit.split('\n\n')[0])?.[1];
  const sourceDateEpoch = Number(timestamp);
  if (timestamp === undefined || !Number.isSafeInteger(sourceDateEpoch)) throw new PolicyError(409, 'Captured recipe commit has no bounded source timestamp.');
  const candidate: FactoryCandidate = {
    catalogPath: await catalogRecipePath(env.DB, policy.pkgbase, policy.collection),
    request: { id: input.requestId, name: policy.pkgbase, upstreamUrl: policy.upstreamUrl, sourceKind: policy.sourceKind, area: policy.ownerArea, declaredLicense: policy.license },
    version: metadata.pkgver, pkgrel: Number(metadata.pkgrel.split('.')[0]), sources: [],
    dependencies: [...new Set(Object.values(evidence.dependencies).flatMap((value) => value!.runtime))].sort(),
    makeDependencies: [...new Set(Object.values(evidence.dependencies).flatMap((value) => value!.build))].sort(),
    smokeCommands, architectures: policy.architectures, buildImages, imageDigest: prepared[0].imageRef, sourceDateEpoch,
    license: policy.license, surface: 'binary', description, recipeMode: 'custom-shell', buildCommands: [], packageCommands: [],
    explanation: input.reason, upstreamCommit: capture.manifest.commit,
    sbom: { preservedRecipe: evidence, packageVersion: { epoch: metadata.epoch, pkgrel: metadata.pkgrel } },
  };
  const draft = await assembleRecipeRevision(candidate, recipe, { passed: true, repairAttempts: 0, checks: [
    { name: 'original-git-tree', passed: true, detail: 'Complete retained Git proof, paths, bytes and modes verified.' },
    { name: 'native-metadata', passed: true, detail: 'Current signed inspections match admitted targets, split outputs and full version.' },
    { name: 'retained-sources', passed: true, detail: 'Complete source inventories retained for every target. Offline makepkg verification remains a build gate.' },
  ] }, input.revisionId);
  preservedRecipe(draft.revision);
  if (new TextEncoder().encode(canonicalJson(draft)).length > 4 * 1024 * 1024) throw new PolicyError(409, 'Preserved review draft exceeds its 4 MiB metadata budget.');
  return { draft, catalog };
}
