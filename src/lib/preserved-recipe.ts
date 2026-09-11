import * as v from 'valibot';
import type { Architecture, Revision } from './model';
import { readOprEvidence } from './server/sbom';
import { parseArchRelation } from './server/arch';

const object = v.strictObject({ sha256: v.pipe(v.string(), v.regex(/^[a-f0-9]{64}$/)),
  size: v.pipe(v.number(), v.integer(), v.minValue(1), v.maxValue(2 * 1024 * 1024)) });

const relations = v.pipe(v.array(v.pipe(v.string(), v.maxLength(256), v.check((value) => Boolean(parseArchRelation(value))))), v.maxLength(2048));

const dependencies = v.strictObject({ runtime: relations, build: relations });

const schema = v.strictObject({ schemaVersion: v.literal(1), capture: object,
  sources: v.strictObject({ x86_64: v.optional(object), aarch64: v.optional(object) }),
  dependencies: v.strictObject({ x86_64: v.optional(dependencies), aarch64: v.optional(dependencies) }),
  metadataDirectory: v.pipe(v.string(), v.regex(/^\.opr-review-[A-Za-z0-9_-]{8,128}$/)) });

export type PreservedRecipe = v.InferOutput<typeof schema>;

const buildSchema = v.strictObject({ capture: object, sourceBundle: object,
  recipe: v.optional(object), inspection: v.optional(v.strictObject({ srcinfoSha256: v.pipe(v.string(), v.regex(/^[a-f0-9]{64}$/)), architectures: v.optional(v.record(v.pipe(v.string(), v.regex(/^(x86_64|aarch64)$/)), v.pipe(v.string(), v.regex(/^[a-f0-9]{64}$/)))) })) });

export type PreservedBuildInputs = v.InferOutput<typeof buildSchema>;

export function parsePreservedBuildInputs(value: unknown): PreservedBuildInputs {
  const inputs = v.parse(buildSchema, value);

  if (inputs.capture.size > 512 * 1024) throw new Error('Preserved capture exceeds metadata budget');

  return inputs;
}

export function preservedBuildInputs(revision: Pick<Revision, 'id' | 'sbom_json' | 'architectures_json' | 'preserved_origin_revision_id'>, target: Architecture): PreservedBuildInputs | null {
  const evidence = preservedRecipe(revision);

  if (!evidence) return null;

  if (!evidence.sources[target]) throw new Error('Preserved sources omit native target');

  const repair = readOprEvidence(JSON.parse(revision.sbom_json))?.factoryRepair;
  const recipe = repair && typeof repair === 'object' && !Array.isArray(repair) ? (repair as { recipe?: unknown }).recipe : undefined;
  const inspection = repair && typeof repair === 'object' && !Array.isArray(repair) ? (repair as { inspection?: unknown }).inspection : undefined;
  const parsed = v.safeParse(buildSchema, { capture: evidence.capture, sourceBundle: evidence.sources[target], ...(recipe === undefined ? {} : { recipe }), ...(inspection === undefined ? {} : { inspection }) });
  if (!parsed.success) throw new Error('Invalid preserved repair inputs');
  return parsed.output;
}

/** Immutable input references are review scope; live database authority is checked separately. */
export function preservedRecipe(revision: Pick<Revision, 'id' | 'sbom_json' | 'architectures_json' | 'preserved_origin_revision_id'>): PreservedRecipe | null {
  const value = readOprEvidence(JSON.parse(revision.sbom_json))?.preservedRecipe;

  if (value === undefined) return null;
  const parsed = v.safeParse(schema, value);

  if (!parsed.success) throw new Error('Invalid preserved recipe evidence');
  const evidence = parsed.output, targets = JSON.parse(revision.architectures_json);

  if (!Array.isArray(targets) || !targets.length || targets.length !== new Set(targets).size ||
      JSON.stringify([...targets].sort()) !== JSON.stringify(Object.keys(evidence.sources).sort()) ||
      JSON.stringify([...targets].sort()) !== JSON.stringify(Object.keys(evidence.dependencies).sort()) ||
      evidence.metadataDirectory !== `.opr-review-${revision.preserved_origin_revision_id ?? revision.id}` || evidence.capture.size > 512 * 1024) throw new Error('Preserved recipe scope differs from revision');

  return evidence;
}
