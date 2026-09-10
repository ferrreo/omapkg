import * as v from 'valibot';
import type { Revision } from './model';
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

/** Immutable input references are review scope; live database authority is checked separately. */
export function preservedRecipe(revision: Pick<Revision, 'id' | 'sbom_json' | 'architectures_json'>): PreservedRecipe | null {
  const value = readOprEvidence(JSON.parse(revision.sbom_json))?.preservedRecipe;
  if (value === undefined) return null;
  const parsed = v.safeParse(schema, value);
  if (!parsed.success) throw new Error('Invalid preserved recipe evidence');
  const evidence = parsed.output, targets = JSON.parse(revision.architectures_json);
  if (!Array.isArray(targets) || !targets.length || targets.length !== new Set(targets).size ||
      JSON.stringify([...targets].sort()) !== JSON.stringify(Object.keys(evidence.sources).sort()) ||
      JSON.stringify([...targets].sort()) !== JSON.stringify(Object.keys(evidence.dependencies).sort()) ||
      evidence.metadataDirectory !== `.opr-review-${revision.id}` || evidence.capture.size > 512 * 1024) throw new Error('Preserved recipe scope differs from revision');
  return evidence;
}
