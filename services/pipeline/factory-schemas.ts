import * as v from 'valibot';

const vendorArtifactSchema = v.object({
    schemaVersion: v.literal(1),
    format: v.picklist(['deb', 'rpm', 'appimage1', 'appimage2', 'run']),
    surface: v.picklist(['binary', 'recipe']),
    sourcePath: v.string(),
    sourceSize: v.number(),
    sourceSha256: v.pipe(v.string(), v.regex(/^[0-9a-f]{64}$/)),
    payloadPath: v.nullable(v.string()),
    entriesPath: v.nullable(v.string()),
    controlPath: v.optional(v.nullable(v.string())),
    controlEntriesPath: v.optional(v.nullable(v.string())),
    inventory: v.optional(v.pipe(v.array(v.string()), v.maxLength(200))),
    controlInventory: v.optional(v.pipe(v.array(v.string()), v.maxLength(200))),
    appimageOffset: v.optional(v.nullable(v.number())),
    metadata: v.record(v.string(), v.string()),
});

export const factoryCandidateSchema = v.object({
  version: v.pipe(v.string(), v.minLength(1), v.maxLength(128)),
  sources: v.pipe(
    v.array(v.object({
      name: v.pipe(v.string(), v.minLength(1), v.maxLength(128)),
      url: v.pipe(v.string(), v.minLength(1), v.maxLength(2_048)),
      sha256: v.pipe(v.string(), v.regex(/^[0-9a-f]{64}$/)),
    })),
    v.minLength(1),
  ),
  sourceRoot: v.optional(v.pipe(v.string(), v.regex(/^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$/))),
  dependencies: v.array(v.string()),
  makeDependencies: v.optional(v.array(v.string())),
  smokeCommands: v.pipe(v.array(v.string()), v.minLength(1)),
  architectures: v.pipe(v.array(v.picklist(['x86_64', 'aarch64'])), v.minLength(1)),
  sourceDateEpoch: v.pipe(v.number(), v.integer(), v.minValue(0)),
  pkgrel: v.optional(v.pipe(v.number(), v.integer(), v.minValue(1), v.maxValue(9_999))),
  imageDigest: v.optional(v.pipe(v.string(), v.regex(/^.+@sha256:[0-9a-f]{64}$/))),
  license: v.pipe(v.string(), v.minLength(1), v.maxLength(128)),
  surface: v.picklist(['binary', 'recipe']),
  publicRecipe: v.optional(v.nullable(v.pipe(v.string(), v.maxLength(2 * 1024 * 1024)))),
  description: v.pipe(v.string(), v.minLength(1), v.maxLength(160)),
  buildCommands: v.pipe(v.array(v.string()), v.minLength(1)),
  packageCommands: v.pipe(v.array(v.string()), v.minLength(1)),
  explanation: v.pipe(v.string(), v.minLength(1), v.maxLength(8_192)),
  sbom: v.optional(v.record(v.string(), v.unknown())),
  upstreamCommit: v.optional(v.nullable(v.string())),
  vendorArtifact: v.optional(vendorArtifactSchema),
});

/** Model-facing candidate shape. Vendor metadata comes only from inspection evidence. */
export const factoryCandidateInputSchema = v.omit(factoryCandidateSchema, ['vendorArtifact']);

export type FactoryCandidateInput = v.InferOutput<typeof factoryCandidateSchema>;

export type FactoryCandidateToolInput = v.InferOutput<typeof factoryCandidateInputSchema>;

export const sourceEvidenceSchema = v.object({
  sourceKind: v.picklist(['git', 'archive']),
  upstreamUrl: v.string(),
  normalizedUrl: v.string(),
  finalUrl: v.optional(v.string()),
  redirectChain: v.optional(v.pipe(v.array(v.string()), v.maxLength(4))),
  sourceName: v.pipe(v.string(), v.minLength(1), v.maxLength(160)),
  sourceSha256: v.string(),
  sourceKey: v.optional(v.string()),
  upstreamCommit: v.nullable(v.string()),
  sourceRoot: v.optional(v.pipe(v.string(), v.regex(/^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$/))),
  files: v.pipe(v.array(v.string()), v.maxLength(200)),
  licenseFiles: v.pipe(v.array(v.string()), v.maxLength(200)),
  vendor: v.optional(v.object({
    kind: v.picklist(['go', 'rust', 'npm']),
    sourceName: v.string(),
    sourceSha256: v.pipe(v.string(), v.regex(/^[0-9a-f]{64}$/)),
    sourceUrl: v.string(),
    sourceKey: v.string(),
    components: v.array(v.object({
      name: v.string(), version: v.string(), source: v.string(),
      checksum: v.nullable(v.string()), checksumAlgorithm: v.nullable(v.picklist(['SHA256', 'GO-H1'])), integrity: v.nullable(v.string()), license: v.nullable(v.string()),
    })),
  })),
  vendorArtifact: v.optional(vendorArtifactSchema),
});

export const recipeLintSchema = v.object({
  passed: v.boolean(),
  checks: v.array(v.object({ name: v.string(), passed: v.boolean(), detail: v.string() })),
  repairAttempts: v.number(),
});

export const sourceReadInputSchema = v.object({
  paths: v.pipe(v.array(v.pipe(v.string(), v.minLength(1), v.maxLength(256))), v.minLength(1), v.maxLength(12)),
});
