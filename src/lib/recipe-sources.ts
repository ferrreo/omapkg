import type { Architecture } from './model';
import type { InputObject } from './frozen-inputs';
import type { RecipeCapture } from './recipe-capture';
import { recipeFilePath } from './distribution';
import type { Srcinfo } from './srcinfo';
import { publicSourceURL } from './server/policy';
import * as v from 'valibot';
import { MAX_INPUT_OBJECT, MAX_INPUT_TRANSFER } from './frozen-inputs';
import { EMPTY_RECIPE_SHA } from './recipe-capture';

export type RecipeSource = {
  source: string; name: string; checksums: Record<string, string>;
} & ({ kind: 'local'; path: string } | { kind: 'file'; url: string } |
  { kind: 'git'; url: string; ref: { kind: 'commit' | 'tag' | 'branch' | 'head'; value: string }; signed: boolean });
export type RecipeSourcePlan = {
  schemaVersion: 1; kind: 'recipe-source-plan'; capture: InputObject;
  inspection: { jobId: string; attempt: number; reportSha256: string; srcinfoSha256: string };
  pkgbase: string; version: string; architecture: Architecture;
  sources: RecipeSource[]; validpgpkeys: string[];
};

const digest = v.pipe(v.string(), v.regex(/^[a-f0-9]{64}$/));
const object = v.strictObject({ sha256: digest, size: v.pipe(v.number(), v.integer(), v.minValue(0), v.maxValue(MAX_INPUT_OBJECT)) });
const filename = v.pipe(v.string(), v.maxLength(255));
const expansion = { entries: v.pipe(v.number(), v.integer(), v.minValue(0), v.maxValue(200000)), expandedBytes: v.pipe(v.number(), v.integer(), v.minValue(0), v.maxValue(MAX_INPUT_OBJECT)) };
const bundleSchema = v.strictObject({
  schemaVersion: v.literal(1), kind: v.literal('recipe-source-bundle'), plan: object,
  sources: v.pipe(v.array(v.variant('kind', [
    v.strictObject({ kind: v.literal('file'), name: filename, object, redirects: v.pipe(v.array(v.pipe(v.string(), v.maxLength(2048))), v.minLength(1), v.maxLength(9)) }),
    v.strictObject({ kind: v.literal('git'), name: filename, object, commit: v.pipe(v.string(), v.regex(/^[a-f0-9]{40}$/)), ...expansion }),
  ])), v.maxLength(2048)),
  caches: v.pipe(v.array(v.strictObject({ kind: v.picklist(['go', 'cargo', 'npm']), object, ...expansion })), v.maxLength(3)),
  keys: v.pipe(v.array(v.strictObject({ fingerprint: v.pipe(v.string(), v.regex(/^(?:[A-F0-9]{40}|[A-F0-9]{64})$/)), object })), v.maxLength(256)),
});
export type RecipeSourceBundle = v.InferOutput<typeof bundleSchema>;

export function parseRecipeSourceBundle(input: unknown): RecipeSourceBundle {
  const value = v.parse(bundleSchema, input);
  const refs = recipeSourceObjects(value);
  const sizes = new Map<string, number>();
  for (const ref of refs) {
    if ((ref.size === 0) !== (ref.sha256 === EMPTY_RECIPE_SHA) || (sizes.has(ref.sha256) && sizes.get(ref.sha256) !== ref.size)) throw new Error('Source object has inconsistent size');
    sizes.set(ref.sha256, ref.size);
  }
  if (!value.plan.size || value.plan.size > 2 * 1024 * 1024 || refs.reduce((sum, ref) => sum + ref.size, 0) > MAX_INPUT_TRANSFER ||
      value.caches.some((cache) => !cache.object.size || cache.expandedBytes > cache.object.size) || value.sources.some((source) => source.kind === 'git' && (!source.object.size || source.expandedBytes > source.object.size)) ||
      value.keys.some((key) => !key.object.size || key.object.size > 1024 * 1024)) throw new Error('Source bundle exceeds object budget');
  if (new Set(value.sources.map((source) => source.name)).size !== value.sources.length || new Set(value.caches.map((cache) => cache.kind)).size !== value.caches.length ||
      new Set(value.keys.map((key) => key.fingerprint)).size !== value.keys.length) throw new Error('Source bundle repeats a source, cache or key');
  for (const source of value.sources) {
    recipeFilePath(source.name);
    if (source.name.includes('/') || source.name.startsWith('-') || new TextEncoder().encode(source.name).length > 255) throw new Error('Unsafe prepared source name');
    for (const url of source.kind === 'file' ? source.redirects : []) {
      // Public release hosts can issue temporary signed URLs in redirects.
      const parsed = new URL(url); parsed.search = ''; publicSourceURL(parsed.href);
      if (parsed.username || parsed.password || /[\x00-\x20\x7f\\]/.test(url)) throw new Error('Unsafe source redirect URL');
    }
  }
  return value;
}

export function recipeSourceObjects(value: RecipeSourceBundle): InputObject[] {
  return [value.plan, ...value.sources.map((source) => source.object), ...value.caches.map((cache) => cache.object), ...value.keys.map((key) => key.object)];
}

const algorithms: Record<string, number> = { md5: 32, sha1: 40, sha224: 56, sha256: 64, sha384: 96, sha512: 128, b2: 128 };

/** Follow makepkg's source naming and architecture arrays without evaluating shell. */
export function recipeSources(capture: RecipeCapture, metadata: Srcinfo, architecture: Architecture): Pick<RecipeSourcePlan, 'sources' | 'validpgpkeys'> {
  if (capture.pkgbase !== metadata.pkgbase || !['x86_64', 'aarch64'].includes(architecture)) throw new Error('Source plan identity differs from inspected recipe');
  if (metadata.outputs.some((output) => Object.keys(output.fields).some((key) => /^(source|validpgpkeys|\w+sums)(_|$)/.test(key)))) throw new Error('Source declarations must belong to the package base');
  if (metadata.outputs.some((output) => !(output.fields.arch ?? metadata.base.arch).some((arch) => arch === architecture || arch === 'any'))) throw new Error('Recipe has outputs unsupported on this native target');
  const sources: RecipeSource[] = [];
  for (const suffix of ['', `_${architecture}`]) {
    const raw = metadata.base[`source${suffix}`] ?? [];
    const sums = Object.entries(metadata.base).filter(([key]) => key.endsWith(`sums${suffix}`) && (suffix || !key.includes('_')));
    for (const [key, values] of sums) {
      const algorithm = key.slice(0, -`sums${suffix}`.length);
      if (!(algorithm in algorithms) || values.length !== raw.length || values.some((value) => value !== 'SKIP' && !new RegExp(`^[a-fA-F0-9]{${algorithms[algorithm]}}$`).test(value))) throw new Error(`Invalid or unsupported source checksum array: ${key}`);
    }
    for (let index = 0; index < raw.length; index++) {
      const source = raw[index], alias = source.indexOf('::');
      const address = alias < 0 ? source : source.slice(alias + 2);
      const git = address.startsWith('git+https://');
      const name = alias >= 0 ? source.slice(0, alias) : git
        ? address.split('#')[0].split('?')[0].replace(/\/$/, '').split('/').at(-1)!.split('.git')[0]
        : address.split('/').at(-1)!;
      recipeFilePath(name);
      if (name.includes('/') || name.startsWith('-') || new TextEncoder().encode(name).length > 255 || sources.some((entry) => entry.name === name)) throw new Error('Source filenames must be unique, bounded directory entries');
      const checksums = Object.fromEntries(sums.map(([key, values]) => [key.slice(0, -`sums${suffix}`.length), values[index] === 'SKIP' ? 'SKIP' : values[index].toLowerCase()]));
      const common = { source, name, checksums };
      // makepkg prefers a captured file over SRCDEST, even for an HTTPS source.
      if (!git && capture.files.some((file) => file.path === name)) sources.push({ ...common, kind: 'local', path: name });
      else if (git) {
        if (address.split('#').length > 2 || address.split('?').length > 2) throw new Error('Ambiguous Git source fragment or query');
        if (capture.files.some((file) => file.path === name || file.path.startsWith(name + '/'))) throw new Error('Git source overlaps the captured recipe directory');
        const url = publicSourceURL(address.slice(4).split('#')[0].split('?')[0]);
        const fragment = address.includes('#') ? address.slice(address.indexOf('#') + 1).split('?')[0] : '';
        const query = address.includes('?') ? address.slice(address.indexOf('?') + 1).split('#')[0] : '';
        if (query && query !== 'signed') throw new Error('Unsupported Git source query');
        const match = /^(commit|tag|branch)=(.+)$/.exec(fragment);
        if (fragment && (!match || /[\x00-\x20\x7f~^:?*=\[\\]|\.\.|@\{|\/$|\.$|\.lock(?:\/|$)|\/\/|(?:^|\/)\./.test(match[2]) || match[2].startsWith('-') || match[2].startsWith('/'))) throw new Error('Invalid Git source reference');
        if (match?.[1] === 'commit' && !/^[a-fA-F0-9]{40}$/.test(match[2])) throw new Error('Git commit sources require a full immutable commit');
        sources.push({ ...common, kind: 'git', url, ref: match ? { kind: match[1] as 'commit' | 'tag' | 'branch', value: match[2] } : { kind: 'head', value: 'HEAD' }, signed: query === 'signed' });
      } else if (address.startsWith('https://')) {
        if (new URL(address).hash) throw new Error('Archive source URL cannot contain a fragment');
        sources.push({ ...common, kind: 'file', url: publicSourceURL(address) });
      } else throw new Error(`Source requires capture or a supported HTTPS transport: ${name}`);
    }
  }
  if (sources.length > 2048) throw new Error('Recipe source plan exceeds 2048 entries');
  const validpgpkeys = metadata.base.validpgpkeys ?? [];
  if (validpgpkeys.length > 256 || validpgpkeys.some((key) => !/^(?:[a-fA-F0-9]{40}|[a-fA-F0-9]{64})$/.test(key))) throw new Error('Invalid source signing key fingerprint');
  return { sources, validpgpkeys: [...new Set(validpgpkeys.map((key) => key.toUpperCase()))].sort() };
}
