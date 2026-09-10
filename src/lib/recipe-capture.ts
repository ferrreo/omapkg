import * as v from 'valibot';
import { createHash } from 'node:crypto';
import type { InputObject } from './frozen-inputs';
import { publicSourceURL } from './server/policy';
import { recipeFilePath } from './distribution';

export { recipeFilePath } from './distribution';

export const MAX_RECIPE_FILES = 2048;

export const MAX_RECIPE_TREE_BYTES = 32 * 1024 * 1024;

export const EMPTY_RECIPE_SHA = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';

const digest = v.pipe(v.string(), v.regex(/^[a-f0-9]{64}$/));

const object = v.strictObject({ sha256: digest, size: v.pipe(v.number(), v.integer(), v.minValue(0), v.maxValue(MAX_RECIPE_TREE_BYTES)) });

const schema = v.strictObject({
  schemaVersion: v.literal(1), kind: v.literal('recipe-capture'),
  pkgbase: v.pipe(v.string(), v.regex(/^[a-z0-9][a-z0-9@._+-]{0,63}$/)),
  origin: v.picklist(['arch', 'omarchy', 'opr', 'aur-reference', 'alarm-reference']),
  repository: v.pipe(v.string(), v.maxLength(2048)), commit: v.pipe(v.string(), v.regex(/^[a-f0-9]{40}$/)),
  directory: v.pipe(v.string(), v.maxLength(512)),
  git: v.strictObject({ commit: object, trees: v.pipe(v.array(object), v.minLength(1), v.maxLength(512)) }),
  files: v.pipe(v.array(v.strictObject({ path: v.pipe(v.string(), v.maxLength(512)), mode: v.picklist(['100644', '100755', '120000']), object })), v.minLength(1), v.maxLength(MAX_RECIPE_FILES)),
});

export type RecipeCapture = v.InferOutput<typeof schema>;

export type RecipeFile = RecipeCapture['files'][number];

export function parseRecipeCapture(input: unknown, oprRepository?: string): RecipeCapture {
  const result = v.safeParse(schema, input);

  if (!result.success) throw new Error('Invalid recipe capture manifest');
  const value = result.output;
  recipeFilePath(value.directory, true);
  const url = new URL(publicSourceURL(value.repository));

  if (url.search || url.hash) throw new Error('Recipe repository cannot contain a query or fragment');
  const repository = value.repository.replace(/\.git$/, '').replace(/\/$/, '');

  if ((value.origin === 'arch' && !/^https:\/\/gitlab\.archlinux\.org\/archlinux\/packaging\/packages\/[a-z0-9@._+-]+$/.test(repository)) ||
      (value.origin === 'omarchy' && repository !== 'https://github.com/omacom/omarchy-pkgs') ||
      (value.origin === 'opr' && repository !== `https://github.com/${oprRepository}`) ||
      (value.origin === 'aur-reference' && !/^https:\/\/aur\.archlinux\.org\/[a-z0-9@._+-]+$/.test(repository)) ||
      (value.origin === 'alarm-reference' && repository !== 'https://github.com/archlinuxarm/PKGBUILDs')) throw new Error('Recipe origin differs from its source repository');
  const refs = [value.git.commit, ...value.git.trees, ...value.files.map((file) => file.object)];
  const sizes = new Map<string, number>();

  for (const ref of refs) {
    if ((ref.size === 0) !== (ref.sha256 === EMPTY_RECIPE_SHA) || (sizes.has(ref.sha256) && sizes.get(ref.sha256) !== ref.size)) throw new Error('Recipe object has inconsistent size');
    sizes.set(ref.sha256, ref.size);
  }

  if (value.git.commit.size > 128 * 1024 || value.git.trees.some((ref) => ref.size > 1024 * 1024) ||
      value.git.commit.size + value.git.trees.reduce((sum, ref) => sum + ref.size, 0) > 4 * 1024 * 1024 ||
      value.files.reduce((sum, file) => sum + file.object.size, 0) > MAX_RECIPE_TREE_BYTES) throw new Error('Recipe capture exceeds its byte budget');

  if (new Set(value.files.map((file) => file.path)).size !== value.files.length || new Set(value.git.trees.map((ref) => ref.sha256)).size !== value.git.trees.length) throw new Error('Recipe capture repeats a file or tree');
  const files = new Map(value.files.map((file) => [recipeFilePath(file.path), file]));

  for (const file of value.files) {
    if (file.mode === '120000' && file.object.size > 512) throw new Error('Recipe symlink target is too long');

    if ((file.path === '.omarchy/package.json' && file.object.size > 64 * 1024) || (file.path === '.SRCINFO' && file.object.size > 1024 * 1024)) throw new Error('Recipe metadata exceeds inspection budget');
    const parents = file.path.split('/'); parents.pop();

    while (parents.length) { if (files.has(parents.join('/'))) throw new Error('Recipe file has a non-directory parent'); parents.pop(); }
  }

  const recipe = files.get('PKGBUILD');

  if (!recipe || recipe.mode === '120000' || !recipe.object.size || recipe.object.size > 2 * 1024 * 1024) throw new Error('Recipe needs a bounded regular PKGBUILD');

  return value;
}

function gitHash(kind: string, bytes: Uint8Array): string {
  return createHash('sha1').update(`${kind} ${bytes.length}\0`).update(bytes).digest('hex');
}

function parseTree(bytes: Uint8Array) {
  const tree: Array<{ name: string; mode: string; sha: string }> = [];
  const names = new Set<string>();
  let offset = 0;

  while (offset < bytes.length) {
    const space = bytes.indexOf(32, offset), end = bytes.indexOf(0, space + 1);

    if (space < offset || end < space || end + 21 > bytes.length) throw new Error('Truncated recipe Git tree');
    const mode = new TextDecoder('utf-8', { fatal: true }).decode(bytes.subarray(offset, space));
    const name = new TextDecoder('utf-8', { fatal: true }).decode(bytes.subarray(space + 1, end));

    if (!name || name.includes('/') || names.has(name)) throw new Error('Invalid recipe Git tree name');
    names.add(name);
    tree.push({ name, mode, sha: Buffer.from(bytes.subarray(end + 1, end + 21)).toString('hex') });
    offset = end + 21;
  }

  return tree;
}

/** Verify complete directory membership and original blob bytes against the retained Git commit. */
export async function verifyRecipeCapture(value: RecipeCapture, read: (ref: InputObject) => Promise<Uint8Array>) {
  const load = async (ref: InputObject) => {
    const bytes = ref.size === 0 ? new Uint8Array() : await read(ref);

    if (bytes.length !== ref.size || createHash('sha256').update(bytes).digest('hex') !== ref.sha256) throw new Error('Recipe object checksum changed');

    return bytes;
  };

  const commit = await load(value.git.commit);

  if (gitHash('commit', commit) !== value.commit) throw new Error('Recipe Git commit proof differs');
  const first = new TextDecoder('utf-8', { fatal: true }).decode(commit.subarray(0, commit.indexOf(10)));

  if (!/^tree [a-f0-9]{40}$/.test(first)) throw new Error('Recipe commit has no root tree');
  const trees = new Map<string, ReturnType<typeof parseTree>>();

  for (const ref of value.git.trees) {
    const bytes = await load(ref), sha = gitHash('tree', bytes);

    if (trees.has(sha)) throw new Error('Duplicate recipe Git tree proof');
    trees.set(sha, parseTree(bytes));
  }

  const used = new Set<string>();

  const tree = (sha: string) => { const entries = trees.get(sha);

 if (!entries) throw new Error('Recipe Git tree proof is incomplete'); used.add(sha);

 return entries; };

  let root = first.slice(5);

  for (const part of value.directory ? value.directory.split('/') : []) {
    const entry = tree(root).find((entry) => entry.name === part && entry.mode === '40000');

    if (!entry) throw new Error('Recipe directory is absent from commit');
    root = entry.sha;
  }

  const expected = new Map<string, { mode: string; sha: string }>();
  let visitedDirectories = 0;

  const walk = (sha: string, prefix = '') => {
    if (++visitedDirectories > MAX_RECIPE_FILES) throw new Error('Recipe tree has too many directories');

    for (const entry of tree(sha)) {
      const path = recipeFilePath(prefix + entry.name);

      if (entry.mode === '40000') { if (path.split('/').length > 32) throw new Error('Recipe tree is too deep'); walk(entry.sha, `${path}/`); }
      else { if (expected.size >= MAX_RECIPE_FILES) throw new Error('Recipe tree has too many files'); expected.set(path, entry); }
    }
  };

  walk(root);

  if (used.size !== trees.size || expected.size !== value.files.length) throw new Error('Recipe directory inventory is incomplete or has extra files');
  const retained = new Map<string, Uint8Array>();
  const links = new Map<string, string>();

  for (const file of value.files) {
    const entry = expected.get(file.path), bytes = await load(file.object);

    if (!entry || entry.mode !== file.mode || entry.sha !== gitHash('blob', bytes)) throw new Error('Recipe file differs from original Git blob');

    if (file.mode === '120000') links.set(file.path, new TextDecoder('utf-8', { fatal: true }).decode(bytes));

    if (['PKGBUILD', '.SRCINFO', '.omarchy/package.json'].includes(file.path)) {
      if (file.mode === '120000' || bytes.length > 2 * 1024 * 1024) throw new Error('Recipe metadata must be a bounded regular file');
      retained.set(file.path, bytes);
    }
  }

  for (const [path, target] of links) {
    let parts = path.split('/').slice(0, -1);
    const remaining = target.split('/'); const visited = new Set([path]);

    if (!target || target.startsWith('/') || target.length > 512) throw new Error('Unsafe recipe symlink');

    while (remaining.length) {
      const part = remaining.shift()!;

      if (part === '..') { if (!parts.length) throw new Error('Recipe symlink escapes directory'); parts.pop(); }
      else if (part !== '.') {
        recipeFilePath(part); parts.push(part);
        const resolved = parts.join('/'), link = links.get(resolved);

        if (link !== undefined) {
          if (visited.has(resolved) || visited.size > 32 || link.startsWith('/')) throw new Error('Unsafe or cyclic recipe symlink');
          visited.add(resolved); parts.pop(); remaining.unshift(...link.split('/'));
        }
      }
    }
  }

  return retained;
}
