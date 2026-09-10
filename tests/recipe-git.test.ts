import { expect, test } from 'bun:test';
import { createHash } from 'node:crypto';
import { commitRecipeTree } from '../services/pipeline/github-pr';
import { revisionPackagePath, recipeGitUrl } from '../src/lib/server/catalog-recipe';
import { encodeOprEvidence } from '../src/lib/server/sbom';
import { checkRecipeTree } from '../services/pipeline/integrity';

test('recipe paths bind immutable catalog evidence and keep historical paths', () => {
  const sbom = (collection: string, pkgbase = 'demo') => JSON.stringify({ comment: encodeOprEvidence({ catalogPath: { pkgbase, collection } }) });
  expect(revisionPackagePath('demo', '{}')).toBe('packages/demo');
  expect(revisionPackagePath('demo', sbom('core'))).toBe('packages/core/demo');
  expect(recipeGitUrl('owner/recipes', 'a'.repeat(40), 'demo', sbom('core'))).toBe(`https://github.com/owner/recipes/tree/${'a'.repeat(40)}/packages/core/demo`);
  expect(() => revisionPackagePath('demo', sbom('../core'))).toThrow();
  expect(() => revisionPackagePath('demo', sbom('core', 'another'))).toThrow();
  expect(() => revisionPackagePath('../demo', '{}')).toThrow();
});

test('complete recipe integrity checks auxiliary bytes, executable modes, extra files and truncated trees', async () => {
  const root = 'packages/omarchy/demo', commit = 'a'.repeat(40), hashes = ['b', 'c', 'd', 'e'].map((value) => value.repeat(40));

  const files = [{ path: `${root}/PKGBUILD`, bytes: new TextEncoder().encode('pkgname=demo\n'), mode: '100644' as const },
    { path: `${root}/hooks/install`, bytes: new Uint8Array([0, 128, 255]), mode: '100755' as const },
    { path: `${root}/link`, bytes: new TextEncoder().encode('hooks/install'), mode: '120000' as const },
    { path: `${root}/empty`, bytes: new Uint8Array(), mode: '100644' as const }];

  const blobHash = (bytes: Uint8Array) => createHash('sha1').update(`blob ${bytes.length}\0`).update(bytes).digest('hex');
  let changedMode = false, changedBytes = false, extra = false, truncated = false;
  const paths: string[] = [], previous = globalThis.fetch;
  globalThis.fetch = (async (input, init) => {
    const url = new URL(String(input)), path = url.pathname.split('/git/')[1]; paths.push(path + url.search);

    if (path === `commits/${commit}`) return Response.json({ tree: { sha: hashes[0] } });
    const level = hashes.indexOf(path.split('/')[1]);

    if (path.startsWith('trees/') && level < 3) return Response.json({ sha: hashes[level], tree: [{ path: root.split('/')[level], mode: '040000', type: 'tree', sha: hashes[level + 1] }] });

    if (path === `trees/${hashes[3]}`) return Response.json({ sha: hashes[3], truncated, tree: [
      { path: 'hooks', type: 'tree', mode: '040000', sha: 'f'.repeat(40) },
      ...files.map((file) => ({ path: file.path.slice(root.length + 1), type: 'blob', mode: changedMode && file.path.endsWith('/install') ? '100644' : file.mode, sha: blobHash(file.bytes), size: file.bytes.length })),
      ...(extra ? [{ path: 'unexpected.install', type: 'blob', mode: '100755', sha: '0'.repeat(40), size: 10 }] : []),
    ] });

    if (path.startsWith('blobs/')) {
      expect(new Headers(init?.headers).get('Accept')).toBe('application/vnd.github.raw+json');
      const file = files.find((file) => blobHash(file.bytes) === path.slice(6))!;

      return new Response(changedBytes && file.path.endsWith('/install') ? new Uint8Array([0, 128, 254]) : file.bytes);
    }

    throw new Error(`Unexpected integrity request: ${path}`);
  }) as typeof fetch;
  const env = { DB: {} as D1Database, ARTIFACTS: {} as R2Bucket, GITHUB_REPOSITORY: 'owner/recipes', GITHUB_REPO_TOKEN: 'github_pat_test' };

  try {
    expect(await checkRecipeTree(env, 'owner/recipes', root, commit, files)).toEqual({ paths: [], reason: '' });
    expect(paths.filter((path) => path.includes('?recursive='))).toEqual([`trees/${hashes[3]}?recursive=1`]);
    changedMode = true;
    expect((await checkRecipeTree(env, 'owner/recipes', root, commit, files)).paths).toEqual([`${root}/hooks/install`]);
    changedMode = false; changedBytes = true;
    expect((await checkRecipeTree(env, 'owner/recipes', root, commit, files)).reason).toContain('hash mismatch');
    changedBytes = false; extra = true;
    expect((await checkRecipeTree(env, 'owner/recipes', root, commit, files)).paths).toEqual([`${root}/unexpected.install`]);
    extra = false; truncated = true;
    await expect(checkRecipeTree(env, 'owner/recipes', root, commit, files)).rejects.toThrow('incomplete');
  } finally { globalThis.fetch = previous; }
});

test('recipe trees preserve bytes, commit coupled files once, and retry without extra commits', async () => {
  const parent = 'a'.repeat(40), base = 'b'.repeat(40), tree = 'c'.repeat(40), commit = 'd'.repeat(40);

  const files = [
    { path: 'packages/core/demo/PKGBUILD', bytes: new TextEncoder().encode('pkgname=demo\n# café\n') },
    { path: 'packages/extra/consumer/fix.patch', bytes: new Uint8Array([0, 1, 128, 255]) },
  ];

  const roots = ['packages/core/demo', 'packages/extra/consumer'];
  let head = parent, failedBlob = false, race = false;
  const calls: Array<{ path: string; body: any }> = [];
      const previous = globalThis.fetch;
      globalThis.fetch = (async (input, init) => {
    const path = new URL(String(input)).pathname.split('/git/')[1];
    const body = init?.body ? JSON.parse(String(init.body)) : null;
    calls.push({ path, body });

    if (path === 'ref/heads/cohort') return Response.json({ object: { sha: head } });

    if (path === `commits/${head}`) return Response.json({ tree: { sha: head === parent ? base : tree } });

    if (path === 'blobs') {
      const bytes = Buffer.from(body.content, 'base64');
      expect(files.some((file) => Buffer.from(file.bytes).equals(bytes))).toBe(true);

      return Response.json({ sha: failedBlob ? 'e'.repeat(40) : createHash('sha1').update(`blob ${bytes.length}\0`).update(bytes).digest('hex') }, { status: 201 });
    }

    if (path === 'trees') return Response.json({ sha: tree }, { status: 201 });

    if (path === 'commits') return Response.json({ sha: commit }, { status: 201 });

    if (path === 'refs/heads/cohort') {
      if (race) return new Response('not a fast forward', { status: 422 });
      head = body.sha;

      return Response.json({ object: { sha: head } });
    }

    throw new Error(`Unexpected Git operation: ${path}`);
      }) as typeof fetch;
      const env = { DB: {} as D1Database, ARTIFACTS: {} as R2Bucket, GITHUB_REPOSITORY: 'owner/recipes', GITHUB_REPO_TOKEN: 'github_pat_test' };

  try {
    expect(await commitRecipeTree(env, 'cohort', parent, files, 'Update coupled recipes', roots)).toBe(commit);
    expect(calls.flatMap((call) => call.path === 'commits' ? [call.body] : [])).toEqual([{ message: 'Update coupled recipes', tree, parents: [parent] }]);
    expect(calls.flatMap((call) => call.path === 'refs/heads/cohort' ? [call.body] : [])).toEqual([{ sha: commit, force: false }]);
    expect(calls.find((call) => call.path === 'trees' && call.body.base_tree)?.body).toMatchObject({ base_tree: base, tree: [{ path: 'packages/core/demo', mode: '040000', type: 'tree' }, { path: 'packages/extra/consumer', mode: '040000', type: 'tree' }] });
    expect(calls.flatMap((call) => call.path === 'trees' && !call.body.base_tree ? [call.body.tree[0].path] : [])).toEqual(['PKGBUILD', 'fix.patch']);
    calls.length = 0;
    expect(await commitRecipeTree(env, 'cohort', commit, files, 'Update coupled recipes', roots)).toBe(commit);
    expect(calls.some((call) => call.path === 'commits' || call.path === 'refs/heads/cohort')).toBe(false);
    await expect(commitRecipeTree(env, 'cohort', parent, files, 'Stale attempt', roots)).rejects.toThrow('changed');
    head = parent; failedBlob = true; calls.length = 0;
    await expect(commitRecipeTree(env, 'cohort', parent, files, 'Bad bytes', roots)).rejects.toThrow('retained bytes');
    expect(calls.some((call) => call.path === 'trees' || call.path === 'refs/heads/cohort')).toBe(false);
    failedBlob = false; race = true;
    await expect(commitRecipeTree(env, 'cohort', parent, files, 'Concurrent update', roots)).rejects.toThrow('422');
    expect(head).toBe(parent);
    await expect(commitRecipeTree(env, 'cohort', parent, [{ ...files[0], path: 'packages/../escape' }], 'Unsafe', roots)).rejects.toThrow('Unsafe');
  } finally { globalThis.fetch = previous; }
});
