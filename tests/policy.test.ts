import { describe, expect, test } from 'bun:test';
import { manifestDigest, parseRequest, publicSourceURL, requireMaintainer, requireSecurity, validateRevision } from '../src/lib/server/policy';
import { sha256 } from '../src/lib/server/db';
import type { Revision } from '../src/lib/model';

describe('request trust boundary', () => {
  test('accepts git and archive URLs but never shell or private network locators', () => {
    expect(parseRequest({ name: 'hello', description: 'A command-line greeting.', upstream_url: 'https://github.com/example/hello', source_kind: 'git', area: 'development', declared_license: 'unknown' }).name).toBe('hello');
    expect(publicSourceURL('https://ftp.gnu.org/gnu/hello/hello-2.12.2.tar.gz')).toContain('hello-2.12.2');
    for (const url of ['file:///etc/passwd', 'http://github.com/x/y', 'https://127.0.0.1/x', 'https://2130706433/x', 'https://[::1]/x', 'https://user:password@github.com/x', 'https://git.local/x', 'https://metadata.internal/x', 'https://example.com:4433/x', 'https://github.com/x#branch']) {
      expect(() => publicSourceURL(url)).toThrow();
    }
    expect(() => parseRequest({ name: 'hello;curl bad', description: 'A package.', upstream_url: 'https://github.com/x/y', source_kind: 'git', area: 'system', declared_license: 'unknown' })).toThrow();
  });
  test('public users cannot approve; area reviewers cannot sign for security', () => {
    expect(() => requireMaintainer({ id: 'github:1', role: 'public', areas: [] })).toThrow();
    expect(() => requireMaintainer({ id: 'github:1', role: 'maintainer', areas: ['gaming'] }, 'system')).toThrow();
    expect(() => requireSecurity({ id: 'github:1', role: 'maintainer', areas: ['system'] })).toThrow();
    expect(requireMaintainer({ id: 'github:2', role: 'maintainer', areas: ['gaming'] }, 'gaming').id).toBe('github:2');
  });
  test('approval binds recipe, sources, smoke checks, dependencies, licensing and builder image', async () => {
    const revision: Revision = {
      id: 'r', request_id: 'q', version: '1.0', recipe: 'pkgname=hello\n', recipe_sha256: await sha256('pkgname=hello\n'), manifest_sha256: '',
      sources_json: JSON.stringify([{ name: 'source.tar.gz', url: 'https://example.org/source.tar.gz', sha256: 'a'.repeat(64) }]),
      dependencies_json: '["base-devel"]', smoke_commands_json: '["hello --version"]', architectures_json: '["x86_64"]',
      source_date_epoch: 1700000000, image_digest: `ghcr.io/example/builder@sha256:${'b'.repeat(64)}`,
      license: 'MIT', surface: 'binary', explanation: '', sbom_json: '{}', lint_json: '{"passed":true}',
      upstream_commit: null, pr_url: 'https://github.com/example-owner/recipes/pull/1', commit_sha: 'c'.repeat(40), created_at: 1
    };
    revision.manifest_sha256 = await manifestDigest(revision);
    await validateRevision(revision);
    for (const change of [
      { recipe: 'pkgname=evil' }, { sources_json: '[]' }, { smoke_commands_json: '[]' },
      { dependencies_json: '["curl"]' }, { surface: 'recipe' as const }, { image_digest: 'archlinux:latest' }
    ]) await expect(validateRevision({ ...revision, ...change })).rejects.toThrow();
    await expect(validateRevision({ ...revision, pr_url: null })).rejects.toThrow();
    await expect(validateRevision({ ...revision, lint_json: '{"passed":false}' })).rejects.toThrow();
  });
});
