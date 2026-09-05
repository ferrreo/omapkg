import { describe, expect, test } from 'bun:test';
import type { Sandbox } from '@flue/runtime';
import { fetchMetadataWithRedirects, fetchSourceWithRedirects, parseSourceFetchResponse, parseSourceMetadataResponse } from '../services/pipeline/source-fetch';
import { normalizeSourceUrl, sourceFetchCommand, sourceMetadataCommand } from '../services/pipeline/security';

type Result = { stdout: string; stderr: string; exitCode: number };

function sandboxFor(results: Result[], commands: string[]): Sandbox {
  return {
    exec: async (command: string) => {
      commands.push(command);
      const result = results.shift();
      if (!result) throw new Error('unexpected sandbox command');
      return result;
    },
  } as unknown as Sandbox;
}

const success = 'http_status=200\nredirect_location=\nartifact_magic=1f8b\nartifact_candidate=0\nfiles=\n';

describe('trusted source redirect fetching', () => {
  test('adds GitHub codeload host only after a validated redirect', async () => {
    const commands: string[] = [];
    const allowed: string[] = [];
    const result = await fetchSourceWithRedirects(
      sandboxFor([
        { stdout: 'http_status=302\nredirect_location=https://codeload.github.com/example/project/tar.gz/v1.0.0\n', stderr: '', exitCode: 0 },
        { stdout: success, stderr: '', exitCode: 0 },
      ], commands),
      'https://github.com/example/project/archive/v1.0.0.tar.gz',
      { allowHost: async (host) => { allowed.push(host); } },
    );
    expect(allowed).toEqual(['codeload.github.com']);
    expect(result.finalUrl).toBe('https://codeload.github.com/example/project/tar.gz/v1.0.0');
    expect(result.redirectChain).toEqual([
      'https://github.com/example/project/archive/v1.0.0.tar.gz',
      'https://codeload.github.com/example/project/tar.gz/v1.0.0',
    ]);
    expect(commands[0]).toContain('--max-redirs 0');
    expect(commands[0]).not.toContain('--location');
  });

  test('rejects redirects to private hosts before authorizing them', async () => {
    const allowed: string[] = [];
    await expect(fetchSourceWithRedirects(
      sandboxFor([{ stdout: 'http_status=302\nredirect_location=https://127.0.0.1/secret\n', stderr: '', exitCode: 0 }], []),
      'https://github.com/example/project/archive/v1.0.0.tar.gz',
      { allowHost: async (host) => { allowed.push(host); } },
    )).rejects.toThrow('source redirect host is not public');
    expect(allowed).toEqual([]);
  });

  test('stops redirect loops and does not log signed query secrets', async () => {
    const commands: string[] = [];
    const result = fetchSourceWithRedirects(
      sandboxFor([{ stdout: 'http_status=302\nredirect_location=https://github.com/example/project/archive/v1.0.0.tar.gz\n', stderr: '', exitCode: 0 }], commands),
      'https://github.com/example/project/archive/v1.0.0.tar.gz',
      { allowHost: async () => undefined },
    );
    await expect(result).rejects.toThrow('source redirect loop detected');

    const signedCommands: string[] = [];
    const signed = await fetchSourceWithRedirects(
      sandboxFor([
        { stdout: 'http_status=302\nredirect_location=https://release-assets.githubusercontent.com/project/source.tar.gz?X-Amz-Signature=SECRET&X-Amz-Credential=internal\n', stderr: '', exitCode: 0 },
        { stdout: success, stderr: '', exitCode: 0 },
      ], signedCommands),
      'https://github.com/example/project/archive/v1.0.0.tar.gz',
      { allowHost: async () => undefined },
    );
    expect(signed.finalUrl).toBe('https://release-assets.githubusercontent.com/project/source.tar.gz');
    expect(signed.redirectChain.join('\n')).not.toContain('SECRET');
    expect(signedCommands[1]).toContain('X-Amz-Signature');
  });

  test('rejects credential and signature query parameters on user source URLs', () => {
    for (const key of ['token', 'api_key', 'X-Amz-Signature', 'AWSAccessKeyId']) {
      expect(() => normalizeSourceUrl(`https://example.com/source.tar.gz?${key}=secret`)).toThrow('permanent HTTPS URL');
    }
    expect(() => normalizeSourceUrl('https://example.com/source.tar.gz?download=1')).not.toThrow();
    expect(parseSourceFetchResponse(success)).toEqual({ status: 200, location: null });
    expect(sourceFetchCommand('https://example.com/source.tar.gz', '/workspace/source.bundle')).not.toContain('--location');
  });

  test('bounds Sandbox metadata range fallback and requires archive length', async () => {
    const commands: string[] = [];
    const sandbox = sandboxFor([
      { stdout: 'HTTP/2 403 Forbidden\r\n\r\n\nhttp_status=403\ncurl_status=0\n', stderr: '', exitCode: 0 },
      { stdout: 'HTTP/2 206 Partial Content\r\nContent-Range: bytes 0-0/4242\r\nETag: "archive"\r\n\r\n\nhttp_status=206\ncurl_status=0\n', stderr: '', exitCode: 0 },
    ], commands);
    const result = await fetchMetadataWithRedirects(sandbox, 'https://example.com/source.tar.gz');
    expect(result.status).toBe(206);
    expect(result.headers.contentLength).toBe('4242');
    expect(result.headers.contentRange).toBe('bytes 0-0/4242');
    expect(commands[0]).toContain('--head');
    expect(commands[1]).toContain('--range 0-0 --max-filesize 1');
    expect(commands.join('\n')).not.toContain('/workspace/source.bundle');

    expect(parseSourceMetadataResponse('HTTP/2 206 Partial Content\r\nContent-Length: 1\r\n\nhttp_status=206\ncurl_status=0\n'))
      .toEqual({ status: 206, headers: { 'content-length': '1' }, curlStatus: 0 });
    await expect(fetchMetadataWithRedirects(sandboxFor([
      { stdout: 'HTTP/2 206 Partial Content\r\nContent-Length: 1\r\n\r\n\nhttp_status=206\ncurl_status=0\n', stderr: '', exitCode: 0 },
    ], []), 'https://example.com/source.tar.gz')).rejects.toThrow('source metadata range has no total length');
    expect(sourceMetadataCommand('https://example.com/source.tar.gz', { method: 'range' })).toContain('--max-filesize 1');
  });
});
