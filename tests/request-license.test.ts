import { describe, expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import { parseDeclaredLicense, parseRequest } from '../src/lib/server/policy';
import { submitRequest } from '../src/lib/server/requests';
import type { Env } from '../src/lib/server/env';
import { asD1, TestD1 } from './d1';

const schema = readFileSync(new URL('../migrations/0001_initial.sql', import.meta.url), 'utf8') +
  readFileSync(new URL('../migrations/0002_auth_rate_limit.sql', import.meta.url), 'utf8') +
  readFileSync(new URL('../migrations/0016_request_license.sql', import.meta.url), 'utf8') +
  readFileSync(new URL('../migrations/0024_descriptions.sql', import.meta.url), 'utf8');

const baseRequest = {
  name: 'hello', description: 'A friendly command-line greeting.', upstream_url: 'https://example.com/hello.tar.gz', source_kind: 'archive' as const, area: 'system' as const,
};

function env(db: TestD1): Env {
  return {
    DB: asD1(db), ARTIFACTS: {} as R2Bucket, PUBLIC_ORIGIN: 'https://omapkg.example',
    MAINTAINER_GITHUB_IDS: '', SECURITY_GITHUB_IDS: '', QUARANTINE_HOURS: '48',
  };
}

const actor = { id: 'github:1', role: 'public' as const, areas: [] };

describe('request license declaration', () => {
  test('requires a bounded SPDX expression or an explicit sentinel', () => {
    expect(parseDeclaredLicense('MIT OR Apache-2.0')).toBe('MIT OR Apache-2.0');
    expect(parseDeclaredLicense('(MIT AND Apache-2.0) OR GPL-2.0-only WITH Classpath-exception-2.0')).toContain('GPL-2.0-only');
    expect(parseDeclaredLicense('proprietary')).toBe('proprietary');
    expect(parseDeclaredLicense('unknown')).toBe('unknown');
    expect(() => parseRequest(baseRequest)).toThrow();
    for (const value of ['', 'MIT XOR Apache-2.0', 'MIT OR', 'MIT; rm -rf /', 'MIT\nApache-2.0', 'x'.repeat(257)]) {
      expect(() => parseRequest({ ...baseRequest, declared_license: value })).toThrow();
    }
    expect(() => parseRequest({ ...baseRequest, description: '' })).toThrow();
    expect(() => parseRequest({ ...baseRequest, description: 'x'.repeat(501) })).toThrow();
    expect(parseRequest({ ...baseRequest, description: '  A\n package. ', declared_license: 'unknown' }).description).toBe('A package.');
  });

  test('persists declaration and audit detail while historical rows retain unknown', async () => {
    const db = new TestD1(schema);
    try {
      const requestId = await submitRequest(env(db), actor, { ...baseRequest, declared_license: 'proprietary' });
      expect(db.prepare('SELECT declared_license FROM requests WHERE id=?').bind(requestId).first<{ declared_license: string }>())
        .toEqual({ declared_license: 'proprietary' });
      expect(db.prepare('SELECT description FROM requests WHERE id=?').bind(requestId).first<{ description: string }>())
        .toEqual({ description: baseRequest.description });
      const detail = db.prepare("SELECT detail FROM audit_events WHERE action='request.created' AND target=?").bind(requestId).first<{ detail: string }>();
      expect(JSON.parse(detail?.detail ?? '{}').declared_license).toBe('proprietary');

      db.prepare(`INSERT INTO requests(id,name,upstream_url,source_kind,area,requested_by,status,created_at,updated_at)
        VALUES(?,?,?,?,?,'system','pending',?,?)`)
        .bind('historical-request', 'historical', 'https://example.com/historical.tar.gz', 'archive', 'system', 1, 1).run();
      expect(db.prepare('SELECT declared_license FROM requests WHERE id=?').bind('historical-request').first<{ declared_license: string }>())
        .toEqual({ declared_license: 'unknown' });
    } finally {
      db.close();
    }
  });
});
