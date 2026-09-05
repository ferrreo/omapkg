import { expect, test } from 'bun:test';
import { finalDescription, normalizeRequestDescription } from '../src/lib/server/descriptions';

test('description helpers bound request length and parse legacy PKGBUILD metadata', () => {
  expect(normalizeRequestDescription('  Useful\nsoftware  ')).toBe('Useful software');
  expect(() => normalizeRequestDescription('')).toThrow();
  expect(() => normalizeRequestDescription('x'.repeat(501))).toThrow();
  expect(finalDescription({ description: null, recipe: "pkgdesc='A developer'\\''s tool.'", explanation: 'audit detail' }, 'demo')).toBe("A developer's tool.");
  expect(finalDescription({ description: null, recipe: 'pkgname=demo\n', explanation: 'Verified package.' }, 'demo')).toBe('Verified package.');
});
