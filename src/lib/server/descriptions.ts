import * as v from 'valibot';
import type { Revision } from '../model';

function clean(value: string, max: number): string {
  return [...value].map((character) => character <= '\u001f' || character === '\u007f' ? ' ' : character).join('').replace(/\s+/g, ' ').trim().slice(0, max);
}

export function normalizeRequestDescription(input: string): string {
  const value = clean(input, 500);

  if (!value || input.length > 500) throw new Error('Package description must be 1 to 500 characters.');

  return value;
}

function recipePkgdesc(recipe: string): string | null {
  const line = recipe.split('\n').find((value) => value.trimStart().startsWith('pkgdesc='));

  if (!line) return null;
  const raw = line.trimStart().slice('pkgdesc='.length).trim();

  if (!raw) return null;

  if (raw.startsWith("'")) {
    if (!raw.endsWith("'")) return null;

    return clean(raw.slice(1, -1).replace(/'\\''/g, "'"), 160) || null;
  }

  if (raw.startsWith('"')) {
    try {
      const parsed = v.safeParse(v.string(), JSON.parse(raw));

      return parsed.success ? clean(parsed.output, 160) || null : null;
    } catch {
      return null;
    }
  }

  return clean(raw.replace(/\s+#.*$/, ''), 160) || null;
}

export function finalDescription(
  revision: Pick<Revision, 'description'> & { recipe?: string | null; explanation?: string | null },
  fallback = 'Package',
): string {
  const stored = revision.description ? clean(revision.description, 160) : '';

  if (stored) return stored;
  const parsed = revision.recipe ? recipePkgdesc(revision.recipe) : null;

  if (parsed) return parsed;
  const explanation = revision.explanation ? clean(revision.explanation, 160) : '';

  return explanation || clean(fallback, 160) || 'Package';
}
