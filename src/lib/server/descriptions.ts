import type { Revision } from '../model';

const CONTROL = /[\u0000-\u001f\u007f]/g;

function clean(value: string, max: number): string {
  return value.replace(CONTROL, ' ').replace(/\s+/g, ' ').trim().slice(0, max);
}

export function normalizeRequestDescription(input: unknown): string {
  if (typeof input !== 'string') throw new Error('Package description is required.');
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
      const parsed = JSON.parse(raw);
      return typeof parsed === 'string' ? clean(parsed, 160) || null : null;
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
  const stored = typeof revision.description === 'string' ? clean(revision.description, 160) : '';
  if (stored) return stored;
  const parsed = typeof revision.recipe === 'string' ? recipePkgdesc(revision.recipe) : null;
  if (parsed) return parsed;
  const explanation = typeof revision.explanation === 'string' ? clean(revision.explanation, 160) : '';
  return explanation || clean(fallback, 160) || 'Package';
}
