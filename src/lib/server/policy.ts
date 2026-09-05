import { Schema } from 'effect';
import { areas, type Actor, type Architecture, type Revision, type Source } from '../model';
import { sha256 } from './db';
import { isArchPkgver, parseArchDependency } from './arch';
import { normalizeRequestDescription } from './descriptions';

export class PolicyError extends Error {
  constructor(public status: number, message: string) { super(message); }
}
export function requireMaintainer(actor: Actor | null, area?: string) {
  if (!actor) throw new PolicyError(401, 'Sign in with GitHub to continue.');
  if (!['maintainer', 'security', 'admin'].includes(actor.role) ||
      (area && actor.role === 'maintainer' && !actor.areas.includes(area))) {
    throw new PolicyError(403, 'You need maintainer access for this area.');
  }
  return actor;
}
export function requireSecurity(actor: Actor | null) {
  if (!actor || !['security', 'admin'].includes(actor.role)) throw new PolicyError(403, 'You need security reviewer access.');
  return actor;
}
export function publicSourceURL(input: string): string {
  if (typeof input !== 'string') throw new PolicyError(400, 'Enter a valid HTTPS upstream URL.');
  let url: URL;
  try { url = new URL(input); } catch { throw new PolicyError(400, 'Enter a valid HTTPS upstream URL.'); }
  const host = url.hostname.toLowerCase();
  const sensitiveQuery = (name: string) => {
    const parts = name.toLowerCase().split(/[^a-z0-9]+/).filter(Boolean);
    const compact = parts.join('');
    return parts.some((part) => ['auth', 'authorization', 'bearer', 'credential', 'credentials', 'jwt', 'key', 'password', 'secret', 'sig', 'signature', 'token'].includes(part)) ||
      /(?:apikey|authorization|credential|password|secret|signature|token)$/.test(compact);
  };
  if (url.protocol !== 'https:' || url.username || url.password || url.port || url.hash || input.length > 2048 ||
      !host.includes('.') || host.endsWith('.') || host.endsWith('.local') || host.endsWith('.internal') ||
      host.endsWith('.localhost') || host === 'localhost' || host.includes(':') || /^\d+(\.\d+){3}$/.test(host) ||
      [...url.searchParams.keys()].some(sensitiveQuery)) {
    throw new PolicyError(400, 'Source must use a public HTTPS URL without credentials, IP literals, ports, or fragments.');
  }
  return url.href;
}
const requestSchema = Schema.Struct({
  name: Schema.String, description: Schema.String, upstream_url: Schema.String, source_kind: Schema.Literals(['git', 'archive']),
  area: Schema.Literals(areas), declared_license: Schema.String,
});

const licenseIdentifier = /^[A-Za-z0-9][A-Za-z0-9.+:-]{0,127}$/;
const licenseToken = /[A-Za-z0-9][A-Za-z0-9.+:-]*|[()]/y;

function invalidDeclaredLicense(): never {
  throw new PolicyError(400, 'Declare a valid SPDX license expression, Proprietary, or Unknown.');
}

export function parseDeclaredLicense(input: unknown): string {
  if (typeof input !== 'string') return invalidDeclaredLicense();
  const value = input.trim();
  if (value === 'unknown' || value === 'proprietary') return value;
  if (!value || value.length > 256 || /[\u0000-\u001f\u007f]/.test(value)) return invalidDeclaredLicense();

  licenseToken.lastIndex = 0;
  const tokens: string[] = [];
  let offset = 0;
  while (offset < value.length) {
    if (/\s/.test(value[offset] ?? '')) {
      offset += 1;
      continue;
    }
    licenseToken.lastIndex = offset;
    const match = licenseToken.exec(value);
    if (!match || match.index !== offset) return invalidDeclaredLicense();
    tokens.push(match[0]);
    offset = licenseToken.lastIndex;
  }
  let position = 0;
  const current = () => tokens[position];
  const take = (expected?: string) => {
    const token = current();
    if (!token || (expected && token !== expected)) return invalidDeclaredLicense();
    position += 1;
    return token;
  };
  const primary = (): void => {
    if (current() === '(') {
      take('(');
      expression();
      take(')');
      return;
    }
    const identifier = take();
    if (!licenseIdentifier.test(identifier) || ['AND', 'OR', 'WITH'].includes(identifier)) return invalidDeclaredLicense();
  };
  const withExpression = (): void => {
    primary();
    if (current() === 'WITH') {
      take('WITH');
      const exception = take();
      if (!licenseIdentifier.test(exception) || ['AND', 'OR', 'WITH'].includes(exception)) return invalidDeclaredLicense();
    }
  };
  const conjunction = (): void => {
    withExpression();
    while (current() === 'AND') {
      take('AND');
      withExpression();
    }
  };
  function expression(): void {
    conjunction();
    while (current() === 'OR') {
      take('OR');
      conjunction();
    }
  }
  expression();
  if (position !== tokens.length) return invalidDeclaredLicense();
  return value;
}

export function parseRequest(input: unknown) {
  let value: typeof requestSchema.Type;
  try { value = Schema.decodeUnknownSync(requestSchema)(input); }
  catch { throw new PolicyError(400, 'Package name, description, upstream URL, source type, area and declared license are required.'); }
  if (!/^[a-z0-9][a-z0-9@._+-]{0,79}$/.test(value.name)) throw new PolicyError(400, 'Use a lowercase Arch package name, up to 80 characters.');
  let description: string;
  try { description = normalizeRequestDescription(value.description); }
  catch (cause) { throw new PolicyError(400, cause instanceof Error ? cause.message : 'Package description must be 1 to 500 characters.'); }
  return { ...value, description, declared_license: parseDeclaredLicense(value.declared_license), upstream_url: publicSourceURL(value.upstream_url) };
}

function manifestJSON(value: string, label: string): unknown {
  try { return JSON.parse(value); }
  catch { throw new PolicyError(409, `${label} is invalid.`); }
}
function manifestArray(value: string, label: string): unknown[] {
  const parsed = manifestJSON(value, label);
  if (!Array.isArray(parsed)) throw new PolicyError(409, `${label} must be a JSON array.`);
  return parsed;
}
function manifestObject(value: string, label: string): Record<string, unknown> {
  const parsed = manifestJSON(value, label);
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new PolicyError(409, `${label} must be a JSON object.`);
  return parsed as Record<string, unknown>;
}
const architectures = ['x86_64', 'aarch64'] as const;
const legacyPinnedImage = /^.+@sha256:[a-f0-9]{64}$/;
const fullPinnedImage = /^(?=.{1,512}$)[a-z0-9][a-z0-9.-]*(?::[0-9]{1,5})?(?:\/[a-z0-9][a-z0-9._-]*)+(?::[a-z0-9][a-z0-9._-]{0,127})?@sha256:[a-f0-9]{64}$/;
function buildImages(revision: Pick<Revision, 'build_images_json'>): Record<string, unknown> {
  return manifestObject(revision.build_images_json ?? '{}', 'Builder image manifest');
}
export function revisionImage(revision: Pick<Revision, 'build_images_json' | 'image_digest'>, architecture: Architecture): string {
  if (!architectures.includes(architecture as typeof architectures[number])) throw new PolicyError(409, 'Select supported build architectures.');
  const images = buildImages(revision);
  const entries = Object.entries(images);
  if (!entries.length) {
    if (!legacyPinnedImage.test(revision.image_digest)) throw new PolicyError(409, 'Builder image must be pinned by digest.');
    return revision.image_digest;
  }
  if (entries.some(([name, image]) => !architectures.includes(name as typeof architectures[number]) || typeof image !== 'string' || !fullPinnedImage.test(image))) {
    throw new PolicyError(409, 'Every build architecture needs a full registry image pinned by digest.');
  }
  const image = images[architecture];
  if (typeof image !== 'string') throw new PolicyError(409, `Builder image is missing for ${architecture}.`);
  return image;
}
export async function manifestDigest(revision: Pick<Revision,
  'id'|'request_id'|'version'|'recipe_sha256'|'public_recipe_sha256'|'sources_json'|'dependencies_json'|'smoke_commands_json'|'architectures_json'|
  'make_dependencies_json'|'build_images_json'|'pkgrel'|'source_date_epoch'|'image_digest'|'license'|'surface'|'description'|'sbom_json'>) {
  return sha256(JSON.stringify([
    revision.id, revision.request_id, revision.version, revision.recipe_sha256,
    manifestJSON(revision.sources_json, 'Source manifest'), manifestJSON(revision.dependencies_json, 'Dependency manifest'),
    manifestJSON(revision.make_dependencies_json ?? '[]', 'Build dependency manifest'),
    manifestJSON(revision.smoke_commands_json, 'Smoke command manifest'), manifestJSON(revision.architectures_json, 'Architecture manifest'),
    manifestJSON(revision.build_images_json ?? '{}', 'Builder image manifest'), revision.pkgrel ?? 1, revision.source_date_epoch,
    revision.image_digest, revision.license, revision.surface, manifestJSON(revision.sbom_json, 'SBOM'),
    ...(revision.description == null ? [] : [revision.description]),
    ...(revision.public_recipe_sha256 == null ? [] : [{ publicRecipeSha256: revision.public_recipe_sha256 }])
  ]));
}
export async function validateRevision(revision: Revision) {
  if (await sha256(revision.recipe) !== revision.recipe_sha256 || await manifestDigest(revision) !== revision.manifest_sha256) {
    throw new PolicyError(409, 'Recipe or build manifest integrity check failed. Generate a new revision.');
  }
  const publicRecipe = revision.public_recipe ?? null;
  const publicRecipeSha256 = revision.public_recipe_sha256 ?? null;
  if ((publicRecipe === null) !== (publicRecipeSha256 === null) ||
      (publicRecipe !== null && (typeof publicRecipeSha256 !== 'string' || await sha256(publicRecipe) !== publicRecipeSha256))) {
    throw new PolicyError(409, 'Public recipe integrity evidence is invalid. Generate a new revision.');
  }
  if (!isArchPkgver(revision.version)) throw new PolicyError(409, 'Reviewed version is not a valid Arch pkgver; regenerate with pkgrel separate.');
  if (!legacyPinnedImage.test(revision.image_digest)) throw new PolicyError(409, 'Builder image must be pinned by digest.');
  if (!revision.pr_url || !revision.commit_sha) throw new PolicyError(409, 'A generated GitHub pull request is required before review.');
  const sources = manifestArray(revision.sources_json, 'Source manifest');
  if (!sources.length || sources.some((value) => {
    if (!value || typeof value !== 'object' || Array.isArray(value)) return true;
    const source = value as Partial<Source>;
    return typeof source.url !== 'string' || !/^[a-f0-9]{64}$/.test(source.sha256 ?? '') || !/^[a-zA-Z0-9][a-zA-Z0-9._+-]{0,150}$/.test(source.name ?? '');
  })) {
    throw new PolicyError(409, 'Every source needs a safe filename and pinned SHA-256.');
  }
  for (const source of sources as Source[]) publicSourceURL(source.url);
  const dependencies = manifestArray(revision.dependencies_json, 'Dependency manifest');
  if (dependencies.some((value) => typeof value !== 'string' || value.length > 256 || !parseArchDependency(value))) throw new PolicyError(409, 'Dependency manifest is invalid.');
  const makeDependencies = manifestArray(revision.make_dependencies_json ?? '[]', 'Build dependency manifest');
  if (makeDependencies.some((value) => typeof value !== 'string' || value.length > 256 || !parseArchDependency(value))) throw new PolicyError(409, 'Build dependency manifest is invalid.');
  if (revision.description !== undefined && revision.description !== null &&
      (!revision.description.trim() || revision.description.length > 160 || /[\u0000\r\n]/.test(revision.description))) {
    throw new PolicyError(409, 'Final package description is invalid.');
  }
  if (!Number.isSafeInteger(revision.pkgrel ?? 1) || (revision.pkgrel ?? 1) < 1 || (revision.pkgrel ?? 1) > 9_999) throw new PolicyError(409, 'Package release number is invalid.');
  const smokeCommands = manifestArray(revision.smoke_commands_json, 'Smoke command manifest');
  if (smokeCommands.some((value) => typeof value !== 'string' || !value || value.length > 4_096)) throw new PolicyError(409, 'Smoke command manifest is invalid.');
  const requestedArchitectures: unknown = manifestArray(revision.architectures_json, 'Architecture manifest');
  if (!Array.isArray(requestedArchitectures) || !requestedArchitectures.length || requestedArchitectures.some((a) => !architectures.includes(a as typeof architectures[number]))) {
    throw new PolicyError(409, 'Select supported build architectures.');
  }
  for (const architecture of requestedArchitectures as Architecture[]) revisionImage(revision, architecture);
  manifestObject(revision.sbom_json, 'SBOM');
  const lint = manifestObject(revision.lint_json, 'Factory lint') as { passed?: boolean };
  if (lint.passed !== true) throw new PolicyError(409, 'Factory lint must pass before approval.');
}
