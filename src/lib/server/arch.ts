export type ArchDependency = {
  name: string;
  operator: '>=' | '<=' | '=' | '>' | '<' | null;
  version: string | null;
};

export type PackageMetadata = {
  name: string;
  fullVersion: string;
  architecture: 'x86_64' | 'aarch64';
  installedSize: number;
  depends: string[];
  provides: string[];
  conflicts: string[];
  replaces: string[];
};

const ARCH_PACKAGE_NAME = /^[a-z0-9][a-z0-9@._+-]{0,63}$/;
const ARCH_PKGVER = /^[A-Za-z0-9][A-Za-z0-9@._+%]{0,127}$/;
const ARCH_VERSION = /^(?:[0-9]+:)?[A-Za-z0-9][A-Za-z0-9@._+%~^:-]{0,127}$/;
const ARCH_DEPENDENCY = /^([a-z0-9][a-z0-9@._+-]{0,63})(?:(>=|<=|=|>|<)(.+))?$/;
const ARCH_SONAME = /^[A-Za-z0-9][A-Za-z0-9._+~-]{0,31}:[A-Za-z0-9][A-Za-z0-9._+~^-]{0,127}$/;
const ARCH_SONAME_V1 = /^([A-Za-z0-9][A-Za-z0-9._+~-]{0,127}\.so)(?:=(.+))?$/;

export function isArchPkgver(value: string): boolean {
  return ARCH_PKGVER.test(value);
}

function parseArchPackageVersion(value: string): { epoch: string; pkgver: string; pkgrel: string | null } | null {
  if (!ARCH_VERSION.test(value)) return null;
  const separator = value.indexOf(':');
  const epoch = separator < 0 ? '0' : value.slice(0, separator);
  const rest = separator < 0 ? value : value.slice(separator + 1);
  if (!/^\d+$/.test(epoch) || !rest || rest.includes(':')) return null;
  const releaseSeparator = rest.lastIndexOf('-');
  const possibleRelease = releaseSeparator > 0 ? rest.slice(releaseSeparator + 1) : '';
  return {
    epoch: epoch.replace(/^0+(?=\d)/, ''),
    pkgver: releaseSeparator > 0 && /^\d+(?:\.\d+)?$/.test(possibleRelease) ? rest.slice(0, releaseSeparator) : rest,
    pkgrel: releaseSeparator > 0 && /^\d+(?:\.\d+)?$/.test(possibleRelease) ? possibleRelease : null,
  };
}

export function parseArchDependency(value: string): ArchDependency | null {
  if (typeof value !== 'string' || /\s/.test(value)) return null;
  const match = ARCH_DEPENDENCY.exec(value);
  if (!match || !ARCH_PACKAGE_NAME.test(match[1])) return null;
  const operator = (match[2] as ArchDependency['operator']) ?? null;
  const version = match[3] ?? null;
  if (operator && (!version || !parseArchPackageVersion(version))) return null;
  return { name: match[1], operator, version };
}

/** Parse package relations, including native ALPM v2 `prefix:soname` values. */
export function parseArchRelation(value: string): ArchDependency | null {
  const dependency = parseArchDependency(value);
  if (dependency) return dependency;
  const legacySoname = ARCH_SONAME_V1.exec(value);
  if (legacySoname && (!legacySoname[2] || parseArchPackageVersion(legacySoname[2]))) {
    return { name: legacySoname[1], operator: legacySoname[2] ? '=' : null, version: legacySoname[2] ?? null };
  }
  if (!ARCH_SONAME.test(value) || !/\.so(?:\.|$)/i.test(value.slice(value.indexOf(':') + 1))) return null;
  return { name: value, operator: null, version: null };
}

function relationList(value: unknown, provides: boolean, allowSoname: boolean): string[] | null {
  if (!Array.isArray(value) || value.length > 256) return null;
  const result: string[] = [];
  for (const item of value) {
    if (typeof item !== 'string' || item.length === 0 || item.length > 256 || /[\u0000-\u001f\u007f\s]/.test(item)) return null;
    const relation = allowSoname ? parseArchRelation(item) : parseArchDependency(item);
    if (!relation || (provides && relation.operator !== null && relation.operator !== '=')) return null;
    result.push(item);
  }
  return result;
}

export function parsePackageMetadata(value: unknown): PackageMetadata | null {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  const object = value as Record<string, unknown>;
  const keys = ['name', 'fullVersion', 'architecture', 'installedSize', 'depends', 'provides', 'conflicts', 'replaces'];
  if (Object.keys(object).length !== keys.length || keys.some((key) => !Object.prototype.hasOwnProperty.call(object, key))) return null;
  if (typeof object.name !== 'string' || !ARCH_PACKAGE_NAME.test(object.name)) return null;
  if (typeof object.fullVersion !== 'string' || !parseArchPackageVersion(object.fullVersion)) return null;
  if (object.architecture !== 'x86_64' && object.architecture !== 'aarch64') return null;
  if (typeof object.installedSize !== 'number' || !Number.isSafeInteger(object.installedSize) || object.installedSize < 0) return null;
  const depends = relationList(object.depends, false, true);
  const provides = relationList(object.provides, true, true);
  const conflicts = relationList(object.conflicts, false, false);
  const replaces = relationList(object.replaces, false, false);
  if (!depends || !provides || !conflicts || !replaces) return null;
  return {
    name: object.name,
    fullVersion: object.fullVersion,
    architecture: object.architecture,
    installedSize: object.installedSize,
    depends,
    provides,
    conflicts,
    replaces,
  };
}

export function satisfiesArchRelation(
  dependency: ArchDependency,
  provider: Pick<PackageMetadata, 'name' | 'fullVersion' | 'provides'>,
): boolean {
  if (dependency.name === provider.name) {
    return !dependency.operator || satisfiesArchDependency(dependency, provider.fullVersion);
  }
  for (const value of provider.provides) {
    const provided = parseArchRelation(value);
    if (!provided || provided.name !== dependency.name) continue;
    if (!dependency.operator) return true;
    if (provided.operator === '=' && provided.version && satisfiesArchDependency(dependency, provided.version)) return true;
  }
  return false;
}

function compareVersionText(left: string, right: string): number {
  let a = 0;
  let b = 0;
  const isDigit = (value: string | undefined) => value !== undefined && value >= '0' && value <= '9';
  const isAlpha = (value: string | undefined) => value !== undefined && ((value >= 'A' && value <= 'Z') || (value >= 'a' && value <= 'z'));
  while (a < left.length || b < right.length) {
    while (a < left.length && !isDigit(left[a]) && !isAlpha(left[a])) a += 1;
    while (b < right.length && !isDigit(right[b]) && !isAlpha(right[b])) b += 1;
    if (a >= left.length || b >= right.length) {
      if (a >= left.length && b >= right.length) return 0;
      const remaining = a >= left.length ? right[b] : left[a];
      const remainingIsNumeric = isDigit(remaining);
      if (a >= left.length) return remainingIsNumeric ? -1 : 1;
      return remainingIsNumeric ? 1 : -1;
    }
    const leftNumeric = isDigit(left[a]);
    const rightNumeric = isDigit(right[b]);
    if (leftNumeric !== rightNumeric) return leftNumeric ? 1 : -1;
    const startA = a;
    const startB = b;
    if (leftNumeric) {
      while (a < left.length && isDigit(left[a])) a += 1;
      while (b < right.length && isDigit(right[b])) b += 1;
      const leftDigits = left.slice(startA, a).replace(/^0+(?=\d)/, '');
      const rightDigits = right.slice(startB, b).replace(/^0+(?=\d)/, '');
      if (leftDigits.length !== rightDigits.length) return leftDigits.length < rightDigits.length ? -1 : 1;
      if (leftDigits !== rightDigits) return leftDigits < rightDigits ? -1 : 1;
    } else {
      while (a < left.length && isAlpha(left[a])) a += 1;
      while (b < right.length && isAlpha(right[b])) b += 1;
      const leftText = left.slice(startA, a);
      const rightText = right.slice(startB, b);
      if (leftText !== rightText) return leftText < rightText ? -1 : 1;
    }
  }
  return 0;
}

export function compareArchVersions(left: string, right: string): number | null {
  const a = parseArchPackageVersion(left);
  const b = parseArchPackageVersion(right);
  if (!a || !b) return null;
  if (a.epoch.length !== b.epoch.length) return a.epoch.length < b.epoch.length ? -1 : 1;
  if (a.epoch !== b.epoch) return a.epoch < b.epoch ? -1 : 1;
  const packageComparison = compareVersionText(a.pkgver, b.pkgver);
  if (packageComparison !== 0 || !a.pkgrel || !b.pkgrel) return packageComparison;
  return compareVersionText(a.pkgrel, b.pkgrel);
}

export function satisfiesArchDependency(dependency: ArchDependency, version: string): boolean {
  if (!dependency.operator || !dependency.version) return compareArchVersions(version, version) !== null;
  const comparison = compareArchVersions(version, dependency.version);
  if (comparison === null) return false;
  switch (dependency.operator) {
    case '=': return comparison === 0;
    case '>': return comparison > 0;
    case '>=': return comparison >= 0;
    case '<': return comparison < 0;
    case '<=': return comparison <= 0;
  }
}

function sameRelationCapability(actual: ArchDependency, reviewed: ArchDependency): boolean {
  if (actual.name === reviewed.name) return true;
  if (reviewed.operator !== null || actual.operator !== null || !reviewed.name.endsWith('.so') || !actual.name.includes(':')) return false;
  const soname = actual.name.slice(actual.name.indexOf(':') + 1);
  if (soname === reviewed.name) return true;
  return soname.startsWith(`${reviewed.name}.`) && /^\.\d(?:[A-Za-z0-9._+~-]*)$/.test(soname.slice(reviewed.name.length));
}

type VersionPosition = { epoch: string; pkgver: string; pkgrel: string | null; edge: 'start' | 'point' | 'end' };
type VersionBound = { position: VersionPosition; inclusive: boolean };
type VersionRange = { lower: VersionBound | null; upper: VersionBound | null };

function compareVersionBase(left: VersionPosition, right: VersionPosition): number {
  if (left.epoch.length !== right.epoch.length) return left.epoch.length < right.epoch.length ? -1 : 1;
  if (left.epoch !== right.epoch) return left.epoch < right.epoch ? -1 : 1;
  return compareVersionText(left.pkgver, right.pkgver);
}

function compareVersionPosition(left: VersionPosition, right: VersionPosition): number {
  const base = compareVersionBase(left, right);
  if (base !== 0) return base;
  if (left.edge !== right.edge) return ({ start: 0, point: 1, end: 2 }[left.edge] - { start: 0, point: 1, end: 2 }[right.edge]);
  if (left.edge !== 'point' || right.edge !== 'point' || left.pkgrel === null || right.pkgrel === null) return 0;
  return compareVersionText(left.pkgrel, right.pkgrel);
}

function versionPosition(value: string, edge: VersionPosition['edge']): VersionPosition | null {
  const parsed = parseArchPackageVersion(value);
  return parsed ? { ...parsed, edge } : null;
}

function relationRange(relation: ArchDependency): VersionRange | null {
  if (!relation.operator || !relation.version) return null;
  const point = versionPosition(relation.version, 'point');
  const start = versionPosition(relation.version, 'start');
  const end = versionPosition(relation.version, 'end');
  if (!point || !start || !end) return null;
  const hasRelease = point.pkgrel !== null;
  switch (relation.operator) {
    case '=': return hasRelease
      ? { lower: { position: point, inclusive: true }, upper: { position: point, inclusive: true } }
      : { lower: { position: start, inclusive: true }, upper: { position: end, inclusive: true } };
    case '>=': return { lower: { position: hasRelease ? point : start, inclusive: true }, upper: null };
    case '>': return { lower: { position: hasRelease ? point : end, inclusive: false }, upper: null };
    case '<=': return { lower: null, upper: { position: hasRelease ? point : end, inclusive: true } };
    case '<': return { lower: null, upper: { position: hasRelease ? point : start, inclusive: false } };
  }
}

function lowerCovers(native: VersionBound | null, reviewed: VersionBound | null): boolean {
  if (!reviewed) return true;
  if (!native) return false;
  const comparison = compareVersionPosition(native.position, reviewed.position);
  return comparison > 0 || (comparison === 0 && (!native.inclusive || reviewed.inclusive));
}

function upperCovers(native: VersionBound | null, reviewed: VersionBound | null): boolean {
  if (!reviewed) return true;
  if (!native) return false;
  const comparison = compareVersionPosition(native.position, reviewed.position);
  return comparison < 0 || (comparison === 0 && (!native.inclusive || reviewed.inclusive));
}

/** Return whether native relation is equal to or stricter than reviewed relation. */
export function archRelationCovers(nativeValue: string, reviewedValue: string): boolean {
  const native = parseArchRelation(nativeValue);
  const reviewed = parseArchRelation(reviewedValue);
  if (!native || !reviewed || !sameRelationCapability(native, reviewed)) return false;
  if (!reviewed.operator) return true;
  if (!native.operator || !native.version || !reviewed.version) return false;
  const nativeRange = relationRange(native);
  const reviewedRange = relationRange(reviewed);
  return nativeRange !== null && reviewedRange !== null &&
    lowerCovers(nativeRange.lower, reviewedRange.lower) && upperCovers(nativeRange.upper, reviewedRange.upper);
}
