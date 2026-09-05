import type { Release, Architecture } from '../model';
import { type PackageMetadata, parseArchRelation, satisfiesArchRelation, parseArchDependency, archRelationCovers } from './arch';
import type { Env } from './env';
import { query, sha256, id } from './db';
import { finalDescription } from './descriptions';
import { fail, jsonArray, SHA256, base64, immutableBytes } from './release-storage';
import { packageMetadataFromProvenance, signingRequest } from './release-evidence';

export type ReleaseRow = Release & {
  revision_id: string;
  manifest_sha256: string;
  recipe_sha256: string;
  source_date_epoch: number;
  artifact_sha256: string | null;
  artifact_size: number | null;
  installed_size: number | null;
  artifact_filename: string | null;
  license: string;
  description?: string | null;
  recipe?: string;
  explanation: string;
  dependencies_json: string;
  upstream_url: string;
  provenance: string | null;
  package_metadata?: PackageMetadata;
};

type BinaryRelease = ReleaseRow & {
  surface: 'binary'; artifact_key: string; signature_key: string;
  artifact_sha256: string; artifact_size: number; artifact_filename: string;
};

export function binaryReleases(rows: ReleaseRow[]): BinaryRelease[] {
  return rows.filter((row) => row.surface === 'binary').map((row) => {
    const { artifact_key, signature_key, artifact_sha256, artifact_size, artifact_filename } = row;
    if (!artifact_key || !signature_key || !artifact_sha256 || artifact_size === null || !artifact_filename) {
      fail(409, `Release ${row.id} has incomplete artifact metadata.`);
    }
    return { ...row, surface: 'binary', artifact_key, signature_key, artifact_sha256, artifact_size, artifact_filename };
  });
}

export type RepositorySnapshot = { id: string; architecture: Architecture; channel: 'stable' | 'dev'; dbKey: string; dbSignatureKey: string; dbSha256: string; batchId: string };

export const PACKAGE_FILENAME = /^[A-Za-z0-9][A-Za-z0-9._+:-]{0,220}\.pkg\.tar\.zst$/;

function textValue(value: unknown, fallback = ''): string {
  return typeof value === 'string' ? value.replace(/[\u0000\r\n]+/g, ' ').trim() : fallback;
}

export async function releaseRows(env: Env, where: string, ...values: unknown[]): Promise<ReleaseRow[]> {
  return query<ReleaseRow>(env.DB, `SELECT r.*,
    v.recipe_sha256,v.source_date_epoch,b.artifact_sha256,b.artifact_size,b.installed_size,b.artifact_filename,
    b.provenance,b.revision_id,v.manifest_sha256,v.recipe,v.description,v.license,v.explanation,v.dependencies_json,q.upstream_url
    FROM releases r JOIN builds b ON b.id=r.build_id JOIN revisions v ON v.id=b.revision_id JOIN requests q ON q.id=v.request_id
    WHERE ${where}`, ...values);
}

type ReleasePackage = { row: BinaryRelease; metadata: PackageMetadata };

function releasePackage(row: BinaryRelease): ReleasePackage {
  const metadata = row.package_metadata ?? packageMetadataFromProvenance(row.provenance, {
    name: row.name, version: row.version, architecture: row.architecture, installedSize: row.installed_size,
  });
  return { row, metadata };
}

function relationText(value: unknown, label: string): string {
  if (typeof value !== 'string') fail(409, `${label} contains a non-string relation.`);
  return value;
}

export function assertDependencyGraph(candidates: ReleaseRow[], current: ReleaseRow[], final: ReleaseRow[]) {
  const finalPackages = binaryReleases(final).map(releasePackage);
  const knownPackages = binaryReleases([...current, ...candidates]).map(releasePackage);
  const knownNames = new Set<string>();
  for (const { row, metadata } of knownPackages) {
    knownNames.add(row.name);
    for (const value of metadata.provides) {
      const relation = parseArchRelation(value);
      if (relation) knownNames.add(relation.name);
    }
  }
  const providersFor = (architecture: Architecture) => finalPackages.filter((item) => item.row.architecture === architecture);
  const checkDependency = (owner: ReleasePackage, value: unknown, label: string) => {
    const text = relationText(value, label);
    const dependency = parseArchRelation(text);
    if (!dependency) {
      if (label === 'dependency manifest') fail(409, `Invalid Arch dependency constraint ${text}.`);
      fail(409, `Invalid Arch ${label.toLowerCase()} ${text}.`);
    }
    const providers = providersFor(owner.row.architecture);
    if (providers.some((provider) => satisfiesArchRelation(dependency, provider.metadata))) return;
    // Unknown names are supplied by Arch core/extra or another configured base
    // repository. Only fail when OPR previously advertised this capability.
    if (knownNames.has(dependency.name)) {
      const available = providers.flatMap((provider) => {
        if (provider.metadata.name === dependency.name) return [provider.metadata.fullVersion];
        return provider.metadata.provides.flatMap((value) => {
          const provided = parseArchRelation(value);
          return provided?.name === dependency.name ? [provided.version ?? provider.metadata.fullVersion] : [];
        });
      })[0] ?? 'the final package set';
      fail(409, `Dependency ${text} is not satisfied by ${available} for ${owner.row.name} on ${owner.row.architecture}.`);
    }
  };

  for (const owner of finalPackages) {
    for (const value of owner.metadata.depends) checkDependency(owner, value, 'package dependency');
    for (const value of owner.metadata.conflicts) {
      const text = relationText(value, 'Package conflict');
      const conflict = parseArchDependency(text);
      if (!conflict) fail(409, `Invalid Arch package conflict ${text}.`);
      if (providersFor(owner.row.architecture).some((provider) => provider.row.id !== owner.row.id && satisfiesArchRelation(conflict, provider.metadata))) {
        fail(409, `Package ${owner.row.name} conflicts with ${text} on ${owner.row.architecture}.`);
      }
    }
  }

  for (const candidate of binaryReleases(candidates)) {
    const owner = finalPackages.find((item) => item.row.id === candidate.id);
    if (!owner) continue;
    for (const value of jsonArray(candidate.dependencies_json, 'Dependency manifest')) {
      const text = relationText(value, 'Dependency manifest');
      checkDependency(owner, text, 'dependency manifest');
      if (!owner.metadata.depends.some((native) => archRelationCovers(native, text))) {
        fail(409, `Native package metadata does not contain reviewed dependency ${text}.`);
      }
    }
    for (const value of owner.metadata.replaces) {
      if (!parseArchDependency(relationText(value, 'Package replacement'))) fail(409, `Invalid Arch package replacement ${String(value)}.`);
    }
  }
}

function octal(value: number, width: number): string {
  return Math.max(0, value).toString(8).padStart(width - 1, '0') + '\0';
}

function checksum(value: number): string {
  return Math.max(0, value).toString(8).padStart(6, '0') + '\0 ';
}

function ascii(target: Uint8Array, offset: number, width: number, value: string) {
  const bytes = new TextEncoder().encode(value);
  if (bytes.length > width) throw new Error('tar field too long');
  target.set(bytes, offset);
}

function tarHeader(path: string, size: number): Uint8Array {
  const header = new Uint8Array(512);
  const split = path.lastIndexOf('/');
  const prefix = split > 0 ? path.slice(0, split) : '';
  const name = split > 0 ? path.slice(split + 1) : path;
  if (name.length > 100 || prefix.length > 155) throw new Error('repository entry path too long');
  ascii(header, 0, 100, name);
  ascii(header, 100, 8, octal(0o644, 8));
  ascii(header, 108, 8, octal(0, 8));
  ascii(header, 116, 8, octal(0, 8));
  ascii(header, 124, 12, octal(size, 12));
  ascii(header, 136, 12, octal(0, 12));
  header.fill(0x20, 148, 156);
  header[156] = 0x30;
  ascii(header, 257, 6, 'ustar\0');
  ascii(header, 263, 2, '00');
  ascii(header, 345, 155, prefix);
  let sum = 0;
  for (const byte of header) sum += byte;
  ascii(header, 148, 8, checksum(sum));
  return header;
}

function tar(entries: Array<{ path: string; body: Uint8Array }>): Uint8Array {
  const size = entries.reduce((total, entry) => total + 512 + Math.ceil(entry.body.length / 512) * 512, 1024);
  const result = new Uint8Array(size);
  let offset = 0;
  for (const entry of entries) {
    result.set(tarHeader(entry.path, entry.body.length), offset);
    offset += 512;
    result.set(entry.body, offset);
    offset += Math.ceil(entry.body.length / 512) * 512;
  }
  return result;
}

async function gzip(bytes: Uint8Array): Promise<Uint8Array> {
  const stream = new CompressionStream('gzip');
  const writer = stream.writable.getWriter();
  await writer.write(bytes as unknown as BufferSource);
  await writer.close();
  return new Uint8Array(await new Response(stream.readable).arrayBuffer());
}

function field(name: string, values: string | string[]): string {
  const list = Array.isArray(values) ? values : [values];
  return `%${name}%\n${list.filter(Boolean).join('\n')}\n\n`;
}

async function repositoryDatabase(env: Env, rows: BinaryRelease[]): Promise<Uint8Array> {
  const entries: Array<{ path: string; body: Uint8Array }> = [];
  for (const row of [...rows].sort((a, b) => `${a.name}-${a.version}-${a.architecture}`.localeCompare(`${b.name}-${b.version}-${b.architecture}`))) {
    if (!row.artifact_filename || !PACKAGE_FILENAME.test(row.artifact_filename) || !SHA256.test(row.artifact_sha256) || !Number.isSafeInteger(row.artifact_size) || row.artifact_size < 1) {
      fail(409, `Release ${row.id} has incomplete artifact metadata.`);
    }
    const signature = await env.ARTIFACTS.get(row.signature_key);
    if (!signature) fail(409, `Release ${row.id} has no package signature.`);
    const signatureBytes = new Uint8Array(await signature.arrayBuffer());
    if (!signatureBytes.length || signatureBytes.length > 16_384) fail(409, `Release ${row.id} has invalid package signature.`);
    if (row.installed_size !== null && (!Number.isSafeInteger(row.installed_size) || row.installed_size < 1)) {
      fail(409, `Release ${row.id} has invalid installed package size.`);
    }
    const packageDir = `${row.name}-${row.version}`;
    const metadata = row.package_metadata ?? packageMetadataFromProvenance(row.provenance, {
      name: row.name, version: row.version, architecture: row.architecture, installedSize: row.installed_size,
    });
    const desc = [
      field('FILENAME', row.artifact_filename), field('NAME', row.name), field('BASE', row.name), field('VERSION', row.version),
      field('DESC', finalDescription(row, row.name)), field('CSIZE', String(row.artifact_size)),
      row.installed_size === null ? '' : field('ISIZE', String(row.installed_size)),
      field('SHA256SUM', row.artifact_sha256), field('PGPSIG', base64(signatureBytes)), field('URL', row.upstream_url),
      field('LICENSE', textValue(row.license, 'unknown')), field('ARCH', row.architecture), field('BUILDDATE', String(row.source_date_epoch)),
      field('PACKAGER', 'omapkg'), metadata.depends.length ? field('DEPENDS', metadata.depends) : '',
      metadata.provides.length ? field('PROVIDES', metadata.provides) : '',
      metadata.conflicts.length ? field('CONFLICTS', metadata.conflicts) : '',
      metadata.replaces.length ? field('REPLACES', metadata.replaces) : '',
    ].join('');
    entries.push({ path: `${packageDir}/desc`, body: new TextEncoder().encode(desc) });
  }
  return gzip(tar(entries));
}

export async function currentStable(env: Env): Promise<ReleaseRow[]> {
  return releaseRows(env, "r.channel='stable'");
}

export async function currentDev(env: Env): Promise<ReleaseRow[]> {
  return releaseRows(env, "r.channel='dev'");
}

export function finalStable(current: ReleaseRow[], candidates: ReleaseRow[]): ReleaseRow[] {
  const replaced = new Set(candidates.map((row) => `${row.name}:${row.architecture}`));
  return [...current.filter((row) => !replaced.has(`${row.name}:${row.architecture}`)), ...candidates];
}

export function latestPerPackage(rows: ReleaseRow[]): ReleaseRow[] {
  const latest = new Map<string, ReleaseRow>();
  for (const row of [...rows].sort((left, right) => left.published_at - right.published_at || left.id.localeCompare(right.id))) {
    latest.set(`${row.name}:${row.architecture}`, row);
  }
  return [...latest.values()];
}

export async function snapshot(env: Env, rows: ReleaseRow[], architecture: Architecture, context: BinaryRelease, batchId: string, channel: 'stable' | 'dev' = 'stable') {
  const database = await repositoryDatabase(env, binaryReleases(rows).filter((row) => row.architecture === architecture));
  const digest = await sha256(database);
  const dbKey = `repo/${channel}/${architecture}/${batchId}/opr.db.tar.gz`;
  await immutableBytes(env, dbKey, database, digest, 'application/gzip');
  const signed = await signingRequest(env, {
    buildId: context.build_id, revisionId: context.revision_id, manifestSha256: context.manifest_sha256,
    objectKey: dbKey, objectKind: 'database', artifactSha256: digest, artifactSize: database.byteLength, artifactFilename: 'opr.db.tar.gz',
  });
  return { id: id(), architecture, channel, dbKey, dbSignatureKey: signed.signatureKey, dbSha256: digest, batchId };
}
