import { expect, test } from 'bun:test';
import { planDependencies } from '../src/lib/server/dependency-plan';
import { sha256 } from '../src/lib/server/db';
import { asD1, TestD1 } from './d1';

const schema = `
CREATE TABLE releases(
  id TEXT PRIMARY KEY,build_id TEXT NOT NULL,name TEXT NOT NULL,version TEXT NOT NULL,
  architecture TEXT NOT NULL,surface TEXT NOT NULL,channel TEXT NOT NULL,artifact_key TEXT,signature_key TEXT,published_at INTEGER NOT NULL
);
CREATE TABLE revisions(id TEXT PRIMARY KEY,manifest_sha256 TEXT NOT NULL);
CREATE TABLE approvals(id TEXT PRIMARY KEY,revision_id TEXT NOT NULL,kind TEXT NOT NULL,manifest_sha256 TEXT NOT NULL,revoked_at INTEGER);
CREATE TABLE builds(
  id TEXT PRIMARY KEY,revision_id TEXT NOT NULL,status TEXT NOT NULL,artifact_sha256 TEXT,artifact_size INTEGER,artifact_filename TEXT,provenance TEXT
);
`;

type PackageInput = {
  releaseId: string;
  name: string;
  version?: string;
  channel?: 'stable' | 'dev';
  depends?: string[];
  provides?: string[];
  conflicts?: string[];
  artifactTampered?: boolean;
};

class MemoryR2 {
  readonly objects = new Map<string, { body: Uint8Array; customMetadata: Record<string, string> }>();

  async head(key: string) {
    const object = this.objects.get(key);
    return object ? { size: object.body.byteLength, customMetadata: object.customMetadata } : null;
  }

  async get(key: string) {
    const object = this.objects.get(key);
    return object ? { size: object.body.byteLength, customMetadata: object.customMetadata, arrayBuffer: async () => object.body.slice().buffer } : null;
  }
}

function packageVersion(value: PackageInput): string {
  return value.version ?? '1.0-1';
}

async function insertPackage(db: TestD1, bucket: MemoryR2, value: PackageInput): Promise<void> {
  const version = packageVersion(value);
  const channel = value.channel ?? 'stable';
  const buildId = `build-${value.releaseId}`;
  const filename = `${value.name}-${version}-x86_64.pkg.tar.zst`;
  const artifactKey = `packages/x86_64/${filename}`;
  const artifact = new TextEncoder().encode(`${value.releaseId}-artifact`);
  const artifactSha256 = await sha256(artifact);
  const signature = new TextEncoder().encode(`${value.releaseId}-signature`);
  const signatureSha256 = await sha256(signature);
  bucket.objects.set(artifactKey, { body: artifact, customMetadata: { sha256: value.artifactTampered ? 'f'.repeat(64) : artifactSha256 } });
  bucket.objects.set(`${artifactKey}.sig`, { body: signature, customMetadata: { sha256: signatureSha256 } });
  const metadata = {
    name: value.name, fullVersion: version, architecture: 'x86_64', installedSize: 10,
    depends: value.depends ?? [], provides: value.provides ?? [], conflicts: value.conflicts ?? [], replaces: [],
  };
  const revisionId = `revision-${value.releaseId}`;
  db.prepare('INSERT INTO revisions(id,manifest_sha256) VALUES(?,?)').bind(revisionId, 'm'.repeat(64)).run();
  db.prepare('INSERT INTO approvals(id,revision_id,kind,manifest_sha256,revoked_at) VALUES(?,?,?,?,NULL),(?,?,?,?,NULL)')
    .bind(`area-${value.releaseId}`, revisionId, 'area', 'm'.repeat(64), `security-${value.releaseId}`, revisionId, 'security', 'm'.repeat(64)).run();
  db.prepare('INSERT INTO builds(id,revision_id,status,artifact_sha256,artifact_size,artifact_filename,provenance) VALUES(?,?,?,?,?,?,?)')
    .bind(buildId, revisionId, 'succeeded', artifactSha256, artifact.byteLength, filename, JSON.stringify({ packageMetadata: metadata })).run();
  db.prepare('INSERT INTO releases(id,build_id,name,version,architecture,surface,channel,artifact_key,signature_key,published_at) VALUES(?,?,?,?,?,?,?,?,?,?)')
    .bind(value.releaseId, buildId, value.name, version, 'x86_64', 'binary', channel, artifactKey, `${artifactKey}.sig`, 1).run();
}

async function planner(packages: PackageInput[], dependencies: string[], makeDependencies: string[] = []) {
  const db = new TestD1(schema);
  const bucket = new MemoryR2();
  for (const value of packages) await insertPackage(db, bucket, value);
  try {
    return await planDependencies({
      DB: asD1(db), ARTIFACTS: bucket as unknown as R2Bucket, PUBLIC_ORIGIN: 'https://opr.example',
      PACKAGE_SIGNING_FINGERPRINT: 'a'.repeat(40),
    }, { architecture: 'x86_64', dependencies, makeDependencies });
  } finally {
    db.close();
  }
}

test('dependency planner prefers signed stable packages and includes transitive runtime closure', async () => {
  const result = await planner([
    { releaseId: 'base-stable', name: 'base', version: '1.0-1' },
    { releaseId: 'mid-stable', name: 'mid', version: '1.0-1', depends: ['base>=1.0'] },
    { releaseId: 'mid-dev', name: 'mid', version: '9.0-1', channel: 'dev', depends: ['base>=1.0'] },
  ], ['mid']);
  expect(result.plan?.channel).toBe('stable');
  expect(result.plan?.packages.map((item) => item.releaseId)).toEqual(['mid-stable', 'base-stable']);
  expect(result.plan?.packages.every((item) => item.url.startsWith('https://opr.example/repo/x86_64/'))).toBe(true);
  expect(result.digest).toMatch(/^[0-9a-f]{64}$/);
});

test('dependency planner falls back to reviewed signed dev package', async () => {
  const result = await planner([{ releaseId: 'dev-only', name: 'dev-only', channel: 'dev' }], ['dev-only']);
  expect(result.plan?.channel).toBe('dev');
  expect(result.plan?.packages[0]?.url).toContain('/repo/dev/x86_64/');
});

test('dependency planner keeps stable roots and uses dev only for a missing stable version', async () => {
  const result = await planner([
    { releaseId: 'root-stable', name: 'root', depends: ['base>=2.0-1'] },
    { releaseId: 'base-stable-old', name: 'base', version: '1.0-1' },
    { releaseId: 'base-dev-new', name: 'base', version: '2.0-1', channel: 'dev' },
  ], ['root']);
  expect(result.plan?.channel).toBe('dev');
  expect(result.plan?.packages.find((item) => item.releaseId === 'root-stable')?.url).toContain('/repo/x86_64/');
  expect(result.plan?.packages.find((item) => item.releaseId === 'base-dev-new')?.url).toContain('/repo/dev/x86_64/');
});

test('dependency planner resolves SONAME through a native provider', async () => {
  const result = await planner([{ releaseId: 'provider', name: 'provider', provides: ['lib:libdemo.so.1'] }], ['lib:libdemo.so.1']);
  expect(result.plan?.packages.map((item) => item.name)).toEqual(['provider']);
});

test('dependency planner rejects unsatisfied versions and conflicts, while allowing installable cycles', async () => {
  await expect(planner([{ releaseId: 'old-lib', name: 'libdemo', version: '1.0-1' }], ['libdemo>=2.0-1'])).rejects.toThrow('not satisfied');
  await expect(planner([
    { releaseId: 'first', name: 'first', conflicts: ['second'] },
    { releaseId: 'second', name: 'second' },
  ], ['first', 'second'])).rejects.toThrow('conflict');
  await expect(planner([
    { releaseId: 'parent', name: 'parent', depends: ['child'], conflicts: ['child'] },
    { releaseId: 'child', name: 'child' },
  ], ['parent'])).rejects.toThrow('conflict');
  const cycle = await planner([
    { releaseId: 'cycle-a', name: 'cycle-a', depends: ['cycle-b'] },
    { releaseId: 'cycle-b', name: 'cycle-b', depends: ['cycle-a'] },
  ], ['cycle-a']);
  expect(cycle.plan?.packages.map((item) => item.releaseId)).toEqual(['cycle-a', 'cycle-b']);
});

test('dependency planner rejects tampered published artifact metadata', async () => {
  await expect(planner([{ releaseId: 'tampered', name: 'tampered', artifactTampered: true }], ['tampered'])).rejects.toThrow('unavailable or changed');
});
