import { canonicalJson } from '../src/lib/canonical-json';
import type { FrozenManifest, FrozenPackage } from '../src/lib/frozen-inputs';
import type { Revision } from '../src/lib/model';
import type { OutputContract } from '../src/lib/output-contract';
import { sha256 } from '../src/lib/server/db';

// Inert protocol fixtures. Native installation and detached signature checks live
// in worker/frozen-inputs_test.go; these bytes must never count as native evidence.
export async function frozenFixture(env: { DB: D1Database; ARTIFACTS: R2Bucket }, revision: Revision, contract: OutputContract) {
  async function retain(value: unknown) {
    const bytes = new TextEncoder().encode(typeof value === 'string' ? value : canonicalJson(value));
    const digest = await sha256(bytes);
    await env.ARTIFACTS.put(`private/test-inputs/${digest}`, bytes);
    await env.DB.prepare('INSERT OR IGNORE INTO input_objects VALUES(?,?,?,?,?)').bind(digest, bytes.length, `private/test-inputs/${digest}`, 'github:1', 1).run();
    return { sha256: digest, size: bytes.length };
  }
  const output = contract.outputs[0];
  const filename = `${output.name}-${output.fullVersion.replace(/^[0-9]+:/, '')}-x86_64.pkg.tar.zst`;
  const bytes = await retain('INERT bootstrap package');
  const origin = await retain({ schemaVersion: 1, kind: 'external-bootstrap-capture', architecture: 'x86_64', helperImage: revision.image_digest,
    databases: [{ name: 'core.db', object: await retain('INERT captured database') }], pacmanConfig: await retain('INERT pacman config'), targets: [output.name],
    packages: [{ name: output.name, version: output.fullVersion, architecture: 'x86_64', filename, repository: 'core',
      sha256: bytes.sha256, size: bytes.size, url: `https://example.org/${filename}` }] });
  const pkg: FrozenPackage = { name: output.name, version: output.fullVersion, architecture: 'x86_64', filename,
    package: bytes, signature: await retain('INERT detached signature'), publicKey: await retain('INERT public key'), fingerprint: 'A'.repeat(40), origin: 'external-bootstrap', originEvidence: origin.sha256 };
  const page = await retain([pkg]);
  const manifest: FrozenManifest = { schemaVersion: 1, purpose: 'bootstrap', architecture: 'x86_64', recipeSha256: revision.recipe_sha256,
    cohortSha256: contract.cohort.manifestSha256, sourceDateEpoch: revision.source_date_epoch, helperImage: revision.image_digest,
    helperArchive: await retain('INERT helper archive'), makepkgConfig: await retain('INERT makepkg config'), transferLimitBytes: 1024 * 1024,
    environments: Array.from({ length: contract.runtimeGroups.length + 1 }, (_, index) => ({ name: index ? `runtime-${index - 1}` : 'build',
      packageCount: 1, totalBytes: bytes.size, inventorySha256: '', chunks: [page] })) };
  for (const environment of manifest.environments) environment.inventorySha256 = await sha256(`${pkg.name} ${pkg.version}\n`);
  return { manifest, lock: await retain(manifest), pkg, retain };
}
