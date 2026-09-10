import { createReadStream } from 'node:fs';
import { readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { basename } from 'node:path';
import { parseArgs } from 'node:util';
import { verifyReleaseEvidence } from '../src/verify-release';

const { values } = parseArgs({ options: {
  statement: { type: 'string' }, signature: { type: 'string' }, subject: { type: 'string' },
  key: { type: 'string' }, fingerprint: { type: 'string' }, sbom: { type: 'string' },
} });

if (!values.statement || !values.signature || !values.subject || !values.key || !values.fingerprint) {
  throw new Error('Usage: bun signer/scripts/verify-release.ts --statement attestation.json --signature attestation.json.sig --subject PACKAGE_OR_PKGBUILD --key TRUSTED_KEY.asc --fingerprint TRUSTED_FINGERPRINT [--sbom sbom.json]');
}

async function hashFile(path: string): Promise<string> {
  const hash = createHash('sha256');

  for await (const chunk of createReadStream(path)) hash.update(chunk);

  return hash.digest('hex');
}

const result = await verifyReleaseEvidence({
  statement: await readFile(values.statement), signature: await readFile(values.signature),
  trustedPublicKey: await readFile(values.key, 'utf8'), trustedFingerprint: values.fingerprint,
  subjectSha256: await hashFile(values.subject), subjectName: basename(values.subject),
  sbomSha256: values.sbom ? await hashFile(values.sbom) : undefined,
});

console.log(`Verified ${result.surface} evidence for build ${result.buildId}. Signatures authenticate claims, not software safety.`);
