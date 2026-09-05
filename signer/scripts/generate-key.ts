import { chmodSync, existsSync } from 'node:fs';
import * as openpgp from 'openpgp';

const output = process.argv[2] ?? '.env.local';
if (existsSync(output)) throw new Error(`refusing to overwrite ${output}`);

const { privateKey } = await openpgp.generateKey({
  type: 'rsa',
  // A signing-only 4096-bit key stays below Cloudflare's 5.1 kB secret limit
  // when its unnecessary encryption subkey is omitted.
  rsaBits: 4096,
  subkeys: [],
  userIDs: [{ name: 'omarpkg', email: 'packages@example.com' }],
  format: 'armored',
  config: { v6Keys: false, preferredHashAlgorithm: openpgp.enums.hash.sha256 },
});
const parsed = await openpgp.readPrivateKey({ armoredKey: privateKey });
const fingerprint = parsed.getFingerprint().toLowerCase();
const encoded = btoa(privateKey);
await Bun.write(output, [
  '# Generated locally. Keep this file private and never commit it.',
  `OPR_SIGNING_PRIVATE_KEY_B64=${encoded}`,
  `OPR_SIGNING_FINGERPRINT=${fingerprint}`,
  '',
].join('\n'));
chmodSync(output, 0o600);
console.log(`Generated signer key ${fingerprint} in ${output}.`);
