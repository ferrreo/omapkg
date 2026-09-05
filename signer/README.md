# omapkg signer

`omarpkg-signer` is a private Cloudflare Worker. It owns the only package
signing key in the initial deployment. The main application reaches it through
a Worker service binding; it has no public route.

The initial deployment uses an OpenPGP v4 4096-bit signing-only RSA key held in
a Cloudflare Worker Secret. Its base64 armor fits Cloudflare's 5.1 kB secret
limit because it has no unnecessary encryption subkey. The private key is
available only to this Worker at runtime. The
optional `kms` package contains the same packet flow backed by AWS KMS for a
later managed-key cutover; build workers never receive either key.

## Local key bootstrap

Run from this directory. The script generates a fresh 4096-bit signing-only RSA v4 key and
writes the base64-encoded private key to a mode-0600 ignored file. It does not
print key material.

```sh
bun install
bun run generate-key
stat -c '%a %n' .env.local
```

`signer/.env.local` is ignored by Git. Keep it outside backups and CI logs. Set
the generated value as a Worker Secret without placing it in Wrangler vars:

```sh
sed -n 's/^OPR_SIGNING_PRIVATE_KEY_B64=//p' .env.local \
  | bunx wrangler secret put OPR_SIGNING_PRIVATE_KEY_B64 --config wrangler.jsonc
bunx wrangler secret put SIGNER_TOKEN --config wrangler.jsonc
bunx wrangler secret put CONTROL_TOKEN --config wrangler.jsonc
```

Set `SIGNING_MODE=managed-kms`, `KMS_SIGNER_URL`, and `KMS_SIGNER_TOKEN` when
using the optional Go service under `kms/cmd/opr-kms-signer`; omit
`OPR_SIGNING_PRIVATE_KEY_B64` in that mode. The managed service reads
`AWS_REGION`, `OPR_KMS_KEY_ARN`, and standard AWS SDK credentials or an
execution role, then exposes its private endpoint on `/v1/sign`.

Run that service from `signer/kms` on a private host:

```sh
export AWS_REGION=eu-west-1
export OPR_KMS_KEY_ARN=arn:aws:kms:...
# Set OPR_KMS_TOKEN through the host secret manager before starting.
go run ./cmd/opr-kms-signer
```

Keep `OPR_KMS_TOKEN` in the host secret store and put the service behind a
private network or authenticated reverse proxy. The service spools one request
body with mode `0600`, hashes it, asks KMS to sign the OpenPGP packet digest,
and removes the spool file after responding.

Copy `OPR_SIGNING_FINGERPRINT` from `.env.local` into a public deployment
variable or leave it unset; the Worker always derives and validates its own
fingerprint. Do not put private key material in the repository root `.env`, the
main application, D1, KV, R2, or a build-worker configuration.

## Deployment

The signer and main Worker must use the same Cloudflare account and R2 bucket.
Deploy signer first, then add this binding to the main Worker's Wrangler
configuration:

```json
{
  "services": [
    { "binding": "SIGNER", "service": "omarpkg-signer" }
  ]
}
```

The main Worker sends:

```http
POST https://signer/v1/sign
Authorization: Bearer <SIGNER_TOKEN>
Content-Type: application/json

{"intentId":"<one-use-intent-id>"}
```

The signer does not trust artifact bytes or hashes from this request. It loads
the intent from the control Worker, checks the review and attestation gates,
reads the exact R2 artifact, hashes it, signs it, verifies the serialized
signature, stores `<artifact-key>.sig`, and records the signing event through
the control Worker. A signing intent is ready only once the control Worker has
atomically recorded both area and security approvals for the exact manifest.

## Control Worker contract

`GET /api/internal/signing-intents/{id}` requires `Authorization: Bearer
<CONTROL_TOKEN>` and returns a `ready` contract. Once a completed event has
been recorded, the same request returns `signed` with its existing signature
identity so a retry can verify and return it without signing again:

```json
{
  "id": "intent-1",
  "status": "ready",
  "kind": "package",
  "expiresAt": 1900000000,
  "keyFingerprint": "40-lowercase-hex-characters",
  "artifact": {
    "key": "packages/x86_64/foo-1-1-x86_64.pkg.tar.zst",
    "sha256": "64-lowercase-hex-characters",
    "size": 123,
    "filename": "foo-1-1-x86_64.pkg.tar.zst"
  },
  "build": {
    "id": "build-1",
    "revisionId": "revision-1",
    "status": "succeeded",
    "surface": "binary",
    "architecture": "x86_64",
    "workerId": "worker-1",
    "smokePassed": true
  },
  "review": {
    "manifestSha256": "64-lowercase-hex-characters",
    "areaApproved": true,
    "securityApproved": true
  },
  "attestation": {
    "provenance": "<exact worker-signed JSON string>",
    "provenanceSignature": "<standard-base64 Ed25519 signature>",
    "workerPublicKey": "<standard-base64 raw 32-byte Ed25519 key>"
  }
}
```

The `signature` field is present only on a `signed` retry and contains the
existing immutable signature identity.

The artifact key is looked up directly through the signer's private R2 binding;
the control Worker does not return an arbitrary URL. The signer accepts
`package` objects ending in `.pkg.tar.zst` and `database` objects ending in
`.db`, `.files`, or the supported compressed repository database suffixes.

`POST /api/internal/signing-events` receives the authenticated audit event
after the signature and public key objects are durable. Its failure causes the
sign request to fail closed; an unreferenced signature object must not be
published.

## Outputs

- `keys/opr-package-signing.asc`: stable armored public certificate;
- `<artifact-key>.sig`: raw detached OpenPGP signature;
- sign response: artifact identity, signature R2 key/hash/filename/base64,
  public-key identity, and mode.

For a repository, create the final database first and submit it as `kind:
database`; sign the exact `.db.tar.*` bytes (and `.files.tar.*` when served).
Publish the package, package `.sig`, database, and database `.sig` together.
Clients import the public key and use `SigLevel = Required TrustedOnly`.

## Checks

```sh
bun run check
bun test
(cd kms && go test ./...)
bun run build
```

`bun test` uses a newly generated in-memory 2048-bit test key and verifies a
real detached package signature with GnuPG. It never reads production
`OPR_SIGNING_PRIVATE_KEY_B64`. The Go KMS tests use a fake KMS implementation
only; production `kms.New` requires an explicit AWS region, key ARN, and SDK
credentials and has no in-memory fallback.
