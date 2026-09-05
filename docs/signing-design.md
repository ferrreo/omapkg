# omapkg signing and KMS design

## Decision

Use one signing identity for package and repository database signatures. The
first deployment runs the packet signer in a private Cloudflare Worker with
the OpenPGP private key in a Worker Secret. The optional managed-key path uses
one customer-managed AWS KMS asymmetric RSA key:

- managed key usage: `SIGN_VERIFY`
- managed key spec: `RSA_4096` (use `RSA_3072` if signing latency or cost becomes a
  measured issue)
- managed KMS signing algorithm: `RSASSA_PKCS1_V1_5_SHA_256`
- managed KMS message type: `DIGEST`
- OpenPGP signature: v4, binary-document signature, RSA, SHA-256

In the initial Cloudflare mode, the private key is generated once by the
isolated bootstrap script and is available only to the signer Worker. The
default is a signing-only 4096-bit RSA v4 key with no encryption subkey so its
base64 armor fits Cloudflare's Worker Secret limit. This is an accepted
operational tradeoff: Cloudflare Worker Secrets protect the value at rest, but
are not non-exportable KMS key material. Build workers, the main Worker, and
review services never receive it. The managed KMS path keeps the private key
inside KMS. KMS `Sign` returns the raw RSA signature; it does not return a
pacman-compatible OpenPGP signature file. A small omapkg signer must build the
OpenPGP Signature packet around that RSA result.

OpenPGP v4 hashes the package bytes, the signature fields, and a v4 trailer,
then encodes the resulting RSA PKCS#1 v1.5 signature as an MPI. RSA-PSS output
cannot be substituted into this packet format. KMS's
`DIGEST` mode lets the signer send the already-computed OpenPGP hash without
hashing it a second time.

References: [RFC 4880 §5.2.4](https://www.rfc-editor.org/rfc/rfc4880.html#section-5.2.4),
[KMS Sign](https://docs.aws.amazon.com/kms/latest/APIReference/API_Sign.html),
[KMS RSA algorithms](https://docs.aws.amazon.com/kms/latest/developerguide/symmetric-asymmetric.html).

For the initial Cloudflare deployment, provide a Cloudflare account with the
artifact R2 bucket and a secret-file path for the signer token and control-plane
token. The bootstrap script creates the OpenPGP identity locally without
printing private material. For the managed KMS path, provide an AWS account and
region, the resulting KMS key ARN, an IAM setup for the signer (or a secret-file
path for short-lived deployment credentials), and the domain/email to put in
the public OpenPGP User ID. The existing Cloudflare token cannot create an AWS
key or AWS credentials.

## Where signing runs

Run an `opr-signer` boundary in the same Cloudflare account and call it through
a Worker service binding. Keep authorization, R2/D1 access, and audit writes in
the Worker. The initial packet implementation uses OpenPGP.js in that Worker.
The managed packet/KMS implementation can run in a small trusted Go process in
a Cloudflare Container/Sandbox or in AWS Lambda; it is never part of a build
worker. Give the boundary:

- a private R2 binding for build artifacts and signatures;
- a D1 binding for the immutable build, approval, and signing-intent records;
- the signer-only OpenPGP Worker Secret for initial mode, or an AWS KMS client
  and least-privilege AWS credentials for managed mode;
- no build-worker credentials, source checkout, or package private key.

Cloudflare has Web Crypto and encrypted Worker Secrets, but no general-purpose
non-exportable KMS for this purpose. In managed mode, a Worker may hold AWS API
credentials that can ask KMS to sign; the RSA private material stays in KMS. If
those AWS credentials must not exist at Cloudflare, put the same small signer
behind an AWS Lambda execution role and keep only an authenticated Cloudflare
gateway. Moving from the initial secret-backed identity to KMS creates a new
OpenPGP fingerprint unless a separate key-migration design is adopted; publish
the new certificate and update client trust as one release.

References: [Workers Secrets](https://developers.cloudflare.com/workers/configuration/secrets/),
[Workers Web Crypto](https://developers.cloudflare.com/workers/runtime-apis/web-crypto/).

The repository includes a runnable managed service at
`signer/kms/cmd/opr-kms-signer`. It accepts an authenticated artifact stream,
spools it with mode `0600`, hashes it locally, calls KMS through the Go adapter,
and returns the detached packet plus public certificate. Set the Cloudflare
signer's `SIGNING_MODE=managed-kms`, `KMS_SIGNER_URL`, and
`KMS_SIGNER_TOKEN` to use it. Keep this endpoint private; the Cloudflare signer
continues to enforce the reviewed intent and R2 object policy before forwarding
bytes.

The control-plane signer endpoint must be internal. It must not accept
caller-supplied URLs or hashes. It receives a one-use signing intent, reloads
the referenced record, and signs only an immutable R2 object whose hash and
review state it verifies itself. The managed Go bridge accepts only an
authenticated artifact stream from that Worker, hashes the stream itself, and
does not trust request hash headers.

## Signing protocol

1. The build worker uploads the package to a private immutable R2 key and
   submits worker-signed provenance. The control plane verifies the lease,
   artifact hash, recipe/source approvals, area approval, security approval,
   and `surface: binary` state.
2. The control plane creates one signing intent. It contains an intent ID,
   build ID, exact R2 object key, expected artifact SHA-256, object kind
   (`package` or `database`), expected filename, signing-key fingerprint, and
   short expiry. The intent is consumed atomically.
3. The signer reloads the build and approval state, fetches exactly that R2
   object, streams its bytes through SHA-256, and compares the result with the
   recorded hash. A changed object, stale approval, recipe revision, or
   non-binary surface fails before packet signing is called.
4. For a package, the signer hashes the raw bytes as an OpenPGP binary
   document (`sig type 0x00`). Initial Cloudflare mode signs with its isolated
   OpenPGP.js key; managed mode sends the resulting 32-byte digest to KMS with
   `MessageType=DIGEST` and the fixed PKCS#1 v1.5 SHA-256 algorithm.
5. The signer creates a v4 Tag 2 Signature packet containing the RSA result as
   an MPI, the SHA-256 hash-prefix bytes, creation time, and issuer
   fingerprint. It writes the raw packet bytes to R2 as `<package>.sig` (for
   example, `foo.pkg.tar.zst.sig`). Keep package signatures binary, matching
   `gpg --detach-sign`; armor is only needed for the public key distribution
   file.
6. The signer verifies the generated packet locally with the matching public
   key, checks the expected fingerprint and artifact hash, stores the immutable
   signature object, and appends an audit event containing intent ID, build ID,
   artifact hash, signature hash, signing mode, and fingerprint. Managed mode
   also records KMS key ARN, algorithm, and request ID. A retry may return an
   existing matching result for the same intent; any mismatch fails closed.
7. Build the repository database only after the package set is fixed. Sign the
   exact resulting database bytes (and `.files` database if published), then
   publish package, signature, database, and database signature together.
   `repo-add` embeds a matching package `.sig` when present; pacman validates
   the repository database signature separately.

The same service may sign repository databases, but its authorization path must
distinguish them from package artifacts. It must never sign a Surface B recipe
fetch result or an artifact that is not retained and auditable.

References: [repo-add](https://man.archlinux.org/man/repo-add.8.en),
[pacman signature policy](https://man.archlinux.org/man/pacman.conf.5.en),
[ALPM repository signatures](https://man.archlinux.org/man/alpm-repo-db.7.en).

## OpenPGP implementation

The preferred implementation is a small Go signer in the trusted signer
runtime with:

- `github.com/aws/aws-sdk-go-v2/service/kms` for KMS calls;
- `github.com/ProtonMail/go-crypto/openpgp/packet` for v4 packet hashing,
  serialization, and verification;
- the standard library's `crypto/x509`, `crypto/rsa`, `crypto/sha256`, and
  `encoding/asn1` support for the KMS public key and hash.

The Proton fork's packet `Signature.Sign` accepts a `crypto.Signer`, and its
`PrivateKey` supports a remote signer. Its `NewSignerPrivateKey` helper only
type-switches concrete RSA/ECDSA/EdDSA private-key types, so an AWS adapter
should construct `packet.PrivateKey` with `PublicKey` from the KMS RSA public
key and `PrivateKey` set to the adapter directly. The adapter's `Sign` method
must accept only SHA-256, pass the digest to KMS with `DIGEST`, and return the
raw RSA signature. Reject every other hash or RSA padding option.

Do not use `golang.org/x/crypto/openpgp` directly; its OpenPGP package is
deprecated. OpenPGP.js expects a usable secret key for its normal signing API
and is not the KMS adapter here. A manual packet writer is the fallback if the
Go signer cannot be deployed in the Worker runtime; it needs an interoperability
test against both `gpg --verify` and pacman before use.

If keeping every byte of the signer in a TypeScript Worker is more valuable
than reusing the Go packet implementation, use Web Crypto for SHA-256 and a
small AWS Signature Version 4 client, then serialize the same v4 packet
directly. Treat that as cryptographic infrastructure: pin the packet format,
keep the implementation isolated, and require the acceptance checks below.

References: [ProtonMail packet API](https://pkg.go.dev/github.com/ProtonMail/go-crypto/openpgp/packet),
[Go crypto.Signer](https://pkg.go.dev/crypto#Signer).

## Public key and trust bootstrap

Managed mode uses KMS `GetPublicKey`, which returns a DER-encoded X.509
SubjectPublicKeyInfo. The bootstrap job parses its RSA modulus and exponent;
initial Cloudflare mode reads the generated public half from the same OpenPGP
identity. Both modes emit one stable OpenPGP public certificate containing:

- the RSA primary public-key packet;
- a project User ID, `omapkg <packages@example.com>` by default;
- a self-certification signature made through the same KMS key;
- the full fingerprint and key ID recorded in D1 and the deployment config.

Pin the certificate's creation time and store the armored public certificate
immutably in R2. Publish it at a stable HTTPS URL and provide an installer or
documented `pacman-key --add` step. Clients must import this key into their
pacman keyring and use `SigLevel = Required TrustedOnly`.

Override the default User ID only before generating the initial key. No private
key export is needed for managed mode or permitted after key bootstrap.

## AWS setup for managed mode

The current Cloudflare token cannot create an AWS KMS key. Managed mode needs
an AWS account, a region, and an AWS principal that can create/configure the
key. Key administration and signing use separate principals. Initial
Cloudflare mode needs no AWS account.

Create the key with the AWS CLI or console:

```sh
aws kms create-key \
  --key-spec RSA_4096 \
  --key-usage SIGN_VERIFY \
  --description 'OPR package signing key'
aws kms create-alias \
  --alias-name alias/opr-package-signing \
  --target-key-id <key-id>
```

The signer principal needs only `kms:Sign`, `kms:GetPublicKey`, and
`kms:DescribeKey` on this one key. Put `kms:Sign` in a separate policy
statement so its conditions do not accidentally block the read operations:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ReadOprSigningKey",
      "Effect": "Allow",
      "Action": ["kms:DescribeKey", "kms:GetPublicKey"],
      "Resource": "arn:aws:kms:<region>:<account-id>:key/<key-id>"
    },
    {
      "Sid": "SignOnlyOprDigests",
      "Effect": "Allow",
      "Action": "kms:Sign",
      "Resource": "arn:aws:kms:<region>:<account-id>:key/<key-id>",
      "Condition": {
        "StringEquals": {
          "kms:SigningAlgorithm": "RSASSA_PKCS1_V1_5_SHA_256",
          "kms:MessageType": "DIGEST"
        }
      }
    }
  ]
}
```

The key policy must allow the signer principal, and the admin principal must
be the only principal able to change policy, disable, or schedule deletion.
Enable CloudTrail and retain KMS `Sign` events with omapkg audit records. Do not
grant the signer `kms:ListKeys`, key creation, policy changes, deletion, or
admin permissions.

Worker Secrets/configuration names are:

```text
AWS_ACCESS_KEY_ID                 # omit when using the Lambda execution-role option
AWS_SECRET_ACCESS_KEY             # omit when using the Lambda execution-role option
AWS_REGION
OPR_KMS_KEY_ARN
OPR_KMS_SIGNING_ALGORITHM=RSASSA_PKCS1_V1_5_SHA_256
OPR_PACKAGE_SIGNING_FINGERPRINT
OPR_PACKAGE_SIGNING_PUBLIC_KEY_R2_KEY
```

Access-key values belong in the deployment secret store or an AWS role
mechanism, never Git, D1, KV, R2, build-worker configuration, logs, or a
client-visible `.env` file. The local development file may contain a reference
to a secret file, but this repository must receive no secret values.

## Rotation and recovery

AWS KMS does not automatically rotate asymmetric key material. Rotate by
creating a new RSA KMS key, generating a new OpenPGP certificate and
fingerprint, publishing both public keys during the transition, and selecting
the new key only for new signatures. Keep the old certificate indefinitely for
verification of cached packages and old repository databases. Persist the full
KMS key ARN and OpenPGP fingerprint with every signature; an alias alone is not
an audit identity.

If a key must be revoked, publish the revocation information and stop new
signatures before disabling the key. Keep a cold, offline recovery/certification
plan; a compromised or deleted KMS key cannot create a trustworthy revocation
signature after the fact.

Reference: [AWS KMS key rotation](https://docs.aws.amazon.com/kms/latest/developerguide/rotate-keys.html).

## Acceptance checks

The signing milestone is complete only when a real package and repository
database pass all of these checks:

1. `gpg --verify package.pkg.tar.zst.sig package.pkg.tar.zst` succeeds with
   the published public certificate.
2. A clean Arch environment with the omapkg key imported and
   `SigLevel = Required TrustedOnly` installs the package through pacman.
3. The database and database signature survive an R2 upload/download byte for
   byte and pacman accepts them.
4. A changed artifact, changed recipe revision, expired intent, missing
   approval, replayed intent, or Surface B result causes no signer call and no
   signature object; managed mode also makes no KMS call.
5. Build workers and their daemon logs contain no AWS credentials, OpenPGP
   private material, or signer endpoint capability.
6. CloudTrail, D1 audit records, and R2 object metadata link the KMS operation
   to the exact build, artifact hash, approvals, key ARN, and public-key
   fingerprint.
