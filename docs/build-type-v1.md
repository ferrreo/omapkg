# Omapkg release evidence, version 1

Build type: `https://github.com/ferrreo/omapkg/blob/main/docs/build-type-v1.md`.
Statements use in-toto Statement v1 and the SLSA provenance v1 predicate. This
format does not claim a SLSA level or prove that software is safe.

A binary statement's subject is the exact package archive. A recipe statement's
subject is the published `PKGBUILD`; it authenticates the recipe and its tested
internal build, not a later build on a user's machine. The external parameters
bind the revision, reviewed manifest, internal and published recipe digests, and
exact reviewed runtime exceptions. Resolved dependencies identify fetched source
bytes and the reviewed builder image. The embedded worker report additionally
contains the frozen repository dependency plan and prepared image inventories.

The central detached OpenPGP signature authenticates the complete statement.
Before granting it, the control plane checks current area/security approvals,
manifest integrity, worker enrollment and status, exact uploaded bytes, successful
smoke tests, and runtime evidence. New custom-shell revisions require both
reviewers' explicit acknowledgements tied to that manifest. The signer verifies
the exact Ed25519 worker report carried as base64 in `runDetails.byproducts`.
Its public key is authenticated by the central signature, not trusted merely
because a downloaded report contains it. The worker identity is the SHA-256 of
its base64 public-key string. Neither signature proves honest execution on a
compromised worker or absence of malicious upstream code.

## Independent verification

Download a release's `attestation.json`, `attestation.json.sig`, `sbom.json`, and
package archive (or public `PKGBUILD`) through its package page. Obtain the
central public key and fingerprint through an independently trusted operator
channel; a key downloaded alongside evidence cannot establish its own trust.

```sh
bun install --cwd signer
bun signer/scripts/verify-release.ts \
  --statement attestation.json --signature attestation.json.sig \
  --subject PACKAGE_OR_PKGBUILD --sbom sbom.json \
  --key trusted-key.asc --fingerprint TRUSTED_FINGERPRINT
```

This checks central and embedded worker signatures, subject bytes, worker and
build identity, source and recipe bindings, runtime policy, and optional SBOM
bytes. Keep the subject's original filename (`PKGBUILD` for recipes). It cannot
establish that a downloaded release remains recommended: also consult the
current catalog for withdrawal or quarantine. Historical releases with no public
statement are explicitly labelled; old records are not retroactively attested.

## Key history

Retain old public keys, fingerprints, signed statements and detached signatures
when rotating keys. Publish the replacement fingerprint through the same trusted
channel as enrollment, with activation time and reason. Do not replace or delete
immutable historical evidence. Verification must explicitly select the trusted
historical key; the verifier does not silently accept a key named in a report.

Worker revocation blocks new completion/publication/signing. Central key
revocation must be distributed to consumers with the compromise window and
withdrawal guidance. Historical cryptographic validity does not establish that
a signature preceded compromise: statements have no independent trusted time
or transparency-log inclusion proof. A consumer's trust policy decides whether
to accept historical signatures after revocation. Retain the revoked public-key
certificate and incident history as well as replacement keys.

## Recipe and runtime policy

`make-v1` and `go-v1` templates have immutable version identifiers and definition
digests. Review validation re-renders internal recipe, public recipe and smoke
commands. Other builds use explicitly reviewed custom shell. Deterministic
syntax and ShellCheck error checks cover all three execution surfaces at factory
submission and again in the worker. Static analysis is an additional rejection
check, not a sandbox or proof of safety.

Build and smoke execution are offline, unprivileged containers. Dependency
preparation has network access and never runs the candidate recipe. Runtime smoke
uses a separately pinned minimal Arch image plus runtime dependencies, excluding
the candidate's build-only dependency plan. Operators configure that image;
recipe authors cannot select it. The report records base digest, prepared image
identity, and exact `pacman -Q` inventories for both environments. Official Arch
packages are resolved during preparation, so pinning the base alone does not
make preparation reproducible. Frozen Omapkg packages are checked against their
recorded signatures, digests, versions and architecture.

Namcap's shared-library and interpreter dependency rules inspect the package;
ELF evidence includes required libraries, search paths and machine type. Errors
block the build. Ambiguous findings require a reviewed exact finding hash and
reason; they cannot waive errors. Failed analysis is retained in build logs and
structured blockers. Successful evidence, including exceptions, is worker-signed
and covered by the central statement. Declared dependencies and vendored build
inventory remain distinct from measured runtime requirements. Dynamic loading,
plugins, optional features and unexercised code paths remain unknown. The report
always marks complete runtime closure as false.

Missing dependencies block the parent request. Detection supplies no authority
to admit another upstream. Maintainers may link an existing request or explicitly
submit a new upstream through normal admission. Request graphs reject cycles,
more than eight levels, and more than 64 requests reachable from a root. A
matching approved published binary can resolve a dependency blocker, but the
parent returns to generation or review; this creates no approvals. Recipe and
exception findings require a new reviewed revision.
