# Native output build type v2

Build type URI: `https://github.com/ferrreo/omapkg/blob/main/docs/build-type-v2.md`.

This contract records one native build attempt with an enumerated output set.
It preserves v1 historical verification and does not assert release approval.
`inputPolicy` is `shadow` for legacy image-based preparation, or the frozen lock's
`bootstrap`/`owned` purpose. A valid signature is insufficient to activate a
repository. Admission as a private native provider separately checks current
authority, exact retained bytes and signed origin evidence.

The in-toto Statement v1 uses SLSA provenance v1. Its subjects are every output
filename and exact artifact SHA-256, sorted by filename. Full versions retain
ALPM epochs and fractional package releases. Artifact architecture can be
`x86_64`, `aarch64` or `any`; the build itself has one native target.

External parameters bind the recipe revision and manifest digest, attempt,
cohort revision and digest, complete output contract, installation groups,
reviewed runtime exceptions and recipe policy. Resolved dependencies enumerate
flat sources and, for shadow preparation, builder/runtime images and legacy OPR
packages. Frozen builds instead bind the retained lock, helper archive, makepkg
configuration and complete package-inventory pages. The signed report includes
the lock manifest, native host identity, prepared image identities and observed
installed inventories. These must match the exact reviewed lock; bootstrap input
evidence cannot be relabelled as owned input evidence.

Preserved recipes additionally bind `preservedRecipe: {capture, sourceBundle}` in
the worker report, immutable attempt and external parameters. Each value contains
`sha256` and `size`. Resolved dependencies include `recipe-capture` and
`recipe-source-bundle` with content-addressed URIs. These roots transitively bind
the original Git tree, metadata, source files, mirrors, caches and public keys.
This path requires frozen dependency inputs, an empty flat `sources` array and
the `preserved-recipe-v1` worker capability. Native execution verifies the complete
original tree, retained Git pins and signed-inspection metadata, then invokes
makepkg with network disabled and the recipe tree read-only. Source changes
require a new reviewed revision.

The original worker report is embedded byte-for-byte with its Ed25519 signature,
public key and SHA-256. The builder identity hashes that public-key encoding.
The report binds the attempt, exact inputs, all output identities and hashes,
each installation group, native runtime analysis and successful smoke tests.
Portable outputs require native-code inspection and payload comparison digests.
Cohort qualification compares those payload digests between required native
targets. Signing one build does not establish that the other target passed.

The signer checks the report, expected output contract, artifact subject and
signature. The control plane also checks immutable attempt records, registered
private artifact bytes, current cohort/catalog scope, active worker identity and
independent current recipe/catalog review authority. Database checks fence
changes to those approvals and scope at signature recording. Package signatures
remain attached to private attempt objects; statements live under
`metadata/builds/<build>/attempts/<attempt>/attestation.json`.

The offline verifier requires an independently trusted OpenPGP fingerprint,
valid central signature and worker signature. It checks the entire subject set,
output contract, runtime matrix and resolved inputs even when verifying one
selected output. It rejects substituted preservation roots, v2 evidence under
the v1 build type and incorrect input-policy claims. It cannot infer current
reviewer access, repository membership or release approval from historical
statement bytes.
