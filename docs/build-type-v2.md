# Native output build type v2

Build type URI: `https://github.com/ferrreo/omapkg/blob/main/docs/build-type-v2.md`.

This contract records one native build attempt with an enumerated output set.
It preserves v1 historical verification and does not assert release approval.
The current `inputPolicy` is `shadow`: builder and runtime images are pinned,
but their package inputs have not yet been qualified as an owned distribution.
A valid signature on this statement is insufficient to activate a repository or
to admit the artifacts as owned providers.

The in-toto Statement v1 uses SLSA provenance v1. Its subjects are every output
filename and exact artifact SHA-256, sorted by filename. Full versions retain
ALPM epochs and fractional package releases. Artifact architecture can be
`x86_64`, `aarch64` or `any`; the build itself has one native target.

External parameters bind the recipe revision and manifest digest, attempt,
cohort revision and digest, complete output contract, installation groups,
reviewed runtime exceptions and recipe policy. Resolved dependencies enumerate
sources, builder image, each runtime base image, and any frozen legacy OPR
packages with their artifact and signature hashes and trusted key fingerprint.
The worker report additionally records prepared image identities and installed
package inventories. These inventories describe observed shadow inputs; they
are not an owned input lock.

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
selected output. It rejects v2 evidence under the v1 build type and rejects
claims that this shadow contract qualifies owned inputs. It cannot infer current
reviewer access, repository membership or release approval from historical
statement bytes.
