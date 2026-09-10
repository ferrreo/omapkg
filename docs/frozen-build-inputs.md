# Frozen native build inputs

Native jobs can build and test from retained input archives. Migration 0035 adds
private retention, independent input reviews, immutable attempt bindings and
owned input origins. Workers advertise `frozen-inputs-v1`. The coordinator selects
this path only for an explicitly selected, currently approved lock.
A local bootstrap capture is neither human approval nor an owned release claim.

## Contract

`inputLock` identifies canonical JSON by SHA-256 and byte length. The manifest
binds architecture, recipe/cohort digests, source date epoch, retained preparation
helper and makepkg configuration. It enumerates one build environment and one
runtime environment per reviewed installation group.

Every environment pins its complete package count, archive bytes, sorted
`name version\n` inventory digest and pages of up to 64 package records. Records
pin package/signature/public-key bytes, primary signing fingerprint, full
version/architecture/filename, origin and origin evidence digest. Arch filenames
may omit an epoch; metadata and installed versions must retain it. `any` inputs
can serve either native architecture.

Limits: 128 KiB root, 1 MiB pages, 4,096 unique packages, 4 GiB per archive,
32 GiB helper, 1,024 page references and a reviewed transfer budget capped at
256 GiB. Coordinator metadata is bounded to 4 MiB of unique package pages and
4 MiB of origin documents per lock; each origin document is at most 1 MiB.
These reject excess work; they do not establish measured capacity.
The legacy 64-package dependency plan is unchanged.

The worker retrieves digest references through signed lease-scoped requests,
checks sizes/hashes and exact canonical fields, and validates OCI manifest/blob
hashes. The helper must match its pinned manifest and native architecture.
OCI export can change a registry image's manifest digest; pin the actual retained
manifest and verify that its archive loads before submitting a capture.

## Preparation

Preparation verifies each archive against its own retained key and actual
`.PKGINFO`, then installs a complete transaction into an empty root without sync
repositories. The helper filesystem is not copied into the new root.

Initial extraction checks dependencies/file conflicts while deferring install
scripts and masking hooks. A second transaction runs inside the new root's OCI
container, with its own `/proc` and `/dev`. It installs the same verified bytes
as a fresh transaction so `post_install` and hooks run. Overwriting here is
limited to the already-checked initial filesystem. Hook failures reject
preparation. Both stages disable networking and retain existing capability
restrictions, adding `SYS_CHROOT` for pacman installation.

Build/runtime roots have separate complete inventory checks. Shell analysis uses
locked build tools by default. A new lock can explicitly set `shellAnalysis` to
`helper` to use the retained OCI helper for analysis before preparation. This
requires worker capability `helper-shell-analysis-v1` and new input review; the
helper archive, analysis choice and inventories remain bound by the signed lock.
Both paths analyze read-only script mounts without network access. Compilation uses the pinned makepkg configuration copied to
the work directory, existing fixed output/debug settings, locale `C`, UTC and
the locked source epoch. Execution remains offline and unprivileged. Evidence
includes the lock, prepared images, inventories, native worker/kernel
architecture, kernel/runtime versions and CPU model/evidence digest.

## Capture and validation

Run `services/pipeline/capture-bootstrap-inputs.py` inside a disposable pinned
native helper. Supply a retained helper archive, explicit pacman/makepkg
configurations, recipe/cohort digests, epoch, package targets per environment and
byte budget. `--help` lists arguments; `--self-test` checks parsing.

Capture resolves from an empty local database/cache, retains repository databases
and reads archive sizes from `%CSIZE%` (printed download size can be zero for
cached packages). It verifies package hashes/signatures and retains the public
keys. Output: `manifest.json`, `reference.json`, digest-addressed `objects/` and
a private-bootstrap notice. Capture never installs or publishes packages.
Only explicitly resolved package records supply archive sizes; malformed selected
records still fail capture. Original database bytes remain retained in full, and
this subset capture does not qualify unrelated database records.
A failed or changed capture needs a new output directory.
`--helper-shell-analysis` selects the explicit helper analysis option when preparing
a new capture; otherwise the build package list must include ShellCheck.

From `worker/`, run:

```sh
OPR_FROZEN_E2E_CAPTURE=/absolute/capture go test -run '^TestRunnerFrozenInputsNativeOCI$' -count=1 -v
```

The capture must bind `worker/testdata/frozen`. The test serves retained objects
through signed local requests, builds native/portable outputs, checks runtime
isolation and rejects another package's signing key. It creates no production
reviews or repository membership.

## Review and use

1. Open **Catalog → Frozen build inputs** and upload the capture folder. Every
   object uses resumable 8 MiB parts and whole-object checksum verification.
   Canonical JSON receives an immutable database index for bounded batch reads;
   downloads and native preparation still verify the retained object bytes.
2. Match the capture to its current recipe and cohort. The coordinator verifies
   the complete object index, package counts, exact inventories, source records,
   helper reference and transfer budget. Package origin labels never grant trust.
3. Two distinct humans, with current system and security authority, review the
   exact lock. They review captured source databases, package signing fingerprints,
   public keys and retained helper. Capture metadata alone cannot approve a seed.
4. Select the lock during cohort planning, review or build. A changed selection
   queues a new attempt after a completed or failed build. Prior attempt evidence
   stays immutable. Active leases cannot change locks, and workers without frozen
   input support skip selected jobs. Revoking input authority fences affected
   active leases, including descendants of revoked native inputs.
5. Sign each successful native package and its complete build statement. **Retain
   for private builds** registers the output against its immutable frozen attempt,
   admitted source and both signing intents. Shadow outputs cannot enter this
   registry. Original recipe reviews, input reviews, worker identity and explicit
   input revocations remain authorization checks; proposing a newer recipe does
   not silently discard valid historical input versions.
6. **Prepare owned lock for review** replaces every captured package with a
   retained native output of the exact same name, version and architecture.
   Missing outputs block assembly. If matching builds produced different package
   archive hashes, a maintainer must choose an exact artifact. This choice does
   not establish reproducibility or bypass its release gate. Identical package
   bytes reuse the first eligible origin in digest order.
7. Review the resulting owned lock independently and select it for the final
   native rebuild. Owned input classification permits private build use; final
   component rebuilding, ABI, reproducibility and release checks remain required.

Input pages, downloads and review records are maintainer-only. Worker downloads
require a signed request, current lease and membership in that exact lock's
object index. A selected job cannot fall back to a live repository resolver.

Completion compares the worker's lock digest with the immutable lease. The
coordinator rechecks current authority before signing; the isolated signer
independently checks the reviewed lock digest, output set and native evidence.
Signed statements distinguish `shadow`, `bootstrap` and `owned` input policies
and bind the retained lock, helper, configuration and package pages. Offline
verification rejects changes to that policy, its resolved inputs or worker
evidence. A signed build statement is not release membership or complete release
qualification.

## Rollout requirements

Production bootstrap manifests need explicit private migration approval and a
separate ARM seed decision. Deploy the coordinator migration and protocol before
upgrading workers to advertise the new capability. Existing shadow jobs remain
readable and executable under their prior protocol.

Native ARM execution, full catalog/ABI qualification, independent reproduction,
release/client integration and human cutover remain separate requirements.
