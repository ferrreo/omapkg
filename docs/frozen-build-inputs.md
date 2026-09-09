# Frozen native build inputs

The native worker can build and test from retained input archives. Coordinator
admission, private object registration, production leases and central verification
are still being implemented. Current production claims do not use this path.
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
256 GiB. These reject excess work; they do not establish measured capacity.
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
locked build tools. Compilation uses the pinned makepkg configuration copied to
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
A failed or changed capture needs a new output directory.

From `worker/`, run:

```sh
OPR_FROZEN_E2E_CAPTURE=/absolute/capture go test -run '^TestRunnerFrozenInputsNativeOCI$' -count=1 -v
```

The capture must bind `worker/testdata/frozen`. The test serves retained objects
through signed local requests, builds native/portable outputs, checks runtime
isolation and rejects another package's signing key. It creates no production
reviews or repository membership.

## Remaining authority

Bootstrap manifests need explicit private migration approval and a separate ARM
seed decision. Submitted `owned-build` labels confer no authority: registration
must bind them to admitted source, immutable native builds and signatures.
Input selection must be frozen into each lease/attempt and rechecked by
completion, signing and release gates. Current ingestion and independent
verification reject the new evidence; those integrations must land before the
worker capability is advertised.

Native ARM execution, full catalog/ABI qualification, independent reproduction,
release/client integration and human cutover remain separate requirements.
