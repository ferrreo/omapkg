# Image reproducibility acceptance

`run.sh` drives the real image builders through the shared worker
`RunReproducibilityPair` helper. Each pair has a five-second wall-clock gap,
fresh roots, and no shared output or compiler cache. The helper compares every
declared output file byte-for-byte, including OCI layout metadata and raw image
payloads. The acceptance path does not unpack or normalize an output before
comparison.

Run the native x86 OCI fixture:

```sh
system-images/reproducibility/run.sh --oci
```

The fixture uses the pinned `oci-profile.json`, `FROM scratch`, Buildah's OCI
output, `--network none`, `--pull=never`, `--no-cache`, and the fixed source
epoch in the profile. It then runs a second fixture that writes a fresh real
timestamp into its build context. That negative pair must mismatch. A
mismatch keeps both payload trees, build logs, per-attempt metadata,
`reproducibility-diff.json`, `metadata.diff`, and `payload.diff` under the
printed output directory.

Run boot/filesystem image-build reproducibility against a private candidate:

```sh
SYSTEM_IMAGE_REPRO_CANDIDATE_LOCK=/private/lock.json \
SYSTEM_IMAGE_REPRO_CANDIDATE_LOCK_SIGNATURE=/private/lock.json.sig \
SYSTEM_IMAGE_REPRO_CANDIDATE_ID=candidate-1 \
SYSTEM_IMAGE_REPRO_NATIVE_PLAN=/private/native-plan.json \
SYSTEM_IMAGE_REPRO_NATIVE_PLAN_SIGNATURE=/private/native-plan.json.sig \
SYSTEM_IMAGE_REPRO_KEY=/private/release-key.asc \
SYSTEM_IMAGE_REPRO_FINGERPRINT=0123456789abcdef0123456789abcdef01234567 \
system-images/reproducibility/run.sh --boot \
  --profile system-images/profiles/x86_64-uefi.json
```

For a real disposable native fixture, first fetch the pinned x86_64 kernel,
grub, firmware, and dependency closure into a private directory, then run the
production builder with those exact bytes. The fetch step uses network only to
prepare private test inputs; image builds use a loopback HTTPS server and the
container's isolated build path:

```sh
export SYSTEM_IMAGE_REPRO_BOOT_BUILDER_IMAGE=registry.example/omapkg-builder@sha256:...
export SYSTEM_IMAGE_REPRO_BOOT_BASE_IMAGE="$SYSTEM_IMAGE_REPRO_BOOT_BUILDER_IMAGE"
export SYSTEM_IMAGE_REPRO_BOOT_TOOL_METADATA=/tmp/omapkg-image-toolchain.json
system-images/reproducibility/prepare-tool-image.sh
export SYSTEM_IMAGE_REPRO_BOOT_BUILDER_IMAGE=localhost/omapkg-image-tools@sha256:...
pkgdir=$(mktemp -d)
system-images/reproducibility/run.sh --fetch-real-packages "$pkgdir"
SYSTEM_IMAGE_REPRO_REAL_PACKAGE_DIR="$pkgdir" \
  system-images/reproducibility/run.sh --filesystem-fixture
```

`prepare-tool-image.sh` installs exact `qemu-img`, `gptfdisk`, and `dosfstools`
inside a disposable digest-identified fixture image; no host tools or host
libraries are mounted into the build. Use the exact manifest reference emitted
by the script; its tagless `repo@sha256` form is intentional. The filesystem-controls mode needs
rootful loop/filesystem capacity; rootless Docker is reported as incomplete. It runs
the same production `scripts/build-system-image.sh` twice through the shared
Go comparator. With `SYSTEM_IMAGE_REPRO_REAL_PACKAGE_DIR`, it uses actual
kernel, grub, firmware, and dependency packages plus the builder's real
`arch-chroot`/grub path. Without that variable it uses a clearly labelled
filesystem-controls shim fixture and cannot establish real bootloader
reproducibility. `scripts/boot-system-image.sh` remains the separate native
KVM boot check.

Public manifest mode uses `SYSTEM_IMAGE_REPRO_MANIFEST` instead and may set
`SYSTEM_IMAGE_REPRO_SIGNATURE`, `SYSTEM_IMAGE_REPRO_RELEASE_LOCK`, and
`SYSTEM_IMAGE_REPRO_CLIENT`. The harness never imports or publishes these
outputs. It returns `0` only when every requested pair passes, `1` for a build
or byte mismatch, and `3` when native tools, root privileges, profile inputs,
or immutable locks are unavailable. Missing prerequisites are incomplete, not
skipped successes.

The boot/filesystem check compares image-build payloads and provenance only. It
does not run `scripts/boot-system-image.sh`; boot acceptance is a separate
native KVM observation requiring a matching host, `/dev/kvm`, firmware, and
QEMU. An aarch64 pair must run on an aarch64 host through the existing native
workflow; x86 emulation cannot establish ARM acceptance.
