# Versioned system images

This directory defines installable VM images for the two required native
platform profiles. An image is a derivative of one exact resolved release
transaction. It is not allowed to resolve a live channel, AUR, ALARM, or an
upstream mirror while building.

`profiles/x86_64-uefi.json` and `profiles/aarch64-uefi.json` are reviewed
inputs. Each profile names its architecture, kernel, initramfs, GRUB target,
UEFI firmware, disk layout, and native KVM qualification requirements.

## Release lock

The release service supplies a local lock after it has verified the signed
system and OPR manifests. The builder accepts only this shape:

```json
{
  "schemaVersion": 1,
  "systemManifest": {"path": "system.json", "sha256": "...", "version": "4.0.3"},
  "oprManifest": {"path": "opr.json", "sha256": "...", "generation": "opr-17"},
  "packageSetSha256": "...",
  "packages": [
    {
      "name": "linux",
      "version": "6.12.1-1",
      "architecture": "x86_64",
      "repository": "core",
      "filename": "linux-6.12.1-1-x86_64.pkg.tar.zst",
      "url": "https://packages.example/repo/linux-6.12.1-1-x86_64.pkg.tar.zst",
      "signatureUrl": "https://packages.example/repo/linux-6.12.1-1-x86_64.pkg.tar.zst.sig",
      "sha256": "...",
      "install": true
    }
  ],
  "sourceDateEpoch": 1780000000
}
```

`sha256` for each manifest is the digest of its canonical compact JSON bytes
(object keys sorted recursively). `packageSetSha256` is the digest of the
canonical compact `packages` array sorted by `name`, `architecture`,
`version`, and `sha256`. The lock also retains the exact signed repository
database bytes selected by the transaction. The profile's `installPackages`
names are roots; pacman resolves their complete dependency closure against
those retained databases and the builder maps every selected archive back to
an exact lock digest. This avoids installing unrelated core/extra
alternatives. The package list must contain every package needed by the
resolved closure, including kernel, bootloader, and the firmware package. The
builder downloads each
archive and detached signature from its exact HTTPS URL, checks the archive
digest, and lets pacman enforce its configured required signature policy.

The lock must be generated and reverified by the existing manifest client in
the same invocation. A caller-supplied lock is only an optional byte-for-byte
expectation; it cannot become release authority by carrying an `authority`
field. The client verifies the signed transaction, system and OPR manifests,
and every package chunk under the pinned OpenPGP key before the builder reads
package hashes.

Check a release transaction without root or image tools (the URL and key are
the trust boundary):

```sh
scripts/build-system-image.sh --check \
  --manifest https://packages.example/repo/transactions/stable/tx-4.0.3/manifest.json \
  --key /etc/omarchy/omapkg-release-key.asc \
  --fingerprint "$OMARCHY_RELEASE_FINGERPRINT" \
  --profile system-images/profiles/x86_64-uefi.json
```

Build a raw UEFI disk on a native host. The command requires root because it
creates a loop device, filesystems, and an offline pacman root. It refuses to
replace an existing output unless `--overwrite` is explicit:

```sh
sudo scripts/build-system-image.sh \
  --manifest https://packages.example/repo/transactions/stable/tx-4.0.3/manifest.json \
  --key /etc/omarchy/omapkg-release-key.asc \
  --fingerprint "$OMARCHY_RELEASE_FINGERPRINT" \
  --profile system-images/profiles/x86_64-uefi.json \
  --output /srv/images/omarchy-4.0.3-x86_64-uefi.raw \
  --provenance /srv/images/omarchy-4.0.3-x86_64-uefi.provenance.json
```

The provenance record contains the system and OPR manifest digests, package
set and package digests, profile and recipe digests, source date, kernel,
bootloader, firmware, image digest, and native target. It is emitted only
after the disk has been detached and hashed.

## Native UEFI qualification

Run boot qualification only on a matching native machine. `boot-system-image.sh`
rejects a different host architecture, missing `/dev/kvm`, TCG/emulation, a
pre-existing variable file, or a non-empty output log. It copies the profile's
UEFI variable template to a fresh temporary file, boots a copy of the image,
and records the serial marker in a small JSON evidence file. A passing ARM
test therefore needs a native `aarch64` host with `qemu-system-aarch64` and
KVM; an x86 host running an ARM emulator is not an ARM qualification.

```sh
sudo scripts/boot-system-image.sh \
  --profile system-images/profiles/x86_64-uefi.json \
  --image /srv/images/omarchy-4.0.3-x86_64-uefi.raw \
  --provenance /srv/images/omarchy-4.0.3-x86_64-uefi.provenance.json \
  --evidence /srv/images/omarchy-4.0.3-x86_64-uefi.boot.json
```

This boot runner is a host-side wrapper around the existing reviewed worker
qualification CLI. A coordinator plan should bind its `profile.sha256` to the
same profile file, its candidate/artifact/input digests to the release lock,
and its `boot-state` observation to the evidence JSON emitted here.

No command in this directory installs a package on the invoking host, changes
host boot configuration, or imports an image. Operators must separately review
firmware licensing, hardware coverage, and package/repository signatures before
publishing a release image.
