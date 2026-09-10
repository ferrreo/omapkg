# Preserved recipe captures

Recipe capture copies the exact files from an immutable Git directory. It never
sources PKGBUILD, runs install hooks, regenerates metadata, or invokes a model.
The maintainer import page accepts a capture folder and links it to the package
base in a sealed inventory. This records evidence; it does not admit, approve,
build, or publish a package.

Capture a locally fetched Git commit with:

```sh
python3 services/pipeline/capture-recipe.py \
  --git-directory /path/to/omarchy-pkgs \
  --repository https://github.com/omacom/omarchy-pkgs \
  --commit EXACT_40_CHARACTER_COMMIT \
  --directory pkgbuilds/PACKAGE_BASE \
  --pkgbase PACKAGE_BASE --origin omarchy --output /path/to/new-capture
```

Choose that folder under **Imports → captured inventory → Preserve original
recipe files**. Uploads resume through the existing private input object store.
Empty files are represented by the SHA-256 of empty bytes. They need no upload.
Original paths may contain spaces or Unicode; absolute paths, traversal, control
characters, backslashes and `.git` path components are rejected.

The canonical root records repository attribution, commit, original directory,
package base, file paths, Git modes and SHA-256 object references. It retains the
raw Git commit and the ancestor/directory trees needed to prove complete directory
membership. The server verifies SHA-256 storage identities, Git object hashes,
every original file and mode, and symlink containment. Missing files, extra files,
submodules, changed modes, substituted blobs and incomplete proofs fail closed.
This proves consistency with the specified commit. Reviewers still check source
attribution and whether that commit belongs to the intended upstream repository.

Bounds are 2,048 files and 32 MiB of recipe content per directory, 512 trees and
4 MiB of Git proof, and a 512 KiB canonical root. PKGBUILD is limited to 2 MiB,
`.SRCINFO` to 1 MiB, and `.omarchy/package.json` to 64 KiB. Source archives and
language dependency bundles are separate build inputs, not recipe directory
content. A capture that exceeds a bound fails explicitly instead of dropping
files. Failed local captures may leave an incomplete output folder; retry with a
new folder. The server only registers a complete verified root.

Available `.SRCINFO` is parsed as data, preserving full versions, split outputs,
architecture fields and per-output overrides. Its package relations and version
are compared with captured package metadata. Generated soname differences remain
review work. Missing or malformed `.SRCINFO` stays visible as required sandbox
inspection; it cannot become a successful match. All original Omarchy metadata
is retained, including pins, channels, release rings and rebuild records.
Supported `rebuild_on` names are available as policy input. Upstream release
controls and `rebuilt_against` never grant local release or rebuild authority.
AUR/ALARM references require the normal human OPR admission path.

## Native metadata inspection

Choose an enabled digest-pinned image and request sandbox inspection from the
preserved recipe page. The worker verifies the complete retained Git proof before
materializing files with their original modes and symlinks. It runs
`makepkg --printsrcinfo` as UID/GID 65534, with networking disabled, all
capabilities dropped and both the container root and recipe mount read-only.
Temporary makepkg configuration and destinations live under `/tmp`. Metadata
evaluation has a one-minute limit inside a ten-minute worker lease. The signed
report retains native host/image identity, exact metadata, its checksum, bounded
stderr and any failure. Inspection does not invoke source fetching, package
building or installation.

The worker checks its compiled architecture, kernel, CPU family and OCI image
architecture. These checks detect ordinary architecture mismatches, including a
user-mode emulator changing `uname`; they are not hardware-rooted attestation.
Each report is signed by the registered worker key. The maintainer page compares
current native results against matching captured inventories, exposes raw files
and signed evidence, and retains earlier failed attempts for download.

The queue requires current system/security/admin membership and an enabled
image. AUR/ALARM references also require independently reviewed OPR source policy
binding the exact captured commit or the retained Omarchy upstream reference.
Every object read, heartbeat, registry grant and completion checks the live lease.
Changes to worker, image or source authority fence outstanding leases; restoring
authority cannot revive an old token. Successful inspection supplies metadata
evidence only. Source adaptation, recipe review, source/dependency retention,
native builds and release qualification remain separate required work.

Opt-in native regression uses the same existing builder-image variables as
worker tests, including `OPR_WORKER_E2E_ARCH=aarch64` on a native ARM host:

```sh
cd worker
OPR_WORKER_E2E_IMAGE=REGISTRY/BUILDER@sha256:DIGEST \
  go test -v -run TestRecipeInspectionPreservesGitBytesAndFencesUnsafeMaterialization
```

The regression executes an original Git fixture, checks filesystem and network
isolation from inside PKGBUILD, and verifies the worker's signed report through a
local protocol harness. Application tests separately exercise real D1 lease,
admission, revocation and private object routes.

New generated recipe paths are recorded inside immutable SBOM review evidence.
New unbound OPR recipes use `packages/omapkg/<pkgbase>`; bound catalog requests use
their collection. Historical recipe paths remain readable. The factory, Git
integrity checker and recipe links use the same resolver. Git writes create one
complete tree for every affected recipe directory, then one commit and a
non-forced branch update. Obsolete files disappear in the reviewable commit;
unrelated directories remain unchanged. Identical retries return the existing
commit. A branch change or mismatched PR head aborts the operation.

Git tree/ref behavior follows the [GitHub Git database API](https://docs.github.com/en/rest/git/trees#create-a-tree).
Version and field interpretation follows the [PKGBUILD manual](https://man.archlinux.org/man/PKGBUILD.5.en).

Checks:

```sh
python3 services/pipeline/capture-recipe.py --self-test
bun test tests/recipe-capture.test.ts tests/recipe-git.test.ts
```
