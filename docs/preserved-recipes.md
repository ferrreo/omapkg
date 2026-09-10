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

## Retained build sources

A successful, current native inspection exposes a source preparation plan on the
private recipe page. The plan binds the capture, exact signed inspection attempt,
native target and full package version. Architecture-specific source/checksum
arrays retain makepkg ordering. Local file precedence, aliases, archive filenames,
Git refs and source signing keys are explicit. Unsupported transports, missing
local files, duplicate destinations, short Git commit pins and incompatible output
architectures block preparation instead of being silently omitted.

Capture the exported plan without evaluating recipe shell:

```sh
python3 services/pipeline/capture-recipe-sources.py \
  --plan package-x86_64-sources.json --output /capture/package-sources
```

The tool follows bounded HTTPS redirects with public DNS addresses pinned through
TLS connections, checks declared file hashes and records SHA-256 identities for
all bytes. Git sources use a retained bare mirror, record the resolved commit and
preserve refs needed by makepkg. Git redirects, credentials, extra protocols,
submodule fetching and hooks are disabled during capture. Moving branches and
unsigned inputs remain explicit review evidence; retaining them grants no approval.
Git disk usage is polled and each file is bounded; a filesystem quota is required
when a strict host disk allocation is necessary.

Supply prepared language caches with `--cache go=/path/to/modcache`,
`--cache cargo=/path/to/cargo-home` or `--cache npm=/path/to/npm-cache`, and explicit
public signing keys with repeated `--key /path/to/public-key.asc`. Cache archives
preserve file modes and contained symlinks, normalize archive metadata and expand
hard links into regular files. Credential files and request logs must be removed
from a prepared cache. The tool rejects escaping links, special files and secret
keys. Source signature verification and cache completeness remain native build
gates; capture alone does not establish either.

Select the output folder under **Prepared build sources** to upload its objects
and retain the immutable manifest. The server reconstructs its source plan from
current signed inspection evidence, checks every required object and key reference,
and rejects stale inspection authority or changed inputs. Historical manifests
stay downloadable to maintainers. This operation creates no recipe approval,
cohort build, public source URL or publication record.

Current limits are 2 MiB per plan or bundle, 2,048 declared sources, 200,000 entries
per Git/cache archive, 32 GiB per retained object and 256 GiB total referenced
objects. The capture tool defaults to 4 GiB per object and 32 GiB per run and accepts
smaller or larger explicit limits within those ceilings. Empty source files use
the SHA-256 empty-object identity. Workers also count repeated references toward
the total budget because distinct materialized paths consume disk space.

## Original recipe revisions

After current catalog admission, select one retained source bundle for every
admitted native target and supply installed-package smoke commands on the recipe
page. The coordinator verifies the original Git proof again, checks native full
versions, split outputs and portable-output policy, and assembles a review draft
without evaluating or rendering PKGBUILD. Runtime, build and check dependencies
remain separate for each target. The source timestamp comes from the captured
Git commit. Epoch and fractional package release remain immutable review evidence.

Import reserves the exact draft before GitHub work starts. An upload failure keeps
that draft available under **Resume saved import**; cancellation closes the
unfinished request. A completed retry returns the existing review. The factory
cannot regenerate an imported request or substitute model-supplied preservation
evidence. Catalog, inspection, source and operator authority are checked again
before persistence. Revision insertion and the request transition commit together
only while the reserved generation remains current.

The pull request contains all original paths, byte contents, executable modes and
symlinks. Three review sidecars live under `.opr-review-<revision-id>/`; an existing
path at that location fails the import. Original `opr-manifest.json`, Omarchy
metadata, patches and install hooks remain untouched. Git integrity resolves the
package subtree before inspecting its complete inventory, checks file modes and
hashes streamed raw blob bytes, and detects extra files or directories. Truncated
GitHub tree listings fail verification. Raw blob access follows the
[GitHub blob API](https://docs.github.com/en/rest/git/blobs#get-a-blob).

Import creates no approval or build. Review still requires independent area and
security approval with explicit custom-shell acknowledgement. Preserved jobs are
excluded from workers without `preserved-recipe-v1`, a current cohort output
contract and selected frozen dependency inputs. Review and source retention do not
themselves establish a successful package build.

## Native preserved builds

Deploy migration `0040_preserved_build_inputs.sql` and the coordinator/signer
before deploying workers that advertise `preserved-recipe-v1`. These workers also
require `multi-output-v2`, `frozen-inputs-v1` and `runtime-analysis-v1`. Older workers
skip preserved jobs. A preserved job cannot fall back to live dependency planning.

Each lease and immutable attempt bind `preservedRecipe: {capture, sourceBundle}`
with complete SHA-256 and size references. Private object delivery grants only the
selected frozen lock, complete captured Git proof/tree, and selected source bundle
with its plan, files, mirrors, caches and public keys. Source, catalog, inspection,
image, operator or worker authority changes fence active tokens. Restoring authority
permits a fresh attempt; it never revives the previous lease.

The worker verifies every downloaded object and the complete original Git proof,
then mounts the captured recipe directory read-only. Source/cache tar extraction
enforces entry and expanded-size budgets, rejects traversal, hard links, devices,
duplicate paths and escaping symlinks, and creates links only after validation.
Local copying, hashing and archive reads honor cancellation. Regular file modes,
executables, contained links, install hooks and patches remain intact.

Builds run as an unprivileged user with network disabled. The worker validates
retained Git refs and object integrity, imports only the explicitly retained public
keys into a fresh GnuPG directory, and requires `makepkg --printsrcinfo` to match the
signed native inspection exactly. Makepkg then checks source hashes and signatures,
extracts sources, applies the original recipe's preparation steps, and builds with
`--holdver`. Git hooks and external protocols are disabled; local Git cloning is
allowed inside the sandbox. The original PKGBUILD cannot be updated by `pkgver()`;
a changed version needs a reviewed recipe adaptation.

Go, Cargo and npm caches have separate writable mounts and offline environment
settings. Missing cache contents fail the native build. npm accepts the uppercase
configuration variables used by the worker, as documented in its
[environment configuration](https://docs.npmjs.com/cli/using-npm/config/).
Explicit make/check dependencies must exist in the frozen build environment.
Runtime relations supplied by sibling outputs or their declared provides are
checked in the complete installation transaction. Native SONAME relations retain
ALPM syntax. Outputs must match the reviewed names, full versions and architectures;
portable outputs must contain no native code. Runtime analysis and maintainer smoke
commands run after installation in the separately frozen runtime environment.

The worker signature, native signing control, central statement and offline
verifier all bind the capture and source-bundle references. Statement dependencies
include both roots, which transitively identify every original and prepared byte.
The build page links these reviewed inputs. This remains private build evidence;
it does not qualify another architecture, approve an owned release or authorize
publication.
