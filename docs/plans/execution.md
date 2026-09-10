# Distribution plan execution

Baseline: `af76fec7397b8f8293175485d55271a765592670` on `fer/arch-repository-plan`.
Specification: [approved plan](arch-repository-ownership.md).

This ledger records implementation and acceptance separately. A checked-in
feature is not evidence of full catalog coverage, native hardware acceptance,
human release approval, or production cutover.

| Phase | Implementation | Acceptance |
| --- | --- | --- |
| 0. Preserve security baseline | Existing main implementation retained | 54 focused application tests, 9 signer tests and worker Go suite passed before implementation; rerun after relevant changes. |
| 1. Catalog and UI contracts | Immutable catalog policies, independent reviews, output identity registry, system/OPR classification and first maintainer views implemented | Ownership/concurrency tests pass. Broader consumer/release/admin journeys remain in progress. |
| 2. Import and OPR replacement admission | Arch/Omarchy/existing-OPR capture workflow, resumable uploads, reconciliation UI and shared dependency proposals implemented | Local browser reconciliation passed with real inventories; full recipe import/admission and production workflow acceptance still pending. |
| 3. Native workers, owned inputs and ABI cohorts | Immutable cohort scope, phase/event history, generated changelogs, native matrix and maintainer workbench implemented; multi-output native workers and private signing implemented; owned locks, ABI closure and native cohort checks remain in progress | Phase/admission/native omission, idempotency, stale narrative and publication-fence checks pass. Full native cohort acceptance remains pending. |
| 4. Versioned system and independent OPR releases | Pending | Pending |
| 5. Consumer/client integration and recovery | Pending | Pending |
| 6. Full catalog rebuild and shadow operation | Pending | Pending |
| 7. Human-approved cutover | Pending | Pending |

Required invariants: system versions such as `4.0.3`; independent OPR releases;
human admission of AUR/ALARM replacements; both native architectures; complete
dependency/ABI cohorts; generated phase and cohort changelogs; reviewed release
evidence; consumer, maintainer and admin usability/accessibility acceptance.

Live import/rebuild coverage and operator decisions will be recorded here when
measured. Existing rollout records remain in `docs/discussion-resolution.md`.

## Import and admission evidence

- Application checks passed with no Svelte errors/warnings. The pipeline bundle
  built successfully with the new import workflow.
- 220 application tests passed, including immutable capture/index sealing,
  partial upload/retry, missing/extra/version/architecture comparisons, role
  checks, shared proposal admission and collision-safe catalog review.
- Worker Go checks passed after accepting case-sensitive virtual ALPM
  capabilities such as the real catalog's `KSMBD-MODULE`.
- Native capture tool parser self-check passed. Real metadata validated through
  the same server parser: Omarchy stable 15,660 records; Arch upstream 15,744
  records; existing OPR 3 records (1 x86, 2 ARM). These are captured repository
  records, not newly admitted or rebuilt packages.
- Local browser flow at `/maintain/imports` and `/maintain/imports/[id]` completed
  comparison using those first two captures. Within core/extra/multilib it
  initially reported 3 missing, 315 extra and 422 version differences. That
  first report included ARM reference entries as extras; the corrected comparison
  separates new ARM qualification from existing baseline matching. Omarchy's
  three ARM endpoints were unavailable, which is informational rather than a
  prerequisite for our own ARM support. The selected ALARM extra reference database had
  invalid NUL-filled `findnewest` metadata; it remains an explicit source gap.
- Browser containment passed at 320, 375, 414, 768, 1440 and 1920px. The preview
  uses labelled local test identities and real public capture data; it is not a
  production rollout or a human package-admission decision.

Import status separates metadata capture, ownership review, replacement work,
matching native build evidence and immutable baseline comparison. Neither a
successful upload nor an empty difference filter marks a migration complete.

Remaining import work includes qualified source/recipe mapping, operator review,
owned rebuilds for all required outputs, production capture workflow checks,
and coordinated release readiness. Full-plan completion is unproven.

User clarifications implemented: absent Omarchy ARM baselines become new-target
qualification notes, not import blockers; our own required ARM builds and system
tests remain gates. Import jobs, reconciliation and uploads are maintainer-only,
including `/api/maintain/imports`. Public repository status is a separate
view of published releases, not import progress. Existing OPR capture also queries
recipe-only releases separately so pacman database coverage cannot hide Surface B.

Current comparison implementation keeps full package metadata in SQLite and
streams bounded difference pages through the Worker. A 15,432-record Omarchy
stable x86 baseline versus 15,433 Arch x86 records reports 3 missing, 4 extra and
422 version differences. New ARM reference/qualification work is shown separately
and does not block comparison merely because Omarchy lacks an ARM repository.

## Cohort and publication workbench evidence

- `/maintain/cohorts` creates an enumerated draft from catalog search. Scope
  changes pin exact policy/recipe digests, create new revisions and restart phase
  review. Cross-area edits require access to every member area. System and
  independent OPR lanes use different version fields and admission rules.
- `/maintain/cohorts/[id]` presents Overview, Changes, Phases, Tests and History.
  Phase and condition remain separate. Catalog/recipe authority, current inputs,
  unresolved blockers, both required targets and signed native build evidence
  are checked on the server, with database fences on transitions. The verification
  phase still blocks on the owned-input, ABI, reproduction and system-test work
  that has not yet been implemented or measured.
- Generated JSON and Markdown changelogs derive from immutable scope and a
  digest-linked event history. They identify their comparison baseline and
  planned/built/published state. Prose edits preserve build inputs, change the
  changelog digest and require human review. A phase or scope change makes older
  facts stale; repeating the same event or review does not duplicate history.
- Cohort recipe ownership prevents the legacy per-build publisher from shipping
  a partial cohort. After an eventual authorized switch to owned mode, database
  guards also disable legacy release/channel/snapshot writers. The mode remains
  `shadow`; this is not a cutover. The new distribution contract requires explicit
  release team membership separate from package and administrator authority;
  existing OPR publication retains its verified legacy policy during shadow work.
  No production membership was granted.
- Browser checks used labelled local test identities and drafts, exercised
  blocked cohort creation, generated narrative editing/review and downloads,
  and passed all five cohort sections at 320, 375, 414, 768, 1440 and 1920 pixels.
  Anonymous requests to private imports (including the real POST endpoint) and
  cohorts returned 401. These are application behavior checks, not human
  production approval or native package/release qualification.
- `/repository` now shows public legacy OPR publication counts and active database
  availability for each architecture/channel. It reads publication records only,
  distinguishes binary and recipe-only releases, and checks database/signature
  availability without claiming cryptographic or whole-system qualification.
  System distribution manifests will join this view when that engine is ready.
- Workspace navigation now groups Inbox, Catalog, Cohorts, Releases, Operations
  and Audit; import and worker/image/team deep links remain accessible within
  their sections.
- The complete application suite now passes 225 tests; Svelte and pipeline
  type checks report no errors. Native lease tests cover held and unreviewed
  cohort scope as well as both-target omission gates.

Additional fresh metadata captures passed the server parser and exact index
digest check: Omarchy RC 15,658 records; Omarchy edge 15,774 records, including
115 existing ARM package records; existing OPR 4 records, including one
recipe-only release. RC ARM repositories were absent; edge ARM core/extra were
absent, while its package repository existed. Existing ARM records remain real
reconciliation inputs. Absent external ARM repositories remain new-target
qualification, not a prerequisite for our own support. Comparisons now name
their repository scope and show captured baseline repositories outside it, so
an Arch core/extra comparison cannot imply that omitted Omarchy packages match.
The three fresh captures were also uploaded and sealed through the real local
maintainer API. Browser comparisons against stable, RC and edge passed. Within
core/extra/multilib, stable and RC each show 3 missing, 4 extra and 422 version
differences against the captured Arch input; edge shows 0 missing, 0 extra and
2 version differences. Omarchy package records outside that comparison remain
explicitly visible (228 stable x86; 226 RC x86; 226 edge x86 plus 115 edge ARM).
Both application and pipeline production bundles built successfully.

Full-plan completion remains unproven. Required remaining work includes full
recipe/source import and review, native owned inputs and multi-output execution,
full dependency/ABI planning, independently reproduced critical builds, signed
system/OPR/transaction manifests and activation, client/Omarchy integration,
native boot/upgrade/recovery qualification, full-catalog rebuild coverage,
operational capacity and human workflow/release/cutover acceptance.

## Native output protocol

Managed binary cohorts now lease an explicit v2 output contract. It binds the
cohort revision, package identities, full versions, artifact architectures and
native installation groups. Workers without the capability cannot claim that
work. V1 jobs and historical v1 verification retain their existing contract.

Each output gets an immutable artifact record under its build attempt. Both
direct and multipart uploads enforce the expected set; unique upload storage
keys isolate concurrent writers. Identical retries reuse the winning artifact
reference. Attempt inputs and terminal results are retained independently of the
mutable queue row, including the worker key and exact signed report.

The native runner reads each artifact's actual `.PKGINFO`, checks its pkgbase,
name, full version and architecture, then runs namcap and installation/smoke
checks for every reviewed group. Conflicting split variants can use separate
groups; every output must be covered. Mixed native/`any` outputs are supported.
Portable outputs reject detected native code and carry a payload comparison
hash; cohort qualification compares that hash across required native targets.
The hash excludes `.BUILDINFO` and `.MTREE`, while the exact artifact hash still
binds those build-specific bytes.

The real captured Arch inventory contains 806 split bases. The largest captured
base, `tesseract-data`, has 129 outputs; `vim`/`gvim` and other split alternatives
have conflicting installation requirements. Output/admission validation now
allows up to 256 outputs and explicit, reviewed installation groups instead of
assuming every split result can be installed together. Transfer and evidence
limits remain explicit; this does not establish measured capacity for every
large package.

Native x86 validation passed with four split outputs, an epoch and fractional
pkgrel, a portable documentation package, a sibling dependency and two conflicting
variants installed in separate groups. The prior single-output GNU Hello native
isolation/runtime regression also passed. Application tests cover incomplete or
changed output sets, missing group tests, native code in an `any` output, stale
attempts, immutable evidence, private downloads and concurrent uploads. The full
application suite passes 227 tests; web and pipeline production builds pass.

The maintainer catalog form exposes portable outputs and installation groups;
the build page shows expected/uploaded outputs and private artifact downloads.
Fresh ARM regression, browser acceptance of these additions and central v2
release signing/independent verification remain separate acceptance work. The
ARM regression workflow can now pull retained pinned images without rebuilding
or publishing images.

Owned dependency/base/runtime locks are still pending. These successful native
regressions use the preserved shadow builder/runtime inputs; they are not proof
of owned-only inputs, full-catalog qualification or readiness to publish a system
release. Phase verification continues to block on that missing evidence.

Fresh native ARM regression passed on commit
`2654e74eacc6dcde401b7eaaa18950b178c2ba8a`:
[run 34408439651](https://github.com/ferrreo/omapkg/actions/runs/34408439651).
It pulled the previously retained builder/runtime digests, skipped image building
and publication, and ran both the new split-output/group test and the existing
native isolation/runtime test. The dedicated temporary pull-only Actions secret
was deleted after completion. This closes the native protocol regression check;
it does not qualify those shadow images as owned inputs.


## Private native signing and independent verification

Native v2 output signatures now bind a registered artifact and immutable build
attempt. The central signer and offline verifier validate the complete output
set, native installation groups, portable-output inspection, embedded worker
signature and resolved shadow inputs. One in-toto statement covers every split
output. Epochs, fractional package releases and valid output names containing
`@` remain intact through signing and download.

Current cohort/catalog/recipe scope, independent active reviewers and worker
identity are rechecked before signing. Database guards prevent changed review
or attempt state from becoming a recorded native signature. Historical v1
statements retain their original verifier and publication path. V2 artifacts and
statements stay private; no repository membership is created by signing. The
v2 build type explicitly identifies its current inputs as `shadow`, and the
offline verifier rejects an unsupported claim that those inputs are owned.

The build page exposes private output signatures and the complete signed build
statement. Browser checks used labelled local fixture packages, passed at
320/375/414/768/1440/1920 pixels and downloaded each private evidence object.
Anonymous access returned 401. The local preview requires the bundled Node
runtime for Miniflare stream transfer; Bun's Node shim failed artifact downloads.
This was a preview runtime issue, resolved without changing streaming downloads.

Validation passed: 227 application tests plus the new isolated native signing
regression (228 together), 10 signer tests, Svelte/pipeline/signer type checks,
and web/pipeline/signer production bundles. Signer tests verify real OpenPGP
signatures and reject re-signed incomplete subjects, changed attempts, missing
resolved inputs, forged owned-input classification and native code in portable
outputs. These tests do not establish production release approval, owned input
qualification or full-catalog rebuild coverage.

## Frozen input preparation

The worker has a separate frozen-input path with paged package locks, retained
OCI tooling, per-package signature/key checks and independent roots created from
an empty filesystem. Preparation, compilation and runtime tests disable
networking. Evidence records complete inventories and native host details.

Fresh x86 validation captured 215 build packages and 108 runtime packages from
Arch upstream, retaining package/signature/key bytes and a 467,622,912-byte
helper archive. A native program and an `any` documentation package built,
installed and passed smoke checks in the separate runtime root, without
build-only `gcc` or `make`. Repeated runs on this same host produced identical
output hashes; this is not independent-worker reproduction. The native test
also rejected another retained package's signing key. Go tests, `go vet`, ARM
cross-compilation and the capture parser check pass.

Validation corrected two details: capture reads exact archive sizes from retained
databases because pacman reports remaining download size for cached packages;
capture/worker verify the actual retained OCI manifest because export can change
its digest. Initial root creation checks dependencies/file conflicts, then a
fresh installation inside its own OCI container runs package scripts/hooks with
working `/proc` and `/dev`.

[The input contract](../frozen-build-inputs.md) records limits and acceptance.
At the worker checkpoint, registration/review UI, lease freezing and
central/offline verification were still pending; those integrations follow below.
These captures and native runs are local bootstrap validation, not production
approval or owned-only release qualification. Full-plan completion is unproven.

## Frozen input authority and coordinator acceptance

Migration 0035 retains verified input objects and bounded canonical documents,
immutable lock indexes, independent human reviews, selected build inputs and
native package origins. Every attempt freezes its lock digest. Review or origin
revocation fences affected active leases, including their input ancestry; a
selected job cannot fall back to live repositories. Native package origins retain
their original reviewed attempt when newer recipe/build attempts are proposed.

Maintainers can upload a capture folder, inspect source records, keys and exact
environment inventories, review/select a lock, sign completed native outputs,
retain them as private inputs and assemble an owned lock of matching package
versions. Different archive hashes require an explicit artifact choice. New locks
require independent review; classification or selection does not bypass cohort
ABI/reproducibility/release gates. Import and input pages remain private.

Real local acceptance on 2026-09-10 uploaded 459 objects (766,521,848 bytes)
through the browser, including the retained OCI helper. Separate explicitly
labelled local test identities reviewed and selected the lock. A real x86_64
daemon claimed it, fetched retained objects with signed lease requests, prepared
215 build packages and 108 runtime packages offline, built both fixture outputs,
passed native installation checks and completed through the coordinator in
59 seconds. Both archive hashes matched earlier same-host runs:

- `opr-frozen-docs-1.0-1-any.pkg.tar.zst`:
  `84b607dda35e0e280fe33765da5a3a6465ee4b107ee538b5fabb14cd12af2fb7`
- `opr-frozen-native-1.0-1-x86_64.pkg.tar.zst`:
  `8bd2cec0a1d67d0619e42fca4db64ead0f940918d3992eae074d7498a9e50bb2`

An ephemeral local signer signed both actual packages and the build statement.
GnuPG verified both package signatures; the offline statement verifier verified
both subjects and the `bootstrap` classification. Both outputs entered the
private native input registry. This used the existing HTTP signer transport;
temporary preview configuration was restored and the test signer stopped.
No production admission, signing key, repository membership or cutover changed.

Browser checks passed at 320/375/414/768/1440/1920 pixels, including resumable
uploads, review/selection, private downloads and anonymous access denial. Live
acceptance found and fixed a missing binary `Content-Type` and D1's expression
depth limit of 100. A runnable check now compiles 30 native queries at that limit.
Batch document/index operations avoid one storage request or insert per package.

Validation: 230 application tests, 12 signer tests, Svelte/pipeline/signer type
checks, Go tests/vet and ARM cross-compilation. Tests cover bootstrap relabelling,
missing native providers, immutable attempts, ancestor revocation, distinct
reviewers, stale leases, complete signatures and offline evidence substitution.
Native ARM execution, independent reproduction, full source/catalog and ABI
qualification, release/client integration and human cutover remain open.

## Preserved recipe capture and atomic Git writes

Migration 0036 adds immutable recipe captures and inventory mapping records.
The private import UI uploads original Git directories, verifies their retained
commit/tree/blob proof and exposes exact files, package metadata differences,
missing inspection and AUR/ALARM admission work. Captures grant no recipe,
catalog or release approval. See [preserved recipe captures](../preserved-recipes.md).

The exact captured Omarchy repository commit
`a44e2d2e49d01faa4d351e047bfa5632c2c21b1b` contains 131 recipe directories,
477 retained files and 2,060,963 bytes. Every directory passed independent
server-side proof verification. All 131 lack `.SRCINFO`; 77 identify AUR origin
in retained Omarchy metadata. Those are inspection/admission requirements,
not qualified owned packages. This does not imply that all captured binary
packages have been mapped to those source directories.

The real local browser uploaded the original `1password` directory into local
D1/R2, retained install-script bytes exactly, rejected out-of-capture downloads
and anonymous access, and passed viewport checks at 320, 375, 414, 768, 1440 and
1920 pixels. This used a labelled local test identity, not production approval.

Generated recipes now carry an immutable catalog path in review evidence. Git
publication writes complete recipe directories in one tree commit with a
non-forced ref update; byte substitution, stale parents, no-op retries and
multiple coupled directories have runnable checks. Integrity checks and public
recipe links share the recorded path. Preserved recipe adaptation, sandbox
inspection, source archive preparation and full catalog qualification remained
required before this capture evidence can become executable owned recipes.

Validation passed: 235 application tests, Svelte checks with zero errors or
warnings, pipeline TypeScript, production web build, the Python capture
self-check, and the real browser upload/download flow described above.

## Native source metadata inspection

Migration 0037 adds a separate inspection queue with immutable worker attempts,
signed reports, private source grants and live source/image/worker authority
checks. Revocation fences leases. Workers verify the original Git directory and
evaluate metadata in a native, unprivileged container with networking disabled
and read-only recipe/root mounts. Successful inspection supplies source metadata
for human review; it creates no package approval, build or release.

All 131 original Omarchy recipe captures are now retained in local D1/R2 and
linked to 489 captured source/snapshot records. The `yaru-icon-theme` directory
correctly maps to package base `yaru`. The 54 captures without AUR admission
requirements passed real native x86 inspection through the authenticated local
coordinator and compiled Go worker. The other 77 remain unexecuted pending human
source admission. The first `1password` attempt exposed makepkg's writable
destination check; its signed failure remains retained, followed by a successful
retry using temporary destinations. Original recipe bytes remain unchanged.

The real browser verified signed success/failure downloads, exact original file
downloads, private access and import comparison labels. Viewports at 320, 375,
414, 768, 1440 and 1920 pixels passed. A separate native Git fixture checks
non-root execution, network and filesystem isolation, executable files,
symlinks and signed protocol completion. These local checks use labelled test
identities and do not grant production admission.

Validation passed: 235 application tests with 1,510 assertions, 12 signer tests,
Go tests and vet, ARM cross-compilation, Svelte checks with zero errors/warnings,
pipeline TypeScript, production web build, and 40 native D1 queries at expression
depth 100.

[Native ARM run 34431242722](https://github.com/ferrreo/omapkg/actions/runs/34431242722)
passed on exact code commit `14c228be7f0b7eaed005077ba98edb7a341a7e33` using
`ubuntu-24.04-arm` and retained builder/runtime image digests. The new inspection
fixture ran on aarch64 Linux `6.17.0-1022-azure`, Docker `28.0.4`, Go `1.22.12`;
its native report signature independently verified. Existing native build,
split-output and isolation regressions also passed. The dedicated pull-only
registry credential was removed after the run; no images were republished.
This verifies the inspection worker on ARM, not every imported recipe's ARM
support or a production coordinator rollout.

Preserved recipe adaptation, source archive/VCS/language-cache preparation,
full inventory qualification, ABI cohorts, release/client integration and
cutover remain open.

The shared build helper now keeps temporary configuration under its output
directory. Previously a reviewed source named `makepkg.conf` was overwritten
before makepkg checked source hashes. The native split-output regression now
uses that filename: it reproduced the checksum failure before the fix, then
built and tested all four outputs successfully afterward. Go tests and vet
also passed.

## Preserved recipe source preparation

Signed native inspections now export private, architecture-specific source plans.
They preserve full versions, local-file precedence, aliases, checksum arrays, Git
refs and source signing keys. The offline capture tool retains HTTPS downloads,
bare Git mirrors and explicitly prepared language caches/public keys without
executing recipe shell. Immutable source bundles are uploaded through the existing
resumable object protocol and checked against the current signed inspection.
Source preparation creates no recipe approval or build.

Measured local scope: 54 current x86 inspections yielded 51 usable source plans.
Three captured recipes (`hyprland`, `hyprland-guiutils`, `hyprtoolkit`) declared
ARM-only outputs and correctly blocked x86 source preparation. This is a source
mapping difference, not evidence of x86 or ARM build coverage.

Real capture retained the `asdcontrol` HTTPS archive and local recipe inputs,
`omarchy-audio-tuner` Git tag, and the resolved `omarchy-dev` branch. Native x86
makepkg source verification/extraction passed for the first two with networking
disabled and original recipe files mounted read-only. Git source directories must
be owned by the container build user; using Podman's matching user namespace
resolved the initial manual harness ownership error. These checks are source
preparation acceptance, not package builds or a full worker/coordinator run.

Browser acceptance uploaded both source bundles, downloaded manifests matching
the retained hashes, checked stale-attempt rejection and denied anonymous access.
Layouts passed at 320, 375, 414, 768, 1440 and 1920px. The complete application suite
passes 235 tests (1,532 assertions); Svelte and pipeline checks and production web
build pass. Source capture's runnable parser/archive self-check passes, including
unsafe paths and escaping cache links. The new source authority view executes
within D1's expression-depth limit.

Preserved revision/PR creation, full source-tree materialization in native workers,
source-aware signing, per-target source/caches for the complete catalog and the
remaining release/client/ABI/system/cutover phases are still in progress. None of
these captures constitutes production admission, source signature approval or
full-plan completion.

### Preserved revision review path

Original captures can now become immutable review revisions without recipe
rendering. Every admitted target needs a current source bundle backed by signed
native inspection. The draft binds original files and Git modes, exact full
version, target dependencies, retained sources, smoke commands and commit source
time. Git review sidecars use a separate collision-checked directory. The complete
canonical package subtree is checked for missing/extra files, mode changes and
raw-byte SHA-256 mismatches, including auxiliary hooks, symlinks and binary patches.

Import reserves the exact draft, records upload failures, resumes its existing Git
branch and allows cancellation. Model generation cannot overwrite imported
requests or forge preservation evidence. Source/catalog/worker authority changes
block persistence and approval; persistence now atomically checks the generation
before inserting a revision. Old workers cannot claim preserved revisions.

Local acceptance used actual captured asdcontrol bytes and its earlier signed
native x86 inspection. Browser tests exercised missing ARM sources, saved draft
retention when GitHub credentials are absent, identical retry, cancellation,
anonymous denial and 320–1920 px layouts without JavaScript errors. Local-only
catalog reviews and an explicit test architecture exception enabled this UI
exercise; all resulting upload reservations were cancelled. Nothing was admitted,
merged, approved for build or published in production. Protocol tests independently
covered two target inspections, full-version preservation, original auxiliary
bytes/modes, failed-upload recovery, exact revision persistence and source revocation.

Native worker materialization, source-bound leases and signing/verifier integration
remain required before a preserved build can complete. Full-catalog source capture,
native target qualification and production migration also remain open.

Validation for this slice: 237 application tests / 1,600 assertions, clean Svelte
and pipeline type checks, production web build, and the source/import authority
source/import views with a 40-level expression test budget. Mobile review history is collapsed so failed or
cancelled attempts do not obscure current prerequisites. The local asdcontrol
catalog was restored to both primary targets after browser validation.

### Preserved native source execution

Preserved jobs now carry the reviewed capture and per-target source-bundle roots
through authenticated delivery, immutable attempts, native worker signatures,
private signing control, central statements and offline verification. Workers
require frozen dependency inputs and the complete native output contract. Original
files and Git modes are verified and mounted read-only; retained mirrors, source
files, caches and public keys are staged separately. Makepkg checks original
source hashes/signatures and runs with `--holdver` after native metadata matches
the signed inspection. Source archives reject traversal, special files, duplicate
paths, escaping links and false size/entry budgets. Repeated source references
count toward disk limits, and local reads/copies honor cancellation.

Runtime and make/check relations stay target-specific, including native SONAMEs.
Sibling outputs and their declared provides satisfy runtime requirements in the
complete installation transaction; explicit build/check requirements still need
installed providers. Source authority changes permanently fence active tokens,
including role, catalog, inspection, helper-image and worker changes. Restored
authority permits a fresh attempt, with previous attempt references retained.

Native x86 acceptance built original `asdcontrol` at `1:0.6.0-2` from its HTTPS
archive and captured sudoers file, and original Git-tag-based
`omarchy-audio-tuner` at `0.1.0-1` as an `any` package. Both passed offline build,
runtime analysis, installation and smoke commands with frozen package inventories.
A separate native fixture passed signed Git-tag verification, detached source PGP
verification, patch application, retained executable/symlink handling, Go/Cargo/npm
cache mounts and split native/portable output installation. Cache-mount acceptance
does not claim actual Go/Cargo/npm dependency completeness. Native negative runs
rejected a substituted Git commit, a secret key and changed inspection metadata
before producing packages.

The complete local coordinator run used actual retained asdcontrol input bytes,
browser upload and two labelled local review identities, then a registered daemon
to claim, download, build, upload and complete. An isolated signer signed the
package and native statement over the real control endpoints. The independent
offline verifier accepted both input roots and the complete statement; isolated
GnuPG verified the package's detached signature. The resulting archive SHA-256
`5eef999d986c4440bb48e15e923a7283751af8289d6eb2fa4eee8642775b3af8`
also matches the earlier component run byte-for-byte.

These are local acceptance records. Git review was explicitly seeded locally;
no external recipe PR was merged, no production admission/build approval was
created, and nothing was published. The temporary local architecture exception
was removed, both catalog targets restored, the test worker paused, and preview
configuration restored. Native ARM qualification and full-catalog preparation
remain open.

Build pages now link the exact original capture and native source bundle and show
native failure reasons. Browser checks passed at 320, 375, 414, 768, 1440 and
1920px with no JavaScript errors; anonymous private-input access was denied.
Validation: 237 application tests / 1,653 assertions, 13 signer tests / 100
assertions, Go worker tests, clean Svelte/pipeline/signer type checks, production
web build, and native SQL compilation at the runtime's 100-level expression limit.
The latter uses `tests/check-d1-depth.py`; Cloudflare's current
[SQLite runtime configuration](https://github.com/cloudflare/workerd/blob/main/src/workerd/util/sqlite.c%2B%2B)
sets that limit to 100. A separate stricter 40-level exploratory check is not the
platform limit.

Full-catalog source retention, reviewed target adaptations, native ARM builds,
cohort closure/ABI/reproducibility and system qualification, release/client work
and controlled production migration remain required for the full plan.
