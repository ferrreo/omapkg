# Owning the package distribution

## 01 · Decision and scope

**Extend omapkg into the release authority for the complete Arch core/extra catalog while preserving independent OPR package releases. Core/extra system releases use Omarchy versions such as `4.0.3`; OPR packages retain their own versions and release cadence. Import a verified baseline once; thereafter our team owns updates, packaging changes, rebuilds, signing, security response, and publication.** Track upstream Arch changes. AUR and Arch Linux ARM (ALARM) may inform source/porting proposals; they are not ongoing dependency or binary providers. Dependencies previously obtained there must become human-admitted OPR-managed packages or ARM variants through omapkg. Upstream publication never directly changes a user-visible repository after cutover.

Prepared 9 September 2026. **Status: proposed design; implementation and production readiness are not claimed.** “arch / arch-extra” was clarified by the requester to mean Arch Linux’s core/extra package collections. The requester also confirmed that Omarchy-style versioning applies to core/extra system releases, while OPR packages must still release independently. Here, OPR means the independently published additional-package catalog managed by omapkg; imported Omarchy repository packages can use this lane when they are outside the pinned/default-system set. Explicit release policy, not source repository name, selects the lane. Both `x86_64` and `aarch64` are mandatory primary targets. An existing Omarchy ARM repository is not a prerequisite: absent ARM baselines are informational new-target qualification work, while our own required ARM package coverage and native/system tests remain release gates. `--arch all` means every required target; Arch’s `arch=('any')` means architecture-independent package content. These are separate concepts.

This is distribution maintenance at full catalog scale. A pilot is a migration stage, not the final scope. Every imported package must have an accountable owner, update policy, architecture disposition, and retained source record. An unavailable ARM port, forbidden redistribution, or unbuildable package stays visible as a blocker or an explicitly approved exception. It must never disappear from the coverage denominator.

The design rests on seven rules:

1. **One publisher.** Old sync/build jobs lose write authority at cutover; upstream feeds only propose changes.
2. **One complete transaction lock.** A versioned system manifest plus a compatible OPR snapshot resolve to immutable repositories for every client transaction. System and OPR publication remain separate.
3. **Rebuild coupled packages together.** An ABI-changing provider and affected consumers form a build cohort, across repository boundaries.
4. **Promote tested bytes.** System progression is `edge → rc → stable`; OPR may promote an independently reviewed package/cohort from quarantine to stable. Changed inputs create new candidates in the relevant lane.
5. **Humans own authority.** Agents draft and investigate; deterministic checks enforce policy; maintainers approve admission and release.
6. **No AUR/ALARM fallback.** Missing coverage creates a linked OPR admission proposal; a human decides. Approval to package is separate from permission to build or publish.
7. **Evidence has limits.** Signed records authenticate inputs, execution claims, and release decisions. They do not prove software harmless or runtime discovery complete.

| Release lane | Unit and version | What can ship alone? |
| --- | --- | --- |
| System | Complete core/extra and profile-required base/Omarchy set, e.g. `4.0.3` | A tested system patch release; related packages move together. |
| OPR | One package or dependency/ABI cohort, using each package’s own version | Normal independent OPR updates, with their own changelog and compatible snapshot generation. No new Omarchy version is required. |

**Definition of done:** full inventory reconciled; existing security baseline preserved and its distribution extensions verified; all required outputs and architecture dispositions accounted for; native build/test capacity operational; ABI cohorts exercised; complete releases upgrade and recover correctly; signed changelogs/evidence publicly verifiable; legacy writers and external dependency fallbacks disabled; both architectures ship under the same release policy; every cohort has phase history and a generated, reviewed changelog; consumer, maintainer, and admin journeys pass usability and accessibility gates.

## 02 · What exists, and what must change

This revision is based on fetched `origin/main` at **`af76fec7397b8f8293175485d55271a765592670`**, eight commits after the original assessment (`9873d6f`). The worktree was rebased onto it on 9 September 2026. Omarchy package tooling remains referenced at `a44e2d2e49d01faa4d351e047bfa5632c2c21b1b`, and Omarchy at `5ead870507dfb68db696b3ddb948cc3d178e8d62`; those external snapshots were not refreshed as part of the main-branch rebase.

**The attached security discussion is now implemented in main.** Its deployment/native validation record is in [discussion resolution](../discussion-resolution.md), with the public evidence contract in [build type v1](../build-type-v1.md). Retain these foundations. Phase 0 becomes baseline qualification and migration-contract work, not reimplementation of the completed security project.

| Area | Observed implementation in refreshed main | Remaining work for this plan |
| --- | --- | --- |
| Review/signing | Immutable revisions, area/security approvals, worker-signed execution evidence, central package/database and release-attestation signing | Extend authorizations to complete system/OPR cohorts, snapshot compatibility, generated changelogs, and resolved transactions. |
| Public evidence | Signed in-toto/SLSA statements, exact embedded worker report/signature, binary/public-recipe bindings, independent verifier, historical evidence labels | Preserve v1 verification; add explicit versioned contracts for multi-output builds, complete owned dependency locks, cohorts and distribution manifests. |
| Recipe policy | Immutable `make-v1` and `go-v1` templates, deterministic re-rendering, explicit custom shell and runtime-exception acknowledgement | Reuse for ordinary packages; add reviewed preserved-recipe import and only justified template extensions for real catalog patterns. |
| Runtime validation | Separate operator-pinned runtime image; namcap/ELF checks; build/runtime image identities and package-version inventories; errors cannot be waived | Extend to full captured base/runtime inputs and cohort ABI/system tests. Inventory observation is not an immutable base dependency lock. |
| Dependency blockers | `blocked` request state, scoped findings, maintainer create/link/recheck actions, graph guards and re-resolution after matching approved published binaries | Add draft OPR replacement proposals, identity/ARM-variant matching, all-parent views, owned-only resolution, cohort/snapshot context and eligible internal staged providers. |
| Frozen dependencies | OPR package signature/hash/version checks, `runtimeReleaseIds` separation and recheck of frozen versions after final package resolution | Capture and constrain all core/extra/ARM dependencies too; official repository packages still resolve during preparation. Remove AUR/ALARM fallback. |
| Channels and outputs | `dev`/`stable`/`withdrawn`, promotion batches, per-architecture snapshots, one artifact per build and no `any` artifact model | Independent OPR memberships plus versioned system edge/rc/stable, multiple outputs, complete transaction locks and first-class target matrix. |
| Native ARM | Repository records successful native Go/OCI regression, validated default builder and separate runtime image; ARM workers are ephemeral | Establish dependable native capacity and boot/hardware acceptance for owned releases; replace ALARM-derived normal build/runtime providers through OPR admission. |
| UI | Request detail has dependency blocker forms, explicit shell/exception acknowledgements and `blocked` styling; public package detail has attestation links/runtime coverage labels | Improve existing controls into searchable admission/inbox and cohort phase/changelog views; add system/OPR compatibility, release and consumer/admin journeys. |
| Update/Git automation | Existing scheduled proposal generation, source integrity checks and per-file PR writes; publication/cron recheck blockers | Full catalog cursors, bulk reviewed import, canonical identities/paths, atomic cohort commits and explicit release refs. |

The September 9 rollout record reports service deployment, migrations 0026–0028, native x86 validation, and [native ARM workflow run 34378972091](https://github.com/ferrreo/omapkg/actions/runs/34378972091). These are recorded acceptance evidence. This plan refresh inspected source and reran selected local tests; it did not redeploy services, query live configuration, or repeat native OCI/ARM acceptance. The existing ARM rootfs and online preparation still use ALARM: a passed runtime regression does not satisfy the new no-ALARM-provider requirement.

Source evidence: [model](../../src/lib/model.ts), [publication/promotion](../../src/lib/server/releases.ts), [release attestation](../../src/lib/server/release-attestation.ts), [independent verifier](../../signer/src/verify-release.ts), [recipe policy](../../services/pipeline/recipe-policy.ts), [runtime evidence validation](../../src/lib/server/runtime-evidence.ts), [dependency blockers](../../src/lib/server/dependency-blockers.ts), [dependency plans](../../src/lib/server/dependency-plan.ts), [repository checks](../../src/lib/server/repository.ts), [worker execution](../../worker/runner.go), [dependency preparation](../../worker/dependency.go), [ARM acceptance](../arm-acceptance.md). Source links refer to this checkout; exact baseline SHA is recorded above.

### Omarchy alignment contract

Current package tooling uses flat `pkgbuilds/<package>/` directories with `.omarchy/package.json` policy. Its normal channel progression is edge, rc, stable; fast packages build separately against channel-specific environments. Preserve these semantics when importing metadata. [Omarchy package policy](https://github.com/omacom/omarchy-pkgs/blob/a44e2d2e49d01faa4d351e047bfa5632c2c21b1b/README.md)

| User-facing mode | Current Omarchy behavior | Proposed omapkg integration |
| --- | --- | --- |
| stable | Stable base mirror and stable Omarchy packages | Resolve one stable system version plus a compatible independent OPR snapshot. |
| rc | RC base mirror and release versions of `omarchy` / `omarchy-settings` | Freeze a named candidate, including final package bytes before shipping. |
| edge | Edge repositories and `omarchy-dev` / `omarchy-settings-dev` | Publish consistent system candidates and compatible OPR cohorts; edge still requires review and isolation gates. |
| dev | Local Omarchy source checkout layered over edge packages | Preserve as local development mode. Do not map it to omapkg’s old quarantine channel. |

The current client config orders `[core]`, `[extra]`, `[multilib]`, then `[omarchy]`. Base servers are `stable-mirror.omarchy.org`, `rc-mirror.omarchy.org`, and `mirror.omarchy.org`; Omarchy packages use `pkgs.omarchy.org/{channel}/$arch`. Channel switching refreshes config and performs a full synchronization/downgrade-capable transaction. Preserve compatible repository names and integrate the manifest resolver into that path. [Client channel selection](https://github.com/omacom/omarchy/blob/5ead870507dfb68db696b3ddb948cc3d178e8d62/bin/omarchy-channel-set), [pacman refresh](https://github.com/omacom/omarchy/blob/5ead870507dfb68db696b3ddb948cc3d178e8d62/bin/omarchy-refresh-pacman), [stable config](https://github.com/omacom/omarchy/blob/5ead870507dfb68db696b3ddb948cc3d178e8d62/default/pacman/pacman-stable.conf), [stable mirror](https://github.com/omacom/omarchy/blob/5ead870507dfb68db696b3ddb948cc3d178e8d62/default/pacman/mirrorlist-stable).

Omarchy’s release tooling has a standing recipe `rc` worktree and versioned upstream release branches; `omarchy` and `omarchy-settings` are pinned together. Retain paired-source identity and protect in-flight RC pins from default-branch changes. Resolve configured branches to immutable commits; never infer a channel from whichever branch is currently default. [Release coordinator](https://github.com/omacom/omarchy-pkgs/blob/a44e2d2e49d01faa4d351e047bfa5632c2c21b1b/bin/omarchy-release), [paired pin engine](https://github.com/omacom/omarchy-pkgs/blob/a44e2d2e49d01faa4d351e047bfa5632c2c21b1b/bin/omarchy-pkgs).

ARM is a material gap: tooling accepts `aarch64`, but its published-architecture default is x86_64. Its ARM builder selects a live Arch Linux ARM mirror, while x86 selects Omarchy channel mirrors. That observation describes upstream Omarchy tooling. omapkg main now separately records validated ARM builder/runtime defaults and native regression evidence, but no continuously running ARM daemon. The proposed owned distribution must freeze ARM inputs independently and require complete native results before release. It does not wait for Omarchy to publish an ARM repository: compare existing baseline targets and qualify ARM as our new supported target. [Architecture defaults](https://github.com/omacom/omarchy-pkgs/blob/a44e2d2e49d01faa4d351e047bfa5632c2c21b1b/helpers/paths.sh), [builder inputs](https://github.com/omacom/omarchy-pkgs/blob/a44e2d2e49d01faa4d351e047bfa5632c2c21b1b/build/Dockerfile).

**Compatibility details:** pacman repository names determine database names. `[omarchy]` needs `omarchy.db`; `[core]` needs `core.db`. omapkg’s current generator and routes hard-code `opr.db`. Add an explicit repository identity and exercise real pacman against each name. During migration, keep old paths as documented compatibility endpoints; never silently repoint old omapkg `dev` consumers to Omarchy local-development semantics.

## 03 · Separate origin, repository, and installation role

“Base” cannot mean everything in core, or everything installed by Omarchy. Core/extra are package collections; minimal system membership and Omarchy’s default installation are different sets. A desktop-critical library can live in extra.

| Dimension | Proposed values | Purpose |
| --- | --- | --- |
| Source origin | Arch/Omarchy packaging commit, authoritative upstream source/vendor, AUR/ALARM reference evidence | Distinguish what informed a proposal from the admitted source and builder. Reference evidence does not confer approval. |
| Published repository | core, extra, omarchy, omapkg; multilib where supported | Client resolution namespace and database identity. |
| Installation role | base-system, omarchy-default, optional, build-only | Explain what users receive and which tests must run. Derived dependency closure can cross collections. |
| Release policy | system-train, system-fast-patch, independent-OPR; channel eligibility | Control coupling and cadence without moving recipes between channel directories. |
| Target support | x86_64, aarch64; platform profiles and documented exceptions | Distinguish CPU ABI from hardware enablement. |
| Publication surface | built binary, imported bootstrap binary, recipe-only | Keep evidence and licensing limits visible. |

Maintain reviewed profile manifests for minimal bootable systems, Omarchy default installs, and optional applications. A base-profile change needs base owners even when the recipe lives in extra. Enforce ownership in the API and signer; CODEOWNERS alone is not an authorization boundary.

**Multilib:** Omarchy currently enables it on x86_64. Include its captured package set, updates, 32-bit ABI consumers, and tests in the owned release boundary wherever that profile enables it. Leaving it live upstream would undermine the coherence of owned core/extra. This is a required compatibility extension, despite the request naming core/extra. Do not invent multilib on ARM. Required packages or ARM adaptations previously obtained from ALARM—including its core/extra and platform repositories—must be replaced through the reviewed OPR admission flow below. Neither ALARM repository names nor an AUR recipe make a dependency approved. Existing Omarchy recipes fed by AUR/ALARM also need an explicit OPR ownership/admission decision; importing their old metadata must not preserve automatic external sync authority. Remove live ALARM/AUR resolution from normal build, runtime, and client paths.

Keep package names unchanged unless a reviewed rename/replacement is necessary. Reject duplicate names/providers across enabled collections unless an explicit replacement policy and upgrade test justify them. Preserve core/extra/Omarchy ordering; additions must not silently shadow base packages. Conflicts, replacements, providers, epochs, and split outputs are part of admission, not cosmetic metadata.

## 04 · Git and artifact layout

Use two logical Git repositories: existing omapkg application code and one package-catalog repository configured through the existing GitHub integration. Keep Omarchy application source in its current upstream repository. Avoid one new Git repository per package or per architecture.

Proposed catalog structure:

```text
packages/
  core/<pkgbase>/          PKGBUILD, .SRCINFO, patches, install files, package.json
  extra/<pkgbase>/         same structure
  omarchy/<pkgbase>/       imported Omarchy recipes and local adaptations
  omapkg/<pkgbase>/        admitted OPR additions and AUR/ALARM replacements
  multilib/<pkgbase>/      x86 compatibility recipes where required
profiles/
  base-system.json         architecture-specific bootable roots
  omarchy-default.json    default installation roots
policy/
  targets.json            required architectures and hardware profiles
  owners.json             accountable teams and review rules
  release.json            cadence, freshness, exception, retention policies
imports/<import-id>.json  original repositories, commits, DB digests, dispositions
releases/system/<version>/
  manifest.json           immutable system set, e.g. 4.0.3
  CHANGELOG.md            reviewed system release notes
releases/opr/<generation>/
  manifest.json           package/cohort updates and supported system snapshots
  CHANGELOG.md            independent OPR package changes
cohorts/<cohort-id>/<revision>/
  manifest.json           members, phase evidence, compatibility, approvals
  changelog.json          generated machine-readable cohort changes
  CHANGELOG.md            reviewed cohort narrative and phase summaries
```

A `pkgbase` is the build unit; it can produce multiple installable `pkgname` outputs. Use a global identity registry so outputs cannot collide across directories. One recipe supports both architectures where practical; record architecture-specific sources/patches as reviewed fields. Keep original Arch/Omarchy recipe bytes and import provenance. AUR/ALARM recipes remain untrusted reference evidence until a human admits an OPR proposal and the resulting recipe completes normal review. Preserve upstream history through commit references and archived source bundles; a full copy of every upstream Git history is unnecessary.

Existing omapkg writes `packages/<name>`; introduce one canonical path resolver used by importer, PR writer, integrity checks, worker manifests, and public recipe links. Import `.omarchy/package.json`, patches, hooks, `pinned`, `channels`, `release_ring`, `rebuild_on`, and `rebuilt_against` without executing them. Translate supported fields to the catalog schema, retain the originals, and flag unsupported behavior for review.

**Branch policy:** protect the catalog default branch for accepted proposals. Keep a protected standing `rc` branch for Omarchy compatibility, but record the exact commit for each release candidate. Use short-lived change branches and release worktrees; no per-channel or per-architecture copy of the whole recipe tree. System stable is an immutable signed version tag/manifest; OPR stable is a pointer to an immutable package snapshot generation. Neither uses a mutable Git branch as install truth. Promotion changes signed memberships and pointers, not recipe contents. Security hotfix branches start from the affected release commit and must reconcile into the active train.

An atomic Git commit must contain an entire coupled recipe update. Extend the current per-file GitHub API writes to create one tree/commit for a cohort. Bind approvals to reviewed recipe/input digests; release approval additionally binds the candidate artifact and manifest digests. Re-resolving dependencies or changing a template invalidates affected approvals and tests. Git merges do not grant publication rights.

Package archives, source bundles, logs, `.BUILDINFO`, SBOMs, and attestations live in immutable object storage by content digest. Git contains small manifests and references. D1 holds indexed operational state and approvals; signed release manifests are immutable public records. Verify that D1 records, Git refs, and object digests agree before signing. Large catalog graphs use paged/indexed metadata and immutable graph artifacts, not a giant JSON cell or an unbounded Worker request.

## 05 · Import once, then own updates

1. **Capture a baseline.** Record signed database/package identities from current Omarchy stable, rc, and edge; inventory official core/extra and required multilib, Omarchy recipes, and missing ARM coverage. Inventory AUR/ALARM-derived requirements as replacement work, not approved catalog imports. Record capture time and repository digests independently for each architecture. Catalog membership comes from the captured inventory, not a drifting “latest” query.
2. **Map recipes to binaries.** Preserve `pkgbase`, split outputs, complete versions, source commits, patches, licenses, signing identities, dependencies, providers/conflicts/replacements, install hooks, and build configuration. Map each shipped binary to its packaging/source evidence. Missing records are explicit import failures.
3. **Inspect safely.** Parse available metadata as data first. Never source a PKGBUILD or import hook in the control plane. Any `.SRCINFO` regeneration or shell evaluation runs in the untrusted inspection sandbox without credentials. Arch/Omarchy recipes enter a dedicated reviewed import path; AUR/ALARM dependencies enter the OPR proposal/admission path below; do not force them through AI regeneration or weaken public URL-only submission rules.
4. **Assign ownership and support.** Every package gets an owner, upstream tracking rule, patch disposition, architecture matrix, runtime test policy, and redistribution decision. Preserve custom recipes as custom shell. Package-family batches make review tractable, but each approved member/digest is enumerated. Already-approved equivalent OPR identities may be linked; external origin never grants approval by inheritance.
5. **Seed a transparent bootstrap.** Retain verified Arch x86 baseline binaries as frozen bootstrap inputs and, if explicitly approved for transition, release them with original signatures plus our import authorization. AUR/ALARM binaries cannot use this transition route to become released dependency providers. Label admitted Arch baseline binaries `imported-bootstrap`: they have no omapkg build attestation. A human chooses whether existing users remain on the old service until rebuild completion or move to this clearly labelled managed Arch baseline. ARM bootstrap needs a separately reviewed seed/toolchain plan; if no approved seed exists, report a blocker. Any proposed external bootstrap seed is private, migration-only input subject to explicit human approval, never a fallback repository or an OPR build claim. Replacement outputs must be built and verified by omapkg before entering supported releases.
6. **Rebuild the catalog.** Bring up the toolchain and minimal system first, then dependency layers, default Omarchy, and the rest of extra. Rebuild every source-buildable admitted package on its required targets; recertify `any` outputs. Vendor binaries remain vendor artifacts with distinct evidence. Track completion against the full inventory.
7. **Cut over once.** Reconcile candidate snapshots with the old service; verify client upgrades; freeze old publishers; record final digests; transfer publish authority and endpoints; switch clients using a signed migration package/config. Retain read-only old snapshots. Do not run two writers for one repository namespace.

After ownership begins, existing update feeds detect changes in admitted upstream software, Arch packaging, Omarchy, and security advisories. AUR/ALARM observations can suggest porting or packaging work, but cannot import, update, or publish a provider on their own. A recipe-only upstream fix can matter without a version change. Detection creates a deduplicated proposal; it cannot overwrite local patches, remove packages, switch source owners, or publish. Reconcile with a three-way comparison of last imported upstream, current upstream, and our recipe. Conflicts become review work. A security backport can ship before upstream Arch when our maintainers approve it.

Use the existing scheduler/workflow/worker fleet with durable cursors, bounded pages, fair per-package polling, idempotent job keys, backoff, and priority for security/cohort blockers. Separate detection from build queues. Hash unchanged inputs and skip unnecessary work. No agent call is needed to copy metadata, compare versions, sort a graph, or publish an approved manifest.

### AUR/ALARM replacement and dependency admission

**Extend the existing blocker flow.** Main already stores scoped findings with `open/resolved/superseded` status, blocks the parent, allows maintainers to create or link normal requests, and rechecks published providers on linking, publication and cron. A matching approved signed `dev`/`stable` binary with the right relation and architecture returns the parent to `review` or `pending`, never grants approval. Keep these guards and audit links; build draft replacement proposals and ARM identity matching around this service instead of creating a parallel admission system.

The current resolver has no system snapshot/cohort compatibility context and accepts published providers only. Internal staged providers, all-parent navigation, proposal deduplication and source-scope decisions below are extensions, not existing behavior. Moving a parent out of `blocked` must still recompute the new lock/review basis before any cohort build or publication.

**Admission mechanism and release cadence are separate.** An OPR-managed package is sourced, reviewed, built, signed, and maintained through omapkg. Optional OPR packages keep solo releases. An ARM variant needed by core/extra or the default system still joins the versioned system cohort. It must not float independently merely because it entered through OPR admission.

AUR and ALARM may supply untrusted pointers to authoritative source code, patches, or platform knowledge. A mirror URL, an existing upstream signature, or a familiar package name does not make their binary an eligible provider. Do not re-sign an external binary and call it OPR-built. The intended steady state has no AUR/ALARM fallback in client configuration, dependency solving, build preparation, clean runtime images, or signed release manifests. Source attribution remains in evidence even after replacement.

1. **Detect the gap.** During import or dependency planning, record the capability/name, version constraint, target architecture/platform, required system snapshot, runtime/build/check role, detection evidence, and every blocked parent/cohort. Searching supported owned snapshots happens before proposing anything new.
2. **Link or propose once.** Reuse a matching approved OPR provider or open request. Otherwise generate a draft OPR request with proposed authoritative upstream URL, source/porting evidence, license questions, package identity, architecture scope, suggested owner, and blockers it could resolve. For an existing core/extra package lacking ARM support, propose an ARM variant linked to that identity instead of creating a conflicting same-name package. One request can unblock several parents; version/context differences remain explicit.
3. **Human admission decision.** A maintainer can approve packaging work, link an existing eligible request/provider, request changes, select an alternative, or reject with a reason. Base-impact decisions require base ownership and security review under the existing policy. Approval admits specified source identity and scope, not whatever a future model discovers. Proposed metadata may be inspected under the existing restricted intake policy; materializing a new source, running its recipe, or building it requires the applicable admission/review gates.
4. **Normal omapkg packaging.** The admitted request enters inspection, recipe generation or reviewed adaptation, exact-revision area/security review, native builds on required targets, runtime/ABI checks, provenance, signing, and the appropriate staging/release path. New transitive gaps repeat the same linked workflow. Bound proposal depth/work, deduplicate equivalent requests, and detect cycles so hostile inputs cannot create an unlimited admission queue.
5. **Re-resolve with evidence.** Admission alone never clears the blocker. A built, reviewed provider becomes eligible only in the exact approved candidate/OPR snapshot for that architecture and constraint. For coupled builds it may first be an internal staged cohort artifact; this does not require premature public release. Recompute the parent lock/cohort digest and invalidate affected approvals/tests before continuing. Normal release gates still apply.
6. **Keep unresolved work visible.** Rejection, missing source/rights, unsupported ARM, failed tests, revoked admission, or incompatible versions leave a reasoned blocker with owner and next action. Linking a new alternative requires review. Never silently drop a dependency, substitute a live external package, or call a parent unblocked because its proposal was accepted.

Migration also inventories already installed external packages. Offer reviewed mappings from old identity/version to the OPR-built replacement, including same-name ownership changes, epochs, split outputs, config preservation, `provides/conflicts/replaces`, and any required full-system transaction. Let the user review the resulting local change; ambiguous matches stay unresolved. No blanket `--overwrite`, forced removal, or automatic conversion of an unrecognized user package.

**Acceptance:** a missing ALARM ARM library and an AUR-only runtime dependency each create a single linked proposal; a human can accept or decline; approval alone keeps parents blocked; accepted replacements are built/tested on required targets; rejected/failed requests never trigger external resolution; a matching staged or published provider re-resolves all applicable parents through fresh gates. Inspect final client configs, runtime package inventories, dependency locks, and manifests to prove that released dependencies are owned outputs, with no AUR/ALARM binary pass-through. An OPR-only replacement can still release without changing system `4.0.3`.

## 06 · Dependency and ABI rebuild cohorts

A **build cohort** is the smallest closed set of package changes that must be built and released together. It can include core providers, extra consumers, Omarchy components, optional applications, split outputs, and architecture-specific replacements. It is not a fixed package category or a list of testers.

### Release-lane classification

Core/extra and profile-required system packages belong to the system lane. An imported Omarchy/OPR package outside that set may use independent OPR policy. A package required by the default-system profile cannot float between lanes: its system-owned version is pinned; a newer optional alternative needs explicit non-conflicting identity and tests. Changing lane or making an optional package a base/default dependency needs human review. One package identity has one authority in a resolved client universe.

### Deterministic planning

For each target architecture and candidate base snapshot:

1. Index the entire enabled package universe: declared runtime/build/check dependencies, versioned providers, conflicts/replacements, split-package relationships, file ownership, ELF SONAMEs and required symbols. Preserve build-input and static-link relationships from recorded inventories.
2. Diff old and candidate artifacts. SONAME removal/change, removed or incompatible symbols, and symbol-version changes trigger affected consumers. Compare C/C++ ABI with `abidiff` where debug/type information permits; missing information means unknown coverage. A stable SONAME alone does not establish compatibility. [Libabigail comparison capabilities](https://sourceware.org/libabigail/manual/abidiff.html)
3. Add non-ELF triggers: Python/Perl/Ruby runtime transitions, plugin ABIs, kernel/module pairs, generated bindings, compiler runtimes, schema/config changes, bundled/static dependencies, and explicitly maintained `rebuild_on` rules. A static library security fix needs consumer rebuilds even when there is no runtime link.
4. Walk reverse dependencies to closure. Rebuild affected consumers; retest consumers whose declared contract remains compatible. Expand conservatively when linkage is unknown. Re-run analysis after builds because new outputs can change the affected set. Any new member creates a new cohort revision.
5. Order builds by dependency graph; collapse strongly connected components. For cycles, record a reviewed staged bootstrap using a retained known-good seed, then rebuild the final component against the final set. Never silently break cycles or publish intermediate bootstrap products.
6. Resolve and install the final universe with pacman/libalpm semantics. Cross-check existing TypeScript version/relation logic against `vercmp` and actual pacman transactions. Reject unresolved dependencies across every owned repository, even if omapkg has never published that name before. Use package-file conflicts and representative installed-state transactions as additional checks.

Maintain an indexed graph using ordinary tables and deterministic traversal; a separate graph database is not justified. Distinguish current limits: frozen build plans allow 64 packages; dependency-admission graphs reject cycles, depth beyond eight levels, more than 64 reachable requests per root, and over 4096 open links; blocker reporting and polling are also bounded. These are different domains. Keep bounded, acyclic admission and graph-version concurrency checks. Model build-time strongly connected components only among already-admitted package identities; do not bypass the admission cycle check to bootstrap a toolchain.

Replace the 64-package *artifact transfer* envelope with digest-pinned, chunked manifests and measured per-job limits where full closures require it. Add fair pagination for catalog/blocker scans and explicit, reviewed budget changes when needed; do not simply remove guards or apply the full-catalog size as the default automatic admission budget. Limits must block with evidence rather than truncate the graph. Packages resolving entirely from the captured base still appear in the lock and installed inventory.

Omarchy already records selected `rebuild_on` relationships and per-architecture `rebuilt_against` versions. Import these as useful hints and historical evidence, then strengthen them with measured artifact relationships. Do not treat the hand-maintained list as complete ABI coverage. [Current rebuild trigger](https://github.com/omacom/omarchy-pkgs/blob/a44e2d2e49d01faa4d351e047bfa5632c2c21b1b/bin/sync-rebuilds)

### Cohort phases and generated change records

Every build cohort—system, independent OPR, or a singleton OPR package—has the same understandable phase model. The required tests and promotion targets vary by lane. Phase and condition are separate fields: a cohort can be **Building · blocked on ARM** without inventing an unrelated lifecycle state.

| Phase | Visible evidence and next action | Generated phase changelog |
| --- | --- | --- |
| Plan and admit | Proposed members, why they belong together, missing providers, human admission decisions | Added/removed members, proposed AUR/ALARM replacements, affected architectures, source/ABI causes, unresolved scope. |
| Review recipes | Exact recipe/input diffs and required area/security decisions | Source/patch/config changes, approved variants, review outcomes; proposed changes distinguished from accepted ones. |
| Build | Native per-target jobs, split outputs, queue/failure owner | Actual old/new versions, rebuild-only pkgrel changes, input/environment changes, produced or missing outputs. |
| Verify | Dependency closure, ABI/runtime/system checks and reproducibility evidence | Test results, detected incompatibilities, exceptions, and remaining unknowns. |
| Stage and test | System edge/RC candidate or independent OPR quarantine, with exact compatible base | Candidate identities, relevant install/upgrade tests, tester findings, and differences from the previous candidate. |
| Approve release | Exact cohort revision, changelog, required matrix and final authority | Reviewed user-facing changes, migration/reboot instructions, known issues, and approval scope. |
| Publish | Signed artifacts/manifest and confirmed activation | What actually shipped, affected repositories/targets, parent snapshot and recoverable predecessor. |
| Observe or recover | Rollout health, holds, superseding fix or recovery plan | Confirmed incidents, rollout decisions, recovery/forward-fix outcomes and follow-up cohort references. |

Generate `changelog.json` and `CHANGELOG.md` from immutable cohort revisions and phase events—not raw log scraping. Each phase transition or meaningful blocked/retry/scope change adds an attributed change record with cohort/revision, prior/current digest, actor or automation identity, timestamp, cause, evidence, and next phase. Repeated identical events are idempotent; repeated log lines do not become changelog entries. Preserve previous revisions; never rewrite what an earlier reviewer approved.

The cohort page exposes **Overview**, **Changes**, **Phases**, **Tests**, and **History**. Changes can compare with the parent released state or the preceding cohort revision; label that baseline explicitly. Distinguish “planned”, “built”, and “published” changes. An agent may draft prose from the generated facts, but a human reviews the public narrative; neither can edit facts without changing the underlying revision. Member/input changes invalidate affected build/test/release approval. A prose-only edit changes its digest and requires renewed changelog/release approval without needlessly rebuilding identical artifacts.

System and OPR release changelogs aggregate exact approved cohort changelog digests, with no missing or duplicated members. Every published cohort, including a rebuild-only or one-package OPR release, needs a reviewed changelog. Public summaries omit private source data, unredacted logs, and embargoed security details; maintainers retain the authorized full history. Never imply that a completed build is already available to users.

Rollout cohorts have their own phase/change history: **Prepared → Opted in → Rolling out → Observing → Complete**, with held/recovering conditions when needed. Their notes record the target system version/OPR snapshot, eligibility/cohort changes, exposure, gate decisions, incidents, and recovery results; they link the package-cohort changelogs rather than inventing new package changes. A held rollout does not mutate the release’s package changelog.

**Acceptance:** a solo OPR rebuild, a multi-package ABI transition, and a human-blocked replacement each produce correct phase records and cohort changelogs; replaying an event produces no duplicate; changing membership produces a new revision; publication rejects missing/stale approval or changelog digests; aggregated release notes match published cohorts exactly.

### Concrete example: a library transition

Illustrative change: `libexample.so.1` becomes `libexample.so.2` in extra. The graph finds two extra applications, an Omarchy plugin, and an optional omapkg application. Their source versions may not change; their package releases must. An aarch64-only consumer joins that architecture’s build set. Old consumers cannot accompany the new provider in a candidate snapshot. A consumer that fails to port blocks the cohort; removing it requires a reviewed removal/replacement plan and user-facing notes.

Build the provider, then consumers against the candidate provider, then run runtime and integration tests against the final candidate repositories. Both native targets must pass their required matrix. The system release includes the changed provider and system consumers, and binds a tested compatible OPR snapshot containing rebuilt OPR consumers. Evidence and recovery targets cover that combined transaction. No channel pointer moves when a required member is missing. Unrelated OPR cohorts may continue shipping against their supported system snapshots after proving they do not cross the blocked dependency boundary. An OPR-only provider transition forms its own OPR cohort without forcing a system version bump.

### Package versions and artifact identity

Use Arch version semantics (`epoch:pkgver-pkgrel`), preserving imported epochs and split-package relationships. Increment `pkgrel` for rebuilds without a source release; tooling must not casually add an epoch. Each distinct build-environment variant gets a distinct published package version/filename when its bytes differ, even if source is unchanged. Reserve versions centrally and check all affected channel floors with `vercmp` before building. Never overwrite a published filename with different bytes. [Arch package version fields and split-package rules](https://man.archlinux.org/man/PKGBUILD.5.en)

Fast builds may produce different artifacts for stable, rc, and edge. A stable security bump must not cause the next train to “upgrade” users to an older effective package version. Reconcile hotfixes into rc/edge and rebuild when necessary. Explicitly test stable → rc → edge and return transitions, including epochs, prereleases, removals, replacements, split packages, and architecture-specific releases. Intentional downgrades need a reviewed channel/recovery transaction.

## 07 · First-class x86, ARM, and any packages

Main now records native ARM acceptance and validated image defaults; reuse them as the regression baseline, not proof of continuous fleet capacity or owned ARM inputs. Set checked-in required targets to `[x86_64, aarch64]`. Default catalog import, cohort planning, CI, and release commands expand `all` to that list. Architecture selection never falls back silently to the first worker or reference architecture. A scheduler may run jobs independently; a release waits for every required result.

Use native x86_64 and aarch64 workers for release acceptance. Emulation helps triage and bootstrap but does not satisfy native performance, boot, or hardware gates. Retain worker architecture, CPU baseline, image digest, kernel/runtime versions, and platform profile in evidence. Use generic supported CPU flags; accidental `-march=native` output must not leak into the general repository.

| Case | Required treatment |
| --- | --- |
| Portable source package | Build natively on both targets and test each result. Different bootstrap inputs are recorded explicitly. |
| `arch=('any')` | Inspect content for architecture independence; build/compare during qualification, then permit one shared artifact by policy. Resolve dependencies and install/test it on both native targets. Never create an `all` CPU package. |
| Split package | Record one build with multiple outputs, per-output metadata/signatures, and expected outputs. Missing output blocks the build cohort. |
| Hardware package | Bind to a platform profile; test boot/kernel/firmware/driver pairing on that hardware class. x86-only hardware support does not become an ARM failure or a fake port. |
| Vendor binary with no ARM distribution | Record unsupported vendor constraint; propose a real port/alternative when possible. A human exception is visible; no parity claim. |
| ARM support known only through ALARM | Propose a human-admitted OPR package/ARM variant using reviewed authoritative sources and porting evidence; build it in omapkg. Until eligible owned output exists, the affected target stays blocked. |

Arch Linux ARM is a separate ARM port with its own adaptations and package infrastructure; an x86 package catalog is not an ARM binary source. Use ALARM as reference material for ARM porting proposals, not as a continuing package supplier. Missing ARM coverage goes through the same human-controlled OPR replacement workflow. [Arch Linux ARM](https://archlinuxarm.org/about)

The current [ARM builder](../../worker/images/aarch64/Dockerfile) and [runtime image](../../worker/images/aarch64/runtime.Dockerfile) start from an ALARM rootfs and resolve repository packages online. They also initialize ARM signing trust; the builder uses a checksum-pinned upstream ShellCheck binary. Preserve their proven isolation/trust checks while planning replacement of those normal package inputs and rebuilding the images. Inventory ShellCheck and other tooling explicitly; decide their owned packaging/distribution policy rather than silently losing a validation tool during migration.

Build, qualify, and retain every admitted ARM dependency needed for a candidate before treating it as an eligible provider. Separately capture the approved private bootstrap inputs needed to establish that toolchain; they cannot leak into release dependency resolution. A live mirror URL, timestamp, or builder image tag is insufficient to recover a moved package. A missing owned source/signature/archive required to build our target blocks that snapshot. Absence of an external Omarchy ARM baseline does not; record it as a new target and establish owned inputs and native qualification independently. Keep architecture-specific profiles for at least x86 UEFI and aarch64 UEFI/native acceptance; add board/Apple Silicon enablement only with explicit kernel, bootloader, firmware, and real-device qualification. First-class aarch64 is not a claim to support every ARM board.

## 08 · Releases, channels, and rollout cohorts

Proposed system lifecycle:

```text
Observed update → human-approved revision → locked build cohort
→ native builds on all required targets → deterministic validation
→ signed edge release → maintainer-frozen RC → system and tester evidence
→ human release approval → stable activation → observe or recover
```

Independent OPR flow: reviewed package/cohort → native build and compatibility checks → OPR quarantine → package/cohort approval → OPR stable generation. It does not require a new system RC or version.

Failed checks create structured blocked work. A candidate is immutable; fixes produce a successor. A **rollout cohort** is a group of consenting clients assigned to a system version and resolved OPR snapshot, independent of the build cohort. OPR package/cohort releases can use their own opt-in testers without waiting for a full system train. Suggested initial groups: lab, opt-in testers, stable canary, general stable. Lab/test clients can pin a specific RC, including installation images built from that RC.

### System versions and independent OPR versions

**Public system release versions use `MAJOR.MINOR.PATCH`, for example `4.0.3`.** This is the system release identity shared by core, extra, profile-required Omarchy/base packages, and both primary architectures. Optional OPR updates do not change it. Coordinate allocation with Omarchy’s release owner; omapkg must not create a competing sequence of Omarchy version numbers.

| Record | Example | Contract |
| --- | --- | --- |
| Shipped system | `4.0.3` | Immutable system manifest and package set; never reissued with changed contents. |
| Source/catalog release tag | `v4.0.3` | Protected, signed tag bound into release evidence; source and catalog repos may have distinct commit hashes. |
| Release candidate | `4.0.3-rc1`, `4.0.3-rc2` | Distinct immutable candidates for that planned final version. |
| Edge candidate | `4.0.4-edge.1` | Versioned development candidate for the next allocated release; never presented as stable. |
| Pacman Omarchy package | `4.0.3rc1-1` → `4.0.3-1` | Use current Arch-compatible normalization and verify ordering with `vercmp`. |
| OPR package release | `example-app 2.8.1-2` | Independent package version, approval, changelog, and publication. No `4.0.4` release is required. |
| OPR repository snapshot | Immutable generation + digest | Resolves exact compatible OPR artifacts; this is repository metadata, not a new Omarchy product version. |
| Other system package | Its own upstream `epoch:pkgver-pkgrel` | Package versions remain independent of the system version. |
| Internal digest | SHA-256 of a manifest or snapshot | Integrity identity; never the only user-facing release name. |

Published system `4.0.3` never changes. A core/extra or other system-owned fix becomes a newly allocated patch release such as `4.0.4`, built from the affected stable baseline where appropriate. Coordinate the Omarchy package pair, version reporting, changelog, and source tags even when application code is unchanged. A standalone OPR update instead publishes its package version and a new OPR generation compatible with `4.0.3`; the system version remains `4.0.3`.

The same final version covers both architectures, with their exact artifacts listed separately. No silent `4.0.3` ARM subset after x86 shipment. A candidate’s final version is reserved once; retries reuse the same candidate only when its content digest is identical. Changed final-version package bytes require a new candidate before first shipment; changed bytes after shipment require a new patch version. Repository snapshot URLs and ISO names carry this release version, e.g. `/repo/releases/4.0.3/core/x86_64/core.db`. An expired or failed RC remains archived under its original version.

### Two release manifests, one resolved transaction

The immutable **system manifest** owns the versioned core/extra/default-system set. The independent **OPR manifest** owns an immutable OPR package snapshot and explicit compatibility with supported system snapshot digests. The client receives one signed **resolved transaction manifest** selecting both, so every pacman read uses the same compatible combination. This small composition step extends existing repository snapshots; it does not require another release service.

An OPR update qualifies for solo release when it changes no system-owned package, satisfies dependencies against the selected system/OPR universe, exports no unhandled incompatible interface to other packages, and passes its required architecture/runtime/review gates. It may go from OPR quarantine (legacy `dev`, displayed as package quarantine) to OPR stable after its package policy; it need not wait for a system RC or version bump. If it breaks an OPR dependency, expand the OPR cohort. If it requires a new base ABI, rebuild it as part of the system transition and publish compatibility for that new system snapshot. Keep the last supported artifact for older supported system versions.

Each relevant manifest records:

- System version or OPR generation, parent identity, schema/policy versions, manifest digest, creation/expiry and monotonic sequence for its lane.
- Exact catalog and Omarchy source refs, migration refs, and upstream-import lineage.
- Per-architecture repository snapshot digests owned by that lane, and exact supported system snapshots for OPR. The resolved transaction covers core, extra, omarchy, omapkg, plus profile-required multilib/platform inputs. Unchanged snapshots can be referenced by digest.
- Exact package identities, artifact hashes/signatures, declared architecture, build cohort membership, image/input locks, and evidence references.
- Required test matrix, results, reproducibility status, approved exceptions, reviewer identities, and signed human release authorization.
- Changelog digest, installation/upgrade instructions, reboot requirements, known issues, and tested recovery target/constraints.

Separate immutable package/build records from channel membership. An artifact can be in edge, rc, and stable simultaneously. The current single `releases.channel` field cannot express that safely; do not mutate the only record out of its previous channel during promotion.

### Publication without mixed generations

1. Prepare all immutable snapshots, database signatures, artifacts, and release evidence. Resolve every referenced object and verify visibility from supported serving origins.
2. Sign the complete manifest for its lane after policy checks. Activate its pointer with an expected-parent compare-and-swap in D1; record the audit event in the same transaction. OPR updates also compare the qualified system snapshot identity. A system transition atomically activates its base pointer and a qualified OPR compatibility selection. The resolver reads these selections consistently and signs/publishes an immutable combination. Concurrent changes must rebase/revalidate when their compatibility inputs changed.
3. Clients fetch and authenticate the resolved transaction manifest once, then use immutable URLs for **every** enabled owned repository for that transaction. Proposed paths: `/repo/releases/4.0.3/core/<arch>/core.db` and `/repo/opr/<generation>/omapkg/<arch>/omapkg.db`. Existing OPR repository names remain configurable aliases during migration. Package objects remain addressable by content digest and immutable filename mapping.
4. Run a full pacman transaction using a resolved configuration that preserves approved local settings and repository ordering. Extend `omarchy-refresh-pacman` and channel switching to consume this configuration; otherwise their current config-copy behavior would undo pinning. Retry mirror failures only against the same release ID.

A database transaction on the server does not make multiple pacman HTTP reads atomic. Direct clients of mutable legacy aliases can still mix generations. Ship and test the manifest-aware client/config migration before claiming coherent distribution upgrades. Retain aliases only under a documented compatibility window; a failed mirror fetch must never fall through to a different channel or live upstream. Verify monotonic sequence/freshness so an old signed manifest cannot silently freeze or roll back a client; authorized rollback uses a new signed control record.

### Normal train and fast updates

Normal system changes enter edge after their cohort is complete. A maintainer opens an RC from an exact compatible edge release; edge continues independently. RC changes make a new candidate and invalidate affected system-test/soak evidence. Stable receives the exact final package artifacts tested in RC.

Omarchy’s final release pins can change RC package metadata/version. If `rcN` becomes a final version and bytes change, build that final candidate into rc and test it before stable promotion. A source commit having passed an earlier RC is not sufficient evidence for an untested final artifact. The `omarchy` / `omarchy-settings` pair always resolves to the same upstream commit.

For system-owned fast packages, preserve fast-ring capability with stricter semantics: target a currently supported channel snapshot, build and test against that environment, create an immutable candidate, obtain normal approvals, then publish a new versioned system manifest (a new patch version for stable). A fast update to frozen rc creates a successor RC; it never mutates evidence for the old candidate. Independent OPR packages retain their solo path described above. In either lane, fast is a cadence choice, not permission to bypass ABI closure or copy edge binaries into an older stable base.

Proposed starting policy: normal system releases require at least 48 hours of unchanged candidate soak and completed native/system tests. Rollout starts with named consenting canaries, then an approved expansion; use fixed deterministic client buckets only if scale warrants percentages. Hold on any unresolved confirmed critical security, boot, upgrade, or data-loss regression. OPR keeps package/cohort quarantine and review evidence, with risk-appropriate tests; it does not inherit the full-system ISO gate for an ordinary optional app. Lack of crash reports is not positive acceptance evidence. Security maintainers and release maintainers may jointly authorize shorter soak for urgent fixes with recorded rationale; signatures, complete dependencies, and required target checks remain mandatory.

### Recovery is more than a pointer

Freeze rollout on a confirmed incident. Restore or supersede the whole affected system release or OPR cohort; never automatically demote only a library while leaving incompatible consumers installed. Retain artifact/dependency snapshots for every supported rollback point, including both architectures and old signing identities.

For installed clients, generate a signed whole-transaction recovery plan with version changes, removals/replacements, reboot order, and compatibility checks. Test filesystem snapshots or controlled package downgrades as appropriate. Boot artifacts outside the root snapshot and irreversible application/data migrations need their own recovery steps. When downgrade is unsafe, issue a forward fix and recovery guidance. Server pointer restoration alone does not repair already upgraded machines.

## 09 · Preserve the security baseline; extend its scope

The security-discussion implementation is now merged in main, with repository-recorded rollout and native acceptance. Do not recreate the signer, verifier, template system, runtime worker path or dependency-blocker service. Qualification establishes that this release train retains their guarantees, then extends their evidence and authorization boundaries to owned repository snapshots and cohorts.

| Existing foundation | Preserve and regression-test | Remaining distribution extension |
| --- | --- | --- |
| Accurate security claims and historical labels | UI/docs separate signatures, observed evidence and unknown runtime behavior; Surface B local execution remains outside hosted isolation | Explain imported Arch bootstrap vs OPR-built replacements, architecture coverage, snapshot/cohort status and migration limits with the same precision. |
| Signed public evidence and external verifier | Central signature authenticates exact embedded Ed25519 worker report, subject, recipe/source bindings and SBOM digest; independent fingerprint required | Version multi-output/cohort/system/OPR/transaction statements and their verifier dispatch; bind complete locks, changelogs, approvals and compatibility. Retain v1 readers and immutable old statements. |
| `make-v1` / `go-v1` templates and custom shell | Immutable template definition digests, exact internal/public recipe and smoke re-rendering; area/security acknowledgement of custom shell | Keep imported recipes explicitly reviewed; add templates only for justified repeatable catalog patterns. Extend executable-surface validation for retained import hooks/install/check phases. |
| Shell/isolation checks | Factory/worker syntax and ShellCheck rejection plus native OCI network/protected-path regressions | Requalify replacement images and full owned build/runtime preparation. Preserve Docker/Podman behavior and pinned validation tooling. |
| Clean runtime and measured evidence | Separate operator-selected pinned runtime, namcap/ELF observations, prepared image identities and package inventories; errors are non-waivable | Lock all resolved base/runtime package bytes, analyze provider/consumer ABI changes and verify final cohort/system transactions. Record reproducibility coverage separately. |
| Bounded exact finding exceptions | Current policy permits only specific ambiguous finding classes with exact finding hash/reason and reviewed acknowledgements | Add any expiry/owner/snapshot scope required by distribution policy without turning known runtime errors into waivable findings. |
| Structured dependency blockers and human actions | Actor/area authorization, create/link/recheck, graph concurrency guards and no automatic approval on resolution | Draft OPR replacement proposals, no external fallback, canonical ARM variants, compatible staged cohort providers, fair catalog-scale scanning and polished UI. |

The existing [build type v1](../build-type-v1.md) and [verifier](../../signer/src/verify-release.ts) describe a single package or public recipe subject. Preserve that contract for retained releases. Add new versioned evidence schemas where meaning or verification changes; do not reinterpret old records or silently add cohort-signing power to a package intent. Whole-release/OPR/cohort/changelog signing must have explicit typed authorization checked by the signer. A singleton OPR cohort remains independently publishable.

New publications already require the mandatory runtime/evidence path; legacy records remain visibly unverified where evidence is absent. Reusing a historically signed object during migration does not grant it modern runtime/cohort acceptance. Never fabricate retrospective native evidence or use key re-signing to turn an AUR/ALARM binary into an OPR-built replacement.

Current key history documents rotation, revocation and historical-verification limits. Extend it for client snapshot freshness, explicit rollback authorization and release-manifest sequence checks. The current verifier establishes cryptographic/input consistency, not whether a release remains recommended, was signed before a later compromise, or has independent timestamp/transparency evidence. Preserve independent trust establishment and consult current signed release state through the new client protocol.

Runtime errors remain blocking. Namcap/ELF success still leaves dynamic loads, plugins, optional features and unexercised paths unknown. Main explicitly records `runtimeClosureComplete: false`; retain that honesty when adding ABI and system tests. Use narrow reviewed exceptions only for allowed ambiguous findings. [Namcap limitations](https://man.archlinux.org/man/namcap.1)

### Deterministic decisions and reproducibility

Main records separate build/runtime inventories and a runtime subset of the frozen OPR dependency plan (`runtimeReleaseIds`). Frozen OPR package signatures/digests/versions are checked, including a final version check after dependency resolution. Preserve those checks. The remaining reproducibility gap is that official repository packages can still be chosen during online preparation; name/version inventory and base-image digest do not bind all those package bytes or an immutable repository universe.

Extend locks to every installed base, build, check and runtime input: package hashes/signatures, exact repository snapshot/graph digests, recipe/source bytes, template/tool versions, builder/runtime digests, build flags, locale/timezone and `SOURCE_DATE_EPOCH`. Preserve `.BUILDINFO`, source/license bundles and toolchain evidence. Preparation and offline execution remain distinct recorded phases; inherited bootstrap compilers remain trust inputs.

The same approved inputs must yield the same canonical plan, cohort membership, version allocation, unsigned repository database, changelog facts and unsigned manifest. Use stable ordering and canonical serialization. Record agent proposals once for review instead of rerunning a model during release; signing timestamps/nonces and transport logs are separate envelopes.

Reproducible binaries require comparison. Independently rebuild base/toolchain and ABI-critical outputs on a second native worker before promotion; compare within the same target architecture. x86 and ARM binaries are not expected to match. Preserve mismatch diagnostics and scoped human exceptions when a package cannot yet reproduce. Sample less critical packages initially with visible coverage and a scheduled route to broader verification. Mark artifacts `verified reproducible`, `mismatch`, or `not checked`; neither pinned inputs nor the existing native isolation regression is a byte-reproducibility result.

## 10 · Agentic work with explicit human authority

| Action | Agent | Deterministic service | Human authority |
| --- | --- | --- | --- |
| Detect a version, advisory, or recipe diff | Summarize substantial changes and propose fixes | Fetch allowlisted feeds, compare pinned identities, deduplicate | Maintainer owns tracking policy. |
| Import a package / add a dependency | Suggest mapping, license evidence, port, or test | Validate metadata, source access policy, and limits | Area/base and security reviewers admit it. |
| Change an existing recipe | Draft minimal patch and explain upstream changes | Render/validate, bind revision/input hashes | Area plus security approval of exact revision. |
| Plan an ABI cohort | Explain findings and uncertain edges | Compute providers, graph closure, architecture matrix | Maintainer approves uncertain exceptions and removals. |
| Build/test approved work | Triage failure logs, propose fixes | Dispatch isolated jobs and evaluate required results | No new permission needed for each retry of identical approved inputs. |
| Freeze or ship a release | Draft changelog and review brief | Check applicable lane gates, sign authorized objects, activate via compare-and-swap | Release maintainer approves exact system manifest or independent OPR package/cohort; base owners join only for base impact. |
| Emergency fix or recovery | Produce evidence and options | Hold affected rollout and execute an authorized recovery plan | On-call release/security maintainers authorize expedited shipment or client recovery. |

Repository text, issue comments, PKGBUILDs, and build logs are untrusted inputs to agents. Tool permissions must prevent them from approving, merging into protected release refs, enrolling workers, changing target lists, signing, or switching channels. A human instruction in an upstream README cannot become release authorization. Keep agent model/tool versions and proposal evidence for audit, while redacting secrets and avoiding unnecessary private source retention.

Human review scales through ownership groups, reusable approved templates, precise upstream deltas, and explicit cohort approvals. One action may approve enumerated members with exact digests; blanket approval of future updates is not allowed. Require independent area and security approvers for base/toolchain changes and custom-shell exceptions; the author/agent cannot supply both roles. Release approval remains separate from code approval. Emergency exceptions have a reason, scope, expiry, approver identities, and follow-up work.

## 11 · Testable releases and changelogs

A system release candidate is installable by version from immutable repositories and has a reproducible installation image or VM image for each required platform profile. Each image records system version, resolved OPR snapshot, image recipe, kernel/boot chain, and package digests. Standalone OPR candidates use package/cohort test environments pinned to supported system versions; they do not need a new ISO. System ISO publication, website version, and release announcements consume the same approved `4.0.3` manifest, through Omarchy’s existing release coordination; they cannot independently choose newer packages.

| Test layer | Minimum gate |
| --- | --- |
| Import and metadata | Inventory reconciliation; signature/hash checks; split/any/epoch/provider cases; AUR/ALARM gaps propose OPR replacements and never resolve externally; unsafe recipe inspection stays isolated. |
| Native package build | Required outputs on both architectures, source verification, offline execution, build check phase, metadata/signature validation. |
| ABI and runtime | SONAME/symbol and language-runtime fixtures, missing build-only dependency fixture, static-link rebuild case, clean install/smoke. |
| Whole-system transaction | Fresh install; upgrade from previous stable and oldest supported upgrade baseline; rc/edge transitions; removals/replacements; interrupted download retry. |
| System/hardware | Boot and login, compositor, graphics, networking, audio, package updates, initramfs and kernel modules on each required native profile. |
| Publication and concurrency | A solo OPR app update ships without changing system `4.0.3`; ABI-coupled consumers cannot be omitted; missing output/signature prevents activation; racing promoters cannot clobber a parent; mirror lag cannot mix snapshots; stale leases/signing intents rejected. |
| Recovery and trust | Restore whole cohort; interrupted upgrade/rescue drill; key rotation/revocation; stale-manifest rejection; migration-sensitive downgrade denied. |
| Evidence and presentation | External verification succeeds without private API; each cohort phase/changelog and aggregate package diff match signed manifests; both architectures and exceptions shown; consumer/maintainer/admin journeys pass Section 12. |

Not every optional package needs a desktop integration suite. Every package needs applicable metadata/install/runtime checks; critical packages add tests matched to their actual failure modes. Keep runnable fixtures in existing Bun/Go tests, with native integration/VM harnesses for behavior unit tests cannot establish.

### Changelog contract

Generate a machine-readable diff from the relevant parent and candidate manifests first. System releases and independent OPR package/cohort releases each have their own changelog. Each release aggregates the exact approved per-cohort changelogs and their phase evidence. It includes additions, removals, renames/replacements, old/new full versions by architecture, repository changes, rebuild-only changes and causes, security references, input/base changes, tests, migration/reboot requirements, exceptions, and recovery constraints. Store its digest with the release. An agent may write a readable summary, but a maintainer edits and approves it. Never fabricate upstream release notes from version numbers.

Example format below is illustrative, not a claim about an actual Omarchy release:

```text
Omarchy 4.0.3
Previous release: 4.0.2
Targets: x86_64, aarch64
Candidate evidence: 4.0.3-rc2, followed by tested final-version artifacts

User changes
- Describe observable changes; link their reviewed source changes.

Security and compatibility
- List verified advisory references and affected packages.
- Explain ABI transitions, rebuilt consumers, and any required restart.

Package changes
- repository / package: old version -> new version, per target
- rebuild-only: same source, new pkgrel; name the triggering dependency
- removals/replacements: reason and user migration

Validation and known issues
- Link native tests, hardware profiles, reproduction results, exceptions.

Upgrade and recovery
- Full-system upgrade instructions; reboot and backup requirements.
- Previous complete release and any downgrade/data-migration limitations.
```

Show system `4.0.3` prominently in installed release status, ISO name, system update UI, and system changelog. Show independent OPR package versions and their changelogs in the package catalog/update UI, with the compatible system version beside them. Provide the digest as supporting evidence. Show package support and reproducibility coverage explicitly; do not bury ARM failures or excluded packages in logs.

## 12 · Consumer, maintainer, and admin experience

**UI is a release requirement with its own design and acceptance work—not a final styling pass.** The product must let a consumer answer “Will this work on my system, what changes, and how do I recover?” A maintainer must see “What is blocked, why, who decides, and what happens next?” An administrator must understand the operational impact of a change before authorizing it.

The source baseline already has public package search/detail/request pages, review and build pages, release batches, workers/images, audit, and team management. Reuse those routes, server-side permissions, and components; add missing domain views inside the existing SvelteKit app. Current release UI combines dev/stable batch controls and lacks a full system/OPR distinction; request detail now has blocker create/link/recheck forms and a `blocked` pill, but still lacks the proposed draft-admission lifecycle and cohort phases. Public package pages also now expose signed attestations, recipe mode, runtime coverage and historical gaps. Preserve those controls and labels while adding the missing consumer/workspace flows. Evidence: [dependency review controls](../../src/routes/maintain/requests/[id]/+page.svelte), [public evidence page](../../src/routes/packages/[name]/+page.svelte), [public navigation](../../src/lib/components/PublicNav.svelte), [workspace navigation](../../src/lib/components/MaintainerShell.svelte), [status component](../../src/lib/components/StatusPill.svelte), [release workbench](../../src/routes/maintain/releases/+page.svelte), and [existing UI design contract](../ui-design.md).

### One product language, different levels of detail

Retain the existing Omarchy-style compact masthead, semantic colors, readable monospace type, restrained motion, flat work surfaces, and dense-but-readable records. The visual style of this planning report is not a new product theme. Extend the shared design tokens/component states consistently rather than styling each new screen separately. Use spacing and hierarchy to separate explanation, evidence, and action; long IDs, hashes, agent traces, and storage paths belong in expandable evidence details.

| Concept | Consumer wording | Maintainer/admin wording |
| --- | --- | --- |
| Versioned base | “System release · Omarchy 4.0.3” | System release, exact candidate/manifest and parent |
| Standalone addition | “OPR package update · example-app 2.8.1-2” | Independent OPR package/cohort and snapshot generation |
| Required missing provider | “Waiting for a required package” | Named dependency blocker, target/constraint, proposed OPR request, owner |
| Coupled rebuilds | “These packages update together” | Build cohort with ABI/dependency reasons and complete member set |
| Phased exposure | “Testing”, “Early access”, or “Stable” with an explanation | Rollout cohort, eligibility, phase, exposure and promotion/hold evidence |
| Architecture | “Intel/AMD 64-bit (x86_64)” and “ARM64 (aarch64)” | Exact architecture plus native worker and platform profile |
| Architecture-independent output | “Same package content; tested for both targets” | `any` artifact with per-target install/runtime checks |

Channel, build phase, support, and availability are distinct fields. “Stable” never means “all architectures passed”; “built” never means “published”; “signature verified” never means “safe software”. Keep system edge/rc/stable, OPR package quarantine, and Omarchy local dev mode visibly distinct. One brief explanation sits beside unfamiliar terms; detailed docs remain one click away.

### Consumer surfaces and journeys

**Import status is maintainer-only.** Initial Arch/OPR capture, mapping, reconciliation, replacement queues and import readiness live under the authenticated workspace and private maintainer APIs. Do not publish their progress, draft decisions, internal logs or unresolved admission details on a public status page. The public surface is **Repository status**: only published system versions/OPR snapshots, channel and architecture availability, last publication/freshness, approved release notes and public service notices. Source it from published release state, never from import-job counters. An absent upstream Omarchy ARM baseline is not a public repository incident; availability describes our published ARM repositories.

Public navigation becomes **Packages · System releases · Repository status · Requests · Docs**, with Workspace available to authorized users. Browsing packages/releases/evidence requires no account. Request submission, watching progress, or feedback uses the existing identity/consent model where required.

| Surface | Required information and main action | Important states |
| --- | --- | --- |
| Package search/catalog | Select system version, channel, and target; show package version, system/OPR role, compatibility and availability; open package or request missing coverage | No results, unknown target, waiting for replacement, unavailable/unsupported target, older compatible version, withdrawn release |
| Package detail | Summary and compatibility first; changelog, prerequisites, license/publication surface, exact install steps, version history and expandable evidence | Available, incompatible, recipe-only, testing-only, blocked dependency, replacement proposed, update/recovery advisory |
| System release detail | `4.0.3`, prior version, architectures/platforms, tested candidate, human-readable changes, cohort summaries, known issues, upgrade/reboot/recovery instructions | RC, stable, rollout held, superseded, withdrawn; never present a failed candidate as installable |
| Request/progress detail | Requested package/ARM support, public reason for delay, phase timeline, linked replacement request, next responsible role and last update | Proposed, waiting for maintainer, packaging, building, testing, available, declined with public reason; no invented completion dates |
| Local update/recovery view | Current system version and OPR packages; separate system and independent OPR changes; one coherent transaction preview with removals, restarts, disk/download needs and recovery limits | Offline/stale metadata, incompatible installed package, partial download, interrupted transaction, recovery requiring local action |

A website cannot reliably infer installed architecture, package inventory, or system version from the browser. With no trusted local context, show “Choose your system” and label compatibility as a preview. Use an explicit opt-in handoff from the local client when available. Preserve the chosen context across links and show it near actions; do not silently switch ARM users to x86 or replace a pinned system version with “latest”. Never upload installed-package inventories or telemetry without consent.

For browser-only use, the primary action is **View install steps** or **Copy verified command**, not a button pretending to install remotely. A connected local client separately verifies the transaction and asks the user before changing the machine. Display reviewed package-manager actions; never suggest installing from AUR/ALARM to work around a missing OPR package. Recipe-only/local builds retain their different trust and redistribution explanation.

An ordinary OPR update clearly says **“System release remains 4.0.3”**. A required base transition instead explains which system release is needed and why the package cannot update alone. If installation is blocked, replace the install action with **View required package request** or **Request ARM support** as appropriate. A consumer follows the existing request instead of generating duplicates or seeing private review traces. Status subscriptions are opt-in and notify meaningful changes, not every polling tick.

Example consumer copy, using illustrative package data:

```text
example-app 2.8.1-2 · OPR package update
For Omarchy 4.0.3 · ARM64
Waiting for a required package

The ARM build needs libexample. Its OPR package proposal is awaiting
maintainer review. Your current installed version is unchanged.

View required package request    Read proposed changes
```

Do not show “your current installed version” unless the local client supplied that context; the public web equivalent says “No installation is available for this selection yet”. All screen prototypes use labelled fixture data, not fabricated live results.

### Maintainer workbench

Build on the blocker panel already merged in main. Replace raw request-ID entry with accessible server-backed package/request search and show candidate matches, blocked parents, source scope, target compatibility and ownership before linking. Keep its existing create-pending-request, recheck and regenerate semantics; relabeling a control must not widen its authority. Preserve explicit custom-shell/runtime-exception checkboxes in recipe review. Turn duplicated per-request context into coherent inbox/cohort navigation rather than introducing a second set of approval APIs.

Group the existing workspace into **Inbox · Catalog · Cohorts · Releases · Operations · Audit**. Inbox contains requests, dependency proposals, assigned reviews, and actionable failures. Existing Workers, Images, and Team deep links remain available within Operations; authorized admin settings stay scoped. Filters for role/area, system/OPR, architecture, phase, age, and blocker are URL-addressable and preserved across navigation. Server-side pagination/search must handle the full catalog; do not load every package into the current small local search array.

| Workbench | Screen order and decision | Required interaction |
| --- | --- | --- |
| Dependency proposal | Why needed → blocked parents/cohorts → existing provider matches → proposed source/ARM adaptation → license/trust questions → owner → action | **Admit packaging**, **Link existing provider/request**, **Request changes**, or **Decline**. Explain that admission does not publish or unblock yet. No source URL change hidden inside an approval. |
| Package/recipe review | Package identity and lane → upstream/input/recipe diff → impact → checks and custom-shell evidence → required review roles | Side-by-side or unified diffs, full changed inputs, exact reviewed revision; separate admission and recipe approvals; preserve review text on refresh/failure. |
| Cohort detail | Phase/condition and next blocker → why these members → per-architecture matrix → Changes/Phases/Tests/History → permitted action | Explain each member’s ABI/dependency cause; cross-link shared blockers; show generated phase/cohort changelogs with explicit comparison baseline and pending human edits. |
| System release | `4.0.3-rc2` or final candidate → parent/package/cohort diff → native/system evidence → changelog → rollout/recovery plan → authorization | **Freeze RC**, **Review final candidate**, **Publish Omarchy 4.0.3**, or **Hold release**, only when role and server gates permit. |
| OPR release | Package/cohort version → exact supported system snapshots → target tests → cohort changelog → publication impact | **Publish OPR cohort** without a system-version/ISO requirement. Detect actual coupling and explain if a system transition is required. |
| Build failure | Failed phase/target → concise error and affected consumers → bounded searchable logs/evidence → assigned next action | Retry identical approved work, propose a fix/new revision, or link a blocker. An agent summary links to source evidence; raw logs are secondary. |

The cohort header answers five questions without opening a log: **What changed? Why is it grouped? What phase is it in? What is blocking it? Who acts next?** Rows show native x86 and ARM results independently, including “not required for this hardware profile” with its reviewed basis. Collapsing a matrix must never hide a required failed or missing target. Bulk actions operate only on explicitly enumerated eligible members; disabled actions explain each blocking reason.

Example maintainer decision, using illustrative data:

```text
ABI cohort · libexample transition · Revision 3
Phase: Plan and admit       Condition: Blocked on ARM provider
Release policy: OPR         System compatibility: 4.0.3

libexample / aarch64 has no eligible owned provider.
Proposal: build from the recorded upstream source through omapkg.
Reference: ALARM porting patch, untrusted until reviewed.
Affected: example-app and its linked ARM build.

Admit packaging   Link existing request   Request changes   Decline
Admission starts normal packaging review. It does not authorize release.

Changes: revision 2 → 3      Phases: full history      Evidence: source records
```

### Admin and operational controls

Admin screens prioritize consequences and blocked work over decorative fleet metrics. Keep package/release approval separate from infrastructure administration; an admin role must not implicitly bypass required maintainer/security approval.

| Surface | Required visibility | Controlled action |
| --- | --- | --- |
| Ownership and admission | Unowned packages, admission policies, replacement backlog, source changes, unresolved exceptions | Assign owners; route proposals; review policy/target changes with actor, reason and affected packages. No “allow all future dependencies”. |
| Workers and images | Native target capacity, queues/leases, image digest/trust, drain state, failed checks | Enroll, drain/resume, revoke, change approved image; show impact on in-flight jobs and affected cohorts. Enrollment secrets shown once to authorized users. |
| Release/mirror health | System and OPR pointers, mirror/object verification, compatibility selection, stalled activation | Inspect/retry idempotent operations, hold rollout, launch an authorized recovery flow; never edit an immutable manifest in place. |
| Signing and trust | Signing-service availability, identity expiry/rotation status, affected historical releases | Scoped rotation/revocation workflow with required authority; never display/export private signing keys. |
| Import and migration | Full inventory denominator, replacements awaiting admission, native coverage, source evidence, existing-baseline comparison and new ARM qualification, old writer status | Resume checked batches, inspect mismatches, preview cutover/recovery impact; cutover stays blocked on required owned-package/test gaps, never merely on an absent upstream Omarchy ARM repository. |
| Team, audit and retention | Current roles, historical decisions, actor/time/reason, evidence reachability and recovery coverage | Scoped membership changes and audited exports/retention jobs; preserve last-admin and release-evidence protections. |

Admission, publication, role changes, key revocation, and recovery show a concrete review screen naming the target, exact revision/version, architecture scope, consequences, and required reason before submission. Backend rechecks authorization and evidence at submission time. A stale/conflicting decision keeps the user’s draft, explains what changed, and requires fresh review. No optimistic “Published”, “Approved”, or “Revoked” state before authoritative confirmation. Use optimistic updates only for harmless preferences with an undo/error path.

### Interaction, accessibility, and scale contract

Every new screen has designed loading, empty, error, offline/stale, denied, blocked, partial-result, and success states. State text names the cause, owner/next action, and last verified time. Long-running builds show phase and real counts rather than invented percentages or estimates. Retries preserve context and are idempotent; live events cannot steal focus, reorder a selected row, erase a draft, or scroll logs away while being read.

Use shared status, compatibility, architecture matrix, phase timeline, changelog diff, evidence disclosure, and action-review components only where they recur. Business gates and reason codes come from the server so UI, API, CLI/local client, and signer agree; disabling a browser button is not enforcement. Public projections exclude private prompts, credentials, unreviewed source text, sensitive reviewer details, and embargoed incident evidence. Render upstream/agent content as escaped untrusted text, including in diffs, Markdown summaries, and terminal logs.

Target WCAG 2.2 AA, with keyboard-complete navigation, visible focus, proper dialog focus/return, labelled fields and inline errors, text/icon state cues, accessible progress announcements, reduced motion, sufficient contrast, zoom/reflow, and usable touch targets. Automated scans support manual keyboard/screen-reader review; they do not establish compliance alone. [W3C accessibility reference](https://www.w3.org/WAI/WCAG22/quickref/)

Verify representative screens at 320, 375, 414, 768, 1440, and 1920px, plus text zoom and long real package names/reasons. Dense records stack on narrow screens; genuinely two-dimensional comparisons may scroll in a labelled region while the page and actions remain usable. Use server pagination and bounded log windows first; add virtualization only if measured catalog/workbench performance needs it. Preserve context links, browser back/forward, and meaningful page titles. Do not hide clipped content to claim a responsive pass.

### Design delivery and product acceptance

Phase 1 produces an agreed information architecture, vocabulary, annotated screen/state designs, and a clickable prototype of the key journeys. Use the existing design system. Show consumers, package reviewers, release maintainers, and admins representative tasks; record misunderstandings and revise before freezing API/action contracts. This is a planned deliverable, not a claim that the current report is a working application prototype.

Implement vertical slices with real server states and fixture-driven failure cases alongside the catalog, planner and release engine. Each phase has a UI owner and a short demo with its generated cohort changelog. Before cutover, demonstrate without moderator guidance:

1. A consumer selects ARM/`4.0.3`, distinguishes system and OPR updates, reads a cohort changelog, and finds why an app is unavailable without using an external repository.
2. A consumer follows a replacement request through admission/build/test, sees it become installable only after publication, and updates a solo OPR package without changing the system version.
3. A maintainer finds a shared AUR/ALARM blocker, links or admits one proposal, sees all affected parents, declines an alternative, and cannot mistakenly publish from the admission screen.
4. A reviewer explains an ABI cohort’s membership and phase changes, checks both architectures, edits the generated narrative, and sees stale approval invalidate after a scope change.
5. A release maintainer publishes an independent OPR cohort and a separate `4.0.3` system candidate using clearly different actions and applicable gates; neither can ship with a missing approved changelog.
6. An admin drains a worker, handles signing/mirror failure, and follows a hold/recovery procedure while preserving package/release authority boundaries and audit history.
7. These paths survive network failures, stale data, permission changes, empty/large catalogs, keyboard-only use, screen-reader review, and narrow-screen layouts without losing drafts or claiming success incorrectly.

Acceptance requires all critical tasks complete, no wrong-lane/admission-as-publication misunderstanding, no inaccessible critical action, and no misleading availability or phase status. Record findings and fixes. Product/design, package/security, release, and operations owners sign off their workflows; UI quality is an explicit cutover gate, not an optional follow-up.

## 13 · Implementation map and delivery phases

Keep the existing web/pipeline/D1/R2/Go-worker/signer arrangement. Extend its domain model before increasing catalog traffic. No new orchestration platform, packaging DSL, graph database, or autonomous approval service is required.

| Domain change | Minimum model/API change | Existing implementation to extend |
| --- | --- | --- |
| Catalog ownership/import | Collections, canonical identities, owners/profiles and import dispositions; extend existing blocker/request services with draft AUR/ALARM replacements and ARM variants | `src/lib/model.ts`, `dependency-blockers.ts`, request/revision services, factory schema and GitHub integration |
| Multiple outputs and any | Build execution architecture separate from artifact architecture; one-to-many build artifacts; expected output set | Worker protocol/metadata, worker result API, build rows, signer, public routes |
| Complete dependency universe | Add snapshot identity, per-target graph and chunked all-package locks to current frozen OPR/runtime-subset plans; preserve blockers and final frozen-version checks | `dependency-plan.ts`, `dependency-blockers.ts`, `repository.ts`, worker preparation |
| Cohorts | Cohort revision/digest, members/causes, ordered jobs, phase/condition events, per-phase and per-cohort generated changelogs, required matrix and approvals | Build scheduling, pipeline workflows, existing promotion batches |
| Versioned releases | System version plus independent OPR generations; compatibility selection and resolved transaction manifests; membership separate from artifact status | `releases.ts`, `repository.ts`, route allowlists, catalog/maintainer UI |
| Publication and trust | Repository-specific database names; lane-specific activation pointers and atomic compatibility selection; signed manifests/changelogs/attestations | Signer intents, evidence validation, release storage, D1 transaction guards |
| Omarchy integration | Version reservation, paired pins, explicit rc refs, manifest-aware refresh, versioned image/release outputs | Omarchy package coordinator and Omarchy client scripts |
| Consumer/workspace UX | Shared compatibility/phase/reason views, request progress, dependency inbox, separate release actions, scoped operations; server-backed state/permissions and public projections | Existing `src/routes` and shared components; extend `docs/ui-design.md` during implementation |

Normalize only queryable relationships; keep large immutable evidence in object storage with digest references. Migrations must preserve old dev/stable releases, signatures, rollback references, public evidence and existing blocker/graph state. Build on migrations 0026–0028; add new migration numbers instead of modifying or renumbering applied migrations. Keep evidence-v1 and worker-capability compatibility explicit during phased rollout. Retain old OPR `dev` artifacts as package quarantine; qualify them for independent OPR publication after new gates. Admit a system candidate to edge only through the system path. Do not relabel them as validated distribution releases.

### Delivery sequence

Effort bands are relative, not calendar promises: S = bounded change; M = multiple components; L = substantial infrastructure/catalog work. Put a named person against each role before implementation. Capacity measurements in Phase 1 determine dates.

| Phase | Deliverable and dependencies | Accountable roles | Exit evidence |
| --- | --- | --- | --- |
| 0 · Baseline qualification (S) | Reuse merged security/evidence/blocker implementation and recorded native rollout; pin deployment/image contracts; define additive schema/capability migration | Security lead + worker/API maintainers | Existing regressions pass; v1/historical evidence remains verifiable; runtime capability required; known external dependency/ARM bootstrap boundaries recorded. No rebuild of completed security features. |
| 1 · Inventory and contracts (M) | Capture full core/extra/Omarchy/multilib and ARM inventory; ownership/support ledger; version/channel/path schema; UI vocabulary, annotated state designs and clickable journey prototype; measure build/storage demand | Distribution lead + base/ARM + product/design owners | Every inventory row has a disposition; `4.0.3` version examples round-trip; import rerun produces same catalog digest; missing evidence stays blocked; consumer/maintainer/admin prototype tasks validate lane and admission language. |
| 2 · Catalog and import (L) | Reviewed Arch/Omarchy import, extend existing blocker actions into AUR/ALARM-to-OPR draft admission and request-progress UI, split/any outputs, canonical Git paths, source/input snapshots | Catalog + supply-chain maintainers | Import representative core, split, any, epoch, custom-hook, vendor, and ARM cases; identical rerun creates no duplicates or changed bytes. Then reconcile the entire catalog; replacement proposals are not counted as admitted or built packages. |
| 3 · Native fleet and planner (L) | Reuse native regression/images as baseline; provision reliable native capacity and OPR-owned replacement images/inputs; full dependency graph; ABI/SCC planning; cohort phase/changelog workbench and native matrix; resource limits | Build infrastructure + ABI owners | Native x86/ARM cohorts pass; missing ARM output blocks; multi-repo and static/runtime transitions work; bootstrap cycle rebuilt to final closure; blocked/changed phases generate correct immutable changelog records. |
| 4 · Versioned release engine (L) | System/OPR channel memberships and compatibility composition, full manifests, signing/activation, version allocation, cohort-generated release notes, distinct system/OPR release workspaces, fast patch and solo OPR paths | Release + signer/API maintainers | Exact bytes promoted; race/mirror tests pass; all repo database names work with pacman; final-version retest gate and version ordering pass; solo OPR shipment leaves system `4.0.3` unchanged; coupled OPR consumers block unsafe base movement; missing or stale cohort changelog approval prevents publication. |
| 5 · Omarchy client and recovery (M/L) | Update channel refresh/version reporting; paired source pins; candidate images; signed external-package replacement migration; consumer compatibility/update/request UI; independent OPR updates; complete recovery | Omarchy release/client + hardware owners | Install/upgrade/channel-switch/recovery tests on both required platforms; mutable alias limitations eliminated for supported clients; image/changelog/repo identify the same release; required AUR/ALARM replacements use eligible owned outputs and no fallback. |
| 6 · Full catalog rebuild and shadow operation (L) | Rebuild every source-buildable admitted package; inventory-wide coverage, triage, security update exercise; old service still authoritative until cutover | Package owners + operations | Full inventory accounted for; required targets and allowed exceptions explicit; all default/base profiles pass; at least two complete candidate/upgrade/recovery rehearsals; admin operations and consumer/maintainer usability/accessibility gates pass. |
| 7 · Controlled cutover and ownership (M) | Publish a coordinated Omarchy-style final version; stop old writers; migrate consenting canaries then general stable; retain recovery data | Release lead + on-call operations | Only omapkg can publish; signed source/evidence available; both targets accepted; old automation cannot mutate owned repos; native security/ABI update shipped through new flow; UI owners sign off critical journeys and every published cohort has reviewed phase/change history. |

Phases 0 and 1 can start together immediately; security v1 no longer requires a separate implementation project. New distribution publication still requires baseline qualification plus the applicable new cohort/snapshot gates. Existing OPR publication can continue through main’s verified path while these additions are developed. Prototype consumer, maintainer and admin journeys with the manifest/client contract early, but do not cut over before both publication and client coherence exist. Expand rebuild coverage in dependency order throughout later phases; do not confuse existing native container acceptance with boot/hardware qualification of the replacement system toolchain.

### Staffing, capacity, and operational ownership

Assign base/toolchain owners, package-area owners, ARM/platform owners, release maintainers, security reviewers, build/storage operations, and product/design/accessibility owners. Each delivery phase must have a UI owner, annotated states, and a working journey demo alongside its backend acceptance. Publish escalation and vacancy policy: packages without a qualified owner cannot silently continue receiving unattended changes. Security/boot incidents need staffed on-call ownership and a release authority backup.

Measure native CPU-hours per representative package family, longest critical-path build, working disk/RAM peaks, input/artifact retention, update frequency, and review throughput. Estimate daily demand as changed-package work plus reverse-dependency rebuild work plus independent verification; size each architecture separately with headroom for one large ABI cohort and worker failure. Report queue age, patch latency, blocked cohort age, architecture parity, full-catalog coverage, reproducibility coverage, and recovery success. Do not promise a fixed completion date or treat an x86 build benchmark as ARM capacity.

Retain every object reachable from supported releases, input locks, active candidates, audit/legal source obligations, and recovery windows. Garbage collection uses manifest reachability and retention policy; a “keep two package versions” rule is inadequate for long-lived snapshots. Verify restores of D1, manifests, and signing identity records. A backup that cannot reconstruct a complete release is not a release backup.

### Decisions to ratify during Phase 1

The architecture above is a concrete recommended default. Implementation kickoff should record named owners and decisions on: permitted Arch baseline bootstrap use and the separately reviewed private ARM seed plan (never AUR/ALARM release fallback); required native hardware profiles; reviewable exceptions for packages with no ARM port or redistribution rights; quarantine/canary duration and incident thresholds; supported upgrade/recovery windows; staffing and measured compute budget; and authority for reserving Omarchy version numbers. None changes full core/extra ownership, two primary architectures, human-admitted OPR replacement of AUR/ALARM dependencies, independent optional OPR releases, per-cohort changelogs, or UI acceptance.

## 14 · Evidence and document validation

Sources were refreshed against `origin/main` on 9 September 2026. The attachment is the original requirements record; main now contains the implementation and a separate recorded deployment/native acceptance report. The plan treats that report as historical evidence rather than a fresh live-environment audit. Public Omarchy Git source was inspected at the pinned commits above; host settings and current live archive coverage were not verified. Arch’s package index shows both target-specific and `any` package records; import must use a fresh captured catalog rather than a count embedded in this plan. [Arch package index](https://archlinux.org/packages/)

### Checks rerun for this refresh

At `af76fec`, local validation passed:

- **54 application tests across seven files:** dependency blockers, runtime evidence, recipes/templates, explicit review, release publication, signing control, and worker protocol (`bun test tests/dependency-blockers.test.ts tests/runtime-evidence.test.ts tests/recipe.test.ts tests/explicit-review.test.ts tests/releases.test.ts tests/signing-control.test.ts tests/worker-protocol.test.ts`).
- **9 signer tests:** central signing and independent binary/recipe evidence verification (`bun test` in `signer/`).
- **Go worker suite:** `go test ./...` in `worker/`.

Dependencies were installed from the existing frozen Bun lockfiles. No application, worker, signer, or migration source was changed for this plan refresh. Native OCI integration requires separately configured images and was not rerun; ARM/native deployment evidence remains attributed to the recorded rollout. These tests support reuse of the baseline, not acceptance of the proposed repository ownership or UI features.

The recommended transaction and repository behavior should be validated against native pacman, including version comparison, complete synchronization, repository precedence, and database naming. [Pacman manual](https://man.archlinux.org/man/pacman.8.en), [pacman configuration manual](https://man.archlinux.org/man/pacman.conf.5.en)

Markdown is the source for the accompanying HTML report. The report is local and self-contained, with no remote fonts, scripts, analytics, or build-service dependency. A supplemental Archify diagram was omitted after its readability validation failed; the full release sequence remains in Section 08. Document validation covers content parity, internal links, version examples, replacement/admission and cohort-changelog requirements, responsive layout, and print behavior. Section 12 is the proposed application UX contract; its prototype and product acceptance tests remain implementation deliverables. It is not implementation acceptance or a production test run.
