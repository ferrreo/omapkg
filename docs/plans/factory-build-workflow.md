# Factory build workflow improvements

Date: 10 September 2026
Status: implementation plan; no completion or deployment is claimed.

## Scope and required outcome

Apply this plan to every factory build path: system and OPR packages, imported/preserved recipes, generated recipes, manual/custom recipes, dependency and ABI rebuild cohorts, bootstrap/toolchain builds, and factory-produced build, runtime, and system images. Cover source inspection, recipe authoring, isolated execution, repair, review, validation, and release eligibility. No lane, origin, trigger, or batch size is exempt.

Implementing this plan does not itself authorize imports, admissions, production builds, publication, deployment, or distribution cutover. Those operational actions retain their existing authorization boundaries.

Deliver five workflow improvements and a code-quality acceptance requirement:

1. One readable, exportable package dossier.
2. An agent repair loop capped at three total builds (initial build plus two repair builds), followed by mandatory human intervention if unsuccessful.
3. Versioned templates and packaging guidance adapted from upstream where useful, with missing coverage implemented locally.
4. One local diagnostic and end-to-end factory self-check command.
5. Enforced reproducibility for every newly releasable package and image output.
6. Readable, coherent code with shared behavior implemented once and no unnecessary abstractions or generated boilerplate.

Extend the current SvelteKit, Flue/Workflow, D1/R2, Go worker, and signer implementation. Reuse existing revisions, leases, source manifests, input locks, runtime checks, and evidence contracts. Selectively adapt the comparison factory's useful build-loop, dossier, templates, and packaging guidance with licence and attribution intact. Write missing coverage locally instead of reinventing suitable upstream material.

Current source entry points include [factory](../../src/lib/server/factory.ts), [recipe templates](../../services/pipeline/recipe-template.ts), [recipe policy](../../services/pipeline/recipe-policy.ts), [workflow recovery](../../services/pipeline/workflow-retry.ts), [worker](../../worker/README.md), [release policy](../../src/lib/server/releases.ts), and [native analysis](../native-analysis.md). Reconcile ongoing main-task changes before implementation; names below describe contracts, not mandatory new tables or services.

## Integration decision: selective port, existing runtime

Keep Flue and Cloudflare Workflows. Do not adopt Swamp core, its agent-runner/software-factory extensions, Deno, or the comparison project's web app as additional runtimes. Port selected behavior into the existing implementation and remove any superseded local implementation rather than retaining parallel execution paths.

Use [omarchy-aur-factory at commit 657d9c7](https://github.com/adamhjk/omarchy-aur-factory/tree/657d9c7c95e10573952d44cdb8a3c7ea6992ac0a) as the reviewed port source. Inspect the selected files and their dependencies before importing anything. Do not vendor the whole repository or automatically follow upstream changes.

| Their component | Integration into this system |
| --- | --- |
| Analyze → author → build → audit → repair | Durable steps in our existing Cloudflare Workflow, with three total build attempts. |
| Claude CLI author/fix calls | Our Flue agent, configured model/provider, source-inspection tools, and candidate schema. |
| Audit findings passed back to the author | Structured feedback from our Go worker's build, dependency, package, and runtime checks. |
| Recipe edits between attempts | New immutable candidate revisions with complete diffs and retained evidence. |
| Package dossier | Adapt report assembly to our D1/R2 records, canonical exports, redaction, and evidence links. |
| Packaging templates, ecosystem references, and authoring guidance | Adapt useful material into our typed, versioned renderers and Flue prompts; preserve attribution and implement missing coverage locally. |
| Local namespace build harness | Our native isolated workers, frozen inputs, offline execution, and resource limits. |
| Promotion records | Our authenticated approvals, signing intents, provenance validation, and publication gates. |

Preserve the upstream Apache-2.0 licence, applicable copyright/attribution notices, and any relevant NOTICE material. Mark adapted files prominently as modified, recording upstream paths, commit, and the nature of the adaptation. Keep a concise third-party attribution record and include the licence in applicable distributions. Check selected dependencies for their own terms. Do not treat Swamp runtime source as Apache-licensed merely because this factory is; no Swamp runtime code is part of this port.

Port logic and useful regression cases selectively. Do not copy host-executed recipe inspection, unauthenticated role claims, mutable latest-result lookups across attempts, or duplicated YAML retry rounds into production. Swamp-specific storage and invocation code must be replaced with existing project primitives. The agent proposes candidates; the coordinator authorizes execution; existing security services decide signing and publication.

## 1. Unified package dossier

### Implementation

Generate a dossier from stored evidence for one exact recipe or image-definition revision and its build/repair run. Provide a maintainer page plus Markdown and JSON exports. A mutable request page may link to the latest dossier, but each completed dossier must have immutable identity and a content digest. Cohort and image dossiers link to the complete constituent package dossiers without hiding failed members.

Include:

- Request and upstream identity; source versions, commits, hashes, and verification results.
- Verified license, redistribution decision, and binary versus recipe-only surface.
- Detected build system, chosen template/version, authoring rationale, and departures requiring custom shell.
- Exact recipe and supporting-file digests; dependency and vendor locks; builder/runtime identities.
- Initial attempt and every repair: triggering findings, proposed diff, changed inputs, result, and attempt number.
- Build, lint, package-analysis, clean-install, smoke, and reproducibility results for every required architecture and output.
- Human decisions bound to exact digests; outstanding blockers; publication state and signed evidence links.
- Model identity, duration, token usage, and cost where measured. Mark unavailable values explicitly rather than estimating them.

Use deterministic rendering for factual sections. Agent rationale is attributed explanation, never evidence that a check passed. Reuse stored logs by reference instead of copying unlimited logs into the document. Exports must preserve the complete attempt/output list, with bounded linked evidence where necessary.

Public dossiers are separately redacted projections of published records. Do not expose private prompts, credentials, unreviewed source content, or embargoed findings. Escape untrusted text in the UI and render Markdown safely.

### Acceptance

- A failed initial build, two repairs, and a successful third attempt appear in correct order with separate immutable recipe identities.
- Missing checks remain missing; stale approvals never appear current.
- Re-rendering unchanged evidence produces identical canonical JSON and Markdown bytes.
- All required architectures and split outputs appear; downloads agree with the displayed evidence.
- Public and unauthorized requests cannot retrieve private dossier material.

## 2. Agent repair loop: three total builds, then human intervention

### Attempt semantics

Use user-facing attempt numbers `1`, `2`, and `3`: initial build, first repair build, second repair build. Maximum: three total candidate build/validation attempts in one run, not three retries after the initial build. Stop early on success. If attempt `3` fails, enter `needs-human-intervention`; no fourth build may be scheduled automatically.

The retry budget is durable and shared across generation, recipe validation, dependency preparation, compilation, package/image analysis, runtime smoke, and reproducibility failures. Moving to another phase, refreshing the UI, workflow redelivery, or restarting a worker must not reset it. A successful candidate builds once per required target; reproducibility validation does not schedule duplicate builds. Apply the budget per build unit and exact run, including each cohort member and image definition; automated parent/cohort retries must not create fresh runs to circumvent an exhausted member's budget.

### Execution and authority

1. A maintainer starts an explicitly bounded factory run for the admitted request, catalog recipe, cohort member, or image definition and approved execution policy. Scheduled runs must inherit equivalent explicit policy authorization.
2. Each attempt retains its candidate recipe, inputs, outputs, and deterministic failure evidence before the agent receives feedback.
3. The agent reads bounded, sanitized findings and relevant logs, then proposes the smallest justified repair as a new immutable candidate. Record the diff and explanation.
4. Revalidate recipe policy, source identity, license, dependency admission, input locks, resource limits, and isolation before executing the candidate in a fresh disposable environment.
5. Rerun every check invalidated by the change, including reproducibility-contract checks when inputs or outputs change. Reuse only evidence whose complete input binding remains unchanged.
6. On success, present the final dossier and cumulative diff for human area/security review. Require the existing exact-revision approvals before release signing or publication, including applicable system/base-owner authority.
7. On exhausted retries, retain all evidence and present the failed check, attempted fixes, and a concrete intervention form. A human may reject, edit, supply guidance, or authorize a new bounded run. Link that run to the exhausted one; retain its history and budget.

Automatic attempts are private sandbox candidates. They do not inherit distributable-build approval from an earlier recipe, publish packages, merge recipe changes, or gain access to signing secrets. Implement this distinction explicitly rather than bypassing the current exact-revision build gate. Validate distributable execution requirements before running private candidates. After final human approval, reuse the exact successful artifact whose inputs and execution evidence satisfy that contract; approval alone must not cause a redundant rebuild. Changed recipes or inputs require a new candidate attempt.

Repairs may operate automatically within the admitted source and allowed execution policy. A new source origin, license/redistribution change, unadmitted dependency, security exception, permission expansion, or request to disable a required test stops for human intervention immediately. This is a policy boundary, not a failure the agent may retry around.

Keep transient infrastructure recovery separate from recipe repair. Retrying an upload, poll, or other idempotent control operation does not consume a build attempt. Once build execution starts, that execution counts toward the three-build cap, including interrupted builds; starting it again consumes the next available attempt. If execution status is ambiguous, reconcile or stop for human intervention instead of launching an uncounted duplicate. Use stable run/attempt identifiers, atomic attempt reservation, and lease fencing to prevent duplicate scheduling and stale completion.

### Acceptance

- A controlled repairable failure succeeds automatically without asking a human between ordinary repair attempts.
- Persistent failure executes builds `1–3`, then stops and requires a human action; no fourth build is possible through an automatic path.
- Concurrent callbacks, workflow restarts, and worker loss cannot exceed the budget or mix artifacts between attempts.
- Unsafe proposed changes stop before execution; deleting tests or weakening checks cannot make an attempt pass.
- Success requires actual tool results, not an agent-written success flag.
- Human intervention creates an audited successor run; ordinary retry endpoints cannot reset an exhausted run.

## 3. Port and complete the missing template families

### Template contract

Port and adapt useful templates, ecosystem references, authoring guidance, and relevant fixtures from the pinned comparison repository. Start with its `.claude/skills/arch-packaging/SKILL.md` and `references/` material, inspecting per-file licence terms and dependencies. Record each upstream path/commit and its local destination, modifications, or reason for exclusion. Preserve applicable licence and attribution notices for code, prose, and prompt material alike.

Their reference examples and prompts are not already our executable template contract. Convert suitable material into typed schemas, deterministic command renderers, bounded Flue guidance, and meaningful fixtures. Replace Claude/Swamp-specific invocation details with our existing AI pipeline. Validate technical choices against primary build-system documentation and actual package requirements. Write new implementations where upstream lacks coverage; retain the entire required matrix below rather than reducing scope to what upstream provides.

During adaptation, remove live dependency fetching during builds, mutable source references, host execution, implicit installer hooks, and any guidance that conflicts with our review, signing, isolation, or reproducibility policy. Prefer our existing verified implementation when it already covers the behavior; do not retain duplicate upstream and local versions. Copied material remains untrusted until reviewed and tested.

Keep `make-v1` and `go-v1` immutable. The current `make-v1` is a fixed configure/make/install sequence, not coverage for every Make-based project. Introduce new template versions whenever execution semantics change, including reproducibility fixes.

Every template must define typed parameters, permitted files, pinned tool/dependency inputs, offline preparation/build/check/package stages, expected output metadata, and a meaningful runtime check. Parameters are validated values, never interpolated shell fragments. Unsupported hooks remain an explicit custom-shell candidate requiring review.

### Required coverage matrix

| Family | Required adapted or new implementation | Required validation |
| --- | --- | --- |
| Autotools | Configure/build/check/staged install; distinguish release tarballs from sources requiring a pinned autoreconf toolchain. | Library and CLI fixtures; staged paths and test execution verified. |
| Plain Make | Explicit supported build/check/install targets and staged install mappings; no assumed configure script. | Project with no configure script and a nonstandard install target. |
| CMake | Pinned generator/toolchain, out-of-tree build, offline dependency handling, CTest, staged install. | Executable plus shared-library fixture; no configure-time downloads. |
| Meson/Ninja | Pinned tools, offline wraps/subprojects, compile/test/staged install. | Subproject fixture; missing vendor input fails offline. |
| Rust/Cargo | Locked vendored crates, offline build/test, deterministic paths and profile, explicit binary/library outputs. | Workspace, multiple binaries, build-script fixture, and missing-lock rejection. |
| Python | Pinned PEP 517 backend and build requirements, offline wheel build, staged installation, controlled bytecode generation, tests. | Pure Python and native-extension fixtures. Python is a package build input, not a new factory runtime dependency. |
| Node.js | Separate pinned npm, pnpm, and Yarn adapters; exact lockfiles and offline dependency stores; reviewed lifecycle scripts. | CLI and compiled-assets fixtures for each adapter; no live registry access. |
| Electron | Pinned Electron/runtime and builder inputs, offline assets, system integration and staged application layout. | Application launch in an appropriate isolated display environment, desktop entry, icons, and runtime dependencies. |
| Prebuilt archive | Verified architecture-specific tar/zip inputs and explicit file/install mappings. | CLI and shared-library payloads; wrong architecture and unsafe archive paths rejected. |
| Debian binary package | Verified `.deb` extraction and explicit mapping into Arch layout; maintainer scripts never run implicitly. | Payload and metadata extraction, dependency mapping, license decision. |
| RPM binary package | Verified RPM extraction and explicit mapping; RPM scriptlets never run implicitly. | Payload, permissions, dependency mapping, and architecture checks. |
| AppImage | Verified extraction/repackaging, explicit bundled-versus-system runtime policy, desktop integration. | Extracted application runtime test; no implicit execution during inspection. |
| Vendor `.run` / self-extractor | Supported extraction-only formats with pinned extraction tools and explicit payload mappings. Arbitrary installers remain reviewed custom shell. | Offline extraction, no host writes, redistribution restrictions, and recipe-only behavior. |
| Script/data package | Explicit install mappings, modes, interpreter dependencies, and architecture-independent metadata. | Script execution or data-consumer check; no assumption that every package supports `--version`. |

VCS is a source mode shared by the build templates, not a duplicate build system: pin commits, submodules, and LFS objects; retain the full source bundle; never resolve a moving branch during build. Add coverage for Git sources with each applicable family.

All families must support declared split outputs, epoch/pkgrel handling, architecture-specific inputs, and `any` outputs where valid. Compose these through existing package/output contracts instead of duplicating each template for every combination. Go coverage must also include modules, offline vendoring, workspaces, CGO with pinned native dependencies, and multiple outputs; use a successor to `go-v1` where its fixed contract is insufficient.

Preserved/imported recipes and custom recipes use the same validation, repair-budget, dossier, and reproducibility-evidence contracts without being rewritten into a template merely to qualify. Repairs create explicit reviewed successors and preserve original source provenance. Image builds use versioned image definitions and complete package/tool locks through the same build-run contract; do not disguise an image definition as a PKGBUILD template.

### Acceptance

- Every row has an implemented renderer, reviewed adapted or new guidance, positive fixtures, and a failing trust-boundary fixture; copying reference files alone is incomplete.
- Every adapted file has traceable upstream provenance and required licence/modification notices; missing upstream functionality is covered by local implementations.
- Applicable source families build once per required native x86_64 and aarch64 target and pass reproducibility-contract checks. Target-specific binary payloads are labelled explicitly and cannot imply coverage for an absent architecture.
- Split outputs are all validated; no first-artifact shortcut. `any` describes content, not permission to skip required execution-target checks.
- Missing locks, downloads attempted during build, unsafe paths, shell-valued parameters, or unsupported hooks fail with an actionable diagnosis.
- Every row passes the reproducibility contract in section 5, including installer/repacking families.

## 4. One local diagnostic and factory self-check command

Provide one documented entry point, with a default read-only diagnostic mode and an explicit deep self-check mode. Implement it using existing Go/TypeScript tooling and fixture infrastructure, not a second factory implementation.

The diagnostic reports tool versions, native architecture, container isolation support, worker configuration validity, storage permissions, disk/memory capacity, and configured service connectivity. Separate required checks from optional services. Never print credential values. Return a failing exit status when required prerequisites are missing and give exact remediation steps.

Deep mode creates a disposable namespace/work directory and runs small pinned fixtures through source verification, recipe rendering or preserved-recipe admission, isolated build, clean runtime checks, single-build reproducibility validation, and dossier export. Include system and OPR policy paths, a multi-member cohort, and explicit image-check profiles where native image tooling is available. Missing required profile prerequisites are reported as incomplete, never passed. Exercise signing verification with a dedicated local test identity. Do not publish to production repositories or use production signing keys. Test repair success and retry exhaustion with deterministic injected fixture failures, avoiding live model spend by default; an explicit live-agent option can exercise the configured model with a bounded budget.

The command must work repeatedly, clean up only its own resources, preserve failure evidence on request, and distinguish skipped checks from passed checks. It must never install host dependencies, edit service configuration, or enroll a production worker as an implicit repair.

### Acceptance

- Missing tools produce concise remediation and a nonzero exit code.
- A correctly configured environment completes deep mode and exports a dossier with verified reproducibility-contract evidence.
- Failure and cancellation leave no running fixture jobs, mounted work directories, or leaked test credentials.
- Repeated runs cannot mutate real requests, builds, or repositories.

## 5. Reproducibility with one build per target

### Required behavior

Build each successful candidate once per required target. No second worker, duplicate compilation, or independent rebuild is required for normal release. Apply this to every package and image path. Repair retries execute changed candidates after failure; they are not routine reproducibility rebuilds.

Require complete evidence of retained inputs, controlled execution, deterministic packaging rules, and authenticated output identity. Preserve enough information and input bytes for independent replay later, without scheduling that replay as part of normal operation.

Prove the factory's reproducibility behavior in its test suite: build identical fixture inputs twice with a small wall-clock gap and assert byte-identical outputs. These deliberate duplicate builds belong to regression/acceptance testing, not to every normal package or image job.

**Evidence boundary:** one execution can establish input identity, observed policy compliance, and signed output identity under the trusted-worker model. It cannot alone prove that arbitrary upstream code would produce identical bytes on another execution. Provenance, an SBOM, locked inputs, and container digests are not substitutes for that proof. Distinguish reproducibility-contract-verified from independently-reproduced. Normal release requires the former; the latter requires actual matching independent reproduction evidence.

### Implementation

1. Lock and retain all recipe/supporting files, sources, commits, submodules/LFS, patches, vendor bundles, build/check/runtime packages, repository snapshots, toolchains, and images by digest. Verify consumed inputs and produce a complete offline replay manifest.
2. Use a clean isolated environment without network access, inherited host secrets/environment, or unrecorded writable caches. Fix locale, timezone, umask, build identity, logical paths, source epoch, archive ordering, ownership, compression settings, and CPU target. Derive SOURCE_DATE_EPOCH from retained source identity.
3. Apply deterministic toolchain flags and reviewed path mappings. Check timestamps, generated versions, build IDs, debug paths, random seeds, bytecode, and package metadata. Include split/debug outputs, .BUILDINFO, .PKGINFO, and .MTREE. Normalization must be a declared versioned packaging stage before final hashing.
4. Record host/kernel prerequisites and actual execution observations. Container pinning alone does not constrain clocks, entropy, CPU features, filesystem enumeration, or concurrency. Enforce controls where supported and disclose coverage limits; static inspection cannot prove arbitrary source free from nondeterminism.
5. For OCI images, control layer/configuration/manifest ordering and timestamps. For boot/filesystem images, control filesystem identifiers, partition metadata, layout, timestamps, and bootloader output. Generate machine identity and secrets at first boot rather than in shared artifacts.
6. Before building, reject missing input locks or required deterministic controls. During the single build, capture observed inputs and enforced settings separately from declarations or agent rationale.
7. After building, inspect every output for prohibited host paths, timestamp/ownership/order violations, unexpected outputs, and template-specific nondeterminism indicators. These are explicitly defined checks, not a universal determinism detector.
8. Create canonical signed evidence binding worker, run/attempt, recipe/image-definition digest, complete input digest, target, policy/template versions, checks, limitations, and every output hash. Coordinator and signer independently verify this evidence and stored artifact bytes without recompilation.
9. After final human review, sign and promote the exact successful artifact. Approval and lane promotion must not regenerate payloads. Detached signatures and execution attestations may have distinct timestamps and identities; validate them separately.
10. Route concrete contract violations into the same three-total-build repair loop. Changed inputs invalidate prior evidence and require one new candidate build. Exhaustion leaves outputs private and requires human intervention.

Adapt any existing mandatory two-build qualification gate to this explicit single-build contract. Preserve historical reproduction evidence and accept independently supplied results later; never fabricate a secondary attempt or label one build empirically reproduced. Later mismatches must surface as release incidents.

The contract is target-specific: x86_64 and aarch64 hashes need not match. An any label does not establish cross-target byte equality. Vendor repackaging records deterministic handling of exact vendor bytes, not source-build reproducibility of the vendor binary. Recipe-only and historical/bootstrap records retain their actual evidence labels.

### Mandatory two-build reproducibility tests

- Add a reusable integration-test harness around the real build and packaging code. Build fixture A to completion, wait a small explicit gap (default five seconds), then build fixture B from the exact same declared inputs. Record actual start/end times and assert the gap occurred. Keep the same pinned source epoch; do not freeze the process wall clock to conceal timestamp leaks.
- Give A and B fresh, separate build roots, distinct host work-directory paths, and no shared compiler/object/output cache. Sharing verified read-only source/dependency blobs is allowed. Invoke the actual builder twice; copying or reusing A's output cannot satisfy the test.
- Assert equal complete output-name sets, equal sizes, and equal SHA-256 digests, then compare the final unsigned payload bytes directly. Include every split/debug package and the complete compressed archive, including metadata. For OCI and boot images, compare their declared reproducible payloads rather than invocation-specific signatures or attestations.
- On failure, preserve both outputs and their logs/input/environment evidence. Produce an archive-metadata and payload diff; use diffoscope where useful. The test fails on any final-byte difference, even if extracted payload files match. Do not normalize artifacts inside the test to make a mismatch pass.
- Exercise each adapted or new template family, preserved/custom recipes, bootstrap/toolchain paths, cohort outputs, and image builders with small representative fixtures. Run each applicable architecture pair natively: compare x86_64 A with x86_64 B, and aarch64 A with aarch64 B. Missing native capacity makes that acceptance incomplete, not passed.
- Include a deliberately nondeterministic fixture that embeds real build time or host paths. Confirm the two-build test detects it, then confirm the corrected deterministic fixture passes. This verifies the comparator and isolation setup, not merely the happy path.
- Run affected reproducibility pairs when template, toolchain/image, source preparation, packaging, or worker execution changes; run the complete matrix in the build-system acceptance suite. Longer-running image cases may use a separate integration-test job, but remain required acceptance coverage. Store exact fixture/input/template/environment identities and both output hashes with test results.
- Successful tests establish byte reproducibility for the tested fixtures and environments. Normal jobs use that tested implementation and their single-build evidence; they must not claim their own specific artifacts were independently rebuilt when only the fixture was.

### Acceptance

- Instrument scheduling to prove one successful build per required target, including after final approval and promotion.
- The integration suite performs two real builds separated by the recorded time gap and fails unless all final unsigned output bytes match. The intentionally nondeterministic fixture must fail this comparison.
- Seeded path leaks, timestamp/ownership/order violations, missing locks, mutable inputs, unexpected outputs, and stale evidence fail applicable checks and block signing/publication.
- Replay manifests resolve all declared inputs to retained verified bytes and record commands/environment without live mirrors. Completeness checks do not launch another build.
- Dossier/API/signing labels distinguish contract verification, unknown coverage, historical evidence, and independently observed reproduction.
- System/OPR, preserved/custom, bootstrap, cohort, OCI, and boot-image paths enforce the same contract before release or trusted-environment activation.
- Repairs produce fresh evidence; the third failed build stops for human intervention.

## 6. Readability, maintainability, and duplication

Review the whole application, AI pipeline, workers, signing services, build scripts, and tests for code quality. Apply these standards to every new or adapted change. Inventory existing problems across the codebase; resolve them in focused, behavior-preserving changes rather than mixing an indiscriminate rewrite into the port.

### Required standards

- Trace the real flow and all callers before changing shared behavior. Reuse existing implementations first, then standard-library/native features; introduce new abstractions only for an actual repeated need.
- Give each piece of state one authoritative owner. Implement retry accounting, candidate validation, evidence binding, and publication policy once, with callers using the same implementation wherever the runtime boundary permits. Across trust/runtime boundaries, retain necessary independent verification and use shared contracts and conformance fixtures to prevent drift.
- Keep orchestration separate from model prompts, build execution, evidence rendering, and release authority. Each function/module should have one clear responsibility and a readable control flow. Split large files by real responsibilities, not arbitrary line counts or one-function-per-file rules.
- Use precise domain names, typed inputs/results, and explicit state transitions. Avoid catch-all option bags, boolean mode combinations, deeply nested conditionals, speculative interfaces, pass-through wrappers, and factories with no demonstrated need.
- Extract repeated behavior only when semantics match. Similar-looking code with different security responsibilities must not be merged merely to reduce line count. Avoid both copy-pasted retry stages and a generic workflow language built for one loop.
- Remove dead branches, obsolete adapters, duplicate helpers, stale comments, and superseded tests after callers migrate. No new test-only schema fallbacks, blanket catches, invented success values, or silent error suppression in production code.
- Keep comments focused on intent, invariants, trust boundaries, and non-obvious constraints. Remove narration of obvious code, promotional descriptions, repeated design essays, and unsupported claims about safety or completeness.
- Tests must assert observable behavior and failure boundaries, not merely repeat implementation logic or snapshot incidental formatting. Keep only fixtures/mocks needed to exercise meaningful cases; share setup when it remains easy to understand.
- Preserve validation, authorization, cancellation, resource bounds, and data-loss prevention while simplifying. Necessary security checks are not boilerplate to delete.

### Acceptance

- Produce a repository-wide findings ledger naming concrete locations, impact, and disposition. Address maintainability blockers; explicitly track remaining nonblocking debt instead of claiming every file is clean.
- A reviewer can follow request → candidate → build → repair/intervention → review → publication without tracing multiple competing state machines or hidden side effects.
- No duplicated retry engine, candidate authority, or dossier renderer remains after migration. Any necessary cross-runtime duplication is identified and covered by conformance tests.
- Adapted upstream code uses local naming, types, error handling, and storage conventions while preserving legally required notices. No unused compatibility layer remains solely to resemble upstream.
- Each change has relevant behavioral checks, passes type/lint checks, and leaves no unresolved correctness, security, or significant maintainability finding. Use focused follow-up changes for existing issues outside the port's immediate flow.
- Final review records what was deleted, consolidated, or deliberately retained and why. Do not use raw line-count reduction or an automated style score as a substitute for a readable implementation.

## Delivery sequence and completion evidence

| Step | Deliverable | Verification before proceeding |
| --- | --- | --- |
| A | Agree contracts and selected upstream port scope; inventory repository-wide quality issues. | Trace all build/sign/publication entry points, identify reusable implementations, record licence obligations and additive migration needs. |
| B | Dossier projection and local diagnostic skeleton using existing records. | Rendering, redaction, missing/stale evidence, and prerequisite checks pass. |
| C | Single-build production validation plus the two-build reproducibility test harness, initially using existing Make/Go fixtures. | Test pairs separated by a wall-clock gap produce identical bytes; seeded nondeterminism is detected. Normal release paths build once and enforce evidence checks. |
| D | Durable three-total-build agent loop with private candidates and human intervention. | Repair success, exact exhaustion, policy-stop, restart, and concurrency scenarios pass. |
| E | Port suitable templates/guidance, implement missing families, and complete deep self-check. | Full coverage matrix, upstream attribution, and all offline, runtime, split-output, architecture, and reproducibility-contract fixtures pass. |
| F | Integrate maintainer/public journeys and document operation. | Maintainer can inspect all attempts, intervene, review final bytes, and publish only when every gate passes. |
| G | Complete code-quality review and remove superseded implementations. | Readable end-to-end flow, no duplicate engines, required checks passing, and remaining nonblocking debt explicitly recorded. |

Record the implementation commit, migrations, exact fixture sources, template/image-definition versions, native worker/environment identities, input/output/evidence hashes, failed-case results, and UI findings in the acceptance record. Maintain a build-path coverage matrix listing every trigger and output type with its shared retry/reproducibility enforcement point. Report completion by these outcomes, not by files created or test counts alone. No imports or production package/image publication are part of implementing this plan unless separately authorized.
