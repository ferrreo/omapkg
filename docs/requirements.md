# omapkg requirements

Planning baseline extracted from [`proposal.md`](./proposal.md), `chart.avif`, and the current product brief. Leave every item unchecked until implementation and verification prove it. "Must" means release-blocking; "decision" means work cannot close without an explicit choice.

## Definition of done

- [ ] A maintainer can sign in with GitHub OAuth, review a package request, approve the generated PKGBUILD diff, observe every pipeline stage, and promote a tested batch.
- [ ] A public user can discover a package, verify its provenance and signature, and install a stable Surface A package with Arch tooling.
- [ ] A public user can use a Surface B recipe whose build fetches the vendor bytes at a pinned URL and checksum; omapkg does not redistribute those bytes.
- [ ] A request containing a package name, description, declared license, and upstream Git or source archive URL can produce a reviewed and buildable Arch package on both supported architectures.
- [ ] A registered Linux host can run the worker daemon, receive a scoped job, build inside a disposable offline environment, upload an attestation and artifact, and never receive the signing key.
- [ ] A failed check or opted-in crash signal can return a package to dev, and a stable rollback can make the previous published version available without deleting historical artifacts.
- [ ] The system has a tamper-evident audit trail for every security-sensitive action and exposes appropriate views to maintainers and the public.
- [ ] Deployment uses the latest supported SvelteKit and Effect 4.x with the Flue 2.x-or-newer AI layer, pinned and recorded at release time.

## Requirements from proposal

### Scope and package surfaces

- [ ] **SCOPE-01** omapkg builds on Arch and replaces the AUR submission layer. It does not become a new distribution.
- [ ] **SCOPE-02** Keep Arch `core` and `extra` as upstream inputs in the first release. Defer rebuilding them to a later project.
- [ ] **SCOPE-03** Keep the `PKGBUILD` package format. Reuse Arch devtools and normal Arch build mechanics.
- [ ] **SCOPE-04** Only project-generated PKGBUILDs enter the build pipeline. Outsiders may submit requests, but cannot submit executable packaging code for automatic execution.
- [ ] **SCOPE-05** Host and sign Surface A binaries only when the package and dependency licenses permit redistribution.
- [ ] **SCOPE-06** Publish Surface B recipes for non-redistributable software. Recipes fetch pinned source bytes and checksums directly from the vendor; omapkg does not host those vendor bytes.
- [ ] **SCOPE-07** Every package has an explicit surface, license/provenance record, source record, architecture set, and channel state.
- [ ] **SCOPE-08** Product wording must describe its limits. Release controls target package attacks and supply-chain tampering; harmless breakage remains a report-and-fix concern. Wording must not imply that arbitrary upstream software is guaranteed to work or that attacks are mathematically impossible.

### Request intake and source provenance

- [ ] **REQ-01** A request contains a package name, description, declared license, upstream URL, source kind (`git` or archive), and selected ref/version where applicable.
- [ ] **REQ-02** Source URLs support arbitrary trusted Git hosts and source tar URLs, subject to explicit protocol, size, redirect, archive, and network safety policies.
- [ ] **REQ-03** Resolve mutable Git branches and moving archive URLs to immutable commit or byte digests before the build. Record the resolved ref, URL, redirects, and hashes.
- [ ] **REQ-04** Private source support requires an explicit decision. If supported, scope credentials to one source fetch. Never expose them to the agent or build, or store them in logs or generated PKGBUILDs.
- [ ] **REQ-05** Every request is assigned a lifecycle state: submitted, area review, security review, generating, generated-review, source verification, building, dev, stable, rejected, blocked, or rolled back.
- [ ] **REQ-06** Place requests in category queues such as desktop, gaming, or productivity. A maintainer with the matching area role can claim, approve, deny, or return a request.
- [ ] **REQ-07** Security sign-off is required at the policy-defined points, including initial package creation and changes that alter sources, build commands, dependencies, install scripts, or generated metadata.
- [ ] **REQ-08** Use the configured recipe Git repository, such as `owner/recipes`, as the canonical source of truth. Link requests, generated PKGBUILDs, metadata, and review history to commits and pull requests.
- [ ] **REQ-09** Present every factory-generated change as a reviewable diff and pull request. The factory cannot directly publish a build or bypass the review gate.
- [ ] **REQ-10** Automated upstream release detection resolves new versions and checksums, opens a PR, and waits for maintainer approval. It cannot auto-merge to stable.

### Agentic factory

- [ ] **AI-01** Use Flue `>=2.0` for the AI layer, with the exact package/release pinned, and use Effect `4.x` for typed workflows, errors, and resource lifetimes.
- [ ] **AI-02** AI Gateway fronts model calls, applies account-level routing and budgets, and records model/version/inputs by digest without retaining secrets or unnecessary source content.
- [ ] **AI-03** The factory agent must inspect the declared upstream source, infer package metadata, generate a PKGBUILD, produce a dependency/vendor plan, and explain its proposed changes.
- [ ] **AI-04** Allowlist agent tools and run them in a sandbox with no signing credentials, OAuth secrets, worker enrollment secrets, or production write access.
- [ ] **AI-05** Treat hostile upstream README files, build scripts, package metadata, issue text, and source archives as data. Instructions in those inputs cannot change policy, permissions, destinations, or approval state.
- [ ] **AI-06** Make the generated PKGBUILD, `.install` scripts, source lists, checksums, dependencies, license findings, and SBOM reviewable outputs. A prose explanation cannot replace a diff or machine check.
- [ ] **AI-07** Fail closed when the factory cannot resolve an immutable source, determine a required license decision, satisfy policy, or produce a complete manifest.
- [ ] **AI-08** Require human maintainer approval after generation and before any build that could become distributable. Record requestor confirmation as feedback only; it cannot promote a package.

### Source verification and dependency handling

- [ ] **VERIFY-01** During online verification, fetch the exact declared sources in a no-secrets sandbox and check the URL, redirect, digest, archive shape, declared version, license evidence, and source manifest.
- [ ] **VERIFY-02** Resolve lockfiles and dependency sources during verification. Prefer Arch/omapkg packages where available and record every component digest.
- [ ] **VERIFY-03** Allow vendoring when needed. The factory creates the vendor bundle during online verification, emits an SBOM, seals the bundle, and hands only the sealed bytes to the offline build.
- [ ] **VERIFY-04** Build-time network access is disabled. No `cargo fetch`, `npm install`, language package download, vendor refresh, or equivalent network mutation may occur during the offline build.
- [ ] **VERIFY-05** The build consumes a content-addressed source/dependency cache whose manifest is bound to the reviewed commit and generated PKGBUILD.
- [ ] **VERIFY-06** Source archives and extracted trees are checked for path traversal, unsafe links, duplicate files, oversized expansion, unsupported formats, hooks, submodules, LFS behavior, and other policy-defined hazards.
- [ ] **VERIFY-07** Verification records enough provenance to reproduce the input set: source URLs and redirects, immutable refs, digests, dependency graph, toolchain/container digest, architecture, environment, and `SOURCE_DATE_EPOCH`.

### Build, attestation, and signing

- [ ] **BUILD-01** Run builds in a disposable isolated environment using Arch devtools. Packages that declare both architectures require x86_64 and aarch64 coverage.
- [ ] **BUILD-02** The worker environment has no network during the build and no access to platform production credentials or signing material.
- [ ] **BUILD-03** Emit package files, repository metadata inputs, logs, test results, an SBOM, and a provenance attestation tied to source and manifest digests.
- [ ] **BUILD-04** Reproducibility inputs are applied from the first release: `SOURCE_DATE_EPOCH`, pinned build images/toolchains, recorded environment, and controls for timestamps and build paths. Bit-for-bit verification is a later milestone, not a current promise.
- [ ] **BUILD-05** A separate signing service signs only artifacts whose attestation, manifest, policy checks, review commit, and worker job identity validate. Fail closed on any mismatch.
- [ ] **BUILD-06** The signing key remains in a KMS or equivalent isolated key service and is never present on a worker, in the daemon image, in a build cache, or in logs.
- [ ] **BUILD-07** Arch repository and package signatures can be verified by a clean Arch client using the published keyring. Key rotation, revocation, and recovery are defined before stable release.
- [ ] **BUILD-08** Use a verification script to detect tracked files changed outside the approved pipeline and record the result as a release gate.
- [ ] **BUILD-09** Build and signing failures leave no partially trusted publication and produce a maintainer-visible reason with a correlation ID.

### Linux worker daemon and registration

- [ ] **WORKER-01** Deliver the worker daemon as a small Linux executable in the chosen language (Rust or Go), with versioned install and upgrade instructions and system-service integration where supported.
- [ ] **WORKER-02** Enroll each fresh host through a short-lived, single-use registration flow. Do not accept long-lived shared worker tokens as worker identity.
- [ ] **WORKER-03** Give each worker a revocable identity, capability declaration, architecture record, software version, heartbeat, and last-seen state.
- [ ] **WORKER-04** Dispatch jobs with short-lived, scoped leases bound to one job, worker identity, expected architecture, input manifest, and output destination. Reject replays and duplicate completions.
- [ ] **WORKER-05** Worker communication is authenticated and encrypted; the default deployment requires outbound connectivity and no publicly exposed worker control port.
- [ ] **WORKER-06** Before execution, the daemon verifies job manifests and platform policy. It runs one disposable offline build environment per job and destroys it after completion or timeout.
- [ ] **WORKER-07** The daemon exposes no signing key and receives no broader Cloudflare, GitHub, OAuth, or KMS credentials than a job needs. Secrets are redacted from command output and uploaded logs.
- [ ] **WORKER-08** Let operators pause, revoke, drain, and remove workers. Revocation prevents new jobs and invalidates active leases according to the recovery policy.
- [ ] **WORKER-09** DigitalOcean droplets are the initial operating target, while the same daemon can be installed on supported Linux hosts. Host prerequisites, privileges, container/chroot runtime, disk, memory, architecture, and cleanup guarantees are documented.
- [ ] **WORKER-10** Worker updates are signed or otherwise authenticated, rollbackable, and audited.

### Dev, stable, promotion, and recovery

- [ ] **RELEASE-01** Send every successful build to dev/quarantine first. No build goes directly to stable.
- [ ] **RELEASE-02** Make promotion criteria explicit and machine-checkable: minimum dev time, required smoke tests, no disqualifying crash reports, dependency readiness, and maintainer decision. Treat requestor feedback as evidence, not authority.
- [ ] **RELEASE-03** Stable promotion is a maintainer action on dependency-compatible batches. Publish atomically from a client's perspective; partial metadata must not expose a broken dependency set.
- [ ] **RELEASE-04** Demote or quarantine affected packages after failed checks or policy-defined crash signals, and alert maintainers with evidence.
- [ ] **RELEASE-05** Every published version remains addressable in R2 under an immutable key, including versions later withdrawn from stable.
- [ ] **RELEASE-06** A rollback removes the affected version from the stable index, identifies a compatible previous version, updates repository metadata atomically, and provides an automatic downgrade or operator action with an auditable reason.
- [ ] **RELEASE-07** Package dependency relationships, soname-sensitive batches, and promotion order are represented in release metadata and tested before publication.
- [ ] **RELEASE-08** Crash reporting is anonymous and opt-in, with a published data policy, retention period, redaction rules, disable control, and package/channel linkage.

### Storage, APIs, and Cloudflare architecture

- [ ] **CF-01** SvelteKit is the web application framework and is deployed using the latest supported Cloudflare adapter/runtime at implementation time; the exact versions are locked in the repository.
- [ ] **CF-02** Cloudflare Workers provide the edge/API surface, request validation, rate limits, cache headers, and public catalog delivery.
- [ ] **CF-03** D1 stores relational control-plane metadata needed for users, roles, requests, package versions, jobs, workers, approvals, and searchable audit indexes. It is not the source of truth for immutable artifacts.
- [ ] **CF-04** R2 stores immutable package artifacts, recipes, source/dependency bundles where policy permits, SBOMs, attestations, logs, repository snapshots, and historical versions. Access policies prevent accidental overwrite or public exposure of maintainer data.
- [ ] **CF-05** Workers KV is used only for suitable derived/cache/config data with an explicit invalidation path; correctness-critical state remains in D1, R2, or the workflow state model.
- [ ] **CF-06** Durable Objects provide serialization/coordination for package or build state only where needed, such as one active promotion or lease owner. The design has one authoritative state owner and no silent divergence between D1 and objects.
- [ ] **CF-07** Cloudflare Workflows orchestrate long-running, retryable pipeline stages and resume from recorded stage boundaries without duplicate signing or publication.
- [ ] **CF-08** Cloudflare Sandboxes isolate the factory and online source-verification work where their supported runtime and architecture fit. Offline Arch builds still require the registered worker path when Cloudflare Sandboxes cannot provide the required isolation or architecture.
- [ ] **CF-09** AI Gateway fronts all production model calls and provides budget, routing, observability, and emergency disable controls.
- [ ] **CF-10** R2/CDN publication uses immutable object names, signed or integrity-checked repository metadata, cache invalidation/versioning, and an atomic index switch to avoid cache poisoning or partial updates.
- [ ] **CF-11** The platform remains operable if a derived cache, one worker, one workflow attempt, or one edge location fails; retries are bounded and idempotent.
- [ ] **CF-12** The Cloudflare account, zone, API token scopes, bindings, quotas, service availability, and data-retention settings are documented without committing secrets.

### Authentication, authorization, and audit

- [ ] **AUTH-01** Better Auth provides GitHub OAuth login with secure state/redirect handling, protected session cookies, CSRF protections appropriate to the chosen session flow, and logout/revocation behavior.
- [ ] **AUTH-02** GitHub OAuth client secrets, Better Auth secrets, and Cloudflare credentials are stored as deployment secrets and never committed, sent to agents, or emitted in logs.
- [ ] **AUTH-03** Enforce maintainer access through server-side roles. Area maintainers, security reviewers, release maintainers, and administrators have least-privilege permissions; hiding controls in the UI is not authorization.
- [ ] **AUTH-04** Require the appropriate role for promotion, signing approval, worker enrollment, policy changes, rollback, audit export, and role changes. Record the actor, target, decision, reason, request/job/package IDs, timestamp, and result.
- [ ] **AUTH-05** Public catalog and package downloads expose only data explicitly marked public. Internal prompts, secrets, private source URLs, worker details, and sensitive logs remain restricted.
- [ ] **AUDIT-01** Record audit events for authentication, request changes, source resolution, factory runs, agent tool calls, generated diffs, reviews, verification, worker registration/leases, builds, tests, attestations, signing, publication, downloads where policy requires, demotions, rollbacks, policy changes, and administrative access.
- [ ] **AUDIT-02** Audit records are append-only or tamper-evident, time ordered, correlated across services, exportable, redacted for secrets/PII, and retained for a defined period.
- [ ] **AUDIT-03** Failed and denied actions are logged with a safe reason. Audit storage failure cannot silently turn a successful signing or promotion into an unaudited action.

### Public and maintainer product surfaces

- [ ] **UI-01** The public surface provides package search/browse, package detail, version/channel history, architecture availability, license/provenance, source digest, checksums, signatures/keyring instructions, SBOM/attestation links, build/test status, and safe download/install instructions.
- [ ] **UI-02** The maintainer surface provides request queues, area/security review, generated diffs, source and dependency manifests, agent/build logs, worker health, test evidence, promotion batches, crash reports, rollback controls, and audit search.
- [ ] **UI-03** Public and maintainer views are implemented in SvelteKit and follow the Omarchy design language: clear hierarchy, keyboard navigation, responsive layouts, readable terminal/build output, and accessible status/error states.
- [ ] **UI-04** Before a destructive or release-affecting action is submitted, maintainer controls show the exact action, affected package/version/batch, evidence, and resulting audit event.
- [ ] **UI-05** Public pages do not imply trust based on requestor identity. They show machine evidence and maintainer decisions instead.
- [ ] **UI-06** Visual acceptance covers desktop and mobile layouts, reduced motion, contrast, focus order, screen-reader labels, and no exposure of secrets in rendered or client-side data.

### MCP and agent access

- [ ] **MCP-01** After compatibility is verified, the first MCP release implements the proposal's read-only interface against the specified 2026-07-28 protocol/schema target.
- [ ] **MCP-02** MCP exposes package, build, test, provenance, and metrics queries with cache hints and stable pagination. It does not gain write or promotion authority in the first release.
- [ ] **MCP-03** MCP responses are stateless and safe to cache where marked. Maintainer authorization for private queries is explicit and separate from public catalog access.
- [ ] **MCP-04** Agent access observes the same redaction, rate, audit, and provenance rules as the UI/API.

## Conflicts and proposed resolution

| Proposal statement | User-directed change | Resolution to carry into the plan |
| --- | --- | --- |
| Static CDN front ends; no database/application | Latest SvelteKit, GitHub login, maintainer area, full audit logs | Treat this as an explicit v1 override. Use SvelteKit/Workers for public and authenticated surfaces, D1 for control-plane/audit indexes, and R2 for immutable data. Keep catalog files cacheable and static where useful. |
| Stateless core and read-only MCP | Fully agentic platform with authenticated maintainers | Keep MCP read-only/stateless in v1. Put mutations behind Better Auth, RBAC, PRs, and explicit maintainer approvals. "Agentic" automates evidence and proposals; it does not auto-promote. |
| Self-hosted ephemeral x86_64/aarch64 workers | DigitalOcean droplets initially; daemon installable on any Linux host | Use droplets as initial hosts and daemon enrollment as the worker contract. The host may persist, but each job must use a disposable isolated build environment. |
| Only package name/upstream URL request | Build from any Git host or source tar link | Keep request intake code-free while accepting generic Git/archive URLs. Resolve all mutable inputs to immutable bytes before generation/build. |
| No external PKGBUILDs | Fully agentic generation | Upstream code remains hostile input; only factory output can become the project PKGBUILD after human review and policy gates. |
| Signing key never on a worker | Cloudflare/self-hosted build infrastructure | Keep the isolated KMS signing service. Neither Cloudflare secrets nor worker credentials may provide raw signing-key access. |

## Decisions and external inputs required

- [ ] **DEC-01** Confirm what "Flue" means: canonical package/repository, supported model providers, exact `>=2.0` release, runtime compatibility with Workers/Sandboxes, and license.
- [ ] **DEC-02** Confirm the exact Effect `4.x` package/release and APIs to pin. Record whether the requested version is available for the chosen runtime.
- [ ] **DEC-03** Choose Rust or Go for the daemon. Record support policy, license, release/update channel, and minimum Linux/kernel/runtime prerequisites.
- [ ] **DEC-04** Confirm the canonical GitHub organization/repository (for example, `owner/recipes`), default branch, PR policy, CODEOWNERS, and whether upstream private repositories are in scope.
- [ ] **DEC-05** Choose public hostname(s), Cloudflare zone/account, preview environments, deployment ownership, and data residency/retention constraints.
- [ ] **DEC-06** Provision Cloudflare resources and least-privilege bindings: Workers, SvelteKit adapter, D1 database(s), R2 bucket(s), KV namespace(s), Durable Objects, Workflows, Sandboxes, and AI Gateway. Record quotas and runtime or regional limits.
- [ ] **DEC-07** Choose KMS/signing provider, Arch signing algorithm/keyring distribution, key rotation/revocation process, quorum/approval policy, and disaster recovery owner.
- [ ] **DEC-08** Create GitHub OAuth application credentials and callback URLs. Define which GitHub organization/team membership maps to each maintainer role.
- [ ] **DEC-09** Define source policy: accepted URL schemes, archive formats, redirects, submodules/LFS, source size/timeout limits, private-source behavior, vendor allow/deny rules, and SSRF egress controls.
- [ ] **DEC-10** Define Surface A license acceptance rules and Surface B vendor/legal policy, including who makes exceptions.
- [ ] **DEC-11** Set dev quarantine duration, smoke-test matrix, crash thresholds, dependency-batch algorithm, stable promotion quorum, rollback trigger, and downgrade behavior.
- [ ] **DEC-12** Set audit retention, append-only/tamper-evidence mechanism, searchable fields, PII policy, export format, and who can read or export records.
- [ ] **DEC-13** Define anonymous crash-report fields, endpoint, opt-in UX, retention, redaction, and public data policy.
- [ ] **DEC-14** Confirm the MCP schema/protocol target, public versus authenticated query set, pagination/cache semantics, and hosting hostname.
- [ ] **DEC-15** Select initial curated packages and architecture coverage for the first release; define success volume and cost limits for workers, R2, D1, model calls, and Sandboxes.
- [ ] **DEC-16** Keep the local Cloudflare token outside version control. Before deployment, create scoped, environment-specific tokens and document rotation/revocation. Never place the token or generated credentials in this repository.

## High-risk claims and release gates

The proposal's "no package attacks the user" promise is a security objective, not a proof. Demonstrate the following controls before stable publication:

- [ ] **RISK-01: Hostile upstream input.** README text, build scripts, archive contents, Git hooks, submodules, and install scripts can prompt-inject the agent or execute during packaging. Agent tools, source parsing, PKGBUILD execution, package install testing, and publication are isolated and policy-gated.
- [ ] **RISK-02: URL and archive attacks.** Git refs can move; redirects can change; archives can traverse paths, exhaust disk/CPU, or reach cloud metadata/internal addresses. Fetchers use immutable digests, bounded resources, safe extraction, redirect recording, DNS/IP egress filtering, and no platform secrets.
- [ ] **RISK-03: Verification/build mismatch.** The offline build must consume the exact sealed bytes verified online. Manifest digests, content-addressed storage, locked inputs, and a build-time network deny test prove no TOCTOU substitution.
- [ ] **RISK-04: Package execution at install time.** Arch package files and `.install` hooks can run with user/root privileges. Static checks, isolated install smoke tests, review of privileged paths/hooks, and a deny policy for unacceptable behavior are required.
- [ ] **RISK-05: Dependency and vendor substitution.** Lockfile, checksum, license, dependency graph, and SBOM must be bound to the reviewed generated diff. Mutable registries and vendor responses cannot silently change a build.
- [ ] **RISK-06: Agent authority.** A model may hallucinate commands or follow hostile instructions. It receives no credentials or promotion authority; deterministic validators and human approval remain authoritative; model/tool calls are bounded and audited.
- [ ] **RISK-07: Worker compromise.** A malicious or compromised host must not forge a trusted build or steal the signing key. Worker identity, lease binding, attestation validation, disposable isolation, upload integrity, revocation, and KMS-side policy are required.
- [ ] **RISK-08: OAuth/RBAC failure.** GitHub identity or client-side claims must not grant maintainer actions. OAuth state/redirect/session protections, server-side role checks, least privilege, revocation, and audit events are required.
- [ ] **RISK-09: Publication/cache failure.** CDN cache poisoning or partial repository indexes can break or replace packages. Immutable R2 keys, signed metadata, atomic index switches, cache versioning, and clean-client verification are release gates.
- [ ] **RISK-10: Rollback limits.** Removing a stable index entry does not repair installed systems. Previous versions, compatible downgrade metadata, operator/user action, and a tested recovery path must remain available.
- [ ] **RISK-11: Audit integrity.** A successful signing, promotion, or role change without an audit record is a control failure. Audit writes are correlated, tamper-evident, redacted, retained, and fail closed for security-sensitive actions.
- [ ] **RISK-12: Abuse and cost.** Public requests, source fetches, agent calls, and builds can be used for denial of service or unexpected spend. Rate limits, quotas, size/time limits, cancellation, per-stage budgets, and operator kill switches are required.

## End-to-end acceptance criteria

The release is complete only when these scenarios pass in a test environment with disposable credentials and representative public sources, then pass again for the first production package set.

### E2E-01: Git source to signed Surface A package

- [ ] **Given** a public Git repository on a non-GitHub host with an immutable commit and a redistributable license, **when** a user submits its name and URL, **then** the request is validated, queued, assigned an ID, and visible in the public/maintainer views at the correct privacy level.
- [ ] **When** an area maintainer and required security reviewer approve intake, **then** the Flue factory runs in its no-secrets sandbox, uses Effect-typed workflow/error handling, and opens a pull request in the configured recipe repository containing the generated PKGBUILD, source digest/ref, dependencies, license record, and review evidence.
- [ ] **When** a maintainer approves the generated diff, **then** online verification seals exact source/dependency bytes, emits SBOM/provenance, and records all digests before a build lease is issued.
- [ ] **When** an enrolled x86_64 or aarch64 daemon receives the lease, **then** it verifies identity and manifest, builds with network denied in a disposable Arch environment, runs required checks, uploads artifact/attestation/logs, and destroys the environment.
- [ ] **When** the KMS signing policy validates the attestation and review commit, **then** the artifact and repository metadata are signed without exposing key material to the worker, and the package is published only to dev.
- [ ] **When** quarantine time and smoke-test criteria pass and a maintainer promotes the dependency batch, **then** stable R2/CDN metadata switches atomically and a clean Arch client verifies the keyring, repository signature, package checksum, and package installation.
- [ ] **Then** public package detail shows source, license, architecture, version, channel, checksums, signatures, SBOM/provenance, tests, and relevant history; maintainer detail shows the private evidence and full audit trail.

### E2E-02: Source tar to Surface B recipe

- [ ] **Given** a vendor source tar URL that omapkg is not legally allowed to redistribute, **when** a user submits the URL and declared checksum, **then** the factory verifies the vendor bytes online, generates a recipe with the pinned URL/checksum, and does not place the vendor archive or built proprietary bytes in omapkg-hosted artifacts.
- [ ] **When** a user builds the recipe, **then** the build fetches only the declared vendor bytes, fails on checksum mismatch, and produces a reviewable log/result without weakening omapkg's source or signing controls.

### E2E-03: Failure, demotion, and rollback

- [ ] **When** a smoke test fails, a disallowed network access is detected, an attestation mismatches, or a policy-defined crash signal arrives, **then** the package remains out of stable or returns to dev, maintainers receive evidence, and the action is audited.
- [ ] **When** a stable package is rolled back, **then** the stable index no longer selects it, the previous compatible version remains downloadable from immutable R2 storage, repository metadata stays signed/atomic, and the documented downgrade path works on a clean Arch client.

### E2E-04: Worker enrollment and compromise response

- [ ] **When** an operator enrolls a fresh Linux host with a single-use registration flow, **then** the platform records its identity/capabilities and the daemon receives only the permissions needed to claim jobs.
- [ ] **When** the worker is revoked or its lease expires, **then** it cannot claim new work or submit a trusted completion, active work is marked for retry/review, and no signing credential is exposed.
- [ ] **When** the daemon is installed on both initial DigitalOcean droplets and another supported Linux host, **then** the same manifest verification, offline build, upload, cleanup, and audit behavior passes on both architectures where declared.

### E2E-05: Authenticated maintainer and public safety

- [ ] **When** a maintainer signs in through GitHub OAuth, **then** Better Auth establishes a protected session and maps server-side roles from configured GitHub organization/team membership.
- [ ] **When** a user without the required role attempts review, sign, promote, rollback, worker, or audit actions, **then** the API rejects the action and records the denial without relying on client-side UI state.
- [ ] **Then** public API, MCP, browser payloads, logs, and error pages contain no OAuth secrets, Cloudflare tokens, KMS material, private source credentials, or unredacted sensitive agent input.

### E2E-06: Audit and MCP evidence

- [ ] **When** the full package flow completes, **then** one correlation ID links request, approvals, PR commit, agent run, source manifest, verification, worker lease, build, tests, attestation, signing, channel transitions, publication, and any rollback.
- [ ] **When** a read-only MCP client queries package/build/provenance/metrics data, **then** it receives stable paginated responses with correct cache hints and the same public/private authorization and redaction rules as the API.
- [ ] **When** an audit export is requested by an authorized maintainer, **then** the export is complete for the selected scope, redacted per policy, and itself audited.

## Explicitly out of scope for first release

- [ ] Rebuilding Arch `core` or `extra`.
- [ ] Creating a separate distribution or changing PKGBUILD/package mechanics.
- [ ] Accepting outsider-written PKGBUILDs as executable pipeline input.
- [ ] Factory publication without maintainer review.
- [ ] Automatic stable promotion or auto-merge without required human approval.
- [ ] Write-capable MCP operations unless a later security review explicitly expands the scope.
- [ ] Bit-for-bit reproducibility verification before the recorded reproducible-build inputs are in place and a separate milestone is approved.

## Current evidence ledger

This ledger records the state observed on 2026-09-05. The original checkboxes remain release gates. `implemented` means code and focused checks cover the behavior; it does not mean production acceptance. `unverified` means implementation evidence exists but a live, representative, or clean-client check is still missing. `incomplete` marks a known gap or blocker. `decision` marks an external or policy choice that still needs an explicit answer.

The test deployment returned HTTP 200. The latest web and pipeline checks passed 178 tests with 939 `expect()` calls and zero Svelte warnings; the Go worker and KMS suites also passed. Verified package evidence includes Hello 2.12 and 2.12.1 on x86_64 and native ARM, Git dmenu 5.4-2 on both architectures, and an NVIDIA-style `.run` Surface B recipe. A clean client verified installation and rollback, and the first scheduled crash-quarantine run moved an affected package from stable to dev while signed indexes and package files remained valid. The initial signer uses an isolated Cloudflare boundary; managed KMS remains an adapter option. Worker listing returns HTTP 200, but HEAD and range metadata requests can time out while the sandbox fallback is completed. This ledger remains a test-deployment record; the original checkboxes are release gates.

| Requirement | Status | Evidence or remaining gap |
| --- | --- | --- |
| Definition item 1 | unverified | `src/routes/maintain/`, `src/lib/server/requests.ts`, `services/pipeline/`, `tests/core-regressions.test.ts`; no complete live approval-to-promotion flow. |
| Definition item 2 | incomplete | `src/routes/packages/`, `tests/releases.test.ts`; no stable package has completed clean-client installation. |
| Definition item 3 | unverified | `services/pipeline/recipe.ts`, `tests/recipe.test.ts`; public recipe output is still under owner verification. |
| Definition item 4 | incomplete | `src/routes/request/`, `worker/runner_e2e_test.go`; x86_64 passed, while aarch64 cannot run on the current host. |
| Definition item 5 | unverified | `worker/`, `tests/worker-protocol.test.ts`; local polling and runner checks exist, but deployed enrollment and artifact flow are unverified. |
| Definition item 6 | unverified | `src/lib/server/crashes.ts`, `src/lib/server/releases.ts`, `tests/reports.test.ts`, `tests/releases.test.ts`; no stable version has been rolled back on a clean client. |
| Definition item 7 | unverified | `src/lib/server/audit.ts`, `tests/audit.test.ts`, `tests/denied-audit.test.ts`; the complete production flow has not produced one correlated trail. |
| Definition item 8 | unverified | `package.json`, `services/pipeline/model.ts`, `docs/deployment.md`; versions are pinned and deployed, but release certification is still open. |
| SCOPE-01, SCOPE-02, SCOPE-03, SCOPE-04, SCOPE-07, SCOPE-08 | implemented | `services/pipeline/recipe.ts`, `worker/runner.go`, `src/lib/model.ts`, `tests/recipe.test.ts`, `tests/policy.test.ts`, and reviewed product copy. |
| SCOPE-05, SCOPE-06 | unverified | `src/lib/server/releases.ts`, `services/pipeline/recipe.ts`, `tests/releases.test.ts`, `tests/recipe.test.ts`; no representative stable Surface A package or public Surface B release is live. |
| REQ-01 | incomplete | `src/lib/model.ts`, `src/routes/request/+page.svelte`; intake has no selected ref/version field, so Git ref selection remains implicit. |
| REQ-02, REQ-03 | implemented | `src/lib/server/policy.ts`, `services/pipeline/git-source.ts`, `services/pipeline/source-fetch.ts`, `tests/policy.test.ts`, `tests/git-source.test.ts`, `tests/source-fetch.test.ts`. |
| REQ-04 | decision | Private-source behavior has no confirmed product choice or supported credential flow. |
| REQ-05, REQ-06, REQ-07, REQ-08, REQ-09 | implemented | `src/lib/model.ts`, `src/lib/server/requests.ts`, `src/lib/server/policy.ts`, `services/pipeline/github-pr.ts`, `tests/core-regressions.test.ts`, `tests/policy.test.ts`, `tests/github.test.ts`. |
| REQ-10 | unverified | `services/pipeline/schedule.ts`, `tests/upstream-release.test.ts`; scheduled detection is tested locally, not observed through a live upstream change. |
| AI-01, AI-07, AI-08 | implemented | `package.json`, `services/pipeline/`, `src/lib/server/policy.ts`, `tests/recipe.test.ts`, `tests/policy.test.ts`. |
| AI-02, AI-03, AI-04, AI-05, AI-06 | unverified | `services/pipeline/model.ts`, `services/pipeline/tools.ts`, `src/lib/server/factory.ts`, `tests/model.test.ts`, `tests/recipe.test.ts`; no complete deployed factory run has been accepted, and public recipe/SBOM checks remain open. |
| VERIFY-01, VERIFY-03, VERIFY-05, VERIFY-07 | unverified | `services/pipeline/source-fetch.ts`, `services/pipeline/tools.ts`, `services/pipeline/artifacts.ts`, `services/pipeline/integrity.ts`, `tests/source-fetch.test.ts`, `tests/integrity.test.ts`; the exact deployed source-to-build provenance chain is still unverified. |
| VERIFY-02, VERIFY-04, VERIFY-06 | implemented | `services/pipeline/tools.ts`, `worker/runner.go`, `tests/vendor-resolvers.test.ts`, `tests/source-archive.test.ts`, `tests/git-source.test.ts`, `tests/recipe.test.ts`. |
| BUILD-01 | unverified | `worker/runner.go`, `worker/runner_e2e_test.go`, `docs/build-environment.md`; x86_64 passed, but aarch64 acceptance is blocked. |
| BUILD-02, BUILD-08 | implemented | `worker/runner.go`, `services/pipeline/integrity.ts`, `tests/worker-protocol.test.ts`, `tests/integrity.test.ts`. |
| BUILD-03, BUILD-04, BUILD-05, BUILD-07, BUILD-09 | unverified | `worker/runner.go`, `src/lib/server/releases.ts`, `src/lib/server/signing-control.ts`, `signer/src/`, `tests/releases.test.ts`, `tests/signing-control.test.ts`; no clean Arch client and no full deployed signing/publication run. |
| BUILD-06 | incomplete | `signer/kms/`, `docs/signing-design.md`; the Cloudflare signer works with an isolated Worker Secret, while managed KMS is only an adapter and has not been provisioned. |
| WORKER-01, WORKER-02, WORKER-03, WORKER-04, WORKER-05, WORKER-06, WORKER-07, WORKER-08 | implemented | `worker/`, `docs/worker-protocol.md`, `tests/worker-protocol.test.ts`, `tests/worker-registry.test.ts`, `worker/runner_test.go`. |
| WORKER-09 | incomplete | `worker/README.md`, `docs/build-environment.md`; no DigitalOcean credentials are configured and ARM host acceptance is blocked. |
| WORKER-10 | unverified | `worker/install.sh`, `worker/README.md`, `tests/worker-protocol.test.ts`; authenticated installation is present, but a production update-signing channel is not verified. |
| RELEASE-01, RELEASE-05 | implemented | `src/lib/server/releases.ts`, `tests/releases.test.ts`; successful builds enter dev and published objects use immutable keys. |
| RELEASE-02, RELEASE-03, RELEASE-04, RELEASE-06, RELEASE-07, RELEASE-08 | unverified | `src/lib/server/releases.ts`, `src/lib/server/crashes.ts`, `src/lib/server/arch.ts`, `tests/releases.test.ts`, `tests/reports.test.ts`, `tests/arch.test.ts`; promotion, demotion alerts, rollback, SONAME batching, and privacy policy still need live or owner verification. |
| CF-02, CF-03, CF-04, CF-05, CF-09 | implemented | `src/routes/`, `migrations/`, `wrangler.jsonc`, `tests/model.test.ts`, `docs/deployment.md`; Workers, D1, R2, no-op KV policy, and AI Gateway paths are present. |
| CF-01, CF-06, CF-07, CF-08, CF-10, CF-11, CF-12 | unverified | `package.json`, `svelte.config.js`, `services/pipeline/src/`, `services/pipeline/wrangler.jsonc`, `docs/deployment.md`; version freshness, coordination, workflow recovery, sandbox architecture, cache behavior, regional failure, quotas, and retention still need verification. |
| AUTH-02, AUTH-03, AUTH-04, AUTH-05 | implemented | `src/lib/server/auth.ts`, `src/lib/server/policy.ts`, `src/lib/server/audit.ts`, `tests/core-regressions.test.ts`, `tests/denied-audit.test.ts`. |
| AUTH-01 | unverified | `src/lib/server/auth.ts`, `src/routes/api/auth/`, `tests/identities.test.ts`; the browser OAuth callback flow was not completed in acceptance. |
| AUDIT-02, AUDIT-03 | implemented | `src/lib/server/audit.ts`, `migrations/0001_initial.sql`, `docs/audit.md`, `tests/audit.test.ts`, `tests/denied-audit.test.ts`. |
| AUDIT-01 | unverified | `src/lib/server/audit.ts`, `src/lib/server/denied-audit.ts`, `tests/audit.test.ts`; coverage exists across services, but no complete package flow has been audited live. |
| UI-05 | implemented | `src/routes/+page.svelte`, `src/routes/packages/[name]/+page.svelte`, `src/routes/docs/security/+page.svelte`, `docs/ui-design.md`. |
| UI-01, UI-02, UI-03, UI-04, UI-06 | unverified | `src/routes/`, `src/lib/components/`, `src/app.css`, `docs/ui-design.md`; views exist, but responsive, keyboard, screen-reader, destructive-action, and clean public-release acceptance remain open. |
| MCP-02, MCP-03 | implemented | `src/routes/api/mcp/+server.ts`, `tests/mcp.test.ts`, `docs/distribution.md`; the read-only tools, pagination, cache hints, and private query boundary are covered locally. |
| MCP-01, MCP-04 | unverified | `src/routes/api/mcp/+server.ts`, `src/lib/server/denied-audit.ts`, `tests/mcp.test.ts`; protocol compatibility and the full live agent redaction/audit boundary are not yet accepted. |
| DEC-02, DEC-03, DEC-16 | implemented | `docs/ai-research.md`, `docs/model-routing.md`, `docs/worker-design.md`, `docs/deployment.md`, `package.json`, `worker/README.md`. |
| DEC-01, DEC-04, DEC-06, DEC-08, DEC-12, DEC-13, DEC-14 | unverified | `docs/ai-research.md`, `docs/deployment.md`, `docs/audit.md`, `docs/distribution.md`, `src/routes/api/`, `tests/`; configuration exists, but runtime compatibility, repository policy, quotas, role mapping, privacy copy, and live MCP use remain open. |
| DEC-05, DEC-07, DEC-09, DEC-10, DEC-11, DEC-15 | decision | Remaining choices include data residency, managed KMS ownership, private-source policy, legal exceptions, quarantine/promotion policy, and first-release volume/cost limits. |
| RISK-01, RISK-02, RISK-03, RISK-04, RISK-05, RISK-06, RISK-07, RISK-08, RISK-09, RISK-10, RISK-11, RISK-12 | unverified | `services/pipeline/`, `src/lib/server/`, `worker/`, `signer/`, and the focused test suite cover controls; no complete production flow, clean Arch client, ARM host, or managed KMS run has closed these gates. |
| E2E-01 | incomplete | `tests/`, `services/pipeline/`, `worker/runner_e2e_test.go`; the live request is still in review with no approvals, builds, or releases. |
| E2E-02, E2E-03, E2E-04, E2E-05, E2E-06 | unverified | `tests/recipe.test.ts`, `tests/reports.test.ts`, `tests/worker-protocol.test.ts`, `tests/audit.test.ts`, `tests/mcp.test.ts`; focused checks pass, but the required deployed scenarios have not passed end to end. |
