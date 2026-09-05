# omapkg implementation plan

Implementation is in progress. A milestone is complete only after its checks pass.

## Decisions

- The user's explicit stack overrides the proposal's database-free front-end design: SvelteKit on Cloudflare Workers, D1 control records, immutable R2 artifacts/catalog snapshots, Cloudflare Workflows for the factory, Durable Objects for run coordination, and Sandbox for isolated source inspection. Keep KV out unless measurement shows a need.
- Keep the public, cacheable catalog separate from authenticated maintainer control routes. Better Auth handles GitHub OAuth. Roles use immutable GitHub account IDs, never display names. Maintainers cannot appoint themselves.
- Flue >=2 owns agent loops and tool execution. Effect 4 wraps typed operations and validation. Pin the current Effect 4 release candidate because the stable npm tag remains 3.x.
- The Go daemon runs on Linux and makes outbound HTTPS requests. It holds its own Ed25519 identity, never platform, provider, or signing secrets. Each build uses disposable pinned Arch containers and Arch devtools. DigitalOcean is an eventual host, not part of the worker protocol.
- Source requests contain a name, description, declared license, and upstream URL, never executable recipes. Accept public HTTPS Git hosts, source archives, and supported vendor downloads. Resolve mutable refs to immutable commits or checksums before review.
- There are two review gates: approve the request before factory work, then approve the generated recipe and source manifest with area and security sign-offs before a worker can lease it. Recipe changes invalidate approval. Human promotion remains mandatory.
- Keep online source/dependency verification and secret-free generation separate from the offline build. Generated shell remains untrusted. Materialize dependencies into checksumed bundles before the build. If an ecosystem is unsupported, fail with actionable evidence instead of silently re-enabling network access.
- Package signatures must use pacman-compatible OpenPGP and come from a separate attestation-checking service backed by KMS. A worker key identifies provenance; it is never the package signing key.
- Public safety wording describes controls and limits. It cannot promise that malicious upstream behavior is mathematically impossible.
- Automatic upstream updates apply only to packages with a published build. A detected release creates a system request, moves it from `pending` to `generating`, and leaves the resulting PR in `review`; it never creates a human approval, merges the PR, or queues a build. Three automatic generations are allowed for one detected update. After the third failed generation, the request stays `failed` and one `factory.auto_retry_exhausted` audit event records that a maintainer must retry it explicitly.

## 1. Foundation and review

Create app/config, D1 migrations, typed model, input validation, append-only audit records, Better Auth, request/revision/build APIs, maintainer authorization. Design public catalog and maintainer workbench in Omarchy visual language.

Verify: typecheck/build; executable tests reject invalid sources, unauthorized transitions and changed approvals; local D1 migrations; request creation persists; empty catalog does not invent published packages.

## 2. Agent factory and build execution

Implement durable Flue factory with bounded tool calls, isolated source inspection, lockfile/vendor manifests, generation/lint/repair evidence and review diff. GitHub stores generated requests/recipes/metadata through reviewed PRs. Implement Go enrollment, request signatures/replay protection, lease fencing, heartbeat, isolated online preparation, offline devtools execution, artifact upload and signed provenance.

Verify: real Git and tar inputs; factory creates reviewable recipe; no unapproved job leases; forged/replayed/revoked worker requests fail; network is unavailable in build; builds produce real .pkg.tar.zst archives and SBOM/provenance; failures and retry evidence visible. Exercise x86_64 and aarch64 with matching native hosts or documented emulation evidence.

## 3. Distribution and maintenance

Implement a separate signing boundary, immutable artifacts, pacman repository database/signatures, Surface B recipe-only publishing, dev quarantine and smoke results, feedback/crash policy and reports, release monitoring, dependency-coherent batch promotion, freeze/rollback/downgrade, and read-only MCP.

Verify: pacman validates repository and package signatures; nonredistributable artifacts never served; early/crashed/unreviewed promotion fails; batches move atomically; older versions remain addressable; rollback installs older package with an explicit client downgrade mechanism; upstream change creates a fresh reviewed revision; MCP has no write tools.

## 4. Deployment and full acceptance

Provision account-scoped Cloudflare resources, deployment secrets, OAuth callback and initial maintainer roles, factory AI Gateway, signing provider, repository and Linux host. Deploy and inspect real browser flows/responsive layouts.

Verify: GitHub sign-in -> request upstream link -> approval -> agent-generated PR/diff -> area/security approval -> registered worker -> verified offline build -> separate signature -> dev install -> quarantine/test evidence -> reviewed stable batch -> public download/install -> rollback. Inspect end-to-end audit trail. Repeat with source archive. Completion requires working deployed services and real flows; scaffolding or mocks alone do not satisfy it.

## External setup to resolve

- The domain, GitHub source-of-truth repository, and OAuth app credentials; initial maintainer/security GitHub identities.
- AI provider/model credentials or Cloudflare Workers AI entitlement.
- A pacman-compatible KMS signing service/provider and package public key.
- A native aarch64 host, if no usable local emulator is available.

## Scope boundaries

Do not rebuild Arch core/extra, accept third-party PKGBUILDs, use automatic stable merges, introduce a new package format, or replace the build mechanics. Every requested phase stays in acceptance scope. Record missing external setup as incomplete rather than presenting it as finished.
