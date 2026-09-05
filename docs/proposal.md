A proposal for replacing the AUR

Revised after project review. The biggest change is that submitters no longer
write code; the section on the flow is rewritten around that inversion.



1. The promise
We are not going to promise that every package works perfectly. We are going to promise that no package attacks the user.



That distinction is the core of this proposal. Provenance, license, checksums and build hygiene are machine-verifiable, deterministic and cheap. "Works well" is not verifiable at scale — not by the AUR, not by Debian, not by Fedora.



If a package is broken but harmless, users report it and we fix it. If a package attacks someone, we failed. Only the second case is unacceptable.



This makes the problem tractable and gives us an honest promise we can defend in public.

2. Scope
omapkg sits on top of Arch, not in place of it. core and extra stay as the base
with roughly 14,000 packages already built and signed by Arch maintainers.
omapkg replaces only the AUR layer: user-submitted recipes that today have no
gate at all. This keeps Quattro on Arch.



Nothing here is specific to the AUR layer. PKGBUILDs go through a build system
either way, so the same machinery could take over core and extra later if the
project chooses to de-risk upstream. The design leaves that option open without
making it part of the first release; taking on the base today would require
toolchain bootstrap and cascading rebuilds across thousands of packages.



Two distribution surfaces:

Surface A — signed binaries. Software with a redistributable license. We build it, sign it, host it. This is most of the catalog and where the guarantee is strongest.



Surface B — recipes. Software we cannot legally redistribute: Chrome, the NVIDIA driver, Zoom, Spotify. We never host the bits; the recipe fetches straight from the vendor with a pinned checksum. This is exactly what the AUR does, and it is legally clean.



Without Surface B, "replacing the AUR" would be false — we would be missing precisely the software desktop users want most. With both surfaces, the claim is honest.



3. The flow
Zoom opr_package_flow_v2.png
opr_package_flow_v2.png
Nobody outside the project writes code that enters our pipeline. Users file a
request with a package name and upstream URL. That is small, human-readable,
and directly reviewable. A factory under project control generates the
PKGBUILD, lints it, and tests it.



This dissolves the worst problem in v1. Validating a submitted PKGBUILD means
executing someone else's shell code, and no amount of sandboxing makes
adversarial input safe to review automatically. With requests instead of
implementations, there is no third-party PKGBUILD to validate. This does not
remove supply-chain risk, but it removes the package-hijacking path that the AUR
has suffered.



Five points deserve detail:

The factory's output is reviewed, not trusted. Moving generation in-house relocates the attack surface, it does not delete it. Our agent still reads adversarial content: the upstream repo, its README, its build scripts. An agent prompted by hostile input is not trusted infrastructure. So a maintainer approves the generated diff before it builds. For a version bump that diff is two lines and review is trivial; the real cost falls on initial package creation, which is exactly where we want human eyes.



Requestor validation is a signal, never an authority. A requestor may confirm
that a build works before it ships to stable, and that is useful feedback. The
requestor may be unknown, so their sign-off cannot gate promotion. Their
confirmation goes into the record alongside automated tests and crash reports;
a maintainer decides. The project trusts vetted maintainers and, unavoidably,
upstream.



Source verification is online; the build is offline. Full validation cannot
happen offline. An online pass in a sandbox with no secrets fetches the source
URLs and checks them against what was declared. Only then does the build run in
a chroot with no network, from the verified cache. This removes the class of
attacks where a build downloads something other than what was reviewed.



Dependencies are the expensive part, and we should say so. An offline build means nothing can cargo fetch or npm install at build time. Fedora's approach of packaging Rust crates individually has produced thousands of separate packages and a real maintenance burden — which is why vendoring exceptions exist there at all. Recreating that from scratch for the AUR layer is not realistic.



The middle path: vendored sources are allowed, but our factory produces the
vendor bundle, not upstream. It resolves the lockfile during online
verification, checksums every component, records them in the SBOM, and hands a
sealed bundle to the offline build. This provides auditability without
packaging every crate in the ecosystem. Where a dependency is already in Arch
or omapkg, use that instead.



Reproducibility by construction from day one is cheaper than retrofitting it.
Adopt the inputs immediately: SOURCE_DATE_EPOCH, pinned build containers,
recorded build environments, and no timestamps or paths leaking into artifacts.
The first release does not promise bit-for-bit verification; Arch itself is not
fully there yet. Build reproducibly from the start and verify it later.



The signing key never lives on a worker. The worker produces the artifact plus a
provenance attestation. A separate service, with its key in a KMS, signs only
artifacts from an attested build. If a worker is compromised, the key does not
go with it. A verification script should detect tracked files modified outside
the pipeline, including a hand-applied hotfix or a tampered build.

4. Review, quarantine and recovery
Area queues instead of trust tiers. With the factory model, no outsider writes
code, so there is nothing to grade them on. Pending work goes into category
queues such as desktop, gaming, and productivity. A maintainer in the matching
group can approve or deny it, with a security sign-off on top. This scales with
the expected churn.



dev as quarantine. Every package lands in dev. It leaves for stable on a defined criterion: minimum time, automated smoke tests, no crash reports, and requestor feedback where we have it. Without an explicit criterion, quarantine is just delay.



Anonymous, opt-in crash reporting. Modeled on Fedora's ABRT. Real usage tells us which packages deserve attention, instead of burning effort testing software almost nobody runs. For a distro that talks about sovereignty, this has to be explicitly opt-in with a published data policy.



Recovery. Pulling a broken package from stable does not fix machines that already installed it. We keep every published version forever in R2 (it is cheap) and push an automatic downgrade. Without that, freezing is half a fix.



Promotion happens in batches. Packages sharing dependencies move together or not at all. A half-applied update breaks the user's system with soname errors.



5. Infrastructure
Source of truth: `owner/recipes` on GitHub. Requests, generated PKGBUILDs and
metadata stay under version control and are reviewed through pull requests.
Factory: agent-driven generation of PKGBUILDs, lint and test, running in a sandbox with no secrets and no credentials. Its output is a diff for review, never a direct commit to a build.
Workers: ephemeral, x86_64 and aarch64, self-hosted, discarded after every build.
Storage: Cloudflare R2. Zero egress is what makes distribution traffic viable at all.
Front-ends: static, on CDN, consuming JSON emitted by the pipeline. No database, no application to maintain — the direction Fedora is already moving in.
MCP on the 2026-07-28 spec, read-only in our first release. The stateless core is what makes this cheap: no sessions, no shared storage, so the server runs as a Worker behind a plain load balancer, and list responses carry cache hints so the CDN handles the catalog. Maintainers query builds, tests and metrics from their own agents. Write operations come later — they need a much larger auth surface.
Automated upstream release detection. The same factory watches for new versions, opens a PR with the pkgver and checksums, a maintainer approves the diff. Highest-return, lowest-risk automation available, and it kills the manual version bumping we are still doing by hand in 2026.

6. Out of scope
We are explicitly not going to:

Rebuild core/extra today, or create a new distribution
Change the package format — PKGBUILD stays
Rewrite build mechanics; we reuse Arch's devtools
Accept PKGBUILDs written by people outside the project
Let the factory ship anything a maintainer has not reviewed
Auto-merge anything into stable without review

7. Phases
Phase 1 — foundation. Repository and request format, factory generating PKGBUILDs for a small curated set, human review of generated diffs, online source verification, offline builds on x86_64 and aarch64, signing, dev channel.

Phase 2 — controlled opening. Area queues and maintainer groups, external requests, Surface B, automated upstream release detection, vendored dependency bundles with SBOM.

Phase 3 — visibility. Static front-ends, read-only MCP, crash reporting, automated dev-to-stable promotion criteria, reproducibility verification.
