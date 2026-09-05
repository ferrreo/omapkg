# omapkg build worker design

This design implements the worker boundary in [worker-protocol.md](worker-protocol.md). The daemon is a small statically linked Go program for Linux. It only makes outbound HTTPS requests, claims one leased build at a time, and never receives an inbound connection.

The worker is an untrusted executor. Its Ed25519 key proves which registered host reported an event; it does not prove that host was honest or that a package is safe. Package signing stays in a separate service backed by KMS/HSM. A worker compromise can falsify a build report, but cannot steal the package signing key or authorize a stable release.

## Trust boundaries

| Component | Trust and responsibility |
| --- | --- |
| Worker API Worker | Authenticates signed requests, enforces worker status, lease fencing, replay rejection, and output paths. |
| Durable Object | Serializes lease state and nonce use for each worker/job. Lease transitions are idempotent and stale attempts cannot mutate a newer attempt. |
| Workflow | Orchestrates source verification, factory review, worker execution, smoke results, and promotion waits. It stores state references, never build logs or package bytes. |
| Source verifier Sandbox | Has anonymous outbound network access and no omapkg, GitHub OAuth, R2 write, AI, or signing secrets. It resolves mutable refs and materializes immutable source/vendor bundles. |
| Go worker | Holds only its own private identity key and a pinned image reference. It fetches only declared HTTPS sources, runs the fixed Arch runner, uploads hashes, and signs provenance. |
| R2 | Stores immutable source bundles, logs, SBOMs, provenance, and binary artifacts. Worker URLs are one-object, short-lived presigned URLs. |
| Signer | Revalidates the reviewed input digest, worker attestation, output hash, smoke result, and policy before emitting a pacman-compatible OpenPGP detached signature. |

## End-to-end flow

1. A request contains package name and upstream URL. The factory generates a PKGBUILD and a review diff.
2. After request and generated-recipe approval, the online verifier resolves every source and dependency. Git refs become a commit plus deterministic archive; tar inputs retain a final URL, size, checksum, and optional upstream signature fingerprint.
3. The verifier writes a sealed input bundle to R2 and signs its manifest. The job references the bundle digest and the reviewed recipe digest.
4. A registered worker claims a matching architecture. The worker checks the recipe, image reference/digest, source names, checksums, lease, and source-size limits before doing any build work.
5. The worker fetches sources into a private temporary directory. A disposable preparation container may use the Arch mirror to install the reviewed dependency list, then is committed as a local image with no source, recipe, or host secret mounted.
6. The runner starts a fresh container from that prepared image with `--network=none`, runs Arch `makepkg` as the worker UID, installs the exact package into a disposable smoke image, runs reviewed commands as an unprivileged UID, and removes all derived images, containers, and job state after upload.
7. The worker uploads a package only for Surface A, then submits worker-signed provenance and an idempotent completion. Surface B keeps the recipe and validation evidence but never uploads the vendor artifact.
8. The signer validates the evidence and signs the package. Publication first targets `dev`; a maintainer later promotes a dependency-coherent batch to `stable`.

Arch's clean-chroot guidance uses `mkarchroot`/`makechrootpkg`; those helpers require nested mount/user namespaces that many OCI hosts deny. The worker's native OCI mode uses the pinned Arch image itself as clean root, keeps the official `makepkg`/devtools tooling, and avoids nested namespace requirements. `makepkg` verifies declared source checksums before extraction. `SOURCE_DATE_EPOCH`, `BUILDENV`, `PKGDEST`, `SRCDEST`, and `LOGDEST` are recorded in the build environment. See [Arch clean-chroot guidance](https://wiki.archlinux.org/title/DeveloperWiki:Building_in_a_clean_chroot), [makepkg.conf(5)](https://man.archlinux.org/man/makepkg.conf.5.en), and [Arch package guidelines](https://wiki.archlinux.org/title/Arch_package_guidelines).

## Enrollment and authentication

`opr-worker enroll` generates an Ed25519 key locally, posts the raw public key as standard base64, and saves the private key only after the API returns a worker ID. The enrollment token is read from stdin when no `--token` value is supplied, sent once, and never written to state. The server stores only a token hash, consumes it atomically, gives the worker `pending` status, and requires maintainer approval before any claim.

The config file is atomically replaced, mode `0600`, inside a mode `0700` state directory. It contains the API origin, worker ID, private key, target architecture, optional legacy pinned image reference/digest, and runtime. Current claims carry the platform-selected image reference/digest. It contains no Cloudflare API token, R2 credential, GitHub credential, provider key, or package signing material.

Every request after enrollment carries:

```text
X-OPR-Worker: <worker id>
X-OPR-Timestamp: <unix seconds>
X-OPR-Nonce: <32 lowercase hex characters>
X-OPR-Signature: <standard base64 Ed25519 signature>
```

The signed bytes are exactly `METHOD\nPATH_AND_QUERY\nTIMESTAMP\nNONCE\nBODY_SHA256`, with no trailing newline. The API rejects clock skew over 60 seconds, a reused `(worker, nonce)`, inactive workers, oversized bodies, and lease mutations without the current worker-matching lease token. Job completion may be retried with a fresh nonce; the server deduplicates it by job attempt and state transition.

The worker key identifies a host, not a hardware-attested build. A future TPM/TEE mode can add an attestation document to provenance without changing this protocol.

## API field recommendations

These fields are the minimum needed to keep requests typed, replay-safe, and reviewable.

| Route | Request fields | Response/effect |
| --- | --- | --- |
| `POST /api/workers/enroll` | `token`, `name`, `architecture`, `publicKey` | `{ id }`; token is consumed atomically. |
| `POST /api/worker/claim` | `{}` | `{ job: null }` or leased job below. |
| `POST /api/worker/jobs/{id}/heartbeat` | `leaseToken` | `leaseExpiresAt`, `cancel`; cancel fences and stops the runner. |
| `POST /api/worker/jobs/{id}/logs` | `leaseToken`, monotonic `sequence`, bounded `text` | Append once per sequence; duplicate sequence is harmless. |
| `POST /api/worker/jobs/{id}/uploads` | `leaseToken`, safe `filename`, total `size`, total `sha256` | `{ uploadId, partSize, maxSize, filename, size, sha256, parts[] }`; server reserves or resumes one upload, or returns `{ completed: { key, sha256, size, filename } }` after a crash-safe completed retry. |
| `PUT /api/worker/jobs/{id}/uploads/{uploadId}/{part}?leaseToken=...` | One raw chunk, at most 8 MiB | `{ partNumber, sha256, size, etag }`; each chunk is independently verified. |
| `POST /api/worker/jobs/{id}/uploads/{uploadId}/complete` | `leaseToken` | `{ key, sha256, size, filename }`; object remains private. |
| `DELETE /api/worker/jobs/{id}/uploads/{uploadId}?leaseToken=...` | Empty body | Best-effort abort after failure/cancellation. |
| `POST /api/worker/jobs/{id}/registry-credentials` | `leaseToken` | Short-lived pull-only registry credentials; returned only when a private image is missing locally. |
| `POST /api/worker/jobs/{id}/complete` | `leaseToken`, `status`, `installedSize` for successful binary builds, optional `error`/`artifact`, `provenance`, `provenanceSignature`, `smokePassed` | Validates every field against the leased revision and output record. |

Job fields:

```json
{
  "id": "job-id",
  "leaseToken": "opaque-token",
  "leaseExpiresAt": "2026-09-04T20:00:00Z",
  "revisionId": "revision-id",
  "packageName": "opr-hello",
  "version": "1",
  "pkgrel": 1,
  "architecture": "x86_64",
  "recipe": "<reviewed PKGBUILD>",
  "recipeSha256": "<64 lowercase hex>",
  "sourceDateEpoch": 1777982400,
  "imageRef": "registry.example/opr-builder@sha256:<64 lowercase hex>",
  "imageDigest": "sha256:<64 lowercase hex>",
  "sources": [{"name": "hello.tar.gz", "url": "https://host/hello.tar.gz", "sha256": "<64 lowercase hex>"}],
  "dependencies": ["base-devel"],
  "runtimeDependencies": [],
  "makeDependencies": [],
  "smokeCommands": ["/usr/bin/hello --version"],
  "surface": "binary"
}
```

The worker uses reviewed `imageRef` when present. It must be a full OCI reference ending in the exact `imageDigest`; the daemon pulls and inspects that digest before building. Older claims without `imageRef` use a legacy config `image` only when its configured digest matches. This lets maintainers change approved builder images per architecture without re-enrolling hosts.

## Source and dependency handling

The worker accepts only HTTPS sources without URL credentials. It disables proxy environment use, follows at most five redirects, revalidates every redirect, rejects local/private/link-local/metadata addresses after DNS resolution, caps each response at 512 MiB by default (2 GiB hard ceiling), rejects compressed responses, streams to a `0600` temporary file, hashes while writing, and atomically renames only after the declared SHA-256 matches.

Tar source records include the final URL, filename, byte length, SHA-256, and optional detached signature/fingerprint from the verifier. Git records the repository URL, resolved commit, archive checksum, and each submodule commit. For a private factory archive, the verifier records the same-origin `/sources/<sha256>.tar` URL; the worker authenticates that GET with its signed worker request and rejects redirects. Mutable branch/tag names are provenance metadata only; the build never fetches a mutable ref.

The factory resolves lockfiles online and creates the vendor bundle. The bundle records each component's origin, checksum, license, and selected SBOM identifier. The build rejects recipes that try to run `cargo fetch`, `npm install`, `go mod download`, `pip install`, or another networked dependency resolver. When a reviewed runtime or build dependency is an omapkg package, the claim carries a frozen `dependencyPlan` with exact release IDs, package URLs, detached signature URLs, SHA-256 values, target architecture, and the package signing-key fingerprint. The worker downloads these objects only from the same-origin repository, verifies the key and detached signatures in an ephemeral keyring, installs all planned packages in one `pacman -U` transaction, and then resolves remaining Arch relations with the native repositories. A missing ecosystem fails with evidence instead of enabling network access.

## Offline Arch runner

The configured or reviewed image is pulled only after its reference is pinned and its local digest matches the job. A missing approved private image requests a pull-only registry token over the signed lease API, uses it through an ephemeral `0700` auth directory and `0600` auth file, and deletes that directory before build. Cached images never request credentials. Each job uses a fresh state directory with separate recipe/source and output paths. The runner invokes fixed executable paths; the API never supplies a host command or shell string for the build.

The prep container may use the Arch mirror to install validated package names, then is discarded after its dependency layer is committed locally. A hosted dependency plan is mounted read-only only during preparation; the key, signatures, package files, temporary pacman keyring/config, and cache are removed before the derived image is committed, and the host plan directory is removed before offline build starts. It receives no recipe, source, host path, or credential. The native build container has:

```text
--network none
--read-only
--cap-drop ALL
--security-opt no-new-privileges:true
--pids-limit 512
--memory 4g
--cpus 2
```

Only job work/output directories are mounted. Work is writable for the recipe and build, output is writable only for package creation, and no host process namespace, socket, environment file, control key, or credential directory is mounted. `/usr/bin/makepkg --noconfirm --nodeps --check --log` is the fixed offline build entrypoint. Smoke first installs the exact package into a disposable container image without host mounts, then runs commands as numeric UID `65534` in a fresh `--network=none`, read-only container.

The worker accepts one package artifact per protocol attempt. A split package must be represented as a separate job or the protocol must grow an artifact list; silently choosing one would make provenance incomplete.

## Provenance, artifacts, and signing

The worker streams package uploads in the server-provided chunks (currently 8 MiB), hashing each range in a second pass so package size does not become worker memory usage. Before smoke and upload, native `makepkg` extracts `.PKGINFO`; the worker checks package name, full `pkgver-pkgrel`, target architecture, and nonnegative installed `size`. It preserves bounded `depend`, `provides`, `conflict`, and `replaces` entries in native order, including generated SONAME relations such as `lib:libexample.so.1`. It reports that uncompressed installed size separately from compressed artifact bytes and signs the exact JSON string sent in `provenance`:

```json
{
  "buildId": "job-id",
  "revisionId": "revision-id",
  "workerId": "worker-id",
  "recipeSha256": "<digest>",
  "pkgrel": 1,
  "installedSize": 118848,
  "packageMetadata": {
    "name": "hello",
    "fullVersion": "2.12-1",
    "architecture": "x86_64",
    "installedSize": 118848,
    "depends": ["glibc", "lib:libc.so.6"],
    "provides": [],
    "conflicts": [],
    "replaces": []
  },
  "artifactSha256": "<digest or empty for Surface B>",
  "architecture": "x86_64",
  "imageDigest": "sha256:<digest>",
  "sourceDateEpoch": 1777982400,
  "sources": [{"name": "...", "url": "...", "sha256": "..."}],
  "network": "disabled",
  "startedAt": "2026-09-04T20:00:00Z",
  "finishedAt": "2026-09-04T20:01:00Z"
}
```

The API compares every provenance identity and digest with its leased job and upload record. A successful worker completion only means that evidence was accepted; it does not imply package signature or stable publication. The signer independently rehashes the private R2 object, verifies the worker signature, checks that smoke passed and that policy approvals are current, then emits the Arch-compatible `.sig`. R2 objects are immutable by content-addressed key and old versions remain available for rollback.

Cloudflare Workflows can hold the verify/build/approval sequence across retries and waits; Durable Objects provide serialized lease/nonce state, and R2 presigned URLs provide one-object temporary transfer without giving workers bucket credentials. See [Workflows](https://developers.cloudflare.com/workflows/), [Durable Objects](https://developers.cloudflare.com/durable-objects/), and [R2 presigned URLs](https://developers.cloudflare.com/r2/api/s3/presigned-urls/). Cloudflare Worker secrets stay in bindings and are never copied to a worker host; see [Worker secrets](https://developers.cloudflare.com/workers/configuration/secrets/).

## Host contract and portability

The release targets `linux/amd64` and `linux/arm64` with `CGO_ENABLED=0`. Host requirements are the selected `podman` or `docker` runtime, a matching builder image, enough disk for one image plus one disposable OCI dependency layer, and an outbound HTTPS path to omapkg, R2, and the configured Arch mirror during preparation. Production hosts should be dedicated droplets or equivalent machines, run the daemon under a dedicated account, keep the state directory private, and revoke the worker immediately when the host is lost.

`worker/install.sh` requires an operator supplied SHA-256 copied from an
authenticated project release manifest or release page before it executes a
candidate binary. It then checks the embedded version, retains immutable
release paths, atomically updates its launcher, and installs
`worker/opr-worker.service` when systemd is available. It leaves active
services running until an operator explicitly requests restart; rootless
runtime subuid/subgid setup remains a host prerequisite. The installer does
not invent a worker update key or derive trust from the candidate bytes: the
digest is an external release decision.

Nested `makechrootpkg`/`systemd-nspawn` would require host mount/user namespaces, so native OCI mode avoids that dependency while preserving clean ephemeral root and offline network policy. Local inspection on 2026-09-04 found Go 1.26.5, Podman 5.8.3 (rootless), Docker 28.5.2 (rootless), `systemd-nspawn`, and `bubblewrap`, but no host `makepkg`, `devtools`, `mkarchroot`, or `makechrootpkg`. The pinned Arch image's native OCI path built a real fixture package with `makepkg`, installed it into a disposable smoke image, and passed a reviewed command while the package build had no network. Rootless OCI runtimes remain supported; the daemon fails closed if the runtime cannot enforce the declared isolation flags.

## Verification and acceptance criteria

Automated checks in `worker/`:

- `go test ./...`, `go test -race ./...`, and `go vet ./...` pass.
- Signature tests reject changed method, path, timestamp, nonce, or body; config writes are atomic and private; enrollment never persists its token.
- Metadata tests verify version, runtime, and fixed capability reporting on enrollment, idle claims, and job heartbeats. Installer validation verifies a missing or wrong trusted SHA-256 fails before candidate execution or service changes, while a matching digest and embedded version install atomically and retain older rollback releases.
- Source tests reject HTTP, credentials, local/private destinations, unsafe redirects, oversized responses, compressed responses, duplicate names, and checksum mismatches.
- Runner tests require `network=none`, read-only root, dropped capabilities, no-new-privileges, bounded resources, safe output names, exactly one artifact, reviewed image-reference selection, and native package/smoke execution when an OCI image is configured.

End-to-end acceptance requires a Linux host with a runtime that enforces the declared OCI isolation flags:

1. Enroll with a one-use token, observe `pending`, approve the worker, and verify heartbeats/claims use the registered architecture.
2. Build one public HTTPS source archive and one public Git source resolved to a commit. The verifier records source digests and a vendor/SBOM bundle before leasing.
3. Tamper with the recipe, source bytes, image digest, lease token, or signed provenance and verify each request fails closed.
4. Build an actual `.pkg.tar.zst` with native OCI `makepkg`, verify no network syscall succeeds during the build, install that exact package into a second offline container, run smoke commands as an unprivileged UID, and confirm all worker credentials are absent from every container.
5. Confirm R2 upload hash/size matches the package, worker provenance verifies, Surface B leaves no artifact, and the separate signer emits a pacman-compatible detached signature only after evidence validation.
6. Kill a worker mid-build, let its 180-second lease expire, requeue the attempt, retry completion with a fresh nonce, and verify stale mutations fail.
7. Revoke the worker and verify claim, heartbeat, upload, and completion are rejected. Repeat on both `x86_64` and `aarch64` workers before marking the worker milestone complete.
