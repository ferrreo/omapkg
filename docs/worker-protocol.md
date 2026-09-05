# Worker protocol v1

Use the omapkg origin as the base URL. JSON uses UTF-8. SHA256 values use lowercase hex. All production traffic is HTTPS. Daemon config contains the origin, worker ID, Ed25519 private key, architecture, and container runtime; an optional legacy image reference/digest is accepted for older servers. Current claims carry the full digest-pinned image reference for each architecture. Config file mode is 0600. Enrollment tokens are single-use and short-lived. The daemon does not retain them.

## Enrollment

`POST /api/workers/enroll` body `{ token, name, architecture, publicKey, version?, runtime?, capabilities? }`.
`architecture` is `x86_64` or `aarch64`. `publicKey` is a standard-base64 raw 32-byte Ed25519 public key. `version` is a bounded daemon version string, `runtime` is `podman` or `docker`, and `capabilities` is a unique subset of `offline-oci`, `multipart-upload`, and `registry-pull`. These metadata fields are informational and never widen authorization; legacy enrollment clients may omit them and are shown as unknown. The response is `{ id }`. The caller generates the key locally before enrollment. The server stores only the token hash, consumes the token atomically, and audits the identity. A maintainer creates tokens through `POST /api/admin/enrollment-tokens` `{ architecture }`, which returns `{ token, expiresAt }`.

## Signed requests

All other `/api/worker/*` requests carry:
- `X-OPR-Worker`: worker ID
- `X-OPR-Timestamp`: unix seconds decimal; clock skew <= 60 seconds
- `X-OPR-Nonce`: random 32 lowercase hex chars, unique per request
- `X-OPR-Signature`: standard base64 Ed25519 signature

Sign the exact UTF-8 string `METHOD\nPATH_AND_QUERY\nTIMESTAMP\nNONCE\nBODY_SHA256` (no final newline). Hash an empty body as empty bytes. The server validates the signature, active worker, clock skew, and body size, then inserts the nonce under unique(worker_id, nonce). Replays fail. Job mutations also require an unexpired lease token for that worker. Retries use a fresh nonce. Completion must be idempotent.

## Claim and execute

`POST /api/worker/claim` body `{ version?, runtime?, capabilities? }` -> `{ job: null }` or `{ job: { id, leaseToken, leaseExpiresAt, revisionId, packageName, version, architecture, pkgrel, recipe, recipeSha256, sourceDateEpoch, imageRef, imageDigest, sources, dependencies, runtimeDependencies, makeDependencies, dependencyPlan?, smokeCommands, surface } }`. `version`, `runtime`, and `capabilities` use the enrollment metadata contract and refresh the worker record for idle workers. `leaseExpiresAt` is an RFC3339 timestamp. `pkgrel` is the reviewed positive Arch package release number. `dependencies` remains the de-duplicated union for older daemons; `runtimeDependencies` maps to `depends` and `makeDependencies` maps to `makedepends`. `dependencyPlan` supplies exact signed omapkg package refs when a dependency is published by omapkg; native Arch dependencies remain in the relation arrays. `imageRef` is the full registry reference pinned with `@sha256:<64 lowercase hex>` for the job architecture; `imageDigest` is the matching digest-only `sha256:<64 lowercase hex>` value.

- `sources`: `{ name, url, sha256 }[]` of HTTPS archives/files resolved before approval. Git is exported at the pinned commit during factory verification; the daemon does not build mutable refs.
- `dependencies`: Arch package names installed during online setup. Generated dependency vendoring is represented by verified sources that include the SBOM bundle.
- `smokeCommands`: reviewed shell commands run in a separate offline, unprivileged container after packaging.
- `surface`: `binary` or `recipe`. Surface B results are never uploaded as public binaries.

When present, `dependencyPlan` is `{ channel: "stable"|"dev", publicKeyUrl,
publicKeyFingerprint, packages[] }`. The key URL and every package/signature
URL must be same-origin repository paths. A `dev` plan may contain stable
fallback package paths selected by the server; a `stable` plan cannot contain
development paths. Each package entry is
`{ releaseId, name, version, architecture, filename, url, sha256, size,
signatureUrl, signatureSha256 }`; package refs are exact published rows, not
untrusted package names. `dev` is an explicit plan choice and never changes
the stable repository configuration.

Before building, the worker verifies the recipe hash and pinned image reference/digest, fetches sources with SSRF, size, redirect, and checksum protection during the online phase, and installs Arch dependencies into a disposable image layer. It then starts a fresh OCI root with `--network=none`, `--read-only`, dropped capabilities, and runs Arch `makepkg` directly; no signing material is available. The runtime may use the network only while pulling the image and preparing dependencies. A missing approved private image gets a short-lived pull-only credential through the signed lease API; the daemon uses an ephemeral private auth directory and deletes it before build. Remove containers and derived images after every build, including after errors or signals. Never mount the host control identity inside the container.

`POST /api/worker/jobs/{id}/registry-credentials` body `{ leaseToken }` returns `{ registry, username, password, expiresAt }` for the reviewed private builder image. The server issues a short-lived pull-only credential for the configured registry namespace, audits the image reference and expiry, and never records the password. Credentials are returned with `Cache-Control: no-store` and are valid only for the current worker lease.

`POST /api/worker/jobs/{id}/heartbeat` body `{ leaseToken, version?, runtime?, capabilities? }` -> `{ leaseExpiresAt, cancel }`. Metadata uses the enrollment contract and refreshes the worker fleet record; legacy daemons may send only `leaseToken`. `leaseExpiresAt` is an RFC3339 timestamp. Leases last 180 seconds and refresh every 30 seconds.

`POST /api/worker/jobs/{id}/logs` body `{ leaseToken, sequence, text }` appends a bounded log chunk, idempotently by sequence. Logs must contain no credentials.

`POST /api/worker/jobs/{id}/uploads` body `{ leaseToken, filename, size, sha256 }` starts or resumes one multipart upload. The response is `{ uploadId, partSize, maxSize, filename, size, sha256, parts[] }`, or `{ completed: { key, sha256, size, filename } }` when a matching upload already completed under the current lease. `partSize` is 8 MiB and `maxSize` is 4 GiB. The filename must be a safe basename ending `.pkg.tar.zst`; the declared size and SHA-256 must match the completed object.

`PUT /api/worker/jobs/{id}/uploads/{uploadId}/{partNumber}?leaseToken=...` accepts one raw chunk, at most 8 MiB. The response is `{ partNumber, sha256, size, etag }`; the server verifies each chunk before recording it. All parts must be present and contiguous when the upload is completed, and retries with the same bytes are idempotent.

`POST /api/worker/jobs/{id}/uploads/{uploadId}/complete` body `{ leaseToken }` completes the multipart upload and returns `{ key, sha256, size, filename }`. The server checks every part, streams a whole-object SHA-256 and size check, and stores the immutable private R2 object. `DELETE /api/worker/jobs/{id}/uploads/{uploadId}?leaseToken=...` aborts an active upload after failure or cancellation.

`POST /api/worker/jobs/{id}/complete` body `{ leaseToken, status, installedSize?, error?, artifact?, provenance?, provenanceSignature?, smokePassed }`. `installedSize` is the nonnegative uncompressed package byte count recorded in `.PKGINFO`; it is required for successful binary builds, stored separately from compressed artifact `size`, and rejected on failed completions. Surface B may include the inspected local package value.
`status` is `succeeded` or `failed`. `artifact` `{ key, sha256, size, filename }` must match the server's upload record. `provenance` is an exact JSON string whose UTF-8 bytes are signed by the worker key; the signature uses standard-base64 Ed25519. Provenance JSON includes reviewed `pkgrel` and `installedSize` with the same value for binary completions, plus `packageMetadata`: `{ buildId, revisionId, workerId, recipeSha256, pkgrel, artifactSha256, architecture, imageDigest, installedSize, packageMetadata: { name, fullVersion, architecture, installedSize, depends, provides, conflicts, replaces }, sourceDateEpoch, sources, network: "disabled", startedAt, finishedAt }`.
`packageMetadata` preserves native `.PKGINFO` relation order. Each list has at
most 256 entries, each entry is at most 256 characters and follows Arch
package-relation syntax; `provides` accepts only an unversioned relation or an
`=` version comparison. All four lists are present, including when empty.
When a job includes `dependencyPlan`, provenance includes the exact same plan;
the server rejects any changed package ref or channel.

The server verifies every provenance field against the leased, reviewed inputs and uploaded bytes before marking the build complete. `imageDigest` in provenance uses the digest-only `sha256:<64 lowercase hex>` form. A successful build is not necessarily signed or published. A separate signing service verifies the attestation and returns an OpenPGP detached signature before dev publication. Do not retain or upload nonredistributable artifacts. Surface B publishes the recipe after isolated validation is recorded.

Revoked workers cannot claim, heartbeat, upload, complete, or sign. Expired leases can be retried with a new token. A stale worker cannot mutate the new attempt.
