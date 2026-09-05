# Distribution boundary

omapkg publishes every successful build to `dev` first. A release can enter
`stable` only after its exact revision has area and security approvals, its
smoke checks pass, its quarantine window expires, and unresolved crash reports
are absent. A requestor's feedback is evidence; it is not a promotion grant.

Surface A keeps package bytes under immutable content keys and asks the
configured signer service for a pacman OpenPGP detached signature. The worker
never receives signing material. The signer receives a one-use intent with a
build ID, revision digest, object key, object hash, and object kind. It must
reload and validate that evidence before signing. If `SIGNER` or `SIGNER_URL`
is not configured, binary publication and repository promotion fail closed;
the application never manufactures a signature.

Surface B stores only the generated `PKGBUILD`, SBOM, provenance, and review
evidence. Vendor bytes and proprietary build outputs are rejected at the
publication boundary. Recipes are addressable under:

```text
/repo/recipes/{name}/{version}/{architecture}/PKGBUILD
/repo/dev/recipes/{name}/{version}/{architecture}/PKGBUILD
```

Stable binary objects and detached signatures are served only after a release
row points at them:

```text
/repo/{architecture}/{filename}
/repo/{architecture}/{filename}.sig
/repo/{architecture}/opr.db
/repo/{architecture}/opr.db.sig
/repo/dev/{architecture}/{filename}
/repo/dev/{architecture}/{filename}.sig
/repo/dev/{architecture}/opr.db
/repo/dev/{architecture}/opr.db.sig
```

The public catalog defaults to stable; a caller must request `channel=dev` to
see or download quarantine artifacts. Each binary channel has its own signed
repository database. Development databases are served only below
`/repo/dev/{architecture}` and never enter the stable install path.

An opt-in Arch configuration can keep quarantine separate from stable:

```ini
[omapkg-dev]
SigLevel = Required TrustedOnly
Server = https://omapkg.example/repo/dev/$arch
```

Import `/repo/key.asc` into the local pacman keyring first. Stable clients use
the same block with `[omapkg]` and `Server = https://omapkg.example/repo/$arch`.
Remove `[omapkg-dev]` when testing is complete.

Unknown paths never become direct R2 keys. Public metadata is similarly
allowlisted by a released ID:

```text
/repo/metadata/{releaseId}/sbom.json
/repo/metadata/{releaseId}/provenance.json
/repo/rollback/{releaseId}.json
```

Dev and stable pacman databases are deterministic gzip-compressed ustar
archives with `desc` and `depends` entries, including package SHA-256 and
base64-encoded detached signatures. Publication, promotion, and quarantine
obtain separate database signatures before atomically switching each D1 active
pointer. Historical snapshots and package objects remain addressable after a
newer batch or rollback.

Rollback changes the stable pointer to a compatible previous release and
publishes an immutable downgrade manifest. Its command uses an absolute HTTPS
URL; binary packages use `pacman -U`, while recipes are downloaded to a local
`PKGBUILD` before `makepkg -si -f`. The immutable manifest advertises an
opt-in client at `/repo/rollback/client.sh`. Run it with a manifest URL when
you want an automatic local downgrade; it checks same-origin HTTPS URLs,
package SHA-256, the detached package signature, and the published key before
calling `sudo pacman -U`. Recipe rollbacks verify the PKGBUILD checksum before
`makepkg -si -f`.

```sh
mkdir -p "$HOME/.local/bin"
curl --fail --proto '=https' --proto-redir '=https' --location \
  --output "$HOME/.local/bin/omapkg-rollback" \
  https://omapkg.example/repo/rollback/client.sh
chmod 0755 "$HOME/.local/bin/omapkg-rollback"
omapkg-rollback https://omapkg.example/repo/rollback/{release-id}.json
```

Running the command provides local opt-in. omapkg never starts a downgrade on a
user's machine by itself. The client requires Bash, `curl`, Python 3, `sha256sum`, and
GnuPG; recipe targets also require `makepkg`.

## Crash reports

Crash reporting is anonymous and opt-in. `POST /api/crashes` accepts only a
released ID, short summary, and consent version. Crash records store no IP
address, user-agent, source text, or account identity. HMAC rate-limit keys
derived from the request address expire after 24 hours and are removed by the
15-minute cleanup job; they are not stored with crash records. Raw report text
is removed after 90 days. Confirmed unresolved incident metadata and audit
entries remain so release decisions keep their context. Three unresolved
reports are the default demotion threshold; set `CRASH_THRESHOLD` in deployment
configuration when policy chooses another value. A stable binary is demoted
only after a fresh signed repository snapshot is ready. If signing is
unavailable, the report is retained and the response marks demotion pending.
Maintainers can resolve a report with authenticated `PATCH /api/crashes` and a
report ID plus reason; resolution and its audit event commit together.

## Read-only MCP

`POST /api/mcp` implements MCP `2026-07-28`, verified against the published
[specification changelog](https://github.com/modelcontextprotocol/modelcontextprotocol/blob/main/docs/specification/2026-07-28/changelog.mdx),
[Streamable HTTP transport](https://github.com/modelcontextprotocol/modelcontextprotocol/blob/main/docs/specification/2026-07-28/basic/transports/streamable-http.mdx),
[discovery](https://modelcontextprotocol.io/specification/draft/server/discover),
[tools](https://modelcontextprotocol.io/specification/draft/server/tools),
[pagination](https://modelcontextprotocol.io/specification/draft/server/utilities/pagination),
[caching](https://modelcontextprotocol.io/specification/draft/server/utilities/caching), and
[schema](https://github.com/modelcontextprotocol/modelcontextprotocol/blob/main/schema/2026-07-28/schema.ts).

The endpoint is stateless. It has no initialize handshake, session header, GET
stream, or write tool. Every POST must carry `MCP-Protocol-Version`, `Mcp-Method`, and
the matching per-request `_meta` protocol version and client capabilities.
`Mcp-Name` is required for `tools/call` and must match the selected tool.
`server/discover`, `tools/list`, and cache hints (`ttlMs`, `cacheScope`) are
implemented. The server advertises only `tools`; it has no resource handlers.
Public tools expose catalog search, released package
evidence, released provenance, and computed metrics. `builds.get` appears only
for an authenticated maintainer and returns private build evidence through the
same server-side role check used by the UI. Search, package lookup, and
provenance lookup accept `channel=dev` only when a caller explicitly requests
quarantine data; their default remains stable.

## Signing setup

Initial deployment may use a dedicated Cloudflare signer Worker with an
OpenPGP signing secret while managed KMS integration is completed. Production
signing must use a separate signer boundary, immutable intent records, package
and repository detached signatures, published public-key bootstrap, and key
rotation/revocation procedures. The control plane contract requires the signer
to return an existing immutable signature object key and
never accepts a caller-supplied signature as proof.

The signer reads intent evidence through authenticated
`GET /api/internal/signing-intents/{id}` and reports its completed operation to
`POST /api/internal/signing-events`. Package and dev/stable database objects
use separate intents and detached signatures. Both routes require private
`CONTROL_TOKEN`; neither route is part of public catalog or MCP surface.
