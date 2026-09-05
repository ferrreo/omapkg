# omapkg

omapkg is an agentic Arch package factory and repository. A user submits an
upstream Git URL or source or binary download URL. The factory inspects the
input, proposes a PKGBUILD and dependency plan, and records the evidence for
review. Maintainers approve the request and the generated revision before a
worker builds it in a disposable offline environment. A separate signer
publishes redistributable packages to dev; reviewed batches can then move to
stable after quarantine checks.

The project source is [ferrreo/omapkg](https://github.com/ferrreo/omapkg).
The package recipe repository is configured per deployment; examples in these
docs use `owner/recipes`.

**Status: under active development.** See the [implementation plan](docs/implementation-plan.md),
[requirements](docs/requirements.md), and [acceptance record](docs/acceptance.md)
for scope and evidence. A passing focused test does not certify a production
deployment.

## Stack

- SvelteKit on Cloudflare Workers for public and maintainer surfaces.
- Flue 2 or newer for agent execution, with Effect 4 for typed domain logic.
- Cloudflare Workflows, Durable Objects, Sandboxes, D1, R2, and AI Gateway
  where each service fits the workload.
- Better Auth with GitHub OAuth and server-side roles.
- A Go Linux worker daemon with Ed25519 identity, one-use enrollment, replay
  protection, and fenced leases.
- A separate pacman-compatible OpenPGP signer. Managed KMS is an optional
  signing boundary.

## Development

Bun, Go, and Docker or Podman cover local development and worker tooling.

```sh
bun install
bun run db:migrate
bun run dev
```

Set `PUBLIC_ORIGIN` to `https://omapkg.example` for a deployment or to your
local development URL when running the app locally. Keep `.env` and
`.dev.vars` ignored. Never put Cloudflare, OAuth, GitHub App, registry, or
signing secrets in tracked files, logs, or agent input.

Run the focused checks before a change is reviewed:

```sh
bun run check
bun test tests
bun run build
cd worker && go test ./...
```

See [deployment](docs/deployment.md) for repeatable setup, [worker protocol](docs/worker-protocol.md)
for registration and job exchange, and [signing design](docs/signing-design.md)
for the package and repository signature boundary.

## Trust boundaries

Requests contain package metadata and upstream locations. They cannot contain
executable PKGBUILDs. The factory treats upstream files, build scripts, and
package metadata as untrusted data. It cannot approve or publish its own
output. Reviewed revisions are immutable, and area plus security approval
binds the full source and recipe manifest. Regeneration needs new approval.

Build environments have no network access or platform secrets. A worker
submits the artifact and provenance; the signer checks approval, identity,
provenance, and artifact digest before signing. Signing keys stay outside build
hosts.

## Maintainer roles

Configure GitHub team membership and server-side grants for area maintainers,
security reviewers, release maintainers, and administrators. The API enforces
these roles for review, promotion, signing, worker enrollment, policy changes,
rollback, audit export, and membership changes. Maintainers cannot grant
themselves access.

The public catalog exposes only data marked public. Maintainer views contain
the private evidence and audit trail needed to review a package.
