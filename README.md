# omapkg

omapkg turns upstream software into reviewed Arch Linux packages. Submit a
Git repository, source archive, or vendor download URL. An AI agent inspects
the software and drafts a PKGBUILD, dependency plan, and evidence for review.
Maintainers decide what gets built and released.

The project includes the package catalog, maintainer interface, build workers,
and signing service. Redistributable packages enter a signed `dev` repository
before a release maintainer can promote them to `stable`. When a vendor's
license does not allow redistribution, omapkg publishes a recipe with a pinned
vendor download instead of hosting the binary.

The project source is [ferrreo/omapkg](https://github.com/ferrreo/omapkg).
The package recipe repository is configured per deployment; examples in these
docs use `owner/recipes`.

Under active development. See the [implementation plan](docs/implementation-plan.md),
[requirements](docs/requirements.md), and [acceptance record](docs/acceptance.md)
for scope and evidence. A passing focused test does not certify a production
deployment.

## How the services fit together

Three Cloudflare Workers run the application: `omapkg` serves the web app and
API, `omapkg-pipeline` runs generation and publication jobs, and
`omapkg-signer` signs packages and repository databases. The pipeline and
signer are private services reached through Worker service bindings. Separate
Linux hosts run the Go build daemon and disposable build containers.

![Service architecture: web app calls the pipeline, which requests signing; Linux workers exchange jobs with the web API.](docs/diagrams/services.svg)

[Interactive service diagram](docs/diagrams/services.html)
(download and open the HTML locally).

The web app and pipeline share D1 for requests, immutable revisions, reviews,
build jobs, worker leases, releases, and audit records. They share a private
R2 bucket for verified inputs and build output. The signer reads artifacts
from that bucket and writes detached signatures. The web app serves published
objects through its repository and source routes; clients do not access R2
directly. The diagram shows the main calls; these shared storage bindings and
the signer's authenticated callbacks to the web app are described here to keep
the map readable.

The Go daemon claims jobs through the web API, prepares the approved image and
verified inputs, then runs the build and smoke tests offline. It uploads
results and signed provenance through the API. A successful completion queues
the publication workflow, which checks release policy and calls the signer.
The signer reloads a one-use signing intent from the web app and checks the
review, worker identity, provenance, and artifact bytes before signing.

### Frameworks and their jobs

Versions below describe the dependencies in this checkout. Exact pins live in
[package.json](package.json), [signer/package.json](signer/package.json), and
the Go module files.

| Technology | Where it fits |
| --- | --- |
| Svelte 5 and SvelteKit 2 | Public pages, maintainer screens, server loaders, form actions, and HTTP endpoints live in one app. The Cloudflare adapter builds it into the web Worker. |
| Vite 8, TypeScript 6, and Bun | Vite builds the web app and pipeline as separate bundles. TypeScript checks the application code; Bun installs dependencies, runs scripts, and runs the TypeScript tests. Wrangler handles Cloudflare resources and deployment. |
| Better Auth 1.7 | GitHub OAuth and sessions, backed by D1. Server-side team memberships determine what each signed-in user may do. The GitHub App used for recipe pull requests is a separate integration. |
| Flue 2 | Runs the package agent, its tools, persistent inspection state, and structured candidate output. Its Cloudflare target uses Durable Objects for agent execution. |
| Cloudflare Workflows | `FactoryWorkflow` starts generation with retries; `PublicationWorkflow` processes successful builds and retries publication. These coordinate jobs around the Flue agent. |
| Cloudflare Sandbox | Gives factory tools a place to inspect sources, prepare dependencies, and lint recipes. Source access uses controlled host permissions. Final Arch builds run on the Linux workers. |
| pi-ai and Cloudflare AI Gateway | The pipeline registers a pi-ai provider with Flue. Model requests go through AI Gateway to OpenRouter, using the gateway's stored provider credentials. Model selection lives in `services/pipeline/model.ts`. |
| Valibot 1 and Effect 4 RC | Valibot validates factory requests, tool inputs, and candidate output. Effect currently wraps the shared D1 query helper; most server logic uses ordinary async TypeScript. |
| Go and rootless Podman or Docker | The Linux daemon handles enrollment, job claims, input preparation, containers, and uploads. Builder images are pinned by digest and selected for `x86_64` or `aarch64`. |
| OpenPGP.js 6 | The isolated signer Worker produces pacman-compatible signatures. An optional Go adapter uses AWS KMS to keep private key material in KMS. |

### Inside the factory

![Factory architecture: an approved request enters FactoryWorkflow, which dispatches a Flue agent with model and sandbox tools; its candidate becomes a revision and GitHub pull request.](docs/diagrams/factory.svg)

[Interactive factory diagram](docs/diagrams/factory.html)
(download and open the HTML locally).

Flue handles the agent conversation and tool execution. The surrounding
factory code validates its candidate, assigns the package release number,
creates the recipe pull request, and persists the revision in D1. This is
the handoff from generated output to maintainer review.

## From request to release

1. Submit package metadata and an upstream URL. Requests cannot include an
   executable PKGBUILD. A maintainer approves the request before generation.
2. The factory inspects the source, pins its inputs, collects license evidence,
   and proposes a recipe, dependencies, and smoke commands. It opens a pull
   request in the configured recipe repository.
3. Area and security reviewers approve the exact revision and its full source
   and recipe manifest. Regenerating the recipe creates a revision that needs
   fresh approval.
4. A registered worker claims an approved job. It fetches the pinned builder
   image and verified inputs, builds in a disposable offline environment, and
   runs smoke tests. The daemon returns the result and Ed25519-signed provenance.
5. Publication checks the successful build and review evidence. For a binary
   release, the signer verifies and signs the package before it enters `dev`.
   Recipe-only releases publish the recipe without a binary artifact.
6. A release maintainer promotes a reviewed batch to `stable` after quarantine
   and policy checks. The configured quarantine defaults to 48 hours. Retained
   release history supports rollback.

The agent cannot approve its own output, start a build, sign a package, or
promote a release.

## Finding your way around

| Path | What lives there |
| --- | --- |
| [`src/routes/`](src/routes/) | SvelteKit pages and endpoints. `maintain/` holds review and administration screens; `api/worker/` is the build-worker protocol; `repo/` serves published repositories. |
| [`src/lib/components/`](src/lib/components/) | Shared Svelte UI components for public pages and the maintainer interface. |
| [`src/lib/server/`](src/lib/server/) | Authentication, authorization, request review, worker protocol, signing intents, release policy, and database access. `factory.ts` also contains the Flue agent definition and generation logic. |
| [`services/pipeline/`](services/pipeline/) | The private pipeline Worker, workflow entry points, agent tools, source verification, recipe generation, GitHub pull requests, publication dispatch, and scheduled checks. It imports shared server code from `src/lib/server/`. |
| [`worker/`](worker/) | The Go daemon, container runner, installer, systemd unit, and builder Dockerfiles. See the [worker README](worker/README.md) for host setup. |
| [`signer/`](signer/) | The private OpenPGP signer Worker and its own dependencies and Wrangler config. [`signer/kms/`](signer/kms/) is the optional Go signing service. See the [signer README](signer/README.md). |
| [`migrations/`](migrations/) | D1 schema migrations, including auth, reviews, workers, signing, and releases. |
| [`tests/`](tests/) | Bun tests for application policy and protocols. Go tests live beside the worker and KMS code; signer tests live under `signer/src/`. |
| [`scripts/`](scripts/) | Provisioning, deployment, and ARM builder-image tooling. |
| [`static/`](static/) | Fonts, branding, and other static web assets. |
| [`docs/`](docs/) | Architecture, deployment, security and protocol details, plus acceptance evidence. Diagram sources and standalone viewers live in `docs/diagrams/`. |

The root package installs dependencies for both the web app and pipeline, but
they have separate Vite and Wrangler configurations. The signer has its own
Bun package. The worker and KMS adapter are separate Go modules.

## Development

Bun runs the web development commands. Use Go and rootless Docker or Podman
when working on build hosts; the pipeline build also needs a Node runtime
supported by the pinned Flue and Vite packages.

```sh
bun install
bun run db:migrate
bun run dev
```

Set `PUBLIC_ORIGIN` to `https://omapkg.example` for a deployment or to your
local development URL when running the app locally. Keep `.env` and
`.dev.vars` ignored. Never put Cloudflare, OAuth, GitHub App, registry, or
signing secrets in tracked files, logs, or agent input.

The commands above start the web app with local D1 state. Running the full
package flow also needs the pipeline and signer services, GitHub integration,
AI Gateway configuration, and an enrolled build worker. Use
[`.env.example`](.env.example) as a configuration reference and follow the
deployment guide for those services.

Run the focused checks before a change is reviewed:

```sh
bun run check
bun test tests
bun run build
cd worker && go test ./...
```

For pipeline changes, also run `bun run check:pipeline` and
`bunx vite build --config services/pipeline/vite.config.ts` from the root.
Signer changes have their own checks: run `bun install`, `bun run check`, and
`bun test` inside `signer/`. Run `go test ./...` inside `signer/kms/` when
changing the managed signing adapter.

See [deployment](docs/deployment.md) for repeatable setup, [worker protocol](docs/worker-protocol.md)
for registration and job exchange, and [signing design](docs/signing-design.md)
for the package and repository signature boundary.

## Trust boundaries

Upstream files, build scripts, and package metadata are untrusted data.
Reviewed revisions are immutable, and area plus security approval binds the
full source and recipe manifest.

Build environments have no network access or platform secrets. A worker
submits the artifact and provenance; the signer checks approval, identity,
provenance, and artifact digest before signing. Signing keys stay outside build
hosts.

Worker enrollment uses one-use tokens. Each daemon has an Ed25519 identity;
authenticated requests include replay protection, and fenced leases prevent a
stale worker from completing a job it no longer owns. Registry pull credentials
stay with the daemon, outside the build container.

## Maintainer roles

Configure server-side team memberships tied to GitHub identities for area maintainers,
security reviewers, release maintainers, and administrators. The API enforces
these roles for review, promotion, signing, worker enrollment, policy changes,
rollback, audit export, and membership changes. Maintainers cannot grant
themselves access.

The public catalog exposes only data marked public. Maintainer views contain
the private evidence and audit trail needed to review a package.
