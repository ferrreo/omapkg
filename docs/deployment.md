# Deployment

This guide describes a repeatable deployment without tying it to one account,
zone, or host. Replace example names and secret references with values from
your environment. Keep those values outside the repository.

## Resource layout

The control plane uses Cloudflare services where they fit the workload:

| Resource | Example role | Data or behavior |
| --- | --- | --- |
| Worker | `omapkg` | SvelteKit web interface, API, authentication, and public catalog |
| Worker | `omapkg-pipeline` | Private factory orchestration and build-result processing |
| Worker | `omapkg-signer` | Private package and repository signing boundary |
| Sandbox | `omapkg-factory-sandbox` | Source inspection and dependency preparation without secrets |
| Durable Object | `AgentRun` | Serialized agent and lease coordination where needed |
| Workflow | `PackagePipeline` | Retryable request, review, build, sign, and publication stages |
| D1 | `control-db` | Requests, revisions, reviews, workers, releases, and audit indexes |
| R2 | `artifacts` | Immutable packages, recipes, manifests, attestations, and history |
| AI Gateway | `omapkg` | Model routing, budgets, and request observability |
| Container registry | `builder-images` | Digest-pinned Arch build images |

Attach the public hostname for your deployment, for example
`https://omapkg.example`. The GitHub OAuth callback then is:

```text
https://omapkg.example/api/auth/callback/github
```

Use the matching local callback during development. The public catalog and
authenticated maintainer routes share the SvelteKit application, but their
data and authorization boundaries remain separate.

## Credentials and secrets

Create an account-scoped Cloudflare API token with only the permissions needed
to provision and deploy the selected resources. Keep it in a local secret
store. Do not place it in `wrangler.jsonc`, source, CI output, or a ticket.

Worker secrets should be supplied through the platform secret manager. Typical
names include:

- `BETTER_AUTH_SECRET` and GitHub OAuth client values for the web Worker;
- `GITHUB_APP_PRIVATE_KEY` or a temporary `GITHUB_REPO_TOKEN` for reviewed PRs
  in `owner/recipes`;
- `AI_GATEWAY_TOKEN` for the pipeline Worker;
- `SIGNER_TOKEN` and the signer-only key or KMS connection values;
- `REGISTRY_API_TOKEN` for short-lived builder image pull credentials.

The pipeline and signer receive service bindings and narrowly scoped secrets.
Build workers receive only a short-lived lease credential and, when required,
a pull-only registry credential for the approved image. They never receive a
Cloudflare account token, GitHub OAuth secret, provider key, or package
signing key.

## Provision and deploy

Run from the repository root after configuring local secrets:

```sh
bun scripts/provision.ts
```

The provisioning script should check exact resource names first, create only
missing resources, and print identifiers without printing credentials. Review
the generated bindings and migrations before deployment.

Run the checks and deploy the web Worker and remote migrations:

```sh
bun run check
bun run build
bun scripts/deploy.ts
```

Deploy the signer and pipeline Workers separately after their configurations
and service bindings are ready. Reapply bindings idempotently after each
deployment. Keep the private pipeline route and signer route inaccessible from
the public hostname.

## Pipeline and build images

Build the pipeline bundle with the Node runtime supported by the pinned Flue
and SvelteKit packages:

```sh
bunx vite build --config services/pipeline/vite.config.ts
```

Deploy the generated Wrangler configuration. Pin every builder image by its
full registry reference and content digest:

```text
registry.example/omapkg/builder:arch-stable@sha256:<64 lowercase hex>
```

The selected image must match the job architecture. Approved jobs retain the
image digest recorded at review time, even if an administrator later changes
the default image. Use an Omarchy-derived Arch image when its package mirror
and architecture match the job; keep a plain Arch `base-devel` profile for
portable builds.

Cloudflare Sandboxes handle online source inspection and dependency
preparation when their supported runtime is sufficient. Offline Arch builds
remain on registered Linux workers when the sandbox cannot provide the needed
architecture or isolation. Each build starts with a fresh root, no network,
no signing material, and no platform credentials.

## GitHub integration

The recipe repository is configured as `owner/recipes` in this public example.
Install a GitHub App only on that repository with Metadata read, Contents
read/write, Pull requests read/write, and Checks read. Do not grant
organization administration, Actions write, secrets, or access to the
application repository.

Use a separate Better Auth OAuth application for maintainer sign-in. Store its
client secret as a deployment secret and register the callback under the
deployment's public hostname. GitHub identities map to configured teams and
server-side roles; UI visibility is not authorization.

## Signing and managed KMS

The initial deployment can use a dedicated signer Worker with its private
OpenPGP key in a signer-only secret. A managed KMS adapter is available for a
later migration. In either mode, the signer reloads the immutable artifact,
checks the exact review and attestation state, hashes the bytes, creates the
pacman-compatible detached signature, and records the result.

Managed KMS needs an asymmetric signing key, a region, and a principal limited
to signing and public-key reads. Supply these through the host or platform
secret manager. The RSA private material remains in KMS; it never enters a
build image, worker daemon, source bundle, or log. See [signing design](signing-design.md)
for the packet and rotation details.

## Acceptance evidence

The recorded test deployment passed 178 tests with 939 `expect()` calls and
zero Svelte warnings. It covered signed Hello and Git dmenu packages on
x86_64 and native ARM, a Surface B `.run` recipe, offline smoke checks, crash
quarantine, and clean-client rollback. See [acceptance progress](acceptance.md)
for the evidence scope and limits.

Worker listing currently returns HTTP 200. HEAD and range metadata requests can
still time out; the existing sandbox metadata fallback remains a functional
follow-up until it passes its checks.

The public repository URL for this project is
[github.com/ferrreo/omapkg](https://github.com/ferrreo/omapkg). Deployment
ownership, host addresses, account identifiers, resource IDs, and credentials
belong in the operator's private environment records.
