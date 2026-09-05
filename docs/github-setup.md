# GitHub repository integration

Configure a separate GitHub repository, such as `owner/recipes`, as the
source of truth for requests, generated PKGBUILDs, metadata, and review-linked
history. Runtime calls use a GitHub App installation token scoped to that one
repository.

The App needs only:

- Metadata: read
- Contents: read and write
- Pull requests: read and write
- Checks: read

Do not grant organization administration, Actions write, secrets, or access to
the application repository.

## Create and install the App

Open [GitHub new App settings](https://github.com/settings/apps/new) while
signed in with an account that owns the recipe repository.

Use:

- App name: a deployment-specific name, such as `omapkg Factory`;
- Homepage URL: `https://omapkg.example`;
- user authorization during installation: disabled;
- callback URL: empty, because this App is for server-to-server access;
- webhook: disabled;
- repository selection: `Only select repositories`, then `owner/recipes`.

After creating the App, generate one private key and install it on the recipe
repository. Keep the downloaded PEM file outside the repository and secret
backups. Record the App and installation identifiers in the deployment's
secret store.

Set the repository as a non-secret variable:

```jsonc
"GITHUB_REPOSITORY": "owner/recipes"
```

Set the other values as Worker secrets:

```sh
printf '%s' '<app-id>' | wrangler secret put GITHUB_APP_ID
printf '%s' '<installation-id>' | wrangler secret put GITHUB_APP_INSTALLATION_ID
wrangler secret put GITHUB_APP_PRIVATE_KEY < /path/to/factory.private-key.pem
```

The Worker mints short-lived installation tokens with `node:crypto`. It never
receives a maintainer's OAuth token and never forwards a GitHub credential to a
non-GitHub URL. Restart or redeploy after rotating the App key.

## Test fallback

For temporary local work, create a
[fine-grained personal access token](https://github.com/settings/personal-access-tokens/new)
limited to `owner/recipes` with Contents read/write, Pull requests read/write,
Checks read, and Metadata read. Store it only in a local secret store, use it
as `GITHUB_REPO_TOKEN`, and remove it after App installation works.

Better Auth uses a separate GitHub OAuth application for maintainer sign-in.
Register its callback as `https://omapkg.example/api/auth/callback/github` for
the example deployment, and map GitHub teams to server-side area, security,
release, and administrator roles. The API enforces each role; hiding a control
in the UI is not authorization.
