# omapkg worker

Build static Linux binaries:

```sh
WORKER_VERSION=v0.1.0
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-s -w -X main.workerVersion=$WORKER_VERSION" -o opr-worker .
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags "-s -w -X main.workerVersion=$WORKER_VERSION" -o opr-worker .
```

Release binaries report this embedded version through `opr-worker version`.

Install or upgrade with a versioned binary. The installer keeps prior releases,
updates launcher symlink atomically, refuses to replace a regular launcher or a
custom unit without `--replace-unit`, and leaves an active service running
until an explicit restart:

```sh
# Copy value from authenticated release manifest or release page.
EXPECTED_SHA256=...
sudo ./install.sh --binary ./opr-worker --version "$WORKER_VERSION" --sha256 "$EXPECTED_SHA256"
sudo systemctl restart opr-worker.service
```

Use `--enable`, `--start`, or `--restart` when you want those service actions.
The unit runs as the dedicated `opr-worker` user with private state and
rootless Podman/Docker prerequisites. Configure rootless Podman subuid/subgid
ranges and its user service before starting; Docker rootless hosts must expose
their user daemon to that service account.

`install.sh` requires a binary whose SHA-256 exactly matches required
`--sha256`, then checks that `opr-worker version` exactly matches `--version`.
It hashes and executes a private staging copy, so a changing source path cannot
alter the verified bytes. Release paths are
`/usr/local/lib/opr-worker/releases/` and the launcher is an atomic symlink at
`/usr/local/bin/opr-worker`. It never downloads or publishes a binary, so the
authenticated release manifest and release signing stay outside this local
installer. Do not derive `--sha256` from the same untrusted binary after
download; copy the value from the signed project release channel. The unit
template is also available as `opr-worker.service`.

Enroll a host with a single-use token. Reading from stdin avoids exposing the token in the process list:

```sh
printf '%s\n' "$OPR_ENROLLMENT_TOKEN" | ./opr-worker enroll \
  --origin https://omapkg.example \
  --name worker-x86-1 \
  --architecture x86_64 \
  --state-dir "$HOME/.config/opr-worker" \
  --token-stdin
```

`--image` and `--image-digest` may be supplied for older servers that do not
return a reviewed `imageRef` with each claim. Current servers select a
digest-pinned image per architecture; hosts use that claim without local
reconfiguration.

Enrollment, idle claims, and job heartbeats report the embedded daemon version,
selected container runtime, and fixed capabilities (`offline-oci`,
`multipart-upload`, `registry-pull`). These fields are signed request metadata
and are informational; they do not grant extra job authority.

Run the poller under a dedicated Linux account:

```sh
./opr-worker run --config /var/lib/opr-worker/config.json
```

When using the installed systemd unit, enroll as its service account and pass
`--state-dir /var/lib/opr-worker` so config lands beside the unit's configured
state path.

The config is written atomically with mode `0600` in a mode `0700` directory. The daemon needs outbound HTTPS and the selected `podman` or `docker` runtime. It builds with Arch `makepkg` in a fresh network-disabled OCI root, then installs the exact package in a disposable offline smoke image before running reviewed commands as an unprivileged UID. It never receives inbound worker connections or stores platform, provider, or signing credentials.

Successful signed provenance includes exact `.PKGINFO` package metadata: name,
full version, architecture, installed size, and ordered `depends`, `provides`,
`conflicts`, and `replaces` lists. Relation entries are bounded and validated
with Arch syntax, including generated SONAME values.

Run the native OCI acceptance test against a local digest-pinned builder image:

```sh
OPR_WORKER_E2E_IMAGE=localhost/opr-builder:test@sha256:... go test -run TestRunnerExecuteNativeOCI -v
```

Set `OPR_WORKER_E2E_RUNTIME=docker` to exercise Docker instead of Podman.
Set `OPR_WORKER_E2E_OUTPUT=/path/to/package.pkg.tar.zst` to retain package
bytes plus decoded `.PKGINFO` and `.BUILDINFO` for repository acceptance checks.

For an approved private registry builder, the daemon requests a short-lived
pull token only when the exact digest is absent locally. It uses
an ephemeral private auth directory and sends the password through stdin; no
registry credential enters worker config, containers, logs, or provenance.
