# Arch build environment

Worker images include Arch clean-build tools. `arch-install-scripts` provides
`mkarchroot` and `arch-nspawn`; `devtools` provides `makechrootpkg`. The
default runner uses direct `makepkg` in a pinned OCI root. An Omarchy-derived
stable profile follows the Omarchy mirror; a plain Arch `base-devel` profile
remains available when portability matters.

## Build a local image

Pin the base image by digest in the deployment's private image policy. Keep
the digest paired with the image reference:

```text
docker.io/library/archlinux:base-devel@sha256:<64 lowercase hex>
```

Build a local profile from the repository:

```sh
podman pull docker.io/library/archlinux:base-devel
podman build --pull=never \
  --tag localhost/omapkg-arch-builder:plain \
  --file worker/Dockerfile worker
```

The Omarchy profile uses the same pinned base, verifies the public
`omarchy-keyring`, and then synchronizes packages with the selected stable
mirror:

```sh
podman build --pull=never \
  --tag localhost/omapkg-arch-builder:omarchy-stable \
  --file worker/images/omarchy/Dockerfile worker/images/omarchy
```

Use the image reference and its exact content digest as one policy value:

```sh
export FACTORY_BUILDER_IMAGE='localhost/omapkg-arch-builder@sha256:<64 lowercase hex>'
export FACTORY_BUILDER_IMAGE_DIGEST='sha256:<64 lowercase hex>'
```

The factory reads these values from policy rather than from agent output, so a
recipe cannot select a different builder image. A remote worker uses the same
digest in a private registry reference. Keep the local OCI archive and its
checksum until the registry copy has been checked.

## Registry credentials

Use a short-lived pull-only credential for a private registry. Never reuse an
account deployment token on a build host. With a platform-specific credential
command, log in through stdin using a Docker config owned by the worker
account, then remove the response file:

```sh
jq -r .password /run/user/$(id -u)/registry-credential.json \
  | docker --config /run/user/$(id -u)/omapkg-docker-config login \
      registry.example --username "$(jq -r .username /run/user/$(id -u)/registry-credential.json)" --password-stdin
rm -f /run/user/$(id -u)/registry-credential.json
```

The Go daemon verifies the exact `@sha256:` digest before each build. Builder
hosts never receive the platform account token.

## AArch64 builder

The ARM profile starts from the official Arch Linux ARM generic AArch64
rootfs, not the x86_64 Arch Docker image. Its public source is
`https://os.archlinuxarm.org/os/ArchLinuxARM-aarch64-latest.tar.gz`. Verify
the downloaded rootfs with the published checksum and detached signature
before building the image. Add `base-devel`, `devtools`,
`arch-install-scripts`, binutils, libarchive, RPM tooling, and SquashFS
tooling, then declare `linux/arm64` in the OCI manifest.

```sh
scripts/build-arm-image.sh
```

The script keeps downloads and its build context under a local working
directory, verifies the checksum and detached signature, and requires a
native ARM64 runtime or a Docker/Podman host with AArch64 binfmt support. A
host without that handler reports `Exec format error`; run the acceptance on a
native ARM64 host in that case.

DigitalOcean droplets are a suitable x86_64 host target. Use a provider with
native ARM64 capacity for ARM workers. See DigitalOcean's public [Droplet
availability](https://docs.digitalocean.com/products/droplets/details/availability/)
and [Linux image catalog](https://docs.digitalocean.com/products/droplets/details/images/)
for current options.

## Real package check

`worker/testdata/real-build` describes the GNU Hello fixture. The check
downloads its public source during preparation, then builds a real
`.pkg.tar.zst` with the pinned image. The build container has no network, a
read-only image root, no Linux capabilities, and no host directories beyond
temporary work and output paths. A second unprivileged container checks the
package contents and confirms that an HTTPS request fails.

```sh
worker/testdata/real-build/run.sh
```

The script requires the two `FACTORY_BUILDER_*` variables. It never mounts a
home directory, daemon key, container socket, or platform secret.

## Worker host requirements

The daemon prepares reviewed dependencies in a temporary networked container,
then runs the build and package smoke test with network access disabled. The
host needs rootless Podman or Docker, outbound HTTPS for image and dependency
preparation, enough disk for one image plus one disposable dependency layer,
and a private state directory. The worker never needs a host container socket,
home directory, or platform secret.

Run the native OCI acceptance test against a local digest-pinned builder:

```sh
cd worker
OPR_WORKER_E2E_IMAGE="$FACTORY_BUILDER_IMAGE" go test -run TestRunnerExecuteNativeOCI -v
```

Set `OPR_WORKER_E2E_RUNTIME=docker` to exercise Docker instead of Podman. Set
`OPR_WORKER_E2E_OUTPUT=/path/to/package.pkg.tar.zst` to retain package bytes
and decoded `.PKGINFO` and `.BUILDINFO` for repository checks.

On a native ARM64 host, run the same test with an approved ARM image:

```sh
cd worker
OPR_WORKER_E2E_ARCH=aarch64 \
OPR_WORKER_E2E_IMAGE='registry.example/omapkg/arch-builder:aarch64@sha256:<64 lowercase hex>' \
go test -run TestRunnerExecuteNativeOCI -v
```

Never reuse an x86_64 digest for an ARM worker. The Omarchy builder recipe is
available at the public [Omarchy package repository](https://github.com/omacom/omarchy-pkgs/blob/master/build/Dockerfile);
choose a mirror and architecture that the worker can actually use.

Enroll a worker with its exact pinned reference:

```sh
cd worker
go run . enroll \
  --origin https://omapkg.example \
  --name worker-x86-1 \
  --architecture x86_64 \
  --runtime podman \
  --image "$FACTORY_BUILDER_IMAGE" \
  --image-digest "$FACTORY_BUILDER_IMAGE_DIGEST" \
  --token-stdin
```

For ARM, use its exact reference and enroll only on a native ARM64 host:

```sh
printf '%s\n' "$OPR_ENROLLMENT_TOKEN" | go run . enroll \
  --origin https://omapkg.example \
  --name worker-arm64-1 \
  --architecture aarch64 \
  --runtime podman \
  --image 'registry.example/omapkg/arch-builder:aarch64@sha256:<64 lowercase hex>' \
  --image-digest 'sha256:<64 lowercase hex>' \
  --token-stdin
```

Run the daemon after a maintainer approves the enrolled worker:

```sh
go run . run --config "$HOME/.config/opr-worker/config.json"
```

For a system service, build a versioned binary and run
`worker/install.sh --binary ./opr-worker --version vX.Y.Z --sha256 <trusted-release-sha256>`.
The digest must come from an authenticated project release manifest, not from
the downloaded binary. The installer retains older release binaries, updates
its launcher atomically, and does not restart an active service unless
`--restart` is passed. The installed `opr-worker.service` runs under a
dedicated unprivileged user with a private state directory.

## NVIDIA extraction acceptance

The NVIDIA-style `.run` fixture is checked with
`offlineVendorExtractCommand('run', ...)` in the isolated builder image. The
input mount is read-only. The container runs as an unprivileged UID, with no
network, no capabilities, no new privileges, and a read-only image root.

The fixture checksum and extracted file count are recorded with the test
fixture. The command passes `--extract-only`; it never installs a driver or
executes an installer hook on the host. Keep the fixture and tracked worktree
unchanged after cleanup.
