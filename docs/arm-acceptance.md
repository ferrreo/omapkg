# omapkg ARM worker acceptance

The development host is x86_64. Its `binfmt_misc` is enabled but has no
AArch64 handler, `sudo -n` is unavailable, and both Docker and Podman return
`Exec format error` for the registered ARM image.

GitHub's standard private-repository ARM64 runner is available as
`ubuntu-24.04-arm` (2 vCPU, 8 GiB RAM, 14 GiB storage). The repository currently
has Actions enabled but no workflow, secret, or self-hosted runner. The manual
workflow in [`.github/workflows/arm-worker-e2e.yml`](../.github/workflows/arm-worker-e2e.yml)
uses that native runner.

Before starting it, a maintainer must:

1. Temporarily enable/select the registered `aarch64` builder and create a
   reviewed ARM test build. Keep the ARM builder disabled as default.
2. Create one short-lived, single-use ARM enrollment token in omapkg.
3. Add the token as the repository Actions secret `OPR_ENROLLMENT_TOKEN`.
4. Start **ARM worker acceptance** from the Actions tab with the HTTPS origin,
   full private ARM image reference, and matching `sha256:` digest as inputs.

The workflow compiles the daemon natively, runs its unit tests, enrolls through
stdin, claims one approved build, and checks that the exact private builder
digest was pulled. The daemon receives its short-lived registry pull credential
through the signed lease API. The workflow contains no Cloudflare account
token, registry token, signing key, or provider credential. Delete
`OPR_ENROLLMENT_TOKEN` after the run; enrollment consumes it once.

The worker command exits successfully only after a job has been claimed and the
private image is present on the fresh runner. A missing approved job fails the
workflow instead of being reported as an ARM acceptance.
