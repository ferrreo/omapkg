# omapkg ARM worker acceptance

The development host is x86_64. Native ARM verification uses GitHub's
`ubuntu-24.04-arm` runner. The manual
[ARM worker acceptance workflow](../.github/workflows/arm-worker-e2e.yml) claims
one reviewed ARM build. There is no continuously running ARM worker.

Before starting it, a maintainer must:

1. Select the validated `aarch64` builder and create a reviewed ARM test build.
2. Create one short-lived, single-use ARM enrollment token in omapkg.
3. Add the token as the repository Actions secret `OPR_ENROLLMENT_TOKEN`.
4. Start **ARM worker acceptance** from the Actions tab with the HTTPS origin,
   full private ARM image reference, matching `sha256:` digest, and a separately pinned minimal ARM runtime image as inputs.

The workflow compiles the daemon natively, runs its unit tests, enrolls through
stdin, claims one approved build, and checks that the exact private builder
digest was pulled. The daemon receives its short-lived registry pull credential
through the signed lease API. The workflow contains no Cloudflare account
token, registry token, signing key, or provider credential. Delete
`OPR_ENROLLMENT_TOKEN` after the run; enrollment consumes it once.

The worker command exits successfully only after a job has been claimed and the
private image is present on the fresh runner. A missing approved job fails the
workflow instead of being reported as an ARM acceptance.

The **ARM runtime evidence validation** workflow builds both images from the
signature-verified official rootfs, pushes them with a temporary
`REGISTRY_ROLLOUT_AUTH` Docker auth JSON secret, and runs native Go/OCI regression
checks. Supply registry namespace and a new rollout tag. Register the resulting
digests only after the validation step passes; then delete the temporary secret.

Validated rollout (September 9, 2026):

- Builder: `registry.cloudflare.com/02b05e9d2ce87ca2ccd30cbb50b6eaf3/omarpkg-arch-builder@sha256:f640f189a7cb91a3a1f0f5e654ff7ecd3c854e092589178c26b5304c8d18d440`
- Runtime: `registry.cloudflare.com/02b05e9d2ce87ca2ccd30cbb50b6eaf3/omarpkg-arch-runtime@sha256:d092c726874b17937ddaff0c089e6e63b01599b4bad69a4e079cbc303b163efc`
- [Successful native validation](https://github.com/ferrreo/omapkg/actions/runs/34378972091).

The official ARM rootfs requires `pacman-key --init` and population of
`archlinuxarm` before installing packages. ShellCheck is not in ARM repositories;
the builder pins the official static 0.11.0 ARM binary by SHA-256.
