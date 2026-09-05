# Acceptance progress

Status recorded on 2026-09-05. This record covers public discovery, Git, tar,
and `.run` intake, factory review, signed x86_64 and native ARM test packages,
crash quarantine, rollback, and the deployed application checks. Evidence is
scoped to those test packages and environments. The worker watcher metadata
fallback is the only current functional follow-up.

## Verified path

The Hello path produced a reviewed recipe, an approved pull request, an
offline build, smoke checks, separate package and repository database
signatures, and clean rootless Arch verification and installation in dev and
stable. Hello 2.12 and 2.12.1 passed on x86_64 and a native ARM worker. A
clean client rolled back 2.12.1 to 2.12-6 and verified 142 files.

Git dmenu 5.4-2 passed on both architectures with public signatures and a
clean x86_64 install. Its 14 files, LICENSE, and version command were checked;
the command exited 0. NVIDIA-style
`NVIDIA-Linux-x86_64-610.57.04.run` 610.57.04-3 passed as a Surface B public
recipe. The isolated build and install exposed no helpers or credentials, the
NVML help command exited 0, and LICENSE was present. Binary publication routes
returned 404 as required.

The public loader accepts request descriptions up to 500 characters and
factory descriptions up to 160 characters while retaining compatibility with
older requests. The local worker user service is enabled. A license smoke-path
correction passed its build and dev-release checks.

The latest web and pipeline checks passed 178 tests with 939 `expect()` calls
and zero Svelte warnings. The natural Chris voice showcase passed independent
media checks with 20 real shots at 1920×1080 H.264 and 30 fps; its video stream
is 130.233 seconds and its narration is 130.248 seconds at -16.2 LUFS and
-1.7 dBTP. Showcase media remains outside the repository; the production
record is in [showcase script](showcase-script.md).

The first scheduled crash-quarantine run completed successfully. Three real
reports from independent IPs were resolved in the dashboard. The affected
dmenu release moved from stable to dev; signed repository indexes stayed valid,
the stable index excluded dmenu, the dev index included it, and the package
and its signature remained valid.

The temporary recording session was revoked after capture. The audit stream
records `auth.recording_session_revoked`, and the old session cookie no longer
authenticates.

| Area | Status | Evidence or limit |
| --- | --- | --- |
| Public site and loader | verified | Public discovery and loader routes respond. |
| Hello tar builds | verified for test packages | Hello 2.12 and 2.12.1 passed on x86_64 and a native ARM worker. |
| Git dmenu 5.4-2 | verified | Both architectures were signed and published; a clean x86_64 install checked 14 files, LICENSE, and a version command with exit 0. |
| NVIDIA-style `.run` 610.57.04-3 | verified as Surface B | Recipe built and installed in isolation with no helpers or credentials; NVML help exited 0 and LICENSE was present. Binary routes returned 404. |
| Offline build and smoke | verified for test packages | Clean rootless Arch verification, installation, and smoke checks passed. |
| Package and repository signing | verified for test packages | Separate package and database signatures passed. |
| ARM worker/build | verified for current test packages | Native ARM passed for Hello and Git dmenu. Stable promotion remains release-scoped by architecture. |
| Crash quarantine | verified for the controlled run | Three independent reports were resolved in the dashboard and the affected dmenu release moved from stable to dev with valid signed indexes and package files. |
| Rollback | verified for the test package | A clean client rolled back 2.12.1 to 2.12-6 and verified 142 files. |
| OAuth and maintainer session | verified | GitHub sign-in, server-side maintainer access, recorded approvals, and session revocation were verified. |
| Managed KMS | adapter wired | Managed KMS remains optional and is not provisioned by this deployment. Initial signing uses an isolated signer boundary. |
| Worker watcher metadata | unverified | Worker listing returns HTTP 200, but HEAD and range metadata requests can time out. The existing sandbox fallback still needs its acceptance check. |

## Public evidence limits

The verified package paths show the controls for the listed sources and
architectures. They do not certify arbitrary upstream software, every package
format, every host provider, or a managed-KMS deployment. Public safety copy
should describe the evidence and limits rather than promise that upstream
software is harmless.
