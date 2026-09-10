# Local factory diagnostic

Run `bun scripts/factory-check.ts` for a read-only prerequisite report. It checks
tool versions, native architecture, OCI isolation, an explicitly selected worker
config, storage and memory capacity, and configured service connectivity. It
never enrolls a worker, installs a host dependency, edits configuration, or
prints credential values.

Use `--config PATH` (or `OPR_WORKER_CONFIG`) to validate a worker config. The
config must contain only the fields accepted by `worker/protocol.go`, keep
`config.json` private, use a digest-pinned image when an image is configured,
and place `stateDir` beside the config. Optional pipeline and signer probes use
`PIPELINE_URL` and `SIGNER_URL`; their URL values are not printed.

Run `bun scripts/factory-check.ts --deep` for a disposable self-check. Deep mode
renders the pinned OPR fixtures, system and OPR policy paths, the required
template matrix, a two-member cohort, deterministic repair outcomes, an
ephemeral signing identity, the worker's real reproducibility pair harness, a
canonical dossier export, and the byte comparator. Image profiles that need a
native host or KVM remain `incomplete` until those prerequisites are available.
Fixture Go/OCI subprocesses receive a disposable, whitelisted environment; no
production token, service origin, or signing key is inherited.
The normal run removes its own temporary namespace. Use
`--preserve-failures` to keep it for inspection, or `--work-dir PATH` to place
the owned namespace beneath a chosen directory.

Output is human-readable by default; `--json` emits one canonical diagnostic
document for automation. Required failures and incomplete checks return a
nonzero status. Native image acceptance is opt-in with
`FACTORY_CHECK_IMAGE_ACCEPTANCE=1`; without it, image profiles remain
incomplete. No live-agent CLI mode is exposed; live model spend is disabled.
