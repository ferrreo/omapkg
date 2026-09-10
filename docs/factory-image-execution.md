# Private factory image execution

Maintainers start an image run through `POST /api/maintain/factory-runs` with `operation: "image"`, a target ID/unit key, execution policy, and a reviewed image candidate. The response returns `runId`, `attempt`, `dispatchId`, and `inputSha256`. Retry a failed attempt with the same `runId` and a new reviewed candidate; the shared factory run reserves attempts 2 and 3. After attempt 3, use `operation: "image-intervene"` with `sourceRunId` and a human reason to create an audited successor run.

Image candidates bind:

- OCI or system image kind, architecture, profile ID and digest, and output filename.
- Current `native_qualification_plans` row through `nativePlanId`, plus an issuer-signed `factory-image-native-plan` wrapper whose `qualificationPlanSha256` matches that reviewed row. System images use a reviewed `boot` plan; OCI images use a reviewed `install` plan with runtime observations.
- Candidate lock and detached signature, native plan and detached signature, trusted public-key object, and operator-approved builder digest.

Coordinator admission checks current native-plan review authority, configured signing fingerprint and public-key object, configured builder digest, profile digest, and immutable R2 inputs. Worker claims require `factory-image-v1`; this capability is advertised only when image execution is explicitly enabled with `gpg`, the selected container runtime, and an operator-pinned builder script. The worker daemon does not need host root or `/dev/kvm` for package or OCI builds. KVM belongs to VM boot validation, not image construction.

The caller must obtain the wrapper, candidate lock, and detached signatures from the configured signing/native-plan issuer. The coordinator does not accept a self-signed wrapper or synthesize signing authority; missing or stale issuer evidence stops before attempt reservation.

The worker executes the operator-pinned builder inside a network-disabled, read-only container. OCI construction uses ordinary container privileges. The mounted-filesystem system-image assembler uses a privileged container for loop devices and mounts; that requirement is specific to this assembly method and does not require running the worker daemon as root. Only reviewed input files, a writable output directory, and the builder script are mounted. It uploads the exact image bytes through a fenced multipart session, signs observed builder evidence with its worker key, and completes the job through the authenticated coordinator endpoint. The coordinator verifies worker signature, evidence bindings, stored bytes, and the exact factory attempt before finishing the run.
