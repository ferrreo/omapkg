# Private factory image execution

Maintainers start an image run through `POST /api/maintain/factory-runs` with `operation: "image"`, a target ID/unit key, execution policy, and a reviewed image candidate. The response returns `runId` and `workflowId`; the durable workflow reserves attempts 1–3. On failure, Flue receives bounded failure evidence and proposes a new immutable image definition within stored policy. After attempt 3, use `operation: "image-intervene"` with `sourceRunId` and a human reason to create an audited successor run.

Image candidates bind:

- OCI or system image kind, architecture, profile ID and digest, and output filename.
- Authenticated construction policy hash through `constructionPolicySha256`, plus a retained `factory-image-construction-proof` wrapper whose `runPolicySha256`, candidate, profile, architecture, and retained input lock match the construction request. Post-build boot/install qualification is a separate output gate.
- Candidate lock, construction proof, trusted public-key object for package/repository verification, and operator-approved builder digest.

Coordinator admission checks the authenticated construction policy, configured signing fingerprint and public-key object, configured builder digest, proof/profile digest, and immutable R2 inputs. Worker claims require `factory-image-v1`; this capability is advertised only when image execution is explicitly enabled with `gpg`, the selected container runtime, a full digest-pinned builder image, and an operator-pinned builder script. Startup config validation checks that the worker is running on its declared native kernel architecture, inspects the builder image locally for its manifest digest and Linux target architecture, then hashes the protected builder script bytes against the configured SHA-256 before the daemon advertises or claims image work. These checks run once while loading config; heartbeats remain lease renewals. A missing image, wrong image platform, non-native worker, or changed script stops startup. The worker daemon does not need host root or `/dev/kvm` for package or OCI builds. KVM belongs to VM boot validation, not image construction.

The coordinator binds the wrapper, candidate lock, profile, policy, and worker lease through an authenticated coordinator construction binding. The data lock carries no approval authority; package/repository signatures remain verified during assembly and final publication uses its existing independent signing gates.

OCI construction failures use bounded repair attempts. The repair agent receives the verified Dockerfile bytes, returns replacement Dockerfile text and a short reason, and cannot change the reviewed context, profile, authority, source inputs, or policy. The coordinator retains the replacement, a new candidate lock, and a regenerated construction proof under new digests before re-authorizing the candidate. System-image repairs stop for human intervention unless an independently authorized mutable candidate was supplied.

The worker executes the operator-pinned builder inside a network-disabled, read-only container with 512 process slots, 4 GiB memory, and 2 CPUs. OCI construction uses ordinary container privileges. The mounted-filesystem system-image assembler uses a privileged container for loop devices and mounts; that requirement is specific to this assembly method and does not require running the worker daemon as root. Only reviewed input files, a writable output directory, and the builder script are mounted. Each retained input and the extracted system context are limited to 4 GiB; the context must contain regular package and signature files. Image output uploads are limited to 64 GiB over 8 MiB multipart parts. OCI builders compute their actual exported manifest digest after construction; the final OCI archive is repacked with sorted entries, `SOURCE_DATE_EPOCH` metadata, and numeric root ownership so archive bytes are stable across runs. Before provenance is written, the exported OCI config must report Linux and the architecture declared by the reviewed profile. That observed digest is signed and used for activation. The worker uploads exact image bytes through a fenced multipart session, signs observed builder evidence with its worker key, and completes the job through the authenticated coordinator endpoint. The coordinator verifies worker signature, evidence bindings, stored bytes, and the exact factory attempt before finishing the run.

The real rootless OCI acceptance pair and the production TypeScript completion bridge are opt-in because they need a local digest-pinned Buildah tool image. Run the native A/B pair, then retain one private fixture under `.local` and pass its completion and artifact through the production D1/R2 completion handler:

```sh
tool_image='localhost/opr-image-tools:factory-test@sha256:0227f2bef35e21743f6a37f71aec57f823711ac6bc9675070faa3c827a8acfa3'
(cd worker && OPR_FACTORY_IMAGE_OCI_E2E=1 OPR_FACTORY_IMAGE_OCI_AB=1 OPR_FACTORY_IMAGE_OCI_IMAGE="$tool_image" go test -run TestFactoryImageOCIRealRootlessExecution -count=1 -v)
fixture="$PWD/worker/.local/factory-evidence/oci/fixture.json"
(cd worker && OPR_FACTORY_IMAGE_OCI_E2E=1 OPR_FACTORY_IMAGE_OCI_IMAGE="$tool_image" OPR_FACTORY_IMAGE_E2E_FIXTURE="$fixture" go test -run TestFactoryImageOCIRealRootlessExecution -count=1 -v)
OPR_FACTORY_IMAGE_E2E_FIXTURE="$fixture" bun test tests/factory-image-run.test.ts
```

The bridge seeds the existing in-memory D1/R2 fixture and calls `completePrivateFactoryImage`; no private signing key or external completion server is used.
