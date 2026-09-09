# Supply-chain discussion implementation

This tracks the September 7 discussion against implementation and deployment.
Each checked item below is implemented and verified.
The target is best-effort security with explicit enforceable properties, not a
formal proof that arbitrary software is harmless.

- [x] Narrow the proposal's safety, recipe-generation, SBOM, and reproducibility claims.
- [x] Publish exact worker provenance, worker signature, authenticated key identity,
  and a centrally signed in-toto/SLSA statement; bind binary or public recipe,
  reviewed inputs, and evidence. Preserve and label historical records.
- [x] Supply independent verification with tamper, substitution, and trust tests;
  document signing meaning, rotation, revocation, and historical verification.
- [x] Add constrained, versioned recipe templates and explicit custom-shell mode;
  cover smoke commands and public recipes, re-render at validation, bind review.
- [x] Add deterministic shell checks and isolation regression tests; model review
  cannot override failures or establish safety.
- [x] Analyze package ELF dependencies with namcap, preserve signed results and
  bounded reviewed exceptions, and run smoke tests in a clean runtime environment.
- [x] Record prepared environment identity and exact installed package inventory.
- [x] Distinguish runtime declarations, build inventory, measured requirements,
  observed behavior, and unknown coverage in SBOM/evidence and public UI.
- [x] Add structured dependency blockers and maintainer-only request linking or
  creation; bound graph size/depth and cycles; re-resolve without bypassing review.
- [x] Pass targeted and full relevant checks, including real isolated worker tests.
- [x] Commit and push implementation; deploy web, pipeline, signer, worker and
  images as needed; verify production behavior and record evidence here.

No automatic upstream admission, new packaging DSL, or formal closure research
is included. Existing approved repository resolution remains automatic.

Implementation evidence: release statements and independent verifier live in
`src/lib/server/release-attestation.ts` and `signer/src/verify-release.ts`; runtime
analysis and clean preparation in `worker/analysis.go` and `worker/runner.go`;
review policy in `services/pipeline/recipe-policy.ts`; human admission and bounded
resolution in `src/lib/server/dependency-blockers.ts`.

Local validation: application, signer and Go tests; web, pipeline and signer type
checks; native x86 OCI regression that rejects malformed recipe/smoke/public
shell, refuses network and protected-path writes, rejects undeclared glibc, and
passes after declaring it in a clean runtime without make or tree. Native ARM
validation and production rollout are recorded below.

## Production rollout evidence

Core service code was deployed from `3f143ff` on September 9, 2026. Remote D1
migrations 0026–0028 completed successfully. Existing signing secrets were
retained. Deployment versions:

- Web: `2c8e391b-fbf6-47fc-9ead-f1ebea46c237`.
- Signer: `e45e14a7-6794-4c76-ae3c-9e51a67bb0c2`.
- Pipeline: `c6013eeb-8042-4776-9cd0-3ad520ed2c61`.

The active x86 worker runs `v0.1.0-dev.8b9dfcb`, advertises
`runtime-analysis-v1`, and uses the separately pinned Arch runtime digest
`sha256:522dd24e4a16f41afe71c7561febe519f7575404c291565e9f0be823d1794ca4`.
Both the default Omarchy and optional plain Arch builders passed native
regression checks. Docker and Podman were both exercised. Old x86 builder
records remain in history but are disabled for new selection.

| Published image | Digest |
| --- | --- |
| Pipeline sandbox | `sha256:9db78941e0daa6054191535366336c32dc8138fe5dfa3279ca8122ae267c4835` |
| Default Omarchy x86 builder | `sha256:563930fe24395649d829761e215377a9a1b99543da97cdee890f19efe50c935a` |
| Plain Arch x86 builder | `sha256:a696418348690df6db82f70e158f4ca24b90e867ee0bf7cd023f9c790b6f7b00` |

Production `/docs/security` and `/packages/omapkg-units?channel=dev` respond
successfully. The historical package displays missing runtime evidence and
missing public attestation labels; its attestation URL returns 404. Historical
records were not backfilled with invented execution evidence. New publication
uses the mandatory signed-evidence path, covered by publication/control-plane,
cryptographic signer, and independent-verifier tests.

Native ARM [run 34378972091](https://github.com/ferrreo/omapkg/actions/runs/34378972091)
passed all Go tests and the native OCI dependency/isolation regression (35.57
seconds). Its builder is registered as the ARM default and its separate runtime image is
published for worker configuration. The old ARM builder is disabled for new selection. ARM workers are ephemeral;
there is no continuously running ARM daemon to restart. The enrollment workflow
now requires the validated runtime image alongside its builder.

| Validated ARM image | Digest |
| --- | --- |
| Builder | `sha256:f640f189a7cb91a3a1f0f5e654ff7ecd3c854e092589178c26b5304c8d18d440` |
| Runtime | `sha256:d092c726874b17937ddaff0c089e6e63b01599b4bad69a4e079cbc303b163efc` |

The temporary Actions registry secret and local credential files were deleted
after validation. Final local checks: 211 application tests, 9 signer tests, Go
tests, web/pipeline/signer type checks, production build, and native x86
regressions using both plain Arch and the configured Omarchy default. A final Go
check also enforces verification of frozen package versions after all dependency
resolution. No new release was fabricated to backfill historical evidence.
