# Supply-chain discussion implementation

This tracks the September 7 discussion against implementation and deployment.
Unchecked items are requirements still awaiting implementation or verification.
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
- [ ] Commit and push implementation; deploy web, pipeline, signer, worker and
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
validation and production rollout are tracked below when complete.
