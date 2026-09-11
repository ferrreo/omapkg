# Factory acceptance record

Validation date: 2026-09-11. Factory changes remain under verification; this
record does not mark the combined plan complete or authorize package publication.

| Check | Observed result |
| --- | --- |
| Combined application and signer suite | 360 passed, two opt-in native fixtures skipped, zero failures; 15,023 assertions. The retained OCI bridge also passed separately with its native fixture enabled. |
| Svelte and pipeline types | Zero errors; Svelte also reports zero warnings. |
| Production web bundle | Built successfully. |
| Go worker suite, race checks, and vet | Passed. Environment-dependent native cases require their explicit image settings. |
| Read-only live-worker diagnostic | Every required check passed using the deployed worker's config, including Podman isolation, config validation, capacity, and coordinator HEAD request (HTTP 200). No job was submitted. |
| Native x86 template matrix | All 18 fixtures independently reproduced using distinct builder and clean runtime images. See [template evidence](template-matrix-acceptance.md). |
| Native ARM template matrix | All 18 retained JSON records report independent reproduction on AArch64, with no skipped subtests. [Native ARM job](https://github.com/ferrreo/omapkg/actions/runs/34521724281/job/103020607186). |
| Filesystem images | Both x86 and ARM boot images independently reproduced in [run 34551134781](https://github.com/ferrreo/omapkg/actions/runs/34551134781). Native worker construction, signature verification, and streamed upload passed on both targets. These fixture checks do not establish production cohort boot or upgrade qualification. |
| Release preparation UI | Named change-set selection and review replace manual repository IDs and candidate JSON. Server derives repository references and release notes, rejects stale selections, and retains qualification gates. Browser checks covered selection/review and 320/375/414/768-pixel layouts without horizontal page overflow. |
| Local deep coordinator exercise | An injected first-attempt failure led to an actual isolated worker build on attempt two, authenticated artifact ingestion, and a retained coordinator dossier. A separate exhaustion case stopped after three attempts. |
| Repaired preserved-recipe successor | Actual isolated override inspection supplied the observed metadata hash to the frozen build, runtime install, and smoke check. Coordinator regression verifies signed override completion and exclusion of older workers. |
| OCI image worker adapter | Rootless build, archive payload/digest checks, worker signature verification, and production coordinator completion passed. Two normalized exports produced identical bytes. |
| Signer suite | All 16 tests passed after binding legacy-format fixtures to the required single-build reproducibility contract. The wrong-artifact case still reaches digest-mismatch rejection. |

The local deep exercise used builder
`localhost/opr-template-matrix@sha256:a918bd8252555d3a813b19b2e4038cb2ed082c9b0ee50b38d9e0479883691edf`
and clean runtime
`localhost/opr-template-matrix-runtime@sha256:ae22cd0d6dc6ce18d4e373b407d6566270f9c68f3a6eeb03958aa66ab340d940`.
The actual package SHA-256 was
`5e692436f7b38cd7002045f7b9100c928ab3d52e5903492febd3d81856d68c35`.
Its retained dossier was
`dossier-0410a79015a044b9bb9094a3558110cd4e70a299a85a1381`, with canonical SHA-256
`e4c9b76c79d5a8fb669b0b5c98f7c167d7760a1b94f020bd9ff47b9aa732b397`.
Local evidence is retained under `.local/factory-evidence/`; disposable keys
and package bytes are excluded from Git.

The OCI worker exercise used tool image
`localhost/opr-image-tools:factory-test@sha256:0227f2bef35e21743f6a37f71aec57f823711ac6bc9675070faa3c827a8acfa3`.
Two normalized archives were each 10,240 bytes with SHA-256
`859163678b4dafc0bf50790bcd4a7152e93390c03c02d247d828d35df6e9a8a2`.
Their OCI manifest digest was
`1646265154cac0e07fa1a93d9b0f7d79eca8462b623a6670005f2a6a87eb47d5`.
The test checks the actual layer payload and verifies the worker's Ed25519
signature. A retained Go completion also passed the production TypeScript
completion handler against the isolated database and artifact store.

The refreshed local browser fixture applied every current migration. Package
dossier, retained-attempt links, and human-intervention controls rendered.
JSON and Markdown matched stored exports, ETag matched the canonical digest,
unauthenticated private export returned 401, and public exports redacted
private material. Intervention dispatch is covered by domain tests; this
browser fixture checked form rendering without submitting another workflow.

The full diagnostic CLI still reports its outstanding native checks instead
of converting missing prerequisites to passes. Its deliberately closed local
coordinator probe returns a connectivity failure; the separate read-only
diagnostic against the deployed worker's real origin passed. Native fixtures
used no production credentials, imports, catalog captures, or package
publication.
