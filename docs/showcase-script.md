# omapkg showcase video

Production record for the final showcase cut. It uses 20 real page captures,
the final 288-word narration, and a natural Chris voice. The file is
1920×1080 H.264 at 30 fps. Its video stream is 130.233 seconds, and the
narration track is 130.248 seconds at -16.2 LUFS and -1.7 dBTP. The manifest
uses 0.35-second crossfades.

The video, screenshots, and audio are production assets kept outside this
repository. A reusable producer can use the following layout:

- Captures: `showcase/captures/`
- Manifest: `showcase/manifest.json`
- Narration text: `showcase/narration.txt`
- Narration audio: `showcase/narration-final.mp3`
- Final video: `showcase/omapkg-showcase.mp4`

The final render includes framing updates on `07-factory-review` and
`11-workers`; the other 18 captures were accepted as recorded. Independent QA
passed. Keep deployment credentials, private source URLs, and unredacted agent
input out of captures and narration.

## Shot list

Times below use the manifest timeline. Adjacent shots overlap by 0.35 seconds
for each crossfade; the final row ends at 130.248 seconds. `P1` through `P11`
refer to paragraphs in `showcase/narration.txt` and the matching entries in
the narration alignment file.

| Time | Capture | Source | On-screen treatment | Voiceover | Record |
| --- | --- | --- | --- | --- | --- |
| 00.000 to 05.731 | `01-home` | `captures/01-home.png` | **Inspect before install**<br>public catalog · source → signature → install | P1 | Public home and verified release |
| 05.381 to 10.250 | `02-packages` | `captures/02-packages.png` | **Browse stable releases**<br>search by channel, surface, architecture, and source | P2 | Live catalog and release detail |
| 09.900 to 14.850 | `03-release-evidence` | `captures/03-release-evidence.png` | **Read the release record**<br>source · license · checksums · signature · SBOM · provenance | P2 | Signed package and clean Arch install evidence |
| 14.500 to 19.098 | `03-feedback-privacy` | `captures/03-feedback-privacy.png` | **Feedback stays opt-in**<br>optional feedback · explicit crash reports · privacy guidance | P2 | Opt-in feedback and crash controls |
| 18.748 to 24.150 | `04-request-git` | `captures/04-request-git.png` | **Describe what you need**<br>name, short description, declared license, and upstream link | P3 | Live request form with required metadata |
| 23.800 to 29.350 | `05-request-types` | `captures/05-request-types.png` | **Git or a direct download**<br>tar · zip · deb · RPM · AppImage · `.run` | P3 | Supported source types displayed |
| 29.000 to 32.350 | `06-request-submitted` | `captures/06-request-submitted.png` | **Ready for review**<br>the request gets a durable correlation ID | P3 | Submitted request with correlation ID |
| 32.000 to 35.352 | `06b-queue-states` | `captures/06b-queue-states.png` | **See the live queue**<br>pending · review · failed · built | P3 | Queue states shown on the live route |
| 35.002 to 50.344 | `07-factory-review` | `captures/07-factory-review.png` | **Generate a reviewable recipe**<br>source facts, generated PKGBUILD, revision digest, and SBOM | P4 | Accepted Git, source-tar, and `.run` factory runs |
| 49.994 to 61.701 | `08-human-gates` | `captures/08-human-gates.png` | **Two human gates**<br>approve intake, then approve the exact revision and manifest | P5 | Intake, area, and security approvals on the exact revision |
| 61.351 to 74.089 | `09-build-workbench` | `captures/09-build-workbench.png` | **Offline worker evidence**<br>short lease · digest-pinned image · smoke result · provenance | P6 | x86_64 and native ARM offline builds and smoke checks |
| 73.739 to 85.860 | `10-sign-release` | `captures/10-sign-release.png` | **Sign, quarantine, promote**<br>independent signing, dev publication, then stable promotion | P7 | Package and repository signatures with dev and stable promotion |
| 85.510 to 91.350 | `11-workers` | `captures/11-workers.png` | **Workers and leases**<br>identity, architecture, capabilities, and heartbeat | P8 | Registered workers and heartbeats |
| 91.000 to 97.854 | `12-images` | `captures/12-images.png` | **Pinned build environments**<br>digest-pinned images with scoped job credentials | P8 | Digest-pinned build images |
| 97.504 to 102.850 | `13-team` | `captures/13-team.png` | **Verified team access**<br>GitHub identities with area and server-side roles | P9 | Verified identities and roles |
| 102.500 to 108.650 | `13-audit` | `captures/13-audit.png` | **Trace each decision**<br>actors, targets, reasons, and results in one correlation trail | P9 | Correlated audit records |
| 108.300 to 114.168 | `13-docs` | `captures/13-docs.png` | **Evidence stays readable**<br>documentation and read-only queries expose the record | P9 | Documentation and read-only query view |
| 113.818 to 120.350 | `14-rollback` | `captures/14-rollback.png` | **Keep history addressable**<br>restore signed repository metadata and publish downgrade instructions | P10 | Verified 2.12.1 to 2.12-6 rollback |
| 120.000 to 126.980 | `14-rollback-proof` | `captures/14-rollback-proof.png` | **Verified client output**<br>verbatim rollback-proof.log excerpt | P10 | Clean-client rollback proof |
| 126.630 to 130.248 | `15-close` | `captures/15-close-release.png` | **Evidence before install**<br>source, checks, and decisions stay with the package | P11 | Final public release page |

## Voiceover

The following text is the source for the rendered narration track:

> omapkg builds Arch packages from upstream links, with each step available for review.
>
> The catalog shows releases with source, license, architecture, checksums, signatures, and build evidence. The package page separates optional feedback from explicit crash reporting and shows privacy guidance first.
>
> To add software, submit a name, description, declared license, and upstream link. That can be a Git repository, a source tar, or a vendor installer such as `.run`. omapkg records the input before any build starts.
>
> Inside the factory, agent tools inspect files as data. They produce a recipe, source manifest, dependency plan, description, and SBOM. Maintainers inspect the revision and its evidence.
>
> Intake is the first human gate. Area and security reviewers then approve the exact generated revision and manifest. The factory cannot approve its own output or move it to release.
>
> A worker claims a short-lived lease and uses the approved image for its architecture. It prepares verified inputs, builds with network disabled, runs smoke checks, and sends back the artifact and provenance.
>
> An independent signer checks the attestation and artifact before publication. Packages enter dev first, then a maintainer promotes a compatible batch to stable after quarantine and tests.
>
> Maintainers can inspect worker health, leases, capabilities, and digest-pinned images for each architecture. The same evidence rules apply to x86_64 and native ARM test workers.
>
> Team access uses verified GitHub identities and server-side roles. Audit records connect requests, reviews, builds, signatures, releases, and rollback decisions. Documentation and read-only queries expose evidence without write access.
>
> If a stable release needs to be withdrawn, its history stays addressable. A maintainer records the reason, restores the signed repository and publishes downgrade instructions, and the user chooses whether to downgrade.
>
> The source, checks, and decisions stay with the package.

## Production checks

- The manifest is marked final and every one of its 20 shots resolves to a real capture. No evidence-pending cards are used.
- Verified package records cover Hello and Git dmenu on x86_64 and native ARM, plus the NVIDIA-style `.run` Surface B recipe. Binary routes stay out of the public capture.
- Crash reporting appears as an opt-in control. The completed quarantine proof is described in [acceptance progress](acceptance.md).
