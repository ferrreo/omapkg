# Bounded production demonstration

The 2026-09-11 demonstration used two small GNU source packages on
[the deployed application](https://omapkg.ferreo.dev). It did not import or build
the full Arch catalog. The package builds passed; cohort publication remains
blocked by missing cohort-bound builds, owned inputs, and a qualified System baseline.

## Inspect the demonstration

- [Hello cohort](https://omapkg.ferreo.dev/maintain/cohorts/demo-hello-20260911): revision 3 binds GNU Hello 2.12.3-5. Planning and recipe review passed. Build verification requires native evidence bound to this exact cohort revision.
- [Hello request](https://omapkg.ferreo.dev/maintain/requests/c7acfbcb-d476-4fd8-9f74-118f3ccc5c7d): successful native x86 and ARM builds, runtime checks, and area/security reviews.
- [Which request](https://omapkg.ferreo.dev/maintain/requests/caba9dc6-ce00-470d-a6f7-9294a84c05cd): successful native x86 build and runtime checks after retained failed attempts and human intervention.
- [Import capture](https://omapkg.ferreo.dev/maintain/imports/b18cbe0ef44f15fbe5990c5aaca94e10a6f6c5655f6f9056a0b7d6ec5b51544c): three observed records. Both Hello records link to independently admitted catalog policy; dmenu is excluded from this demo. One recipe source was unavailable. Metadata capture does not establish trust in imported binaries.
- [Hello dossier](https://omapkg.ferreo.dev/maintain/dossiers/dossier-43b076e7a9b9fb236c18ac23a583e0ba91e0856659674382), [Which dossier](https://omapkg.ferreo.dev/maintain/dossiers/dossier-6eab7f6793cf1560b6eb96833dbf1da1f8434b15735710f7), and [cohort dossier](https://omapkg.ferreo.dev/maintain/dossiers/aggregate/aggregate-43b6d98308f0e229fd93b5752996d1f04da63625ec5573a0) retain the actual results and failures. These maintainer views require authentication.

## Native package evidence

| Package | Target | Result | Artifact SHA-256 |
| --- | --- | --- | --- |
| GNU Hello 2.12.3-5 | x86_64 | Build and installed-command check passed | `9e87bc98797c21b71844e0fda6515223b8f86b350cb3158ddc39f8f0d2adf2d7` |
| GNU Hello 2.12.3-5 | aarch64 | Build and installed-command check passed | `f3d197843e2efc24173786d5991df5cc14e1e2532991f1c9483b9d0f1c040939` |
| GNU Which 2.25-6 | x86_64 | Build and installed-command check passed | `7adda89a8b8299e655f7a3762cfaedd5a5fb6ec0312f1506f6c6e1d945aeedf5` |

[ARM worker acceptance](https://github.com/ferrreo/omapkg/actions/runs/34549239312)
passed on a native hosted ARM runner. Its temporary enrollment secret was deleted.
Both review kinds were submitted by the same authorized account, as requested;
security permission remains required. Recipe approval reused the successful
factory artifacts. These single executions do not establish independent package
reproducibility or owned-input qualification.

The retained JSON exports returned HTTP 200 and matched their canonical digests:
Hello `a2975086681a488ef851c57c54cb145506b09ea8f34dc36703a610a4f7291fcd`;
Which `401b53798a06a2d9b2510e17b65282f0c82991f5cb05229dbdcc523ee034c81b`.

## Publication prerequisites

Production has no owned input locks, no registered owned dependency packages,
and no signed or active System release. The successful Hello builds predate cohort binding and cannot serve as
cohort-bound evidence. Publication requires new builds from reviewed owned
inputs, install/upgrade/recovery evidence, and exact supported System snapshots. No release candidate or transaction was fabricated to bypass
these prerequisites. Distribution mode remains `shadow`; the current transaction
manifest returns 404.

## Corrections exposed by the demonstration

The deployed worker now makes its ShellCheck input readable under a service
umask of 0077. Restarted factory runs create fresh immutable candidates instead
of colliding with previous build identities; stranded startup reservations can
recover, and a maintainer can stop a run. Current builder images replaced retired
images that lacked ShellCheck. The native startup test now selects its host
architecture instead of assuming x86. Regeneration now retires stale
dependency findings regardless of the previous request status; a migration
preserves superseded findings as history while keeping current findings open.

Native boot-image comparison also exposed filesystem installation history.
Fresh ext4 construction removed journal and write-counter differences. The next
comparison isolated all remaining x86 differences to `/var/cache/ldconfig/aux-cache`
and `/var/log/pacman.log`; the final-image builder now excludes both disposable
files. A local check varies those files, staging order, and time and verifies
identical fresh filesystem bytes. Native worker checks then exposed an incorrect
fixture path and repository alias symlinks in the exported context. The corrected
fixture includes regular files only; the worker still rejects unsafe archive entries.

[Final native acceptance](https://github.com/ferrreo/omapkg/actions/runs/34551134781)
passed on both x86 and ARM. Each target independently reproduced its 8 GiB
filesystem image, then executed the real worker construction, evidence-signing,
and streamed-upload path. The x86 OCI pair passed too. Retained boot-image hashes:

| Target | Identical primary and secondary SHA-256 |
| --- | --- |
| x86_64 | `008a42d73aea980d5e4ab2f636bc31c4b59102fcaf452a17eee1538262e5502a` |
| aarch64 | `c3758eccaa2b3183f263567907a1525cbcac551c03c2a7b27a23605b4071e28d` |

These fixture checks prove image construction and worker execution. They do not
supply production cohort install, upgrade, recovery, or boot qualification.
