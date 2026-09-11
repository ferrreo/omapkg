# Bounded production demonstration

The 2026-09-11 demonstration used two small GNU source packages on
[the deployed application](https://omapkg.ferreo.dev). It did not import or build
the full Arch catalog. The package builds passed; cohort publication remains
blocked by missing owned dependencies and a qualified System baseline.

## Inspect the demonstration

- [Hello cohort](https://omapkg.ferreo.dev/maintain/cohorts/demo-hello-20260911): revision 3 binds GNU Hello 2.12.3-5. Its phase check records `1 unresolved dependency findings need owned providers.`
- [Hello request](https://omapkg.ferreo.dev/maintain/requests/c7acfbcb-d476-4fd8-9f74-118f3ccc5c7d): successful native x86 and ARM builds, runtime checks, and area/security reviews.
- [Which request](https://omapkg.ferreo.dev/maintain/requests/caba9dc6-ce00-470d-a6f7-9294a84c05cd): successful native x86 build and runtime checks after retained failed attempts and human intervention.
- [Import capture](https://omapkg.ferreo.dev/maintain/imports/b18cbe0ef44f15fbe5990c5aaca94e10a6f6c5655f6f9056a0b7d6ec5b51544c): three observed records. Both Hello records link to independently admitted catalog policy; dmenu is excluded from this demo. One recipe source was unavailable. Metadata capture does not establish trust in imported binaries.
- [Hello dossier](https://omapkg.ferreo.dev/maintain/dossiers/dossier-b590b83b1c8ec7bf4b0e05c11c317502c83c97ecd5029348), [Which dossier](https://omapkg.ferreo.dev/maintain/dossiers/dossier-6eab7f6793cf1560b6eb96833dbf1da1f8434b15735710f7), and [cohort dossier](https://omapkg.ferreo.dev/maintain/dossiers/aggregate/aggregate-2c2718eb3b1691d4e086c8b8b649ef28ba3b9a10112a9071) retain the actual results and failures. These maintainer views require authentication.

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
Hello `065b1370cbb25501fbd79e7013a06fa3541ffb06bbc362617db9bd27b754189b`;
Which `401b53798a06a2d9b2510e17b65282f0c82991f5cb05229dbdcc523ee034c81b`.

## Publication prerequisites

Production has no owned input locks, no registered owned dependency packages,
and no signed or active System release. The Hello dependency finding requires
an owned provider. Later cohort gates also require cohort-bound builds from
reviewed owned inputs, install/upgrade/recovery evidence, and exact supported
System snapshots. No release candidate or transaction was fabricated to bypass
these prerequisites. Distribution mode remains `shadow`; the current transaction
manifest returns 404.

## Corrections exposed by the demonstration

The deployed worker now makes its ShellCheck input readable under a service
umask of 0077. Restarted factory runs create fresh immutable candidates instead
of colliding with previous build identities; stranded startup reservations can
recover, and a maintainer can stop a run. Current builder images replaced retired
images that lacked ShellCheck. The native startup test now selects its host
architecture instead of assuming x86.

Native boot-image comparison also exposed filesystem installation history.
Fresh ext4 construction removed journal and write-counter differences. The next
comparison isolated all remaining x86 differences to `/var/cache/ldconfig/aux-cache`
and `/var/log/pacman.log`; the final-image builder now excludes both disposable
files. A local check varies those files, staging order, and time and verifies
identical fresh filesystem bytes. Full native acceptance is tracked by
[run 34549426188](https://github.com/ferrreo/omapkg/actions/runs/34549426188).
