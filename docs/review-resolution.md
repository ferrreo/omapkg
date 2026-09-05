# Thermos review resolution

Implemented on `fer/thermos-fixes`, based on `28e06e3`. The original
[HTML audit](../reports/thermos-review-2026-09-05.html) describes commit
`02d9de3`; its negative diagnostic probes are archived as text so normal test
discovery cannot mistake them for regression coverage.

## Correctness and security

| Finding | Resolution | Regression evidence |
| --- | --- | --- |
| B01: dev history blocks promotion/quarantine | Channel transitions preserve historical rows. Repository indexes derive from the resulting channel state, and transaction assertions count the rows actually changed. | Promotion with two dev versions; quarantine with a newer dev version; assertions on generated repository contents. |
| B02: rollback retry blocked by immutable manifest | Each attempt writes its own immutable manifest key. The successful transaction publishes that key through the existing public rollback URL. | Retry after signer failure and transaction failure, including the public repository route. |
| B03: recipe upgrade loses predecessor | Stable lifecycle queries include both surfaces. Promotion withdraws predecessors and records the previous release. Binary filtering happens at repository serialization. | Recipe upgrade and rollback; both directions of a binary/recipe surface change. |
| B04: wrong public-recipe rollback hash | Rollback hashes the immutable published PKGBUILD instead of the internal build recipe. | Different internal/public recipes verify against the downloaded public bytes. |
| B05: promotion eligibility races | The final transaction rechecks crashes, approvals, current revision, request state, and successful build/smoke evidence. | Crash arrival and approval revocation during signing both abort the whole transition. |
| B06: plaintext signing credentials | One URL validator protects control, KMS and external signer requests. Nonlocal endpoints require HTTPS; loopback HTTP remains available for development. Production configuration requires HTTPS. External signer redirects are rejected. | Nonlocal HTTP rejection before fetch; HTTPS/loopback behavior; redirect rejection; real config generation in a temporary directory with dummy values. |

The release scenarios live in [release-transitions.test.ts](../tests/release-transitions.test.ts).
Transport and deployment checks also live in [signer tests](../signer/src/index.test.ts)
and [deployment.test.ts](../tests/deployment.test.ts).

## Simplification and file size

- S01: separated release lifecycle, binary repository generation, attestation/signing,
  and immutable storage. Removed the mixed `RepoRelease` casts and duplicate IDs.
- S02: REST and MCP catalog search share a SQL query that selects the latest rows
  and applies pagination before loading recipe/evidence text. REST cursor shape is
  preserved; an intervening package update no longer restarts pagination.
- S03: catalog surfaces share source/list parsing and public release mapping.
- S04: publication dispatch and workflow share payload parsing and job-state updates.
- S05: deleted the unused pipeline barrel and unread dependency traversal set.
- Split worker protocol/results/lifecycle, native container runtime/package metadata,
  factory schemas/vendor resolution, vendor manifest validation, and application CSS
  along existing responsibilities. CSS declarations and order are unchanged; only
  blank lines at file boundaries differ.
- Reused release test fixtures instead of copying them into the new regression suite.

All application and test source files are at most **675 lines**, below the
750-line preference. Largest files are the signer (675), upstream release checker
(651), factory tools (616), public CSS (608), and Go protocol (603). Generated
bundles and dependency lockfiles are not hand-maintained source and are not split.
The two existing Archify documents, `docs/diagrams/services.html` (14,791 lines)
and `docs/diagrams/factory.html` (14,789 lines), remain standalone generated
artifacts so their offline viewing and export controls continue to work.

## Verification

- `bun test`: 208 passed across the application and signer, zero failures.
- `bun test tests`: 200 passed, zero failures.
- `bun run check`: zero errors and warnings.
- `bun run check:pipeline`: passed.
- `bun run build`: passed.
- `bun x vite build --config services/pipeline/vite.config.ts`: passed.
- Signer: 8 tests passed, typecheck passed, Wrangler build/dry-run passed.
- Worker: `go test -race ./...` passed; Linux ARM64 cross-compilation passed.
- KMS: `go test ./...` passed using the existing fake KMS boundary.
- Native OCI: `TestRunnerExecuteNativeOCI` and `TestRunnerDependencyPlanNativeOCI`
  passed with the existing local builder pinned to
  `sha256:1c7d6ca40441e83123c2f3e4e7bc2af26b11641ff5976f9129fc7d67b7f3bea6`.
  These exercise offline build/smoke isolation and installation of a signed dependency.
- Browser: docs and catalog pages render with the existing fonts/theme and no
  horizontal overflow. The catalog API executes successfully against local D1 after
  applying the existing migrations.
- Fresh correctness/security and maintainability reviews completed. The additional
  external signer transport finding was fixed and covered by regression tests.
- Whitespace checks and the source-file size inventory pass.

No production deployment, live KMS operation, GPU acceptance run, or native ARM
runtime test was performed. ARM was cross-compiled; native OCI checks ran on x86_64.
