# Distribution plan execution

Baseline: `af76fec7397b8f8293175485d55271a765592670` on `fer/arch-repository-plan`.
Specification: [approved plan](arch-repository-ownership.md).

This ledger records implementation and acceptance separately. A checked-in
feature is not evidence of full catalog coverage, native hardware acceptance,
human release approval, or production cutover.

| Phase | Implementation | Acceptance |
| --- | --- | --- |
| 0. Preserve security baseline | Existing main implementation retained | 54 focused application tests, 9 signer tests and worker Go suite passed before implementation; rerun after relevant changes. |
| 1. Catalog and UI contracts | Immutable catalog policies, independent reviews, output identity registry, system/OPR classification and first maintainer views implemented | Ownership/concurrency tests pass. Broader consumer/release/admin journeys remain in progress. |
| 2. Import and OPR replacement admission | Arch/Omarchy/existing-OPR capture workflow, resumable uploads, reconciliation UI and shared dependency proposals implemented | Local browser reconciliation passed with real inventories; full recipe import/admission and production workflow acceptance still pending. |
| 3. Native workers, owned inputs and ABI cohorts | Pending | Pending |
| 4. Versioned system and independent OPR releases | Pending | Pending |
| 5. Consumer/client integration and recovery | Pending | Pending |
| 6. Full catalog rebuild and shadow operation | Pending | Pending |
| 7. Human-approved cutover | Pending | Pending |

Required invariants: system versions such as `4.0.3`; independent OPR releases;
human admission of AUR/ALARM replacements; both native architectures; complete
dependency/ABI cohorts; generated phase and cohort changelogs; reviewed release
evidence; consumer, maintainer and admin usability/accessibility acceptance.

Live import/rebuild coverage and operator decisions will be recorded here when
measured. Existing rollout records remain in `docs/discussion-resolution.md`.

## Import and admission evidence

- Application checks passed with no Svelte errors/warnings. The pipeline bundle
  built successfully with the new import workflow.
- 220 application tests passed, including immutable capture/index sealing,
  partial upload/retry, missing/extra/version/architecture comparisons, role
  checks, shared proposal admission and collision-safe catalog review.
- Worker Go checks passed after accepting case-sensitive virtual ALPM
  capabilities such as the real catalog's `KSMBD-MODULE`.
- Native capture tool parser self-check passed. Real metadata validated through
  the same server parser: Omarchy stable 15,660 records; Arch upstream 15,744
  records; existing OPR 3 records (1 x86, 2 ARM). These are captured repository
  records, not newly admitted or rebuilt packages.
- Local browser flow at `/maintain/imports` and `/maintain/imports/[id]` completed
  comparison using those first two captures. Within core/extra/multilib it
  initially reported 3 missing, 315 extra and 422 version differences. That
  first report included ARM reference entries as extras; the corrected comparison
  separates new ARM qualification from existing baseline matching. Omarchy's
  three ARM endpoints were unavailable, which is informational rather than a
  prerequisite for our own ARM support. The selected ALARM extra reference database had
  invalid NUL-filled `findnewest` metadata; it remains an explicit source gap.
- Browser containment passed at 320, 375, 414, 768, 1440 and 1920px. The preview
  uses labelled local test identities and real public capture data; it is not a
  production rollout or a human package-admission decision.

Import status separates metadata capture, ownership review, replacement work,
matching native build evidence and immutable baseline comparison. Neither a
successful upload nor an empty difference filter marks a migration complete.

Remaining import work includes qualified source/recipe mapping, operator review,
owned rebuilds for all required outputs, production capture workflow checks,
and coordinated release readiness. Full-plan completion is unproven.

User clarifications implemented: absent Omarchy ARM baselines become new-target
qualification notes, not import blockers; our own required ARM builds and system
tests remain gates. Import jobs, reconciliation and uploads are maintainer-only,
including `/api/maintain/imports`. Public repository status is a separate planned
view of published releases, not import progress. Existing OPR capture also queries
recipe-only releases separately so pacman database coverage cannot hide Surface B.

Current comparison implementation keeps full package metadata in SQLite and
streams bounded difference pages through the Worker. A 15,432-record Omarchy
stable x86 baseline versus 15,433 Arch x86 records reports 3 missing, 4 extra and
422 version differences. New ARM reference/qualification work is shown separately
and does not block comparison merely because Omarchy lacks an ARM repository.
