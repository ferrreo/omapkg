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
| 3. Native workers, owned inputs and ABI cohorts | Immutable cohort scope, phase/event history, generated changelogs, native matrix and maintainer workbench implemented; owned locks, multi-output workers, ABI closure and native cohort checks remain in progress | Phase/admission/native omission, idempotency, stale narrative and publication-fence checks pass. Full native cohort acceptance remains pending. |
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
including `/api/maintain/imports`. Public repository status is a separate
view of published releases, not import progress. Existing OPR capture also queries
recipe-only releases separately so pacman database coverage cannot hide Surface B.

Current comparison implementation keeps full package metadata in SQLite and
streams bounded difference pages through the Worker. A 15,432-record Omarchy
stable x86 baseline versus 15,433 Arch x86 records reports 3 missing, 4 extra and
422 version differences. New ARM reference/qualification work is shown separately
and does not block comparison merely because Omarchy lacks an ARM repository.

## Cohort and publication workbench evidence

- `/maintain/cohorts` creates an enumerated draft from catalog search. Scope
  changes pin exact policy/recipe digests, create new revisions and restart phase
  review. Cross-area edits require access to every member area. System and
  independent OPR lanes use different version fields and admission rules.
- `/maintain/cohorts/[id]` presents Overview, Changes, Phases, Tests and History.
  Phase and condition remain separate. Catalog/recipe authority, current inputs,
  unresolved blockers, both required targets and signed native build evidence
  are checked on the server, with database fences on transitions. The verification
  phase still blocks on the owned-input, ABI, reproduction and system-test work
  that has not yet been implemented or measured.
- Generated JSON and Markdown changelogs derive from immutable scope and a
  digest-linked event history. They identify their comparison baseline and
  planned/built/published state. Prose edits preserve build inputs, change the
  changelog digest and require human review. A phase or scope change makes older
  facts stale; repeating the same event or review does not duplicate history.
- Cohort recipe ownership prevents the legacy per-build publisher from shipping
  a partial cohort. After an eventual authorized switch to owned mode, database
  guards also disable legacy release/channel/snapshot writers. The mode remains
  `shadow`; this is not a cutover. The new distribution contract requires explicit
  release team membership separate from package and administrator authority;
  existing OPR publication retains its verified legacy policy during shadow work.
  No production membership was granted.
- Browser checks used labelled local test identities and drafts, exercised
  blocked cohort creation, generated narrative editing/review and downloads,
  and passed all five cohort sections at 320, 375, 414, 768, 1440 and 1920 pixels.
  Anonymous requests to private imports (including the real POST endpoint) and
  cohorts returned 401. These are application behavior checks, not human
  production approval or native package/release qualification.
- `/repository` now shows public legacy OPR publication counts and active database
  availability for each architecture/channel. It reads publication records only,
  distinguishes binary and recipe-only releases, and checks database/signature
  availability without claiming cryptographic or whole-system qualification.
  System distribution manifests will join this view when that engine is ready.
- Workspace navigation now groups Inbox, Catalog, Cohorts, Releases, Operations
  and Audit; import and worker/image/team deep links remain accessible within
  their sections.
- The complete application suite now passes 225 tests; Svelte and pipeline
  type checks report no errors. Native lease tests cover held and unreviewed
  cohort scope as well as both-target omission gates.

Additional fresh metadata captures passed the server parser and exact index
digest check: Omarchy RC 15,658 records; Omarchy edge 15,774 records, including
115 existing ARM package records; existing OPR 4 records, including one
recipe-only release. RC ARM repositories were absent; edge ARM core/extra were
absent, while its package repository existed. Existing ARM records remain real
reconciliation inputs. Absent external ARM repositories remain new-target
qualification, not a prerequisite for our own support. Comparisons now name
their repository scope and show captured baseline repositories outside it, so
an Arch core/extra comparison cannot imply that omitted Omarchy packages match.
The three fresh captures were also uploaded and sealed through the real local
maintainer API. Browser comparisons against stable, RC and edge passed. Within
core/extra/multilib, stable and RC each show 3 missing, 4 extra and 422 version
differences against the captured Arch input; edge shows 0 missing, 0 extra and
2 version differences. Omarchy package records outside that comparison remain
explicitly visible (228 stable x86; 226 RC x86; 226 edge x86 plus 115 edge ARM).
Both application and pipeline production bundles built successfully.

Full-plan completion remains unproven. Required remaining work includes full
recipe/source import and review, native owned inputs and multi-output execution,
full dependency/ABI planning, independently reproduced critical builds, signed
system/OPR/transaction manifests and activation, client/Omarchy integration,
native boot/upgrade/recovery qualification, full-catalog rebuild coverage,
operational capacity and human workflow/release/cutover acceptance.
