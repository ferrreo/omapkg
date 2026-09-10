# Complete cohort scope and verification

Cohorts can contain 1–100,000 package bases. A coupled transition remains one
revision and one phase decision, including both native architectures. The
existing inline format remains readable; complete uploads use a versioned root
manifest with an ordered, hashed chunk index.

## Propose scope

Create a draft in **Maintain → Cohorts**, then use **Replace complete scope**.
Download its current proposal or prepare JSON with every affected package:

```json
{
  "title": "Library transition",
  "lane": "system",
  "systemVersion": "4.0.3-rc2",
  "parentSnapshot": null,
  "compatibleSystems": [],
  "members": [
    {
      "pkgbase": "example",
      "catalogRevision": 1,
      "recipeRevisionId": null,
      "cause": "abi",
      "reason": "Rebuild consumers against the changed library."
    }
  ]
}
```

`catalogRevision` must select the current ownership policy. A non-null
`recipeRevisionId` must select the current recipe for that exact package, source,
area and target policy. Null permits initial planning; recipe review and native
build phases still require a binding. Independent OPR uses `lane: "opr"`, a null
system version and exact compatible system snapshot digests.

The browser accepts files up to 32 MiB and sends ordered chunks of at most 100
members. An upload may contain at most 4,096 chunks; each resolved chunk and its
root index must fit one MiB. Oversized chunks can be split. Retry the same file
to resume an interrupted upload. Changed chunk bytes require a new proposal.

Only the final transaction selects the complete revision. It rechecks every
catalog and recipe identity, current ownership authority and exclusive cohort
recipe ownership. Missing members, stale bindings, concurrent edits and attempts
to capture already published legacy builds abort selection atomically. A new
revision restarts phase review. Scope selection grants no admission, build or
publication approval.

The authenticated, same-origin `/api/maintain/cohorts` endpoint exposes:

| Method / operation | Input | Result |
| --- | --- | --- |
| POST `begin` | `cohortId`, `expectedRevision`, `metadata`, `memberCount`, `proposalId` | Resumable upload ID and counters. |
| POST `append` | `uploadId`, zero-based `index`, `members` | Validated immutable chunk; identical retries do not duplicate members. |
| POST `seal` | `uploadId`, `reason` | Atomically selected revision and manifest digest. |
| GET | `cohortId`, optional `manifestSha256`, zero-based `page` | Current scope and 25 members. |
| GET `changes` | `cohortId`, optional `manifestSha256`, package-name `after` | Ordered package changes and continuation cursor. |

An upload belongs to its creating human account. Maintainers need access to all
old and new member areas when selecting scope. No operation fetches upstream
packages or admits imported recipes.

## Check and advance

The review UI displays 25 members at a time. **Verify remaining member pages**
resumes checks without advancing the phase. Plan and recipe-review checks cover
25 members per request. Native phases check one package base, including all its
required targets and split outputs, per request. This bounds artifact work and
database calls independently from the displayed page size.

Every stored result binds the exact cohort revision, phase, verification state,
native matrix and blockers. The server performs native evidence and object
checks before recording a passing result. Page views show status and retained
results without rerunning artifact verification. Required failures and missing
checks remain in the complete coverage count.

Build, recipe, dependency and candidate changes invalidate their cohort's
checks. Unrelated cohort builds preserve existing checks. Reviewer revocations
and changes to historical input authority invalidate verification conservatively
across cohorts. Records remain immutable; later attempts append new results.
Results authenticate what was checked at their recorded time. Storage retention
and final publication remain separate responsibilities.

Advancement is one transaction. It requires a passing, complete page set and
rechecks the cohort's evidence versions, latest report selection and actor's
current area authority. A concurrent review revocation, build update or new
report cannot reuse an earlier prepared transition. Large transitions are never
split into independently advancing subcohorts.

API clients read GET `progress`, then POST `check` with `cohortId`, `revision`,
`manifestSha256`, `phase` and the zero-based verification `page`. Progress includes
the phase's `pageSize`, total/check counts, first missing/failed check and up to
100 failed-check links. Phase advancement uses the normal reviewed phase action.

## Changelogs and evidence

Version 2 changelog facts bind current and previous scope digests and the
`cohort-member-diff-v1` algorithm. That algorithm merges all package names in
binary lexical order, compares complete immutable members, and retains added,
removed, changed and unchanged members. A page is a view of this complete diff.
The reviewed facts do not encode a displayed subset as the complete change set.

`changelog.json` contains the reviewed narrative and exact source bindings.
`changes.json` and `CHANGELOG.md` stream the complete derived changes, including
after a newer cohort revision is selected. Chunk hashes and complete counts are
checked during export. Downloads and scope proposals remain private.

Phase events bind a page selection and its `reportsSha256`. GET `proofs` takes a
`cohortId`, event `sequence` and optional integer `after` cursor, returning up to
512 historical page references. To reproduce `reportsSha256`, hash UTF-8
`cohort-page-proofs-v1\n` followed by canonical JSON `{ "digest": ..., "page": ... }`
and a newline for each reference, ordered by page. GET `report` takes `cohortId`
and `digest` to retrieve exact report JSON; its SHA-256 must match that reference.
Later retries do not change an event's original selection.

Run `bun test tests/cohorts.test.ts`. The regression covers a 12,000-member
transition, partial uploads, complete streamed changes, stale selection races,
independent cohort activity, native page sizing, historical proofs and private
API/export boundaries. Dependency closure, artifact ABI, reproducibility and
system-test producers remain distinct release requirements.
