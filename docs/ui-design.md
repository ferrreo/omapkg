# omapkg UI design

Status: frontend contract for the first working release.

## Direction

omapkg borrows Omarchy's actual page grammar: a small masthead, one-line page title, monospace prose, dense link rows, and content that starts after a measured gap. Public pages help people browse and request packages. Maintainer pages help people inspect evidence and record review decisions. Each package page shows source, review, test, attestation, signature, and channel evidence.

The visual reference is the current [Omarchy site](https://omarchy.org/) and its [HTML source](https://github.com/omacom/omarchy-site/blob/master/index.html). The palette and type choices follow the site's [root tokens](https://github.com/omacom/omarchy-site/blob/master/assets/css/root.css), while the theme model follows [Omarchy theming](https://github.com/omacom/omarchy/blob/quattro/docs/theming.md): semantic roles first, a neutral ramp, and one accent used for active or actionable states.

The live root places a small announcement above a centered ASCII mark, one-line masthead, and three rows of blue icon buttons. The Manual adds a search field and long chapter navigation before article prose. Security uses a plain section heading followed by paragraphs and lists. News and Teams use the same masthead and dense content rhythm; they do not introduce dashboard cards or oversized hero copy.

## Tokens

Values below mirror Omarchy's current source CSS. Keep component CSS on semantic variables; do not add one-off colours.

| Role | Token | Value / use |
| --- | --- | --- |
| Canvas | `--color-canvas` | `rgb(26 27 38)` / `#1a1b26` · page background |
| Storm surface | `--color-surface` | `rgb(36 40 59)` / `#24283b` · selected work surface |
| Terminal rule | `--color-rule` | `rgb(65 72 104)` / `#414868` · borders and dividers |
| Terminal blue | `--color-accent` | `rgb(122 162 247)` / `#7aa2f7` · headings and buttons |
| Terminal cyan | `--color-link` | `rgb(125 207 255)` / `#7dcfff` · links and focus |
| Terminal white | `--color-text` | `rgb(192 202 245)` / `#c0caf5` · readable copy |
| Green | `--color-positive` | `rgb(158 206 106)` / `#9ece6a` · healthy state |
| Turquoise | `--color-accent-hover` | `rgb(180 249 248)` / `#b4f9f8` · hover signal |

Typography uses `JetBrains Mono` throughout, with weight 300 for body copy and headings. Omarchy's source scale is `clamp(0.625rem, 1.25vw, 1rem)`; omapkg raises its minimum to `0.875rem` so phone controls remain readable. Line-height is `1.4`. Page headings use `125%` of that size; no oversized marketing display. Buttons are uppercase, bold, `2.9em` tall, `0.4em` radius, and use Omarchy's layered shadow. Panels use flat tinted surfaces and hairline rules; pills are reserved for state tags.

Spacing follows Omarchy's `em` scale: `.5`, `1`, `1.5`, `2`, `3`, `4`, `5`, `6`. Responsive layout changes at `40rem`, `64rem`, and `90rem`. The root uses `overflow-x: clip`; dense rows become stacked records on narrow screens. Focus rings are immediate and high contrast. Motion uses `0.15s cubic-bezier(0.33, 1, 0.68, 1)` and respects reduced motion.

## Navigation and page shapes

Public navigation keeps Omarchy's compact centered button rail, with the OMAPKG wordmark, package search, Packages, Docs, Privacy, and GitHub sign-in or Workspace. `⌘K`/`Ctrl-K` opens a native dialog with grouped results. The public landing page begins with a short one-line masthead, then puts catalog rows and request controls ahead of explanatory copy. It never displays made-up package counts, uptime, or adoption numbers.

Maintainer navigation uses a compact top rail and work surface: Queue, Workers, Images, Releases, Audit, Team, and public catalog. The request queue remains addressable at `/maintain/requests` from Queue and direct links. The main pane starts with evidence. Tables, diffs, manifests, and timeline rows sit directly on flat work surfaces; avoid nested cards and fake browser chrome. A release-affecting control states the target, evidence, reason, and resulting action before submission.

## Route map

| Route | Audience | Shape | Required evidence / action |
| --- | --- | --- | --- |
| `/` | Public | Catalogue + workflow diagram | Browse, request, Surface A/B explanation, build path |
| `/packages` | Public | Filtered catalogue table | Search, surface, channel, architecture, source, status |
| `/packages/[name]` | Public | Package evidence sheet | Version history, source/ref/digest, license, checksums, signatures, SBOM, attestation, tests, install path |
| `/request` | Public | Short intake form | Name + Git or direct download URL, input type, category, declared license; no PKGBUILD upload |
| `/privacy` | Public | Consent policy | Crash report fields, opt-in boundary, redaction guidance, no automatic telemetry |
| `/maintain` | Maintainer | Queue workbench | Area queue, security review, build/release stage summaries, honest empty states |
| `/maintain/requests/[id]` | Maintainer/security | Review workbench | Generated diff, source/dependency manifest, agent trace, approve/deny/return actions, audit link |
| `/maintain/workers` | Maintainer/admin | Fleet table | Worker identity, daemon version/runtime/capabilities, architecture, heartbeat, lease state, pause/drain/resume, revoke, archive, enrollment token action |
| `/maintain/images` | Maintainer/admin | Image registry | Registered digest-pinned images, architecture defaults, availability, audit-backed admin actions |
| `/maintain/audit` | Maintainer/security/admin | Dense event log | Correlation ID, actor, target, event, reason, result, timestamp, redaction/export |
| `/maintain/releases` | Release maintainer | Batch promotion board | Dev gates, dependencies, smoke/crash evidence, promote, freeze, rollback, immutable history |
| `/maintain/team` | Admin | Membership table | Verified GitHub username, area access, grant/revoke, role change audit |
| `/maintain/builds/[id]` | Maintainer/security | Build workbench | Live bounded logs, recipe, artifact hashes, provenance, worker signature |

The server owns package data. When arrays are empty, render a sentence naming what is empty, why it matters, and one next action. Placeholder rows and fabricated live metrics are forbidden.

The intake accepts Git repositories and direct download URLs for source or binary packages. URL hints cover tar, zip, deb, rpm, AppImage, and `.run`; the inspector records the actual format and reports unsupported inputs before build review. Download metadata is inspected online; after review, supported inputs are extracted in the isolated offline worker.

Audit layout regression fixture uses `upstream.release_check.failed`, a UUID actor, and a full registry reference in event detail. At 1520px the row uses four bounded tracks; at 768px it uses date/action columns with actor, target, and detail below; at 320px and 375px it stacks each field. Every track and event child has `min-width: 0` and `overflow-wrap: anywhere` so full values remain readable without page overflow.

## Interaction contract

- Every button, link, input, select, dialog, and row action has default, hover, focus-visible, active, disabled, loading, error, and success treatment.
- Forms use visible labels, helper text, `aria-describedby`, touched-on-blur validation, and stable helper height. Errors state what broke, why, and what to do.
- Reversible maintainer actions use optimistic updates plus an Undo/error path. Irreversible actions require explicit confirmation and reason.
- Search is keyboard-first and URL-addressable. Filter changes preserve the query string so a review can be linked and revisited.
- Status never relies on colour alone: use text plus a small inline SVG icon or pattern.
- Public pages expose only public package evidence. Internal prompts, worker credentials, private source credentials, and unredacted logs stay server-side.

## Sources

- [Omarchy home](https://omarchy.org/)
- [Omarchy manual](https://omarchy.org/manual/)
- [Omarchy security page](https://omarchy.org/security/)
- [Omarchy news index](https://omarchy.org/news/)
- [Omarchy teams page](https://omarchy.org/teams/)
- [Official site `index.html`](https://github.com/omacom/omarchy-site/blob/master/index.html)
- [Official site root tokens](https://github.com/omacom/omarchy-site/blob/master/assets/css/root.css)
- [Official site element/button styles](https://github.com/omacom/omarchy-site/tree/master/assets/css)
- [Official site fonts](https://github.com/omacom/omarchy-site/tree/master/assets/fonts)
- [Omarchy theming docs](https://github.com/omacom/omarchy/blob/quattro/docs/theming.md)
