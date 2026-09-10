# Rebuild scope proposals

`scripts/plan-rebuilds.ts` computes a dependency-based proposal from two already
captured inventories. It reads local files and writes a new report; it performs
no downloads, imports, admission, builds or publication.

```sh
bun scripts/plan-rebuilds.ts \
  --baseline /path/to/baseline \
  --candidate /path/to/candidate \
  --seed changed-package-base \
  --repository-order core,extra,multilib,omarchy,omapkg \
  --output /path/to/new-proposal.json
```

Both native architectures are selected by default. An explicit `--architecture`
selects a diagnostic target. Missing seeds and unavailable captured sources stay
in the report. Each input's package counts, record digests and complete index
must match its sealed manifest. The command refuses to overwrite an existing
report.

The candidate must represent the intended complete package universe. Comparing
an Omarchy system inventory with an Arch-only inventory will show omitted Omarchy
packages as removals; it does not propose their removal automatically. Repository
priority must be explicit when inventories contain overlapping names. The report
retains every shadowed name and the selected repository. Two conflicting sources
with the same repository/target require resolution before planning.

The planner follows runtime, build and check dependencies through both old and
candidate providers, including versioned virtual providers and SONAME relations.
Every split output belongs to its package base. A removed provider still pulls
old consumers into scope. Multiple possible providers are retained as findings;
the planner does not silently select one. Missing candidate providers remain
visible across the entire candidate universe.

Optional `--rules FILE` accepts existing catalog `rebuildOn` relationships:

```json
[{"pkgbase":"statically-linked-app","rebuildOn":["static-library"]}]
```

Rules add consumers and order them after changed providers. The result groups
strongly connected components and orders groups with dependencies first. Cycles
require a reviewed bootstrap, followed by rebuilding against the final component.
No intermediate package becomes publishable through this report.

The graph permits full-catalog proposals within 100,000 records per inventory
and a two-million-relation/edge budget. Budget violations reject the operation;
they never trim the member list. Native build admission remains a separate
operation. [Complete cohort scope uploads](cohort-scopes.md) retain the full
affected set within one revision; they require exact current ownership and
recipe bindings rather than treating inventory records as admitted recipes.

This is declared-dependency analysis. Artifact-level ABI/symbol changes,
undeclared static/bundled dependencies, native `vercmp`/pacman validation,
admitted owned providers and system tests are additional required evidence.
The proposal grants no release readiness or authority.

Run the graph regression with `bun test tests/rebuild-plan.test.ts`; it includes
a 15,000-package dependency chain, split outputs, old-provider removal, virtual
provider ambiguity, native target separation and a cyclic build component.
