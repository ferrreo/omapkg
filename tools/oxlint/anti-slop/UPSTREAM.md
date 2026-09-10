# anti-slop provenance

Source: [dmmulroy/anti-slop](https://github.com/dmmulroy/anti-slop), commit `c44ef22ca116d0ba62a3ff663a0bd13a3f3fa40b`.

Installed from the upstream `install-anti-slop` skill bundle at that commit.
The vendored plugin lives at `tools/oxlint/anti-slop/` and is registered by
the repository root `.oxlintrc.json`.

The repository had no existing Oxlint installation. Exact compatible versions
`oxlint@1.82.0` and `@oxlint/plugins@1.82.0` were added as development
dependencies with Bun. The generic rules and the opt-in Effect rules are
enabled because this repository directly depends on `effect`.

Intentional local configuration: JSON configuration is used because the
available runtime does not provide a `node` executable for experimental
TypeScript config loading. Generated and staged agent-tooling directories are
ignored explicitly in `.oxlintrc.json`; existing source and project rules are
otherwise preserved. The generic runtime-typeof rule allows checks inside
declared type guards, an upstream-supported option that matches this
repository's boundary predicates.

The upstream MIT text is retained in `LICENSE`. The nested
`vendor/eslint-stylistic/LICENSE` and `UPSTREAM.md` files are retained with
the redistributed readability rule.
