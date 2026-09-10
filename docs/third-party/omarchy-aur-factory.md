# omarchy-aur-factory packaging guidance

Reviewed source: [adamhjk/omarchy-aur-factory](https://github.com/adamhjk/omarchy-aur-factory) at commit `657d9c7c95e10573952d44cdb8a3c7ea6992ac0a`.

The selected source is Apache-2.0. The repository has a root `LICENSE` file and no `NOTICE` file at this commit. The applicable licence text is retained at [`licenses/Apache-2.0-omarchy-aur-factory.txt`](../../licenses/Apache-2.0-omarchy-aur-factory.txt).

## Adapted material

| Upstream path | Local destination | Change | Dependency decision |
| --- | --- | --- | --- |
| `.claude/skills/arch-packaging/SKILL.md` | `services/pipeline/packaging-guidance.ts` | Extracted inspection, staged install, validation, and evidence rules into immutable, bounded Flue guidance. Replaced Swamp commands and Claude-specific workflow language with coordinator-owned policy. | No runtime dependency. |
| `.claude/skills/arch-packaging/references/pkgbuild.md` | `services/pipeline/packaging-guidance.ts` | Adapted field, path, checksum, dependency, and staging constraints. Existing local recipe validation remains authoritative. | No runtime dependency. |
| `.claude/skills/arch-packaging/references/c-cpp.md` | `services/pipeline/packaging-guidance.ts` | Adapted Autotools, Plain Make, CMake, and Meson inspection/build/check/install guidance. | No runtime dependency. |
| `.claude/skills/arch-packaging/references/{go,rust,python,nodejs}.md` | `services/pipeline/packaging-guidance.ts` | Adapted offline lock/vendor, toolchain, output, and runtime guidance for Go, Rust, Python, and separate npm/pnpm/Yarn families. | No runtime dependency. |
| `.claude/skills/arch-packaging/references/binary.md` | `services/pipeline/packaging-guidance.ts` | Adapted archive, Electron, AppImage, and extraction-only rules. Installer execution is explicitly excluded. | No runtime dependency. |
| `.claude/skills/arch-packaging/references/validation.md` | `services/pipeline/packaging-guidance.ts` | Adapted lint, metadata, dependency, path, permission, and runtime-check expectations. | No runtime dependency. |
| `.claude/skills/arch-packaging/references/vcs.md` | `services/pipeline/packaging-guidance.ts` | Adapted VCS as a pinned source mode shared by build families. | No runtime dependency. |

The local file carries a prominent modified-file notice and records this commit and source paths in its header. It is distributed under the retained Apache-2.0 terms; local changes remain subject to the repository's terms.

## Excluded material

No Swamp runtime, workflow, model, report, or invocation code was imported. The upstream Next.js application and its `package-lock.json` dependency tree were inspected but are not part of this adaptation, so their transitive package notices are not introduced into omapkg. The upstream `.agents` skills, setup scripts, screenshots, and unrelated application code are also excluded.

The upstream packaging references contain no additional per-file copyright or `NOTICE` text. If a future port copies code or prose from another upstream path, add its source path, commit, licence, and dependency terms to this record before committing the adaptation.

