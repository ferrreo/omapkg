# Template matrix native acceptance

`worker/template_matrix_test.go` runs each typed family through `Runner.Execute`
and the real two-build `RunReproducibilityPair` harness. It uses only local
fixture bytes, fresh build roots, a five-second wall-clock gap, and a
digest-pinned builder plus separate runtime image.

Before each build, test runner invokes `scripts/template-fixture-render.ts`
with Bun and verifies returned source and recipe SHA-256 values. Bun belongs to
the pinned CI/test environment; it is never installed in build containers.

Build private x86_64 matrix capacity when cached image does not already contain
all tools:

```sh
podman build --pull=never \
  --tag localhost/opr-template-matrix:local \
  --file worker/Dockerfile.template-matrix worker
```

Build AArch64 capacity on native ARM or approved AArch64 binfmt using the
separately pinned base and package recipe:

```sh
podman build --pull=never \
  --tag localhost/opr-template-matrix-aarch64:local \
  --file worker/Dockerfile.template-matrix-aarch64 worker
```

The fixture assets are generated from the tracked source definitions at test
time: deterministic source archives, `.deb`, RPM via `rpmbuild`, Type 2
AppImage via `mksquashfs`, and a known extraction-only `.run`. No source mirror
or production artifact is used.

Run x86_64 acceptance with an approved private fixture image:

```sh
cd worker
OPR_WORKER_TEMPLATE_MATRIX_IMAGE='registry.example/omapkg/template-builder@sha256:<64 lowercase hex>' \
OPR_WORKER_TEMPLATE_MATRIX_RUNTIME_IMAGE='registry.example/omapkg/template-runtime@sha256:<64 lowercase hex>' \
OPR_WORKER_TEMPLATE_MATRIX_ARCH=x86_64 \
OPR_WORKER_TEMPLATE_MATRIX_EVIDENCE=/private/acceptance/template-matrix-x86 \
go test -run TestTemplateFamilyReproducibilityNativeOCI -v
```

Run the same matrix on native AArch64 capacity with the matching image digest:

```sh
cd worker
OPR_WORKER_TEMPLATE_MATRIX_IMAGE='registry.example/omapkg/template-builder-arm64@sha256:<64 lowercase hex>' \
OPR_WORKER_TEMPLATE_MATRIX_RUNTIME_IMAGE='registry.example/omapkg/template-runtime-arm64@sha256:<64 lowercase hex>' \
OPR_WORKER_TEMPLATE_MATRIX_ARCH=aarch64 \
OPR_WORKER_TEMPLATE_MATRIX_EVIDENCE=/private/acceptance/template-matrix-arm64 \
go test -run TestTemplateFamilyReproducibilityNativeOCI -v
```

Unset image variables leave every family explicitly `SKIP`/incomplete. Missing
family tools or an unavailable architecture also remain incomplete; they never
count as a renderer-only pass. The fixture test still checks that all required
families, source bytes, and staged recipes exist.

Set `OPR_WORKER_TEMPLATE_MATRIX_EVIDENCE` to retain one JSON evidence file per
family. Each file records builder/runtime refs, source and rendered recipe
digests, both attempt timestamps, output hashes, and comparator status.

The test does not pull images, install host dependencies, fetch sources, publish
artifacts, or use production signing keys. AppImage fixture generation requires
`mksquashfs` on the test host; without it that family is reported incomplete.

Latest local x86 acceptance used builder and runtime refs
`localhost/opr-template-matrix@sha256:a918bd8252555d3a813b19b2e4038cb2ed082c9b0ee50b38d9e0479883691edf`
and the distinct runtime alias
`localhost/opr-template-matrix-runtime@sha256:ae22cd0d6dc6ce18d4e373b407d6566270f9c68f3a6eeb03958aa66ab340d940`.
Evidence for all 18 independently reproduced fixtures is retained under
`.local/factory-acceptance/templates/x86/`. ARM image base is pinned to
`docker.io/library/omarpkg-arm-builder@sha256:e9cbff215a6022ff61f4542b9ab1325e742c89a6a3f736488b4359a373f76db8`.
