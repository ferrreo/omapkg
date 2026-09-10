#!/usr/bin/env bash
set -euo pipefail

# Build clean AArch64 runtime from an already signature-verified ARM rootfs.
# Builder image supplies only retained Electron package archive; it is never
# used as runtime base.
repo_root=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
runtime=${OPR_ARM_RUNTIME:-podman}
builder_image=${OPR_ARM_TEMPLATE_BUILDER_IMAGE:?set OPR_ARM_TEMPLATE_BUILDER_IMAGE to a digest-pinned ARM builder}
rootfs_context=${OPR_ARM_RUNTIME_ROOTFS_CONTEXT:?set OPR_ARM_RUNTIME_ROOTFS_CONTEXT to verified rootfs context}
runtime_image=${OPR_ARM_TEMPLATE_RUNTIME_IMAGE:-localhost/opr-template-matrix-runtime-aarch64:local}
work_dir=${OPR_ARM_TEMPLATE_RUNTIME_WORKDIR:-$repo_root/.local/arm/template-runtime}

command -v "$runtime" >/dev/null || { echo "missing runtime: $runtime" >&2; exit 2; }
test -d "$rootfs_context" || { echo "rootfs context is missing: $rootfs_context" >&2; exit 2; }
mkdir -p "$work_dir"
stage=$(mktemp -d "$work_dir/context.XXXXXX")
container="opr-template-electron-package-$$"
cleanup() { "$runtime" rm -f "$container" >/dev/null 2>&1 || true; rm -rf "$stage"; }
trap cleanup EXIT

cp -al "$rootfs_context/." "$stage/"
mkdir -p "$stage/opt"
"$runtime" create --name "$container" "$builder_image" >/dev/null
"$runtime" cp "$container:/opt/electron43-arm-runtime.pkg.tar.zst" "$stage/opt/electron43-arm-runtime.pkg.tar.zst"

if [[ "$runtime" == docker ]]; then
  "$runtime" build --pull=false --platform linux/arm64 --tag "$runtime_image" \
    --file "$repo_root/worker/Dockerfile.template-matrix-runtime-aarch64" "$stage"
else
  "$runtime" build --pull=never --arch arm64 --tag "$runtime_image" \
    --file "$repo_root/worker/Dockerfile.template-matrix-runtime-aarch64" "$stage"
fi
platform=$("$runtime" image inspect --format '{{.Os}}/{{.Architecture}}' "$runtime_image")
[[ "$platform" == linux/arm64 ]] || { echo "runtime image is not linux/arm64: $platform" >&2; exit 1; }
if [[ "$runtime" == docker ]]; then
  manifest_ref=$("$runtime" image inspect --format '{{index .RepoDigests 0}}' "$runtime_image" 2>/dev/null || true)
  if [[ ! "$manifest_ref" =~ @sha256:[0-9a-f]{64}$ ]]; then
    "$runtime" push "$runtime_image" >/dev/null
    manifest_ref=$("$runtime" image inspect --format '{{index .RepoDigests 0}}' "$runtime_image")
  fi
  [[ "$manifest_ref" =~ @sha256:[0-9a-f]{64}$ ]] || { echo 'runtime image has no manifest digest' >&2; exit 1; }
  printf 'runtime_image=%s\n%s\n' "$manifest_ref" "$platform"
else
  digest=$("$runtime" image inspect --format '{{.Digest}}' "$runtime_image")
  [[ "$digest" =~ ^sha256:[0-9a-f]{64}$ ]] || { echo 'runtime image has no digest' >&2; exit 1; }
  printf 'runtime_image=%s\n%s %s\n' "$runtime_image" "$platform" "$digest"
fi
