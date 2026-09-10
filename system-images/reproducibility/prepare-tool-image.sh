#!/usr/bin/env bash
set -euo pipefail

runtime=$(printenv SYSTEM_IMAGE_REPRO_CONTAINER_RUNTIME || true)
base_image=$(printenv SYSTEM_IMAGE_REPRO_BOOT_BASE_IMAGE || true)
tag=$(printenv SYSTEM_IMAGE_REPRO_BOOT_TOOL_TAG || true)
metadata_output=$(printenv SYSTEM_IMAGE_REPRO_BOOT_TOOL_METADATA || true)
architecture=$(printenv SYSTEM_IMAGE_REPRO_ARCH || true)
[[ -n "$runtime" ]] || runtime=docker
[[ -n "$tag" ]] || tag=localhost/omapkg-image-tools:repro
[[ -n "$metadata_output" ]] || metadata_output=./image-repro-toolchain.json
[[ -n "$architecture" ]] || architecture=x86_64
if [[ "$architecture" == x86_64 ]]; then buildah_package='buildah=1:1.45.0-1'; else buildah_package=buildah; fi
[[ $# -eq 0 || ( $# -eq 1 && "$1" == --push-local ) ]] || { echo 'usage: prepare-tool-image.sh [--push-local]' >&2; exit 2; }
if [[ ${1:-} == --push-local && ! "$tag" =~ ^(localhost|127\.0\.0\.1):[0-9]+/[a-z0-9._/:-]+$ ]]; then
  echo '--push-local requires a loopback registry tag' >&2; exit 2
fi
[[ "$base_image" =~ @sha256:[a-f0-9]{64}$ ]] || { echo 'SYSTEM_IMAGE_REPRO_BOOT_BASE_IMAGE must be digest-pinned' >&2; exit 3; }
command -v "$runtime" >/dev/null 2>&1 || { echo "missing container runtime: $runtime" >&2; exit 3; }
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT INT TERM
cat >"$work/Containerfile" <<EOF
FROM $base_image
EOF
if [[ "$architecture" == aarch64 ]]; then
  cat >>"$work/Containerfile" <<EOF
RUN cp /etc/pacman.conf /tmp/opr-pacman.conf \
    && sed -i '/^[#[:space:]]*DownloadUser[[:space:]]*=/d; /^[#[:space:]]*DisableSandboxSyscalls[[:space:]]*$/d; /^\[options\]$/a DownloadUser = root\\nDisableSandboxSyscalls\\nDisableSandboxFilesystem' /tmp/opr-pacman.conf \
    && pacman --config /tmp/opr-pacman.conf -Sy --noconfirm \
      $buildah_package crun mtools e2fsprogs util-linux qemu-img gptfdisk dosfstools jq grub \
    && rm -f /tmp/opr-pacman.conf
EOF
else
  cat >>"$work/Containerfile" <<EOF
RUN pacman -Sy --noconfirm \
    $buildah_package crun mtools e2fsprogs util-linux qemu-img gptfdisk dosfstools jq grub
EOF
fi
if [[ "$runtime" == docker ]]; then
  DOCKER_BUILDKIT=0 "$runtime" build --pull=false --network bridge --file "$work/Containerfile" --tag "$tag" "$work"
else
  "$runtime" build --pull=false --network bridge --file "$work/Containerfile" --tag "$tag" "$work"
fi
if [[ ${1:-} == --push-local ]]; then "$runtime" push "$tag" >/dev/null; fi
manifest_ref=$("$runtime" image inspect --format '{{index .RepoDigests 0}}' "$tag" 2>/dev/null || true)
[[ "$manifest_ref" =~ @sha256:[a-f0-9]{64}$ ]] || { echo 'tool image has no locally usable manifest digest; refusing config-image ID fallback' >&2; exit 1; }
config_id=$("$runtime" image inspect --format '{{.Id}}' "$tag")
tool_inventory=$("$runtime" run --rm --network none "$manifest_ref" bash -lc 'set -e; for package in buildah crun mtools e2fsprogs util-linux qemu-img gptfdisk dosfstools jq grub; do archive=$(find /var/cache/pacman/pkg -maxdepth 1 -type f -name "$package-*.pkg.tar.zst" | head -n1); test -n "$archive"; version=$(pacman -Q "$package"); sha=$(sha256sum "$archive" | cut -d" " -f1); jq -c -n --arg package "$package" --arg version "$version" --arg archive "$(basename "$archive")" --arg sha "$sha" "{package:\$package,version:\$version,archive:\$archive,sha256:\$sha}"; done' | jq -s .)
"$runtime" run --rm --network none "$manifest_ref" bash -lc 'command -v buildah && command -v mcopy && command -v debugfs && command -v tune2fs && command -v e2fsck && command -v unshare && command -v qemu-img && command -v sgdisk && command -v partx && command -v mkfs.fat && command -v arch-chroot && command -v grub-install && command -v curl && command -v gpg && command -v bsdtar && command -v jq' >/dev/null
jq -cS -n --arg base "$base_image" --arg tag "$tag" --arg manifest "$manifest_ref" --arg config "$config_id" --argjson tools "$tool_inventory" '{schemaVersion:1,kind:"private-image-repro-toolchain",baseImage:$base,localTag:$tag,manifestRef:$manifest,configImageId:$config,tools:$tools,network:"prep-only"}' >"$metadata_output"
echo "SYSTEM_IMAGE_REPRO_BOOT_BUILDER_IMAGE=$manifest_ref"
echo "toolchain metadata: $metadata_output"
