#!/usr/bin/env bash
set -euo pipefail

repo_root=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
work_dir=${OPR_ARM_WORKDIR:-$repo_root/.local/arm/aarch64-20260905}
image=${OPR_ARM_IMAGE:-localhost/omapkg-arch-builder:aarch64-2026-09-05}
rootfs_url=${OPR_ARM_ROOTFS_URL:-http://os.archlinuxarm.org/os/ArchLinuxARM-aarch64-latest.tar.gz}
keyserver=${OPR_ARM_KEYSERVER:-hkps://keyserver.ubuntu.com}
key_fingerprint=68B3537F39A313B3E574D06777193F152BDBE6A6

for command_name in curl gpg md5sum sha256sum tar; do
  command -v "$command_name" >/dev/null || { echo "missing required command: $command_name" >&2; exit 2; }
done

runtime=${OPR_ARM_RUNTIME:-docker}
case "$runtime" in
  docker) command -v docker >/dev/null || { echo 'missing required command: docker' >&2; exit 2; } ;;
  podman) command -v podman >/dev/null || { echo 'missing required command: podman' >&2; exit 2; } ;;
  *) echo 'OPR_ARM_RUNTIME must be docker or podman' >&2; exit 2 ;;
esac

mkdir -p "$work_dir"
chmod 700 "$work_dir"
archive="$work_dir/ArchLinuxARM-aarch64-latest.tar.gz"
signature="$archive.sig"
checksum="$archive.md5"
context="$work_dir/context"
gnupg_home="$work_dir/gnupg"

curl --fail --location --retry 3 --output "$archive" "$rootfs_url"
curl --fail --location --retry 3 --output "$signature" "$rootfs_url.sig"
curl --fail --location --retry 3 --output "$checksum" "$rootfs_url.md5"
(cd "$work_dir" && md5sum --check "$(basename "$checksum")")
rootfs_sha256=$(sha256sum "$archive" | awk '{print $1}')
expected_sha256=${OPR_ARM_ROOTFS_SHA256:-42a4eeaa038994ffd31fa173256ef2f0ef511358eeb41b9ea1f8626391b9b319}
if [[ "$rootfs_sha256" != "$expected_sha256" ]]; then
  echo "unexpected Arch Linux ARM rootfs SHA-256: $rootfs_sha256" >&2
  echo "set OPR_ARM_ROOTFS_SHA256 explicitly when accepting a new upstream rootfs" >&2
  exit 1
fi

mkdir -p "$gnupg_home"
chmod 700 "$gnupg_home"
GNUPGHOME="$gnupg_home" gpg --batch --keyserver "$keyserver" --recv-keys "$key_fingerprint" >/dev/null
fingerprints=$(GNUPGHOME="$gnupg_home" gpg --batch --with-colons --fingerprint "$key_fingerprint" | awk -F: '$1 == "fpr" { print $10 }')
grep -qx "$key_fingerprint" <<<"$fingerprints"
GNUPGHOME="$gnupg_home" gpg --batch --verify "$signature" "$archive" >/dev/null

if [[ -e "$context" ]]; then
  find "$context" -depth -type f -exec unlink {} \;
  find "$context" -depth -type l -exec unlink {} \;
  find "$context" -depth -type d -empty -exec rmdir {} \;
fi
mkdir -p "$context"
tar --extract --gzip --file "$archive" --directory "$context" \
  --no-xattrs --no-same-owner --no-same-permissions --delay-directory-restore

cat > "$work_dir/provenance.txt" <<EOF
source_url=$rootfs_url
source_sha256=$rootfs_sha256
source_md5=$(awk '{print $1}' "$checksum")
signature_key=$key_fingerprint
retrieved_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
EOF

if [[ "$runtime" == docker ]]; then
  docker buildx build --platform linux/arm64 --load --tag "$image" \
    --file "$repo_root/worker/images/aarch64/Dockerfile" "$context"
  actual=$(docker image inspect --format '{{.Os}}/{{.Architecture}}' "$image")
else
  podman build --arch arm64 --tag "$image" \
    --file "$repo_root/worker/images/aarch64/Dockerfile" "$context"
  actual=$(podman image inspect --format '{{.Os}}/{{.Architecture}}' "$image")
fi
test "$actual" = linux/arm64
printf 'image=%s\nplatform=%s\nrootfs_sha256=%s\n' "$image" "$actual" "$rootfs_sha256"

if [[ "${OPR_ARM_PUSH:-0}" == 1 ]]; then
  "$runtime" push "$image"
fi
