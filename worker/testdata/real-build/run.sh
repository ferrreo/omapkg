#!/bin/sh
set -eu

: "${FACTORY_BUILDER_IMAGE:?set FACTORY_BUILDER_IMAGE to a digest-pinned local image}"
: "${FACTORY_BUILDER_IMAGE_DIGEST:?set FACTORY_BUILDER_IMAGE_DIGEST to the image digest}"

case "$FACTORY_BUILDER_IMAGE" in
  *@$FACTORY_BUILDER_IMAGE_DIGEST) ;;
  *) echo 'FACTORY_BUILDER_IMAGE must end with FACTORY_BUILDER_IMAGE_DIGEST' >&2; exit 2 ;;
esac

actual_digest=$(podman image inspect --format '{{.Digest}}' "$FACTORY_BUILDER_IMAGE")
test "$actual_digest" = "$FACTORY_BUILDER_IMAGE_DIGEST"

tmp=$(mktemp -d "${TMPDIR:-/tmp}/omarpkg-real-build.XXXXXX")
cleanup() {
  podman unshare rm -rf -- "$tmp" 2>/dev/null || :
}
trap cleanup EXIT INT TERM
work=$tmp/work
output=$tmp/output
mkdir "$work" "$output"
cp "$(dirname "$0")/PKGBUILD" "$work/PKGBUILD"
curl --fail --location --proto '=https' --tlsv1.2 --max-time 60 \
  -o "$work/hello-2.12.tar.gz" \
  https://ftp.gnu.org/gnu/hello/hello-2.12.tar.gz
printf '%s  %s\n' \
  cf04af86dc085268c5f4470fbae49b18afbc221b78096aab842d934a76bad0ab \
  "$work/hello-2.12.tar.gz" | sha256sum -c -
chmod -R a+rwX "$work" "$output"

podman run --rm --pull=never --network none --read-only \
  --cap-drop ALL --security-opt no-new-privileges:true \
  --pids-limit 512 --memory 4g --cpus 2 \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,mode=1777 \
  --tmpfs /run:rw,noexec,nosuid,nodev \
  --workdir /work --user 65534:65534 \
  --mount "type=bind,src=$work,dst=/work" \
  --mount "type=bind,src=$output,dst=/output" \
  "$FACTORY_BUILDER_IMAGE" \
  sh -ceu '
    cp /etc/makepkg.conf /tmp/makepkg.conf
    printf "\nPKGDEST=/output\nSRCDEST=/work\nLOGDEST=/output\nPKGEXT='.pkg.tar.zst'\n" >> /tmp/makepkg.conf
    makepkg --noconfirm --check --config /tmp/makepkg.conf >/tmp/makepkg.log 2>&1
    tail -20 /tmp/makepkg.log
  '

artifact=$(find "$output" -maxdepth 1 -type f -name '*.pkg.tar.zst' -print)
test "$(printf '%s\n' "$artifact" | wc -l)" -eq 1
printf 'artifact=%s\n' "$artifact"
sha256sum "$artifact"

podman run --rm --pull=never --network none --read-only \
  --cap-drop ALL --security-opt no-new-privileges:true \
  --pids-limit 512 --memory 4g --cpus 2 \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,mode=1777 \
  --tmpfs /run:rw,noexec,nosuid,nodev \
  --workdir /opr/output --user 65532:65532 \
  --mount "type=bind,src=$output,dst=/opr/output,readonly" \
  "$FACTORY_BUILDER_IMAGE" \
  sh -ceu '
    pkg=$(find /opr/output -maxdepth 1 -type f -name "*.pkg.tar.zst" -print -quit)
    test -n "$pkg"
    pacman -Qp "$pkg" | grep -F "opr-hello-real 2.12-1"
    bsdtar -tf "$pkg" | grep -Fx usr/bin/hello
    ! curl --fail --silent --connect-timeout 1 https://example.com/
    echo smoke-ok
  '
