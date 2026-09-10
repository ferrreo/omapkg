#!/usr/bin/env bash
set -euo pipefail

output=$1
mirror=${SYSTEM_IMAGE_REPRO_ARCH_MIRROR:-https://fastly.mirror.pkgbuild.com}
mkdir -p "$output"
root=$(mktemp -d)
trap 'rm -rf -- "$root"' EXIT INT TERM
mkdir -p "$root/var/lib/pacman" "$root/etc"
cat >"$root/pacman.conf" <<EOF
[options]
Architecture = auto
SigLevel = Required DatabaseOptional
[core]
Server = $mirror/core/os/\$arch
[extra]
Server = $mirror/extra/os/\$arch
EOF
pacman --config "$root/pacman.conf" --root "$root" --dbpath "$root/var/lib/pacman" -Sy --noconfirm
pacman --config "$root/pacman.conf" --root "$root" --dbpath "$root/var/lib/pacman" -Sp --print-format '%n|%f|%l' base linux grub edk2-ovmf >"$output/closure.tsv"
: >"$output/packages.tsv"
while IFS='|' read -r name filename url; do
  [[ -n "$filename" && -n "$url" ]] || continue
  [[ "$url" == https://* || "$url" == file://* ]] || { echo "unsupported package URL: $url" >&2; exit 1; }
  package="$output/$filename"
  signature="$package.sig"
  if [[ "$url" == file://* ]]; then
    url_path=$(printf '%s' "$url" | sed 's#^file://##')
    cp -- "$url_path" "$package"
    cp -- "$url_path.sig" "$signature"
  else
    curl --fail --location --proto '=https' --tlsv1.2 --output "$package" "$url"
    curl --fail --location --proto '=https' --tlsv1.2 --output "$signature" "$url.sig"
  fi
  pacman-key --verify "$signature" "$package" >/dev/null
  sha=$(sha256sum "$package" | awk '{print $1}')
  sig_sha=$(sha256sum "$signature" | awk '{print $1}')
  printf '%s\t%s\t%s\t%s\t%s\n' "$name" "$filename" "$url" "$sha" "$sig_sha" >>"$output/packages.tsv"
done <"$output/closure.tsv"
sort -u -o "$output/packages.tsv" "$output/packages.tsv"
jq -cS -n --arg mirror "$mirror" --argjson count "$(wc -l <"$output/packages.tsv")" '{schemaVersion:1,source:"private-arch-fixture",mirror:$mirror,packageCount:$count,packagesFile:"packages.tsv"}' >"$output/manifest.json"
echo "fetched private real package fixture: $output"
