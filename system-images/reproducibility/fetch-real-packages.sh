#!/usr/bin/env bash
set -euo pipefail

output=$1
mirror_from_env=$(printenv SYSTEM_IMAGE_REPRO_ARCH_MIRROR || true)
mirror=${mirror_from_env:-https://fastly.mirror.pkgbuild.com}
profile=${SYSTEM_IMAGE_REPRO_PROFILE:-}
architecture=${SYSTEM_IMAGE_REPRO_ARCH:-}
if [[ -n "$profile" && -f "$profile" ]]; then
  architecture=$(jq -er '.architecture' "$profile")
fi
case "$architecture" in x86_64|aarch64) ;; *) echo "unsupported native fixture architecture: $architecture" >&2; exit 3 ;; esac
if [[ "$architecture" == aarch64 && -z "$mirror_from_env" ]]; then
  echo 'incomplete: SYSTEM_IMAGE_REPRO_ARCH_MIRROR is required for aarch64 package capture' >&2
  exit 3
fi
mkdir -p "$output"
root=$(mktemp -d)
trap 'rm -rf -- "$root"' EXIT INT TERM
mkdir -p "$root/var/lib/pacman" "$root/etc"
if [[ "$architecture" == aarch64 ]]; then
  cat >"$root/pacman.conf" <<EOF
[options]
Architecture = auto
SigLevel = Required DatabaseOptional
[core]
Server = $mirror/\$arch/\$repo
[extra]
Server = $mirror/\$arch/\$repo
EOF
else
  cat >"$root/pacman.conf" <<EOF
[options]
Architecture = auto
SigLevel = Required DatabaseOptional
[core]
Server = $mirror/core/os/\$arch
[extra]
Server = $mirror/extra/os/\$arch
EOF
fi
pacman --config "$root/pacman.conf" --root "$root" --dbpath "$root/var/lib/pacman" -Sy --noconfirm
if [[ -n "$profile" && -f "$profile" ]]; then
  mapfile -t package_roots < <(jq -er '.installPackages[]?, .firmware.package' "$profile")
else
  if [[ "$architecture" == x86_64 ]]; then package_roots=(base linux grub edk2-ovmf); else package_roots=(base linux-aarch64 grub edk2-aarch64); fi
fi
pacman --config "$root/pacman.conf" --root "$root" --dbpath "$root/var/lib/pacman" -Sp --print-format '%n|%f|%l' "${package_roots[@]}" >"$output/closure.tsv"
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
jq -cS -n --arg mirror "$mirror" --arg architecture "$architecture" --argjson count "$(wc -l <"$output/packages.tsv")" '{schemaVersion:1,source:"private-arch-fixture",mirror:$mirror,architecture:$architecture,packageCount:$count,packagesFile:"packages.tsv"}' >"$output/manifest.json"
echo "fetched private real package fixture: $output"
