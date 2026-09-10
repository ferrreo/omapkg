#!/usr/bin/env bash
set -euo pipefail

repo_root=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
mode=build
lock=
profile=
output=
provenance=
work_dir=
overwrite=0
manifest_url=
manifest_signature=
trusted_key=
trusted_fingerprint=
manifest_client=${OMARCHY_MANIFEST_CLIENT:-$repo_root/omarchy-manifest-client}
allow_http=0

die() { echo "system image: $*" >&2; exit 2; }
usage() {
  cat >&2 <<'EOF'
usage: build-system-image.sh [--check] --manifest URL --key FILE --fingerprint HEX --profile FILE
       [--signature URL] [--release-lock FILE]
       [--output FILE --provenance FILE [--work-dir DIR] [--overwrite]]
EOF
}
while (($#)); do
  case $1 in
    --check) mode=check ;;
    --release-lock) lock=${2:-}; shift ;;
    --profile) profile=${2:-}; shift ;;
    --manifest) manifest_url=${2:-}; shift ;;
    --signature) manifest_signature=${2:-}; shift ;;
    --key) trusted_key=${2:-}; shift ;;
    --fingerprint) trusted_fingerprint=${2:-}; shift ;;
    --client) manifest_client=${2:-}; shift ;;
    --allow-http) allow_http=1 ;;
    --output) output=${2:-}; shift ;;
    --provenance) provenance=${2:-}; shift ;;
    --work-dir) work_dir=${2:-}; shift ;;
    --overwrite) overwrite=1 ;;
    -h|--help) usage; exit 0 ;;
    *) usage; die "unknown option: $1" ;;
  esac
  shift
done

[[ -n "$profile" && -f "$profile" ]] || die "--profile must name a regular file"
[[ -n "$manifest_url" ]] || die "--manifest is required; image locks must be reverified by the manifest client"
command -v jq >/dev/null || die "missing jq"
command -v sha256sum >/dev/null || die "missing sha256sum"

canonical_sha() {
  jq -e -s 'length == 1 and (.[0] | type == "object")' "$1" >/dev/null || die "invalid JSON object: $1"
  jq -cS . "$1" | tr -d '\n' | sha256sum | awk '{print $1}'
}
sha256_value() { sha256sum "$1" | awk '{print $1}'; }
hex64() { [[ "$1" =~ ^[a-f0-9]{64}$ ]]; }
safe_file() { [[ -f "$1" && ! -L "$1" ]] || die "expected regular file: $1"; }

temporary_root=
cleanup_paths=()
cleanup_all() { for path in "${cleanup_paths[@]}"; do [[ -n "$path" && -d "$path" ]] && rm -rf -- "$path"; done; }
trap cleanup_all EXIT INT TERM

# A lock is accepted only when produced by the pinned manifest client in this
# invocation. The client verifies the transaction, both lane manifests, and
# every package chunk under the configured OpenPGP key before writing it.
if [[ -n "$manifest_url" ]]; then
  [[ -n "$trusted_key" && -n "$trusted_fingerprint" ]] || die "--manifest requires --key and --fingerprint"
  safe_file "$trusted_key"
  command -v "$manifest_client" >/dev/null 2>&1 || die "manifest client not found: $manifest_client"
  temporary_root=$(mktemp -d "${TMPDIR:-/tmp}/omapkg-image-lock.XXXXXX")
  cleanup_paths+=("$temporary_root")
  chmod 700 "$temporary_root"
  client_args=(image-lock --manifest "$manifest_url" --key "$trusted_key" --fingerprint "$trusted_fingerprint" --arch "$(jq -er '.architecture' "$profile")" --output "$temporary_root/lock")
  [[ -n "$manifest_signature" ]] && client_args+=(--signature "$manifest_signature")
  (( allow_http )) && client_args+=(--allow-http)
  "$manifest_client" "${client_args[@]}" >/dev/null
  if [[ -n "$lock" ]]; then
    [[ "$(canonical_sha "$lock")" == "$(canonical_sha "$temporary_root/lock/release-lock.json")" ]] || die "supplied release lock differs from newly verified manifest inputs"
  fi
  lock=$temporary_root/lock/release-lock.json
fi
safe_file "$lock"

profile_sha256=$(canonical_sha "$profile")
lock_sha256=$(canonical_sha "$lock")
jq -e '.schemaVersion == 1 and .authority == "omarchy-manifest-client-v1" and (.packages | type == "array" and length > 0)' "$lock" >/dev/null || die "release lock is not a manifest-client image lock"
architecture=$(jq -er '.architecture' "$profile")
case "$architecture" in x86_64|aarch64) ;; *) die "profile architecture is unsupported" ;; esac
jq -e --arg arch "$architecture" '.architecture == $arch and .requiresNative == true and .requiresKvm == true and .emulationAllowed == false and .platform == "uefi"' "$profile" >/dev/null || die "profile is not a native UEFI profile"
native_host=$(jq -er '.qualification.nativeHost' "$profile")
[[ "$native_host" == "$architecture" ]] || die "profile native host differs from profile architecture"
system_ref=$(jq -er '.systemManifest.path' "$lock")
opr_ref=$(jq -er '.oprManifest.path' "$lock")
lock_dir=$(CDPATH='' cd -- "$(dirname -- "$lock")" && pwd)
[[ "$system_ref" != /* && "$opr_ref" != /* ]] || die "manifest paths must be relative to image lock"
system_manifest=$lock_dir/$system_ref
opr_manifest=$lock_dir/$opr_ref
safe_file "$system_manifest"; safe_file "$opr_manifest"
system_digest=$(jq -er '.systemManifest.sha256' "$lock")
opr_digest=$(jq -er '.oprManifest.sha256' "$lock")
hex64 "$system_digest" || die "invalid system manifest digest"
hex64 "$opr_digest" || die "invalid OPR manifest digest"
[[ "$(canonical_sha "$system_manifest")" == "$system_digest" ]] || die "system manifest bytes do not match lock"
[[ "$(canonical_sha "$opr_manifest")" == "$opr_digest" ]] || die "OPR manifest bytes do not match lock"
for ref in transaction systemManifest oprManifest; do
  signature_ref=$(jq -er --arg ref "$ref" '.[$ref].signature' "$lock"); signature_digest=$(jq -er --arg ref "$ref" '.[$ref].signatureSha256' "$lock")
  [[ "$signature_ref" != /* ]] || die "$ref signature path must be relative to image lock"
  safe_file "$lock_dir/$signature_ref"; hex64 "$signature_digest" || die "invalid $ref signature digest"
  [[ "$(sha256_value "$lock_dir/$signature_ref")" == "$signature_digest" ]] || die "$ref signature bytes do not match lock"
done
jq -e '.kind == "system" and .lane == "system"' "$system_manifest" >/dev/null || die "lock system manifest is not a system manifest"
jq -e '.kind == "opr" and .lane == "opr"' "$opr_manifest" >/dev/null || die "lock OPR manifest is not an OPR manifest"
transaction_digest=$(jq -er '.transactionSha256' "$lock"); hex64 "$transaction_digest" || die "invalid transaction digest"
transaction_ref=$(jq -er '.transaction.path' "$lock")
[[ "$transaction_ref" != /* ]] || die "transaction path must be relative to image lock"
transaction_path="$lock_dir/$transaction_ref"
safe_file "$transaction_path"
[[ "$(canonical_sha "$transaction_path")" == "$transaction_digest" ]] || die "transaction bytes do not match lock"
while IFS= read -r chunk; do
  chunk_ref=$(jq -er '.path' <<<"$chunk"); [[ "$chunk_ref" != /* ]] || die "package chunk path must be relative to image lock"
  chunk_path="$lock_dir/$chunk_ref"; safe_file "$chunk_path"
  [[ "$(sha256_value "$chunk_path")" == "$(jq -er '.sha256' <<<"$chunk")" ]] || die "package chunk bytes do not match lock"
done < <(jq -c '.packageChunks[]' "$lock")
repo_count=$(jq -er '.repositories | length' "$lock")
(( repo_count > 0 )) || die "verified lock has no signed repository databases"
package_set=$(jq -cS '[.packages[]] | sort_by(.name,.architecture,.version,.sha256)' "$lock" | tr -d '\n' | sha256sum | awk '{print $1}')
[[ "$package_set" == "$(jq -er '.packageSetSha256' "$lock")" ]] || die "package set digest does not match lock"
jq -e '.packageCount == (.packages | length) and .sourcePackageCount >= .packageCount' "$lock" >/dev/null || die "release lock package counts do not match selected/source entries"
source_date_epoch=$(jq -er '.sourceDateEpoch // 0 | numbers | select(. > 0 and . < 4102444800)' "$lock") || die "invalid sourceDateEpoch"

for required in $(jq -er '.basePackages[]?, .kernel.package, .bootloader.package, .firmware.package' "$profile"); do
  jq -e --arg name "$required" '.packages | any(.[]; .name == $name)' "$lock" >/dev/null || die "release lock omits profile package: $required"
done
[[ "$(jq -er '.installPackages | type' "$profile")" == array ]] || die "profile must enumerate its complete install closure"
while IFS= read -r required; do
  [[ -n "$required" ]] || die "profile install package name is empty"
  jq -e --arg name "$required" '.packages | any(.[]; .name == $name)' "$lock" >/dev/null || die "release lock omits install package: $required"
done < <(jq -er '.installPackages[]' "$profile")
profile_arches=$(jq -r '.packages[] | .architecture' "$lock")
while IFS= read -r package_arch; do
  case "$package_arch" in "$architecture"|any|x86_64|aarch64) ;; *) die "package architecture $package_arch is invalid" ;; esac
done <<<"$profile_arches"
while IFS= read -r row; do
  name=$(jq -er '.name' <<<"$row"); version=$(jq -er '.version' <<<"$row"); filename=$(jq -er '.filename' <<<"$row")
  artifact_url=$(jq -er '.url' <<<"$row"); signature_url=$(jq -er '.signatureUrl' <<<"$row")
  digest=$(jq -er '.sha256' <<<"$row"); signature_digest=$(jq -er '.signatureSha256' <<<"$row")
  hex64 "$digest" || die "invalid package digest for $name"
  hex64 "$signature_digest" || die "invalid package signature digest for $name"
  [[ "$filename" != */* && "$filename" =~ ^[A-Za-z0-9._+@:-]+\.pkg\.tar\.[A-Za-z0-9]+$ ]] || die "unsafe package filename for $name"
  [[ "$artifact_url" =~ ^https://[^/?#]+/[^?#]+$ && "$signature_url" =~ ^https://[^/?#]+/[^?#]+\.sig$ ]] || die "package $name must use immutable HTTPS URLs"
  [[ "$version" != *$'\n'* && "$name" != *$'\n'* ]] || die "package identity contains a newline"
done < <(jq -c '.packages[]' "$lock")
duplicate_filename=$(jq -r '.packages[].filename' "$lock" | sort | uniq -d | head -n1)
[[ -z "$duplicate_filename" ]] || die "release lock has duplicate package filename: $duplicate_filename"

if [[ "$mode" == check ]]; then
  echo "verified image lock: transaction=$transaction_digest system=$system_digest opr=$opr_digest packageSet=$package_set profile=$profile_sha256"
  exit 0
fi
[[ -n "$output" && -n "$provenance" ]] || die "--output and --provenance are required for a build"
[[ "$output" != "$provenance" ]] || die "image and provenance paths must differ"
[[ ! -L "$output" && ! -L "$provenance" ]] || die "output paths must not be symlinks"
if [[ -e "$output" || -e "$provenance" ]] && (( ! overwrite )); then die "refusing to overwrite existing output; pass --overwrite"; fi
output_parent=$(CDPATH='' cd -- "$(dirname -- "$output")" 2>/dev/null || true); [[ -n "$output_parent" && -d "$output_parent" ]] || die "output parent must exist"
prov_parent=$(CDPATH='' cd -- "$(dirname -- "$provenance")" 2>/dev/null || true); [[ -n "$prov_parent" && -d "$prov_parent" ]] || die "provenance parent must exist"
[[ "$EUID" == 0 ]] || die "image build needs root for loop devices and filesystems"
native_host=$(uname -m)
case "$native_host" in x86_64) [[ "$architecture" == x86_64 ]] || die "x86_64 builder cannot produce aarch64 native image" ;; aarch64|arm64) [[ "$architecture" == aarch64 ]] || die "aarch64 builder cannot produce x86_64 native image" ;; *) die "unsupported native builder architecture: $native_host" ;; esac
for command_name in curl qemu-img sgdisk losetup udevadm mkfs.fat mkfs.ext4 mount umount blkid pacman grub-install arch-chroot gpg realpath bsdtar; do command -v "$command_name" >/dev/null || die "missing required command: $command_name"; done
if [[ -n "$work_dir" ]]; then mkdir -p -- "$work_dir"; chmod 700 "$work_dir"; build_root=$(mktemp -d "$work_dir/build.XXXXXX"); else build_root=$(mktemp -d "${TMPDIR:-/tmp}/omapkg-system-image.XXXXXX"); fi
cleanup_paths+=("$build_root"); temporary_root=$build_root
chmod 700 "$temporary_root"
cache=$temporary_root/packages; mkdir -p "$cache"; chmod 700 "$cache"
disk_size=$(jq -er '.disk.sizeBytes | numbers | select(. >= 2147483648)' "$profile")
esp_size=$(jq -er '.disk.espSizeMiB | numbers | select(. >= 64)' "$profile")
image_tmp=$temporary_root/image.raw
qemu-img create -f raw "$image_tmp" "$disk_size" >/dev/null
sgdisk --zap-all "$image_tmp" >/dev/null
sgdisk --new=1:2048:+"${esp_size}"M --typecode=1:ef00 --change-name=1:ESP --new=2:0:0 --typecode=2:8300 --change-name=2:ROOT "$image_tmp" >/dev/null
loop=$(losetup --find --show --partscan "$image_tmp")
mounted=0
dev_mounted=0; proc_mounted=0; sys_mounted=0
detach() {
  if (( sys_mounted )); then umount -R "$temporary_root/root/sys" || return 1; fi
  if (( proc_mounted )); then umount -R "$temporary_root/root/proc" || return 1; fi
  if (( dev_mounted )); then umount -R "$temporary_root/root/dev" || return 1; fi
  if (( mounted )); then umount "$temporary_root/root/boot/efi" || return 1; umount "$temporary_root/root" || return 1; mounted=0; fi
  losetup -d "$loop" 2>/dev/null || true
  cleanup_all
}
trap detach EXIT INT TERM
udevadm settle
esp_device=${loop}p1; root_device=${loop}p2
mkfs.fat -F32 "$esp_device" >/dev/null
mkfs.ext4 -F "$root_device" >/dev/null
mkdir -p "$temporary_root/root"
mount "$root_device" "$temporary_root/root"; mounted=1
root=$temporary_root/root
mkdir -p "$root/boot/efi" "$root/dev" "$root/proc" "$root/sys"
mount "$esp_device" "$root/boot/efi"
mount --rbind /dev "$root/dev"; mount --make-rslave "$root/dev"; dev_mounted=1
mount -t proc proc "$root/proc"; proc_mounted=1
mount -t sysfs sysfs "$root/sys"; sys_mounted=1
mkdir -p "$root/var/lib/pacman" "$root/etc" "$root/boot"
pacman_conf=$temporary_root/pacman.conf
printf '%s\n' '[options]' 'Architecture = auto' 'SigLevel = Required DatabaseOptional' 'LocalFileSigLevel = Required' >"$pacman_conf"
mkdir -p "$root/var/lib/pacman/sync"
while IFS= read -r repo; do
  repo_name=$(jq -er '.name' <<<"$repo"); repo_path=$(jq -er '.path' <<<"$repo"); repo_sig=$(jq -er '.signature' <<<"$repo"); repo_digest=$(jq -er '.sha256' <<<"$repo"); repo_sig_digest=$(jq -er '.signatureSha256' <<<"$repo")
  [[ "$repo_path" != /* && "$repo_sig" != /* ]] || die "repository paths must be relative to image lock"
  safe_file "$lock_dir/$repo_path"; safe_file "$lock_dir/$repo_sig"; [[ "$(sha256_value "$lock_dir/$repo_path")" == "$repo_digest" ]] || die "repository database changed: $repo_name"; [[ "$(sha256_value "$lock_dir/$repo_sig")" == "$repo_sig_digest" ]] || die "repository signature changed: $repo_name"
  install -m0644 "$lock_dir/$repo_path" "$root/var/lib/pacman/sync/$repo_name.db"
  install -m0600 "$lock_dir/$repo_sig" "$root/var/lib/pacman/sync/$repo_name.db.sig"
  printf '\n[%s]\nServer = file://%s\n' "$repo_name" "$cache" >>"$pacman_conf"
done < <(jq -c '.repositories[]' "$lock")
gpgdir=$temporary_root/gpg; mkdir -p "$gpgdir"; chmod 700 "$gpgdir"
gpg --batch --no-tty --homedir "$gpgdir" --import "$trusted_key" >/dev/null
printf '%s:6:\n' "$trusted_fingerprint" | gpg --batch --no-tty --homedir "$gpgdir" --import-ownertrust >/dev/null
mapfile -t package_roots < <(jq -er '.installPackages[]' "$profile")
(( ${#package_roots[@]} > 0 )) || die "profile has no installable roots"
closure_file=$temporary_root/closure.txt
pacman --gpgdir "$gpgdir" --config "$pacman_conf" --root "$root" --dbpath "$root/var/lib/pacman" --cachedir "$cache" --noconfirm -Sp --print-format '%f' "${package_roots[@]}" >"$closure_file"
declare -A selected_packages=()
while IFS= read -r filename; do
  filename=${filename##*/}
  [[ "$filename" =~ ^[A-Za-z0-9._+@:-]+\.pkg\.tar\.[A-Za-z0-9]+$ ]] || continue
  selected_packages["$filename"]=1
done <"$closure_file"
firmware_filename=$(jq -er --arg name "$(jq -er '.firmware.package' "$profile")" '.packages[] | select(.name == $name) | .filename' "$lock" | head -n1)
selected_packages["$firmware_filename"]=1
(( ${#selected_packages[@]} > 0 )) || die "signed repository closure returned no package archives"
for filename in "${!selected_packages[@]}"; do
  row=$(jq -ce --arg filename "$filename" '.packages[] | select(.filename == $filename)' "$lock") || die "pacman selected unbound package: $filename"
  [[ "$(jq -r '.install' <<<"$row")" == true || "$filename" == "$firmware_filename" ]] || die "selected package is not installable: $filename"
  url=$(jq -er '.url' <<<"$row"); sig_url=$(jq -er '.signatureUrl' <<<"$row"); expected=$(jq -er '.sha256' <<<"$row")
  curl --fail --location --proto '=https' --tlsv1.2 --output "$cache/$filename" "$url"
  [[ "$(sha256_value "$cache/$filename")" == "$expected" ]] || die "package bytes changed: $filename"
  curl --fail --location --proto '=https' --tlsv1.2 --output "$cache/$filename.sig" "$sig_url"
  [[ "$(sha256_value "$cache/$filename.sig")" == "$(jq -er '.signatureSha256' <<<"$row")" ]] || die "package signature bytes changed: $filename.sig"
done
pacman --gpgdir "$gpgdir" --config "$pacman_conf" --root "$root" --dbpath "$root/var/lib/pacman" --cachedir "$cache" --noconfirm --needed -S "${package_roots[@]}"
kernel_path=$(jq -er '.kernel.path' "$profile"); initramfs_path=$(jq -er '.kernel.initramfs[0]' "$profile"); boot_target=$(jq -er '.bootloader.target' "$profile")
[[ -f "$root$kernel_path" && -f "$root$initramfs_path" ]] || die "profile kernel or initramfs was not installed"
arch-chroot "$root" grub-install --target="$boot_target" --efi-directory=/boot/efi --boot-directory=/boot --removable --no-nvram --recheck >/dev/null
root_uuid=$(blkid -s UUID -o value "$root_device")
esp_uuid=$(blkid -s UUID -o value "$esp_device")
filesystem=$(jq -er '.disk.filesystem' "$profile")
printf '%s\n' "UUID=$root_uuid / $filesystem defaults 0 1" "UUID=$esp_uuid /boot/efi vfat umask=0077 0 2" >"$root/etc/fstab"
kernel_args=$(jq -er '.boot.kernelArguments' "$profile" | sed "s/{rootUuid}/$root_uuid/g")
printf '%s\n' "search --no-floppy --fs-uuid --set=root $root_uuid" "linux $kernel_path $kernel_args" "initrd $initramfs_path" >"$root/boot/grub/grub.cfg"
sync
umount -R "$root/sys"; sys_mounted=0; umount -R "$root/proc"; proc_mounted=0; umount -R "$root/dev"; dev_mounted=0; umount "$root/boot/efi"; umount "$root"; mounted=0; losetup -d "$loop"
install -m0644 "$image_tmp" "$output"
image_sha256=$(sha256_value "$output")
profile_recipe=$(sha256_value "$repo_root/scripts/build-system-image.sh")
profile_arch=$(jq -er '.architecture' "$profile")
firmware_code=$(realpath -e -- "$(jq -er '.firmware.codePath' "$profile")") || die "UEFI code path is unavailable"
firmware_vars=$(realpath -e -- "$(jq -er '.firmware.varsTemplatePath' "$profile")") || die "UEFI variable template path is unavailable"
safe_file "$firmware_code"; safe_file "$firmware_vars"
firmware_package=$(jq -er '.firmware.package' "$profile")
firmware_package_sha=$(jq -er --arg name "$firmware_package" '.packages[] | select(.name == $name) | .sha256' "$lock" | head -n1)
firmware_filename=$(jq -er --arg name "$firmware_package" '.packages[] | select(.name == $name) | .filename' "$lock" | head -n1)
firmware_archive="$cache/$firmware_filename"
[[ -f "$firmware_archive" ]] || die "profile firmware package was not retained"
bsdtar --list --file "$firmware_archive" | grep -Fqx "${firmware_code#/}" || die "firmware code is not owned by pinned package $firmware_package"
bsdtar --list --file "$firmware_archive" | grep -Fqx "${firmware_vars#/}" || die "firmware variable template is not owned by pinned package $firmware_package"
archive_code_sha=$(bsdtar --extract --to-stdout --file "$firmware_archive" -- "${firmware_code#/}" | sha256sum | awk '{print $1}')
archive_vars_sha=$(bsdtar --extract --to-stdout --file "$firmware_archive" -- "${firmware_vars#/}" | sha256sum | awk '{print $1}')
[[ "$archive_code_sha" == "$(sha256_value "$firmware_code")" ]] || die "host UEFI code bytes differ from pinned firmware package"
[[ "$archive_vars_sha" == "$(sha256_value "$firmware_vars")" ]] || die "host UEFI variable template differs from pinned firmware package"
jq -cS -n --arg profile "$profile_sha256" --arg profileId "$(jq -er '.id' "$profile")" --arg recipe "$profile_recipe" --arg lock "$lock_sha256" --arg transaction "$transaction_digest" --arg system "$system_digest" --arg opr "$opr_digest" --arg packageSet "$package_set" --arg image "$image_sha256" --arg architecture "$profile_arch" --arg version "$(jq -er '.systemVersion' "$lock")" --arg generation "$(jq -er '.oprGeneration' "$lock")" --arg kernel "$(jq -er '.kernel.path' "$profile")" --arg bootloader "$(jq -er '.bootloader.target' "$profile")" --arg firmware "$firmware_package" --arg firmwarePackageSHA "$firmware_package_sha" --arg codePath "$firmware_code" --arg codeSHA "$(sha256_value "$firmware_code")" --arg varsPath "$firmware_vars" --arg varsSHA "$(sha256_value "$firmware_vars")" --argjson epoch "$source_date_epoch" --slurpfile packageRows <(jq -cS '[.packages[]] | sort_by(.name,.architecture,.version,.sha256)' "$lock") --slurpfile repoRows <(jq -cS '.repositories' "$lock") '{schemaVersion:1,authority:"omarchy-manifest-client-v1",transactionSha256:$transaction,systemManifestSha256:$system,oprManifestSha256:$opr,packageSetSha256:$packageSet,releaseLockSha256:$lock,profileId:$profileId,profileSha256:$profile,platformProfile:$profileId,recipeSha256:$recipe,systemVersion:$version,oprGeneration:$generation,architecture:$architecture,nativeArchitecture:$architecture,sourceDateEpoch:$epoch,kernel:$kernel,bootloader:$bootloader,firmware:{package:$firmware,packageSha256:$firmwarePackageSHA,codePath:$codePath,codeSha256:$codeSHA,varsTemplatePath:$varsPath,varsTemplateSha256:$varsSHA},imageSha256:$image,repositories:$repoRows[0],packages:$packageRows[0]}' >"$provenance"
chmod 644 "$output"; chmod 644 "$provenance"
echo "built $output ($image_sha256)"
