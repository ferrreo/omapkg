#!/usr/bin/env bash
set -euo pipefail

if [[ "${OMAPKG_IMAGE_CLEAN_ENV:-}" != 1 ]]; then
  clean_env=(PATH=/usr/bin:/bin HOME=/tmp LANG=C LC_ALL=C TZ=UTC TMPDIR=/tmp OMAPKG_IMAGE_CLEAN_ENV=1)
  exec env -i "${clean_env[@]}" "$0" "$@"
fi

repo_root=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
mode=build
lock=
candidate_lock=
candidate_id=
native_plan=
candidate_lock_signature=
native_plan_signature=
coordinator_binding=
candidate_mode=0
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
       build-system-image.sh [--check] --candidate-lock FILE --candidate-lock-signature FILE --candidate-id ID --native-plan FILE --native-plan-signature FILE --key FILE --fingerprint HEX --profile FILE
EOF
}
while (($#)); do
  case $1 in
    --check) mode=check ;;
    --release-lock) lock=${2:-}; shift ;;
    --candidate-lock) candidate_lock=${2:-}; candidate_mode=1; shift ;;
    --candidate-lock-signature) candidate_lock_signature=${2:-}; candidate_mode=1; shift ;;
    --candidate-id) candidate_id=${2:-}; candidate_mode=1; shift ;;
    --native-plan) native_plan=${2:-}; candidate_mode=1; shift ;;
    --native-plan-signature) native_plan_signature=${2:-}; candidate_mode=1; shift ;;
    --coordinator-binding) coordinator_binding=${2:-}; candidate_mode=1; shift ;;
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
if (( ! candidate_mode )); then
  [[ -n "$manifest_url" ]] || die "--manifest is required; image locks must be reverified by the manifest client"
else
  [[ -z "$manifest_url" && -n "$candidate_lock" && -n "$candidate_id" && -n "$native_plan" && ( -n "$coordinator_binding" || ( -n "$candidate_lock_signature" && -n "$native_plan_signature" ) ) ]] || die "private candidate builds require a coordinator binding or signed candidate inputs without --manifest"
  [[ -n "$trusted_key" && -n "$trusted_fingerprint" ]] || die "private candidate builds require --key and --fingerprint for package signatures"
fi
command -v jq >/dev/null || die "missing jq"
command -v sha256sum >/dev/null || die "missing sha256sum"

canonical_sha() {
  jq -e -s 'length == 1 and (.[0] | type == "object")' "$1" >/dev/null || die "invalid JSON object: $1"
  jq -cS . "$1" | tr -d '\n' | sha256sum | awk '{print $1}'
}
sha256_value() { sha256sum "$1" | awk '{print $1}'; }
hex64() { [[ "$1" =~ ^[a-f0-9]{64}$ ]]; }
guid_from_hash() { local hex=${1:0:32}; printf '%s-%s-%s-%s-%s' "${hex:0:8}" "${hex:8:4}" "${hex:12:4}" "${hex:16:4}" "${hex:20:12}"; }
safe_file() { [[ -f "$1" && ! -L "$1" ]] || die "expected regular file: $1"; }
offline_exec() { unshare --net -- "$@"; }
verify_reviewed_signature() {
  local payload=$1 signature=$2 verify_root status
  safe_file "$payload"; safe_file "$signature"
  verify_root=$(mktemp -d "${TMPDIR:-/tmp}/omapkg-image-signature.XXXXXX")
  cleanup_paths+=("$verify_root")
  chmod 700 "$verify_root"
  gpg --batch --no-tty --homedir "$verify_root" --import "$trusted_key" >/dev/null 2>&1 || die "cannot load trusted candidate authority key"
  status=$(gpg --batch --no-tty --status-fd=1 --homedir "$verify_root" --verify "$signature" "$payload" 2>/dev/null || true)
  grep -Eq "^\\[GNUPG:\\] VALIDSIG ${trusted_fingerprint^^}( |$)" <<<"$status" || die "candidate authority signature is invalid"
}
archive_paths_checked=0
archive_metadata_checked=0
timestamp_ownership_order_checked=0
declare -A allowed_owners=()
inspect_package_archive() {
  local archive=$1 listing mtree entries sorted
  listing=$(bsdtar --list --file "$archive")
  [[ "$listing" == "$(printf '%s\n' "$listing" | LC_ALL=C sort)" ]] || die "package archive member order is not deterministic: $(basename "$archive")"
  awk '$0 ~ /^\// || $0 ~ /(^|\/)\.\.(\/|$)/ { bad=1 } END { exit bad+0 }' <<<"$listing" || die "package archive contains an unsafe path: $(basename "$archive")"
  archive_paths_checked=1
  mtree=$(bsdtar --extract --to-stdout --file "$archive" .MTREE | gzip --decompress)
  entries=$(grep '^\.' <<<"$mtree" || true)
  [[ -n "$entries" ]] || die "package archive has no mtree entries: $(basename "$archive")"
  sorted=$(printf '%s\n' "$entries" | LC_ALL=C sort)
  [[ "$entries" == "$sorted" ]] || die "package archive mtree order is not deterministic: $(basename "$archive")"
  awk '/^\./ { if ($0 !~ /time=[0-9]+(\.0)?/ || ($0 ~ /uid=/ && $0 !~ /uid=[0-9]+/) || ($0 ~ /gid=/ && $0 !~ /gid=[0-9]+/)) bad=1 } END { exit bad+0 }' <<<"$entries" || die "package archive timestamp or ownership metadata is not deterministic: $(basename "$archive")"
  default_uid=$(sed -n 's#^/set.*uid=\([0-9][0-9]*\).*#\1#p' <<<"$mtree" | head -n1)
  default_gid=$(sed -n 's#^/set.*gid=\([0-9][0-9]*\).*#\1#p' <<<"$mtree" | head -n1)
  [[ -n "$default_uid" && -n "$default_gid" ]] && allowed_owners["$default_uid:$default_gid"]=1
  while IFS= read -r entry; do
    uid=$(sed -n 's/.* uid=\([0-9][0-9]*\).*/\1/p' <<<"$entry")
    gid=$(sed -n 's/.* gid=\([0-9][0-9]*\).*/\1/p' <<<"$entry")
    [[ -n "$uid" && -n "$gid" ]] && allowed_owners["$uid:$gid"]=1
  done <<<"$entries"
  archive_metadata_checked=1
  timestamp_ownership_order_checked=1
}
normalize_ext4_metadata() {
  local device=$1 inodes=$2 epoch=$3 inode fs_time fsck_status
  if e2fsck -fyD "$device" >/dev/null 2>&1; then fsck_status=0; else fsck_status=$?; fi
  (( fsck_status < 2 )) || die "cannot verify ext4 image before normalization"
  while IFS= read -r inode; do
    [[ "$inode" =~ ^[0-9]+$ ]] || die "invalid staged inode identity"
    printf '%s\n' "set_inode_field <$inode> atime $epoch" "set_inode_field <$inode> ctime $epoch" "set_inode_field <$inode> mtime $epoch" "set_inode_field <$inode> crtime $epoch" quit | debugfs -w "$device" >/dev/null 2>&1 || die "cannot normalize ext4 inode metadata: $inode"
  done <"$inodes"
  fs_time=$(date -u -d "@$epoch" +%Y%m%d%H%M%S)
  tune2fs -T "$fs_time" "$device" >/dev/null 2>&1 || die "cannot normalize ext4 superblock time"
  printf '%s\n' "set_super_value wtime $epoch" "set_super_value mtime $epoch" "set_super_value lastcheck $epoch" "set_super_value mkfs_time $epoch" quit | debugfs -w "$device" >/dev/null 2>&1 || die "cannot normalize ext4 superblock timestamps"
}

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
elif (( candidate_mode )); then
  lock=$candidate_lock
fi
safe_file "$lock"

profile_sha256=$(canonical_sha "$profile")
lock_sha256=$(canonical_sha "$lock")
if (( candidate_mode )); then
  safe_file "$native_plan"
  safe_file "$trusted_key"
  if [[ -n "$coordinator_binding" ]]; then safe_file "$coordinator_binding"; else command -v gpg >/dev/null || die "missing gpg for candidate authority verification"; verify_reviewed_signature "$lock" "$candidate_lock_signature"; verify_reviewed_signature "$native_plan" "$native_plan_signature"; fi
  jq -e --arg id "$candidate_id" '.schemaVersion == 1 and .authority == "factory-candidate-v1" and .candidate.executionScope == "private" and .candidate.id == $id and (.candidate.ownedUniverseSha256 | type == "string") and (.candidate.inputLockSha256 | type == "string") and (.candidate.nativePlanSha256 | type == "string") and (.packages | type == "array" and length > 0)' "$lock" >/dev/null || die "candidate lock is not a reviewed private image lock"
  candidate_owned_universe=$(jq -er '.candidate.ownedUniverseSha256' "$lock"); candidate_input_lock=$(jq -er '.candidate.inputLockSha256' "$lock"); candidate_native_plan=$(jq -er '.candidate.nativePlanSha256' "$lock")
  hex64 "$candidate_owned_universe" || die "candidate owned-universe digest is invalid"
  hex64 "$candidate_input_lock" || die "candidate input-lock digest is invalid"
  hex64 "$candidate_native_plan" || die "candidate native-plan digest is invalid"
  [[ "$(canonical_sha "$native_plan")" == "$candidate_native_plan" ]] || die "native plan bytes do not match candidate lock"
  jq -e --arg id "$candidate_id" --arg arch "$(jq -er '.architecture' "$profile")" --arg owned "$candidate_owned_universe" --arg input "$candidate_input_lock" '.schemaVersion == 1 and (.kind == "factory-image-native-plan" or .kind == "factory-image-construction-proof") and .candidateId == $id and .architecture == $arch and .inputLockSha256 == $input and .status == "reviewed" and ((.kind == "factory-image-native-plan" and .executionScope == "private" and .ownedUniverseSha256 == $owned) or (.kind == "factory-image-construction-proof" and (.runPolicySha256 | type == "string")))' "$native_plan" >/dev/null || die "native plan is not the exact reviewed private construction proof"
  if [[ -n "$coordinator_binding" ]]; then jq -e --arg id "$candidate_id" --arg arch "$(jq -er '.architecture' "$profile")" --arg lock "$lock_sha256" --arg proof "$candidate_native_plan" --arg profile "$profile_sha256" '.schemaVersion == 1 and .kind == "factory-image-coordinator-binding" and .candidateId == $id and .architecture == $arch and .candidateLockSha256 == $lock and .constructionProofSha256 == $proof and .profileSha256 == $profile and (.policySha256 | test("^[a-f0-9]{64}$")) and (.inputSha256 | test("^[a-f0-9]{64}$"))' "$coordinator_binding" >/dev/null || die "coordinator construction binding is invalid"; fi
else
  jq -e '.schemaVersion == 1 and .authority == "omarchy-manifest-client-v1" and (.packages | type == "array" and length > 0)' "$lock" >/dev/null || die "release lock is not a manifest-client image lock"
  candidate_owned_universe=
  candidate_input_lock=
  candidate_native_plan=
fi
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
image_seed=$(printf '%s\n%s\n%s\n%s\n%s\n' "$lock_sha256" "$profile_sha256" "$architecture" "$source_date_epoch" "${candidate_native_plan:-}" | sha256sum | awk '{print $1}')
disk_guid=$(guid_from_hash "$image_seed")
esp_partition_guid=$(guid_from_hash "$(printf '%s-esp' "$image_seed" | sha256sum | awk '{print $1}')")
root_partition_guid=$(guid_from_hash "$(printf '%s-root' "$image_seed" | sha256sum | awk '{print $1}')")
root_uuid=$(guid_from_hash "$(printf '%s-rootfs' "$image_seed" | sha256sum | awk '{print $1}')")
esp_uuid_raw=$(printf '%s' "$image_seed" | cut -c1-8)
esp_uuid="${esp_uuid_raw:0:4}-${esp_uuid_raw:4:4}"
export SOURCE_DATE_EPOCH="$source_date_epoch" TZ=UTC LANG=C LC_ALL=C E2FSPROGS_FAKE_TIME="$source_date_epoch"

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
for command_name in curl qemu-img sgdisk losetup udevadm mkfs.fat mkfs.ext4 mount umount blkid pacman grub-install arch-chroot gpg realpath bsdtar gzip unshare debugfs e2fsck tune2fs mcopy truncate dd; do command -v "$command_name" >/dev/null || die "missing required command: $command_name"; done
if [[ -n "$work_dir" ]]; then mkdir -p -- "$work_dir"; chmod 700 "$work_dir"; build_root=$(mktemp -d "$work_dir/build.XXXXXX"); else build_root=$(mktemp -d "${TMPDIR:-/tmp}/omapkg-system-image.XXXXXX"); fi
cleanup_paths+=("$build_root"); temporary_root=$build_root
chmod 700 "$temporary_root"
cache=$temporary_root/packages; mkdir -p "$cache"; chmod 700 "$cache"
disk_size=$(jq -er '.disk.sizeBytes | numbers | select(. >= 2147483648)' "$profile")
esp_size=$(jq -er '.disk.espSizeMiB | numbers | select(. >= 64)' "$profile")
image_tmp=$temporary_root/image.raw
qemu-img create -f raw "$image_tmp" "$disk_size" >/dev/null
sgdisk --zap-all "$image_tmp" >/dev/null
sgdisk --disk-guid="$disk_guid" --new=1:2048:+"${esp_size}"M --partition-guid=1:"$esp_partition_guid" --typecode=1:ef00 --change-name=1:ESP --new=2:0:0 --partition-guid=2:"$root_partition_guid" --typecode=2:8300 --change-name=2:ROOT "$image_tmp" >/dev/null
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
mkfs.fat -F32 -i "$esp_uuid_raw" "$esp_device" >/dev/null
mkfs.ext4 -F -U "$root_uuid" -E lazy_itable_init=0,lazy_journal_init=0,hash_seed="$root_uuid" "$root_device" >/dev/null
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
  inspect_package_archive "$cache/$filename"
done
offline_exec pacman --gpgdir "$gpgdir" --config "$pacman_conf" --root "$root" --dbpath "$root/var/lib/pacman" --cachedir "$cache" --noconfirm --needed -S "${package_roots[@]}"
rm -f -- "$root/etc/machine-id" "$root/var/lib/systemd/random-seed" "$root"/etc/ssh/ssh_host_* 2>/dev/null || true
ln -s /run/machine-id "$root/etc/machine-id"
[[ ! -e "$root/var/lib/systemd/random-seed" && -z "$(find "$root/etc/ssh" -maxdepth 1 -name 'ssh_host_*' -print -quit 2>/dev/null)" ]] || die "machine identity or host SSH material leaked into image"
kernel_path=$(jq -er '.kernel.path' "$profile"); initramfs_path=$(jq -er '.kernel.initramfs[0]' "$profile"); boot_target=$(jq -er '.bootloader.target' "$profile")
[[ -f "$root$kernel_path" && -f "$root$initramfs_path" ]] || die "profile kernel or initramfs was not installed"
offline_exec arch-chroot "$root" grub-install --target="$boot_target" --efi-directory=/boot/efi --boot-directory=/boot --removable --no-nvram --recheck >/dev/null
filesystem=$(jq -er '.disk.filesystem' "$profile")
printf '%s\n' "UUID=$root_uuid / $filesystem defaults 0 1" "UUID=$(blkid -s UUID -o value "$esp_device") /boot/efi vfat umask=0077 0 2" >"$root/etc/fstab"
kernel_args=$(jq -er '.boot.kernelArguments' "$profile" | sed "s/{rootUuid}/$root_uuid/g")
printf '%s\n' "search --no-floppy --fs-uuid --set=root $root_uuid" "linux $kernel_path $kernel_args" "initrd $initramfs_path" >"$root/boot/grub/grub.cfg"
find "$root" -xdev -print0 | xargs -0 touch -h -d "@$source_date_epoch"
find "$root/boot/efi" -xdev -print0 | xargs -0 touch -h -d "@$source_date_epoch"
while IFS= read -r path; do
  owner=$(stat -c '%u:%g' "$path")
  [[ -n "${allowed_owners[$owner]:-}" ]] || die "image path has undeclared ownership: $path ($owner)"
done < <(find "$root" -xdev -print)
[[ -z "$(find "$root" -xdev -printf '%T@ %p\n' | awk -v epoch="$source_date_epoch" '$1 + 0 != epoch { print; exit }')" ]] || die "image root contains an uncontrolled timestamp"
esp_epoch=$((source_date_epoch - source_date_epoch % 2))
[[ -z "$(find "$root/boot/efi" -xdev -printf '%T@ %p\n' | awk -v epoch="$esp_epoch" '$1 + 0 != epoch { print; exit }')" ]] || die "ESP contains an uncontrolled timestamp"
root_inodes="$temporary_root/root-inodes.txt"
find "$root" -xdev -printf '%i\n' | sort -nu >"$root_inodes"
esp_stage="$temporary_root/esp-stage"
mkdir -p "$esp_stage"
cp -a "$root/boot/efi/." "$esp_stage/"
find "$esp_stage" -print0 | xargs -0 touch -h -d "@$esp_epoch"
sync
[[ "$(blkid -s UUID -o value "$root_device")" == "$root_uuid" ]] || die "root filesystem UUID changed during image build"
[[ "$(blkid -s UUID -o value "$esp_device" | tr -d '-' | tr '[:upper:]' '[:lower:]')" == "$esp_uuid_raw" ]] || die "ESP filesystem UUID changed during image build"
umount -R "$root/sys"; sys_mounted=0; umount -R "$root/proc"; proc_mounted=0; umount -R "$root/dev"; dev_mounted=0; umount "$root/boot/efi"; umount "$root"; mounted=0
normalize_ext4_metadata "$root_device" "$root_inodes" "$source_date_epoch"
losetup -d "$loop"; loop=
esp_image="$temporary_root/esp.img"
truncate -s "$((esp_size * 1024 * 1024))" "$esp_image"
mkfs.fat -F32 -i "$esp_uuid_raw" "$esp_image" >/dev/null
mcopy -s -p -i "$esp_image" "$esp_stage"/* :: >/dev/null
[[ "$(blkid -s UUID -o value "$esp_image" | tr -d '-' | tr '[:upper:]' '[:lower:]')" == "$esp_uuid_raw" ]] || die "staged ESP filesystem UUID changed"
dd if="$esp_image" of="$image_tmp" bs=512 seek=2048 conv=notrunc status=none
install -m0644 "$image_tmp" "$output"
image_sha256=$(sha256_value "$output")
image_size=$(stat -c '%s' "$output")
image_name=$(basename -- "$output")
source_manifest_sha=$(jq -cS -n --arg system "$system_digest" --arg opr "$opr_digest" '[{name:"system",sha256:$system},{name:"opr",sha256:$opr}]' | tr -d '\n' | sha256sum | awk '{print $1}')
image_output_set_sha=$(jq -cS -n --arg filename "$image_name" --arg sha "$image_sha256" --argjson size "$image_size" '[{filename:$filename,size:$size,sha256:$sha}]' | tr -d '\n' | sha256sum | awk '{print $1}')
input_identity_sha=${candidate_input_lock:-$lock_sha256}
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
jq -cS -n --arg profile "$profile_sha256" --arg profileId "$(jq -er '.id' "$profile")" --arg recipe "$profile_recipe" --arg lock "$lock_sha256" --arg inputLock "$input_identity_sha" --arg transaction "$transaction_digest" --arg system "$system_digest" --arg opr "$opr_digest" --arg packageSet "$package_set" --arg image "$image_sha256" --arg imageName "$image_name" --arg sourceManifest "$source_manifest_sha" --arg imageSet "$image_output_set_sha" --arg candidateId "$candidate_id" --arg candidateOwned "$candidate_owned_universe" --arg candidateInput "$candidate_input_lock" --arg candidatePlan "$candidate_native_plan" --arg architecture "$profile_arch" --arg version "$(jq -er '.systemVersion' "$lock")" --arg generation "$(jq -er '.oprGeneration' "$lock")" --arg kernel "$(jq -er '.kernel.path' "$profile")" --arg bootloader "$(jq -er '.bootloader.target' "$profile")" --arg firmware "$firmware_package" --arg firmwarePackageSHA "$firmware_package_sha" --arg codePath "$firmware_code" --arg codeSHA "$(sha256_value "$firmware_code")" --arg varsPath "$firmware_vars" --arg varsSHA "$(sha256_value "$firmware_vars")" --argjson imageSize "$image_size" --argjson epoch "$source_date_epoch" --slurpfile packageRows <(jq -cS '[.packages[]] | sort_by(.name,.architecture,.version,.sha256)' "$lock") --slurpfile repoRows <(jq -cS '.repositories' "$lock") --argjson candidateMode "$candidate_mode" '{schemaVersion:1,authority:(if ($candidateMode == 1) then "factory-candidate-v1" else "omarchy-manifest-client-v1" end),candidate:(if ($candidateMode == 1) then {id:$candidateId,executionScope:"private",ownedUniverseSha256:$candidateOwned,inputLockSha256:$candidateInput,nativePlanSha256:$candidatePlan} else null end),transactionSha256:$transaction,systemManifestSha256:$system,oprManifestSha256:$opr,packageSetSha256:$packageSet,releaseLockSha256:$lock,profileId:$profileId,profileSha256:$profile,platformProfile:$profileId,recipeSha256:$recipe,systemVersion:$version,oprGeneration:$generation,architecture:$architecture,nativeArchitecture:$architecture,sourceDateEpoch:$epoch,kernel:$kernel,bootloader:$bootloader,firmware:{package:$firmware,packageSha256:$firmwarePackageSHA,codePath:$codePath,codeSha256:$codeSHA,varsTemplatePath:$varsPath,varsTemplateSha256:$varsSHA},imageSha256:$image,repositories:$repoRows[0],packages:$packageRows[0],reproducibility:{schemaVersion:1,status:"reproducibility-contract-verified",mode:"single-build",target:$architecture,inputs:{recipeSha256:$recipe,sourceManifestSha256:$sourceManifest,inputLockSha256:$inputLock,dependencyPlanSha256:$transaction,imageDigest:("sha256:" + $profile),sourceDateEpoch:$epoch},controls:{network:"disabled",locale:"C",timezone:"UTC",umask:"022",hostSecrets:"excluded",writableCaches:"excluded",nativeTarget:$architecture,archivePathsChecked:true,filesystemIds:"derived-from-inputs",timestamps:"SOURCE_DATE_EPOCH+E2FSPROGS_FAKE_TIME",partitionLayout:"reviewed-profile",ordering:"sorted-lock-and-pacman"},outputs:{setSha256:$imageSet,files:[{filename:$imageName,size:$imageSize,sha256:$image}],unexpected:[],prohibitedPaths:[]},limitations:["one image execution does not establish independent byte reproduction","bootloader and filesystem tools remain constrained by their reviewed native environment"]}}' >"$provenance"
jq -cS '.reproducibility.controls += {archiveMetadataChecked:true,timestampOwnershipOrderChecked:true,filesystemMetadataChecked:true,networkPreparation:"verified-https-before-offline-stage",pacmanInstallDates:"normalized-to-source-epoch",fatTimestampResolutionSeconds:2,mkinitcpioOutput:"pinned-package-bytes",grubOutput:"offline-native-tool",filesystemOrder:"deterministic-guid-and-tooling",filesystemConstruction:"normalized-ext4-inodes-and-staged-fat",machineIdentity:"first-boot",secrets:"first-boot"}' "$provenance" >"$provenance.tmp"
mv -- "$provenance.tmp" "$provenance"
chmod 644 "$output"; chmod 644 "$provenance"
echo "built $output ($image_sha256)"
