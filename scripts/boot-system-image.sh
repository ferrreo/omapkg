#!/usr/bin/env bash
set -euo pipefail

profile=
image=
provenance=
evidence=
timeout_seconds=60

die() { echo "system image boot: $*" >&2; exit 2; }
while (($#)); do
  case $1 in
    --profile) profile=${2:-}; shift ;;
    --image) image=${2:-}; shift ;;
    --provenance) provenance=${2:-}; shift ;;
    --evidence) evidence=${2:-}; shift ;;
    --timeout) timeout_seconds=${2:-}; shift ;;
    -h|--help) echo 'usage: boot-system-image.sh --profile FILE --image FILE --provenance FILE --evidence FILE [--timeout SECONDS]'; exit 0 ;;
    *) die "unknown option: $1" ;;
  esac
  shift
done
[[ -f "$profile" && ! -L "$profile" && -f "$image" && ! -L "$image" && -f "$provenance" && ! -L "$provenance" ]] || die "profile, image and provenance must be regular files"
[[ -n "$evidence" && ! -e "$evidence" && ! -L "$evidence" ]] || die "evidence output exists or is missing"
[[ "$timeout_seconds" =~ ^[1-9][0-9]{0,2}$ && "$timeout_seconds" -le 300 ]] || die "timeout must be 1..300 seconds"
command -v jq >/dev/null || die "missing jq"
command -v sha256sum >/dev/null || die "missing sha256sum"
command -v timeout >/dev/null || die "missing timeout"
command -v realpath >/dev/null || die "missing realpath"
canonical_sha() { jq -e -s 'length == 1 and (.[0] | type == "object")' "$1" >/dev/null || die "invalid JSON object: $1"; jq -cS . "$1" | tr -d '\n' | sha256sum | awk '{print $1}'; }
sha256_value() { sha256sum "$1" | awk '{print $1}'; }
architecture=$(jq -er '.architecture' "$profile")
jq -e --arg arch "$architecture" '.schemaVersion == 1 and .platform == "uefi" and .requiresNative == true and .requiresKvm == true and .emulationAllowed == false and .architecture == $arch' "$profile" >/dev/null || die "profile is not a native UEFI profile"
[[ "$(canonical_sha "$profile")" == "$(jq -er '.profileSha256' "$provenance")" ]] || die "profile digest is not bound by provenance"
[[ "$(sha256_value "$image")" == "$(jq -er '.imageSha256' "$provenance")" ]] || die "image digest is not bound by provenance"
[[ "$(jq -er '.architecture' "$provenance")" == "$architecture" && "$(jq -er '.nativeArchitecture' "$provenance")" == "$architecture" ]] || die "provenance architecture does not match profile"
native=$(uname -m)
case "$native" in x86_64) [[ "$architecture" == x86_64 ]] || die "x86_64 host cannot claim aarch64 qualification" ;; aarch64|arm64) [[ "$architecture" == aarch64 ]] || die "aarch64 host cannot claim x86_64 qualification" ;; *) die "unsupported native host architecture: $native" ;; esac
[[ -c /dev/kvm ]] || die "native KVM device /dev/kvm is unavailable"
qemu_binary=$(jq -er '.qualification.qemuBinary' "$profile")
command -v "$qemu_binary" >/dev/null || die "matching native QEMU binary is unavailable: $qemu_binary"
firmware_code=$(realpath -e -- "$(jq -er '.firmware.codePath' "$profile")") || die "UEFI firmware code is unavailable"
firmware_vars=$(realpath -e -- "$(jq -er '.firmware.varsTemplatePath' "$profile")") || die "UEFI variable template is unavailable"
[[ -f "$firmware_code" && -f "$firmware_vars" ]] || die "UEFI firmware code and clean variable template are required"
[[ "$(sha256_value "$firmware_code")" == "$(jq -er '.firmware.codeSha256' "$provenance")" ]] || die "UEFI code changed after image build"
[[ "$(sha256_value "$firmware_vars")" == "$(jq -er '.firmware.varsTemplateSha256' "$provenance")" ]] || die "UEFI variable template changed after image build"
work=$(mktemp -d "${TMPDIR:-/tmp}/omapkg-uefi-boot.XXXXXX")
cleanup() { rm -rf -- "$work"; }
trap cleanup EXIT INT TERM
chmod 700 "$work"
disk="$work/image.raw"; vars="$work/vars.fd"; log="$work/serial.log"
cp --reflink=auto -- "$image" "$disk"
cp --reflink=auto -- "$firmware_vars" "$vars"
chmod 600 "$vars"
machine=$(jq -er '.qualification.machine' "$profile")
marker=$(jq -er '.boot.serialMarker' "$profile")
root_args=(-accel kvm -machine "$machine" -m 2048 -nodefaults -nographic -no-reboot -drive "if=pflash,format=raw,readonly=on,file=$firmware_code" -drive "if=pflash,format=raw,file=$vars" -drive "if=virtio,format=raw,file=$disk" -serial "file:$log")
set +e
timeout --foreground "$timeout_seconds" "$qemu_binary" "${root_args[@]}"
qemu_status=$?
set -e
[[ "$qemu_status" == 0 || "$qemu_status" == 124 ]] || die "native KVM boot exited with status $qemu_status"
grep -Fq -- "$marker" "$log" || die "native KVM boot did not reach serial marker: $marker"
image_sha=$(sha256_value "$image")
log_sha=$(sha256_value "$log")
provenance_sha=$(canonical_sha "$provenance")
mkdir -p -- "$(dirname -- "$evidence")"
jq -cS -n --arg profile "$(jq -er '.profileSha256' "$provenance")" --arg provenance "$provenance_sha" --arg image "$image_sha" --arg arch "$architecture" --arg native "$native" --arg qemu "$qemu_binary" --arg marker "$marker" --arg log "$log_sha" --argjson kvm true --argjson cleanVars true '{schemaVersion:1,operation:"boot",profileSha256:$profile,provenanceSha256:$provenance,imageSha256:$image,architecture:$arch,nativeArchitecture:$native,qemuBinary:$qemu,kvm:$kvm,cleanVars:$cleanVars,serialMarker:$marker,serialLogSha256:$log}' >"$evidence"
chmod 644 "$evidence"
echo "native UEFI boot passed: $evidence"
