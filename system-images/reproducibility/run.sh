#!/usr/bin/env bash
set -euo pipefail

repo_root=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
kind=all
gap_seconds=5
output_root=
fetch_output=
boot_profile="$repo_root/system-images/profiles/x86_64-uefi.json"

usage() {
  cat <<'EOF'
usage: system-images/reproducibility/run.sh [--oci|--boot|--all|--filesystem-fixture] [--profile FILE] [--gap SECONDS] [--output DIR]
       system-images/reproducibility/run.sh --fetch-real-packages DIR

The OCI pair uses the pinned scratch fixture. The boot/filesystem pair uses
SYSTEM_IMAGE_REPRO_* inputs; see system-images/reproducibility/README.md.
Exit 0 means every requested pair passed, 1 means a build or byte mismatch,
and 3 means acceptance is incomplete because a native tool or input is absent.
EOF
}

incomplete() { echo "image reproducibility: incomplete: $*" >&2; return 3; }
safe_file() { [[ -f "$1" && ! -L "$1" ]]; }

while (($#)); do
  case $1 in
    --oci) kind=oci ;;
    --boot|--filesystem) kind=boot ;;
    --boot-fixture|--filesystem-fixture) kind=filesystem-fixture ;;
    --fetch-real-packages) kind=fetch-real; fetch_output=${2:-}; shift ;;
    --all) kind=all ;;
    --gap) gap_seconds=${2:-}; shift ;;
    --output) output_root=${2:-}; shift ;;
    --profile) boot_profile=${2:-}; shift ;;
    --help|-h) usage; exit 0 ;;
    *) usage >&2; echo "image reproducibility: unknown option: $1" >&2; exit 2 ;;
  esac
  shift
done
[[ "$gap_seconds" =~ ^[1-9][0-9]*$ ]] || { echo 'image reproducibility: --gap must be a positive integer' >&2; exit 2; }
if [[ "$boot_profile" != /* ]]; then boot_profile="$repo_root/$boot_profile"; fi

if [[ -z "$output_root" ]]; then
  output_root=$(mktemp -d "${TMPDIR:-/tmp}/omapkg-image-repro.XXXXXX")
else
  mkdir -p -- "$output_root"
fi
chmod 700 "$output_root"
echo "image reproducibility outputs: $output_root"

run_worker_test() {
  local test_kind=$1 profile=$2
  (
    cd "$repo_root/worker"
    OPR_IMAGE_REPRO_ACCEPTANCE=1 \
    OPR_IMAGE_REPRO_KIND="$test_kind" \
    OPR_IMAGE_REPRO_GAP="$gap_seconds" \
    OPR_IMAGE_REPRO_REPO_ROOT="$repo_root" \
    OPR_IMAGE_REPRO_PROFILE="$profile" \
    OPR_IMAGE_REPRO_OUTPUT="$output_root" \
    go test . -run '^TestImageReproducibilityAcceptance$' -count=1 -timeout=90m -v
  )
}

oci_prerequisites() {
  for command_name in go buildah jq sha256sum cmp; do
    command -v "$command_name" >/dev/null 2>&1 || { incomplete "missing $command_name"; return 3; }
  done
  [[ "$(uname -m)" == x86_64 ]] || { incomplete "OCI fixture requires native x86_64 execution; host is $(uname -m)"; return 3; }
  safe_file "$repo_root/system-images/reproducibility/oci-profile.json" || { incomplete 'missing pinned OCI profile'; return 3; }
  safe_file "$repo_root/system-images/reproducibility/oci/Dockerfile" || { incomplete 'missing OCI Dockerfile fixture'; return 3; }
  safe_file "$repo_root/system-images/reproducibility/oci/payload.txt" || { incomplete 'missing OCI payload fixture'; return 3; }
  jq -e '.schemaVersion == 1 and .architecture == "x86_64" and .format == "oci" and .base == "scratch" and .network == "none" and .builder == "buildah" and (.builderVersion | type == "string" and length > 0) and (.dockerfileSha256 | test("^[a-f0-9]{64}$")) and (.payloadSha256 | test("^[a-f0-9]{64}$")) and (.sourceDateEpoch | numbers | . > 0)' "$repo_root/system-images/reproducibility/oci-profile.json" >/dev/null || { incomplete 'pinned OCI profile failed validation'; return 3; }
  [[ "$(sha256sum "$repo_root/system-images/reproducibility/oci/Dockerfile" | awk '{print $1}')" == "$(jq -er '.dockerfileSha256' "$repo_root/system-images/reproducibility/oci-profile.json")" ]] || { incomplete 'pinned OCI Dockerfile digest changed'; return 3; }
  [[ "$(sha256sum "$repo_root/system-images/reproducibility/oci/payload.txt" | awk '{print $1}')" == "$(jq -er '.payloadSha256' "$repo_root/system-images/reproducibility/oci-profile.json")" ]] || { incomplete 'pinned OCI payload digest changed'; return 3; }
}

boot_prerequisites() {
  local missing=()
  local host_arch profile_arch
  host_arch=$(case "$(uname -m)" in x86_64) echo x86_64 ;; aarch64|arm64) echo aarch64 ;; *) echo unknown ;; esac)
  profile_arch=$(jq -er '.architecture' "$boot_profile" 2>/dev/null || true)
  for command_name in go jq sha256sum curl qemu-img sgdisk losetup udevadm mkfs.fat mkfs.ext4 mount umount blkid pacman grub-install arch-chroot gpg realpath bsdtar; do
    command -v "$command_name" >/dev/null 2>&1 || missing+=("$command_name")
  done
  safe_file "$boot_profile" || missing+=("profile=$boot_profile")
  [[ "$EUID" -eq 0 ]] || missing+=("root")
  if [[ "$EUID" -eq 0 ]] && ! losetup -f >/dev/null 2>&1; then missing+=(usable-loop-device); fi
  [[ "$host_arch" == "$profile_arch" ]] || missing+=(native-profile-architecture)
  if [[ -n "${SYSTEM_IMAGE_REPRO_CANDIDATE_LOCK:-}" || -n "${SYSTEM_IMAGE_REPRO_CANDIDATE_ID:-}" || -n "${SYSTEM_IMAGE_REPRO_NATIVE_PLAN:-}" ]]; then
    safe_file "${SYSTEM_IMAGE_REPRO_CANDIDATE_LOCK:-}" || missing+=(SYSTEM_IMAGE_REPRO_CANDIDATE_LOCK)
    safe_file "${SYSTEM_IMAGE_REPRO_CANDIDATE_LOCK_SIGNATURE:-}" || missing+=(SYSTEM_IMAGE_REPRO_CANDIDATE_LOCK_SIGNATURE)
    [[ -n "${SYSTEM_IMAGE_REPRO_CANDIDATE_ID:-}" ]] || missing+=(SYSTEM_IMAGE_REPRO_CANDIDATE_ID)
    safe_file "${SYSTEM_IMAGE_REPRO_NATIVE_PLAN:-}" || missing+=(SYSTEM_IMAGE_REPRO_NATIVE_PLAN)
    safe_file "${SYSTEM_IMAGE_REPRO_NATIVE_PLAN_SIGNATURE:-}" || missing+=(SYSTEM_IMAGE_REPRO_NATIVE_PLAN_SIGNATURE)
  else
    [[ -n "${SYSTEM_IMAGE_REPRO_MANIFEST:-}" ]] || missing+=(SYSTEM_IMAGE_REPRO_MANIFEST)
  fi
  safe_file "${SYSTEM_IMAGE_REPRO_KEY:-}" || missing+=(SYSTEM_IMAGE_REPRO_KEY)
  [[ "${SYSTEM_IMAGE_REPRO_FINGERPRINT:-}" =~ ^[A-Fa-f0-9]{40}$ ]] || missing+=(SYSTEM_IMAGE_REPRO_FINGERPRINT)
  if ((${#missing[@]})); then
    incomplete "boot/filesystem image prerequisites: ${missing[*]}"
    return 3
  fi
}

filesystem_fixture_acceptance() {
  local runtime=${SYSTEM_IMAGE_REPRO_CONTAINER_RUNTIME:-docker}
  local builder_image=${SYSTEM_IMAGE_REPRO_BOOT_BUILDER_IMAGE:-}
  local real_package_dir=${SYSTEM_IMAGE_REPRO_REAL_PACKAGE_DIR:-}
  local profile_arch expected_arch container_arch
  command -v "$runtime" >/dev/null 2>&1 || { incomplete "missing container runtime: $runtime"; return 3; }
  command -v go >/dev/null 2>&1 || { incomplete 'missing go for the worker acceptance adapter'; return 3; }
  [[ "$builder_image" =~ @sha256:[a-f0-9]{64}$ ]] || { incomplete 'SYSTEM_IMAGE_REPRO_BOOT_BUILDER_IMAGE must be digest-pinned'; return 3; }
  safe_file "$boot_profile" || { incomplete "profile is not a regular file: $boot_profile"; return 3; }
  profile_arch=$(jq -er '.architecture' "$boot_profile" 2>/dev/null || true)
  expected_arch=$(jq -er '.qualification.nativeHost' "$boot_profile" 2>/dev/null || true)
  [[ "$profile_arch" == x86_64 || "$profile_arch" == aarch64 ]] || { incomplete 'profile architecture is unsupported'; return 3; }
  container_arch=$("$runtime" run --rm --network none "$builder_image" uname -m 2>/dev/null || true)
  [[ "$container_arch" == x86_64 && "$expected_arch" == x86_64 || ( "$container_arch" == aarch64 || "$container_arch" == arm64 ) && "$expected_arch" == aarch64 ]] || { incomplete "builder image architecture does not match profile: $container_arch vs $expected_arch"; return 3; }
  "$runtime" run --rm --privileged --network none "$builder_image" losetup -f >/dev/null 2>&1 || { incomplete 'builder container has no usable native loop device'; return 3; }
  "$runtime" run --rm --network none "$builder_image" bash -lc 'command -v buildah && command -v mcopy && command -v debugfs && command -v tune2fs && command -v e2fsck && command -v unshare && command -v qemu-img && command -v sgdisk && command -v partx && command -v mkfs.fat' >/dev/null 2>&1 || { incomplete 'digest-pinned builder image lacks a required image/filesystem tool'; return 3; }
  local binary="$output_root/image-repro.test"
  (cd "$repo_root/worker" && go test -c -o "$binary" $(find . -maxdepth 1 -name '*.go' ! -name '*_test.go' -printf '%f ' ) image_reproducibility_test.go factory_image_system_e2e_test.go) || return 1
  local fixture_mounts=()
  fixture_mounts+=(-v "$boot_profile:/work/input-profile.json:ro" -e OPR_IMAGE_REPRO_INPUT_PROFILE=/work/input-profile.json -e SYSTEM_IMAGE_REPRO_ARCH="$profile_arch")
  if [[ -n "$real_package_dir" ]]; then
    [[ -d "$real_package_dir" ]] || { incomplete "real package fixture directory is missing: $real_package_dir"; return 3; }
    fixture_mounts+=(-v "$real_package_dir:/work/real-packages:ro" -e SYSTEM_IMAGE_REPRO_REAL_PACKAGE_DIR=/work/real-packages)
  fi
  "$runtime" run --rm --privileged --network none \
    -v "$repo_root:/repo:ro" -v "$output_root:/work/results:rw" -v "$binary:/work/image-repro.test:ro" \
    -e OPR_IMAGE_REPRO_GAP="$gap_seconds" \
    "${fixture_mounts[@]}" "$builder_image" /repo/system-images/reproducibility/boot-fixture.sh /work/image-repro.test
}

fetch_real_packages() {
  local runtime=${SYSTEM_IMAGE_REPRO_CONTAINER_RUNTIME:-docker}
  local builder_image=${SYSTEM_IMAGE_REPRO_BOOT_BUILDER_IMAGE:-}
  [[ -n "$fetch_output" ]] || { echo 'image reproducibility: --fetch-real-packages needs DIR' >&2; return 2; }
  command -v "$runtime" >/dev/null 2>&1 || { incomplete "missing container runtime: $runtime"; return 3; }
  [[ "$builder_image" =~ @sha256:[a-f0-9]{64}$ ]] || { incomplete 'SYSTEM_IMAGE_REPRO_BOOT_BUILDER_IMAGE must be digest-pinned'; return 3; }
  mkdir -p -- "$fetch_output"
  local profile_arch
  profile_arch=$(jq -er '.architecture' "$boot_profile" 2>/dev/null || true)
  "$runtime" run --rm --network bridge -v "$repo_root:/repo:ro" -v "$boot_profile:/work/profile.json:ro" -v "$fetch_output:/out:rw" -e SYSTEM_IMAGE_REPRO_PROFILE=/work/profile.json -e SYSTEM_IMAGE_REPRO_ARCH="$profile_arch" -e SYSTEM_IMAGE_REPRO_ARCH_MIRROR="${SYSTEM_IMAGE_REPRO_ARCH_MIRROR:-}" "$builder_image" /repo/system-images/reproducibility/fetch-real-packages.sh /out
}

oci_status=0
boot_status=0
if [[ "$kind" == oci || "$kind" == all ]]; then
  if oci_prerequisites; then run_worker_test oci "$repo_root/system-images/reproducibility/oci-profile.json" || oci_status=$?; else oci_status=$?; fi
fi
if [[ "$kind" == filesystem-fixture ]]; then
  filesystem_fixture_acceptance || exit $?
  exit 0
fi
if [[ "$kind" == fetch-real ]]; then
  fetch_real_packages || exit $?
  exit 0
fi
if [[ "$kind" == boot || "$kind" == all ]]; then
  if boot_prerequisites; then run_worker_test boot "$boot_profile" || boot_status=$?; else boot_status=$?; fi
fi
if [[ "$oci_status" -eq 1 || "$boot_status" -eq 1 ]]; then exit 1; fi
if [[ "$oci_status" -eq 3 || "$boot_status" -eq 3 ]]; then exit 3; fi
exit 0
