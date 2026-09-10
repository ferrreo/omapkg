#!/usr/bin/env bash
set -euo pipefail

# Trusted operator builder for private OCI candidates. Worker runs this file
# inside a pinned, network-disabled builder container; candidate inputs remain
# data and never supply shell fragments or a builder command.

candidate_lock=
candidate_lock_signature=
candidate_id=
native_plan=
native_plan_signature=
coordinator_binding=
trusted_key=
trusted_fingerprint=
profile=
context_archive=
dockerfile=
output=
provenance=
work_dir=
image_ref=

die() { printf 'private OCI image: %s\n' "$*" >&2; exit 2; }
while (($#)); do
  case "$1" in
    --candidate-lock) candidate_lock=${2:-}; shift ;;
    --candidate-lock-signature) candidate_lock_signature=${2:-}; shift ;;
    --candidate-id) candidate_id=${2:-}; shift ;;
    --native-plan) native_plan=${2:-}; shift ;;
    --native-plan-signature) native_plan_signature=${2:-}; shift ;;
    --coordinator-binding) coordinator_binding=${2:-}; shift ;;
    --key) trusted_key=${2:-}; shift ;;
    --fingerprint) trusted_fingerprint=${2:-}; shift ;;
    --profile) profile=${2:-}; shift ;;
    --context) context_archive=${2:-}; shift ;;
    --dockerfile) dockerfile=${2:-}; shift ;;
    --output) output=${2:-}; shift ;;
    --provenance) provenance=${2:-}; shift ;;
    --work-dir) work_dir=${2:-}; shift ;;
    --image-ref) image_ref=${2:-}; shift ;;
    -h|--help) printf '%s\n' 'build-oci-image.sh --candidate-lock FILE --candidate-lock-signature FILE --candidate-id ID --native-plan FILE --native-plan-signature FILE --key FILE --fingerprint HEX --profile FILE --context FILE --dockerfile FILE --output FILE --provenance FILE --work-dir DIR'; exit 0 ;;
    *) die "unknown option: $1" ;;
  esac
  shift
done

for required in "$candidate_lock" "$native_plan" "$trusted_key" "$profile" "$context_archive"; do
  [[ -f "$required" && ! -L "$required" ]] || die "input is not a regular file: $required"
done
[[ -n "$candidate_id" && -n "$output" && -n "$provenance" && -n "$work_dir" && -n "$image_ref" ]] || die 'required output identity is missing'
[[ "$trusted_fingerprint" =~ ^[A-Fa-f0-9]{40}$ ]] || die 'authority fingerprint is invalid'
command -v jq >/dev/null || die 'missing jq'
command -v gpg >/dev/null || die 'missing gpg'
command -v buildah >/dev/null || die 'missing buildah'
command -v tar >/dev/null || die 'missing tar'
command -v sha256sum >/dev/null || die 'missing sha256sum'

canonical_sha() { jq -e -s 'length == 1 and (.[0] | type == "object")' "$1" >/dev/null || die "invalid JSON object: $1"; jq -cS . "$1" | tr -d '\n' | sha256sum | awk '{print $1}'; }
sha256_value() { sha256sum "$1" | awk '{print $1}'; }
safe_file() { [[ -f "$1" && ! -L "$1" ]] || die "expected regular file: $1"; }

verify_signature() {
  local payload=$1 signature=$2 home status
  home=$(mktemp -d "$work_dir/gpg.XXXXXX"); chmod 700 "$home"
  gpg --batch --no-tty --homedir "$home" --import "$trusted_key" >/dev/null 2>&1 || die 'cannot import authority key'
  status=$(gpg --batch --no-tty --status-fd=1 --homedir "$home" --verify "$signature" "$payload" 2>/dev/null || true)
  grep -Eq "^\[GNUPG:\] VALIDSIG ${trusted_fingerprint^^}( |$)" <<<"$status" || die 'authority signature is invalid'
  rm -rf -- "$home"
}

profile_sha=$(canonical_sha "$profile")
lock_sha=$(canonical_sha "$candidate_lock")
plan_sha=$(canonical_sha "$native_plan")
if [[ -n "$coordinator_binding" ]]; then safe_file "$coordinator_binding"; else safe_file "$candidate_lock_signature"; safe_file "$native_plan_signature"; verify_signature "$candidate_lock" "$candidate_lock_signature"; verify_signature "$native_plan" "$native_plan_signature"; fi
jq -e --arg id "$candidate_id" --arg arch "$(jq -er '.architecture' "$profile")" --arg plan "$plan_sha" \
  '.schemaVersion == 1 and .authority == "factory-candidate-v1" and .candidate.executionScope == "private" and .candidate.id == $id and .candidate.nativePlanSha256 == $plan and (.candidate.inputLockSha256 | type == "string")' "$candidate_lock" >/dev/null || die 'candidate lock is not a reviewed private lock'
jq -e --arg id "$candidate_id" --arg arch "$(jq -er '.architecture' "$profile")" --arg profile "$profile_sha" \
  '.schemaVersion == 1 and .kind == "factory-image-construction-proof" and .status == "reviewed" and .candidateId == $id and .architecture == $arch and .profileSha256 == $profile and (.runPolicySha256 | type == "string") and (.inputLockSha256 | type == "string")' "$native_plan" >/dev/null || die 'construction proof is not bound to candidate and profile'
if [[ -n "$coordinator_binding" ]]; then jq -e --arg id "$candidate_id" --arg arch "$(jq -er '.architecture' "$profile")" --arg lock "$lock_sha" --arg proof "$plan_sha" --arg profile "$profile_sha" '.schemaVersion == 1 and .kind == "factory-image-coordinator-binding" and .candidateId == $id and .architecture == $arch and .candidateLockSha256 == $lock and .constructionProofSha256 == $proof and .profileSha256 == $profile and (.policySha256 | test("^[a-f0-9]{64}$")) and (.inputSha256 | test("^[a-f0-9]{64}$"))' "$coordinator_binding" >/dev/null || die 'coordinator construction binding is invalid'; fi
jq -e '.schemaVersion == 1 and (.format == "oci" or .kind == "oci")' "$profile" >/dev/null || die 'profile is not an OCI image profile'

mkdir -p -- "$work_dir"
context_dir=$(mktemp -d "$work_dir/context.XXXXXX")
trap 'rm -rf -- "$context_dir" "$work_dir/gpg."*' EXIT INT TERM
while IFS= read -r entry; do
  [[ -z "$entry" || "$entry" != /* ]] || die 'OCI context contains an absolute path'
  [[ "$entry" != *'../'* && "$entry" != ../* && "$entry" != '..' ]] || die 'OCI context contains a traversal path'
done < <(tar -tf "$context_archive")
tar -xf "$context_archive" --no-same-owner --no-same-permissions -C "$context_dir"
[[ "$dockerfile" = /* ]] || die 'Dockerfile must be an absolute verified input path'
safe_file "$dockerfile"
profile_arch=$(jq -er '.architecture | select(. == "x86_64" or . == "aarch64")' "$profile") || die 'profile architecture is invalid'
case "$profile_arch" in
  x86_64) expected_image_arch=amd64 ;;
  aarch64) expected_image_arch=arm64 ;;
esac
source_date_epoch=$(jq -er '.sourceDateEpoch | numbers | select(. > 0)' "$profile") || die 'profile sourceDateEpoch is invalid'
image_tag="localhost/omapkg-${candidate_id}"
build_args=(buildah --root /tmp/containers/storage --runroot /tmp/containers/runroot bud --pull=false --timestamp "$source_date_epoch" --file "$dockerfile" --tag "$image_tag" "$context_dir")
[[ "${BUILDAH_ISOLATION:-}" == chroot ]] || build_args=(buildah --root /tmp/containers/storage --runroot /tmp/containers/runroot bud --network=none "${build_args[@]:6}")
"${build_args[@]}"
raw_output="$work_dir/output.raw.oci"
buildah --root /tmp/containers/storage --runroot /tmp/containers/runroot push "$image_tag" "oci-archive:$raw_output"
oci_dir="$work_dir/oci-archive"
mkdir -p -- "$oci_dir"
tar -xf "$raw_output" --no-same-owner --no-same-permissions -C "$oci_dir"
tar -C "$oci_dir" --sort=name --mtime="@$source_date_epoch" --owner=0 --group=0 --numeric-owner -cf "$output" blobs index.json oci-layout
command -v skopeo >/dev/null || die 'missing skopeo'
raw_manifest=$(skopeo inspect --raw "oci-archive:$output") || die 'cannot inspect exported OCI manifest'
image_digest=$(tar -xOf "$output" index.json | jq -er '.manifests as $manifests | if ($manifests | length) == 1 then $manifests[0].digest else empty end | strings | select(test("^sha256:[a-f0-9]{64}$"))') || die 'exported OCI index has no valid manifest digest'
manifest_json=$(tar -xOf "$output" "blobs/sha256/${image_digest#sha256:}") || die 'exported OCI manifest blob is missing'
[[ "sha256:$(printf '%s' "$manifest_json" | sha256sum | awk '{print $1}')" == "$image_digest" ]] || die 'exported OCI manifest checksum differs from index'
[[ "sha256:$(printf '%s' "$raw_manifest" | sha256sum | awk '{print $1}')" == "$image_digest" ]] || die 'skopeo manifest differs from exported OCI index'
config_digest=$(jq -er '.config.digest | strings | select(test("^sha256:[a-f0-9]{64}$"))' <<<"$manifest_json") || die 'exported OCI manifest has no valid config digest'
config_blob=$(tar -xOf "$output" "blobs/sha256/${config_digest#sha256:}") || die 'exported OCI config blob is missing'
jq -e --arg arch "$expected_image_arch" '.os == "linux" and .architecture == $arch' <<<"$config_blob" >/dev/null || die 'exported OCI config platform differs from reviewed profile'
[[ "$image_digest" =~ ^sha256:[a-f0-9]{64}$ ]] || die 'builder did not return an OCI image digest'
actual_image_ref="${image_ref%@*}@$image_digest"
image_sha=$(sha256_value "$output")
image_size=$(stat -c '%s' "$output")
mkdir -p -- "$(dirname -- "$provenance")"
jq -cS -n --arg profile "$profile_sha" --arg lock "$lock_sha" --arg plan "$plan_sha" --arg id "$candidate_id" --arg arch "$(jq -er '.architecture' "$profile")" --arg image "$image_sha" --argjson size "$image_size" --argjson epoch "$source_date_epoch" \
  --arg imageRef "$actual_image_ref" '{schemaVersion:1,kind:"factory-image-oci",candidateId:$id,architecture:$arch,profileSha256:$profile,candidateLockSha256:$lock,nativePlanSha256:$plan,imageSha256:$image,imageSize:$size,imageRef:$imageRef,sourceDateEpoch:$epoch,network:"disabled",runtime:"oci-archive",reproducibility:{status:"reproducibility-contract-verified",mode:"single-build"}}' >"$provenance"
