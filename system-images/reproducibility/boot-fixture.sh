#!/usr/bin/env bash
set -euo pipefail

test_binary=$1
fixture=/work/fixture
results=/work/results/filesystem-fixture
epoch=1700000000
real_package_dir=${SYSTEM_IMAGE_REPRO_REAL_PACKAGE_DIR:-}
input_profile=${OPR_IMAGE_REPRO_INPUT_PROFILE:-}
mkdir -p "$fixture/bin" "$fixture/packages" "$results"
chmod 700 "$fixture" "$results"
command -v losetup >/dev/null 2>&1 || { echo 'incomplete: missing losetup' >&2; exit 3; }
losetup -f >/dev/null 2>&1 || { echo 'incomplete: no usable native loop device' >&2; exit 3; }

gpg_home=$fixture/gnupg
mkdir -p "$gpg_home"
chmod 700 "$gpg_home"
gpg --batch --no-tty --pinentry-mode loopback --passphrase '' --homedir "$gpg_home" --quick-generate-key 'omapkg image fixture <image-fixture@example.invalid>' rsa2048 sign 1d >/dev/null 2>&1
fingerprint=$(gpg --batch --no-tty --homedir "$gpg_home" --with-colons --list-secret-keys | awk -F: '$1 == "fpr" { print $10; exit }')
[[ "$fingerprint" =~ ^[A-F0-9]{40}$ ]] || { echo 'fixture key generation failed' >&2; exit 1; }
gpg --batch --no-tty --homedir "$gpg_home" --armor --export "$fingerprint" >"$fixture/release-key.asc"

profile=$fixture/profile.json
if [[ -n "$input_profile" ]]; then
  [[ -f "$input_profile" && ! -L "$input_profile" ]] || { echo "incomplete: profile is not a regular file: $input_profile" >&2; exit 3; }
  cp -- "$input_profile" "$profile"
else
  jq -cS -n '{schemaVersion:1,id:"x86_64-uefi-fixture-v1",architecture:"x86_64",nativeGoarch:"amd64",platform:"uefi",requiresNative:true,requiresKvm:true,emulationAllowed:false,disk:{sizeBytes:2147483648,espSizeMiB:64,filesystem:"ext4"},kernel:{package:"linux",path:"/boot/vmlinuz-linux",initramfs:["/boot/initramfs-linux.img"]},bootloader:{package:"grub",target:"x86_64-efi",efiBinary:"EFI/BOOT/BOOTX64.EFI"},firmware:{package:"edk2-ovmf",codePath:"/usr/share/edk2/x64/OVMF_CODE.fd",varsTemplatePath:"/usr/share/edk2/x64/OVMF_VARS.fd"},basePackages:["base","linux","grub"],installPackages:["base","linux","grub"],boot:{kernelArguments:"root=UUID={rootUuid} rw console=ttyS0",serialMarker:"login:"},qualification:{qemuBinary:"qemu-system-x86_64",machine:"q35",nativeHost:"x86_64",kvmDevice:"/dev/kvm",cleanVarsRequired:true}}' >"$profile"
fi
architecture=$(jq -er '.architecture' "$profile")
native_host=$(jq -er '.qualification.nativeHost' "$profile")
host_arch=$(case "$(uname -m)" in x86_64) echo x86_64 ;; aarch64|arm64) echo aarch64 ;; *) echo unknown ;; esac)
[[ "$architecture" == "$native_host" && "$host_arch" == "$native_host" ]] || { echo "incomplete: native profile/host mismatch: $architecture/$native_host on $host_arch" >&2; exit 3; }
firmware_package_name=$(jq -er '.firmware.package' "$profile")
firmware_code_path=$(jq -er '.firmware.codePath' "$profile")
firmware_vars_path=$(jq -er '.firmware.varsTemplatePath' "$profile")
mkdir -p -- "$(dirname -- "$firmware_code_path")" "$(dirname -- "$firmware_vars_path")"
if [[ -z "$real_package_dir" ]]; then
  printf 'fixture firmware code\n' >"$firmware_code_path"
  printf 'fixture firmware vars\n' >"$firmware_vars_path"
fi

make_package() {
  local name=$1 payload=$2 package_root="$fixture/package-$1" package="$fixture/packages/$1-1-1-x86_64.pkg.tar.zst"
  mkdir -p "$package_root"
  printf '%s\n' "pkgname = $name" "pkgbase = $name" 'pkgver = 1-1' 'pkgdesc = reproducibility fixture' 'url = https://example.invalid/fixture' "builddate = $epoch" 'packager = omapkg image fixture' 'size = 1' 'arch = x86_64' 'license = MIT' >"$package_root/.PKGINFO"
  if [[ "$payload" == base ]]; then
    mkdir -p "$package_root/etc"
    printf 'NAME=fixture\n' >"$package_root/etc/os-release"
  elif [[ "$payload" == linux ]]; then
    mkdir -p "$package_root/boot"
    printf 'fixture kernel\n' >"$package_root/boot/vmlinuz-linux"
    printf 'fixture initramfs\n' >"$package_root/boot/initramfs-linux.img"
  elif [[ "$payload" == firmware ]]; then
    mkdir -p "$package_root/usr/share/edk2/x64"
    cp /usr/share/edk2/x64/OVMF_CODE.fd "$package_root/usr/share/edk2/x64/OVMF_CODE.fd"
    cp /usr/share/edk2/x64/OVMF_VARS.fd "$package_root/usr/share/edk2/x64/OVMF_VARS.fd"
  fi
  (cd "$package_root" && bsdtar --format=ustar --mtime "@$epoch" -cf - $(find . -mindepth 1 -printf '%P\n' | LC_ALL=C sort)) | zstd -T0 -q -o "$package"
  gpg --batch --no-tty --yes --homedir "$gpg_home" --detach-sign --local-user "$fingerprint" "$package"
  printf '%s\n' "$package"
}

if [[ -n "$real_package_dir" ]]; then
  mkdir -p "$fixture/signatures"
  for source_package in "$real_package_dir"/*.pkg.tar.zst; do
    filename=$(basename "$source_package")
    ln -s "$source_package" "$fixture/packages/$filename"
    gpg --batch --no-tty --yes --homedir "$gpg_home" --detach-sign --local-user "$fingerprint" --output "$fixture/signatures/$filename.sig" "$source_package"
    ln -s "$fixture/signatures/$filename.sig" "$fixture/packages/$filename.sig"
  done
  firmware_package=$(find "$fixture/packages" -maxdepth 1 \( -type f -o -type l \) -name "$firmware_package_name-*.pkg.tar.zst" | head -n1)
  [[ -n "$firmware_package" ]] || { echo "incomplete: real package fixture has no $firmware_package_name archive" >&2; exit 3; }
  bsdtar -xOf "$firmware_package" "${firmware_code_path#/}" >"$firmware_code_path"
  bsdtar -xOf "$firmware_package" "${firmware_vars_path#/}" >"$firmware_vars_path"
else
  [[ "$architecture" == x86_64 ]] || { echo 'incomplete: ARM filesystem fixture requires real package inputs' >&2; exit 3; }
  base_package=$(make_package base base)
  linux_package=$(make_package linux linux)
  grub_package=$(make_package grub grub)
  firmware_package=$(make_package edk2-ovmf firmware)
fi
package_files=("$fixture/packages"/*.pkg.tar.zst)
repo_db="$fixture/packages/fixture.db.tar.gz"
for package in "${package_files[@]}"; do
  gpg --batch --no-tty --yes --homedir "$gpg_home" --detach-sign --local-user "$fingerprint" "$package"
done
GNUPGHOME="$gpg_home" repo-add --sign --key "$fingerprint" "$repo_db" "${package_files[@]}" >/dev/null

cat >"$fixture/system.json" <<'EOF'
{"schemaVersion":1,"kind":"system","lane":"system","identity":{"version":"fixture-system"}}
EOF
cat >"$fixture/opr.json" <<'EOF'
{"schemaVersion":1,"kind":"opr","lane":"opr","identity":{"generation":"fixture-opr"}}
EOF
cat >"$fixture/transaction.json" <<'EOF'
{"schemaVersion":1,"kind":"resolved-transaction","lane":"transaction","identity":{"version":"fixture-system","generation":"fixture-opr"}}
EOF
for document in system opr transaction; do
  gpg --batch --no-tty --yes --homedir "$gpg_home" --detach-sign --local-user "$fingerprint" "$fixture/$document.json"
done

canonical_sha() { jq -cS . "$1" | tr -d '\n' | sha256sum | awk '{print $1}'; }
sha256_file() { sha256sum "$1" | awk '{print $1}'; }
system_sha=$(canonical_sha "$fixture/system.json")
opr_sha=$(canonical_sha "$fixture/opr.json")
transaction_sha=$(canonical_sha "$fixture/transaction.json")
system_sig_sha=$(sha256_file "$fixture/system.json.sig")
opr_sig_sha=$(sha256_file "$fixture/opr.json.sig")
transaction_sig_sha=$(sha256_file "$fixture/transaction.json.sig")
repo_sha=$(sha256_file "$repo_db")
repo_sig_sha=$(sha256_file "$repo_db.sig")

package_rows=$fixture/package-rows.json
: >"$package_rows.ndjson"
for package in "${package_files[@]}"; do
  filename=$(basename "$package")
  pkginfo=$(bsdtar -xOf "$package" .PKGINFO 2>/dev/null || bsdtar -xOf "$package" ./.PKGINFO)
  name=$(awk -F' = ' '$1 == "pkgname" { print $2; exit }' <<<"$pkginfo")
  version=$(awk -F' = ' '$1 == "pkgver" { print $2; exit }' <<<"$pkginfo")
  architecture=$(awk -F' = ' '$1 == "arch" { print $2; exit }' <<<"$pkginfo")
  [[ -n "$name" && -n "$version" && -n "$architecture" ]] || { echo "incomplete: package metadata missing in $filename" >&2; exit 3; }
  jq -c -n --arg name "$name" --arg version "$version" --arg architecture "$architecture" --arg filename "$filename" --arg url "https://localhost:8443/packages/$filename" --arg signatureUrl "https://localhost:8443/packages/$filename.sig" --arg sha256 "$(sha256_file "$package")" --arg signatureSha256 "$(sha256_file "$package.sig")" '{name:$name,version:$version,filename:$filename,url:$url,signatureUrl:$signatureUrl,sha256:$sha256,signatureSha256:$signatureSha256,architecture:$architecture,install:true}' >>"$package_rows.ndjson"
done
jq -s '.' "$package_rows.ndjson" >"$package_rows"
package_set=$(jq -cS 'sort_by(.name,.architecture,.version,.sha256)' "$package_rows" | tr -d '\n' | sha256sum | awk '{print $1}')
input_lock=$(printf 'omapkg-image-fixture-inputs-v1\n' | sha256sum | awk '{print $1}')
owned_universe=$(printf 'omapkg-image-fixture-owned-v1\n' | sha256sum | awk '{print $1}')
plan=$fixture/native-plan.json
jq -cS -n --arg candidateId fixture-candidate --arg architecture "$architecture" --arg owned "$owned_universe" --arg input "$input_lock" '{schemaVersion:1,kind:"factory-image-native-plan",executionScope:"private",candidateId:$candidateId,architecture:$architecture,ownedUniverseSha256:$owned,inputLockSha256:$input,status:"reviewed"}' >"$plan"
plan_sha=$(canonical_sha "$plan")
gpg --batch --no-tty --yes --homedir "$gpg_home" --detach-sign --local-user "$fingerprint" "$plan"

lock=$fixture/candidate-lock.json
jq -cS -n --arg candidateId fixture-candidate --arg architecture "$architecture" --arg owned "$owned_universe" --arg input "$input_lock" --arg plan "$plan_sha" --arg tx "$transaction_sha" --arg txSig "$transaction_sig_sha" --arg system "$system_sha" --arg systemSig "$system_sig_sha" --arg opr "$opr_sha" --arg oprSig "$opr_sig_sha" --arg repoSha "$repo_sha" --arg repoSig "$repo_sig_sha" --arg packageSet "$package_set" --argjson packages "$(cat "$package_rows")" '{schemaVersion:1,authority:"factory-candidate-v1",candidate:{id:$candidateId,executionScope:"private",ownedUniverseSha256:$owned,inputLockSha256:$input,nativePlanSha256:$plan},architecture:$architecture,systemVersion:"fixture-system",oprGeneration:"fixture-opr",sourceDateEpoch:1700000000,transactionSha256:$tx,transaction:{path:"transaction.json",signature:"transaction.json.sig",signatureSha256:$txSig},systemManifestSha256:$system,systemManifest:{path:"system.json",sha256:$system,signature:"system.json.sig",signatureSha256:$systemSig},oprManifestSha256:$opr,oprManifest:{path:"opr.json",sha256:$opr,signature:"opr.json.sig",signatureSha256:$oprSig},packageChunks:[],repositories:[{name:"fixture",path:"packages/fixture.db.tar.gz",signature:"packages/fixture.db.tar.gz.sig",sha256:$repoSha,signatureSha256:$repoSig}],packages:$packages,packageSetSha256:$packageSet,packageCount:($packages|length),sourcePackageCount:($packages|length)}' >"$lock"
gpg --batch --no-tty --yes --homedir "$gpg_home" --detach-sign --local-user "$fingerprint" "$lock"

mkdir -p "$fixture/http" "$fixture/http/packages"
for package in "${package_files[@]}"; do
  filename=$(basename "$package")
  ln -s "$package" "$fixture/http/packages/$filename"
  ln -s "$package.sig" "$fixture/http/packages/$filename.sig"
done
openssl req -x509 -newkey rsa:2048 -nodes -subj /CN=localhost -addext subjectAltName=DNS:localhost -days 1 -keyout "$fixture/tls.key" -out "$fixture/tls.crt" >/dev/null 2>&1
(cd "$fixture/http" && exec openssl s_server -quiet -WWW -accept 8443 -cert "$fixture/tls.crt" -key "$fixture/tls.key") >"$fixture/http.log" 2>&1 &
server_pid=$!
trap 'kill "$server_pid" 2>/dev/null || true' EXIT INT TERM
health_package=$(basename "${package_files[0]}")
for _ in $(seq 1 30); do curl --silent --fail --cacert "$fixture/tls.crt" "https://localhost:8443/packages/$health_package" -o /dev/null && break; sleep 0.2; done

if [[ -z "$real_package_dir" ]]; then
cat >"$fixture/bin/arch-chroot" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
root=$1
mkdir -p "$root/boot/efi/EFI/BOOT"
printf 'fixture grub output\n' >"$root/boot/efi/EFI/BOOT/BOOTX64.EFI"
EOF
chmod +x "$fixture/bin/arch-chroot"
cat >"$fixture/bin/grub-install" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
chmod +x "$fixture/bin/grub-install"
else
  grub_package=$(find "$fixture/packages" -maxdepth 1 \( -type f -o -type l \) -name 'grub-*.pkg.tar.zst' | head -n1)
  [[ -n "$grub_package" ]] || { echo 'incomplete: real package fixture has no grub archive' >&2; exit 3; }
  bsdtar -xOf "$grub_package" usr/bin/grub-install >"$fixture/bin/grub-install"
  chmod +x "$fixture/bin/grub-install"
  command -v arch-chroot >/dev/null 2>&1 || { echo 'incomplete: real builder image has no arch-chroot' >&2; exit 3; }
fi
export SYSTEM_IMAGE_REPRO_CANDIDATE_LOCK="$lock"
export SYSTEM_IMAGE_REPRO_CANDIDATE_LOCK_SIGNATURE="$lock.sig"
export SYSTEM_IMAGE_REPRO_CANDIDATE_ID=fixture-candidate
export SYSTEM_IMAGE_REPRO_NATIVE_PLAN="$plan"
export SYSTEM_IMAGE_REPRO_NATIVE_PLAN_SIGNATURE="$plan.sig"
export SYSTEM_IMAGE_REPRO_KEY="$fixture/release-key.asc"
export SYSTEM_IMAGE_REPRO_FINGERPRINT="$fingerprint"
export OPR_IMAGE_REPRO_ACCEPTANCE=1
export OPR_IMAGE_REPRO_KIND=boot
export OPR_IMAGE_REPRO_REPO_ROOT=/repo
export OPR_IMAGE_REPRO_PROFILE="$profile"
export OPR_IMAGE_REPRO_OUTPUT="$results"
export OPR_IMAGE_REPRO_GAP=${OPR_IMAGE_REPRO_GAP-5}
export CURL_CA_BUNDLE="$fixture/tls.crt"
export PATH="$fixture/bin:$PATH"
mkdir -p "$fixture/home"
exec env -i \
  PATH="$fixture/bin:/usr/bin:/bin" HOME="$fixture/home" LANG=C LC_ALL=C TZ=UTC TMPDIR=/tmp \
  SOURCE_DATE_EPOCH="$epoch" OMAPKG_IMAGE_CLEAN_ENV=1 CURL_CA_BUNDLE="$fixture/tls.crt" \
  SYSTEM_IMAGE_REPRO_CANDIDATE_LOCK="$SYSTEM_IMAGE_REPRO_CANDIDATE_LOCK" \
  SYSTEM_IMAGE_REPRO_CANDIDATE_LOCK_SIGNATURE="$SYSTEM_IMAGE_REPRO_CANDIDATE_LOCK_SIGNATURE" \
  SYSTEM_IMAGE_REPRO_CANDIDATE_ID="$SYSTEM_IMAGE_REPRO_CANDIDATE_ID" \
  SYSTEM_IMAGE_REPRO_NATIVE_PLAN="$SYSTEM_IMAGE_REPRO_NATIVE_PLAN" \
  SYSTEM_IMAGE_REPRO_NATIVE_PLAN_SIGNATURE="$SYSTEM_IMAGE_REPRO_NATIVE_PLAN_SIGNATURE" \
  SYSTEM_IMAGE_REPRO_KEY="$SYSTEM_IMAGE_REPRO_KEY" SYSTEM_IMAGE_REPRO_FINGERPRINT="$SYSTEM_IMAGE_REPRO_FINGERPRINT" \
  OPR_IMAGE_REPRO_ACCEPTANCE=1 OPR_IMAGE_REPRO_KIND=boot OPR_IMAGE_REPRO_REPO_ROOT=/repo \
  OPR_IMAGE_REPRO_PROFILE="$profile" OPR_IMAGE_REPRO_OUTPUT="$results" OPR_IMAGE_REPRO_GAP="${OPR_IMAGE_REPRO_GAP-5}" \
  "$test_binary" -test.run '^TestImageReproducibilityAcceptance$' -test.count=1 -test.v
