#!/usr/bin/env bash
set -euo pipefail

root=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
command -v jq >/dev/null
for profile in "$root"/system-images/profiles/*.json; do
  jq -e '.schemaVersion == 1 and (.architecture == "x86_64" or .architecture == "aarch64") and .platform == "uefi" and .requiresNative == true and .requiresKvm == true and .emulationAllowed == false' "$profile" >/dev/null
done
bash -n "$root/scripts/build-system-image.sh" "$root/scripts/boot-system-image.sh"
grep -F -- "-Sp --print-format '%f'" "$root/scripts/build-system-image.sh" >/dev/null
grep -F 'selected_packages' "$root/scripts/build-system-image.sh" >/dev/null
grep -F -- '--gpgdir "$gpgdir"' "$root/scripts/build-system-image.sh" >/dev/null
grep -F -- '--disk-guid="$disk_guid"' "$root/scripts/build-system-image.sh" >/dev/null
grep -F -- 'E2FSPROGS_FAKE_TIME' "$root/scripts/build-system-image.sh" >/dev/null
grep -F -- 'factory-candidate-v1' "$root/scripts/build-system-image.sh" >/dev/null
grep -F -- 'verify_reviewed_signature' "$root/scripts/build-system-image.sh" >/dev/null

# Inert builder binding fixture: fake client stands in for the already-tested
# signed client output; no network, pacman, mount, or image build is invoked.
fixture=$(mktemp -d "${TMPDIR:-/tmp}/omapkg-image-contract.XXXXXX")
trap 'rm -rf -- "$fixture"' EXIT
mkdir -p "$fixture/seed"
printf '%s' '{"kind":"system","lane":"system"}' >"$fixture/seed/system.json"
printf '%s' '{"kind":"opr","lane":"opr"}' >"$fixture/seed/opr.json"
printf '%s' '{"kind":"resolved-transaction"}' >"$fixture/seed/transaction.json"
printf '%s' 'database' >"$fixture/seed/repo-core.db"
printf '%s' 'signature' >"$fixture/seed/repo-core.db.sig"
printf '%s' 'signature' >"$fixture/seed/transaction.json.sig"
printf '%s' 'signature' >"$fixture/seed/system.json.sig"
printf '%s' 'signature' >"$fixture/seed/opr.json.sig"
printf '%s' 'trusted key fixture' >"$fixture/trusted-key.asc"
fixture_sha() { sha256sum "$1" | awk '{print $1}'; }
tx_sha=$(fixture_sha "$fixture/seed/transaction.json"); sys_sha=$(fixture_sha "$fixture/seed/system.json"); opr_sha=$(fixture_sha "$fixture/seed/opr.json"); db_sha=$(fixture_sha "$fixture/seed/repo-core.db"); dbsig_sha=$(fixture_sha "$fixture/seed/repo-core.db.sig"); sig_sha=$(fixture_sha "$fixture/seed/transaction.json.sig")
jq -n --arg tx "$tx_sha" --arg sys "$sys_sha" --arg opr "$opr_sha" --arg db "$db_sha" --arg dbsig "$dbsig_sha" --arg sig "$sig_sha" '{schemaVersion:1,authority:"omarchy-manifest-client-v1",transactionSha256:$tx,transaction:{path:"transaction.json",sha256:$tx,signature:"transaction.json.sig",signatureSha256:$sig},systemManifest:{path:"system.json",sha256:$sys,signature:"system.json.sig",signatureSha256:$sig},oprManifest:{path:"opr.json",sha256:$opr,signature:"opr.json.sig",signatureSha256:$sig},repositories:[{name:"core",architecture:"x86_64",path:"repo-core.db",sha256:$db,signature:"repo-core.db.sig",signatureSha256:$dbsig,packageBaseUrl:"https://example/repo"}],packageChunks:[],packages:["base","linux","grub","edk2-ovmf","aurora"]|map({releaseId:"r",name:.,version:"1",architecture:"x86_64",repository:"core",filename:(.+"-1-x86_64.pkg.tar.zst"),url:("https://example/"+.+"-1-x86_64.pkg.tar.zst"),signatureUrl:("https://example/"+.+"-1-x86_64.pkg.tar.zst.sig"),sha256:("a"*64),signatureSha256:("b"*64),install:true}),packageCount:5,sourcePackageCount:5,packageSetSha256:"",architecture:"x86_64",systemVersion:"4.0.3",oprGeneration:"opr-1",sourceDateEpoch:1}' >"$fixture/raw-lock.json"
package_set=$(jq -cS '[.packages[]]|sort_by(.name,.architecture,.version,.sha256)' "$fixture/raw-lock.json" | tr -d '\n' | sha256sum | awk '{print $1}')
jq --arg digest "$package_set" '.packageSetSha256=$digest' "$fixture/raw-lock.json" >"$fixture/seed/release-lock.json"
printf '%s\n' '#!/usr/bin/env bash' 'set -euo pipefail' 'seed='"$fixture/seed" 'for ((index=1; index<=$#; index++)); do' '  if [[ "${!index}" == --output ]]; then next=$((index + 1)); output=${!next}; fi' 'done' 'mkdir -p "$output"' 'cp "$seed"/* "$output/"' >"$fixture/fake-client"
chmod +x "$fixture/fake-client"
"$root/scripts/build-system-image.sh" --check --allow-http --manifest http://example/tx --key "$fixture/trusted-key.asc" --fingerprint "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" --client "$fixture/fake-client" --profile "$root/system-images/profiles/x86_64-uefi.json" | grep -F 'verified image lock:' >/dev/null
printf '%s' '{"kind":"system","lane":"system","tampered":true}' >"$fixture/seed/system.json"
set +e
"$root/scripts/build-system-image.sh" --check --allow-http --manifest http://example/tx --key "$fixture/trusted-key.asc" --fingerprint "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" --client "$fixture/fake-client" --profile "$root/system-images/profiles/x86_64-uefi.json" >"$fixture/failure.out" 2>&1
status=$?
set -e
(( status != 0 ))
grep -F 'system manifest bytes do not match lock' "$fixture/failure.out" >/dev/null
(cd "$root/omarchy/manifest-client" && go test ./...)
echo 'system image contracts passed'
