#!/usr/bin/env bash
set -euo pipefail

manifest_url=${1:?usage: omapkg-rollback https://packages.example.org/repo/rollback/RELEASE_ID.json}
case "$manifest_url" in https://*) ;; *) echo 'rollback manifest URL must use HTTPS' >&2; exit 2 ;; esac
command -v jq >/dev/null || { echo 'rollback manifest parsing requires jq' >&2; exit 2; }
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --output "$tmp/manifest.json" "$manifest_url"
jq -er --arg manifest_url "$manifest_url" '
  def clean_url:
    if type == "string" and startswith("https://") and (test("[\\x00-\\x20\\x7f\\\\]") | not) and (contains("#") | not)
    then . else error("manifest contains an unsafe URL") end;
  def origin:
    clean_url | split("/")[2] |
    if length > 0 and (test("[@?#]") | not) then "https://" + . else error("invalid manifest origin") end;
  ($manifest_url | origin) as $origin |
  def same_origin:
    . as $url | if origin == $origin then $url else error("manifest contains a different origin") end;
  def digest:
    if type == "string" and test("^[0-9a-f]{64}$") then . else error("manifest contains an invalid SHA-256") end;
  if type != "object" or .schemaVersion != 1 or .kind != "opr-downgrade" then error("unsupported rollback manifest")
  elif (.artifact | type) == "object" then
    (.artifact.url | same_origin) as $url |
    ($url | split("?")[0] | split("/")[-1]) as $filename |
    if ($filename | test("^[A-Za-z0-9][A-Za-z0-9._+:-]{0,220}\\.pkg\\.tar\\.zst$")) then
      ["binary", $url, ((.artifact.signatureUrl // ($url + ".sig")) | same_origin), $filename,
       (.artifact.sha256 | digest), ((.publicKeyUrl // ($origin + "/repo/key.asc")) | same_origin)][]
    else error("manifest contains an invalid package filename") end
  elif (.recipe | type) == "object" then ["recipe", (.recipe.url | same_origin), (.recipe.sha256 | digest)][]
  else error("manifest has no supported downgrade target") end
' "$tmp/manifest.json" > "$tmp/fields"
mapfile -t fields < "$tmp/fields"
if [[ "${fields[0]}" == binary ]]; then
  package_url=${fields[1]}
  signature_url=${fields[2]}
  filename=${fields[3]}
  expected=${fields[4]}
  key_url=${fields[5]}
  curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --output "$tmp/$filename" "$package_url"
  printf '%s  %s\n' "$expected" "$tmp/$filename" | sha256sum --check --status
  curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --output "$tmp/$filename.sig" "$signature_url"
  curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --output "$tmp/key.asc" "$key_url"
  export GNUPGHOME="$tmp/gnupg"
  mkdir -m 700 "$GNUPGHOME"
  gpg --batch --quiet --homedir "$GNUPGHOME" --import "$tmp/key.asc"
  gpg --batch --quiet --homedir "$GNUPGHOME" --verify "$tmp/$filename.sig" "$tmp/$filename"
  sudo pacman -U --noconfirm "$tmp/$filename"
else
  recipe_url=${fields[1]}
  expected=${fields[2]}
  curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --output "$tmp/PKGBUILD" "$recipe_url"
  printf '%s  %s\n' "$expected" "$tmp/PKGBUILD" | sha256sum --check --status
  cd "$tmp"
  makepkg -si -f
fi
