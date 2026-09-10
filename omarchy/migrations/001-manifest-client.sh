#!/usr/bin/env bash
set -euo pipefail

# Migration is intentionally a check-only step. Package installation and
# channel selection require a signed transaction URL and explicit operator use.
client=${OMARCHY_MANIFEST_CLIENT:-/usr/lib/omarchy/omapkg-manifest-client}
key=${OMARCHY_RELEASE_KEY:-/etc/omarchy/omapkg-release-key.asc}
fingerprint=${OMARCHY_RELEASE_FINGERPRINT:-}

[[ -x "$client" ]] || { echo "manifest client is missing or not executable: $client" >&2; exit 1; }
[[ -r "$key" ]] || { echo "trusted release key is missing: $key" >&2; exit 1; }
[[ "$fingerprint" =~ ^[A-Fa-f0-9]{16,64}$ ]] || { echo 'OMARCHY_RELEASE_FINGERPRINT must be configured' >&2; exit 1; }
echo 'Manifest client migration prerequisites are present.'
echo 'No pacman transaction or channel change was started.'
