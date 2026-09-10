# Omarchy manifest client

`manifest-client` is the Phase 5 local consumer. It consumes one signed
`resolved-transaction` manifest, verifies its signed `system` and `opr`
references, checks immutable repository database bytes and OpenPGP signatures,
and stages one pacman configuration preserving local options and owned-repo
order.

Build on a supported Go toolchain:

```sh
go -C omarchy/manifest-client build -o ../../omarchy-manifest-client .
go -C omarchy/manifest-client test ./...
```

The client trusts only the OpenPGP public key and full fingerprint supplied by
local configuration. The same release key must be admitted to pacman's trusted
keyring so pacman can enforce package signatures. A key URL in a manifest is
metadata, never trust-on-first-use. Manifest and repository URLs must be HTTPS, same-origin, query-free,
fragment-free, and contain no mutable channel alias. Every signed JSON object
is verified as the exact compact canonical bytes published by the release
authority.

Typical consumer flow:

```sh
omarchy-refresh-pacman stable https://packages.example/repo/transactions/stable/txn-4.0.3-opr-1/manifest.json
less /var/lib/omarchy/manifest-stage/transaction-plan.txt
omarchy-manifest-client apply \
  --key /etc/omarchy/omapkg-release-key.asc \
  --fingerprint "$OMARCHY_RELEASE_FINGERPRINT"
```

Set `OMARCHY_MANIFEST_DISCOVERY_URL` to a channel pointer to avoid copying
release URLs. The client follows a same-origin redirect, or reads a pointer's
immutable release reference, then verifies only the final immutable manifest
and its final `.sig` URL. The signed `channel` field must match
`OMARCHY_CHANNEL`; a stable pointer cannot select an RC or edge transaction.

`stage` does not mutate the installed pacman configuration or package database.
`apply` is the explicit action that runs one full `pacman -Syu`; package
changes remain pacman's transaction and signature responsibility. A staged
plan is digest-bound and invalidated if the local pacman config or signed
manifest changes. State and config use durable same-directory writes with a
commit marker so an interrupted commit can be completed on the next client
run.

Sequences are high-water marks. A replay or expired manifest fails. A lower
system/OPR selection is accepted only when the newer signed transaction has an
authorized recovery record whose `fromDigest` matches the installed resolved
manifest, whose retained target is itself signed, and whose repository and
package-chunk set matches the selected transaction. The high-water marks stay
at their previous values after recovery. The `recovery` command prints limits;
it never starts a downgrade.

Tests use temporary GnuPG keys, signed JSON/repository fixtures, a fake
pacman, and HTTPS test servers. They do not install, remove, downgrade, or
change a production machine. Native boot, graphics, initramfs, hardware,
filesystem snapshot, package data-migration, and application recovery remain
platform qualification work; this module does not claim those gates.
