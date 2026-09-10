# Manifest-aware client migration

Install the `omarchy/manifest-client` binary at the path in
`001-manifest-client.conf`, install the release public key out of band in both
the client key path and the pacman trusted keyring, and pin its full OpenPGP
fingerprint in `OMARCHY_RELEASE_FINGERPRINT`. The key is trusted by local
configuration; a key URL inside a manifest never becomes a trust decision.

`omarchy-refresh-pacman stable [URL]` fetches one signed resolved transaction,
or uses `OMARCHY_MANIFEST_DISCOVERY_URL` when URL is omitted, then verifies
the signed system and OPR manifests, checks every immutable repository
database and signature, then stages a pacman config and a human-readable plan.
It does not change the installed system. Run `omarchy-manifest-client apply`
after reviewing `transaction-plan.txt` to execute one complete `pacman -Syu`
transaction. The config and high-water state are committed after pacman
succeeds. A changed local pacman config invalidates the staged review.
High-water state is retained per channel, so selecting RC or edge does not
reuse stable's replay counter.

`omarchy-channel-set stable|rc|edge [URL]` uses same pinned transaction path.
The signed channel must match selected channel. `dev` remains Omarchy
local-development mode and is rejected by this wrapper; it is not mapped to a
package quarantine channel. A discovery pointer may redirect to an immutable
signed transaction, but mutable aliases, query strings, and mirror fallbacks
are rejected after discovery.

The staged renderer rejects any enabled pacman section outside signed owned
repositories, including AUR, ALARM, and live upstream mirrors. Migrate or
remove those sections explicitly before retrying; they are never preserved as
silent fallbacks.

`omarchy-manifest-recovery` prints the signed recovery constraints recorded in
local state. Downgrades require a newer resolved-transaction sequence with
`recovery.authorized`, a matching `fromDigest`, a signed retained target, and
the same selected repositories/package set. The client never performs an
automatic downgrade.

Qualification is limited to Go unit/integration tests with fake pacman and
signed fixtures. Native x86_64/aarch64 boot, initramfs, hardware, filesystem
snapshot, and application data-migration recovery still require platform
acceptance work. Pacman remains responsible for package-level transaction
semantics and package signatures; this client does not claim a filesystem or
boot rollback.
