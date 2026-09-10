# Consumer contract

The client consumes the canonical bytes served by the release routes:

- `/repo/transactions/{channel}/{releaseId}/manifest.json` and `.sig`
- `/repo/releases/{channel}/{releaseId}/manifest.json` and `.sig`
- `/repo/opr/{channel}/{releaseId}/manifest.json` and `.sig`

Each JSON object is schema `1`, policy `distribution-release-v1`, and carries
`kind`, `lane`, `channel`, `identity`, `releaseId`, `parent`, `createdAt`, non-null
`expiresAt`, `sequence`, `architectures`, `repositories`, `packageChunks`,
`packageCount`, `compatibility`, `changelog`, `approvals`, `recovery`, and
`policy`. A resolved transaction has signed `systemManifest` and `oprManifest`
references. A reference contains `url`, `digest`, `signatureUrl`, `sequence`,
`channel`, `version`, and `generation`.

Transaction channels are `stable`, `rc`, and `edge`. OPR leaf manifests may be
`stable` or `quarantine`; stable transactions require stable OPR, while RC and
edge transactions may select either. Channel discovery may move; the client follows a same-origin
redirect or derives an immutable transaction URL from a pointer response, then
uses that final URL to fetch the final detached signature.

`repositories` are ordered immutable records with `name`, `architecture`,
`snapshotDigest`, `dbUrl`, `signatureUrl`, and `packageBaseUrl`. The client
selects records for its local architecture, fetches each database and detached
signature, checks `snapshotDigest`, and verifies both with the locally pinned
OpenPGP key. It does not construct a URL from a channel, architecture, or
mutable alias.

`packageChunks` are signed immutable refs with `url`, `sha256`, `size`,
`index`, `count`, and `packageCount`. The client validates their shape and
keeps their signed URLs in the transaction evidence; pacman resolves package
archives from the signed repository database and verifies package signatures.

The detached OpenPGP signature is over the exact compact canonical JSON bytes
(recursive lexicographic object keys, array order preserved). The client
requires a local trusted key file and full configured fingerprint. A URL or
fingerprint advertised by a manifest cannot add trust.

Normal transactions require `sequence >` local transaction high-water. System
and OPR lane sequence high-water marks are tracked separately from selected
manifest digests. A recovery transaction still advances transaction sequence;
it may select lower lane versions only when `recovery.authorized` is true,
`reason` and `constraints` are present, `fromDigest` equals the installed
resolved digest, and its signed `target` is a retained resolved transaction
whose system/OPR refs, repository records, and package chunks exactly match
the selected transaction. The next independent OPR update can reuse that
selected system digest; a different lower-sequence selection is blocked.
Replay state is keyed by channel, so stable, RC, and edge keep independent
high-water counters.
