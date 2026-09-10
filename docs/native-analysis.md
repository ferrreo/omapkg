# Native analysis and retained ABI observations

Worker analysis runs in Go. The daemon mounts its own static executable into the
existing isolated, nonroot, read-only container and invokes `analyze-package`.
Networking remains disabled. `bsdtar` converts the package to a tar stream;
Go's `archive/tar` and `debug/elf` inspect its contents. Installed package metadata
comes from pacman's local database; `vercmp` and `ldconfig` supply native version
and library-cache semantics. No Python or namcap process runs in this path.

Runtime reports use `schemaVersion: 2`, `tool: "go-native-analysis"`. Historical
schema-1 namcap reports remain readable and verifiable. Runtime errors still
block. Existing independently reviewed exceptions cover only the named ambiguous
findings; changing a finding changes its digest. Dynamic loads, plugins,
runtime-selected subprocesses and unexercised data paths remain unknown.
`runtimeClosureComplete` remains false.

The analysis checks ELF machine/class/byte order, dynamic table consistency,
DT_NEEDED, interpreter paths, RPATH/RUNPATH and `$ORIGIN`, actual resolved file
ownership, required and optional dependency closures, and script interpreters.
Unsupported loader tokens or ambiguous interpreter syntax are visible findings,
never silently resolved against an arbitrary provider. Python scripts inside a
package are data to inspect; their interpreter is a package dependency, not a
dependency of the analyzer.

## ABI objects

Each new native multi-output report includes an `abiInventory` reference in its
runtime analysis: `{ "sha256": "…", "size": 123 }`. That reference is inside the
worker-signed provenance and retained central build statement. The inventory
binds one exact artifact SHA-256 and an ordered list of digest-pinned chunks.
Every chunk records its starting offset and file/symbol counts.

File records include path, type, mode, link target, file digest and native-code
kind. ELF records add SONAME, needed libraries, class/machine/byte order, loader
paths, interpreter and presence of debug and dynamic-symbol information. Symbol
records retain table/index, name, binding, visibility, type, size, definition
status, version, version provider and hidden-version bit. Copy relocations retain
their provider version even when the executable defines the copied symbol.
Static and thin archives retain content identity. This inventory does not claim
to compare C/C++ type layouts; `typeAbi` is explicitly `not-checked`.

Limits are enforced without truncation: 512 KiB per document, 2,048 records per
chunk, 2,048 chunks per inventory, 100,000 files and two million symbols per
package, and 4,096 uploaded documents per build attempt. The existing runtime
summary remains bounded at 256 KiB. Archive analysis allows 4 GiB per file and
32 GiB expanded package content inside the existing worker resource limits.
Exceeding a limit fails the build with a diagnostic.

Workers upload package artifacts first, then chunks, then the inventory through
`PUT /api/worker/jobs/:id/evidence/:digest?leaseToken=…`. Upload authorization uses
the signed worker request and current reviewed lease. Every object must name an
uploaded artifact in that attempt. Inventory admission checks every referenced
chunk, size, offset and count. Completion and native signing reject unavailable
or mismatched inventory references. Stored evidence is immutable.

Maintainers can download selected inventories from the build page. The same
private artifact endpoint accepts `attempt` and `evidence` parameters for an
inventory or one of its chunks. Downloads verify bytes against the stored digest;
anonymous access is rejected. Publication and qualification remain separate
actions; retaining or signing an inventory does not approve a release.

## Other runtime entry points

Catalog capture is `opr-worker capture-catalog`. The pipeline image builds the
same Go source as `/usr/local/bin/omapkg-tools` and invokes its capture command.
Public-only HTTP/DNS checks, bounded archive parsing, exact target identities,
recipe-only OPR capture and canonical import hashes remain enforced. Build the
pipeline Dockerfile using a repository-root context containing `worker/*.go` and
`worker/go.mod`.

The legacy rollback shell uses `jq` for manifest parsing. It rejects malformed
schema, unsafe/different origins, invalid filenames and digests before invoking
installation commands. It preserves the adjacent package signature required by
pacman. Offline operator capture and development-check scripts are separate
from these production runtime entry points.

## Checks

`go test ./...` in `worker` includes compiled versioned ELF fixtures, copy
relocations, static archives, dependency/optional-provider cases, interpreter and
archive validation, catalog parsing and canonical hashes. Native OCI regressions
also exercise split outputs and the undeclared build-only-library failure.
Application tests cover signed uploads, missing chunks, stale leases, wrong
attempts/artifacts, private downloads, corruption and historical verification.
Rollback tests replace installation commands with inert fixtures and make any
Python invocation fail.
