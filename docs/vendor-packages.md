# Vendor packages

omapkg accepts a public HTTPS URL as `source_kind=archive` whether the bytes are a source archive or a vendor binary. The inspector reads bytes and magic values, so a filename extension never selects an extractor.

Supported binary formats:

- Debian packages: the `ar` container must contain `debian-binary`, one `control.tar.*`, and one `data.tar.*`. The inspector reads bounded control fields and extracts the data payload into a deterministic tar file.
- RPM packages: metadata comes from `rpm -qp --queryformat`; the payload is read with `rpm2cpio` and libarchive. The RPM header and cpio payload are inspected without installing the package or running scriptlets.
- AppImage Type 2: the file must be ELF with the Type 2 `AI\x02` marker. The inspector derives the filesystem offset from the ELF layout, verifies SquashFS magic at that offset, and uses `unsquashfs` only for listing and extraction.
- AppImage Type 1: the file must be ELF with the Type 1 `AI\x01` marker and an ISO 9660 `CD001` descriptor at byte offset 32,769. libarchive reads the ISO payload without starting `AppRun`.
- Makeself and NVIDIA-style `.run` installers: the inspector reads at most the first 1 MiB, records a streaming SHA-256, and writes no payload. It never executes the installer during online inspection.

`vendorArtifactCommand()` in `services/pipeline/artifacts.ts` writes a JSON manifest and a bounded entry manifest under the disposable sandbox workspace. Payload entries are normalized and checked before extraction. Absolute paths, `..` components, duplicate names, symlinks, hard links, device nodes, FIFOs, sockets, control characters, oversized entry sets, and expanded payloads fail the inspection. Extraction uses archive tools with no owner or timestamp restoration, then creates a sorted tar with fixed timestamps and numeric ownership.

The factory records `surface: recipe` by default. A vendor binary becomes Surface A only after maintainers record explicit redistribution evidence. Spotify and similar vendor downloads stay recipe-only when redistribution rights are absent. Surface B recipes retain the vendor URL and checksum and do not copy the vendor installer into omapkg artifacts.

`offlineVendorExtractCommand()` supplies reviewed recipe build steps:

- Debian data archives are selected from the `ar` member list and extracted with libarchive.
- RPM payloads are converted with `rpm2cpio` and extracted with libarchive.
- AppImage payloads are extracted with `unsquashfs` at the reviewed offset, or libarchive for Type 1.
- `.run` payloads are checksum-checked, then invoked as `sh <file> --extract-only --target <dir>` inside the offline worker build. This is the only installer invocation, and it happens after review in the worker isolation boundary; no driver or system installation is allowed.

The sandbox image needs `ar`/binutils, libarchive (`bsdtar`), `squashfs-tools`, and RPM metadata/payload tools (`rpm`, `rpm2cpio`). The Type 1 path uses libarchive's ISO reader. Keep source download limits and source hashing streaming so large vendor binaries can reach the 2 GiB inspection limit without buffering them in a Worker request.

The AppImage layout follows the [AppImage architecture reference](https://docs.appimage.org/reference/architecture.html) and [format specification](https://github.com/AppImage/AppImageSpec/blob/master/draft.md). Real `.deb`, RPM, Type 1/2 AppImage, and NVIDIA-style `.run` fixtures exercise detection, extraction, path checks, checksum handling, and the no-install boundary in `tests/artifacts.test.ts`.
