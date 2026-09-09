"""Inspect package bytes with namcap and pyelftools; never execute package code."""
import hashlib
import json
import platform
import sys
import tarfile

from elftools.elf.elffile import ELFFile
import Namcap.depends
import Namcap.package
import Namcap.rules.sodepends as shared
from Namcap.rules.shebangdepends import ShebangDependsRule
import Namcap.version


def inspect(filename):
    package = Namcap.package.load_from_tarball(filename)
    if package is None:
        raise ValueError("Cannot read native package metadata")
    elf_files = []
    native_code = []
    payload = {}
    findings = []

    def record(level, messages):
        for message, arguments in messages:
            code = message.split()[0]
            detail = message % arguments
            if len(detail) > 4096:
                raise ValueError("Dependency diagnostic exceeds limit")
            arguments = arguments if isinstance(arguments, tuple) else (arguments,)
            dependency = str(arguments[0]) if code.startswith("dependency-") and arguments else None
            fingerprint = hashlib.sha256(f"{level}\n{code}\n{detail}".encode()).hexdigest()
            findings.append(dict(code=code, level=level, detail=detail, dependency=dependency, sha256=fingerprint))

    with tarfile.open(filename, "r") as archive:
        for entry in archive:
            name = entry.name.rstrip("/")
            if name.startswith("/") or any(part in ("", ".", "..") for part in name.split("/")) or name in payload:
                raise ValueError("Duplicate or unsafe package path")
            if len(payload) >= 100000:
                raise ValueError("Package payload inventory exceeds 100,000 entries")
            digest = None
            if entry.isfile():
                with archive.extractfile(entry) as source:
                    digest = hashlib.file_digest(source, "sha256").hexdigest()
            payload[name] = [name, entry.type.decode("ascii"), entry.mode, entry.uid, entry.gid, entry.linkname, digest]
            if not entry.isfile():
                continue
            with archive.extractfile(entry) as source:
                magic = source.read(8)
                if magic.startswith((b"\x7fELF", b"MZ", b"!<arch>\n", b"!<thin>\n")) or magic[:4] in (
                    b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe",
                ) or (magic[:4] == b"\xca\xfe\xba\xbe" and 1 <= int.from_bytes(magic[4:8], "big") <= 32) or (magic[:4] == b"\xbe\xba\xfe\xca" and 1 <= int.from_bytes(magic[4:8], "little") <= 32):
                    native_code.append(entry.name)
                    if len(native_code) > 4096:
                        raise ValueError("Native code inventory exceeds limit")
                if magic[:4] != b"\x7fELF":
                    continue
                source.seek(0)
                elf = ELFFile(source)
                if platform.machine() == "aarch64" and elf.elfclass != 64:
                    raise ValueError("Mixed ELF bitness is unsupported by ARM dependency analysis")
                needed, runpaths = [], []
                for segment in elf.iter_segments():
                    if segment.header.p_type == "PT_DYNAMIC":
                        for tag in segment.iter_tags():
                            if tag.entry.d_tag == "DT_NEEDED":
                                needed.append(tag.needed)
                            elif tag.entry.d_tag in ("DT_RPATH", "DT_RUNPATH"):
                                runpaths.append(getattr(tag, "rpath", getattr(tag, "runpath", "")))
                elf_files.append(dict(path=entry.name, machine=elf.header.e_machine, needed=needed, searchPaths=runpaths))
                if len(elf_files) > 4096:
                    raise ValueError("ELF inventory exceeds limit")
        # namcap groups 64-bit ELF under 'x86-64', but its ldconfig parser puts
        # AArch64 entries under 'i686'. These native ARM images contain only
        # 64-bit userspace; mixed ELF bitness was rejected above.
        if platform.machine() == "aarch64":
            original = shared.filllibcache

            def fill_arm_cache():
                original()
                shared.libcache["x86-64"].update(shared.libcache["i686"])

            shared.filllibcache = fill_arm_cache
        for rule in (shared.SharedLibsRule(), ShebangDependsRule()):
            rule.analyze(package, archive)
            for level, messages in (("error", rule.errors), ("warning", rule.warnings), ("info", rule.infos)):
                record(level, messages)
        for level, messages in zip(("error", "warning", "info"), Namcap.depends.analyze_depends(package)):
            record(level, messages)
    if len(findings) > 1024:
        raise ValueError("Dependency findings exceed limit")
    # Build environment metadata differs across native targets. Keep its exact
    # bytes in the package hash; compare installable payload independently.
    payload_json = json.dumps([payload[name] for name in sorted(payload) if name not in (".BUILDINFO", ".MTREE")], separators=(",", ":"), ensure_ascii=False)
    return dict(schemaVersion=1, tool="namcap", toolVersion=Namcap.version.get_version(), payloadSha256=hashlib.sha256(payload_json.encode()).hexdigest(),
                elf=elf_files, nativeCode=native_code, findings=findings, runtimeClosureComplete=False,
                unknowns=["unexercised dlopen", "plugins", "runtime-selected subprocesses", "data paths"])


if __name__ == "__main__":
    result = json.dumps(inspect(sys.argv[1]), separators=(",", ":"), sort_keys=True)
    if len(result.encode()) > 256 * 1024:
        raise ValueError("Dependency evidence exceeds 256 KiB")
    print(result)
