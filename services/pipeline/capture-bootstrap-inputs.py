#!/usr/bin/env python3
"""Capture private bootstrap inputs. Does not approve, install or publish them.

Run inside a disposable, pinned native helper container with /capture writable.
The caller retains that helper's OCI archive before invoking this script.
"""

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tarfile
import tempfile
import io
import urllib.request
from urllib.parse import urlsplit

MAX_PACKAGE_BYTES = 4 << 30
MAX_TRANSFER_BYTES = 256 << 30


def command(*args):
    return subprocess.run(args, check=True, stdout=subprocess.PIPE, text=True).stdout


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def retain(directory, data):
    digest = hashlib.sha256(data).hexdigest()
    destination = directory / digest
    if not destination.exists():
        destination.write_bytes(data)
    return {"sha256": digest, "size": len(data)}


def retain_file(directory, path):
    size = path.stat().st_size
    with path.open("rb") as file:
        digest = hashlib.file_digest(file, "sha256").hexdigest()
    destination = directory / digest
    if path != destination and not destination.exists():
        os.link(path, destination)
    return {"sha256": digest, "size": size}


def verify_helper_archive(path, image):
    with tarfile.open(path, "r:") as archive:
        members = archive.getmembers()
        if len(members) > 1024 or len({member.name for member in members}) != len(members):
            raise ValueError("retained helper archive has too many or repeated entries")
        index = archive.getmember("index.json")
        if not index.isfile() or index.size > 1 << 20:
            raise ValueError("retained helper OCI index is missing or too large")
        manifest = json.load(archive.extractfile(index))
        if (manifest.get("schemaVersion") != 2 or len(manifest.get("manifests", [])) != 1
                or manifest["manifests"][0].get("digest") != image.split("@")[-1]):
            raise ValueError("retained OCI helper differs from image pin; pin the exported manifest digest before capture")
        archive.getmember("blobs/sha256/" + image.split(":")[-1])
        for member in members:
            if member.isdir() and member.name.rstrip("/") in (".", "blobs", "blobs/sha256"):
                continue
            if not member.isfile() or member.size > 32 << 30:
                raise ValueError("retained helper contains a nonregular or oversized entry")
            if member.name in ("index.json", "oci-layout"):
                continue
            if not re.fullmatch(r"blobs/sha256/[0-9a-f]{64}", member.name):
                raise ValueError("retained helper has an unsafe OCI object name")
            if hashlib.file_digest(archive.extractfile(member), "sha256").hexdigest() != member.name.split("/")[-1]:
                raise ValueError("retained helper OCI blob checksum mismatch")


def database_sizes(path, package_names=None):
    sizes = {}
    total = 0
    prefixes = tuple(name + "-" for name in package_names) if package_names is not None else None
    if path.stat().st_size > 32 << 20:
        raise ValueError("bootstrap repository database exceeds 32 MiB")
    with tarfile.open(path, "r:*") as archive:
        for index, member in enumerate(archive):
            total += member.size
            if total > 512 << 20 or index >= 100000:
                raise ValueError("expanded repository database exceeds capture budget")
            if not member.isfile() or not member.name.endswith("/desc"):
                continue
            # Bootstrap resolves an explicit subset; the original database is
            # retained in full. A selected malformed record still fails closed.
            if prefixes is not None and not member.name.startswith(prefixes):
                continue
            if member.size > 1 << 20:
                raise ValueError("package database record exceeds 1 MiB")
            text = archive.extractfile(member).read().decode("utf-8")
            fields = {}
            for section in text.strip().split("\n\n"):
                lines = section.splitlines()
                if lines and lines[0] in ("%FILENAME%", "%CSIZE%"):
                    if lines[0] in fields or len(lines) != 2:
                        raise ValueError("duplicate or invalid package archive size")
                    fields[lines[0]] = lines[1]
            filename, size = fields.get("%FILENAME%"), fields.get("%CSIZE%", "")
            if not filename or not size.isdigit() or not 0 < int(size) <= MAX_PACKAGE_BYTES or filename in sizes:
                raise ValueError("captured package archive size is invalid")
            sizes[filename] = int(size)
    return sizes


def parse_plan(text, architecture, sizes):
    records = []
    for line in text.splitlines():
        fields = line.split("\t")
        if len(fields) != 8:
            raise ValueError("pacman returned an incomplete package plan")
        name, version, arch, filename, digest, url, signature, repository = fields
        size = sizes.get(repository, {}).get(filename, 0)
        if (not re.fullmatch(r"[a-z0-9][a-z0-9@._+-]{0,63}", name)
                or not re.fullmatch(r"(?:[0-9]+:)?[A-Za-z0-9][A-Za-z0-9@._+%~^:-]{0,127}", version)
                or arch not in (architecture, "any") or filename not in [f"{name}-{full_version}-{arch}.pkg.tar.{extension}"
                    for full_version in (version, version.split(':')[-1]) for extension in ("zst", "xz")]
                or not re.fullmatch(r"[0-9a-f]{64}", digest) or not 0 < size <= MAX_PACKAGE_BYTES):
            raise ValueError(f"pacman returned an invalid package identity, checksum or size for {name!r}")
        parsed = urlsplit(url)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
            raise ValueError("bootstrap capture requires public HTTPS package locations")
        signature_bytes = base64.b64decode(signature, validate=True)
        if not signature_bytes or len(signature_bytes) > 1 << 20:
            raise ValueError("captured database does not contain a bounded package signature")
        records.append({"name": name, "version": version, "architecture": arch, "filename": filename,
                        "sha256": digest, "size": size, "url": url, "signature": signature_bytes,
                        "repository": repository})
    if not records or len(records) > 4096 or len({record["name"] for record in records}) != len(records):
        raise ValueError("bootstrap closure is empty, repeated or exceeds 4096 packages")
    return sorted(records, key=lambda item: item["name"])


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args):
        raise ValueError("bootstrap capture does not follow package redirects")


def download(record, directory):
    destination = directory / record["sha256"]
    if destination.exists():
        if retain_file(directory, destination) != {"sha256": record["sha256"], "size": record["size"]}:
            raise ValueError("existing retained package differs from capture")
        return destination
    temporary = directory / (record["sha256"] + ".part")
    digest = hashlib.sha256()
    size = 0
    request = urllib.request.Request(record["url"], headers={"Accept-Encoding": "identity", "User-Agent": "omapkg-bootstrap-capture/1"})
    with urllib.request.build_opener(NoRedirect()).open(request, timeout=120) as response, temporary.open("xb") as file:
        if response.status != 200 or response.headers.get("Content-Encoding", "identity") != "identity":
            raise ValueError("unexpected bootstrap package response")
        while block := response.read(1 << 20):
            size += len(block)
            if size > record["size"]:
                raise ValueError("bootstrap package exceeds captured size")
            digest.update(block)
            file.write(block)
    if size != record["size"] or digest.hexdigest() != record["sha256"]:
        raise ValueError("bootstrap package differs from captured database")
    temporary.rename(destination)
    return destination


def capture(args):
    root = Path(args.output)
    objects = root / "objects"
    objects.mkdir(parents=True, exist_ok=True)
    native = command("uname", "-m").strip()
    if native != args.architecture:
        raise ValueError("bootstrap capture requires matching native architecture")
    verify_helper_archive(Path(args.helper_archive), args.helper_image)
    helper_archive = retain_file(objects, Path(args.helper_archive))
    makepkg_config = retain(objects, Path(args.makepkg_config).read_bytes())
    config = root / "pacman.conf"
    config.write_text(re.sub(r"^DownloadUser\s*=.*$", "DownloadUser = root", Path(args.pacman_config).read_text(), flags=re.MULTILINE))
    environments = []
    remaining = args.transfer_limit_bytes - helper_archive["size"] - makepkg_config["size"]
    downloaded = set()
    for index, targets in enumerate([args.build_packages] + args.runtime_packages):
        name = "build" if index == 0 else f"runtime-{index - 1}"
        resolver = root / ("resolver-" + name)
        resolver.mkdir()
        cache = resolver / "cache"
        cache.mkdir()
        # Empty local database: the helper's installed packages cannot disappear
        # from the lock merely because the resolver considers them satisfied.
        command("pacman", "--config", str(config), "--dbpath", str(resolver), "-Sy", "--noconfirm")
        text = command("pacman", "--config", str(config), "--dbpath", str(resolver), "--cachedir", str(cache), "-Sp", "--noconfirm", "--print-format",
                       "%n\t%v\t%a\t%f\t%h\t%l\t%g\t%r", "--", *targets)
        package_names = {line.split("\t", 1)[0] for line in text.splitlines()}
        databases = []
        sizes = {}
        for path in sorted((resolver / "sync").iterdir()):
            if path.is_file():
                databases.append({"name": path.name, "object": retain_file(objects, path)})
                if path.suffix == ".db":
                    sizes[path.stem] = database_sizes(path, package_names)
        records = parse_plan(text, args.architecture, sizes)
        evidence = retain(objects, canonical({"schemaVersion": 1, "kind": "external-bootstrap-capture",
            "architecture": args.architecture, "helperImage": args.helper_image, "pacmanConfig": retain_file(objects, config), "databases": databases,
            "targets": targets, "packages": [{k: v for k, v in record.items() if k != "signature"} for record in records]}))
        packages = []
        for record in records:
            if record["sha256"] not in downloaded:
                remaining -= record["size"]
                if remaining < 0:
                    raise ValueError("bootstrap packages exceed explicit transfer budget")
                downloaded.add(record["sha256"])
            path = download(record, objects)
            signature = retain(objects, record["signature"])
            status = command("gpg", "--batch", "--homedir", "/etc/pacman.d/gnupg", "--no-auto-key-retrieve",
                             "--status-fd", "1", "--verify", str(objects / signature["sha256"]), str(path))
            valid = [line.split() for line in status.splitlines() if line.startswith("[GNUPG:] VALIDSIG ")]
            if len(valid) != 1:
                raise ValueError("bootstrap package requires exactly one verified signature")
            fingerprint = valid[0][-1]
            if not re.fullmatch(r"[0-9A-F]{40}", fingerprint):
                raise ValueError("bootstrap package signer identity is invalid")
            key = subprocess.run(["gpg", "--batch", "--homedir", "/etc/pacman.d/gnupg", "--export", fingerprint],
                                 check=True, stdout=subprocess.PIPE).stdout
            if not key or len(key) > 1 << 20:
                raise ValueError("bootstrap public key is empty or exceeds limit")
            packages.append({k: record[k] for k in ("name", "version", "architecture", "filename")} | {
                "package": {"sha256": record["sha256"], "size": record["size"]}, "signature": signature,
                "publicKey": retain(objects, key), "fingerprint": fingerprint,
                "origin": "external-bootstrap", "originEvidence": evidence["sha256"]})
        inventory = "".join(sorted(f'{item["name"]} {item["version"]}\n' for item in packages)).encode()
        environments.append({"name": name, "packageCount": len(packages), "totalBytes": sum(item["package"]["size"] for item in packages),
            "inventorySha256": hashlib.sha256(inventory).hexdigest(),
            "chunks": [retain(objects, canonical(packages[start:start + 64])) for start in range(0, len(packages), 64)]})
    manifest = {"schemaVersion": 1, "purpose": "bootstrap", "architecture": args.architecture,
        "recipeSha256": args.recipe_sha256, "cohortSha256": args.cohort_sha256, "sourceDateEpoch": args.source_date_epoch,
        "helperImage": args.helper_image, "helperArchive": helper_archive, "makepkgConfig": makepkg_config,
        "transferLimitBytes": args.transfer_limit_bytes, "environments": environments}
    if args.helper_shell_analysis:
        manifest["shellAnalysis"] = "helper"
    reference = retain(objects, canonical(manifest))
    (root / "manifest.json").write_bytes(canonical(manifest))
    (root / "reference.json").write_bytes(canonical(reference))
    (root / "NOTICE.txt").write_text("PRIVATE BOOTSTRAP CAPTURE. No human approval, owned build claim or release eligibility.\n")
    print(json.dumps({"reference": reference, "environments": [{"name": item["name"], "packages": item["packageCount"], "bytes": item["totalBytes"]} for item in environments]}))


def main():
    if sys.argv[1:] == ["--self-test"]:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "test.db"
            record = b"%FILENAME%\nbase-1.0-1-any.pkg.tar.zst\n\n%CSIZE%\n123\n\n"
            with tarfile.open(path, "w:gz") as archive:
                member = tarfile.TarInfo("base-1.0-1/desc")
                member.size = len(record)
                archive.addfile(member, io.BytesIO(record))
            sizes = {"core": database_sizes(path)}
            line = "\t".join(["base", "1:1.0-1", "any", "base-1.0-1-any.pkg.tar.zst", "a" * 64,
                              "https://example.org/base-1.0-1-any.pkg.tar.zst", base64.b64encode(b"signature").decode(), "core"])
            assert parse_plan(line, "x86_64", sizes)[0]["size"] == 123
            xz_line = line.replace(".pkg.tar.zst", ".pkg.tar.xz")
            assert parse_plan(xz_line, "x86_64", {"core": {"base-1.0-1-any.pkg.tar.xz": 123}})[0]["size"] == 123
            for invalid in [line.replace("https://", "file://"), line.replace("any\t", "aarch64\t"), line + "\n" + line]:
                try:
                    parse_plan(invalid, "x86_64", sizes)
                except ValueError:
                    continue
                raise AssertionError("accepted invalid frozen package plan")
            with tarfile.open(path, "w:gz") as archive:
                for name, data in [("base-1.0-1/desc", record), ("broken-1.0-1/desc", b"\0" * 100)]:
                    member = tarfile.TarInfo(name)
                    member.size = len(data)
                    archive.addfile(member, io.BytesIO(data))
            assert database_sizes(path, {"base"}) == sizes["core"]
            for selected in (None, {"broken"}):
                try:
                    database_sizes(path, selected)
                except ValueError:
                    continue
                raise AssertionError("accepted malformed selected database record")
        print("bootstrap capture self-check passed")
        return
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True)
    parser.add_argument("--architecture", choices=("x86_64", "aarch64"), required=True)
    parser.add_argument("--helper-image", required=True)
    parser.add_argument("--helper-archive", required=True)
    parser.add_argument("--makepkg-config", required=True)
    parser.add_argument("--pacman-config", required=True)
    parser.add_argument("--recipe-sha256", required=True)
    parser.add_argument("--cohort-sha256", required=True)
    parser.add_argument("--source-date-epoch", type=int, required=True)
    parser.add_argument("--transfer-limit-bytes", type=int, required=True)
    parser.add_argument("--build-packages", nargs="+", required=True)
    parser.add_argument("--runtime-packages", nargs="+", action="append", required=True)
    parser.add_argument("--helper-shell-analysis", action="store_true", help="Pin shell analysis to retained helper instead of build-root tools")
    args = parser.parse_args()
    if (not re.fullmatch(r"[^\s]+@sha256:[0-9a-f]{64}", args.helper_image)
            or any(not re.fullmatch(r"[0-9a-f]{64}", value) for value in (args.recipe_sha256, args.cohort_sha256))
            or args.source_date_epoch < 0 or not 0 < args.transfer_limit_bytes <= MAX_TRANSFER_BYTES):
        parser.error("invalid immutable input identity or transfer budget")
    capture(args)


if __name__ == "__main__":
    main()
