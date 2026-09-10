#!/usr/bin/env python3
"""Retain a native inspection's source plan. Never evaluate a PKGBUILD.

HTTPS files and bare Git mirrors are captured before isolated offline builds.
Language caches and public signing keys must be supplied explicitly for review.
"""
import argparse
import hashlib
import http.client
import ipaddress
import json
import os
from pathlib import Path
import re
import resource
import signal
import socket
import ssl
import subprocess
import tarfile
import tempfile
import time
from urllib.parse import urljoin, urlsplit

MAX_OBJECT = 32 << 30
MAX_TRANSFER = 256 << 30
MAX_ENTRIES = 200000
HASH = re.compile(r"[a-f0-9]{64}")
ALGORITHMS = {"md5": "md5", "sha1": "sha1", "sha224": "sha224", "sha256": "sha256", "sha384": "sha384", "sha512": "sha512", "b2": "blake2b"}
CACHES = ("go", "cargo", "npm")


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def safe_name(value):
    if (not isinstance(value, str) or not value or len(value.encode()) > 255 or value.startswith("-")
            or value in (".", "..") or value.lower() == ".git" or re.search(r"[\x00-\x1f\x7f/\\]", value)):
        raise ValueError("unsafe source filename")
    return value


def public_url(value):
    parsed = urlsplit(value)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.port or parsed.username or parsed.password or parsed.fragment
            or len(value) > 2048 or "." not in parsed.hostname or parsed.hostname.endswith((".", ".local", ".internal", ".localhost"))
            or re.search(r"[\x00-\x20\x7f\\]", value)):
        raise ValueError("source requires a public HTTPS URL without credentials or fragments")
    try:
        ipaddress.ip_address(parsed.hostname)
    except ValueError:
        return parsed
    raise ValueError("IP literal sources are unsupported")


def public_addresses(host):
    addresses = sorted({result[4][0] for result in socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)})
    if not addresses or any(not ipaddress.ip_address(address).is_global for address in addresses):
        raise ValueError("source DNS resolves to a nonpublic address")
    return addresses


class PinnedHTTPS(http.client.HTTPSConnection):
    def connect(self):
        # Pin the checked address while retaining hostname-based TLS verification.
        address = public_addresses(self.host)[0]
        self.sock = self._context.wrap_socket(socket.create_connection((address, self.port), self.timeout), server_hostname=self.host)


def download(url, path, limit):
    chain = []
    for _ in range(9):
        parsed = public_url(url)
        chain.append(url)
        connection = PinnedHTTPS(parsed.hostname, timeout=120, context=ssl.create_default_context())
        try:
            connection.request("GET", (parsed.path or "/") + ("?" + parsed.query if parsed.query else ""),
                               headers={"Accept-Encoding": "identity", "User-Agent": "omapkg-source-capture/1"})
            response = connection.getresponse()
            if response.status in (301, 302, 303, 307, 308):
                location = response.getheader("Location")
                if not location:
                    raise ValueError("source redirect lacks a destination")
                url = urljoin(url, location)
                continue
            if response.status != 200 or response.getheader("Content-Encoding", "identity") != "identity":
                raise ValueError(f"source download returned HTTP {response.status}")
            size = 0
            with path.open("xb") as file:
                while block := response.read(1 << 20):
                    size += len(block)
                    if size > limit:
                        raise ValueError("source download exceeds byte budget")
                    file.write(block)
            return chain
        finally:
            connection.close()
    raise ValueError("source download exceeds redirect budget")


def retain(objects, path):
    size = path.stat().st_size
    if size > MAX_OBJECT:
        raise ValueError("retained source object exceeds 32 GiB")
    with path.open("rb") as file:
        digest = hashlib.file_digest(file, "sha256").hexdigest()
    target = objects / digest
    if size == 0:
        return {"sha256": digest, "size": size}
    if not target.exists():
        os.link(path, target)
    else:
        with target.open("rb") as file:
            if target.stat().st_size != size or hashlib.file_digest(file, "sha256").hexdigest() != digest:
                raise ValueError("existing retained object checksum differs")
    return {"sha256": digest, "size": size}


def checksum_file(path, checksums):
    for algorithm, expected in checksums.items():
        if algorithm not in ALGORITHMS or not isinstance(expected, str):
            raise ValueError("unsupported source checksum")
        if expected == "SKIP":
            continue
        with path.open("rb") as file:
            actual = hashlib.file_digest(file, ALGORITHMS[algorithm]).hexdigest()
        if actual != expected:
            raise ValueError(f"source {algorithm} differs from inspected checksum")


def command(args, directory, limit=1 << 20, file_limit=MAX_OBJECT, tree_limit=None):
    env = {key: value for key, value in os.environ.items() if not key.startswith(("GIT_", "GPG_")) and key.lower() not in ("http_proxy", "https_proxy", "all_proxy", "no_proxy")}
    env.update(HOME=str(directory), XDG_CONFIG_HOME=str(directory), GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL="/dev/null", GIT_TERMINAL_PROMPT="0",
               GIT_ALLOW_PROTOCOL="https", GIT_LFS_SKIP_SMUDGE="1", GNUPGHOME=str(directory / "gnupg"))
    def budget():
        resource.setrlimit(resource.RLIMIT_FSIZE, (file_limit, file_limit))
    with tempfile.TemporaryFile(dir=directory) as output, tempfile.TemporaryFile(dir=directory) as errors:
        process = subprocess.Popen(args, env=env, cwd=directory, stdout=output, stderr=errors, start_new_session=True, preexec_fn=budget)
        deadline = time.monotonic() + 1800
        try:
            while process.poll() is None:
                if time.monotonic() > deadline:
                    raise ValueError("source capture command timed out")
                if tree_limit is not None:
                    size = entries = 0
                    # ponytail: disk polling can overshoot between checks; use a filesystem quota for a strict host allocation.
                    for path in directory.rglob("*"):
                        try:
                            size += path.lstat().st_size
                        except FileNotFoundError:
                            continue  # Git atomically renames temporary objects.
                        entries += 1
                        if size > tree_limit or entries > MAX_ENTRIES:
                            raise ValueError("Git source capture exceeds disk or entry budget")
                time.sleep(0.2)
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
            process.wait()
        if process.returncode:
            raise ValueError(f"{args[0]} failed during source capture (exit {process.returncode})")
        if output.tell() > limit:
            raise ValueError("source command output exceeds metadata budget")
        output.seek(0)
        return output.read()


def git(directory, *args, network=None, file_limit=MAX_OBJECT):
    settings = ["git", "-c", "core.hooksPath=/dev/null", "-c", "credential.helper=", "-c", "http.extraHeader=", "-c", "http.proxy=",
                "-c", "http.followRedirects=false", "-c", "submodule.recurse=false", "-c", "init.templateDir=", "-c", "safe.bareRepository=all"]
    if network:
        parsed = public_url(network)
        if parsed.query:
            raise ValueError("Git source URL cannot contain a query")
        addresses = public_addresses(parsed.hostname)
        # Git's curl resolver pins the origin; redirects and other protocols are disabled.
        addresses = [f"[{address}]" if ":" in address else address for address in addresses]
        settings += ["-c", f"http.curloptResolve={parsed.hostname}:443:{','.join(addresses)}"]
    return command([*settings, *args], directory, file_limit=file_limit, tree_limit=file_limit if network else None)


def archive_tree(directory, destination, limit):
    entries, expanded = 0, 0
    with tarfile.open(destination, "w", format=tarfile.PAX_FORMAT) as archive:
        for path in sorted(directory.rglob("*")):
            name = path.relative_to(directory).as_posix()
            if len(name.encode()) > 512 or any(part in (".", "..", "") or re.search(r"[\x00-\x1f\x7f\\]", part) for part in name.split("/")):
                raise ValueError("unsafe source archive path")
            info = archive.gettarinfo(str(path), arcname=name)
            if info.islnk():
                info.type, info.linkname, info.size = tarfile.REGTYPE, "", path.stat().st_size
            entries += 1
            if info.issym():
                # Cache links must remain inside the archive even after link resolution.
                if Path(info.linkname).is_absolute() or not path.resolve().is_relative_to(directory.resolve()):
                    raise ValueError("source cache link escapes its directory")
            elif not info.isdir() and not info.isfile():
                raise ValueError("source archive contains a device or special file")
            expanded += info.size
            if entries > MAX_ENTRIES or expanded > limit:
                raise ValueError("expanded source archive exceeds budget")
            info.uid = info.gid = info.mtime = 0
            info.uname = info.gname = ""
            info.pax_headers = {}
            info.mode = 0o755 if info.isdir() or info.mode & 0o111 else 0o644
            if info.isfile():
                with path.open("rb") as file:
                    archive.addfile(info, file)
            else:
                archive.addfile(info)
            if archive.offset > limit:
                raise ValueError("source archive exceeds byte budget")
    if destination.stat().st_size > limit:
        raise ValueError("source archive exceeds byte budget")
    return {"entries": entries, "expandedBytes": expanded}


def capture_git(source, temporary, objects, limit):
    mirror = temporary / "mirror"
    reference = source["ref"]
    kind, value = reference["kind"], reference["value"]
    if kind not in ("head", "commit", "tag", "branch") or not isinstance(value, str) or value.startswith("-"):
        raise ValueError("invalid Git source reference")
    selected = {"head": "HEAD", "commit": value, "tag": "refs/tags/" + value, "branch": "refs/heads/" + value}[kind]
    if kind in ("tag", "branch"):
        if "=" in value:
            raise ValueError("ambiguous Git source reference")
        git(temporary, "check-ref-format", selected)
    if kind == "commit" and not re.fullmatch(r"[a-fA-F0-9]{40}", value):
        raise ValueError("full immutable Git source commit required")
    git(temporary, "clone", "--mirror", "--", source["url"], str(mirror), network=source["url"], file_limit=limit)
    commit = git(temporary, "--git-dir=" + str(mirror), "rev-parse", "--verify", "--end-of-options", selected + "^{commit}").decode().strip()
    if not re.fullmatch(r"[a-f0-9]{40}", commit) or (kind == "commit" and commit != value.lower()):
        raise ValueError("Git source resolution differs from requested commit")
    git(temporary, "--git-dir=" + str(mirror), "fsck", "--full", "--no-reflogs")
    # Match makepkg's treatment of archive attributes before checking Git checksums.
    (mirror / "info").mkdir(exist_ok=True)
    (mirror / "info/attributes").write_text("* -export-subst -export-ignore\n")
    if any(value != "SKIP" for value in source["checksums"].values()):
        if kind not in ("commit", "tag"):
            raise ValueError("Git branch/head sources cannot have archive checksums")
        source_tar = temporary / "checkout.tar"
        git(temporary, "--git-dir=" + str(mirror), "archive", "--format=tar", "--output=" + str(source_tar), selected, file_limit=limit)
        checksum_file(source_tar, source["checksums"])
    path = temporary / "mirror.tar"
    expansion = archive_tree(mirror, path, limit)
    return {"name": source["name"], "kind": "git", "commit": commit, "object": retain(objects, path), **expansion}


def capture(args):
    plan_bytes = Path(args.plan).read_bytes()
    if len(plan_bytes) > 2 << 20:
        raise ValueError("source plan exceeds 2 MiB")
    plan = json.loads(plan_bytes)
    if (canonical(plan) != plan_bytes or plan.get("schemaVersion") != 1 or plan.get("kind") != "recipe-source-plan"
            or plan.get("architecture") not in ("x86_64", "aarch64") or not HASH.fullmatch(plan["capture"]["sha256"])
            or not isinstance(plan.get("sources"), list) or len(plan["sources"]) > 2048):
        raise ValueError("invalid canonical native source plan")
    names = [safe_name(source["name"]) for source in plan["sources"]]
    if len(set(names)) != len(names):
        raise ValueError("source plan repeats a filename")
    output = Path(args.output).resolve()
    output.mkdir(parents=True, exist_ok=False)
    objects = output / "objects"
    objects.mkdir()
    plan_path = output / "plan.json"
    plan_path.write_bytes(plan_bytes)
    plan_ref = retain(objects, plan_path)
    manifest = {"schemaVersion": 1, "kind": "recipe-source-bundle", "plan": plan_ref, "sources": [], "caches": [], "keys": []}
    remaining = args.transfer_limit_bytes - plan_ref["size"]
    for source in plan["sources"]:
        if source["kind"] == "local":
            if source["path"] != source["name"]:
                raise ValueError("local source path differs from captured filename")
            continue
        with tempfile.TemporaryDirectory(dir=output) as work:
            temporary = Path(work)
            limit = min(args.object_limit_bytes, remaining)
            if source["kind"] == "file":
                path = temporary / "download"
                redirects = download(source["url"], path, limit)
                checksum_file(path, source["checksums"])
                entry = {"name": source["name"], "kind": "file", "object": retain(objects, path), "redirects": redirects}
            elif source["kind"] == "git":
                entry = capture_git(source, temporary, objects, limit)
            else:
                raise ValueError("unsupported planned source kind")
            remaining -= entry["object"]["size"]
            manifest["sources"].append(entry)
    for item in args.cache:
        kind, path = item.split("=", 1)
        if kind not in CACHES or any(cache["kind"] == kind for cache in manifest["caches"]):
            raise ValueError("cache must be go, cargo or npm and appear once")
        directory = Path(path).resolve(strict=True)
        if not directory.is_dir() or output.is_relative_to(directory):
            raise ValueError("cache must be a separate prepared directory")
        if any((directory / name).exists() for name in ("credentials", "credentials.toml", ".npmrc", ".netrc", "_logs")):
            raise ValueError("prepare a cache without credentials, user configuration or request logs")
        with tempfile.TemporaryDirectory(dir=output) as work:
            archive = Path(work) / "cache.tar"
            expansion = archive_tree(directory, archive, min(args.object_limit_bytes, remaining))
            ref = retain(objects, archive)
            remaining -= ref["size"]
            manifest["caches"].append({"kind": kind, "object": ref, **expansion})
    for key in args.key:
        path = Path(key).resolve(strict=True)
        if not path.is_file() or not 0 < path.stat().st_size <= 1 << 20:
            raise ValueError("source signing key must be a public key under 1 MiB")
        with tempfile.TemporaryDirectory(dir=output) as work:
            temporary = Path(work)
            (temporary / "gnupg").mkdir(mode=0o700)
            data = command(["gpg", "--batch", "--no-options", "--with-colons", "--import-options", "show-only", "--dry-run", "--import", str(path)], temporary).decode()
        records = [line.split(":") for line in data.splitlines()]
        if any(fields[0] in ("sec", "ssb") for fields in records) or sum(fields[0] == "pub" for fields in records) != 1:
            raise ValueError("source signing key must contain exactly one public key and no secret key")
        fingerprint = next((fields[9] for fields in records if fields[0] == "fpr"), "")
        if not re.fullmatch(r"(?:[A-F0-9]{40}|[A-F0-9]{64})", fingerprint) or any(entry["fingerprint"] == fingerprint for entry in manifest["keys"]):
            raise ValueError("source signing key fingerprint is missing or repeated")
        # Copy across filesystems before retaining via a hard link.
        with tempfile.TemporaryDirectory(dir=output) as work:
            copy = Path(work) / "key"
            copy.write_bytes(path.read_bytes())
            ref = retain(objects, copy)
        remaining -= ref["size"]
        manifest["keys"].append({"fingerprint": fingerprint, "object": ref})
    if remaining < 0 or not set(plan["validpgpkeys"]).issubset({key["fingerprint"] for key in manifest["keys"]}):
        raise ValueError("source signing keys are incomplete or capture exceeds byte budget")
    manifest["caches"].sort(key=lambda value: value["kind"])
    manifest["keys"].sort(key=lambda value: value["fingerprint"])
    path = output / "manifest.json"
    data = canonical(manifest)
    if len(data) > 2 << 20 or len(data) > remaining:
        raise ValueError("source bundle exceeds metadata or transfer budget")
    path.write_bytes(data)
    reference = retain(objects, path)
    (output / "reference.json").write_bytes(canonical(reference))
    print(json.dumps({"reference": reference, "sources": len(manifest["sources"]), "caches": len(manifest["caches"]), "keys": len(manifest["keys"])}))


def self_test():
    for name in ("../escape", "-option", ".git", "a/b", "a\\b", ""):
        try:
            safe_name(name)
        except ValueError:
            continue
        raise AssertionError("unsafe source name accepted")
    for url in ("file:///tmp/input", "https://127.0.0.1/source", "https://user:pass@example.org/a", "https://example.org:444/a"):
        try:
            public_url(url)
        except ValueError:
            continue
        raise AssertionError("unsafe source URL accepted")
    resolve = socket.getaddrinfo
    try:
        socket.getaddrinfo = lambda *args, **kwargs: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443))]
        try:
            public_addresses("example.org")
        except ValueError:
            pass
        else:
            raise AssertionError("private DNS destination accepted")
    finally:
        socket.getaddrinfo = resolve
    with tempfile.TemporaryDirectory() as root:
        directory = Path(root)
        tree = directory / "cache"
        tree.mkdir()
        data = tree / "file with spaces"
        data.write_bytes(b"source bytes\0\xff")
        checksum_file(data, {"sha256": hashlib.sha256(data.read_bytes()).hexdigest(), "b2": "SKIP"})
        try:
            checksum_file(data, {"sha256": "0" * 64})
        except ValueError:
            pass
        else:
            raise AssertionError("changed source checksum accepted")
        first, second = directory / "a.tar", directory / "b.tar"
        assert archive_tree(tree, first, 1 << 20) == {"entries": 1, "expandedBytes": len(data.read_bytes())}
        archive_tree(tree, second, 1 << 20)
        assert first.read_bytes() == second.read_bytes()
        (tree / "escape").symlink_to("../outside")
        try:
            archive_tree(tree, directory / "unsafe.tar", 1 << 20)
        except ValueError:
            pass
        else:
            raise AssertionError("escaping source cache link accepted")
    print("recipe source capture self-check passed")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan")
    parser.add_argument("--output")
    parser.add_argument("--cache", action="append", default=[], metavar="KIND=DIRECTORY")
    parser.add_argument("--key", action="append", default=[], help="Explicit public source signing key")
    parser.add_argument("--object-limit-bytes", type=int, default=4 << 30)
    parser.add_argument("--transfer-limit-bytes", type=int, default=32 << 30)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
    elif not args.plan or not args.output or not 1 <= args.object_limit_bytes <= MAX_OBJECT or not 1 <= args.transfer_limit_bytes <= MAX_TRANSFER:
        parser.error("--plan, --output and bounded positive byte limits are required")
    else:
        capture(args)
