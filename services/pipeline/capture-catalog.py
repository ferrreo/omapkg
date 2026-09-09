#!/usr/bin/env python3
"""Capture repository metadata as inert data. Never execute recipes or install packages."""
import argparse
import base64
import hashlib
import io
import ipaddress
import json
from pathlib import Path
import re
import socket
import subprocess
import tarfile
import tempfile
from urllib.error import HTTPError
from urllib.parse import urlparse, urlencode, parse_qsl, quote
from urllib.request import HTTPRedirectHandler, Request, build_opener

MAX_DATABASE = 32 * 1024 * 1024
MAX_MEMBER = 512 * 1024
MAX_EXPANDED = 512 * 1024 * 1024
NAME = re.compile(r"^[a-z0-9][a-z0-9@._+-]{0,63}$")


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def digest(data):
    return hashlib.sha256(data).hexdigest()


def public_url(value):
    url = urlparse(value)
    if (url.scheme != "https" or not url.hostname or url.username or url.password
            or url.port or url.fragment or url.hostname.endswith(".")):
        raise ValueError("Use a public HTTPS repository origin without credentials, port or fragment")
    if any(re.search(r"token|secret|password|authorization|credential|signature", key, re.I) for key, _ in parse_qsl(url.query)):
        raise ValueError("Use a public HTTPS repository origin without credentials, query, port or fragment")
    for address in socket.getaddrinfo(url.hostname, 443, type=socket.SOCK_STREAM):
        if not ipaddress.ip_address(address[4][0]).is_global:
            raise ValueError("Repository resolves to a non-public address")
    return value


class PublicRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        public_url(newurl)
        return super().redirect_request(request, fp, code, msg, headers, newurl)


def download(url, maximum=MAX_DATABASE):
    public_url(url)
    with build_opener(PublicRedirect).open(Request(url, headers={"User-Agent": "omapkg-catalog-capture/1"}), timeout=60) as response:
        data = response.read(maximum + 1)
        if len(data) > maximum:
            raise ValueError("Repository object exceeds capture limit")
        return data


def fields(data):
    result = {}
    current = None
    for line in data.decode("utf-8", errors="strict").splitlines():
        if line.startswith("%") and line.endswith("%"):
            current = line[1:-1]
            if not re.fullmatch(r"[A-Z0-9_]+", current) or current in result:
                raise ValueError("Invalid or duplicate repository metadata field")
            result[current] = []
        elif line:
            if current is None or "\x00" in line:
                raise ValueError("Invalid repository metadata")
            result[current].append(line)
    return result


def parse_database(path, source):
    # libarchive handles the existing gzip/xz/zstd formats; tarfile supplies framing.
    process = subprocess.Popen(["bsdtar", "-cf", "-", "--format=ustar", "@" + str(path)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    packages = {}
    expanded = 0
    try:
        with tarfile.open(fileobj=process.stdout, mode="r|") as archive:
            for member in archive:
                if member.isdir():
                    continue
                parts = member.name.split("/")
                if not member.isfile() or len(parts) != 2 or parts[0] in ("", ".", "..") or parts[1] not in ("desc", "depends"):
                    raise ValueError("Repository archive contains an unexpected entry")
                if member.size < 0 or member.size > MAX_MEMBER:
                    raise ValueError("Repository metadata entry exceeds limit")
                expanded += member.size
                if expanded > MAX_EXPANDED or len(packages) > 100000:
                    raise ValueError("Expanded repository exceeds capture budget")
                try:
                    metadata = fields(archive.extractfile(member).read(MAX_MEMBER + 1))
                except ValueError as error:
                    raise ValueError(f"{member.name}: {error}") from error
                target = packages.setdefault(parts[0], {})
                if any(key in target and target[key] != value for key, value in metadata.items()):
                    raise ValueError("Conflicting package metadata")
                target.update(metadata)
        if process.wait(timeout=30) != 0:
            raise ValueError("Repository archive could not be decoded")
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()
        process.stdout.close()
        process.stderr.close()
    entries = []
    names = set()
    for metadata in packages.values():
        def one(key, fallback=None):
            values = metadata.get(key, [])
            if len(values) != 1:
                if not values and fallback is not None:
                    return fallback
                raise ValueError("Package metadata needs one " + key)
            return values[0]
        name = one("NAME")
        pkgbase = one("BASE", name)
        arch = one("ARCH")
        sha = one("SHA256SUM")
        if not NAME.fullmatch(name) or not NAME.fullmatch(pkgbase) or name in names or arch not in (source["target"], "any") or not re.fullmatch(r"[a-f0-9]{64}", sha):
            raise ValueError("Invalid package identity, architecture, duplicate or digest")
        names.add(name)
        signature = one("PGPSIG", "") or None
        if signature:
            base64.b64decode(signature, validate=True)
        entries.append({
            "sourceId": source["id"], "name": name, "pkgbase": pkgbase, "version": one("VERSION"),
            "architecture": arch, "target": source["target"], "collection": source["collection"],
            "filename": one("FILENAME"), "sha256": sha, "size": int(one("CSIZE")), "installedSize": int(one("ISIZE", "0")),
            "description": one("DESC", ""), "upstreamUrl": one("URL", "") or None, "licenses": metadata.get("LICENSE", []),
            "dependencies": metadata.get("DEPENDS", []), "makeDependencies": metadata.get("MAKEDEPENDS", []),
            "checkDependencies": metadata.get("CHECKDEPENDS", []), "provides": metadata.get("PROVIDES", []),
            "conflicts": metadata.get("CONFLICTS", []), "replaces": metadata.get("REPLACES", []), "packageSignature": signature,
        })
    return sorted(entries, key=lambda entry: entry["name"])


def recipe_catalog(source, output):
    origin = urlparse(source["url"])
    pages, entries, cursors = [], [], set()
    url = source["url"]
    while url:
        body = json.loads(download(url))
        if not isinstance(body.get("items"), list) or len(body["items"]) > 100:
            raise ValueError("Invalid OPR recipe catalog page")
        pages.append(body)
        for item in body["items"]:
            if item.get("surface") != "recipe" or item.get("architecture") != source["target"] or not NAME.fullmatch(item.get("name", "")):
                raise ValueError("OPR recipe identity or target mismatch")
            recipe_url = item["recipeUrl"]
            if urlparse(recipe_url).netloc != origin.netloc or not urlparse(recipe_url).path.endswith("/PKGBUILD"):
                raise ValueError("OPR recipe is outside its captured origin")
            recipe = download(recipe_url, 2 * 1024 * 1024)
            recipe_sha = digest(recipe)
            (output / ("recipe-" + recipe_sha + ".PKGBUILD")).write_bytes(recipe)
            detail_url = f"{origin.scheme}://{origin.netloc}/api/catalog/{quote(item['name'])}?" + urlencode({"channel": item["channel"]})
            details = json.loads(download(detail_url))
            version = next((entry for entry in details.get("versions", []) if entry.get("id") == item["id"]), None)
            if version is None:
                raise ValueError("Recipe changed while its catalog was captured")
            entries.append({
                "sourceId": source["id"], "name": item["name"], "pkgbase": item["name"], "version": item["version"],
                "architecture": source["target"], "target": source["target"], "collection": source["collection"],
                "filename": "PKGBUILD", "sha256": recipe_sha, "size": len(recipe), "installedSize": 0,
                "description": item.get("description", ""), "upstreamUrl": item.get("source", {}).get("upstreamUrl"),
                "licenses": [item.get("license", "unknown")], "dependencies": version.get("dependencies", []),
                "makeDependencies": [], "checkDependencies": [], "provides": [], "conflicts": [], "replaces": [],
                "packageSignature": None, "surface": "recipe", "recipeUrl": recipe_url,
            })
        cursor = body.get("nextCursor")
        if not cursor:
            break
        if not isinstance(cursor, str) or len(cursor) > 2048 or cursor in cursors or len(pages) > 1000:
            raise ValueError("Invalid or cyclic recipe catalog pagination")
        cursors.add(cursor)
        url = source["url"] + "&" + urlencode({"cursor": cursor})
    if len({entry["name"] for entry in entries}) != len(entries):
        raise ValueError("Recipe catalog changed or repeated an identity during capture")
    return canonical({"pages": pages}).encode(), entries


def source_specs(kind, channel, architectures, opr_origin=None, opr_layout="omapkg"):
    specs = []
    for arch in architectures:
        repos = ["core", "extra"] + (["multilib"] if arch == "x86_64" else [])
        if kind == "opr":
            if not opr_origin:
                raise ValueError("An OPR origin is required")
            if opr_layout == "omarchy":
                url = f"{opr_origin.rstrip('/')}/{channel}/{arch}/omarchy.db"
                collection = "omarchy"
            else:
                prefix = "/repo" + ("/dev" if channel == "dev" else "")
                url = f"{opr_origin.rstrip('/')}{prefix}/{arch}/opr.db"
                collection = "omapkg"
            specs.append({"id": f"opr-{channel}-{arch}", "url": url, "collection": collection, "target": arch})
            if opr_layout == "omapkg":
                api_url = opr_origin.rstrip("/") + "/api/catalog?" + urlencode({"channel": channel, "architecture": arch, "surface": "recipe", "limit": 100})
                specs.append({"id": f"opr-{channel}-recipes-{arch}", "url": api_url, "collection": collection, "target": arch, "format": "recipe-catalog"})
        else:
            for repo in repos:
                if kind == "arch":
                    url = f"https://geo.mirror.pkgbuild.com/{repo}/os/{arch}/{repo}.db" if arch == "x86_64" else f"https://fl.us.mirror.archlinuxarm.org/aarch64/{repo}/{repo}.db"
                else:
                    host = "mirror.omarchy.org" if channel == "edge" else f"{channel}-mirror.omarchy.org"
                    url = f"https://{host}/{repo}/os/{arch}/{repo}.db"
                specs.append({"id": f"{kind}-{channel}-{repo}-{arch}", "url": url, "collection": repo, "target": arch})
            if kind == "omarchy":
                specs.append({"id": f"omarchy-{channel}-packages-{arch}", "url": f"https://pkgs.omarchy.org/{channel}/{arch}/omarchy.db", "collection": "omarchy", "target": arch})
    return specs


def capture(specs, output, keyring=None):
    output.mkdir(parents=True, exist_ok=True)
    sources, entries = [], []
    for spec in specs:
        source = {**spec, "status": "unavailable", "sha256": None, "entries": 0, "signature": "unverified", "signatureSha256": None, "error": None}
        try:
            if spec.get("format") == "recipe-catalog":
                data, parsed = recipe_catalog(spec, output)
            else:
                data, parsed = download(spec["url"]), None
            path = output / (spec["id"] + ".db")
            path.write_bytes(data)
            source["sha256"] = digest(data)
            if parsed is None:
                parsed = parse_database(path, spec)
            source.update(status="captured", sha256=digest(data), entries=len(parsed))
            try:
                if spec.get("format") == "recipe-catalog":
                    raise HTTPError(spec["url"], 404, "Catalog has per-recipe evidence", {}, None)
                signature = download(spec["url"] + ".sig", 1024 * 1024)
                signature_path = output / (spec["id"] + ".db.sig")
                signature_path.write_bytes(signature)
                source["signatureSha256"] = digest(signature)
                if keyring:
                    result = subprocess.run(["gpgv", "--keyring", str(keyring), str(signature_path), str(path)], capture_output=True, timeout=30)
                    source["signature"] = "verified" if result.returncode == 0 else "failed"
            except HTTPError as error:
                source["signature"] = "missing" if error.code == 404 else "unverified"
            except (ValueError, OSError, subprocess.SubprocessError):
                source["signature"] = "unverified"
            entries.extend(parsed)
        except Exception as error:
            source.update(status="unavailable", entries=0, error=f"{type(error).__name__}: {error}"[:2000])
        sources.append(source)
        print(canonical({"source": spec["id"], "status": source["status"], "entries": source["entries"]}), flush=True)
    return sources, sorted(entries, key=lambda entry: (entry["sourceId"], entry["name"]))


def self_test():
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "repo.db"
        data = b"%NAME%\nexample\n\n%VERSION%\n1.0-1\n\n%ARCH%\nany\n\n%SHA256SUM%\n" + b"a" * 64 + b"\n\n%FILENAME%\nexample-1.0-1-any.pkg.tar.zst\n\n%CSIZE%\n10\n"
        with tarfile.open(path, "w:gz") as archive:
            member = tarfile.TarInfo("example-1.0-1/desc"); member.size = len(data)
            archive.addfile(member, io.BytesIO(data))
        source = {"id": "test", "collection": "extra", "target": "aarch64"}
        result = parse_database(path, source)
        assert result[0]["architecture"] == "any" and result[0]["target"] == "aarch64"
        with tarfile.open(path, "w:gz") as archive:
            member = tarfile.TarInfo("../desc"); member.size = len(data)
            archive.addfile(member, io.BytesIO(data))
        try:
            parse_database(path, source)
            raise AssertionError("unsafe archive accepted")
        except ValueError:
            pass
    assert len(source_specs("arch", "upstream", ["x86_64", "aarch64"])) == 5
    print("Capture parser checks passed")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", choices=["arch", "omarchy", "opr"])
    parser.add_argument("--channel", choices=["upstream", "stable", "rc", "edge", "dev"], default="stable")
    parser.add_argument("--arch", choices=["all", "x86_64", "aarch64"], default="all")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--opr-origin")
    parser.add_argument("--opr-layout", choices=["omapkg", "omarchy"], default="omapkg")
    parser.add_argument("--keyring", type=Path)
    parser.add_argument("--describe", action="store_true")
    parser.add_argument("--only-source")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test(); return
    if not args.source or (not args.output and not args.describe):
        parser.error("--source and --output are required")
    channel = "upstream" if args.source == "arch" else args.channel
    if args.source == "omarchy" and channel not in ("stable", "rc", "edge"):
        parser.error("Omarchy capture uses stable, rc or edge")
    if args.source == "opr" and args.opr_layout == "omapkg" and channel not in ("stable", "dev"):
        parser.error("Existing omapkg repositories use stable or dev")
    architectures = ["x86_64", "aarch64"] if args.arch == "all" else [args.arch]
    specs = source_specs(args.source, channel, architectures, args.opr_origin, args.opr_layout)
    if args.describe:
        print(canonical(specs)); return
    if args.only_source:
        specs = [source for source in specs if source["id"] == args.only_source]
        if not specs: parser.error("Unknown source identity")
    sources, entries = capture(specs, args.output, args.keyring)
    index = [[entry["sourceId"], entry["name"], digest(canonical(entry).encode())] for entry in entries]
    manifest = {"schemaVersion": 1, "kind": args.source, "channel": channel, "sources": sorted(sources, key=lambda source: source["id"]), "entriesSha256": digest(canonical(index).encode())}
    (args.output / "capture.json").write_text(canonical({"manifest": manifest, "entries": entries}) + "\n")
    (args.output / "manifest.json").write_text(canonical(manifest) + "\n")
    (args.output / "index.json").write_text(canonical(index) + "\n")
    for offset in range(0, len(entries), 100):
        (args.output / f"entries-{offset // 100:05}.json").write_text(canonical(entries[offset:offset + 100]) + "\n")
    print(canonical({"capture": str(args.output / "capture.json"), "packages": len(entries), "unavailableSources": sum(source["status"] != "captured" for source in sources)}))


if __name__ == "__main__":
    main()
