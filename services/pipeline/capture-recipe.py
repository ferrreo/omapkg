#!/usr/bin/env python3
"""Retain an exact Git recipe directory and Merkle proof. Never evaluate recipes."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
from urllib.parse import urlparse

MAX_FILES = 2048
MAX_BYTES = 32 * 1024 * 1024
EMPTY_SHA = hashlib.sha256(b"").hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def safe_path(value, empty=False):
    if empty and value == "":
        return value
    if len(value.encode()) > 512 or re.search(r"[\x00-\x1f\x7f\\]", value) or any(not part or part in (".", "..") or part.lower() == ".git" for part in value.split("/")):
        raise ValueError("Unsafe recipe path: " + value)
    return value


def git(directory, *args, limit=MAX_BYTES):
    env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL="/dev/null", GIT_TERMINAL_PROMPT="0", GIT_LFS_SKIP_SMUDGE="1")
    result = subprocess.run(["git", "-C", str(directory), "-c", "core.hooksPath=/dev/null", "-c", "protocol.file.allow=never", "-c", "submodule.recurse=false", *args],
                            env=env, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=180)
    if len(result.stdout) > limit:
        raise ValueError("Git object exceeds capture budget")
    return result.stdout


def tree_entries(raw):
    entries = []
    offset = 0
    while offset < len(raw):
        space = raw.index(b" ", offset)
        end = raw.index(b"\0", space)
        mode = raw[offset:space].decode("ascii")
        name = raw[space + 1:end].decode("utf-8")
        oid = raw[end + 1:end + 21]
        if len(oid) != 20:
            raise ValueError("Truncated Git tree")
        entries.append((mode, name, oid.hex()))
        offset = end + 21
    return entries


def capture(directory, repository, commit, subdir, pkgbase, origin, output):
    parsed = urlparse(repository)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("Recipe repository must be a public HTTPS Git URL")
    if not re.fullmatch(r"[a-f0-9]{40}", commit) or not re.fullmatch(r"[a-z0-9][a-z0-9@._+-]{0,63}", pkgbase):
        raise ValueError("An immutable SHA-1 Git commit and package base are required")
    safe_path(subdir, empty=True)
    output.mkdir(parents=True, exist_ok=False)
    objects = output / "objects"
    objects.mkdir()

    def retain(data):
        digest = hashlib.sha256(data).hexdigest()
        if data:
            (objects / digest).write_bytes(data)
        return {"sha256": digest, "size": len(data)}

    def object_bytes(kind, oid, limit):
        size = int(git(directory, "cat-file", "-s", oid, limit=100))
        if size > limit:
            raise ValueError("Git object exceeds capture budget")
        raw = git(directory, "cat-file", kind, oid, limit=limit)
        actual = hashlib.sha1(f"{kind} {len(raw)}\0".encode() + raw).hexdigest()
        if actual != oid or len(raw) != size:
            raise ValueError("Git object changed during capture")
        return raw

    raw_commit = object_bytes("commit", commit, 128 * 1024)
    first = raw_commit.split(b"\n", 1)[0]
    if not re.fullmatch(rb"tree [a-f0-9]{40}", first):
        raise ValueError("Commit has no canonical root tree")
    trees = {}
    proof_size = len(raw_commit)

    def tree(oid):
        nonlocal proof_size
        if oid not in trees:
            raw = object_bytes("tree", oid, 1024 * 1024)
            proof_size += len(raw)
            if proof_size > 4 * 1024 * 1024 or len(trees) >= 512:
                raise ValueError("Git proof exceeds metadata budget")
            trees[oid] = (retain(raw), tree_entries(raw))
        return trees[oid][1]

    root = first[5:].decode()
    for part in subdir.split("/") if subdir else []:
        candidates = [entry for entry in tree(root) if entry[1] == part and entry[0] == "40000"]
        if len(candidates) != 1:
            raise ValueError("Recipe directory is absent from commit")
        root = candidates[0][2]
    files = []
    total = 0

    def walk(oid, prefix=""):
        nonlocal total
        for mode, name, blob in tree(oid):
            path = safe_path(prefix + name)
            if mode == "40000":
                walk(blob, path + "/")
                continue
            if mode not in ("100644", "100755", "120000"):
                raise ValueError("Recipe submodules or special files require separate handling: " + path)
            data = object_bytes("blob", blob, MAX_BYTES - total)
            total += len(data)
            if len(files) >= MAX_FILES:
                raise ValueError("Recipe has too many files")
            files.append({"path": path, "mode": mode, "object": retain(data)})

    walk(root)
    if not any(file["path"] == "PKGBUILD" and file["mode"] in ("100644", "100755") and file["object"]["size"] for file in files):
        raise ValueError("Recipe directory has no regular PKGBUILD")
    manifest = {"schemaVersion": 1, "kind": "recipe-capture", "pkgbase": pkgbase, "origin": origin, "repository": repository,
                "commit": commit, "directory": subdir, "git": {"commit": retain(raw_commit), "trees": sorted([item[0] for item in trees.values()], key=lambda item: item["sha256"])},
                "files": sorted(files, key=lambda file: file["path"])}
    raw = canonical(manifest)
    ref = retain(raw)
    (output / "manifest.json").write_bytes(raw)
    (output / "reference.json").write_bytes(canonical(ref))
    return {"reference": ref, "files": len(files), "bytes": total, "pkgbase": pkgbase}


def self_test():
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        repo = root / "repo"
        repo.mkdir()
        git(repo, "init")
        (repo / "recipe").mkdir()
        recipe = b"pkgname=demo\n# Never evaluated: $(touch /should-not-exist)\n"
        (repo / "recipe/PKGBUILD").write_bytes(recipe)
        (repo / "recipe/empty").touch()
        (repo / "recipe/patch").write_bytes(bytes([0, 128, 255]))
        git(repo, "add", ".")
        git(repo, "-c", "user.name=Capture test", "-c", "user.email=test@example.invalid", "commit", "-m", "Fixture")
        commit = git(repo, "rev-parse", "HEAD").decode().strip()
        first = capture(repo, "https://github.com/example/recipes", commit, "recipe", "demo", "opr", root / "first")
        second = capture(repo, "https://github.com/example/recipes", commit, "recipe", "demo", "opr", root / "second")
        assert first == second and first["files"] == 3
        assert (root / "first/objects" / hashlib.sha256(recipe).hexdigest()).read_bytes() == recipe
        assert not (root / "first/objects" / EMPTY_SHA).exists()
        for path in ("../outside", "a//b", ".git/config", "a/./b"):
            try:
                safe_path(path)
            except ValueError:
                continue
            raise AssertionError(path)
    print("recipe capture self-test passed")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--git-directory", type=Path)
    parser.add_argument("--repository")
    parser.add_argument("--commit")
    parser.add_argument("--directory", default="")
    parser.add_argument("--pkgbase")
    parser.add_argument("--origin", choices=("arch", "omarchy", "opr", "aur-reference", "alarm-reference"))
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.self_test:
        return self_test()
    if not all((args.git_directory, args.repository, args.commit, args.pkgbase, args.origin, args.output)):
        parser.error("--git-directory, --repository, --commit, --pkgbase, --origin and --output are required")
    print(json.dumps(capture(args.git_directory, args.repository, args.commit, args.directory, args.pkgbase, args.origin, args.output)))


if __name__ == "__main__":
    main()
