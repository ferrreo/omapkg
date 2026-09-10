#!/usr/bin/env python3
"""Native acceptance of pinned original asdcontrol; private bootstrap inputs only.

Requires Go, Git and Podman, and a locally pulled, digest-pinned native helper.
Source/package downloads happen during preparation; worker builds stay offline.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import tarfile
from urllib.parse import urlsplit

PROJECT = Path(__file__).resolve().parents[1]
REPOSITORY = "https://github.com/omacom/omarchy-pkgs"
COMMIT = "a44e2d2e49d01faa4d351e047bfa5632c2c21b1b"
RECIPE_SHA256 = "e28612f2405e8ab2d15ebf0fab120904202c06e0b539ce9dedb296fe8950ddc9"
ARCHIVE_SHA256 = "3112a6d5fc51a204c96ef9d27187577c6efc80b952e37a77969efbd0124e81d3"
URL = "https://github.com/omakasui/asdcontrol/archive/refs/tags/v0.6.0.tar.gz"


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def command(*args, **kwargs):
    return subprocess.run([str(arg) for arg in args], check=True, **kwargs)


def capture(root, image, helper_analysis):
    architecture = os.uname().machine
    assert architecture in ("x86_64", "aarch64"), "Native Linux host required"
    assert re.fullmatch(r"[a-z0-9./_:-]+@sha256:[a-f0-9]{64}", image), "Pinned helper required"
    root.mkdir(parents=True, exist_ok=False)
    recipe, sources, frozen = (root / name for name in ("recipe", "sources", "frozen"))
    frozen.mkdir()
    repo = root / "git"
    command("git", "init", repo)
    command("git", "-C", repo, "-c", "core.hooksPath=/dev/null", "fetch", "--depth=1", REPOSITORY, COMMIT)
    command("python3", PROJECT / "services/pipeline/capture-recipe.py", "--git-directory", repo,
            "--repository", REPOSITORY, "--commit", COMMIT, "--directory", "pkgbuilds/asdcontrol",
            "--pkgbase", "asdcontrol", "--origin", "omarchy", "--output", recipe)
    capture_ref = json.loads((recipe / "reference.json").read_text())
    tree = json.loads((recipe / "manifest.json").read_text())
    files = {item["path"]: item["object"] for item in tree["files"]}
    assert files["PKGBUILD"]["sha256"] == RECIPE_SHA256, "Pinned original recipe changed"
    recipe_text = (recipe / "objects" / RECIPE_SHA256).read_text()
    commit = (recipe / "objects" / tree["git"]["commit"]["sha256"]).read_text()
    epoch = int(re.search(r"^committer .* (\d+) [+-]\d{4}$", commit, re.MULTILINE)[1])
    environment = os.environ | {"OPR_WORKER_E2E_IMAGE": image, "OPR_WORKER_E2E_ARCH": architecture,
                                "OPR_WORKER_E2E_RUNTIME": "podman", "OPR_INSPECTION_E2E_CAPTURE": str(recipe)}
    command("go", "test", "-count=1", "-v", "-run", "^TestRetainedRecipeInspectionNativeOCI$", ".",
            cwd=PROJECT / "worker", env=environment)
    signed = json.loads((recipe / "native-inspection.json").read_text())
    report = json.loads(signed["report"])
    assert report["error"] is None and report["architecture"] == architecture and report["capture"] == capture_ref
    fields = {}
    for line in report["srcinfo"].splitlines():
        if line.strip():
            key, value = line.strip().split(" = ", 1)
            fields.setdefault(key, []).append(value)
    assert all(fields[key] == [value] for key, value in {"pkgbase": "asdcontrol", "pkgname": "asdcontrol",
                                                       "epoch": "1", "pkgver": "0.6.0", "pkgrel": "2"}.items())
    assert architecture in fields["arch"] and fields["depends"] == ["glibc", "gcc-libs"]
    assert fields["makedepends"] == ["make", "gcc"] and not fields.get("validpgpkeys")
    assert fields["source"] == ["asdcontrol-0.6.0.tar.gz::" + URL, "asdcontrol.sudoers"]
    assert fields["sha256sums"] == [ARCHIVE_SHA256, files["asdcontrol.sudoers"]["sha256"]]
    plan = {"schemaVersion": 1, "kind": "recipe-source-plan", "capture": capture_ref,
            "inspection": {"jobId": report["jobId"], "attempt": report["attempt"],
                           "reportSha256": hashlib.sha256(signed["report"].encode()).hexdigest(),
                           "srcinfoSha256": report["srcinfoSha256"]},
            "pkgbase": "asdcontrol", "version": "1:0.6.0-2", "architecture": architecture, "validpgpkeys": [],
            "sources": [{"kind": "file", "name": "asdcontrol-0.6.0.tar.gz", "source": fields["source"][0],
                         "url": URL, "checksums": {"sha256": ARCHIVE_SHA256}},
                        {"kind": "local", "name": "asdcontrol.sudoers", "path": "asdcontrol.sudoers",
                         "source": "asdcontrol.sudoers", "checksums": {"sha256": fields["sha256sums"][1]}}]}
    plan_path = root / "source-plan.json"
    plan_path.write_bytes(canonical(plan))
    command("python3", PROJECT / "services/pipeline/capture-recipe-sources.py", "--plan", plan_path, "--output", sources)
    archive = frozen / "helper.tar"
    # A digest-named export can retain the pre-conversion digest in its name.
    alias = "localhost/opr-preserved-helper:" + hashlib.sha256(str(root).encode()).hexdigest()[:16]
    command("podman", "tag", image, alias)
    try:
        command("podman", "save", "--format", "oci-archive", "--output", archive, alias)
    finally:
        command("podman", "untag", image, alias)
    with tarfile.open(archive, "r:") as retained:
        index = json.load(retained.extractfile("index.json"))
    helper = alias + "@" + index["manifests"][0]["digest"]
    with (frozen / "makepkg.conf").open("wb") as file:
        command("podman", "run", "--rm", "--read-only", "--network=none", "--cap-drop=ALL",
                "--security-opt=no-new-privileges", image, "cat", "/etc/makepkg.conf", stdout=file)
    mirror = "https://geo.mirror.pkgbuild.com/$repo/os/$arch" if architecture == "x86_64" else "https://fl.us.mirror.archlinuxarm.org/$arch/$repo"
    mirror_host = urlsplit(mirror).hostname
    (frozen / "resolver.conf").write_text(f"""[options]
Architecture = {architecture}
SigLevel = Required DatabaseOptional
LocalFileSigLevel = Required
GPGDir = /etc/pacman.d/gnupg
DownloadUser = root
DisableSandboxFilesystem
[core]
Server = {mirror}
[extra]
Server = {mirror}
""")
    command("podman", "run", "--rm", "--read-only", "--network=bridge", "--add-host", f"{mirror_host}:{socket.gethostbyname(mirror_host)}",
            "--cap-drop=ALL", "--cap-add=SETUID", "--cap-add=SETGID",
            "--security-opt=no-new-privileges", "--tmpfs", "/tmp:rw,nosuid,nodev,size=256m",
            "--mount", f"type=bind,src={frozen},dst=/capture",
            "--mount", f"type=bind,src={PROJECT / 'services/pipeline/capture-bootstrap-inputs.py'},dst=/capture.py,ro",
            image, "python3", "/capture.py", "--output", "/capture", "--architecture", architecture,
            "--helper-image", helper, "--helper-archive", "/capture/helper.tar", "--makepkg-config", "/capture/makepkg.conf",
            "--pacman-config", "/capture/resolver.conf", "--recipe-sha256", RECIPE_SHA256, "--cohort-sha256", "a" * 64,
            "--source-date-epoch", str(epoch), "--transfer-limit-bytes", str(16 << 30),
            "--build-packages", "base-devel", "namcap", "python", "python-pyelftools", "pacman", "git", *([] if helper_analysis else ["shellcheck"]),
            "--runtime-packages", "filesystem", "bash", "coreutils", "pacman", "glibc", "gcc-libs", *(["--helper-shell-analysis"] if helper_analysis else []))
    for directory in (recipe, sources):
        for path in (directory / "objects").iterdir():
            target = frozen / "objects" / path.name
            if not target.exists():
                os.link(path, target)
    job = {"id": "preserved-asdcontrol-native", "attempt": 1, "revisionId": "preserved-asdcontrol-revision",
           "packageName": "asdcontrol", "version": "0.6.0", "pkgrel": 2, "architecture": architecture,
           "recipe": recipe_text, "recipeSha256": RECIPE_SHA256, "sourceDateEpoch": epoch,
           "imageRef": helper, "imageDigest": helper.split("@")[-1], "inputLock": json.loads((frozen / "reference.json").read_text()),
           "outputContract": {"schemaVersion": 2, "cohort": {"id": "preserved-native-cohort", "revision": 1, "manifestSha256": "a" * 64},
                              "outputs": [{"name": "asdcontrol", "fullVersion": "1:0.6.0-2", "architecture": architecture}], "runtimeGroups": [["asdcontrol"]]},
           "surface": "binary", "sources": [], "preservedRecipe": {"capture": capture_ref, "sourceBundle": json.loads((sources / "reference.json").read_text())},
           "dependencies": ["glibc", "gcc-libs", "make", "gcc"], "runtimeDependencies": ["glibc", "gcc-libs"], "makeDependencies": ["make", "gcc"],
           "smokeCommands": ["asdcontrol --help", "test ! -x /usr/bin/gcc", "test ! -x /usr/bin/make"]}
    (frozen / "job.json").write_bytes(canonical(job))
    command("go", "test", "-count=1", "-v", "-run", "^TestRunnerPreservedRecipeNativeOCI$", ".", cwd=PROJECT / "worker",
            env=environment | {"OPR_PRESERVED_E2E_CAPTURE": str(frozen)})


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--helper-image", required=True)
    parser.add_argument("--helper-shell-analysis", action="store_true")
    args = parser.parse_args()
    capture(args.output.resolve(), args.helper_image, args.helper_shell_analysis)
