#!/usr/bin/env python3
"""Capture exact Arch recipe tags from a sealed inventory, without executing recipes.

Each attempt is retained separately. Resume the same output directory after an
interruption; --retry-failed creates new attempts for recorded source gaps.
"""
import argparse
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from datetime import datetime, timezone
import fcntl
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("recipe_capture", Path(__file__).with_name("capture-recipe.py"))
recipe_capture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(recipe_capture)
canonical = recipe_capture.canonical


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def project_path(name):
    # Same canonical mapping as Arch devtools' gitlab_project_name_to_path.
    name = re.sub(r"([a-zA-Z0-9]+)\+([a-zA-Z]+)", r"\1-\2", name).replace("+", "plus")
    name = re.sub(r"[_-]{2,}", "-", re.sub(r"[^a-zA-Z0-9_.-]", "-", name))
    return "unix-tree" if name == "tree" else name


def version_tag(version):
    return version.replace(":", "-", 1).replace("~", ".")


def rate_limit(repository):
    request = urllib.request.Request(repository + ".git/info/refs?service=git-upload-pack", method="HEAD")
    try:
        try:
            response = urllib.request.urlopen(request, timeout=20)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            return {"status": response.status, "retryAt": max(int(time.time()) + max(60, int(response.headers.get("Retry-After", "60"))),
                                                            int(response.headers.get("Ratelimit-Reset", "0"))),
                    "headers": {key: value for key, value in response.headers.items() if "ratelimit" in key.lower() or key.lower() == "retry-after"}}
    except (OSError, ValueError):
        return {"status": 429, "retryAt": int(time.time()) + 60}


def tasks_for(catalog, selected):
    manifest = json.loads((catalog / "manifest.json").read_text())
    if manifest.get("schemaVersion") != 1 or manifest.get("kind") != "arch":
        raise ValueError("Use a captured Arch inventory")
    rows = []
    for chunk in sorted(catalog.glob("entries-*.json")):
        if chunk.stat().st_size > 8 << 20:
            raise ValueError("Inventory chunk exceeds 8 MiB")
        rows.extend(json.loads(chunk.read_text()))
        if len(rows) > 100000:
            raise ValueError("Inventory exceeds 100,000 records")
    index = sorted([[row["sourceId"], row["name"], digest(row)] for row in rows])
    if not rows or digest(index) != manifest["entriesSha256"] or len({tuple(row[:2]) for row in index}) != len(rows):
        raise ValueError("Inventory entries differ from the sealed index")
    source_ids = [source["id"] for source in manifest["sources"] if source["target"] == "x86_64"]
    groups = {}
    for row in rows:
        if row["sourceId"] not in source_ids:
            continue
        base, version = row["pkgbase"], row["version"]
        if row["target"] != "x86_64" or not re.fullmatch(r"[a-z0-9][a-z0-9@._+-]{0,63}", base) or not isinstance(version, str) or len(version) > 128:
            raise ValueError("Invalid captured Arch package identity")
        if selected and base not in selected:
            continue
        groups.setdefault((base, version), []).append({"sourceId": row["sourceId"], "name": row["name"], "entrySha256": digest(row)})
    if selected and selected - {base for base, _ in groups}:
        raise ValueError("Selected package base is absent from the captured Arch targets")
    priority = {source["id"]: {"core": 0, "extra": 1, "multilib": 2}.get(source.get("collection"), 3) for source in manifest["sources"]}
    ordered = sorted(groups.items(), key=lambda item: (min(priority[row["sourceId"]] for row in item[1]), item[0]))
    tasks = [{"pkgbase": base, "version": version, "entries": sorted(entries, key=lambda row: (row["sourceId"], row["name"]))}
             for (base, version), entries in ordered]
    request = {"schemaVersion": 1, "kind": "arch-recipe-capture-run", "catalogManifestSha256": digest(manifest),
               "entriesSha256": manifest["entriesSha256"], "sourceIds": sorted(source_ids), "packages": sorted(selected),
               "unavailableSources": [source for source in manifest["sources"] if source["target"] == "x86_64" and source["status"] != "captured"],
               "tasks": len(tasks), "records": sum(len(task["entries"]) for task in tasks)}
    return request, tasks


def capture_one(root, task, attempt):
    task_id = digest(task)
    destination = root / "captures" / task_id / str(attempt)
    destination.parent.mkdir(parents=True, exist_ok=True)
    repository = "https://gitlab.archlinux.org/archlinux/packaging/packages/" + project_path(task["pkgbase"])
    tag = "refs/tags/" + version_tag(task["version"])
    result = {"task": task, "attempt": attempt, "repository": repository, "tag": tag,
              "startedAt": datetime.now(timezone.utc).isoformat(), "status": "failed"}
    try:
        with tempfile.TemporaryDirectory(prefix=task["pkgbase"] + "-", dir=root / "git-work") as temporary:
            repo = Path(temporary)
            git = lambda *args: recipe_capture.git(repo, "-c", "credential.helper=", "-c", "init.templateDir=", "-c", "http.followRedirects=false", "-c", "protocol.version=0", *args)
            git("init", "--bare")
            git("check-ref-format", tag)
            git("fetch", "--depth=1", "--no-tags", repository + ".git", tag)
            commit = git("rev-parse", "FETCH_HEAD^{commit}").decode().strip()
            captured = recipe_capture.capture(repo, repository, commit, "", task["pkgbase"], "arch", destination)
            ref = git("rev-parse", "FETCH_HEAD").decode().strip()
            kind = git("cat-file", "-t", ref).decode().strip()
            if kind not in ("tag", "commit"):
                raise ValueError("Version ref is not a Git tag or commit")
            raw = recipe_capture.git(repo, "cat-file", kind, ref, limit=128 * 1024)
            if hashlib.sha1(f"{kind} {len(raw)}\0".encode() + raw).hexdigest() != ref:
                raise ValueError("Git version ref changed during capture")
            if kind == "tag" and not raw.startswith(f"object {commit}\ntype commit\n".encode()):
                raise ValueError("Version tag does not directly identify the captured commit")
            tag_ref = {"sha256": hashlib.sha256(raw).hexdigest(), "size": len(raw)}
            (destination / "objects" / tag_ref["sha256"]).write_bytes(raw)
            result.update(status="captured", commit=commit, capture=captured, versionRef={"gitSha1": ref, "kind": kind, "object": tag_ref})
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        detail = error.stderr.decode(errors="replace") if isinstance(error, subprocess.CalledProcessError) and error.stderr else str(error)
        result["error"] = detail[:4000]
    result["finishedAt"] = datetime.now(timezone.utc).isoformat()
    directory = root / "results" / task_id
    directory.mkdir(parents=True, exist_ok=True)
    with (directory / f"{attempt:05}.json").open("xb") as file:
        file.write(canonical(result))
    return result


def run(args):
    request, tasks = tasks_for(args.catalog, set(args.pkgbase or []))
    root = args.output.resolve()
    if root.exists() and any(root.iterdir()) and not (root / "request.json").is_file():
        raise ValueError("Output is not an existing recipe capture run")
    root.mkdir(parents=True, exist_ok=True)
    with (root / ".lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        path = root / "request.json"
        if path.exists():
            if path.read_bytes() != canonical(request):
                raise ValueError("Capture scope changed; use a new output directory")
        else:
            path.write_bytes(canonical(request))
        (root / "git-work").mkdir(exist_ok=True)
        cooldown = root / "rate-limit.json"
        if cooldown.exists() and json.loads(cooldown.read_text())["retryAt"] > time.time():
            raise ValueError("Upstream requested a cooldown; retry after the time in rate-limit.json")
        work, results = [], {}
        for task in tasks:
            task_id = digest(task)
            attempts = sorted((root / "results" / task_id).glob("*.json"))
            last = json.loads(attempts[-1].read_text()) if attempts else None
            if last and last["task"] != task:
                raise ValueError("Stored recipe capture scope differs")
            if last:
                results[task_id] = last
            if not last or (args.retry_failed and last["status"] == "failed"):
                previous = [int(path.stem) for path in attempts]
                previous.extend(int(path.name) for path in (root / "captures" / task_id).glob("*") if path.is_dir() and path.name.isdigit())
                work.append((task, max(previous, default=0) + 1))
                results.pop(task_id, None)

        def progress(stopped=False):
            counts = {status: sum(row["status"] == status for row in results.values()) for status in ("captured", "failed")}
            value = {"tasks": len(tasks), "records": request["records"], **counts, "pending": len(tasks) - len(results),
                     "stopped": stopped, "intervalSeconds": args.interval, "updatedAt": datetime.now(timezone.utc).isoformat()}
            temporary = root / "progress.tmp"
            temporary.write_bytes(canonical(value))
            temporary.replace(root / "progress.json")
            print(json.dumps(value), flush=True)

        progress()
        iterator = iter(work)
        with ThreadPoolExecutor(max_workers=args.jobs) as executor:
            pending = {}
            last_start = 0.0

            def submit(task, attempt):
                nonlocal last_start
                time.sleep(max(0, args.interval - (time.monotonic() - last_start)))
                last_start = time.monotonic()
                return executor.submit(capture_one, root, task, attempt)

            for _ in range(min(args.jobs, len(work))):
                task, attempt = next(iterator)
                pending[submit(task, attempt)] = task
            stopped = False
            while pending:
                finished, _ = wait(pending, return_when=FIRST_COMPLETED)
                for future in finished:
                    task = pending.pop(future)
                    result = future.result()
                    results[digest(task)] = result
                    if result["status"] == "failed" and re.search(r"(?:HTTP|error:)\s*429\b", result["error"], re.IGNORECASE):
                        if not stopped:
                            cooldown.write_bytes(canonical(rate_limit(result["repository"])))
                        stopped = True
                    item = next(iterator, None) if not stopped else None
                    if item:
                        pending[submit(*item)] = item[0]
                    if len(results) % 10 == 0 or not pending:
                        progress(stopped)
        return 1 if stopped else 0


def self_test():
    assert project_path("libsigc++") == "libsigcplusplus"
    assert project_path("foo+bar++") == "foo-barplusplus"
    assert project_path("tree") == "unix-tree"
    assert project_path("a__b--c") == "a-b-c"
    assert version_tag("2:1.4~rc1-3.2") == "2-1.4.rc1-3.2"
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        rows = [{"pkgbase": "demo", "name": "demo", "version": "1.0-1", "target": "x86_64", "sourceId": "arch-extra-x86_64"},
                {"pkgbase": "demo", "name": "demo-docs", "version": "1.0-1", "target": "x86_64", "sourceId": "arch-extra-x86_64"}]
        manifest = {"schemaVersion": 1, "kind": "arch", "sources": [{"id": "arch-extra-x86_64", "target": "x86_64", "status": "captured"}],
                    "entriesSha256": digest(sorted([[row["sourceId"], row["name"], digest(row)] for row in rows]))}
        (root / "manifest.json").write_bytes(canonical(manifest))
        (root / "entries-00000.json").write_bytes(canonical(rows))
        request, tasks = tasks_for(root, set())
        assert request["records"] == 2 and request["tasks"] == 1 and len(tasks[0]["entries"]) == 2
        rows[0]["version"] = "2.0-1"
        (root / "entries-00000.json").write_bytes(canonical(rows))
        try:
            tasks_for(root, set())
        except ValueError:
            pass
        else:
            raise AssertionError("Accepted changed catalog index")
    print("Arch recipe capture self-check passed")


if __name__ == "__main__":
    if sys.argv[1:] == ["--self-test"]:
        self_test()
    else:
        parser = argparse.ArgumentParser(description=__doc__)
        parser.add_argument("--catalog", type=Path, required=True)
        parser.add_argument("--output", type=Path, required=True)
        parser.add_argument("--pkgbase", action="append")
        parser.add_argument("--retry-failed", action="store_true")
        parser.add_argument("--jobs", type=int, choices=range(1, 9), default=4)
        parser.add_argument("--interval", type=int, choices=range(1, 61), default=3, help="Seconds between repository fetches")
        sys.exit(run(parser.parse_args()))
