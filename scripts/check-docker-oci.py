#!/usr/bin/env python3
"""Check cold OCI loading and digest lookup without pulling or executing an image."""

import hashlib
import io
import json
import platform
import subprocess
import tarfile
import tempfile
import uuid
from pathlib import Path


def encode(value):
    data = json.dumps(value, separators=(",", ":")).encode()
    return data, "sha256:" + hashlib.sha256(data).hexdigest()


architecture = {"aarch64": "arm64", "x86_64": "amd64"}[platform.machine()]
config, config_sha = encode({"architecture": architecture, "os": "linux", "config": {}, "rootfs": {"type": "layers", "diff_ids": []}})
manifest, manifest_sha = encode({"schemaVersion": 2, "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
    "config": {"mediaType": "application/vnd.docker.container.image.v1+json", "digest": config_sha, "size": len(config)}, "layers": []})
reference = "localhost/opr-oci-check-" + uuid.uuid4().hex + "@" + manifest_sha
index, _ = encode({"schemaVersion": 2, "manifests": [{"mediaType": "application/vnd.docker.distribution.manifest.v2+json",
    "digest": manifest_sha, "size": len(manifest), "annotations": {"org.opencontainers.image.ref.name": reference}}]})
files = {"oci-layout": b'{"imageLayoutVersion":"1.0.0"}', "index.json": index,
    "blobs/sha256/" + config_sha[7:]: config, "blobs/sha256/" + manifest_sha[7:]: manifest}
with tempfile.TemporaryDirectory(prefix="opr-oci-check-") as directory:
    archive = Path(directory) / "image.tar"
    with tarfile.open(archive, "w") as output:
        for name, data in files.items():
            entry = tarfile.TarInfo(name)
            entry.size = len(data)
            output.addfile(entry, io.BytesIO(data))
    try:
        subprocess.run(["docker", "load", "-i", str(archive)], check=True, timeout=30, stdout=subprocess.DEVNULL)
        image = json.loads(subprocess.check_output(["docker", "image", "inspect", reference], timeout=30))[0]
        assert image["Architecture"] == architecture and reference in image["RepoDigests"], "OCI reference or architecture changed"
    finally:
        subprocess.run(["docker", "image", "rm", reference], timeout=30, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
print("Cold OCI import and exact digest lookup passed")
