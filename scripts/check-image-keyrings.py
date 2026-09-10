#!/usr/bin/env python3
"""Reject package-manager private keys in every layer of a saved image."""
import argparse
import io
import json
from pathlib import Path
import tarfile
import tempfile


def check(path):
    with tarfile.open(path, "r:*") as image:
        names = set(image.getnames())
        if "index.json" in names:
            index = json.load(image.extractfile("index.json"))
            if len(index["manifests"]) != 1:
                raise ValueError("Expected one retained helper image")
            manifest = json.load(image.extractfile("blobs/sha256/" + index["manifests"][0]["digest"].split(":")[1]))
            layers = ["blobs/sha256/" + layer["digest"].split(":")[1] for layer in manifest["layers"]]
        else:
            manifest = json.load(image.extractfile("manifest.json"))
            if len(manifest) != 1:
                raise ValueError("Expected one retained helper image")
            layers = manifest[0]["Layers"]
        for name in layers:
            with tarfile.open(fileobj=image.extractfile(name), mode="r|*") as layer:
                for member in layer:
                    path = member.name.removeprefix("./").lstrip("/")
                    if member.isfile() and path.startswith(("etc/pacman.d/gnupg/private-keys-v1.d/", "etc/pacman.d/gnupg/openpgp-revocs.d/")):
                        raise ValueError("Image layer contains package-manager private key material: " + path)


def self_test():
    with tempfile.TemporaryDirectory() as directory:
        archive = Path(directory) / "image.tar"
        for private in (False, True):
            layer = io.BytesIO()
            with tarfile.open(fileobj=layer, mode="w") as file:
                member = tarfile.TarInfo("etc/pacman.d/gnupg/" + ("private-keys-v1.d/key.key" if private else "pubring.gpg"))
                member.size = 4
                file.addfile(member, io.BytesIO(b"TEST"))
            with tarfile.open(archive, "w") as image:
                for name, data in [("manifest.json", json.dumps([{"Layers": ["layer.tar"]}]).encode()), ("layer.tar", layer.getvalue())]:
                    member = tarfile.TarInfo(name)
                    member.size = len(data)
                    image.addfile(member, io.BytesIO(data))
            try:
                check(archive)
            except ValueError:
                assert private
            else:
                assert not private
    print("Image keyring layer check passes")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", nargs="?", type=Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
    elif args.archive:
        check(args.archive)
        print("No package-manager private key material in image layers")
    else:
        parser.error("An image archive or --self-test is required")
