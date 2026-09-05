# Real build fixture

This fixture packages GNU Hello 2.12. The script downloads the public source
archive, checks its SHA-256, builds it in the pinned Arch image, and inspects
the resulting package in a separate offline container.

Set the same image variables used by the factory, then run:

```sh
FACTORY_BUILDER_IMAGE='localhost/omapkg-arch-builder@sha256:<64 lowercase hex>' \
FACTORY_BUILDER_IMAGE_DIGEST='sha256:<64 lowercase hex>' \
  worker/testdata/real-build/run.sh
```

The source archive is kept out of the repository. Its URL and checksum are in
`source.txt`.
