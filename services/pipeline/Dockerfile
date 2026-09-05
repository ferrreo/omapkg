FROM docker.io/cloudflare/sandbox:0.12.9@sha256:4a56a37a3cfd9b38d65bb4b5d0b341e6490a3a4c0226274ae4c1cca4948e85fe AS toolchain

ARG GO_VERSION=1.26.5
ARG GO_SHA256=5c2c3b16caefa1d968a94c1daca04a7ca301a496d9b086e17ad77bb81393f053
ARG RUST_VERSION=1.98.1
ARG RUST_RELEASE_DATE=2026-09-03
ARG RUST_TARGET=x86_64-unknown-linux-gnu
ARG RUST_SHA256=5326b36c53de11d148c8f8dab6553a3d1006c2cfd32123683073fad3c302605b

# The tarballs and detached signatures come from the official Go and Rust
# release endpoints. Do not run either project's installer: only the compiler,
# standard library, and Cargo components needed for vendoring are copied.
RUN set -eux; \
  apt-get update; \
  DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    ca-certificates curl gnupg xz-utils; \
  work_dir="$(mktemp -d)"; \
  gpg_home="$work_dir/gnupg"; \
  mkdir -m 700 "$gpg_home"; \
  export GNUPGHOME="$gpg_home"; \
  go_url="https://dl.google.com/go/go${GO_VERSION}.linux-amd64.tar.gz"; \
  curl --fail --location --retry 3 --silent --show-error "$go_url" \
    --output "$work_dir/go.tar.gz"; \
  curl --fail --location --retry 3 --silent --show-error "$go_url.sha256" \
    --output "$work_dir/go.tar.gz.sha256"; \
  curl --fail --location --retry 3 --silent --show-error "$go_url.asc" \
    --output "$work_dir/go.tar.gz.asc"; \
  curl --fail --location --retry 3 --silent --show-error \
    https://dl.google.com/linux/linux_signing_key.pub \
    --output "$work_dir/google-signing-key.asc"; \
  gpg --batch --import "$work_dir/google-signing-key.asc"; \
  gpg --batch --with-colons --fingerprint \
    | awk -F: '$1 == "fpr" { print $10 }' \
    | grep -Fx EB4C1BFD4F042F6DDDCCEC917721F63BD38B4796; \
  test "$(tr -d "[:space:]" < "$work_dir/go.tar.gz.sha256")" = "$GO_SHA256"; \
  printf '%s  %s\n' "$GO_SHA256" "$work_dir/go.tar.gz" | sha256sum --check -; \
  gpg --batch --verify "$work_dir/go.tar.gz.asc" "$work_dir/go.tar.gz"; \
  mkdir -p /opt; \
  tar --extract --gzip --file "$work_dir/go.tar.gz" --directory /opt \
    --no-same-owner --no-same-permissions; \
  rust_url="https://static.rust-lang.org/dist/${RUST_RELEASE_DATE}/rust-${RUST_VERSION}-${RUST_TARGET}.tar.xz"; \
  curl --fail --location --retry 3 --silent --show-error "$rust_url" \
    --output "$work_dir/rust.tar.xz"; \
  curl --fail --location --retry 3 --silent --show-error "$rust_url.sha256" \
    --output "$work_dir/rust.tar.xz.sha256"; \
  curl --fail --location --retry 3 --silent --show-error "$rust_url.asc" \
    --output "$work_dir/rust.tar.xz.asc"; \
  curl --fail --location --retry 3 --silent --show-error \
    https://static.rust-lang.org/rust-key.gpg.ascii \
    --output "$work_dir/rust-key.gpg.ascii"; \
  gpg --batch --import "$work_dir/rust-key.gpg.ascii"; \
  gpg --batch --with-colons --fingerprint \
    | awk -F: '$1 == "fpr" { print $10 }' \
    | grep -Fx 108F66205EAEB0AAA8DD5E1C85AB96E6FA1BE5FE; \
  test "$(awk '{ print $1 }' "$work_dir/rust.tar.xz.sha256")" = "$RUST_SHA256"; \
  printf '%s  %s\n' "$RUST_SHA256" "$work_dir/rust.tar.xz" | sha256sum --check -; \
  gpg --batch --verify "$work_dir/rust.tar.xz.asc" "$work_dir/rust.tar.xz"; \
  mkdir "$work_dir/rust"; \
  tar --extract --xz --file "$work_dir/rust.tar.xz" --directory "$work_dir/rust" \
    --no-same-owner --no-same-permissions; \
  rust_root="$work_dir/rust/rust-${RUST_VERSION}-${RUST_TARGET}"; \
  mkdir -p /opt/rust/bin /opt/rust/cargo /opt/rust/lib/rustlib; \
  cp --archive "$rust_root/rustc/." /opt/rust/; \
  cp --archive "$rust_root/rust-std-${RUST_TARGET}/lib/rustlib/." \
    /opt/rust/lib/rustlib/; \
  cp --archive "$rust_root/cargo/." /opt/rust/cargo/; \
  ln -s ../cargo/bin/cargo /opt/rust/bin/cargo; \
  rm -rf "$work_dir" /var/lib/apt/lists/*

FROM docker.io/cloudflare/sandbox:0.12.9@sha256:4a56a37a3cfd9b38d65bb4b5d0b341e6490a3a4c0226274ae4c1cca4948e85fe

# Keep xz available for source archives. Go's complete GOROOT (including src)
# and Rust's compiler rlibs are intentional runtime inputs for vendoring.
ENV GOROOT=/opt/go
ENV PATH=/opt/go/bin:/opt/rust/bin:${PATH}

RUN set -eux; \
  apt-get update; \
  DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    libarchive-tools rpm rpm2cpio squashfs-tools xz-utils; \
  rm -rf /var/lib/apt/lists/* /usr/share/doc/* /usr/share/man/* \
    /usr/share/lintian /usr/share/zsh

COPY --from=toolchain /opt/go /opt/go
COPY --from=toolchain /opt/rust /opt/rust
