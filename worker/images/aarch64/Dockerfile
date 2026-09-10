FROM scratch

# Build context is an official Arch Linux ARM root filesystem. The builder
# script verifies its detached signature before extracting it here.
COPY . /

RUN pacman-key --init && pacman-key --populate archlinuxarm \
    && cp /etc/pacman.conf /tmp/opr-pacman.conf \
    && sed -i '/^[#[:space:]]*DownloadUser[[:space:]]*=/d; /^[#[:space:]]*DisableSandboxSyscalls[[:space:]]*$/d; /^\[options\]$/a DownloadUser = root\nDisableSandboxSyscalls\nDisableSandboxFilesystem' /tmp/opr-pacman.conf \
    && pacman --config /tmp/opr-pacman.conf -Syu --noconfirm --needed \
      base-devel arch-install-scripts devtools binutils libarchive rpm-tools squashfs-tools curl xz \
    && pacman --config /tmp/opr-pacman.conf -Scc --noconfirm && rm /tmp/opr-pacman.conf \
    && rm -rf /etc/pacman.d/gnupg/openpgp-revocs.d /etc/pacman.d/gnupg/private-keys-v1.d

# Arch Linux ARM does not package ShellCheck. Pin the official static ARM release.
ADD --checksum=sha256:12b331c1d2db6b9eb13cfca64306b1b157a86eb69db83023e261eaa7e7c14588 https://github.com/koalaman/shellcheck/releases/download/v0.11.0/shellcheck-v0.11.0.linux.aarch64.tar.xz /tmp/shellcheck.tar.xz
RUN tar -xJf /tmp/shellcheck.tar.xz -C /tmp \
    && install -Dm755 /tmp/shellcheck-v0.11.0/shellcheck /usr/bin/shellcheck \
    && install -Dm644 /tmp/shellcheck-v0.11.0/LICENSE.txt /usr/share/licenses/shellcheck/LICENSE \
    && rm -rf /tmp/shellcheck.tar.xz /tmp/shellcheck-v0.11.0

ENV LANG=C.UTF-8
ENV LC_ALL=C.UTF-8

LABEL org.opencontainers.image.title="omapkg Arch Linux ARM builder"
LABEL org.opencontainers.image.description="AArch64 Arch Linux package builder"
LABEL org.opencontainers.image.source="https://github.com/ferrreo/omapkg"
LABEL org.opencontainers.image.architectures="aarch64"
LABEL org.opencontainers.image.base.name="Arch Linux ARM Generic AArch64"
LABEL org.opencontainers.image.base.source="https://archlinuxarm.org/platforms/armv8/generic"
LABEL org.opencontainers.image.base.rootfs.sha256="42a4eeaa038994ffd31fa173256ef2f0ef511358eeb41b9ea1f8626391b9b319"
LABEL org.opencontainers.image.base.signature.key="68B3537F39A313B3E574D06777193F152BDBE6A6"
