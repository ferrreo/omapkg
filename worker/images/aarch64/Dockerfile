FROM scratch

# Build context is an official Arch Linux ARM root filesystem. The builder
# script verifies its detached signature before extracting it here.
COPY . /

RUN cp /etc/pacman.conf /tmp/opr-pacman.conf \
    && sed -i '/^[#[:space:]]*DownloadUser[[:space:]]*=/d; /^[#[:space:]]*DisableSandboxSyscalls[[:space:]]*$/d; /^\[options\]$/a DownloadUser = root\nDisableSandboxSyscalls\nDisableSandboxFilesystem' /tmp/opr-pacman.conf \
    && pacman --config /tmp/opr-pacman.conf -Syu --noconfirm --needed \
      base-devel arch-install-scripts devtools binutils libarchive rpm-tools squashfs-tools namcap shellcheck \
    && pacman --config /tmp/opr-pacman.conf -Scc --noconfirm && rm /tmp/opr-pacman.conf

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
