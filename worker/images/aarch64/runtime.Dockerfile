FROM scratch

# Use the same signature-verified official rootfs context as the ARM builder.
COPY . /
RUN pacman-key --init && pacman-key --populate archlinuxarm \
    && cp /etc/pacman.conf /tmp/opr-pacman.conf \
    && sed -i '/^[#[:space:]]*DownloadUser[[:space:]]*=/d; /^[#[:space:]]*DisableSandboxSyscalls[[:space:]]*$/d; /^\[options\]$/a DownloadUser = root\nDisableSandboxSyscalls\nDisableSandboxFilesystem' /tmp/opr-pacman.conf \
    && pacman --config /tmp/opr-pacman.conf -Syu --noconfirm && pacman --config /tmp/opr-pacman.conf -Scc --noconfirm && rm /tmp/opr-pacman.conf \
    && rm -rf /etc/pacman.d/gnupg/openpgp-revocs.d /etc/pacman.d/gnupg/private-keys-v1.d
ENV LANG=C.UTF-8
ENV LC_ALL=C.UTF-8
LABEL org.opencontainers.image.title="omapkg minimal Arch Linux ARM runtime"
LABEL org.opencontainers.image.base.rootfs.sha256="42a4eeaa038994ffd31fa173256ef2f0ef511358eeb41b9ea1f8626391b9b319"
