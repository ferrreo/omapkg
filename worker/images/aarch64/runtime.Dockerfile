FROM scratch

# Use the same signature-verified official rootfs context as the ARM builder.
COPY . /
RUN pacman -Syu --noconfirm && pacman -Scc --noconfirm
ENV LANG=C.UTF-8
ENV LC_ALL=C.UTF-8
LABEL org.opencontainers.image.title="omapkg minimal Arch Linux ARM runtime"
LABEL org.opencontainers.image.base.rootfs.sha256="42a4eeaa038994ffd31fa173256ef2f0ef511358eeb41b9ea1f8626391b9b319"
