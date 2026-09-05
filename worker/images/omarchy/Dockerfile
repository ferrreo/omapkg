ARG TARGETARCH=amd64

FROM docker.io/library/archlinux:base-devel@sha256:84cd9ef000b3cff245ec028e87965b84724f4bf1cc63fc2741ba927b88515ed6

ARG TARGETARCH

COPY omarchy-signing-key.asc /tmp/omarchy-signing-key.asc

RUN set -eux; \
    test "$TARGETARCH" = amd64; \
    printf 'Server = https://stable-mirror.omarchy.org/$repo/os/$arch\n' > /etc/pacman.d/mirrorlist; \
    sed -i 's/^LocalFileSigLevel.*/LocalFileSigLevel = Optional/' /etc/pacman.conf; \
    pacman-key --init; \
    pacman-key --add /tmp/omarchy-signing-key.asc; \
    pacman-key --lsign-key 40DFB630FF42BCFFB047046CF0134EE680CAC571; \
    printf '\n[omarchy]\nSigLevel = Required DatabaseOptional\nServer = https://pkgs.omarchy.org/stable/$arch\n' >> /etc/pacman.conf; \
    pacman -Sy --noconfirm omarchy-keyring; \
    pacman-key --populate omarchy; \
    sed -i '/^\[omarchy\]$/,/^$/d' /etc/pacman.conf; \
    pacman -Syyuu --noconfirm; \
    pacman -S --needed --noconfirm arch-install-scripts devtools; \
    pacman -Scc --noconfirm; \
    rm -f /tmp/omarchy-signing-key.asc; \
    rm -rf /etc/pacman.d/gnupg/openpgp-revocs.d /etc/pacman.d/gnupg/private-keys-v1.d

ENV LANG=C.UTF-8
ENV LC_ALL=C.UTF-8

LABEL org.opencontainers.image.title="omapkg Arch builder"
LABEL org.opencontainers.image.description="Omarchy stable mirror Arch package builder"
LABEL org.opencontainers.image.source="https://github.com/ferrreo/omapkg"
LABEL org.opencontainers.image.architectures="x86_64"
