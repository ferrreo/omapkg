FROM docker.io/library/archlinux:base-devel@sha256:84cd9ef000b3cff245ec028e87965b84724f4bf1cc63fc2741ba927b88515ed6

# The runner invokes these Arch clean-chroot tools by their fixed paths.
RUN pacman -Syu --noconfirm --needed arch-install-scripts devtools binutils libarchive rpm-tools squashfs-tools \
    && pacman -Scc --noconfirm
