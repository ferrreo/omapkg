pkgname=electron43-arm-runtime
pkgver=43.2.0
pkgrel=1
pkgdesc='Pinned official Electron 43 arm64 runtime for private template acceptance'
arch=('aarch64')
license=('MIT')
depends=('bash' 'glibc' 'gcc-libs' 'gtk3' 'nss' 'alsa-lib' 'libxss' 'libx11' 'libxcb' 'libxcomposite' 'libxdamage' 'libxrandr' 'mesa' 'libdrm' 'at-spi2-core' 'pango' 'cairo' 'dbus' 'libpulse')
source=('electron.zip')
sha256sums=('50e1cdefbf8590e0d89b0276314a99c7b98e8eed732204c6f1a1c2a38376ed87')

package() {
  install -d "$pkgdir/opt/electron43" "$pkgdir/usr/bin"
  for path in *; do
    case "$path" in electron.zip|PKGBUILD) continue ;; esac
    cp -a "$path" "$pkgdir/opt/electron43/"
  done
  ln -s /opt/electron43/electron "$pkgdir/usr/bin/electron43"
}
