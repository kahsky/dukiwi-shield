#!/bin/bash
# Build the transitional package clamav-antivirus_<VERSION>_all.deb: no files, depends on dukiwi-shield.
# Computers that still have the old package (clamav-antivirus ≤ 1.31.1) and the Dukiwi APT repository get it as an
# ordinary update, which installs Dukiwi Shield; dukiwi-shield only conflicts with clamav-antivirus (<< 2.0~), so the
# two can sit side by side and the transitional package can be removed later.
# Usage: tools/build-transitional.sh VERSION   (run from build-deb.sh; output next to the dukiwi-shield package)
set -e
VERSION="$1"
[ -n "$VERSION" ] || { echo "usage: $0 VERSION" >&2; exit 1; }
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DIR="$(mktemp -d)"
PKG="$DIR/clamav-antivirus_${VERSION}_all"
mkdir -p "$PKG/DEBIAN" "$PKG/usr/share/doc/clamav-antivirus"
cat > "$PKG/DEBIAN/control" <<EOF
Package: clamav-antivirus
Version: ${VERSION}
Architecture: all
Section: oldlibs
Priority: optional
Maintainer: Dukiwi SA <info@dukiwi.com>
Depends: dukiwi-shield (>= ${VERSION})
Description: transitional package: ClamAV Antivirus is now Dukiwi Shield
 This empty package moves computers that still have the old ClamAV Antivirus package
 to Dukiwi Shield. It can be removed once Dukiwi Shield is installed.
EOF
printf 'clamav-antivirus (%s) noble; urgency=medium\n\n  * Transitional package: ClamAV Antivirus is now Dukiwi Shield.\n\n -- Dukiwi SA <info@dukiwi.com>  %s\n' \
    "$VERSION" "$(date -R)" | gzip -9n > "$PKG/usr/share/doc/clamav-antivirus/changelog.gz"
dpkg-deb --build --root-owner-group "$PKG" >/dev/null
mv "$PKG.deb" "$ROOT/clamav-antivirus_${VERSION}_all.deb"
rm -rf "$DIR"
echo "  ✅ Transitional package built: clamav-antivirus_${VERSION}_all.deb"
