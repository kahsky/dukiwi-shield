#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════
# CLAMAV ANTIVIRUS — building the RPM package (Fedora and derivatives), noarch, from any distribution.
# Usage: ./build-rpm.sh   →  dukiwi-shield-<VERSION>-1.noarch.rpm
# Requires rpmbuild ("rpm" package on Debian/Mint). The files come from build-deb.sh --stage-only.
# ═══════════════════════════════════════════════════════════════════════════
set -e
APP_NAME="dukiwi-shield"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
VERSION="$(sed -n 's/^VERSION="\(.*\)"/\1/p' "$SCRIPT_DIR/build-deb.sh" | head -1)"
command -v rpmbuild >/dev/null 2>&1 || { echo "rpmbuild absent : sudo apt install rpm" >&2; exit 2; }
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
SRC="$WORK/${APP_NAME}-${VERSION}"
mkdir -p "$SRC" "$WORK/rpmbuild"/{BUILD,RPMS,SOURCES,SPECS,SRPMS}
"$SCRIPT_DIR/build-deb.sh" --stage-only "$SRC/tree" >/dev/null
# Fedora: units and udev rules live under /usr/lib (lib → usr/lib is a link, but the RPM must list /usr/lib)
mkdir -p "$SRC/tree/usr"
if [ -d "$SRC/tree/lib" ]; then cp -a "$SRC/tree/lib/." "$SRC/tree/usr/lib/"; rm -rf "$SRC/tree/lib"; fi
cp "$SCRIPT_DIR/dukiwi.repo" "$SRC/"
cp "$SCRIPT_DIR/RPM-GPG-KEY-dukiwi" "$SRC/"
tar -C "$WORK" -czf "$WORK/rpmbuild/SOURCES/${APP_NAME}-${VERSION}.tar.gz" "${APP_NAME}-${VERSION}"
rpmbuild -bb --define "_topdir $WORK/rpmbuild" --define "version $VERSION" --define "dist %{nil}" \
         --define "_unitdir /usr/lib/systemd/system" --define "_udevrulesdir /usr/lib/udev/rules.d" \
         "$SCRIPT_DIR/${APP_NAME}.spec" >/dev/null
OUT="$(ls "$WORK"/rpmbuild/RPMS/noarch/${APP_NAME}-${VERSION}-1*.noarch.rpm | head -1)"
FINAL="$SCRIPT_DIR/${APP_NAME}-${VERSION}-1.noarch.rpm"
cp -f "$OUT" "$FINAL"
echo "══════════════════════════════════════════"
echo "  ✅ RPM construit : $(basename "$FINAL") ($(du -h "$FINAL" | cut -f1))"
echo "  Installer : sudo dnf install ./$(basename "$FINAL")"
echo "══════════════════════════════════════════"
