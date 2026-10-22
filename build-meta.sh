#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════
# LINUX SHIELD — métapaquet « linux-shield » (deb, et rpm si rpmbuild est présent).
# Il dépend du paquet technique clamav-antivirus (nom, chemins, unités et dépôt inchangés pour les installations
# existantes) et fournit la commande linux-shield. Version propre au métapaquet : il n'est reconstruit que s'il change.
# Usage : ./build-meta.sh   →  linux-shield_<META_VERSION>_all.deb, linux-shield-<META_VERSION>-1.noarch.rpm
# Publication : cd ../repo && ./publish.sh ../clamav-antivirus/linux-shield_<META_VERSION>_all.deb
# ═══════════════════════════════════════════════════════════════════════════
set -e
META="linux-shield"
META_VERSION="1.0.0"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PKG_DIR="${META}_${META_VERSION}_all"
cd "$SCRIPT_DIR"
rm -rf "$PKG_DIR" "${PKG_DIR}.deb"
mkdir -p "${PKG_DIR}/DEBIAN" "${PKG_DIR}/usr/bin"
ln -s /opt/clamav-antivirus/clamav-antivirus.py "${PKG_DIR}/usr/bin/${META}"
cat > "${PKG_DIR}/DEBIAN/control" <<CTRL
Package: ${META}
Version: ${META_VERSION}
Section: metapackages
Priority: optional
Architecture: all
Depends: clamav-antivirus
Maintainer: Dukiwi SA <info@dukiwi.ch>
Homepage: https://github.com/kahsky/linux-shield
Description: Linux Shield - sécurité du poste Linux (métapaquet : installe clamav-antivirus)
 Linux Shield réunit en une application les protections d'un poste Linux :
 antivirus ClamAV avec service système et protection en temps réel, pare-feu,
 centre de sécurité (failles, intégrité, persistance, pot de miel), contrôle
 des liens et des courriels, sauvegardes et durcissement.
 .
 Ce métapaquet installe le paquet technique clamav-antivirus (toujours à jour
 depuis le dépôt Dukiwi) et la commande linux-shield.
CTRL
chmod -R go-w "${PKG_DIR}"
dpkg-deb --build --root-owner-group "${PKG_DIR}" >/dev/null
rm -rf "$PKG_DIR"
echo "  ✅ Métapaquet deb : ${PKG_DIR}.deb"
if command -v rpmbuild >/dev/null 2>&1; then
    WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
    mkdir -p "$WORK"/{BUILD,RPMS,SOURCES,SPECS,SRPMS}
    rpmbuild -bb --define "_topdir $WORK" --define "version $META_VERSION" --define "dist %{nil}" "$SCRIPT_DIR/${META}.spec" >/dev/null 2>"$WORK/rpmbuild.log" || { cat "$WORK/rpmbuild.log" >&2; exit 1; }
    cp -f "$WORK/RPMS/noarch/${META}-${META_VERSION}-1.noarch.rpm" "$SCRIPT_DIR/"
    echo "  ✅ Métapaquet rpm : ${META}-${META_VERSION}-1.noarch.rpm"
else
    echo "  rpmbuild absent : métapaquet rpm non construit (sudo apt install rpm)" >&2
fi
