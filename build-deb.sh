#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════
# CLAMAV ANTIVIRUS — Build .deb package
# Usage: ./build-deb.sh
# Output: dukiwi-shield_<VERSION>_all.deb
# ═══════════════════════════════════════════════════════════════════════════

set -e

APP_NAME="dukiwi-shield"
VERSION="2.7.1"
ARCH="all"
PKG_DIR="${APP_NAME}_${VERSION}_${ARCH}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# --stage-only <dir> : construit seulement l'arborescence (partagée avec build-rpm.sh), sans paquet Debian
STAGE_ONLY=""
if [ "${1:-}" = "--stage-only" ]; then STAGE_ONLY="$2"; PKG_DIR="$2"; fi

echo "══════════════════════════════════════════"
echo "  Building ${APP_NAME} v${VERSION} .deb"
echo "══════════════════════════════════════════"

# ── Clean previous builds ──
rm -rf "$PKG_DIR" "${PKG_DIR}.deb"

# ── Create directory structure ──
echo "[1/5] Creating package structure..."
mkdir -p "${PKG_DIR}/DEBIAN"
mkdir -p "${PKG_DIR}/opt/${APP_NAME}/ui"
mkdir -p "${PKG_DIR}/opt/${APP_NAME}/icons"
mkdir -p "${PKG_DIR}/usr/share/applications"
mkdir -p "${PKG_DIR}/usr/share/nemo/actions"
mkdir -p "${PKG_DIR}/etc/xdg/autostart"
mkdir -p "${PKG_DIR}/lib/systemd/system"
mkdir -p "${PKG_DIR}/lib/udev/rules.d"
mkdir -p "${PKG_DIR}/opt/${APP_NAME}/keys"
mkdir -p "${PKG_DIR}/usr/share/polkit-1/actions"

# ── Copy application files ──
echo "[2/5] Copying application files..."
cp "${SCRIPT_DIR}/dukiwi-shield.py"             "${PKG_DIR}/opt/${APP_NAME}/"
cp "${SCRIPT_DIR}/dukiwi-shield-daemon.py"      "${PKG_DIR}/opt/${APP_NAME}/"
cp "${SCRIPT_DIR}/dukiwi_shield_common.py"                "${PKG_DIR}/opt/${APP_NAME}/"
cp "${SCRIPT_DIR}/dukiwi_shield_backup.py"                "${PKG_DIR}/opt/${APP_NAME}/"
cp "${SCRIPT_DIR}/dukiwi_shield_extras.py"                "${PKG_DIR}/opt/${APP_NAME}/"
cp "${SCRIPT_DIR}/dukiwi_shield_harden.py"                "${PKG_DIR}/opt/${APP_NAME}/"
cp "${SCRIPT_DIR}/dukiwi_shield_distro.py"                "${PKG_DIR}/opt/${APP_NAME}/"
cp "${SCRIPT_DIR}/dukiwi_shield_honeypot.py"              "${PKG_DIR}/opt/${APP_NAME}/"
cp "${SCRIPT_DIR}/dukiwi_shield_urlguard.py"              "${PKG_DIR}/opt/${APP_NAME}/"
cp "${SCRIPT_DIR}/dukiwi_shield_guard.py"                 "${PKG_DIR}/opt/${APP_NAME}/"
cp "${SCRIPT_DIR}/dukiwi-shield-native-host"    "${PKG_DIR}/opt/${APP_NAME}/"
cp "${SCRIPT_DIR}/dukiwi-shield-browser-setup"  "${PKG_DIR}/opt/${APP_NAME}/"
# Extensions Thunderbird / navigateurs (XPI, CRX, dossiers décompressés, update.xml, identifiants)
"${SCRIPT_DIR}/build-extensions.sh" --quiet
mkdir -p "${PKG_DIR}/opt/${APP_NAME}/extensions"
cp -r "${SCRIPT_DIR}/dist/extensions/." "${PKG_DIR}/opt/${APP_NAME}/extensions/"
cp "${SCRIPT_DIR}/dukiwi-shield-tray"           "${PKG_DIR}/opt/${APP_NAME}/"
cp "${SCRIPT_DIR}/dukiwi-shield-scan-nemo.sh"             "${PKG_DIR}/opt/${APP_NAME}/"
cp "${SCRIPT_DIR}/dukiwi-shield-sandbox"                  "${PKG_DIR}/opt/${APP_NAME}/"
cp "${SCRIPT_DIR}/dukiwi_shield_protect.py"               "${PKG_DIR}/opt/${APP_NAME}/"
cp "${SCRIPT_DIR}/dukiwi_shield_hygiene.py"               "${PKG_DIR}/opt/${APP_NAME}/"
cp "${SCRIPT_DIR}/dukiwi_shield_audit.py"                 "${PKG_DIR}/opt/${APP_NAME}/"
cp "${SCRIPT_DIR}/dukiwi_shield_folders.py"               "${PKG_DIR}/opt/${APP_NAME}/"
cp "${SCRIPT_DIR}/dukiwi-shield-cli"                      "${PKG_DIR}/opt/${APP_NAME}/"
cp "${SCRIPT_DIR}/dukiwi-shield-shred"                    "${PKG_DIR}/opt/${APP_NAME}/"
mkdir -p "${PKG_DIR}/usr/bin"
install -m 755 "${SCRIPT_DIR}/dukiwi-shield-launcher"     "${PKG_DIR}/usr/bin/dukiwi-shield"
cp "${SCRIPT_DIR}/systemd/"*.service               "${PKG_DIR}/lib/systemd/system/"
cp "${SCRIPT_DIR}/systemd/"*.timer                 "${PKG_DIR}/lib/systemd/system/"
cp "${SCRIPT_DIR}/ui/index.html"                    "${PKG_DIR}/opt/${APP_NAME}/ui/"
cp "${SCRIPT_DIR}/ui/style.css"                     "${PKG_DIR}/opt/${APP_NAME}/ui/"
cp "${SCRIPT_DIR}/ui/app.js"                        "${PKG_DIR}/opt/${APP_NAME}/ui/"
cp "${SCRIPT_DIR}/ui/i18n.js"                       "${PKG_DIR}/opt/${APP_NAME}/ui/"
cp "${SCRIPT_DIR}/ui/center.js"                     "${PKG_DIR}/opt/${APP_NAME}/ui/"
cp "${SCRIPT_DIR}/ui/awareness.js"                  "${PKG_DIR}/opt/${APP_NAME}/ui/"
cp "${SCRIPT_DIR}/udev/"*.rules                     "${PKG_DIR}/lib/udev/rules.d/"
cp "${SCRIPT_DIR}/dukiwi-shield-unlock"          "${PKG_DIR}/opt/${APP_NAME}/"
cp "${SCRIPT_DIR}/keys/dukiwi.gpg"            "${PKG_DIR}/opt/${APP_NAME}/keys/"
cp "${SCRIPT_DIR}/keys/dukiwi.asc"            "${PKG_DIR}/opt/${APP_NAME}/keys/"
cp "${SCRIPT_DIR}/polkit/"*.policy                  "${PKG_DIR}/usr/share/polkit-1/actions/"
cp "${SCRIPT_DIR}/icons/"*.svg                      "${PKG_DIR}/opt/${APP_NAME}/icons/"
cp "${SCRIPT_DIR}/dukiwi-shield.desktop"         "${PKG_DIR}/usr/share/applications/"
cp "${SCRIPT_DIR}/dukiwi-shield-nemo.nemo_action" "${PKG_DIR}/usr/share/nemo/actions/"
cp "${SCRIPT_DIR}/dukiwi-shield-sandbox.nemo_action" "${PKG_DIR}/usr/share/nemo/actions/"
cp "${SCRIPT_DIR}/dukiwi-shield-shred.nemo_action" "${PKG_DIR}/usr/share/nemo/actions/"
cp "${SCRIPT_DIR}/dukiwi-shield-autostart.desktop" "${PKG_DIR}/etc/xdg/autostart/"

# Normalize permissions (independent of the builder's umask), then mark scripts executable
find "${PKG_DIR}" -type d -exec chmod 755 {} +
find "${PKG_DIR}" -type f -exec chmod 644 {} +
chmod +x "${PKG_DIR}/opt/${APP_NAME}/dukiwi-shield.py"
chmod +x "${PKG_DIR}/opt/${APP_NAME}/dukiwi-shield-daemon.py"
chmod +x "${PKG_DIR}/opt/${APP_NAME}/dukiwi-shield-unlock"
chmod +x "${PKG_DIR}/opt/${APP_NAME}/dukiwi-shield-tray"
chmod +x "${PKG_DIR}/opt/${APP_NAME}/dukiwi-shield-scan-nemo.sh"
chmod +x "${PKG_DIR}/opt/${APP_NAME}/dukiwi-shield-sandbox" "${PKG_DIR}/opt/${APP_NAME}/dukiwi-shield-shred" "${PKG_DIR}/opt/${APP_NAME}/dukiwi-shield-cli"
chmod +x "${PKG_DIR}/usr/bin/dukiwi-shield"

# ── Integrity manifest (sha256 of every packaged file), signed with the Dukiwi key if present ──
echo "[2b/5] Writing integrity manifest..."
REPO_KEYS="${REPO_KEYS:-$HOME/GITHUB/repo/keys/gnupg}"
python3 - "${PKG_DIR}" "${VERSION}" << 'PY'
import hashlib, json, os, sys, datetime
root, version = sys.argv[1], sys.argv[2]
files = {}
for dp, _, fns in os.walk(root):
    if os.path.relpath(dp, root).startswith("DEBIAN"):
        continue
    for fn in fns:
        full = os.path.join(dp, fn)
        rel = os.path.relpath(full, root)
        if os.path.islink(full) or rel in ("opt/dukiwi-shield/integrity.json", "opt/dukiwi-shield/integrity.json.sig"):
            continue
        h = hashlib.sha256()
        with open(full, "rb") as f:
            h.update(f.read())
        files[rel] = h.hexdigest()
with open(os.path.join(root, "opt/dukiwi-shield/integrity.json"), "w") as f:
    json.dump({"version": version, "date": datetime.datetime.now().isoformat(timespec="seconds"),
               "files": dict(sorted(files.items()))}, f, indent=2)
print(f"  {len(files)} fichiers")
PY
if [ -d "${REPO_KEYS}" ]; then
    GNUPGHOME="${REPO_KEYS}" gpg --batch --yes --detach-sign \
        -o "${PKG_DIR}/opt/${APP_NAME}/integrity.json.sig" "${PKG_DIR}/opt/${APP_NAME}/integrity.json" \
        && echo "  integrity.json signé (clé Dukiwi)"
else
    echo "  (clé privée absente : integrity.json non signé)"
fi

if [ -n "$STAGE_ONLY" ]; then
    rm -rf "${PKG_DIR}/DEBIAN"
    echo "  arborescence prête dans ${PKG_DIR}"
    exit 0
fi

# ── Create DEBIAN/control ──
echo "[3/5] Writing package metadata..."
cat > "${PKG_DIR}/DEBIAN/control" << EOF
Package: ${APP_NAME}
Version: ${VERSION}
Section: utils
Priority: optional
Architecture: ${ARCH}
Conflicts: clamav-antivirus
Replaces: clamav-antivirus
Breaks: clamav-antivirus
Depends: python3 (>= 3.8), python3-gi, python3-pyudev, python3-apt, gir1.2-webkit2-4.1, gir1.2-ayatanaappindicator3-0.1 | gir1.2-appindicator3-0.1, gir1.2-gtk-3.0, pkexec | policykit-1, clamav, clamav-daemon, clamav-freshclam, lynis, unhide, chkrootkit, debsums, msmtp-mta | mail-transport-agent, zenity, systemd, udev, udisks2
Recommends: libnotify-bin, mintupdate | update-manager, timeshift, rclone, rsync, gocryptfs, flatpak, firejail
Maintainer: Dukiwi SA <info@dukiwi.ch>
Homepage: https://dukiwi.ch
Description: Dukiwi Shield - antivirus, protection et vérification d'intégrité pour Linux
 Dukiwi Shield : antivirus (ClamAV), protection du poste et vérification d'intégrité pour Linux :
 - Service système : scan complet et mises à jour sans mot de passe
 - Mises à jour planifiées tous les jours à 07:00 et 5 min après le démarrage
 - Scan complet automatique après la première installation
 - Surveillance des rafales d'écritures (fanotify) et alerte "danger potentiel"
 - Analyse des clés USB avant leur mise à disposition (question pour les disques)
 - État du système : mises à jour de sécurité en attente et CVE associées
 - Popups glissants en bas à droite, interface en français, anglais, allemand, italien
 - Vue simple rassurante et vue avancée, page Paramètres (seuils, USB, planification)
 - Pare-feu UFW et SSH pilotés depuis l'application, surveillance du volume envoyé
 - Scan rapide de répertoires avec progression détaillée
 - Quarantaine automatique des fichiers infectés
 - Icône bouclier dans la barre des tâches
 - Intégration Nemo (clic droit : Scan with Dukiwi Shield)
 - Interface HTML/CSS facilement personnalisable
 .
 Développé par Dukiwi SA, Estavayer-le-Lac, Suisse.
EOF

# ── Create DEBIAN/postinst (post-installation script) ──
cat > "${PKG_DIR}/DEBIAN/postinst" << 'EOF'
#!/bin/bash
set -e

# ── Reprise d'une installation des versions précédentes (paquet « OLD », ≤ 1.31.1) ─────────────────────────────
# Le paquet précédent vient d'être retiré (Conflicts/Replaces) : état, quarantaine, cache, journaux, politique, fichiers
# de durcissement et réglage de l'heure des mises à jour passent sous le nouveau nom ; liens systemd orphelins supprimés.
OLD=clamav-antivirus
migrate_dir() {
    if [ -d "$1" ] && [ ! -L "$1" ]; then
        set +e
        if [ ! -e "$2" ] || [ -z "$(ls -A "$2" 2>/dev/null)" ]; then
            rmdir "$2" 2>/dev/null || true
            mv "$1" "$2"
        else
            cp -an "$1/." "$2/" && rm -rf "$1"
        fi
        set -e
    fi
    return 0
}
systemctl stop $OLD-daemon.service linux-shield-daemon.service 2>/dev/null || true
migrate_dir /var/lib/$OLD /var/lib/dukiwi-shield
migrate_dir /var/log/$OLD /var/log/dukiwi-shield
migrate_dir /etc/$OLD /etc/dukiwi-shield
migrate_dir /etc/systemd/system/$OLD-update.timer.d /etc/systemd/system/dukiwi-shield-update.timer.d
for f in /etc/sysctl.d/90-$OLD* /etc/security/limits.d/90-$OLD* /etc/systemd/coredump.conf.d/90-$OLD* \
         /etc/modprobe.d/90-$OLD* /etc/ssh/sshd_config.d/90-$OLD* /etc/needrestart/conf.d/90-$OLD*; do
    [ -e "$f" ] && { mv -f "$f" "${f//$OLD/dukiwi-shield}" || true; }
done
for f in /etc/hosts /etc/login.defs /etc/sysctl.d/90-dukiwi-shield* /etc/security/limits.d/90-dukiwi-shield* \
         /etc/systemd/coredump.conf.d/90-dukiwi-shield* /etc/modprobe.d/90-dukiwi-shield* /etc/ssh/sshd_config.d/90-dukiwi-shield* \
         /etc/needrestart/conf.d/90-dukiwi-shield*; do
    # réécrit sur place (même inode : /etc/hosts peut être un montage), jamais bloquant
    if [ -f "$f" ] && grep -q '# ClamAV Antivirus GUI' "$f" 2>/dev/null; then
        sed 's/# ClamAV Antivirus GUI/# Dukiwi Shield/' "$f" > "$f.dukiwi-tmp" && cat "$f.dukiwi-tmp" > "$f" || true
        rm -f "$f.dukiwi-tmp"
    fi
done
rm -f /etc/xdg/autostart/$OLD-autostart.desktop
for l in /etc/systemd/system/multi-user.target.wants/$OLD-daemon.service /etc/systemd/system/multi-user.target.wants/linux-shield-daemon.service \
         /etc/systemd/system/$OLD-daemon.service /etc/systemd/system/timers.target.wants/$OLD-update.timer; do
    [ -L "$l" ] && rm -f "$l"
done
# Restes non suivis par l'ancien paquet (caches Python) une fois celui-ci retiré
[ -d /opt/$OLD ] && [ ! -e /opt/$OLD/$OLD.py ] && rm -rf /opt/$OLD
true

STATE_DIR=/var/lib/dukiwi-shield

# Enable and start freshclam service
systemctl enable clamav-freshclam 2>/dev/null || true
systemctl start clamav-freshclam 2>/dev/null || true

# Service système + planification des mises à jour (07:00 et 5 min après le démarrage)
mkdir -p "$STATE_DIR"
FIRST_INSTALL=0
if [ "$1" = "configure" ] && [ ! -f "$STATE_DIR/state.json" ]; then
    # Première installation du service : scan complet automatique au démarrage du daemon
    touch "$STATE_DIR/first-scan-pending"
    FIRST_INSTALL=1
fi

systemctl daemon-reload 2>/dev/null || true
udevadm control --reload-rules 2>/dev/null || true
# Extensions : hôte natif et politiques pour Thunderbird, Firefox, Chrome, Chromium, Edge, Brave
/opt/dukiwi-shield/dukiwi-shield-browser-setup install 2>/dev/null || true
systemctl enable dukiwi-shield-daemon.service 2>/dev/null || true
systemctl enable dukiwi-shield-update.timer 2>/dev/null || true
systemctl restart dukiwi-shield-daemon.service 2>/dev/null || true
systemctl start dukiwi-shield-update.timer 2>/dev/null || true

# Relancer les GUI ouvertes pour charger la nouvelle version : le service utilisateur (Restart=always) ou la
# surveillance du service root relancent le bouclier dans chaque session graphique active
pkill -f "/opt/dukiwi-shield/dukiwi-shield.py" 2>/dev/null || true

# Update desktop database
if command -v update-desktop-database &> /dev/null; then
    update-desktop-database /usr/share/applications/ 2>/dev/null || true
fi

echo ""
echo "═══════════════════════════════════════════════════"
echo "  ✅ Dukiwi Shield installé avec succès !"
echo ""
echo "  Lancez-le depuis le menu Applications > Système"
echo "  ou via: /opt/dukiwi-shield/dukiwi-shield.py"
echo ""
echo "  Service système : dukiwi-shield-daemon (actif)"
echo "  Mises à jour    : tous les jours à 07:00 et"
echo "                    5 minutes après le démarrage"
echo "  Surveillance    : écritures (fanotify), clés USB (udev)"
echo "  Extensions      : Thunderbird, Chrome/Edge/Brave au prochain"
echo "                    démarrage ; Firefox : voir Sécurité › Liens"
if [ "$FIRST_INSTALL" = "1" ]; then
echo "  Scan initial    : un scan complet du système va"
echo "                    démarrer automatiquement."
fi
echo "═══════════════════════════════════════════════════"
echo ""

exit 0
EOF
chmod 755 "${PKG_DIR}/DEBIAN/postinst"

# ── Create DEBIAN/prerm (pre-removal script) ──
cat > "${PKG_DIR}/DEBIAN/prerm" << 'EOF'
#!/bin/bash
set -e
# Kill running instances
pkill -f "/opt/dukiwi-shield/dukiwi-shield.py" 2>/dev/null || true
if [ "$1" = "remove" ]; then
    /opt/dukiwi-shield/dukiwi-shield-browser-setup remove 2>/dev/null || true
    systemctl stop dukiwi-shield-update.timer 2>/dev/null || true
    systemctl disable dukiwi-shield-update.timer 2>/dev/null || true
    systemctl stop dukiwi-shield-daemon.service 2>/dev/null || true
    systemctl disable dukiwi-shield-daemon.service 2>/dev/null || true
    # Leurres anti-rançongiciel (fichiers cachés .dukiwi-guard-*) retirés des dossiers personnels
    find /home -maxdepth 4 -xdev -type f -name '.dukiwi-guard-*' -delete 2>/dev/null || true
fi
exit 0
EOF
chmod 755 "${PKG_DIR}/DEBIAN/prerm"

# ── Create DEBIAN/postrm (post-removal script) ──
cat > "${PKG_DIR}/DEBIAN/postrm" << 'EOF'
#!/bin/bash
set -e
systemctl daemon-reload 2>/dev/null || true
udevadm control --reload-rules 2>/dev/null || true
if [ "$1" = "purge" ]; then
    rm -rf /var/lib/dukiwi-shield /var/log/dukiwi-shield /run/dukiwi-shield
fi
exit 0
EOF
chmod 755 "${PKG_DIR}/DEBIAN/postrm"

# ── Build the .deb ──
echo "[4/5] Building .deb package..."
dpkg-deb --build --root-owner-group "${PKG_DIR}"

# ── Verify ──
echo "[5/5] Verifying package..."
dpkg-deb --info "${PKG_DIR}.deb"
echo ""

# ── Clean build dir ──
rm -rf "${PKG_DIR}"

SIZE=$(du -h "${PKG_DIR}.deb" | cut -f1)
echo "══════════════════════════════════════════"
echo "  ✅ Package built: ${PKG_DIR}.deb (${SIZE})"
echo ""
echo "  Install:   sudo dpkg -i ${PKG_DIR}.deb"
echo "  Fix deps:  sudo apt-get install -f"
echo "  Remove:    sudo dpkg -r ${APP_NAME}"
echo "══════════════════════════════════════════"
