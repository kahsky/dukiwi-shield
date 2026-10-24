# Dukiwi Shield — paquet RPM (Fedora et dérivés). Construit par build-rpm.sh à partir de l'arborescence
# commune (build-deb.sh --stage-only) : mêmes fichiers que le paquet Debian, manifeste d'intégrité signé inclus.
Name:           dukiwi-shield
Version:        %{version}
Release:        1%{?dist}
Summary:        Dukiwi Shield — antivirus, protection et vérification d'intégrité pour Linux
License:        Proprietary
URL:            https://github.com/kahsky/dukiwi-shield
BuildArch:      noarch
Obsoletes:      clamav-antivirus < 2.0.0
Source0:        %{name}-%{version}.tar.gz

Requires:       python3 >= 3.8
Requires:       python3-gobject
Requires:       python3-pyudev
Requires:       webkit2gtk4.1
Requires:       libayatana-appindicator-gtk3
Requires:       gtk3
Requires:       polkit
Requires:       clamav
Requires:       clamd
Requires:       clamav-update
Requires:       lynis
Requires:       unhide
Requires:       chkrootkit
Requires:       msmtp
Requires:       zenity
Requires:       systemd
Requires:       udisks2
Requires:       firewalld
Requires:       dnf-plugins-core
Recommends:     gnome-shell-extension-appindicator
Recommends:     timeshift
Recommends:     rsync
Recommends:     rclone
Recommends:     gocryptfs
Recommends:     flatpak
Recommends:     dnf-automatic
%{?systemd_requires}

%description
Interface graphique moderne pour ClamAV avec un service système : analyses complètes sans mot de passe,
mises à jour planifiées, surveillance des rafales d'écritures (fanotify), analyse des clés USB avant
mise à disposition, état du système (avis de sécurité dnf et CVE), pare-feu firewalld piloté depuis
l'application, vérification d'intégrité (rpm -V, chkrootkit, unhide, Lynis, noyau, processus),
notifications par courrier, interface en français, anglais, allemand et italien.
Développé par Dukiwi SA, Estavayer-le-Lac, Suisse.

%prep
%setup -q

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}
cp -a tree/. %{buildroot}/
install -D -m 644 dukiwi.repo %{buildroot}%{_sysconfdir}/yum.repos.d/dukiwi.repo

%post
mkdir -p /var/lib/dukiwi-shield
# Anciens noms du fichier de dépôt (dukiwi-clamav < 1.25.1, nom de 1.25.1) : même dépôt : même dépôt, retiré pour ne pas le lister deux fois
rm -f /etc/yum.repos.d/dukiwi-clamav.repo /etc/yum.repos.d/dukiwi-clamav.repo.rpmsave /etc/yum.repos.d/linux-shield.repo /etc/yum.repos.d/linux-shield.repo.rpmsave
if [ "$1" = "1" ] && [ ! -f /var/lib/dukiwi-shield/state.json ]; then
    touch /var/lib/dukiwi-shield/first-scan-pending
fi
# clamd@scan : Fedora livre LocalSocket commenté dans scan.conf ; sans lui, pas de moteur clamd (clamscan lent)
if [ -f /etc/clamd.d/scan.conf ] && ! grep -q '^LocalSocket' /etc/clamd.d/scan.conf; then
    sed -i '0,/^#\s*LocalSocket\s/s|^#\s*LocalSocket\s\+\(\S\+\)|LocalSocket \1|' /etc/clamd.d/scan.conf
    grep -q '^LocalSocket' /etc/clamd.d/scan.conf || echo 'LocalSocket /run/clamd.scan/clamd.sock' >> /etc/clamd.d/scan.conf
fi
systemctl enable clamd@scan.service >/dev/null 2>&1 || true
systemctl enable clamav-freshclam.service >/dev/null 2>&1 || true
systemctl start clamav-freshclam.service >/dev/null 2>&1 || true

# ── Reprise d'une installation des versions précédentes (paquet « OLD », ≤ 1.31.1) ─────────────────────────────
# Le paquet précédent vient d'être retiré (Obsoletes) : état, quarantaine, cache, journaux, politique, fichiers
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

systemctl daemon-reload >/dev/null 2>&1 || true
udevadm control --reload-rules >/dev/null 2>&1 || true
/opt/dukiwi-shield/dukiwi-shield-browser-setup install >/dev/null 2>&1 || true
systemctl enable dukiwi-shield-daemon.service >/dev/null 2>&1 || true
systemctl enable dukiwi-shield-update.timer >/dev/null 2>&1 || true
systemctl restart dukiwi-shield-daemon.service >/dev/null 2>&1 || true
systemctl start dukiwi-shield-update.timer >/dev/null 2>&1 || true
pkill -f "/opt/dukiwi-shield/dukiwi-shield.py" >/dev/null 2>&1 || true
if command -v update-desktop-database >/dev/null 2>&1; then update-desktop-database /usr/share/applications/ >/dev/null 2>&1 || true; fi
if command -v restorecon >/dev/null 2>&1; then restorecon -R /opt/dukiwi-shield /var/lib/dukiwi-shield >/dev/null 2>&1 || true; fi

%posttrans
# Après le retrait de l'ancien paquet (son %preun peut arrêter et désactiver le service) : service actif et activé
systemctl daemon-reload >/dev/null 2>&1 || true
systemctl enable dukiwi-shield-daemon.service dukiwi-shield-update.timer >/dev/null 2>&1 || true
systemctl restart dukiwi-shield-daemon.service >/dev/null 2>&1 || true
systemctl start dukiwi-shield-update.timer >/dev/null 2>&1 || true

%preun
if [ "$1" = "0" ]; then
    /opt/dukiwi-shield/dukiwi-shield-browser-setup remove >/dev/null 2>&1 || true
    pkill -f "/opt/dukiwi-shield/dukiwi-shield.py" >/dev/null 2>&1 || true
    systemctl stop dukiwi-shield-update.timer >/dev/null 2>&1 || true
    systemctl disable dukiwi-shield-update.timer >/dev/null 2>&1 || true
    systemctl stop dukiwi-shield-daemon.service >/dev/null 2>&1 || true
    systemctl disable dukiwi-shield-daemon.service >/dev/null 2>&1 || true
    find /home -maxdepth 4 -xdev -type f -name '.dukiwi-guard-*' -delete >/dev/null 2>&1 || true
fi

%postun
systemctl daemon-reload >/dev/null 2>&1 || true
udevadm control --reload-rules >/dev/null 2>&1 || true

%files
/opt/dukiwi-shield
%{_unitdir}/dukiwi-shield-daemon.service
%{_unitdir}/dukiwi-shield-update.service
%{_unitdir}/dukiwi-shield-update.timer
%{_udevrulesdir}/*.rules
%{_datadir}/applications/dukiwi-shield.desktop
%{_datadir}/nemo/actions/dukiwi-shield-nemo.nemo_action
%{_datadir}/polkit-1/actions/com.dukiwi.dukiwi-shield.policy
%config(noreplace) %{_sysconfdir}/xdg/autostart/dukiwi-shield-autostart.desktop
%config(noreplace) %{_sysconfdir}/yum.repos.d/dukiwi.repo

%changelog
* Thu Oct 15 2026 Dukiwi SA <info@dukiwi.ch> - %{version}-1
- Prise en charge de Fedora : dnf, rpm, firewalld, SELinux
