#!/usr/bin/env python3
"""
Dukiwi Shield — protections actives (service système).

1. DNS filtré : systemd-resolved interroge un résolveur qui bloque les domaines malveillants (Quad9 ou Cloudflare
   « Security »), en DNS-over-TLS quand le réseau le permet. Fichier unique 90-dukiwi-shield-dns.conf, testé après
   application (annulé si plus rien ne se résout) ; suspendu sur un réseau au profil Entreprise (DNS interne).
2. Isoler l'ordinateur : réseau coupé (NetworkManager, sinon mode panique de firewalld, sinon ufw tout refusé),
   programmes suspects suspendus, analyse complète lancée ; « Rétablir le réseau » annule la coupure.
3. Chiffrement du dossier personnel (fscrypt) : vérifications et marche à suivre seulement, rien d'automatique.
(c) 2026 Dukiwi SA - Estavayer-le-Lac
"""

import glob
import os
import re
import shutil
import socket
import subprocess
import time

DNS_DROPIN = "/etc/systemd/resolved.conf.d/90-dukiwi-shield-dns.conf"
DNS_PROVIDERS = {
    "quad9": ["9.9.9.9#dns.quad9.net", "149.112.112.112#dns.quad9.net", "2620:fe::fe#dns.quad9.net", "2620:fe::9#dns.quad9.net"],
    "cloudflare": ["1.1.1.2#security.cloudflare-dns.com", "1.0.0.2#security.cloudflare-dns.com",
                   "2606:4700:4700::1112#security.cloudflare-dns.com", "2606:4700:4700::1002#security.cloudflare-dns.com"],
}
DNS_TEST_HOSTS = ("www.dukiwi.com", "debian.org", "fedoraproject.org")
SUSPICIOUS_EXE_PREFIXES = ("/tmp/", "/var/tmp/", "/dev/shm/", "/run/user/")


def run(cmd, timeout=60):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.SubprocessError) as e:
        return subprocess.CompletedProcess(cmd, 1, "", str(e))


def unit_active(name):
    return run(["systemctl", "is-active", "--quiet", name], timeout=10).returncode == 0


# ═══ 1. DNS filtré ════════════════════════════════════════════════════════
def resolved_usable():
    """systemd-resolved actif et /etc/resolv.conf pointant sur son résolveur local (sinon le réglage n'aurait aucun effet)."""
    if not shutil.which("resolvectl") or not unit_active("systemd-resolved"):
        return False, "resolved_missing"
    try:
        target = os.path.realpath("/etc/resolv.conf")
    except OSError:
        target = ""
    if "/run/systemd/resolve/" not in target:
        try:
            with open("/etc/resolv.conf") as f:
                if "127.0.0.53" not in f.read():
                    return False, "resolv_not_stub"
        except OSError:
            return False, "resolv_not_stub"
    return True, ""


def dns_status():
    usable, why = resolved_usable()
    provider = ""
    try:
        with open(DNS_DROPIN) as f:
            txt = f.read()
        provider = next((p for p, servers in DNS_PROVIDERS.items() if servers[0] in txt), "custom")
    except OSError:
        pass
    return {"usable": usable, "reason": why, "active": bool(provider), "provider": provider}


def dns_resolves(timeout=6.0):
    socket.setdefaulttimeout(timeout)
    try:
        for host in DNS_TEST_HOSTS:
            try:
                socket.getaddrinfo(host, 443)
                return True
            except OSError:
                continue
        return False
    finally:
        socket.setdefaulttimeout(None)


def restart_resolved():
    run(["systemctl", "restart", "systemd-resolved"], timeout=60)
    run(["resolvectl", "flush-caches"], timeout=20)
    time.sleep(1.5)


def dns_apply(provider):
    """Écrit le fichier de configuration, redémarre systemd-resolved et vérifie que la résolution marche encore ;
    sinon annule. Retourne (ok, erreur)."""
    if provider not in DNS_PROVIDERS:
        return False, "invalid_provider"
    usable, why = resolved_usable()
    if not usable:
        return False, why
    try:
        with open(DNS_DROPIN) as f:
            previous = f.read()
    except OSError:
        previous = None
    content = ("# Dukiwi Shield — DNS filtré (domaines malveillants bloqués). Désactivable dans Pare-feu › DNS filtré.\n"
               "[Resolve]\n"
               f"DNS={' '.join(DNS_PROVIDERS[provider])}\n"
               "DNSOverTLS=opportunistic\n"
               "Domains=~.\n")
    if previous == content:
        return True, ""
    os.makedirs(os.path.dirname(DNS_DROPIN), exist_ok=True)
    with open(DNS_DROPIN + ".tmp", "w") as f:
        f.write(content)
    os.chmod(DNS_DROPIN + ".tmp", 0o644)
    os.replace(DNS_DROPIN + ".tmp", DNS_DROPIN)
    restart_resolved()
    if dns_resolves():
        return True, ""
    # Le réseau bloque ce résolveur (pare-feu d'entreprise, portail captif) : retour à la configuration précédente
    if previous is None:
        os.unlink(DNS_DROPIN)
    else:
        with open(DNS_DROPIN, "w") as f:
            f.write(previous)
    restart_resolved()
    return False, "dns_test_failed"


def dns_remove():
    if not os.path.exists(DNS_DROPIN):
        return False
    os.unlink(DNS_DROPIN)
    restart_resolved()
    return True


# ═══ 2. Isoler l'ordinateur ═══════════════════════════════════════════════
def nm_running():
    return bool(shutil.which("nmcli")) and unit_active("NetworkManager")


def network_cut():
    """Coupe le réseau ; retourne (méthode, état précédent à restaurer) ou (None, erreur)."""
    if nm_running():
        r = run(["nmcli", "networking", "off"], timeout=30)
        if r.returncode == 0:
            return "nmcli", {}
    if shutil.which("firewall-cmd") and unit_active("firewalld"):
        r = run(["firewall-cmd", "--panic-on"], timeout=30)
        if r.returncode == 0:
            return "firewalld", {}
    if shutil.which("ufw"):
        status = run(["ufw", "status", "verbose"], timeout=30).stdout or ""
        m = re.search(r"Default:\s*(\w+) \(incoming\),\s*(\w+) \(outgoing\)", status)
        prev = {"incoming": m.group(1) if m else "deny", "outgoing": m.group(2) if m else "allow",
                "active": "Status: active" in status}
        ok = all(run(["ufw", "default", "deny", d], timeout=30).returncode == 0 for d in ("incoming", "outgoing"))
        if ok and not prev["active"]:
            ok = run(["ufw", "--force", "enable"], timeout=60).returncode == 0
        if ok:
            return "ufw", prev
    return None, "no_method"


def network_restore(method, prev):
    if method == "nmcli":
        return run(["nmcli", "networking", "on"], timeout=30).returncode == 0
    if method == "firewalld":
        return run(["firewall-cmd", "--panic-off"], timeout=30).returncode == 0
    if method == "ufw":
        ok = True
        for d in ("incoming", "outgoing"):
            ok = run(["ufw", "default", (prev or {}).get(d) or ("deny" if d == "incoming" else "allow"), d], timeout=30).returncode == 0 and ok
        if prev and prev.get("active") is False:
            run(["ufw", "--force", "disable"], timeout=60)
        return ok
    return False


def suspicious_processes(alert_pids=(), trusted=(), self_pid=None):
    """Processus à suspendre pendant l'isolement : exécutable dans un dossier temporaire ou effacé du disque, ou
    programme d'une alerte « danger » récente, jamais un programme approuvé ni un fil du noyau."""
    out = []
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        pid = int(entry)
        if pid in (1, self_pid or os.getpid()):
            continue
        try:
            exe = os.readlink(f"/proc/{pid}/exe")
            with open(f"/proc/{pid}/comm") as f:
                comm = f.read().strip()
        except OSError:
            continue
        clean = exe.replace(" (deleted)", "")
        if clean in trusted:
            continue
        reason = ""
        if clean.startswith(SUSPICIOUS_EXE_PREFIXES):
            reason = "exe_in_temp"
        elif exe.endswith(" (deleted)") and not clean.startswith(("/usr/", "/opt/", "/snap/", "/app/")):
            reason = "exe_deleted"
        elif pid in alert_pids:
            reason = "danger_alert"
        if reason:
            out.append({"pid": pid, "comm": comm, "exe": exe, "reason": reason})
    return out


# ═══ 3. Chiffrement du dossier personnel ══════════════════════════════════
def _findmnt(path):
    r = run(["findmnt", "-no", "SOURCE,FSTYPE,TARGET", "-T", path], timeout=10)
    parts = (r.stdout or "").split()
    return (parts + ["", "", ""])[:3]


def disk_encrypted():
    r = run(["lsblk", "-rno", "TYPE,FSTYPE"], timeout=10)
    return any("crypt" in ln or "LUKS" in ln for ln in (r.stdout or "").splitlines())


def home_encryption_check(users, sessions_uids=()):
    """État pour l'assistant : disque déjà chiffré, système de fichiers de /home, fonction « encrypt » d'ext4, outils
    installés, et pour chaque utilisateur : dossier chiffré ou non, connecté, taille et place libre."""
    source, fstype, target = _findmnt("/home")
    feature = None
    if fstype == "ext4" and source.startswith("/dev/") and shutil.which("tune2fs"):
        r = run(["tune2fs", "-l", source], timeout=20)
        feats = re.search(r"^Filesystem features:\s*(.*)$", r.stdout or "", re.M)
        feature = bool(feats and "encrypt" in feats.group(1).split())
    elif fstype == "f2fs":
        feature = True                                  # f2fs : chiffrement activé au formatage (-O encrypt), vérifié par fscrypt setup
    pam = bool(glob.glob("/lib/*/security/pam_fscrypt.so") + glob.glob("/usr/lib/*/security/pam_fscrypt.so")
               + glob.glob("/usr/lib64/security/pam_fscrypt.so") + glob.glob("/lib/security/pam_fscrypt.so"))
    boot_same_fs = _findmnt("/boot")[0] == source
    st = os.statvfs(target or "/home")
    free = st.f_bavail * st.f_frsize
    out_users = []
    for pw in users:
        if pw.pw_uid < 1000:
            continue
        encrypted, method = False, ""
        private = f"/home/.ecryptfs/{pw.pw_name}/.Private"
        try:
            ecr_user = _findmnt(pw.pw_dir)[1] == "ecryptfs" or (os.path.isdir(private) and any(os.scandir(private)))
        except OSError:
            ecr_user = False
        if ecr_user:
            out_users.append({"user": pw.pw_name, "home": pw.pw_dir, "encrypted": True, "method": "ecryptfs",
                              "logged_in": pw.pw_uid in sessions_uids, "size": 0, "space_ok": True})
            continue
        if shutil.which("fscrypt"):
            r = run(["fscrypt", "status", pw.pw_dir], timeout=15)
            encrypted = r.returncode == 0 and "is encrypted with fscrypt" in (r.stdout or "")
        if not encrypted and shutil.which("lsattr"):
            r = run(["lsattr", "-d", pw.pw_dir], timeout=10)
            encrypted = "E" in ((r.stdout or "").split() or [""])[0]
        r = run(["du", "-sxb", pw.pw_dir], timeout=120)
        try:
            size = int((r.stdout or "0").split()[0])
        except (ValueError, IndexError):
            size = 0
        out_users.append({"user": pw.pw_name, "home": pw.pw_dir, "encrypted": encrypted, "method": "fscrypt" if encrypted else "",
                          "logged_in": pw.pw_uid in sessions_uids,
                          "size": size, "space_ok": free > size * 1.1})
    try:
        ecryptfs = any(os.scandir("/home/.ecryptfs"))      # dossier vide laissé par un ancien paquet : ignoré
    except OSError:
        ecryptfs = False
    return {"checked_at": time.strftime("%Y-%m-%dT%H:%M:%S"), "disk_encrypted": disk_encrypted(), "ecryptfs": ecryptfs,
            "fs": fstype, "device": source, "fs_supported": fstype in ("ext4", "f2fs"), "encrypt_feature": feature,
            "boot_same_fs": boot_same_fs, "fscrypt": bool(shutil.which("fscrypt")), "pam": pam, "free": free, "users": out_users}
