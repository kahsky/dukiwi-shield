#!/usr/bin/env python3
"""
Dukiwi Shield — détections du centre de sécurité (service système).

1. Leurres anti-rançongiciel : un fichier caché par dossier (Documents, Images, Bureau, dossier personnel). Personne n'a
   de raison de l'écrire : un programme qui le modifie est suspendu (réponse automatique) et signalé ; un leurre
   supprimé ou renommé est signalé, avec le programme qui écrivait dans ce dossier à ce moment-là s'il y en a un.
2. Caméra et micro : programme qui ouvre /dev/video* (lecture de /proc/*/fd) ou qui enregistre le micro (pactl, par
   session) → popup d'information, « Toujours autoriser » mémorisé.
3. Mineurs de cryptomonnaie : nom connu, adresse de pool (stratum+tcp://…) ou options de mineur dans la ligne de
   commande → danger (suspension) ; connexion vers un port de pool avec un processeur saturé, ou programme hors paquets
   qui sature le processeur pendant 15 minutes → avertissement.
4. Certificats racine ajoutés : magasin du système et bases NSS (Firefox, Chrome, Thunderbird). Un certificat racine
   ajouté permet d'intercepter le HTTPS ; chaque nouveau est signalé, la checklist les liste (« Ignorer » par empreinte).
5. Détournement réseau : /etc/hosts vers une adresse publique, proxy (bureau, Firefox, /etc/environment, apt, dnf),
   nouveau serveur DNS public inconnu sur un réseau déjà connu.
(c) 2026 Dukiwi SA - Estavayer-le-Lac
"""

import glob
import hashlib
import ipaddress
import os
import pwd
import re
import shutil
import subprocess
import tempfile
import threading
import time
import zipfile

import dukiwi_shield_audit as audit
from dukiwi_shield_common import home_mounted
from datetime import datetime

DECOY_PREFIX = ".dukiwi-guard-"
DECOY_DIRS = (("DOCUMENTS", "Documents", "docx"), ("PICTURES", "Pictures", "jpg"), ("DESKTOP", "Desktop", "pdf"), ("", "", "xlsx"))
DECOY_CHECK_SEC = 5
DECOY_MISSING_COOLDOWN = 3600            # s entre deux alertes « leurre supprimé » sans programme identifié (même chemin)
SUSPECT_WINDOW = 30                      # s : programme qui écrivait dans le dossier du leurre juste avant sa disparition

PRIVACY_CHECK_SEC = 5
PRIVACY_COOLDOWN = 900                   # s avant de signaler à nouveau le même programme sur le même appareil
PRIVACY_IGNORED = {"pipewire", "wireplumber", "pipewire-media-session", "pulseaudio", "pipewire-pulse", "v4l2-relayd",
                   "pavucontrol", "gnome-control-center", "cinnamon-settings", "plasmashell", "kmix", "xdg-desktop-portal"}

MINER_CHECK_SEC = 15
MINER_NAMES = {"xmrig", "xmr-stak", "xmr-stak-cpu", "minerd", "cpuminer", "cpuminer-multi", "ethminer", "nbminer", "t-rex",
               "lolminer", "phoenixminer", "nanominer", "srbminer", "srbminer-multi", "cgminer", "bfgminer", "gminer",
               "teamredminer", "kdevtmpfsi", "kinsing", "xmrigdaemon", "xmrigminer", "ccminer", "bminer", "wildrig"}
MINER_CMD_RE = re.compile(r"stratum\d?\+(tcp|ssl|tls)://|--donate-level|--coin[= ](monero|xmr|eth|etc|rvn|kas)|--algo[= ](rx/|cn/|randomx|kawpow|ethash)|"
                          r"(minexmr|nanopool\.org|supportxmr|2miners\.com|f2pool|hashvault\.pro|moneroocean|c3pool|herominers|unmineable|"
                          r"nicehash\.com|xmrpool|minergate|ethermine|miningpoolhub)", re.I)
MINER_PORTS = {3333, 4444, 5555, 7777, 14444, 14433, 45700}
CPU_BUSY = 0.8                           # fraction d'un cœur
CPU_SUSTAINED_SEC = 900
CPU_IGNORE_PARTS = ("/steamapps/", "/Steam/", "/lutris/", "/Heroic/", "/.wine/", "/Games/")

SLOW_CHECK_SEC = 600                     # certificats, détournement réseau
WATCH_CHECK_SEC = 60                     # démarrage automatique, tâches planifiées, services, extensions
SSH_CHECK_SEC = 30                       # clés SSH autorisées
KEYLOGGER_CHECK_SEC = 15                 # programmes qui lisent le clavier
LOGIN_CHECK_SEC = 60                     # connexions SSH et ouvertures de session
PERSISTENCE_DIRS = ("/etc/xdg/autostart", "/etc/cron.d", "/etc/cron.hourly", "/etc/cron.daily", "/etc/cron.weekly", "/etc/cron.monthly",
                    "/var/spool/cron/crontabs", "/var/spool/cron/atjobs", "/var/spool/at", "/etc/systemd/system", "/etc/profile.d",
                    "/etc/rc.local", "/etc/ld.so.preload")
SSH_KEY_TYPES = ("ssh-rsa", "ssh-dss", "ssh-ed25519", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521",
                 "sk-ssh-ed25519@openssh.com", "sk-ecdsa-sha2-nistp256@openssh.com")
SUID_SKIP = ("/var/lib/docker/", "/var/lib/containers/", "/containers/storage/", "/var/lib/lxc/", "/var/lib/lxd/", "/var/lib/flatpak/",
             "/var/lib/snapd/", "/snap/", "/var/lib/waydroid/", "/var/lib/machines/", "/.local/share/flatpak/",
             "/.ecryptfs/")                      # copie chiffrée d'eCryptfs : la vue déchiffrée (type ecryptfs) est analysée
CERT_ANCHOR_DIRS = ("/usr/local/share/ca-certificates", "/etc/pki/ca-trust/source/anchors", "/etc/ca-certificates/trust-source/anchors")
TRUSTED_RESOLVERS = {"1.1.1.1", "1.0.0.1", "1.1.1.2", "1.0.0.2", "1.1.1.3", "1.0.0.3", "8.8.8.8", "8.8.4.4", "9.9.9.9", "149.112.112.112",
                     "9.9.9.10", "149.112.112.10", "9.9.9.11", "149.112.112.11", "208.67.222.222", "208.67.220.220", "208.67.222.123",
                     "208.67.220.123", "94.140.14.14", "94.140.15.15", "76.76.2.0", "76.76.10.0", "185.228.168.9", "185.228.169.9",
                     "2606:4700:4700::1111", "2606:4700:4700::1001", "2606:4700:4700::1112", "2606:4700:4700::1002", "2620:fe::fe",
                     "2620:fe::9", "2001:4860:4860::8888", "2001:4860:4860::8844", "2620:119:35::35", "2620:119:53::53"}
VPN_LINK_RE = re.compile(r"^(tun|tap|wg|ppp|tailscale|proton|nordlynx|mullvad|zt|cscotun|vpn)", re.I)


def now_iso():
    return datetime.now().isoformat(timespec="seconds")


def run_quiet(cmd, timeout=30, env=None):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env)
    except (OSError, subprocess.SubprocessError):
        return subprocess.CompletedProcess(cmd, 1, "", "")


def is_public(ip):
    try:
        a = ipaddress.ip_address(ip.split("%")[0])
    except ValueError:
        return False
    if a.version == 6 and a not in ipaddress.ip_network("2000::/3"):
        return False                                     # fe00::, ff02::1… (fichier hosts par défaut)
    return a.is_global and not a.is_multicast


def local_v6_prefixes():
    """Préfixes /64 globaux des interfaces : le routeur (serveur DNS) y a son adresse, qui change avec le préfixe du fournisseur."""
    out = set()
    try:
        with open("/proc/net/if_inet6") as f:
            for ln in f:
                h = ln.split()[0]
                if h[:1] in "23":
                    out.add(h[:16])
    except OSError:
        pass
    return out


def same_local_v6(ip, prefixes):
    try:
        a = ipaddress.ip_address(ip.split("%")[0])
    except ValueError:
        return False
    return a.version == 6 and a.exploded.replace(":", "")[:16] in prefixes


def proc_info(pid):
    info = {"pid": pid, "comm": "?", "exe": "", "cmdline": "", "uid": None, "user": ""}
    try:
        with open(f"/proc/{pid}/comm") as f:
            info["comm"] = f.read().strip()
        info["exe"] = os.readlink(f"/proc/{pid}/exe")
    except OSError:
        pass
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as f:
            info["cmdline"] = f.read().replace(b"\0", b" ").decode(errors="replace").strip()[:300]
        st = os.stat(f"/proc/{pid}")
        info["uid"] = st.st_uid
        info["user"] = pwd.getpwuid(st.st_uid).pw_name
    except (OSError, KeyError):
        pass
    return info


def machine_tag():
    """Suffixe propre à cette machine : deux ordinateurs qui synchronisent le même dossier n'écrivent pas le même leurre."""
    try:
        with open("/etc/machine-id") as f:
            return hashlib.sha256(f.read().strip().encode()).hexdigest()[:6]
    except OSError:
        return hashlib.sha256(os.uname().nodename.encode()).hexdigest()[:6]


def xdg_dir(pw, key, default):
    """Dossier XDG localisé (Images, Bureau…) d'après ~/.config/user-dirs.dirs."""
    if not key:
        return pw.pw_dir
    try:
        with open(os.path.join(pw.pw_dir, ".config", "user-dirs.dirs")) as f:
            for ln in f:
                m = re.match(rf'^\s*XDG_{key}_DIR="(.*)"', ln)
                if m:
                    path = m.group(1).replace("$HOME", pw.pw_dir)
                    return path if path.rstrip("/") != pw.pw_dir.rstrip("/") else ""
    except OSError:
        pass
    return os.path.join(pw.pw_dir, default)


def decoy_bytes(ext, seed):
    """Contenu vraisemblable (vrai document zip pour docx/xlsx, en-têtes JPEG/PDF) : un rançongiciel qui trie par type le prend."""
    filler = hashlib.sha256(seed.encode()).hexdigest() * 64
    if ext in ("docx", "xlsx"):
        import io
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr("[Content_Types].xml", '<?xml version="1.0" encoding="UTF-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>')
            z.writestr("word/document.xml" if ext == "docx" else "xl/workbook.xml", f"<doc>{filler}</doc>")
        return buf.getvalue()
    if ext == "jpg":
        return b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00" + filler.encode() + b"\xff\xd9"
    return b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n" + filler.encode() + b"\n%%EOF\n"


class SecurityGuard(threading.Thread):
    def __init__(self, daemon, helpers):
        super().__init__(daemon=True, name="security-guard")
        self.d = daemon
        self.log = helpers["log"]
        self.write_log = helpers["write_log"]
        self.exe_trusted = helpers["exe_trusted"]        # paquet du système, /opt, snap, flatpak, ou approuvé
        self.dconf_read = helpers["dconf_read"]
        self.human_users = helpers["human_users"]
        self.lock = threading.Lock()
        self.tag = machine_tag()
        self.decoys = {}                 # chemin → {sha, ino, size, mtime, uid}
        self.decoys_pending = []         # comptes dont le dossier personnel n'est pas encore monté (eCryptfs)
        self.last_decoy_sync = 0.0
        self.decoy_alerted = {}          # chemin → horodatage (alerte sans programme identifié)
        self.decoy_pid_alerted = {}      # pid → horodatage
        self.privacy_active = {}         # (exe, appareil) → {pid, comm, since}
        self.privacy_alerted = {}        # (exe, appareil) → horodatage
        self.cpu_prev = {}               # pid → (ticks, horodatage)
        self.cpu_busy_since = {}         # pid → horodatage du début de la saturation
        self.miner_alerted = {}          # exe → horodatage
        self.clk = os.sysconf("SC_CLK_TCK") if hasattr(os, "sysconf") else 100
        self._certs = (0.0, None)
        self._redirects = (0.0, None)
        self.persistence_fp = None
        self.keylogger_alerted = {}      # (exe, appareil) → horodatage
        self.login_cursor = None
        self.persistence_running = False
        self.active = False

    # ── boucle ───────────────────────────────────────────────────────────
    def run(self):
        self.active = True
        last = {"decoy": 0.0, "privacy": 0.0, "miner": 0.0, "slow": time.time() - SLOW_CHECK_SEC + 90, "watch": 0.0, "ssh": 0.0,
                "keys": 0.0, "logins": 0.0}
        try:
            self.sync_decoys()
        except Exception as e:  # noqa: BLE001
            self.log(f"Leurres : {e}")
        self.log(f"Centre de sécurité : leurres ({len(self.decoys)}), caméra/micro, mineurs, certificats, détournement réseau")
        while not self.d.shutdown.wait(1):
            now = time.time()
            for name, period, fn in (("decoy", DECOY_CHECK_SEC, self.check_decoys), ("privacy", PRIVACY_CHECK_SEC, self.check_privacy),
                                     ("miner", MINER_CHECK_SEC, self.check_miners), ("slow", SLOW_CHECK_SEC, self.check_slow),
                                     ("watch", WATCH_CHECK_SEC, self.check_persistence), ("ssh", SSH_CHECK_SEC, self.check_ssh_keys),
                                     ("keys", KEYLOGGER_CHECK_SEC, self.check_keyloggers), ("logins", LOGIN_CHECK_SEC, self.check_logins)):
                if now - last[name] >= period:
                    last[name] = now
                    try:
                        fn()
                    except Exception as e:  # noqa: BLE001
                        self.log(f"Centre de sécurité ({name}) : {e}")
        self.active = False

    def setting(self, key):
        return self.d.settings.get(key) is not False

    def alert(self, kind, severity, **fields):
        base = {"kind": kind, "severity": severity, "time": now_iso(), "pid": 0, "comm": "", "exe": "", "count": 0,
                "top_dir": "", "reasons": [], "sample": [], "title": "", "detail": ""}
        base.update(fields)
        self.d.publish_alert(base)

    # ═══ 1. Leurres anti-rançongiciel ═════════════════════════════════════
    def decoy_paths(self):
        out = []
        pending = []
        for pw in self.human_users():
            if pw.pw_uid < 1000:
                continue
            if not home_mounted(pw):
                pending.append(pw.pw_name)
                for leftover in glob.glob(os.path.join(pw.pw_dir, DECOY_PREFIX + "*")):
                    try:
                        os.unlink(leftover)              # leurre écrit sous le montage par une version précédente : inutile
                    except OSError:
                        pass
                continue
            for key, default, ext in DECOY_DIRS:
                folder = xdg_dir(pw, key, default)
                if folder and os.path.isdir(folder):
                    out.append((os.path.join(folder, f"{DECOY_PREFIX}{self.tag}.{ext}"), pw, ext))
        seen, uniq = set(), []
        for item in out:
            if item[0] not in seen:
                seen.add(item[0])
                uniq.append(item)
        self.decoys_pending = pending
        return uniq

    def write_decoy(self, path, pw, ext):
        data = decoy_bytes(ext, path + self.tag)
        tmp = path + ".tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o644)
        try:
            os.write(fd, data)
            os.fchown(fd, pw.pw_uid, pw.pw_gid)
        finally:
            os.close(fd)
        os.replace(tmp, path)
        old = int(time.time()) - 86400 * 40          # date ancienne : ressemble à un document existant
        os.utime(path, (old, old), follow_symlinks=False)
        st = os.lstat(path)
        self.decoys[path] = {"sha": hashlib.sha256(data).hexdigest(), "ino": st.st_ino, "size": st.st_size,
                             "mtime": st.st_mtime, "uid": pw.pw_uid, "ext": ext, "user": pw.pw_name}

    def sync_decoys(self):
        """Crée les leurres manquants (ou les retire si la protection est désactivée). Au démarrage, un leurre modifié
        pendant l'arrêt du service est signalé puis réécrit."""
        stored = self.d.state.get("decoys") or {}
        self.last_decoy_sync = time.time()
        if not self.setting("ransomware_decoys"):
            self.remove_decoys()
            return
        with self.lock:
            for path, pw, ext in self.decoy_paths():
                try:
                    st = os.lstat(path)
                except FileNotFoundError:
                    st = None
                prev = self.decoys.get(path) or stored.get(path)       # la mémoire du service d'abord (à jour), puis l'état sauvé
                if st is not None and prev:
                    if self.file_sha(path) == prev.get("sha"):
                        self.decoys[path] = dict(prev, ino=st.st_ino, size=st.st_size, mtime=st.st_mtime)
                        continue
                    self.write_log(f"⚠ ransomware decoy modified while the service was stopped: {path}")
                    self.alert("ransomware", "warn", title=os.path.basename(path), detail=path, path=path, top_dir=os.path.dirname(path),
                               reasons=["decoy_changed_offline"], user=pw.pw_name)
                try:
                    self.write_decoy(path, pw, ext)
                except OSError as e:
                    self.log(f"Leurre {path} : {e}")
            self.save_decoys()

    def remove_decoys(self):
        with self.lock:
            stored = dict(self.d.state.get("decoys") or {})
            stored.update(self.decoys)
            for path in stored:
                if os.path.basename(path).startswith(DECOY_PREFIX):
                    try:
                        os.unlink(path)
                    except OSError:
                        pass
            self.decoys = {}
            self.save_decoys()

    def save_decoys(self):
        data = {p: {k: v for k, v in i.items() if k in ("sha", "uid", "ext", "user")} for p, i in self.decoys.items()}
        if data != (self.d.state.get("decoys") or {}):
            self.d.state.update(decoys=data)

    @staticmethod
    def file_sha(path):
        h = hashlib.sha256()
        try:
            with open(path, "rb", opener=lambda p, fl: os.open(p, fl | os.O_NOFOLLOW)) as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    h.update(chunk)
        except OSError:
            return ""
        return h.hexdigest()

    def consider(self, pid, path):
        """Appelé par le moniteur d'activité (fanotify) pour chaque fichier écrit puis fermé."""
        if path in self.decoys and self.setting("ransomware_decoys"):
            threading.Thread(target=self.decoy_written, args=(pid, path), daemon=True).start()

    def decoy_written(self, pid, path):
        info = proc_info(pid)
        now = time.time()
        with self.lock:
            meta = self.decoys.get(path) or {}
            if self.file_sha(path) == meta.get("sha"):
                return                                   # réécrit à l'identique (synchronisation, sauvegarde restaurée)
            if now - self.decoy_pid_alerted.get(pid, 0) < 60:
                self.recreate(path)
                return
            self.decoy_pid_alerted[pid] = now
        self.report_decoy(info, path, "decoy_modified")
        with self.lock:
            self.recreate(path)

    def report_decoy(self, info, path, reason):
        exe = (info.get("exe") or "").replace(" (deleted)", "")
        if exe and exe in self.d.user_trusted():
            self.write_log(f"ransomware decoy {reason} by trusted program {exe}: {path}")
            return
        self.write_log(f"⚠ danger: ransomware decoy {reason} by {info.get('comm')} (pid {info.get('pid')}, {exe}): {path}")
        self.alert("ransomware", "danger", pid=info.get("pid") or 0, comm=info.get("comm") or "", exe=info.get("exe") or "",
                   cmdline=info.get("cmdline") or "", user=info.get("user") or "", title=os.path.basename(path), detail=path,
                   path=path, top_dir=os.path.dirname(path), reasons=[reason])

    def recreate(self, path):
        meta = self.decoys.get(path) or {}
        try:
            pw = pwd.getpwuid(meta.get("uid"))
            self.write_decoy(path, pw, meta.get("ext") or path.rsplit(".", 1)[-1])
            self.save_decoys()                            # nouvelle empreinte (un .docx/.xlsx change à chaque écriture)
        except (KeyError, OSError, TypeError) as e:
            self.log(f"Leurre {path} : recréation impossible ({e})")

    def suspect_writer(self, folder):
        """Programme qui écrivait dans `folder` dans les dernières secondes (suivi du moniteur d'activité)."""
        monitor = getattr(self.d, "monitor", None)
        best, best_n = None, 0
        cutoff = time.time() - SUSPECT_WINDOW
        for pid, track in list(getattr(monitor, "tracks", {}).items()):
            if track.get("first", 0) < cutoff - 60 or pid == os.getpid():
                continue
            n = sum(1 for p in list(track.get("paths") or ()) if os.path.dirname(p) == folder)
            if n > best_n and os.path.exists(f"/proc/{pid}"):
                best, best_n = pid, n
        return best

    def check_decoys(self):
        if not self.setting("ransomware_decoys"):
            if self.decoys:
                self.remove_decoys()
            return
        if (not self.decoys or self.decoys_pending) and time.time() - self.last_decoy_sync > 30:
            self.sync_decoys()                            # dossier personnel monté entre-temps (ouverture de session)
            if not self.decoys:
                return
        for path in list(self.decoys):
            meta = self.decoys.get(path)
            if not meta:
                continue
            try:
                st = os.lstat(path)
            except FileNotFoundError:
                st = None
            if st is None:
                try:
                    pw = pwd.getpwuid(meta.get("uid"))
                except (KeyError, TypeError):
                    pw = None
                if pw is not None and not home_mounted(pw):
                    with self.lock:
                        self.decoys.pop(path, None)       # session fermée : le dossier chiffré est démonté, rien à signaler
                        if pw.pw_name not in self.decoys_pending:
                            self.decoys_pending.append(pw.pw_name)
                    continue
            if st is not None and st.st_ino == meta["ino"] and st.st_size == meta["size"] and st.st_mtime == meta["mtime"]:
                continue
            if st is not None and self.file_sha(path) == meta["sha"]:
                meta.update(ino=st.st_ino, size=st.st_size, mtime=st.st_mtime)
                continue
            if st is not None and time.time() - st.st_mtime < 10 and getattr(getattr(self.d, "monitor", None), "active", False):
                continue                                  # écriture toute récente : le moniteur d'activité donne le programme
            # Disparu, renommé ou remplacé sans fermeture d'écriture vue : programme qui écrivait là, sinon avertissement
            pid = self.suspect_writer(os.path.dirname(path))
            reason = "decoy_removed" if st is None else "decoy_replaced"
            if pid:
                self.report_decoy(proc_info(pid), path, reason)
            elif time.time() - self.decoy_alerted.get(path, 0) > DECOY_MISSING_COOLDOWN:
                self.decoy_alerted[path] = time.time()
                self.write_log(f"⚠ ransomware decoy {reason}: {path}")
                self.alert("ransomware", "warn", title=os.path.basename(path), detail=path, path=path, top_dir=os.path.dirname(path),
                           reasons=[reason], user=meta.get("user") or "")
            with self.lock:
                self.recreate(path)

    def decoy_list(self):
        return sorted(self.decoys)

    # ═══ 2. Caméra et micro ═══════════════════════════════════════════════
    def camera_users(self):
        """{(exe, "camera"): {pid, comm, exe, user, device}} des programmes qui ont /dev/video* ouvert."""
        if not glob.glob("/dev/video*"):
            return {}
        out = {}
        for pid in os.listdir("/proc"):
            if not pid.isdigit() or int(pid) == os.getpid():
                continue
            fd_dir = f"/proc/{pid}/fd"
            try:
                fds = os.listdir(fd_dir)
            except OSError:
                continue
            for fd in fds:
                try:
                    target = os.readlink(f"{fd_dir}/{fd}")
                except OSError:
                    continue
                if target.startswith("/dev/video"):
                    info = proc_info(int(pid))
                    if info["comm"] not in PRIVACY_IGNORED:
                        out[(info["exe"] or info["comm"], "camera")] = dict(info, device=target)
                    break
        return out

    def mic_users(self):
        """Enregistrements du micro en cours (pactl list source-outputs) pour chaque session qui a un serveur son."""
        if not shutil.which("pactl"):
            return {}
        out = {}
        for path in glob.glob("/run/user/*"):
            uid = os.path.basename(path)
            if not uid.isdigit() or int(uid) < 1000 or not (os.path.exists(f"{path}/pulse/native") or os.path.exists(f"{path}/pipewire-0")):
                continue
            try:
                pw = pwd.getpwuid(int(uid))
            except KeyError:
                continue
            env = {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "XDG_RUNTIME_DIR": path, "HOME": pw.pw_dir}
            base = ["runuser", "-u", pw.pw_name, "--", "env", f"XDG_RUNTIME_DIR={path}", f"HOME={pw.pw_dir}", "LC_ALL=C"] if os.geteuid() == 0 else []
            sources = run_quiet(base + ["pactl", "list", "short", "sources"], timeout=5, env=env)
            monitors = {ln.split("\t")[0] for ln in (sources.stdout or "").splitlines() if ".monitor" in ln}
            r = run_quiet(base + ["pactl", "list", "source-outputs"], timeout=5, env=env)
            for block in re.split(r"\n(?=Source Output #)", r.stdout or ""):
                m_src = re.search(r"^\s*Source:\s*(\S+)", block, re.M)
                if m_src and m_src.group(1) in monitors:
                    continue                                 # capture du son des haut-parleurs (vumètre, partage d'écran)
                props = dict(re.findall(r'^\s*([\w.]+) = "(.*)"$', block, re.M))
                pid = props.get("application.process.id")
                if not pid or not pid.isdigit():
                    continue
                info = proc_info(int(pid))
                name = props.get("application.process.binary") or info["comm"]
                if name in PRIVACY_IGNORED or info["comm"] in PRIVACY_IGNORED:
                    continue
                out[(info["exe"] or name, "microphone")] = dict(info, comm=info["comm"] if info["comm"] != "?" else name,
                                                                 device=props.get("application.name") or name)
        return out

    def check_privacy(self):
        if not self.setting("privacy_watch"):
            self.privacy_active = {}
            return
        current = self.camera_users()
        current.update(self.mic_users())
        allowed = self.d.state.get("privacy_allowed") or {}
        now = time.time()
        for key, info in current.items():
            if key in self.privacy_active:
                continue
            self.privacy_active[key] = {"pid": info["pid"], "comm": info["comm"], "since": now}
            exe, device = key
            if exe in allowed or now - self.privacy_alerted.get(key, 0) < PRIVACY_COOLDOWN:
                continue
            self.privacy_alerted[key] = now
            trusted = bool(info["exe"]) and self.exe_trusted(info["exe"])
            self.write_log(f"privacy: {device} used by {info['comm']} (pid {info['pid']}, {info['exe']})")
            self.alert("privacy", "info" if trusted else "warn", pid=info["pid"], comm=info["comm"], exe=info["exe"], user=info["user"],
                       device=device, title=info["comm"], detail=info.get("device") or "", reasons=[f"privacy_{device}"],
                       trusted=trusted)
        for key in list(self.privacy_active):
            if key not in current:
                self.privacy_active.pop(key, None)
                self.privacy_alerted[key] = now          # le délai court depuis la fin de l'utilisation

    def privacy_state(self):
        return [{"exe": k[0], "device": k[1], "comm": v["comm"], "pid": v["pid"]} for k, v in self.privacy_active.items()]

    # ═══ 3. Mineurs de cryptomonnaie ══════════════════════════════════════
    def pool_connections(self):
        """{pid: port distant} des connexions établies vers un port de pool de minage."""
        out = {}
        r = run_quiet(["ss", "-Htnp", "state", "established"], timeout=10)
        for ln in (r.stdout or "").splitlines():
            parts = ln.split()
            if len(parts) < 4:
                continue
            peer = parts[3]
            port = peer.rsplit(":", 1)[-1]
            if not port.isdigit() or int(port) not in MINER_PORTS or not is_public(peer.rsplit(":", 1)[0].strip("[]")):
                continue
            for pid in re.findall(r"pid=(\d+)", ln):
                out[int(pid)] = int(port)
        return out

    def cpu_fraction(self, pid, now):
        try:
            with open(f"/proc/{pid}/stat") as f:
                fields = f.read().rsplit(")", 1)[1].split()
            ticks = int(fields[11]) + int(fields[12])
        except (OSError, IndexError, ValueError):
            return None
        prev = self.cpu_prev.get(pid)
        self.cpu_prev[pid] = (ticks, now)
        if not prev or now <= prev[1]:
            return None
        return (ticks - prev[0]) / self.clk / (now - prev[1])

    def check_miners(self):
        if not self.setting("miner_watch"):
            return
        now = time.time()
        pools = self.pool_connections()
        trusted_set = self.d.user_trusted()
        alive = set()
        for entry in os.listdir("/proc"):
            if not entry.isdigit():
                continue
            pid = int(entry)
            if pid == os.getpid():
                continue
            alive.add(pid)
            cpu = self.cpu_fraction(pid, now)
            try:
                with open(f"/proc/{pid}/comm") as f:
                    comm = f.read().strip()
                with open(f"/proc/{pid}/cmdline", "rb") as f:
                    cmd = f.read().replace(b"\0", b" ").decode(errors="replace")[:600]
            except OSError:
                continue
            if not cmd:
                continue                                  # fil du noyau
            base = os.path.basename(cmd.split(" ", 1)[0]).lower()
            named = comm.lower() in MINER_NAMES or base in MINER_NAMES
            cmd_hit = MINER_CMD_RE.search(cmd)
            busy = cpu is not None and cpu >= CPU_BUSY
            if busy:
                self.cpu_busy_since.setdefault(pid, now)
            else:
                self.cpu_busy_since.pop(pid, None)
            if not (named or cmd_hit or pid in pools or busy):
                continue
            info = proc_info(pid)
            exe = info["exe"].replace(" (deleted)", "")
            if exe in trusted_set or now - self.miner_alerted.get(exe or comm, 0) < 86400:
                continue
            reasons, severity = [], ""
            if named:
                reasons.append("miner_name")
            if cmd_hit:
                reasons.append("miner_pool" if "stratum" in cmd_hit.group(0).lower() or "." in cmd_hit.group(0) else "miner_options")
            if reasons:
                severity = "danger"
            elif pid in pools and busy:
                severity, reasons = "danger", ["miner_port_cpu"]
            elif busy and now - self.cpu_busy_since.get(pid, now) >= CPU_SUSTAINED_SEC and exe \
                    and not any(p in exe for p in CPU_IGNORE_PARTS) and not self.exe_trusted(exe):
                severity, reasons = "warn", ["miner_cpu"]
            if not severity:
                continue
            self.miner_alerted[exe or comm] = now
            detail = f"{pools[pid]}" if pid in pools else ""
            self.alert("miner", severity, pid=pid, comm=info["comm"], exe=info["exe"], cmdline=info["cmdline"], user=info["user"],
                       title=info["comm"], detail=detail, reasons=reasons, cpu=round((cpu or 0) * 100), port=pools.get(pid) or 0)
        for pid in list(self.cpu_prev):
            if pid not in alive:
                self.cpu_prev.pop(pid, None)
                self.cpu_busy_since.pop(pid, None)

    # ═══ 4. Certificats racine ajoutés ════════════════════════════════════
    @staticmethod
    def pem_blocks(text):
        return re.findall(r"-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----", text, re.S)

    @staticmethod
    def cert_details(pem):
        """(empreinte SHA-256, sujet, fin de validité) d'un certificat PEM."""
        import ssl
        try:
            der = ssl.PEM_cert_to_DER_cert(pem)
        except ValueError:
            return None
        fp = hashlib.sha256(der).hexdigest().upper()
        subject, end = "", ""
        if shutil.which("openssl"):
            r = subprocess.run(["openssl", "x509", "-noout", "-subject", "-enddate", "-nameopt", "utf8,sep_comma_plus"],
                               input=pem, capture_output=True, text=True, timeout=10)
            for ln in (r.stdout or "").splitlines():
                if ln.startswith("subject="):
                    subject = ln.split("=", 1)[1].strip()
                elif ln.startswith("notAfter="):
                    end = ln.split("=", 1)[1].strip()
        cn = re.search(r"CN\s*=\s*([^,]+)", subject)
        o = re.search(r"O\s*=\s*([^,]+)", subject)
        return fp, (cn.group(1) if cn else (o.group(1) if o else subject)).strip()[:120], end

    def system_anchor_certs(self):
        out = []
        for d in CERT_ANCHOR_DIRS:
            for path in sorted(glob.glob(os.path.join(d, "**", "*"), recursive=True)):
                if not os.path.isfile(path):
                    continue
                try:
                    with open(path, "rb") as f:
                        raw = f.read(1 << 20)
                except OSError:
                    continue
                text = raw.decode(errors="replace")
                blocks = self.pem_blocks(text)
                if not blocks and shutil.which("openssl"):
                    r = subprocess.run(["openssl", "x509", "-inform", "DER", "-outform", "PEM"], input=raw, capture_output=True, timeout=10)
                    blocks = self.pem_blocks(r.stdout.decode(errors="replace"))
                for pem in blocks[:5]:
                    det = self.cert_details(pem)
                    if det:
                        out.append({"fp": det[0], "name": det[1], "until": det[2], "store": "system", "where": path})
        return out

    def nss_dbs(self):
        dbs = []
        for pw in self.human_users():
            h = pw.pw_dir
            for pattern in (".pki/nssdb", ".mozilla/firefox/*", "snap/firefox/common/.mozilla/firefox/*",
                            ".var/app/org.mozilla.firefox/.mozilla/firefox/*", ".thunderbird/*", "snap/thunderbird/common/.thunderbird/*",
                            ".var/app/org.mozilla.Thunderbird/.thunderbird/*", "snap/chromium/current/.pki/nssdb"):
                for d in glob.glob(os.path.join(h, pattern)):
                    if os.path.isfile(os.path.join(d, "cert9.db")):
                        app = "chrome" if "nssdb" in d else ("thunderbird" if "thunderbird" in d else "firefox")
                        dbs.append((pw.pw_name, app, d))
        return dbs

    def nss_certs(self):
        """Autorités ajoutées par l'utilisateur dans les bases NSS (les racines intégrées n'y figurent pas) : drapeau « C »
        dans le premier champ de confiance (SSL). Lecture sur une copie : la base de l'utilisateur n'est jamais touchée."""
        if not shutil.which("certutil"):
            return []
        out = []
        for user, app, d in self.nss_dbs():
            with tempfile.TemporaryDirectory(prefix="dukiwi-nss-") as tmp:
                for name in ("cert9.db", "key4.db", "pkcs11.txt"):
                    src = os.path.join(d, name)
                    if os.path.isfile(src):
                        shutil.copyfile(src, os.path.join(tmp, name))
                r = run_quiet(["certutil", "-L", "-d", f"sql:{tmp}"], timeout=20)
                for ln in (r.stdout or "").splitlines():
                    m = re.match(r"^(.*?)\s+([a-zA-Z]*),([a-zA-Z]*),([a-zA-Z]*)\s*$", ln)
                    if not m or "C" not in m.group(2):
                        continue
                    nick = m.group(1).strip()
                    pem = run_quiet(["certutil", "-L", "-d", f"sql:{tmp}", "-n", nick, "-a"], timeout=20).stdout or ""
                    for block in self.pem_blocks(pem)[:1]:
                        det = self.cert_details(block)
                        if det:
                            out.append({"fp": det[0], "name": det[1] or nick, "until": det[2], "store": app, "where": d, "user": user})
        return out

    def root_cas(self, max_age=SLOW_CHECK_SEC):
        """Certificats racine ajoutés (système + NSS), regroupés par empreinte, avec l'état « ignoré »."""
        with self.lock:
            at, value = self._certs
        if value is not None and time.time() - at < max_age:
            return value
        merged = {}
        for c in self.system_anchor_certs() + self.nss_certs():
            cur = merged.setdefault(c["fp"], dict(c, stores=[]))
            label = c["store"] + (f" ({c['user']})" if c.get("user") else "")
            if label not in cur["stores"]:
                cur["stores"].append(label)
        acks = self.d.state.get("acknowledged_certs") or {}
        value = sorted((dict(c, acknowledged=c["fp"] in acks) for c in merged.values()), key=lambda c: c["name"].lower())
        with self.lock:
            self._certs = (time.time(), value)
        return value

    # ═══ 5. Détournement réseau ═══════════════════════════════════════════
    @staticmethod
    def hosts_findings(path="/etc/hosts"):
        out = []
        try:
            with open(path) as f:
                lines = f.read().splitlines()
        except OSError:
            return out
        for ln in lines:
            parts = ln.split("#", 1)[0].split()
            if len(parts) >= 2 and is_public(parts[0]):
                for name in parts[1:4]:
                    out.append({"key": f"hosts:{parts[0]} {name}", "type": "hosts", "value": f"{name} → {parts[0]}", "where": path})
        return out

    def proxy_findings(self):
        out = []
        for pw in self.human_users():
            if pw.pw_uid < 1000:
                continue
            mode = self.dconf_read(pw, "/system/proxy/mode").strip("'")
            if mode in ("manual", "auto"):
                if mode == "auto":
                    value = self.dconf_read(pw, "/system/proxy/autoconfig-url").strip("'") or "PAC"
                else:
                    host = self.dconf_read(pw, "/system/proxy/http/host").strip("'") or self.dconf_read(pw, "/system/proxy/socks/host").strip("'")
                    port = self.dconf_read(pw, "/system/proxy/http/port").split()[-1:] or [""]
                    value = f"{host}:{port[0]}".rstrip(":")
                out.append({"key": f"proxy:desktop:{pw.pw_name}:{value}", "type": "proxy_desktop", "value": value, "where": pw.pw_name})
            kde = os.path.join(pw.pw_dir, ".config", "kioslaverc")
            try:
                with open(kde) as f:
                    txt = f.read()
                m = re.search(r"^\s*ProxyType\s*=\s*([1-4])", txt, re.M)
                if m:
                    hp = re.search(r"^\s*(httpProxy|Proxy Config Script)\s*=\s*(\S+)", txt, re.M)
                    value = hp.group(2) if hp else f"type {m.group(1)}"
                    out.append({"key": f"proxy:kde:{pw.pw_name}:{value}", "type": "proxy_desktop", "value": value, "where": kde})
            except OSError:
                pass
            for prefs in glob.glob(os.path.join(pw.pw_dir, ".mozilla/firefox/*/prefs.js")) + \
                    glob.glob(os.path.join(pw.pw_dir, "snap/firefox/common/.mozilla/firefox/*/prefs.js")):
                try:
                    with open(prefs, errors="replace") as f:
                        txt = f.read()
                except OSError:
                    continue
                m = re.search(r'user_pref\("network\.proxy\.type",\s*([12])\)', txt)
                if not m:
                    continue
                if m.group(1) == "2":
                    u = re.search(r'user_pref\("network\.proxy\.autoconfig_url",\s*"([^"]*)"\)', txt)
                    value = u.group(1) if u else "PAC"
                else:
                    h = re.search(r'user_pref\("network\.proxy\.(?:http|socks)",\s*"([^"]*)"\)', txt)
                    p = re.search(r'user_pref\("network\.proxy\.(?:http|socks)_port",\s*(\d+)\)', txt)
                    value = f"{h.group(1) if h else '?'}:{p.group(1) if p else ''}".rstrip(":")
                out.append({"key": f"proxy:firefox:{pw.pw_name}:{value}", "type": "proxy_firefox", "value": value, "where": prefs})
        env_re = re.compile(r"^\s*(?:export\s+)?(https?_proxy|all_proxy|ftp_proxy)\s*=\s*[\"']?([^\"'\s]+)", re.I | re.M)
        for path in ("/etc/environment", "/etc/profile.d/proxy.sh"):
            try:
                with open(path) as f:
                    for var, value in env_re.findall(f.read()):
                        out.append({"key": f"proxy:env:{var.lower()}={value}", "type": "proxy_env", "value": f"{var}={value}", "where": path})
            except OSError:
                pass
        apt_re = re.compile(r'^\s*Acquire::(?:https?|ftp)::Proxy\s+"([^"]+)"', re.I | re.M)
        for path in ["/etc/apt/apt.conf"] + sorted(glob.glob("/etc/apt/apt.conf.d/*")):
            try:
                with open(path) as f:
                    for value in apt_re.findall(f.read()):
                        if value.upper() != "DIRECT" and value.lower() != "false":
                            out.append({"key": f"proxy:apt:{value}", "type": "proxy_pkg", "value": value, "where": path})
            except OSError:
                pass
        try:
            with open("/etc/dnf/dnf.conf") as f:
                for value in re.findall(r"^\s*proxy\s*=\s*(\S+)", f.read(), re.M):
                    out.append({"key": f"proxy:dnf:{value}", "type": "proxy_pkg", "value": value, "where": "/etc/dnf/dnf.conf"})
        except OSError:
            pass
        return out

    @staticmethod
    def dns_servers():
        """Serveurs DNS des interfaces physiques (resolvectl), sinon /etc/resolv.conf ; liens VPN exclus."""
        servers = []
        if shutil.which("resolvectl"):
            r = run_quiet(["resolvectl", "dns"], timeout=10)
            for ln in (r.stdout or "").splitlines():
                m = re.match(r"^(?:Link \d+ \(([^)]+)\)|Global):\s*(.*)$", ln.strip())
                if m and not (m.group(1) and VPN_LINK_RE.match(m.group(1))):
                    servers += [s.split("#")[0] for s in m.group(2).split()]
        if not servers:
            try:
                with open("/etc/resolv.conf") as f:
                    servers = re.findall(r"^\s*nameserver\s+(\S+)", f.read(), re.M)
            except OSError:
                pass
        return sorted({s for s in servers if s and not s.startswith("127.")})

    def dns_findings(self):
        """Nouveau serveur DNS public inconnu sur un réseau déjà connu (premier passage = référence mémorisée)."""
        net = getattr(self.d, "current_network", None) or {}
        key = net.get("key")
        if not key:
            return []
        local6 = local_v6_prefixes()
        current = [s for s in self.dns_servers() if is_public(s) and s not in TRUSTED_RESOLVERS and not same_local_v6(s, local6)]
        known = dict(self.d.state.get("network_dns") or {})
        if key not in known:
            known[key] = current
            self.d.state.update(network_dns=known)
            return []
        return [{"key": f"dns:{key}:{s}", "type": "dns", "value": s, "where": net.get("name") or key}
                for s in current if s not in known[key]]

    def redirects(self, max_age=SLOW_CHECK_SEC):
        with self.lock:
            at, value = self._redirects
        if value is not None and time.time() - at < max_age:
            return value
        found = self.hosts_findings() + self.proxy_findings() + self.dns_findings()
        acks = self.d.state.get("acknowledged_redirects") or {}
        value = [dict(f, acknowledged=f["key"] in acks) for f in found]
        with self.lock:
            self._redirects = (time.time(), value)
        return value

    def invalidate(self):
        with self.lock:
            self._certs = (0.0, None)
            self._redirects = (0.0, None)

    def check_slow(self):
        """Toutes les 10 minutes : nouveau certificat racine ou nouveau détournement → alerte (premier relevé silencieux) ;
        leurres posés dans les dossiers apparus depuis (nouvel utilisateur, dossier Documents créé)."""
        if self.setting("ransomware_decoys"):
            self.sync_decoys()
        # Un dossier personnel chiffré non monté cache ses bases NSS, réglages de proxy… : les références ne rétrécissent
        # jamais dans ce cas, sinon tout réapparaîtrait « nouveau » à l'ouverture de session.
        pending = any(not home_mounted(pw) for pw in self.human_users() if pw.pw_uid >= 1000)
        certs = self.root_cas(max_age=0)
        known = self.d.state.get("known_certs")
        fps = sorted(set(c["fp"] for c in certs) | (set(known or []) if pending else set()))
        if known is not None:
            for c in certs:
                if c["fp"] not in known and not c["acknowledged"]:
                    self.write_log(f"⚠ certificate: new root certificate {c['name']} ({', '.join(c['stores'])}) {c['fp'][:16]}")
                    self.alert("certificate", "warn", title=c["name"], detail=", ".join(c["stores"]), fp=c["fp"], reasons=["new_root_ca"])
        if known is None or fps != sorted(known):
            self.d.state.update(known_certs=fps)
        found = self.redirects(max_age=0)
        known_r = self.d.state.get("known_redirects")
        keys = sorted(set(f["key"] for f in found) | (set(known_r or []) if pending else set()))
        if known_r is not None:
            for f in found:
                if f["key"] not in known_r and not f["acknowledged"]:
                    self.write_log(f"⚠ redirect: {f['type']} {f['value']} ({f['where']})")
                    self.alert("redirect", "warn", title=f["value"], detail=f["where"], key=f["key"], subtype=f["type"], reasons=[f"redirect_{f['type']}"])
        if known_r is None or keys != sorted(known_r):
            self.d.state.update(known_redirects=keys)

    # ═══ 6. Démarrage automatique, tâches planifiées, extensions (veille) ═════
    def persistence_fingerprint(self):
        """Empreinte bon marché des dossiers où s'installe un programme qui veut revenir à chaque démarrage, et des
        extensions des navigateurs (identifiants et versions) : relevé complet seulement quand elle change."""
        fp = []
        paths = list(PERSISTENCE_DIRS)
        for pw in self.human_users():
            paths += [os.path.join(pw.pw_dir, ".config/autostart"), os.path.join(pw.pw_dir, ".config/systemd/user")]
            paths += glob.glob(os.path.join(pw.pw_dir, ".mozilla/firefox/*/extensions.json"))
            for _editor, sub in audit.EDITOR_DIRS:
                d = os.path.join(pw.pw_dir, sub)
                try:
                    fp.append((d, tuple(sorted(os.listdir(d)))))
                except OSError:
                    pass
            for ext_dir in glob.glob(os.path.join(pw.pw_dir, ".config/*/*/Extensions")) + glob.glob(os.path.join(pw.pw_dir, ".config/*/Default/Extensions")) \
                    + glob.glob(os.path.join(pw.pw_dir, ".config/*/Profile */Extensions")):
                try:
                    fp.append((ext_dir, tuple(sorted((e, tuple(sorted(os.listdir(os.path.join(ext_dir, e)))))
                                                      for e in os.listdir(ext_dir) if os.path.isdir(os.path.join(ext_dir, e))))))
                except OSError:
                    continue
        for p in paths:
            try:
                st = os.stat(p)
                fp.append((p, st.st_mtime_ns, st.st_size))
            except OSError:
                continue
        return hash(tuple(fp))

    def check_persistence(self):
        fp = self.persistence_fingerprint()
        if self.persistence_fp is None:
            self.persistence_fp = fp                       # référence au démarrage (le relevé quotidien fait le reste)
            return
        if fp == self.persistence_fp or self.persistence_running:
            return
        self.persistence_fp = fp
        refresh = getattr(self.d, "refresh_persistence", None)
        if not refresh:
            return

        def run_refresh():
            self.persistence_running = True
            try:
                time.sleep(3)                              # laisser l'installation finir d'écrire (extension, paquet)
                refresh(reason="watch")
                self.persistence_fp = self.persistence_fingerprint()
            except Exception as e:  # noqa: BLE001
                self.log(f"Veille de la persistance : {e}")
            finally:
                self.persistence_running = False
        threading.Thread(target=run_refresh, daemon=True, name="persistence-watch").start()

    # ═══ 7. Clés SSH autorisées ═══════════════════════════════════════════
    @staticmethod
    def parse_authorized_keys(path):
        """[{fp, type, comment, options, line}] d'un fichier authorized_keys (empreinte SHA256 comme ssh-keygen -l)."""
        import base64
        out = []
        try:
            with open(path, errors="replace") as f:
                lines = f.read().splitlines()
        except OSError:
            return out
        for n, ln in enumerate(lines):
            if not ln.strip() or ln.lstrip().startswith("#"):
                continue
            parts = ln.split()
            idx = next((i for i, x in enumerate(parts) if x in SSH_KEY_TYPES), None)
            if idx is None or idx + 1 >= len(parts):
                continue
            try:
                blob = base64.b64decode(parts[idx + 1] + "==")
            except ValueError:
                continue
            fp = "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")
            out.append({"fp": fp, "type": parts[idx], "comment": " ".join(parts[idx + 2:])[:120], "options": " ".join(parts[:idx])[:200], "line": n})
        return out

    def ssh_key_files(self):
        users = [pw for pw in self.human_users() if pw.pw_uid >= 1000]
        try:
            users.append(pwd.getpwnam("root"))
        except KeyError:
            pass
        out = []
        for pw in users:
            if pw.pw_uid >= 1000 and not home_mounted(pw):
                continue                                   # dossier chiffré non monté : ses clés ne sont pas visibles
            for name in ("authorized_keys", "authorized_keys2"):
                p = os.path.join(pw.pw_dir, ".ssh", name)
                if os.path.isfile(p):
                    out.append((pw.pw_name, p))
        return out

    def ssh_keys(self):
        return [dict(k, user=user, path=path) for user, path in self.ssh_key_files() for k in self.parse_authorized_keys(path)]

    def check_ssh_keys(self):
        keys = self.ssh_keys()
        known = self.d.state.get("ssh_keys_known")
        pending = tuple(pw.pw_dir.rstrip("/") + "/" for pw in self.human_users() if pw.pw_uid >= 1000 and not home_mounted(pw))
        current = sorted({f"{k['path']}|{k['fp']}" for k in keys} | {x for x in (known or []) if pending and x.startswith(pending)})
        if known is None:
            self.d.state.update(ssh_keys_known=current)    # référence silencieuse au premier passage
            return
        new = [k for k in keys if f"{k['path']}|{k['fp']}" not in known]
        if not new and len(current) == len(known):
            return
        sshd = bool(((getattr(self.d, "security", None) or {}).get("ssh") or {}).get("active"))
        for k in new:
            self.write_log(f"⚠ ssh key added for {k['user']}: {k['type']} {k['fp']} {k['comment']} ({k['path']})")
            self.alert("ssh_key", "danger" if sshd else "warn", title=k["user"], detail=k["comment"] or k["type"], path=k["path"],
                       fp=k["fp"], keytype=k["type"], user=k["user"], reasons=["ssh_key_added" + ("_sshd" if sshd else "")])
        self.d.state.update(ssh_keys_known=current)

    def remove_ssh_key(self, path, fp):
        """Retire la ou les lignes de cette empreinte (fichier réécrit en place : propriétaire et droits conservés)."""
        keys = [k for k in self.parse_authorized_keys(path) if k["fp"] == fp]
        if not keys:
            return False
        drop = {k["line"] for k in keys}
        with open(path, errors="replace") as f:
            lines = f.read().splitlines()
        kept = [ln for i, ln in enumerate(lines) if i not in drop]
        st = os.stat(path)
        tmp = path + ".dukiwi-tmp"
        with open(tmp, "w") as f:
            f.write("\n".join(kept) + ("\n" if kept else ""))
        os.chown(tmp, st.st_uid, st.st_gid)
        os.chmod(tmp, st.st_mode & 0o777)
        os.replace(tmp, path)
        known = [x for x in (self.d.state.get("ssh_keys_known") or []) if x != f"{path}|{fp}"]
        self.d.state.update(ssh_keys_known=known)
        return True

    # ═══ 8. Fichiers SUID / SGID hors paquets ═════════════════════════════
    @staticmethod
    def suid_scan(timeout=1800):
        """Fichiers SUID ou SGID (exécutés avec les droits de leur propriétaire, souvent root) sur les systèmes de fichiers
        locaux et les dossiers temporaires ; conteneurs, Flatpak et snap laissés de côté."""
        r = run_quiet(["findmnt", "-rno", "TARGET", "-t", "ext4,ext3,ext2,btrfs,xfs,f2fs,jfs,zfs,tmpfs,ecryptfs"], timeout=20)
        targets = []
        for t in (r.stdout or "").splitlines():
            t = t.replace("\\x20", " ")
            if t.startswith(("/proc", "/sys", "/run/user", "/snap")) or (t.startswith("/run") and t not in ("/run/shm",)):
                continue
            if t.startswith("/dev") and t != "/dev/shm":
                continue
            targets.append(t)
        if not targets:
            targets = ["/"]
        cmd = ["find"] + sorted(set(targets)) + ["-xdev", "-type", "f", "(", "-perm", "-4000", "-o", "-perm", "-2000", ")", "-print0"]
        if shutil.which("ionice"):
            cmd = ["ionice", "-c3"] + cmd
        r = subprocess.run(["nice", "-n", "19"] + cmd, capture_output=True, timeout=timeout)
        paths = [p.decode(errors="replace") for p in (r.stdout or b"").split(b"\0") if p]
        return sorted({p for p in paths if not any(x in p for x in SUID_SKIP)})

    # ═══ 9. Espions du clavier ════════════════════════════════════════════
    def check_keyloggers(self):
        if not self.setting("keylogger_watch"):
            return
        trusted = self.d.user_trusted()
        now = time.time()
        for r in audit.keyboard_readers():
            exe = r["exe"].replace(" (deleted)", "")
            key = (exe or r["comm"], r["device"] or "x11")
            if exe in trusted or now - self.keylogger_alerted.get(key, 0) < 6 * 3600:
                continue
            self.keylogger_alerted[key] = now
            bad_place = exe.startswith(("/tmp/", "/var/tmp/", "/dev/shm/", "/home/", "/run/")) or r["exe"].endswith(" (deleted)")
            severity = "danger" if bad_place or r["reason"] == "x11_logger" else ("warn" if r["reason"] == "untrusted_reader" else "info")
            try:
                user = pwd.getpwuid(r["uid"]).pw_name
            except (KeyError, TypeError):
                user = ""
            self.write_log(f"⚠ {'danger' if severity == 'danger' else 'keyboard'}: keyboard read by {r['comm']} (pid {r['pid']}, {r['exe']}) "
                           f"{r['device_name'] or r['reason']}")
            self.alert("keylogger", severity, pid=r["pid"], comm=r["comm"], exe=r["exe"], cmdline=r["cmdline"], user=user,
                       title=r["comm"], detail=r["device_name"] or r["device"], device=r["device"], reasons=[r["reason"]])

    # ═══ 10. Connexions inhabituelles ═════════════════════════════════════
    def check_logins(self):
        if not self.setting("login_watch"):
            return
        known = self.d.state.get("login_known")
        humans = {pw.pw_name for pw in self.human_users() if pw.pw_uid >= 1000} | {"root"}
        if known is None or self.login_cursor is None:
            # Référence : les 30 derniers jours (aucune alerte), puis lecture depuis le dernier curseur
            stored = self.d.state.get("login_cursor") if known is not None else None
            if known is not None and not stored:
                stored = audit.journal_cursor()          # référence perdue : on repart de maintenant, sans relire 30 jours
            events, cursor = audit.journal_logins(cursor=stored)
            if known is None:
                known = {}
                for e in events:
                    if e["kind"] == "ssh" and e["user"] in humans:
                        known.setdefault(e["user"], {}).setdefault(e["ip"], {"first": datetime.fromtimestamp(e["t"]).isoformat(timespec="seconds")})
                cursor = cursor or audit.journal_cursor()
                self.d.state.update(login_known=known, login_cursor=cursor)
                self.login_cursor = cursor
                return
            self.login_cursor = cursor or self.d.state.get("login_cursor")
        else:
            events, cursor = audit.journal_logins(cursor=self.login_cursor)
            self.login_cursor = cursor or self.login_cursor
        changed = False
        for e in events:
            if e["user"] not in humans:
                continue
            when = datetime.fromtimestamp(e["t"])
            night = when.hour in audit.NIGHT_HOURS
            if e["kind"] == "local":
                if night:
                    self.write_log(f"login: night session for {e['user']} ({e['service']}) at {when:%H:%M}")
                    self.alert("login", "info", title=e["user"], detail=e["service"], user=e["user"], subtype="night_local",
                               hour=f"{when:%H:%M}", reasons=["login_night"])
                continue
            ip, user = e["ip"], e["user"]
            mine = known.setdefault(user, {})
            reasons = []
            country = ""
            if is_public(ip):
                conns = getattr(self.d, "connections", None)
                if conns is not None:
                    conns.geolocate([ip])
                    country = ((getattr(conns, "geo", {}) or {}).get(ip) or {}).get("countryCode", "")
            if ip not in mine:
                seen_countries = {v.get("country") for v in mine.values() if v.get("country")}
                reasons.append("login_new_country" if country and seen_countries and country not in seen_countries else "login_new_ip")
                mine[ip] = {"first": when.isoformat(timespec="seconds"), "country": country}
                changed = True
            if user == "root":
                reasons.append("login_root")
            if night:
                reasons.append("login_night")
            if e["method"] == "password" and is_public(ip):
                reasons.append("login_password_internet")
            if not reasons:
                continue
            severity = "danger" if "login_new_country" in reasons or ("login_root" in reasons and is_public(ip)) else \
                ("warn" if "login_new_ip" in reasons or "login_root" in reasons else "info")
            self.write_log(f"⚠ login: ssh {user} from {ip} {country} ({e['method']}) — {', '.join(reasons)}")
            self.alert("login", severity, title=user, detail=f"{ip} {country}".strip(), user=user, ip=ip, country=country,
                       method=e["method"], subtype="ssh", hour=f"{when:%H:%M}", reasons=reasons)
        if changed or cursor:
            self.d.state.update(login_known=known, login_cursor=self.login_cursor)
