#!/usr/bin/env python3
"""
Dukiwi Shield — system service (root).

Runs permanently via systemd and listens on a Unix socket. It lets a
user without administrator rights request:
  - a full system scan (or of a system directory / their home),
  - a signature update (freshclam),
without entering a password. The GUI falls back to pkexec if the service is missing.

It also runs:
  - the automatic full scan after the first installation,
  - scheduled updates (dukiwi-shield-update.timer: every day
    at 07:00 and 5 minutes after boot),
  - write-burst monitoring (fanotify): a program that modifies
    many files is reported (info), or marked "potential danger" if it
    is unknown to the system, runs from a temporary/personal folder,
    or if clamd recognizes its executable,
  - scanning of USB media before they are made available (udev + private
    mount) — large USB hard drives trigger a question,
  - the system status report: pending security updates and
    the CVEs they fix (apt).

Usage:
  dukiwi-shield-daemon.py                 # daemon mode (root)
  dukiwi-shield-daemon.py --request update      # client: request an update and wait
  dukiwi-shield-daemon.py --request scan [/path]
  dukiwi-shield-daemon.py --request status
  dukiwi-shield-daemon.py --request system-status

(c) 2026 Dukiwi SA - Estavayer-le-Lac
"""

import ctypes
import grp
import hashlib
import hmac
import secrets
import ipaddress
import fnmatch
import shlex
import email.message
import email.utils
import glob
import json
import os
import pwd
import queue as _queue
import stat as _stat
import re
import shutil
import signal
import socket
import sqlite3
import struct
import subprocess
import sys
import threading
import time
import urllib.request
import uuid
import urllib.error
import urllib.parse
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import dukiwi_shield_harden as harden  # noqa: E402
import dukiwi_shield_distro as distro  # noqa: E402
import dukiwi_shield_honeypot  # noqa: E402
import dukiwi_shield_urlguard  # noqa: E402
import dukiwi_shield_guard  # noqa: E402
import dukiwi_shield_protect as protect  # noqa: E402
import dukiwi_shield_hygiene as hygiene  # noqa: E402
import dukiwi_shield_audit as audit  # noqa: E402
import dukiwi_shield_folders  # noqa: E402
from dukiwi_shield_common import (  # noqa: E402
    VERSION, SYSTEM_STATE_DIR, SYSTEM_LOG_DIR, DAEMON_SOCKET,
    SYSTEM_STATE_FILE, SYSTEM_QUARANTINE_DIR, SYSTEM_PROGRESS_FILE, SYSTEM_SCAN_CACHE_DB, SYSTEM_SECRET_FILE,
    quarantine_index_add, quarantine_index_load, quarantine_enrich, parse_moved_line, run_as_user, open_user_file,
    SYSTEM_FILELIST_CACHE, FIRST_SCAN_FLAG, SYSTEM_LOG_FILE, USB_MOUNT_ROOT,
    SYSTEM_SETTINGS_FILE, DEFAULT_SETTINGS, DAEMON_ALLOWED_ROOTS, LANGUAGES,
    BURST_PID_COOLDOWN_SEC, BURST_GLOBAL_COOLDOWN, BURST_IGNORE_PREFIXES, BURST_IGNORE_PARTS,
    LineSocket, peer_credentials, daemon_connect, daemon_request, find_command, SCAN_EXCLUDE, home_mounted,
    is_noise_line, classify_line, db_last_update, db_files_info, t,
    sanitize_settings, parse_ufw_verbose, parse_ufw_numbered, systemd_is_active, ntfs_mount_problem,
)

APP_DIR = os.path.dirname(os.path.abspath(__file__))
KEYRING = os.path.join(APP_DIR, "keys", "dukiwi.gpg")
INTEGRITY_FILE = os.path.join(APP_DIR, "integrity.json")
# Test overrides of the server addresses: honoured only by a service not running as root (test mode). A root
# service started with a polluted environment (sudo -E) must not fetch its updates or allowlist elsewhere.
_TEST_ENV = os.environ if os.geteuid() != 0 else {}
MANIFEST_URL = _TEST_ENV.get("DUKIWI_SHIELD_MANIFEST_URL",
                             "https://www.dukiwi.com/repo/dukiwi-shield/manifest.json")
UPDATES_DIR = os.path.join(SYSTEM_STATE_DIR, "updates")
POLICY_DIR = "/etc/dukiwi-shield"
POLICY_FILE = os.path.join(POLICY_DIR, "policy.json")          # deployed by dukiwi-kit (root)
ALLOWLIST_URL = _TEST_ENV.get("DUKIWI_SHIELD_ALLOWLIST_URL", "https://www.dukiwi.com/repo/api/allowlist.json")
TELEMETRY_URL = _TEST_ENV.get("DUKIWI_SHIELD_TELEMETRY_URL", "https://www.dukiwi.com/repo/api/telemetry.php")
ALLOWLIST_FILE = os.path.join(SYSTEM_STATE_DIR, "allowlist.json")
BLOCKLIST_FILE = os.path.join(SYSTEM_STATE_DIR, "ip-blocklist.txt")
BLOCKLIST_URLS = {
    "feodo": "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
    "sslbl": "https://sslbl.abuse.ch/blacklist/sslipblacklist.txt",
}
OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/"
GEOIP_FIELDS = "status,country,countryCode,org,isp,query"
GEOIP_FREE_URL = "http://ip-api.com/batch?fields=" + GEOIP_FIELDS        # free: HTTP only, 15 batched requests/min
GEOIP_PRO_URL = "https://pro.ip-api.com/batch?key={key}&fields=" + GEOIP_FIELDS   # Pro plan: HTTPS, no limit
GEOIP_MIN_INTERVAL = 5          # seconds between two batched requests (≤ 12/min, under the free limit)
GEOIP_CACHE_MAX = 2000          # addresses kept in cache (24 h), persisted in the service state


def geoip_url(key):
    key = (key or "").strip()
    return GEOIP_PRO_URL.format(key=urllib.parse.quote(key, safe="")) if key else GEOIP_FREE_URL
UNLOCK_TTL = 900
ADMIN_GROUPS = ("sudo", "admin", "wheel")
# Service state never sent to the GUIs: decoy locations and secret, honeypot ports, login cursors, cache, known keys
STATE_SECRET_KEYS = ("decoys", "decoy_seed", "honeypot_random_ports", "login_cursor", "geo_cache", "ssh_keys_known",
                     "known_users", "login_known")
USER_AGENT = f"dukiwi-shield/{VERSION}"
LOG_MAX_BYTES = 5 * 1024 * 1024
PROGRESS_INTERVAL = 0.25      # seconds between two progress events
PROGRESS_SAVE_INTERVAL = 2.0  # seconds between two saves of the resume file
CLAMD_CONF = distro.clamd_conf()                       # Debian : /etc/clamav/clamd.conf ; Fedora : /etc/clamd.d/scan.conf
USB_MANIFEST = ".dukiwi-shield"   # hidden manifest at the root of an already scanned removable drive
USB_MANIFEST_LEGACY = ".clamav"   # name used by previous versions: read back, replaced at the next scan
SCAN_BATCH = 100               # files per clamdscan call (one worker = one clamd connection)
SCAN_WORKERS_MAX = 8
MANIFEST_MAX_FILES = 200000
HISTORY_MAX = 20
ALERTS_MAX = 30
SYSTEM_STATUS_MIN_INTERVAL = 300   # seconds between two on-demand apt checks
TEST_MODE = os.geteuid() != 0 and "DUKIWI_SHIELD_SOCKET" in os.environ

# Tool output parsed in English whatever the system language: systemd gives the service the locale from
# /etc/default/locale (LANG=fr_CH.UTF-8 → "ufw status" answers "État : actif", "Partout"…) and the parser then
# believed the firewall inactive after a successful activation. The program's own messages are translated by the
# interface, not by the service locale.
os.environ["LC_ALL"] = "C.UTF-8"
os.environ["LANG"] = "C.UTF-8"
os.environ.pop("LANGUAGE", None)


def now_iso():
    return datetime.now().isoformat(timespec="seconds")


def log(msg):
    """Daemon log (journald via stdout)."""
    print(f"[{now_iso()}] {msg}", flush=True)


def run_quiet(cmd, timeout=60):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except Exception as e:  # noqa: BLE001
        return subprocess.CompletedProcess(cmd, 1, "", str(e))


def http_get(url, timeout=60, data=None, headers=None):
    """Simple GET/POST (urllib) with User-Agent; returns bytes; raises on error."""
    req = urllib.request.Request(url, data=data, headers={"User-Agent": USER_AGENT, **(headers or {})})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def gpg_verify(sig_path, data_path):
    """Verifies a detached signature with the embedded Dukiwi public key."""
    if not os.path.exists(KEYRING):
        return False, "no_keyring"
    if not shutil.which("gpgv"):
        return False, "no_gpgv"
    r = run_quiet(["gpgv", "--keyring", KEYRING, sig_path, data_path], timeout=30)
    return r.returncode == 0, ((r.stderr or "") + (r.stdout or "")).strip()[-300:]


def _ver_order(c):
    """Rank of a non-digit character in dpkg order: "~" before anything (even the end of the string), then the end,
    letters, then every other sign."""
    if c == "~":
        return -1
    if c.isascii() and c.isalpha():
        return ord(c)
    return ord(c) + 256


def _verrevcmp(a, b):
    """Compare one part of a version (upstream or revision) with dpkg's verrevcmp algorithm: alternating non-digit
    segments (ordered by _ver_order) and digit segments (compared as integers)."""
    i = j = 0
    digit = "0123456789"
    while i < len(a) or j < len(b):
        while (i < len(a) and a[i] not in digit) or (j < len(b) and b[j] not in digit):
            ac = _ver_order(a[i]) if i < len(a) and a[i] not in digit else 0
            bc = _ver_order(b[j]) if j < len(b) and b[j] not in digit else 0
            if ac != bc:
                return ac - bc
            i += 1
            j += 1
        while i < len(a) and a[i] == "0":
            i += 1
        while j < len(b) and b[j] == "0":
            j += 1
        first_diff = 0
        while i < len(a) and a[i] in digit and j < len(b) and b[j] in digit:
            if not first_diff:
                first_diff = ord(a[i]) - ord(b[j])
            i += 1
            j += 1
        if i < len(a) and a[i] in digit:
            return 1
        if j < len(b) and b[j] in digit:
            return -1
        if first_diff:
            return first_diff
    return 0


def _split_version(v):
    v = str(v or "").strip()
    epoch, sep, rest = v.partition(":")
    if not sep or not epoch.isdigit():
        epoch, rest = "0", v
    upstream, _sep, revision = rest.rpartition("-") if "-" in rest else (rest, "", "")
    return int(epoch), upstream, revision


def version_compare(a, b):
    """< 0, 0 or > 0, like "dpkg --compare-versions" (epoch, upstream version, revision). Pure Python: also works on
    Fedora, which has no dpkg (the built-in update never saw a newer version there), and starts no process per
    comparison (thousands of them for the vulnerability report)."""
    ea, ua, ra = _split_version(a)
    eb, ub, rb = _split_version(b)
    if ea != eb:
        return ea - eb
    return _verrevcmp(ua, ub) or _verrevcmp(ra, rb)


def version_gt(a, b):
    return version_compare(a, b) > 0


def manifest_changes(manifest, current, limit=10):
    """What changed since `current`, from the signed update manifest: [{version, title, text}], newest first."""
    out = []
    for c in manifest.get("changes") or []:
        if not isinstance(c, dict) or not c.get("version") or not version_gt(str(c["version"]), current):
            continue
        out.append({"version": str(c["version"])[:40], "title": str(c.get("title") or "")[:200], "text": str(c.get("text") or "")[:1200]})
    return out[:limit]


def uid_groups(uid):
    try:
        pw = pwd.getpwuid(uid)
    except KeyError:
        return []
    groups = [g.gr_name for g in grp.getgrall() if pw.pw_name in g.gr_mem]
    try:
        groups.append(grp.getgrgid(pw.pw_gid).gr_name)
    except KeyError:
        pass
    return groups


def is_public_ip(ip):
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_multicast or addr.is_reserved)


def ubuntu_osv_ecosystem():
    """OSV ecosystem of the underlying Ubuntu: "Ubuntu:24.04:LTS" (Ubuntu 24.04, Linux Mint 22), "Ubuntu:26.04:LTS",
    "Ubuntu:25.10"… Empty if the version is unknown: the inventory is then "unsupported" rather than
    built on the packages of another version (24.04 kernel 6.8 reported on a 26.04 running 7.0, for example)."""
    rel = distro.ubuntu_release()
    if not rel:
        return ""
    return f"Ubuntu:{rel}:LTS" if distro.ubuntu_is_lts(rel) else f"Ubuntu:{rel}"


# ═══════════════════════════════════════════════════════════════════════════
# Persistent state
# ═══════════════════════════════════════════════════════════════════════════

class State:
    def __init__(self):
        self.lock = threading.Lock()
        self.data = self._load()

    def _load(self):
        try:
            with open(SYSTEM_STATE_FILE) as f:
                return json.load(f)
        except Exception:
            return {}

    def get(self, key, default=None):
        with self.lock:
            return self.data.get(key, default)

    def snapshot(self):
        with self.lock:
            return dict(self.data)

    def update(self, **kwargs):
        with self.lock:
            self.data.update(kwargs)
            self._save()

    def prepend(self, key, entry, limit):
        with self.lock:
            items = self.data.get(key, [])
            items.insert(0, entry)
            self.data[key] = items[:limit]
            self._save()

    def _save(self):
        tmp = SYSTEM_STATE_FILE + ".tmp"
        with open(tmp, "w") as f:
            json.dump(self.data, f, indent=2, ensure_ascii=False)
        os.chmod(tmp, 0o644)
        os.replace(tmp, SYSTEM_STATE_FILE)


class Settings:
    """System settings (Settings page), persisted in settings.json."""

    def __init__(self):
        self.lock = threading.Lock()
        try:
            with open(SYSTEM_SETTINGS_FILE) as f:
                stored = json.load(f)
        except Exception:
            stored = {}
        self.data, _ = sanitize_settings({}, stored)

    def get(self, key):
        with self.lock:
            return self.data.get(key, DEFAULT_SETTINGS.get(key))

    def snapshot(self):
        with self.lock:
            return dict(self.data)

    def update(self, incoming):
        with self.lock:
            merged, errors = sanitize_settings(self.data, incoming)
            changed = {k: v for k, v in merged.items() if self.data.get(k) != v}
            self.data = merged
            tmp = SYSTEM_SETTINGS_FILE + ".tmp"
            with open(tmp, "w") as f:
                json.dump(self.data, f, indent=2)
            os.chmod(tmp, 0o644)
            os.replace(tmp, SYSTEM_SETTINGS_FILE)
        return changed, errors


# ═══════════════════════════════════════════════════════════════════════════
# Jobs
# ═══════════════════════════════════════════════════════════════════════════

# ── Engine: clamd (database in memory, multi-threaded) ───────────────────
def clamd_socket_path():
    try:
        with open(CLAMD_CONF, encoding="utf-8", errors="replace") as f:
            for ln in f:
                ln = ln.strip()
                if ln.startswith("LocalSocket ") or ln.startswith("LocalSocket\t"):
                    return ln.split(None, 1)[1].strip()
    except OSError:
        pass
    return "/run/clamd.scan/clamd.sock" if distro.is_rpm() else "/var/run/clamav/clamd.ctl"


def clamd_enable_local_socket():
    """Fedora ships /etc/clamd.d/scan.conf with "#LocalSocket /run/clamd.scan/clamd.sock" commented out: without a
    socket, clamd@scan is useless and the antivirus would fall back to clamscan (slow). Uncommented once, as root."""
    if not distro.is_rpm() or os.geteuid() != 0:
        return False
    try:
        with open(CLAMD_CONF, encoding="utf-8", errors="replace") as f:
            text = f.read()
    except OSError:
        return False
    if re.search(r"^LocalSocket\s", text, flags=re.M):
        return False
    new = re.sub(r"^#\s*LocalSocket\s+(\S+)", r"LocalSocket \1", text, count=1, flags=re.M)
    if new == text:
        new = text.rstrip("\n") + "\nLocalSocket /run/clamd.scan/clamd.sock\n"
    try:
        with open(CLAMD_CONF, "w", encoding="utf-8") as f:
            f.write(new)
    except OSError:
        return False
    log("clamd : LocalSocket activé dans " + CLAMD_CONF)
    return True


def clamd_ping(timeout=5):
    """Does clamd answer on its socket? (PING → PONG)"""
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect(clamd_socket_path())
        s.sendall(b"zPING\0")
        data = s.recv(64)
        s.close()
        return b"PONG" in data
    except OSError:
        return False


def ensure_clamd(wait=90):
    """clamd keeps the signature database in memory and scans several files in parallel: it is the fast
    engine. Started if needed (clamscan reloads the database on every run)."""
    if clamd_ping():
        return True
    if os.geteuid() != 0 or not shutil.which("clamdscan"):
        return False
    if clamd_enable_local_socket():
        run_quiet(["systemctl", "restart", distro.clamd_unit()], timeout=60)
    else:
        run_quiet(["systemctl", "start", distro.clamd_unit()], timeout=30)
    deadline = time.time() + wait
    while time.time() < deadline:
        if clamd_ping():
            return True
        time.sleep(2)
    return False


_DB_VERSION = {"v": "", "at": 0.0}


def signature_db_version():
    """Version of the daily database (to date the manifests), read at most every 10 min."""
    if time.time() - _DB_VERSION["at"] < 600:
        return _DB_VERSION["v"]
    v = ""
    r = run_quiet(["clamscan", "--version"], timeout=30)
    m = re.search(r"/(\d+)/", r.stdout or "")
    if m:
        v = m.group(1)
    else:
        for name in ("daily.cld", "daily.cvd"):
            p = f"/var/lib/clamav/{name}"
            if os.path.exists(p):
                v = str(int(os.path.getmtime(p)))
                break
    _DB_VERSION.update(v=v, at=time.time())
    return v


def parse_find_line(line):
    """Ligne « chemin\ttaille\tmtime\tctime\tinode » (find -printf) → (chemin, taille, mtime_µs, ctime_µs, inode)."""
    parts = line.rstrip("\n").split("\t")
    if len(parts) < 5:
        return parts[0], 0, 0, 0, 0

    def micro(x):
        if "." not in x:                      # already in microseconds (work list read back)
            return int(x)
        s, _, f = x.partition(".")
        return int(s) * 1000000 + int((f + "000000")[:6])
    try:
        return parts[0], int(parts[1]), micro(parts[2]), micro(parts[3]), int(parts[4])
    except ValueError:
        return parts[0], 0, 0, 0, 0


class ScanCache:
    """Files already verified clean: fingerprint (size, mtime, ctime, inode) → not reread as long as they have not
    changed, for `days` days. SQLite in /var/lib/dukiwi-shield/scan-cache.db (millions of entries)."""

    def __init__(self, path, days):
        self.days = int(days or 0)
        self.db = sqlite3.connect(path, check_same_thread=False, timeout=30)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=OFF")
        self.db.execute("CREATE TABLE IF NOT EXISTS files (path TEXT PRIMARY KEY, size INTEGER, mtime INTEGER, "
                        "ctime INTEGER, ino INTEGER, scanned_at INTEGER)")
        self.lock = threading.Lock()

    def lookup(self, entries):
        """Paths of `entries` (find tuples) known to be clean, unchanged and recent enough."""
        if not self.days or not entries:
            return set()
        since = int(time.time()) - self.days * 86400
        out = set()
        with self.lock:
            for i in range(0, len(entries), 500):
                chunk = entries[i:i + 500]
                marks = ",".join("?" * len(chunk))
                rows = self.db.execute(f"SELECT path,size,mtime,ctime,ino,scanned_at FROM files WHERE path IN ({marks})",
                                       [e[0] for e in chunk]).fetchall()
                known = {r[0]: r for r in rows}
                for e in chunk:
                    r = known.get(e[0])
                    if r and r[5] >= since and (r[1], r[2], r[3], r[4]) == (e[1], e[2], e[3], e[4]):
                        out.add(e[0])
        return out

    def record(self, entries):
        if not entries:
            return
        now = int(time.time())
        with self.lock:
            self.db.executemany("INSERT OR REPLACE INTO files(path,size,mtime,ctime,ino,scanned_at) VALUES (?,?,?,?,?,?)",
                                [(e[0], e[1], e[2], e[3], e[4], now) for e in entries])
            self.db.commit()

    def purge(self, keep_days=90):
        with self.lock:
            self.db.execute("DELETE FROM files WHERE scanned_at < ?", (int(time.time()) - keep_days * 86400,))
            self.db.commit()

    def count(self):
        with self.lock:
            return self.db.execute("SELECT COUNT(*) FROM files").fetchone()[0]

    def close(self):
        with self.lock:
            try:
                self.db.commit()
                self.db.close()
            except sqlite3.Error:
                pass


# ── .clamav manifest of a removable drive ─────────────────────────────────
def usb_secret():
    """HMAC secret of the installation (never copied to the key): a manifest forged by the key is ignored."""
    try:
        with open(SYSTEM_SECRET_FILE, "rb") as f:
            s = f.read()
        if len(s) >= 32:
            return s
    except OSError:
        pass
    s = os.urandom(32)
    try:
        fd = os.open(SYSTEM_SECRET_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        os.write(fd, s)
        os.close(fd)
    except OSError:
        pass
    return s


def manifest_sign(data):
    body = json.dumps({k: v for k, v in data.items() if k != "hmac"}, sort_keys=True, separators=(",", ":")).encode()
    return hmac.new(usb_secret(), body, hashlib.sha256).hexdigest()


def usb_manifest_read(mountpoint):
    """.clamav manifest of an already scanned medium; None if it is missing, unreadable or not signed
    by this installation."""
    path = os.path.join(mountpoint, USB_MANIFEST)
    if not os.path.exists(path) and os.path.exists(os.path.join(mountpoint, USB_MANIFEST_LEGACY)):
        path = os.path.join(mountpoint, USB_MANIFEST_LEGACY)
    try:
        # The drive is attacker-made: no symbolic link (to /dev/zero…), no FIFO, bounded size
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as f:
            st = os.fstat(f.fileno())
            if not _stat.S_ISREG(st.st_mode) or st.st_size > 64 * 2 ** 20:
                return None
            data = json.loads(f.read(64 * 2 ** 20 + 1).decode("utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict) or data.get("format") != 1 or not isinstance(data.get("files"), dict):
        return None
    if not hmac.compare_digest(str(data.get("hmac") or ""), manifest_sign(data)):
        return None
    return data


def manifest_fresh(manifest, days):
    try:
        age = time.time() - datetime.fromisoformat(manifest.get("scanned_at", "")).timestamp()
    except (TypeError, ValueError):
        return False
    return days > 0 and age < days * 86400


def usb_manifest_write(mountpoint, files, db_version, infected):
    """Writes .clamav (hidden) at the root: clean files {relative path: [size, mtime_µs]}, signed."""
    data = {"format": 1, "app": "dukiwi-shield", "version": VERSION, "scanned_at": now_iso(), "db": db_version,
            "files": files, "infected": sorted(infected)[:1000]}
    data["hmac"] = manifest_sign(data)
    path = os.path.join(mountpoint, USB_MANIFEST)
    tmp = path + ".tmp"
    try:
        # Never through a symbolic link left on the drive: the temporary file is created new, and the target is
        # replaced by rename (which replaces a link instead of following it)
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, separators=(",", ":"))
        os.replace(tmp, path)
        return True
    except OSError as e:
        log(f"Manifeste USB non écrit ({mountpoint}) : {e}")
        try:
            os.remove(tmp)
        except OSError:
            pass
        return False


# ── Quick scan: home folders + locations where malware installs itself ──
QUICK_SCAN = "quick"
QUICK_SCAN_DIRS = ("/tmp", "/var/tmp", "/dev/shm", "/etc/cron.d", "/etc/cron.hourly", "/etc/cron.daily", "/etc/cron.weekly",
                   "/etc/cron.monthly", "/var/spool/cron", "/etc/systemd/system", "/etc/xdg/autostart", "/etc/profile.d",
                   "/etc/init.d", "/etc/rc.local", "/etc/ld.so.preload", "/usr/local/bin", "/usr/local/sbin", "/usr/local/lib",
                   "/usr/local/share", "/opt", "/var/www", "/srv", "/root")
# /dev/shm and /run/user are part of the quick scan: the other full-scan exclusions remain
QUICK_SCAN_EXCLUDE = [e for e in SCAN_EXCLUDE if e not in ("/dev/*", "/run/*")]
SYSTEM_EXE_PREFIXES = ("/usr/", "/bin/", "/sbin/", "/lib/", "/lib64/", "/snap/", "/app/", "/var/lib/flatpak/", "/opt/dukiwi-shield/")


def quick_scan_paths():
    """Home folders, temporary folders, autostart and scheduled tasks, software installed by hand
    (/usr/local, /opt), local websites, and running programs that do not come from the system."""
    roots = [p for p in QUICK_SCAN_DIRS if os.path.exists(p)]
    roots += [pw.pw_dir for pw in human_users() if pw.pw_uid >= 1000 and os.path.isdir(pw.pw_dir)]
    for pid in os.listdir("/proc"):
        if not pid.isdigit():
            continue
        try:
            exe = os.readlink(f"/proc/{pid}/exe").replace(" (deleted)", "")
        except OSError:
            continue
        if os.path.isfile(exe) and (not exe.startswith(SYSTEM_EXE_PREFIXES) or exe.startswith("/usr/local/")):
            roots.append(exe)
    out = []
    for p in sorted(set(roots), key=len):
        if not any(p == r or p.startswith(r.rstrip("/") + "/") for r in out):
            out.append(p)                                   # already covered by a parent folder: not added
    return sorted(out)


class Job:
    _counter = 0
    _counter_lock = threading.Lock()

    def __init__(self, kind, path=None, resume=False, auto=False, requested_by=None, usb=None, integrity=False, use_cache=True, paths=None):
        with Job._counter_lock:
            Job._counter += 1
            self.id = Job._counter
        self.kind = kind            # 'scan' | 'update'
        self.path = path
        self.paths = paths          # quick scan: list of locations (path is then "quick")
        self.resume = resume
        self.auto = auto            # started by the system (first install, resume)
        self.usb = usb              # dict describing the scanned USB drive, or None
        self.integrity = integrity  # full scan: integrity check (rootkits, packages) BEFORE the scan
        self.skipped = 0            # system files verified by debsums, skipped by the antivirus
        self.cached = 0             # unchanged files already verified clean (cache or .clamav manifest), not re-read
        self.use_cache = use_cache
        self.engine = ""            # clamd | clamscan
        self.paused = False         # paused to scan a USB key, resumed afterwards
        self.pause_event = threading.Event()
        self.procs = []             # workers clamdscan en cours
        self.count_lock = threading.Lock()
        self.manifest_keep = {}     # support amovible : fichiers sains {relatif: [taille, mtime]}
        self.usb_infected = set()
        self.found_sigs = {}        # infected path → signature (for the quarantine index)
        self.integrity_warnings = None
        self.requested_by = requested_by
        self.created_at = time.time()
        self.started_at = None
        self.cancel_event = threading.Event()
        self.cancelled_by_user = False
        self.result = None          # (status, msg_key, msg_params) once finished
        self.proc = None
        self.proc_lock = threading.Lock()
        # progression
        self.phase = "queued"       # queued | prepare | counting | scanning | updating | done
        self.scanned = 0
        self.total = 0
        self.found = 0              # files found during the inventory
        self.infected = 0
        self.denied = 0
        self.errors = 0
        self.current_file = ""
        self.threats = []

    def public(self):
        return {
            "id": self.id,
            "kind": self.kind,
            "path": self.path,
            "resume": self.resume,
            "auto": self.auto,
            "usb": self.usb,
            "integrity": self.integrity,
            "skipped": self.skipped,
            "cached": self.cached,
            "engine": self.engine,
            "paused": self.paused,
            "integrity_warnings": self.integrity_warnings,
            "phase": self.phase,
            "scanned": self.scanned,
            "total": self.total,
            "found": self.found,
            "infected": self.infected,
            "denied": self.denied,
            "errors": self.errors,
            "file": self.current_file,
            "threats": self.threats[-50:],
            "started_at": self.started_at,
            "elapsed": (time.time() - self.started_at) if self.started_at else 0,
            "source": "daemon",
        }

    def _signal_procs(self, sig):
        with self.proc_lock:
            for p in [self.proc] + list(self.procs):
                if p and p.poll() is None:
                    try:
                        os.kill(p.pid, sig)
                    except OSError:
                        pass

    def pause(self):
        """USB key inserted: the running scan stops (workers suspended), resumes after the key has been scanned."""
        self.paused = True
        self.pause_event.set()
        self._signal_procs(signal.SIGSTOP)

    def unpause(self):
        self.paused = False
        self.pause_event.clear()
        self._signal_procs(signal.SIGCONT)

    def cancel(self, by_user=False):
        self.cancelled_by_user = self.cancelled_by_user or by_user
        self.cancel_event.set()
        if self.paused:
            self.unpause()
        with self.proc_lock:
            for p in [self.proc] + list(self.procs):
                if p and p.poll() is None:
                    try:
                        p.terminate()
                    except OSError:
                        pass


# ═══════════════════════════════════════════════════════════════════════════
# Activity monitor (fanotify) — write bursts per process
# ═══════════════════════════════════════════════════════════════════════════

FAN_CLOEXEC = 0x01
FAN_CLASS_NOTIF = 0x00
FAN_UNLIMITED_QUEUE = 0x10
FAN_MARK_ADD = 0x01
FAN_MARK_FILESYSTEM = 0x100
FAN_CLOSE_WRITE = 0x08
AT_FDCWD = -100
O_LARGEFILE = 0o100000
FAN_EVENT = struct.Struct("=IBBHQii")   # event_len, vers, reserved, metadata_len, mask, fd, pid

TRUSTED_EXE_PREFIXES = ("/usr/", "/bin/", "/sbin/", "/lib", "/opt/", "/snap/", "/var/lib/flatpak/", "/app/")
# Maintenance tools known to write many files at once (package managers, caches, boot images, backups): their
# bursts are expected, no information popup (telemetry: 24 "burst" alerts in one week for fc-cache from the
# Firefox snap, users approving dpkg, flatpak-system-helper, update-mime-database).
# Only for a trusted executable (system location, snap, flatpak): a "dpkg" under /tmp stays monitored.
QUIET_BURST_BASENAMES = frozenset({
    "dpkg", "apt", "apt-get", "aptd", "unattended-upgrade", "synaptic", "mintupdate", "mintupdate-cli", "packagekitd", "gnome-software",
    "plasma-discover", "rpm", "dnf", "dnf5", "yum", "flatpak", "flatpak-system-helper", "revokefs-fuse", "snapd", "snap", "snap-update-ns",
    "fc-cache", "update-mime-database", "update-icon-caches", "gtk-update-icon-cache", "update-desktop-database", "mandb", "ldconfig",
    "ldconfig.real", "update-initramfs", "mkinitramfs", "dracut", "dkms", "depmod", "timeshift", "rsync", "rclone", "borg", "restic",
})
UNTRUSTED_EXE_PREFIXES = ("/tmp/", "/var/tmp/", "/dev/shm/", "/run/user/", "/home/", "/root/", "/media/", "/mnt/")
# Package managers and update tools: what they launch (install scripts, caches, module compilation…) writes many
# files because the user or the system requested an installation; a burst from a program descending from them is
# expected. Never "flatpak" or "snap", from which the applications themselves descend.
PACKAGE_TOOLS = frozenset({
    "dpkg", "apt", "apt-get", "aptd", "aptitude", "nala", "unattended-upgrade", "unattended-upgrades", "synaptic", "mintupdate",
    "mintupdate-cli", "mintinstall", "update-manager", "do-release-upgrade", "packagekitd", "gnome-software", "plasma-discover",
    "rpm", "dnf", "dnf5", "yum", "flatpak-system-helper", "snapd", "dkms", "update-initramfs", "mkinitramfs", "dracut",
})
SCRIPT_INTERPRETERS = ("python", "perl", "bash", "dash", "sh")
# Programs that run code they are given (a script, -c, -e): judging them by their own binary says nothing
INTERPRETER_NAMES = ("python", "perl", "bash", "dash", "sh", "zsh", "fish", "ksh", "node", "nodejs", "ruby", "php",
                     "lua", "java", "pwsh", "Rscript", "tclsh", "wish", "gjs", "osascript", "busybox")


def is_interpreter(exe):
    base = os.path.basename(str(exe or "")).replace(" (deleted)", "")
    stem = re.sub(r"[\d.]+$", "", base)          # python3.12 → python, perl5.38 → perl
    return stem in INTERPRETER_NAMES or base in INTERPRETER_NAMES


# Interpreter options: code given inline / module run (no script file to judge), options followed by a value
INLINE_CODE_OPTS = {"-c", "-e", "-E", "-p", "-m", "--eval", "--print", "--command", "-r", "--require"}
VALUE_OPTS = {"-W", "-X", "-o", "-O", "-I", "--import", "--loader", "--input-type"}


def script_of(argv, cwd="/"):
    """Script file an interpreter runs, from its arguments; "" for code given inline, read from stdin or a module
    (nothing on disk to judge, so never trusted by the interpreter's own package)."""
    args, i = list(argv[1:]), 0
    shell = re.sub(r"[\d.]+$", "", os.path.basename(argv[0] if argv else "")) in ("sh", "bash", "dash", "zsh", "ksh", "fish")
    # Shells: only -c gives inline code (-e means "stop on error"); others: -c, -e, -m… (python, perl, node, ruby)
    inline = {"-c", "--command"} if shell else INLINE_CODE_OPTS
    ends = "c" if shell else "cem"
    while i < len(args):
        a = args[i]
        if a == "--":
            i += 1
            break
        if a in inline or (a.startswith("-") and not a.startswith("--") and 2 < len(a) <= 4 and a[-1] in ends
                           and a[1:].isalpha()):
            return ""
        if a in VALUE_OPTS:
            i += 2
            continue
        if a.startswith("-") and a != "-":
            i += 1
            continue
        break
    if i >= len(args) or args[i] in ("-", ""):
        return ""
    return os.path.normpath(os.path.join(cwd, args[i]))


# LD_PRELOAD is not listed: legitimate tools set it for a whole session (Plank's libplanksep) and the process watch
# already reports unknown preloaded libraries
CODE_INJECTION_ENV = (b"ELECTRON_RUN_AS_NODE=",)


def code_injected(pid, argv):
    """True if a (trusted) program was started so that it runs code it was handed: Electron applications in Node
    mode, a debugger port, NODE_OPTIONS loading a module."""
    if any(a.startswith(("--inspect", "--remote-debugging", "--js-flags", "--require")) for a in argv[1:]):
        return True
    try:
        with open(f"/proc/{pid}/environ", "rb") as f:
            env = f.read(1 << 20).split(b"\0")
    except OSError:
        return False
    for e in env:
        if e.startswith(CODE_INJECTION_ENV) and e.split(b"=", 1)[1].strip() not in (b"", b"0"):
            return True
        if e.startswith(b"NODE_OPTIONS=") and re.search(rb"(^|\s)(-r|--require|--import|--loader|--inspect)", e[13:]):
            return True
    return False


def root_owned_chain(path):
    """The file and every folder above it belong to root and are not writable by group or others: nobody but root
    can have put or replaced it there."""
    p = os.path.normpath(path or "")
    if not p.startswith("/"):
        return False
    try:
        while True:
            st = os.stat(p)
            if st.st_uid != 0 or (st.st_mode & 0o022 and not (os.path.isdir(p) and st.st_mode & 0o1000 and p != path)):
                return False
            if p == "/":
                return True
            p = os.path.dirname(p)
    except OSError:
        return False
BURST_IDENTIFY_AT = 3                    # writes by a program before recording who it is (it may finish before the evaluation)
HABIT_LEARNED_AT = 2                     # "It's OK" on the same burst before it is ignored automatically
# Folders that belong to an application (in addition to the ~/ patterns of the central whitelist): a burst that
# only writes there is an application installing or updating itself, not ransomware (which targets documents).
APP_DATA_DIRS = ("/home/*/.local/share/Steam/*", "/home/*/.steam/*", "/home/*/.var/app/*", "/home/*/snap/*",
                 "/home/*/.local/share/flatpak/*", "/home/*/.vscode/extensions/*", "/home/*/.cursor/*",
                 "/home/*/.local/share/JetBrains/*", "/home/*/.cache/*")


def package_tool(names):
    """Name of a package manager among `names` (a process name is truncated to 15 characters), otherwise ""."""
    for n in sorted(names):
        if n in PACKAGE_TOOLS or (len(n) == 15 and any(t.startswith(n) for t in PACKAGE_TOOLS)):
            return n
    return ""


def load_policy():
    """Enterprise policy (/etc/dukiwi-shield/policy.json): root-owned file, not writable by others,
    optional detached signature (policy.json.sig, policy-key.gpg key in the same folder or Dukiwi key)."""
    try:
        st = os.stat(POLICY_FILE)
    except OSError:
        return {}
    if st.st_uid != 0 or (st.st_mode & 0o022):
        log("Politique ignorée : policy.json doit appartenir à root et ne pas être modifiable par d'autres")
        return {}
    try:
        with open(POLICY_FILE, encoding="utf-8") as f:
            policy = json.load(f)
    except (OSError, ValueError) as e:
        log(f"Politique illisible : {e}")
        return {}
    if not isinstance(policy, dict):
        return {}
    sig = POLICY_FILE + ".sig"
    if os.path.exists(sig):
        keyring = os.path.join(POLICY_DIR, "policy-key.gpg")
        r = run_quiet(["gpgv", "--keyring", keyring if os.path.exists(keyring) else KEYRING, sig, POLICY_FILE], timeout=30)
        if r.returncode != 0:
            log("Politique ignorée : signature invalide")
            return {}
        policy["_signed"] = True
    policy["_mtime"] = st.st_mtime
    return policy


# What identifies a person or a session in a path, wherever it is in the text (a key such as
# "autostart:/home/<name>/…" does not start with /home): home folder, crontab, mounted drives, AppImage mount.
_ANON_RES = (
    (re.compile(r"(/home/)[^/\s:\"']+"), r"\1~"),
    (re.compile(r"(/var/spool/cron/crontabs/)[^/\s:\"']+"), r"\1~"),
    (re.compile(r"(/var/spool/cron/)(?!crontabs\b|atjobs\b|atspool\b)[^/\s:\"']+"), r"\1~"),
    (re.compile(r"(/run/media/|/media/)[^/\s:\"']+"), r"\1~"),
    (re.compile(r"(/run/user/)\d+"), r"\1~"),
    (re.compile(r"(/tmp/\.mount_)[^/\s:\"']+"), r"\1~"),
)


def anonymize_path(path):
    """Path (or text) without account name or session identifier, for telemetry."""
    text = str(path or "")
    for rx, repl in _ANON_RES:
        text = rx.sub(repl, text)
    return text


def anonymize_list(values, limit=50):
    """Anonymized list without duplicates (ten mounts of the same AppImage become a single line)."""
    return list(dict.fromkeys(anonymize_path(v) for v in values if v))[:limit]


# Program launched from an AppImage: the mount folder changes at every launch (/tmp/.mount_<name><6 chars>),
# so trust is based on the file's content, not on its path.
APPIMAGE_MOUNT_RE = re.compile(r"^/tmp/\.mount_[^/]+/")
APPIMAGE_HASH_MAX = 512 << 20


class TrustedPrograms:
    """Approved programs ("It's me"): by path, and by fingerprint for those from an AppImage. Used like
    a set of paths (`exe in trusted`)."""

    _digests = {}                        # (path, inode, size, mtime) → sha256, shared between rebuilds

    def __init__(self, programs):
        programs = [p for p in programs or [] if p.get("exe")]
        self.paths = {p["exe"] for p in programs}
        self.hashes = {p["sha256"] for p in programs if p.get("sha256")}

    @classmethod
    def digest(cls, exe):
        try:
            st = os.stat(exe)
            if st.st_size > APPIMAGE_HASH_MAX:
                return ""
            key = (exe, st.st_ino, st.st_size, st.st_mtime_ns)
            if key not in cls._digests:
                if len(cls._digests) > 500:
                    cls._digests.clear()
                h = hashlib.sha256()
                with open(exe, "rb") as f:
                    for chunk in iter(lambda: f.read(1 << 20), b""):
                        h.update(chunk)
                cls._digests[key] = h.hexdigest()
            return cls._digests[key]
        except OSError:
            return ""

    def __contains__(self, exe):
        exe = normalize_exe(exe)
        if not exe:
            return False
        if exe in self.paths:
            return True
        return bool(self.hashes) and bool(APPIMAGE_MOUNT_RE.match(exe)) and self.digest(exe) in self.hashes

    def __iter__(self):
        return iter(self.paths)

    def __len__(self):
        return len(self.paths)


def normalize_exe(exe):
    """Executable path without the "(deleted)" suffix (binary replaced by an update while running)."""
    exe = (exe or "").strip()
    if exe.endswith(" (deleted)"):
        exe = exe[:-len(" (deleted)")]
    return exe


class ActivityMonitor(threading.Thread):
    """Detects processes that modify many files in a short time."""

    def __init__(self, daemon):
        super().__init__(daemon=True, name="activity-monitor")
        self.daemon_ref = daemon
        self.fd = None
        self.active = False
        self.tracks = {}            # pid -> dict
        self.reported = {}          # pid -> timestamp of the last report
        self.last_report = 0
        self.dpkg_cache = {}
        self.self_pid = os.getpid()

    # ── fanotify ─────────────────────────────────────────────────────────
    def _init_fanotify(self):
        libc = ctypes.CDLL(None, use_errno=True)
        libc.fanotify_init.argtypes = [ctypes.c_uint, ctypes.c_uint]
        libc.fanotify_mark.argtypes = [ctypes.c_int, ctypes.c_uint, ctypes.c_uint64,
                                       ctypes.c_int, ctypes.c_char_p]
        fd = libc.fanotify_init(FAN_CLASS_NOTIF | FAN_CLOEXEC | FAN_UNLIMITED_QUEUE,
                                os.O_RDONLY | O_LARGEFILE | os.O_CLOEXEC)
        if fd < 0:
            raise OSError(ctypes.get_errno(), "fanotify_init")
        marked = 0
        for path in ("/", "/home"):
            if not os.path.isdir(path):
                continue
            rc = libc.fanotify_mark(fd, FAN_MARK_ADD | FAN_MARK_FILESYSTEM, FAN_CLOSE_WRITE,
                                    AT_FDCWD, path.encode())
            if rc == 0:
                marked += 1
        if not marked:
            os.close(fd)
            raise OSError(ctypes.get_errno(), "fanotify_mark")
        return fd

    def run(self):
        try:
            self.fd = self._init_fanotify()
        except OSError as e:
            log(f"Moniteur d'activité indisponible ({e}) — surveillance des rafales désactivée")
            return
        self.active = True
        log("Moniteur d'activité (fanotify) actif")
        while not self.daemon_ref.shutdown.is_set():
            try:
                buf = os.read(self.fd, 65536)
            except OSError:
                break
            off = 0
            while off + FAN_EVENT.size <= len(buf):
                event_len, _v, _r, _ml, mask, fd, pid = FAN_EVENT.unpack_from(buf, off)
                if event_len < FAN_EVENT.size:
                    break
                off += event_len
                if fd < 0:
                    continue
                try:
                    if pid != self.self_pid and mask & FAN_CLOSE_WRITE:
                        try:
                            path = os.readlink(f"/proc/self/fd/{fd}")
                        except OSError:
                            path = None
                        if path:
                            self.record(pid, path)
                            onaccess = getattr(self.daemon_ref, "onaccess", None)
                            if onaccess:
                                onaccess.consider(pid, path)      # on-arrival scan (downloads, desktop, drives)
                            guard = getattr(self.daemon_ref, "guard", None)
                            if guard:
                                guard.consider(pid, path)         # anti-ransomware decoys
                finally:
                    try:
                        os.close(fd)
                    except OSError:
                        pass
        self.active = False

    def stop(self):
        if self.fd is not None:
            try:
                os.close(self.fd)
            except OSError:
                pass

    # ── Suivi ────────────────────────────────────────────────────────────
    @staticmethod
    def ignored(path):
        if path.startswith(BURST_IGNORE_PREFIXES):
            return True
        return any(part in path for part in BURST_IGNORE_PARTS)

    def record(self, pid, path):
        if self.ignored(path) or not self.daemon_ref.settings.get("burst_monitor"):
            return
        now = time.time()
        window = self.daemon_ref.settings.get("burst_window_sec")
        track = self.tracks.get(pid)
        if track is None or now - track["first"] > window:
            track = {"first": now, "paths": set(), "home": 0, "count": 0}
            self.tracks[pid] = track
            if len(self.tracks) > 2000:      # limit memory: purge old tracks
                cutoff = now - window
                self.tracks = {p: tr for p, tr in self.tracks.items() if tr["first"] >= cutoff}
        if path in track["paths"]:
            return
        if len(track["paths"]) < 400:
            track["paths"].add(path)
        track["count"] += 1
        if track["count"] == BURST_IDENTIFY_AT:
            # Who writes: recorded from the first writes. An installer that lives one second has finished before the
            # evaluation (25th or 50th write) and the alert then named "?", treated as an unknown program.
            track["info"] = self.process_info(pid)
        if path.startswith("/home/") or path.startswith("/root/"):
            track["home"] += 1
        info_th = self.daemon_ref.settings.get("burst_info_threshold")
        danger_th = self.daemon_ref.settings.get("burst_danger_threshold")
        if track["count"] in (danger_th, info_th, 150, 500, 2000):
            self.evaluate(pid, track, now)

    # ── Evaluation ───────────────────────────────────────────────────────
    def process_info(self, pid):
        info = {"pid": pid, "comm": "?", "exe": "", "cmdline": "", "uid": None, "user": "", "ppid": 0, "argv": [], "script": ""}
        try:
            with open(f"/proc/{pid}/comm") as f:
                info["comm"] = f.read().strip()
        except OSError:
            pass
        try:
            info["exe"] = os.readlink(f"/proc/{pid}/exe")
        except OSError:
            pass
        try:
            with open(f"/proc/{pid}/cmdline", "rb") as f:
                raw = f.read()
            info["cmdline"] = raw.replace(b"\0", b" ").decode(errors="replace").strip()[:300]
            info["argv"] = [a.decode(errors="replace")[:512] for a in raw.split(b"\0")[:16] if a]
        except OSError:
            pass
        if is_interpreter(info["exe"]) and info["argv"]:
            # A script is judged by its own file, never by the interpreter (python3 belongs to a package)
            try:
                cwd = os.readlink(f"/proc/{pid}/cwd")
            except OSError:
                cwd = "/"
            info["script"] = script_of(info["argv"], cwd)
        try:
            with open(f"/proc/{pid}/status") as f:
                for line in f:
                    if line.startswith("PPid:"):
                        info["ppid"] = int(line.split()[1])
                    elif line.startswith("Uid:"):
                        info["uid"] = int(line.split()[1])
                        break
            if info["uid"] is not None:
                info["user"] = pwd.getpwuid(info["uid"]).pw_name
        except (OSError, KeyError, ValueError):
            pass
        return info

    def exe_trusted(self, exe):
        """Executable known to the system (dpkg package / system location) or approved by the user ("It's me")?"""
        exe = normalize_exe(exe)
        if not exe:
            return False
        if exe in self.daemon_ref.user_trusted() or self.daemon_ref.central_trusted(exe):
            return True
        if exe.startswith(UNTRUSTED_EXE_PREFIXES):
            return False
        if not exe.startswith(TRUSTED_EXE_PREFIXES):
            return False
        if exe.startswith("/app/"):
            return True                       # inside a Flatpak sandbox (path seen from its own mount namespace)
        if exe.startswith(("/snap/", "/var/lib/flatpak/", "/opt/")):
            # Only if nobody but root can have put it there (/opt/<app> is sometimes left to the user)
            return root_owned_chain(exe)
        if exe in self.dpkg_cache:
            return self.dpkg_cache[exe]
        r = run_quiet(["dpkg", "-S", exe], timeout=15)
        owned = r.returncode == 0
        if len(self.dpkg_cache) > 500:
            self.dpkg_cache.clear()
        self.dpkg_cache[exe] = owned
        return owned

    @staticmethod
    def clamd_check(paths):
        """Quick scan via clamd (clamdscan --fdpass). Returns the list of FOUND."""
        found = []
        if not shutil.which("clamdscan") or not paths:
            return found
        r = run_quiet(["clamdscan"] + distro.clamdscan_args() + ["--fdpass", "--no-summary", "--infected"] + list(paths), timeout=60)
        for line in (r.stdout or "").splitlines():
            if line.endswith(" FOUND"):
                found.append(line)
        return found

    def evaluate(self, pid, track, now):
        if now - self.reported.get(pid, 0) < BURST_PID_COOLDOWN_SEC:
            return
        info = self.process_info(pid)
        if not info["exe"] and (track.get("info") or {}).get("exe"):
            info = track["info"]              # program already finished: identity recorded at its first writes
        if info["comm"] in ("clamscan", "clamd", "clamdscan", "freshclam", "find") and \
                info["exe"].startswith("/usr/"):
            return
        # The program that decides: the script for an interpreter ("" for inline code: nothing to trust)
        exe_path = info.get("script", "") if is_interpreter(info["exe"]) else normalize_exe(info["exe"])
        if exe_path and exe_path in self.daemon_ref.user_trusted():
            self.reported[pid] = now          # approved program: no more alerts
            return
        trusted = self.exe_trusted(exe_path) if exe_path else False
        if trusted and code_injected(pid, info.get("argv") or []):
            trusted = False               # a trusted binary made to run foreign code (Electron as Node, inspector…)
        if trusted and os.path.basename(exe_path) in QUIET_BURST_BASENAMES:
            self.reported[pid] = now          # gestionnaire de paquets, cache, sauvegarde : rafale attendue, silence
            return
        infected_exe = self.clamd_check([exe_path]) if exe_path and os.path.exists(exe_path) else []
        sample = sorted(track["paths"])[:200]
        infected_files = self.clamd_check(sample[:12])
        severity = "info"
        reasons = []
        if infected_exe:
            severity = "danger"
            reasons.append("exe_infected")
        if infected_files:
            severity = "danger"
            reasons.append("files_infected")
        # Most affected folder (to offer a targeted scan, and to recognize a burst already declared normal)
        dirs = {}
        for p in sample:
            d = os.path.dirname(p)
            dirs[d] = dirs.get(d, 0) + 1
        top_dir = max(dirs, key=dirs.get) if dirs else "/"
        if severity == "info" and self.daemon_ref.settings.get("auto_ignore_known") is not False \
                and not exe_path.startswith(("/tmp/", "/var/tmp/", "/dev/shm/")):
            # Nothing infected: what is known is ignored automatically ("Learn from my choices" setting), a log line
            # keeps a record of it. In order: action launched by a package manager (apt upgrade, system update…),
            # application that only writes in its own folder, burst the user has already declared normal.
            why = self.launched_by(info)
            if why:
                why = f"launched by {why}"
            elif track["paths"] and all(self.app_data_path(p) for p in track["paths"]):
                why = "application folder"
            elif self.daemon_ref.habit_learned(self.daemon_ref.habit_key(exe_path or info["exe"], top_dir)):
                why = "learned"
            if why:
                self.reported[pid] = now
                self.note_auto_ignored(why, info["comm"], track["count"], top_dir, now)
                return
        if not trusted and track["home"] >= self.daemon_ref.settings.get("burst_danger_threshold"):
            severity = "danger"
            reasons.append("untrusted_home_burst")
        if not trusted and exe_path.startswith(("/tmp/", "/var/tmp/", "/dev/shm/")):
            severity = "danger"
            reasons.append("exe_in_temp")
        if severity == "info" and track["count"] < self.daemon_ref.settings.get("burst_info_threshold"):
            return
        if severity == "info" and now - self.last_report < BURST_GLOBAL_COOLDOWN:
            return
        self.reported[pid] = now
        self.last_report = now
        alert = {
            "kind": "burst",
            "time": now_iso(), "severity": severity, "reasons": reasons,
            "pid": pid, "comm": info["comm"], "exe": exe_path or info["exe"], "cmdline": info["cmdline"],
            "interpreter": info["exe"] if is_interpreter(info["exe"]) else "",
            "user": info["user"], "trusted": trusted, "exe_replaced": info["exe"].endswith(" (deleted)"),
            "count": track["count"], "home_count": track["home"],
            "window": self.daemon_ref.settings.get("burst_window_sec"),
            "sample": sample[:8], "top_dir": top_dir,
            "infected_exe": infected_exe, "infected_files": infected_files,
        }
        self.daemon_ref.publish_alert(alert)

    def launched_by(self, info):
        """Package manager or update tool this program descends from ("apt", "dpkg", "mintupdate"…),
        "" otherwise. Walks up the parents from the one recorded with the identity; a system executable is required."""
        ppid = int(info.get("ppid") or 0)
        for _ in range(8):
            if ppid <= 1:
                return ""
            p = self.process_info(ppid)
            parent = int(p.get("ppid") or 0)
            # The name comes from the real program file (the process name and its arguments can be set by anyone),
            # the tool must run as root, and its file must be root's (package or root-only folder)
            prog = p.get("script", "") if is_interpreter(p["exe"]) else normalize_exe(p["exe"])
            if prog and p.get("uid") == 0:
                tool = package_tool({os.path.splitext(os.path.basename(prog))[0].lower()})
                if tool and root_owned_chain(prog) and self.exe_trusted(prog):
                    return tool
            ppid = parent
        return ""

    def app_data_path(self, path):
        """File in the folder belonging to a known application (Steam, Flatpak, editor extensions, ~/ patterns of
        the central allowlist)?"""
        if any(fnmatch.fnmatch(path, pat) for pat in APP_DATA_DIRS):
            return True
        return any(pat.startswith("/home/*/") and fnmatch.fnmatch(path, pat) for pat in getattr(self.daemon_ref, "central_patterns", ()))

    def note_auto_ignored(self, why, comm, count, top_dir, now):
        """Log of bursts ignored automatically: at most one log line per minute (a system update produces
        dozens of them), with the count per reason."""
        pending = getattr(self, "auto_ignored", None)
        if pending is None:
            pending = self.auto_ignored = {"since": now, "n": {}, "last": ""}
        pending["n"][why] = pending["n"].get(why, 0) + 1
        pending["last"] = f"{comm} · {count} files · {top_dir}"
        if now - pending["since"] >= 60 or sum(pending["n"].values()) == 1:
            detail = ", ".join(f"{n}× {w}" for w, n in sorted(pending["n"].items()))
            self.daemon_ref.write_log(f"file bursts ignored automatically: {detail} (last: {pending['last'][:160]})")
            self.auto_ignored = {"since": now, "n": {}, "last": ""}


# ═══════════════════════════════════════════════════════════════════════════
# Monitoring of the volume sent to the Internet (/proc/net/dev)
# ═══════════════════════════════════════════════════════════════════════════

IGNORED_IFACE_PREFIXES = ("lo", "docker", "veth", "br-", "virbr", "vboxnet", "lxc", "lxdbr", "cni")


def read_tx_bytes():
    """Bytes transmitted, summed over physical/VPN interfaces (excluding loopback and local bridges)."""
    total = 0
    per_iface = {}
    try:
        with open("/proc/net/dev") as f:
            for line in f.readlines()[2:]:
                name, _, rest = line.partition(":")
                name = name.strip()
                if name.startswith(IGNORED_IFACE_PREFIXES):
                    continue
                fields = rest.split()
                if len(fields) >= 9:
                    tx = int(fields[8])
                    per_iface[name] = tx
                    total += tx
    except (OSError, ValueError):
        pass
    return total, per_iface


def outbound_processes(limit=8):
    """Processes with established outbound connections (via ss)."""
    procs = {}
    r = run_quiet(["ss", "-Htnp", "state", "established"], timeout=10)
    for line in (r.stdout or "").splitlines():
        for m in re.finditer(r'\("([^"]+)",pid=(\d+)', line):
            name, pid = m.group(1), int(m.group(2))
            entry = procs.setdefault((name, pid), {"name": name, "pid": pid, "connections": 0})
            entry["connections"] += 1
    return sorted(procs.values(), key=lambda p: -p["connections"])[:limit]


ONACCESS_MAX_BYTES = 512 * 1024 * 1024
REMOVABLE_PREFIXES = ("/media/", "/mnt/", "/run/media/")
USER_DIR_DEFAULTS = ("Downloads", "Téléchargements", "Desktop", "Bureau", "Scaricati", "Scrivania", "Herunterladen", "Schreibtisch")


class OnAccessScanner(threading.Thread):
    """On-arrival scan: a file closed after writing in a download folder, on the desktop or on removable
    media (fanotify event from the activity monitor) goes through clamd; infected → quarantined before being
    opened, red popup, alert, email. Browsers first write a .part / .crdownload file: that is the file scanned,
    so the download fails cleanly if the file is infected."""

    def __init__(self, daemon):
        super().__init__(daemon=True, name="onaccess-scanner")
        self.daemon_ref = daemon
        self.queue = _queue.Queue()
        self.recent = {}
        self.dirs, self.dirs_at = (), 0.0
        self.lock = threading.Lock()
        self.stats = {"scanned": 0, "infected": 0, "last": ""}

    def watched_dirs(self):
        """Download folders and desktops of each user (XDG user-dirs.dirs, otherwise usual names), refreshed every 5 min."""
        now = time.time()
        if now - self.dirs_at < 300:
            return self.dirs
        dirs = set()
        for pw in pwd.getpwall():
            if not ((pw.pw_uid >= 1000 or pw.pw_uid == 0) and pw.pw_dir.startswith(("/home/", "/root")) and os.path.isdir(pw.pw_dir)):
                continue
            home = pw.pw_dir.rstrip("/")
            names = []
            try:
                # Read without blocking or following into a device: a FIFO here froze the whole activity monitor
                with open_user_file(os.path.join(home, ".config", "user-dirs.dirs"), limit=1 << 16) as f:
                    for ln in f:
                        m = re.match(r'^XDG_(DOWNLOAD|DESKTOP)_DIR="?\$HOME/([^"\n]+?)/?"?$', ln.strip())
                        if m:
                            names.append(m.group(2))
            except OSError:
                pass
            for n in names + list(USER_DIR_DEFAULTS):
                d = os.path.join(home, n)
                if os.path.isdir(d):
                    dirs.add(d + "/")
        self.dirs, self.dirs_at = tuple(sorted(dirs)), now
        return self.dirs

    def consider(self, pid, path):
        if self.daemon_ref.settings.get("on_access_scan") is False:
            return
        if path.startswith(SYSTEM_STATE_DIR) or not (path.startswith(REMOVABLE_PREFIXES) or path.startswith(self.watched_dirs())):
            return
        now = time.time()
        with self.lock:
            if now - self.recent.get(path, 0) < 10:
                return
            self.recent[path] = now
            if len(self.recent) > 2000:
                self.recent = {p: t for p, t in self.recent.items() if now - t < 60}
        self.queue.put(path)

    def run(self):
        while not self.daemon_ref.shutdown.is_set():
            try:
                path = self.queue.get(timeout=1)
            except _queue.Empty:
                continue
            try:
                self.scan(path)
            except Exception as e:  # noqa: BLE001
                log(f"Analyse à l'arrivée {path} : {e}")

    def scan(self, path):
        try:
            st = os.lstat(path)
        except OSError:
            return
        if not _stat.S_ISREG(st.st_mode) or st.st_size == 0 or st.st_size > ONACCESS_MAX_BYTES or not shutil.which("clamdscan"):
            return
        r = run_quiet(["clamdscan"] + distro.clamdscan_args() + ["--fdpass", "--no-summary", "--infected", path], timeout=180)
        self.stats["scanned"] += 1
        self.stats["last"] = now_iso()
        sig = ""
        for line in (r.stdout or "").splitlines():
            if line.endswith(" FOUND") and ": " in line:
                sig = line.rsplit(": ", 1)[1][:-len(" FOUND")].strip()
        if not sig:
            return
        dest = self.quarantine(path, st)
        self.stats["infected"] += 1
        try:
            owner = pwd.getpwuid(st.st_uid).pw_name
        except KeyError:
            owner = str(st.st_uid)
        if dest:
            quarantine_index_add(SYSTEM_QUARANTINE_DIR, dest, path, sig, owner=st.st_uid)
        self.daemon_ref.write_log(f"⚠ on-access: {path} → {sig} ({'quarantined' if dest else 'NOT quarantined'})")
        log(f"Analyse à l'arrivée : {path} infecté ({sig}), {'mis en quarantaine' if dest else 'quarantaine impossible'}")
        self.daemon_ref.publish_alert({"kind": "download", "severity": "danger", "time": now_iso(), "title": os.path.basename(path), "detail": sig,
                                       "path": path, "quarantined": bool(dest), "user": owner, "pid": 0, "comm": "", "exe": "", "count": 0,
                                       "top_dir": os.path.dirname(path), "reasons": ["infected_download"], "sample": [path]})

    @staticmethod
    def quarantine_copy(src, path):
        """Copies the open file src into the quarantine folder under the name of path; returns the new path."""
        try:
            os.makedirs(SYSTEM_QUARANTINE_DIR, mode=0o700, exist_ok=True)
            base = os.path.basename(path) or "file"
            dest, n = os.path.join(SYSTEM_QUARANTINE_DIR, base), 1
            while True:
                try:
                    out = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                    break
                except FileExistsError:
                    dest, n = os.path.join(SYSTEM_QUARANTINE_DIR, f"{base}.{n:03d}"), n + 1
            os.lseek(src, 0, os.SEEK_SET)
            with os.fdopen(out, "wb") as f:
                while True:
                    chunk = os.read(src, 1 << 20)
                    if not chunk:
                        break
                    f.write(chunk)
            return dest
        except OSError as e:
            log(f"Quarantaine impossible pour {path} : {e}")
            return ""

    def quarantine(self, path, st):
        """Isolates path if it is still the file that was scanned (st): opened without following a symbolic link,
        copied through that descriptor, removed only if the folder entry still is that inode. A user who swaps the
        folder for a link to /etc between the scan and now gets nothing moved."""
        try:
            src = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        except OSError as e:
            log(f"Quarantaine impossible pour {path} : {e}")
            return ""
        try:
            cur = os.fstat(src)
            if not _stat.S_ISREG(cur.st_mode) or (cur.st_dev, cur.st_ino) != (st.st_dev, st.st_ino):
                log(f"Quarantaine refusée pour {path} : fichier remplacé après l'analyse")
                return ""
            return self.daemon_ref._quarantine_fd(src, path, cur)
        finally:
            os.close(src)


class NetworkMonitor(threading.Thread):
    """Alerts when the volume sent exceeds the configured threshold within the configured window."""

    INTERVAL = 15

    def __init__(self, daemon):
        super().__init__(daemon=True, name="network-monitor")
        self.daemon_ref = daemon
        self.samples = deque()      # (timestamp, tx_total)
        self.last_alert = 0
        self.active = False
        self.current_gb = 0.0

    def run(self):
        self.active = True
        while not self.daemon_ref.shutdown.is_set():
            try:
                self.tick()
            except Exception as e:  # noqa: BLE001
                log(f"Réseau : {e}")
            self.daemon_ref.shutdown.wait(self.INTERVAL)
        self.active = False

    def tick(self):
        settings = self.daemon_ref.settings
        now = time.time()
        total, per_iface = read_tx_bytes()
        window = float(settings.get("upload_window_hours")) * 3600
        self.samples.append((now, total))
        while len(self.samples) > 1 and now - self.samples[0][0] > window:
            self.samples.popleft()
        oldest_t, oldest_tx = self.samples[0]
        sent = max(0, total - oldest_tx)       # a counter that restarts (reboot) gives 0
        self.current_gb = sent / 1e9
        if not settings.get("upload_monitor"):
            return
        threshold = float(settings.get("upload_alert_gb")) * 1e9
        if sent >= threshold and now - self.last_alert > window:
            self.last_alert = now
            alert = {
                "kind": "upload", "severity": "info", "time": now_iso(),
                "bytes": sent, "gb": round(sent / 1e9, 2), "window_hours": settings.get("upload_window_hours"),
                "threshold_gb": settings.get("upload_alert_gb"),
                "since": datetime.fromtimestamp(oldest_t).isoformat(timespec="seconds"),
                "processes": outbound_processes(), "ifaces": per_iface,
                "comm": "", "pid": 0, "count": 0, "top_dir": "", "reasons": [], "sample": [],
            }
            self.daemon_ref.publish_alert(alert)


# ═══════════════════════════════════════════════════════════════════════════
# Network security: UFW firewall and SSH service
# ═══════════════════════════════════════════════════════════════════════════

def ssh_port():
    try:
        with open("/etc/ssh/sshd_config") as f:
            for line in f:
                line = line.strip()
                if line.lower().startswith("port ") and not line.startswith("#"):
                    return int(line.split()[1])
    except (OSError, ValueError, IndexError):
        pass
    return 22


TIMESHIFT_CONF = "/etc/timeshift/timeshift.json"
TIMESHIFT_CRON = "/etc/cron.d/timeshift-hourly"


def timeshift_best_practice_config(existing=None):
    """Recommended Timeshift configuration: system snapshots on the main disk, daily (5),
    weekly (3), monthly (2); btrfs mode if the root is an @ subvolume, otherwise rsync excluding all the
    contents of home folders (Timeshift default setting: hidden data — Flatpak, Steam,
    browsers — weighs tens of GB). Documents belong to the backup."""
    r = run_quiet(["findmnt", "-no", "FSTYPE,UUID,OPTIONS", "/"], timeout=10)
    parts = (r.stdout or "").split()
    fstype, uuid_root, options = (parts + ["", "", ""])[:3]
    btrfs = fstype == "btrfs" and "subvol=/@" in options
    cfg = dict(existing or {})
    cfg.update({
        "backup_device_uuid": uuid_root, "parent_device_uuid": "", "do_first_run": "false",
        "btrfs_mode": "true" if btrfs else "false", "include_btrfs_home": "false", "stop_cron_emails": "true",
        "schedule_monthly": "true", "schedule_weekly": "true", "schedule_daily": "true", "schedule_hourly": "false", "schedule_boot": "false",
        "count_monthly": "2", "count_weekly": "3", "count_daily": "5", "count_hourly": "6", "count_boot": "5",
        "exclude": [] if btrfs else ["/root/**", "/home/*/**"],
        "exclude-apps": cfg.get("exclude-apps") or [],
    })
    return cfg, btrfs


TIMESHIFT_TARGET_FS = ("ext4", "ext3", "xfs", "btrfs")       # Linux file systems with hard links (rsync snapshots)


def timeshift_targets(needed):
    """Mounted drives other than the system disk that can hold the snapshots (Linux file system), with their free
    space: [{uuid, label, mountpoint, fstype, free, size, enough}]. Offered when the main disk has no room."""
    r = run_quiet(["lsblk", "-J", "-b", "-o", "NAME,UUID,FSTYPE,MOUNTPOINT,FSAVAIL,SIZE,LABEL,MODEL,PKNAME"], timeout=15)
    try:
        tree = json.loads(r.stdout or "{}").get("blockdevices") or []
    except ValueError:
        return []
    root = run_quiet(["findmnt", "-no", "UUID", "/"], timeout=10).stdout.strip()
    out, stack = [], [(n, "") for n in tree]
    while stack:
        n, model = stack.pop()
        model = n.get("model") or model
        stack += [(c, model) for c in n.get("children") or []]
        mp, fs, uuid = n.get("mountpoint") or "", (n.get("fstype") or "").lower(), n.get("uuid") or ""
        if not uuid or uuid == root or fs not in TIMESHIFT_TARGET_FS or not mp or mp in ("/", "/boot", "/boot/efi", "/home") \
                or mp.startswith(("/snap/", "/var/", "/usr/")):
            continue
        free = int(n.get("fsavail") or 0)
        out.append({"uuid": uuid, "label": n.get("label") or (model or "").strip() or os.path.basename(mp), "mountpoint": mp,
                    "fstype": fs, "free": free, "size": int(n.get("size") or 0), "enough": bool(needed) and free >= needed})
    return sorted(out, key=lambda d: (not d["enough"], -d["free"]))


def timeshift_write_config(cfg):
    os.makedirs(os.path.dirname(TIMESHIFT_CONF), exist_ok=True)
    tmp = TIMESHIFT_CONF + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)
    os.chmod(tmp, 0o644)
    os.replace(tmp, TIMESHIFT_CONF)


TIMESHIFT_MIN_FREE = 10 * 1024 ** 3        # below this threshold, scheduled snapshots are suspended
TIMESHIFT_GUARD_CRON = ("SHELL=/bin/sh\nPATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin\n"
                        "# Dukiwi Shield : instantane planifie seulement s'il reste au moins 10 Go sur le disque principal\n"
                        "@hourly root a=$(df -k --output=avail / | tail -n1 | tr -d ' '); [ \"${a:-0}\" -ge 10485760 ] && timeshift --check\n")
DU_EXCLUDES = ["/home", "/root", "/timeshift", "/timeshift-btrfs", "/dev", "/proc", "/sys", "/run", "/tmp", "/media", "/mnt",
               "/var/lib/docker", "/var/lib/schroot", "/snap", "/var/cache/apt/archives", "/var/log", "/swapfile", "/lost+found"]


def estimate_system_size(timeout=900):
    """Size of the system as Timeshift copies it in rsync mode (without home folders), in bytes;
    None if du fails. One to two minutes on a large system, at low priority."""
    cmd = []
    if shutil.which("nice"):
        cmd += ["nice", "-n", "19"]
    if shutil.which("ionice"):
        cmd += ["ionice", "-c", "3"]
    cmd += ["du", "-sxB1"] + [f"--exclude={p}" for p in DU_EXCLUDES] + ["/"]
    r = run_quiet(cmd, timeout=timeout)
    m = re.match(r"\s*(\d+)", r.stdout or "")
    return int(m.group(1)) if m else None


def timeshift_space_needed(size, btrfs=False):
    """Free space required before enabling: 1.2 × the system + 10 GB (first full copy, then increments);
    with btrfs the snapshots copy nothing, only the minimum threshold applies."""
    return TIMESHIFT_MIN_FREE if btrfs else int(size * 1.2) + TIMESHIFT_MIN_FREE


def timeshift_free_bytes(cfg=None):
    """Free space (and mount point) of the disk receiving the snapshots: the configured device if it is
    mounted, otherwise the main disk; (None, "") if the configured disk is an unmounted dedicated disk."""
    uuid = (cfg or {}).get("backup_device_uuid") or ""
    path = "/"
    if uuid:
        r = run_quiet(["findmnt", "-rno", "TARGET", "-S", f"UUID={uuid}"], timeout=10)
        lines = [x.strip() for x in (r.stdout or "").splitlines() if x.strip()]
        if lines:
            path = lines[0]
        else:
            return None, ""
    try:
        st = os.statvfs(path)
        return st.f_bavail * st.f_frsize, path
    except OSError:
        return None, path


def timeshift_restore_test(sample=20):
    """Monthly test: a few system files from the last Timeshift snapshot (rsync) read in full and compared with the
    system when they have not changed since (same size, same date). With btrfs, snapshots are only mounted by
    Timeshift itself: test skipped."""
    import random
    res = {"date": now_iso(), "ok": False, "checked": 0, "restored": 0, "compared": 0, "identical": 0, "failed": [], "error": ""}
    try:
        with open(TIMESHIFT_CONF, encoding="utf-8") as f:
            cfg = json.load(f)
    except (OSError, ValueError):
        res["error"] = "not_configured"
        return res
    if str(cfg.get("btrfs_mode", "")).lower() == "true":
        res["error"] = "btrfs"
        return res
    _free, path = timeshift_free_bytes(cfg)
    base = os.path.join(path, "timeshift", "snapshots") if path else ""
    names = sorted(n for n in os.listdir(base) if re.match(r"^\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2}$", n)) if base and os.path.isdir(base) else []
    if not names:
        res["error"] = "device_unmounted" if not path else "no_snapshot"
        return res
    root = os.path.join(base, names[-1], "localhost")
    files = []
    for top in ("etc", "usr/bin", "usr/sbin", "usr/lib/python3"):
        for dirpath, dirs, fnames in os.walk(os.path.join(root, top)):
            for n in fnames:
                p = os.path.join(dirpath, n)
                if os.path.isfile(p) and not os.path.islink(p):
                    files.append(p)
            if len(files) > 6000:
                break
    if not files:
        res["error"] = "no_files"
        return res
    for snap_file in random.sample(files, min(sample, len(files))):
        res["checked"] += 1
        rel = os.path.relpath(snap_file, root)
        try:
            digest = sha256_file(snap_file)
            res["restored"] += 1
        except OSError as e:
            res["failed"].append({"path": "/" + rel, "error": str(e)[:120]})
            continue
        live = "/" + rel
        try:
            st_s, st_l = os.stat(snap_file), os.stat(live)
        except OSError:
            continue
        if st_s.st_size == st_l.st_size and int(st_s.st_mtime) == int(st_l.st_mtime):
            res["compared"] += 1
            if sha256_file(live) == digest:
                res["identical"] += 1
            else:
                res["failed"].append({"path": live, "error": "content_differs"})
    res["ok"] = res["restored"] > 0 and not res["failed"]
    res["snapshot"] = names[-1]
    return res


def collect_timeshift_status(list_snapshots=True):
    """Timeshift system snapshots: installed, configured, schedule, last snapshot (root read)."""
    ts = {"checked_at": now_iso(), "installed": shutil.which("timeshift") is not None, "configured": False,
          "schedule": [], "mode": "", "device": "", "snapshots": None, "last": None, "error": ""}
    if not ts["installed"]:
        return ts
    cfg = {}
    try:
        with open(TIMESHIFT_CONF, encoding="utf-8") as f:
            cfg = json.load(f)
        ts["configured"] = True
        ts["mode"] = "btrfs" if str(cfg.get("btrfs_mode", "")).lower() == "true" else "rsync"
        ts["device"] = cfg.get("backup_device_uuid", "") or ""
        ts["schedule"] = [k for k in ("boot", "hourly", "daily", "weekly", "monthly")
                          if str(cfg.get(f"schedule_{k}", "")).lower() == "true"]
    except (OSError, ValueError):
        ts["configured"] = False
    free, _path = timeshift_free_bytes(cfg)
    ts["free_bytes"] = free
    ts["low_space"] = free is not None and free < TIMESHIFT_MIN_FREE
    try:
        with open(TIMESHIFT_CRON, encoding="utf-8") as f:
            ts["managed"] = "df " in f.read()          # schedule set up by the application (space safeguard)
    except OSError:
        ts["managed"] = False
    if ts["configured"] and list_snapshots and os.geteuid() == 0:
        r = run_quiet(["timeshift", "--list", "--scripted"], timeout=120)
        names = sorted(set(re.findall(r"\b(\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2})\b", (r.stdout or ""))))
        if r.returncode == 0 or names:
            ts["snapshots"] = len(names)
            if names:
                ts["last"] = datetime.strptime(names[-1], "%Y-%m-%d_%H-%M-%S").isoformat(timespec="seconds")
        else:
            ts["error"] = ((r.stderr or "") + (r.stdout or "")).strip()[-200:]
    return ts


def collect_security_status():
    """State of the UFW firewall and the SSH service."""
    ufw = firewalld_status() if distro.firewall_backend() == "firewalld" else \
        {"installed": shutil.which("ufw") is not None, "active": False, "enabled": False,
         "default_incoming": "", "default_outgoing": "", "rules": [], "error": "", "backend": "ufw"}
    if ufw["installed"] and ufw.get("backend") != "firewalld":
        try:
            with open("/etc/ufw/ufw.conf") as f:
                ufw["enabled"] = any(line.strip() == "ENABLED=yes" for line in f)
        except OSError:
            pass
        ufw["active"] = ufw["enabled"] and systemd_is_active("ufw")
        if os.geteuid() == 0:
            r = run_quiet(["ufw", "status", "verbose"], timeout=20)
            if r.returncode == 0:
                ufw.update(parse_ufw_verbose(r.stdout))
                r2 = run_quiet(["ufw", "status", "numbered"], timeout=20)
                ufw["rules"] = parse_ufw_numbered(r2.stdout) if r2.returncode == 0 else []
            else:
                ufw["error"] = (r.stderr or r.stdout or "").strip()[:200]
            if not ufw["active"] and ufw["enabled"] and ufw_chains_loaded():
                ufw["active"] = True                    # ufw output not parsable: the chains are authoritative
            ufw["conflicts"] = firewall_conflicts()
            ufw["unit_enabled"] = unit_enabled("ufw")
        else:
            ufw["error"] = "root_required"
    ssh_installed = shutil.which("sshd") is not None or os.path.exists("/usr/sbin/sshd")
    ssh = {"installed": ssh_installed, "active": False, "enabled": False, "port": ssh_port(),
           "allowed_by_firewall": False}
    if ssh_installed:
        ssh["active"] = systemd_is_active("ssh") or systemd_is_active("sshd")
        r = run_quiet(["systemctl", "is-enabled", "ssh"], timeout=10)
        ssh["enabled"] = (r.stdout or "").strip() == "enabled"
    port = str(ssh["port"])
    ssh["allowed_by_firewall"] = any(
        rule["action"].startswith("ALLOW") and (rule["to"].startswith(port) or "OpenSSH" in rule["to"])
        for rule in ufw["rules"])
    return {"ufw": ufw, "ssh": ssh, "checked_at": now_iso()}


VALID_PROTO = ("tcp", "udp", "any")
FIREWALL_PROFILES = ("home", "public", "enterprise")
PROFILE_TAG = "cav-profile"                     # comment of the rules managed by the network profile
PROFILE_PRIVATE_NETS = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fe80::/10"]


def unit_active(name):
    r = run_quiet(["systemctl", "is-active", name], timeout=10)
    return (r.stdout or "").strip() == "active"


def unit_enabled(name):
    r = run_quiet(["systemctl", "is-enabled", name], timeout=10)
    return (r.stdout or "").strip() == "enabled"


MINT_AUTOMATION = "/usr/bin/mintupdate-automation"                                  # Linux Mint
MINT_AUTO_UPGRADE_FLAG = "/var/lib/linuxmint/mintupdate-automatic-upgrades-enabled"  # flag file read by the Update Manager
APT_AUTO_CONF = "/etc/apt/apt.conf.d/20auto-upgrades"                                # unattended-upgrades (autres Debian/Ubuntu)


def local_subnets():
    """Directly connected IPv4 subnets (ip -j route, scope link), excluding virtual interfaces."""
    r = run_quiet(["ip", "-j", "route"], timeout=10)
    nets = set()
    try:
        for rt in json.loads(r.stdout or "[]"):
            dst, dev = rt.get("dst", ""), rt.get("dev", "")
            if rt.get("scope") == "link" and "/" in dst and not dev.startswith(("lo", "docker", "br-", "veth", "virbr", "tun", "tap")):
                nets.add(dst)
    except ValueError:
        pass
    return sorted(nets)


def profile_services(profile):
    """Services allowed from the local network by the profile, depending on what is installed on the machine."""
    if profile == "public":
        return []
    svc = []
    if unit_active("ssh") or unit_active("sshd"):
        svc.append("ssh")
    if shutil.which("cupsd") or os.path.exists("/usr/sbin/cupsd"):
        svc.append("cups")
    if shutil.which("smbd") or os.path.exists("/usr/sbin/smbd"):
        svc.append("samba")
    if profile == "home":
        svc.append("mdns")
        if shutil.which("kdeconnectd") or glob.glob("/usr/lib/*/libexec/kdeconnectd") or glob.glob("/usr/libexec/kdeconnectd") \
                or glob.glob("/home/*/.local/share/gnome-shell/extensions/gsconnect*"):
            svc.append("kdeconnect")
    return svc


def profile_nets(profile):
    if profile == "public":
        return []
    if profile == "enterprise":
        return (local_subnets() or PROFILE_PRIVATE_NETS[:3]) + ["fe80::/10"]
    return list(PROFILE_PRIVATE_NETS)


def profile_rules(profile):
    """ufw arguments of the profile rules: permissions limited to the local network, tagged PROFILE_TAG."""
    ports = {"ssh": [(str(ssh_port()), "tcp")], "cups": [("631", "tcp")], "samba": [("139,445", "tcp"), ("137,138", "udp")],
             "mdns": [("5353", "udp")], "kdeconnect": [("1714:1764", "tcp"), ("1714:1764", "udp")]}
    rules = []
    nets = profile_nets(profile)
    for name in profile_services(profile):
        for port, proto in ports[name]:
            for net in nets:
                rules.append(["allow", "from", net, "to", "any", "port", port, "proto", proto, "comment", f"{PROFILE_TAG} {name}"])
    return rules
VALID_ACTION = ("allow", "deny", "reject", "limit")
VALID_POLICY = ("allow", "deny", "reject")
NETWORK_SKIP_TYPES = ("loopback", "vpn", "wireguard", "tun", "tap", "bridge", "dummy", "ip-tunnel")


TRAY_LAUNCHER = "/opt/dukiwi-shield/dukiwi-shield-tray"


def graphical_sessions():
    """Sessions graphiques locales actives : [{id, user, uid, type}] (loginctl)."""
    out = []
    r = run_quiet(["loginctl", "list-sessions", "--no-legend"], timeout=10)
    for ln in (r.stdout or "").splitlines():
        parts = ln.split()
        if not parts:
            continue
        sid = parts[0]
        s = run_quiet(["loginctl", "show-session", sid, "-p", "Type", "-p", "State", "-p", "Name", "-p", "Remote", "-p", "Class"], timeout=10)
        props = dict(kv.split("=", 1) for kv in (s.stdout or "").splitlines() if "=" in kv)
        if props.get("State") != "active" or props.get("Type") not in ("x11", "wayland") or props.get("Remote") == "yes" \
                or props.get("Class", "user") != "user":
            continue
        try:
            uid = pwd.getpwnam(props.get("Name", "")).pw_uid
        except KeyError:
            continue
        if uid >= 1000:
            out.append({"id": sid, "user": props.get("Name"), "uid": uid, "type": props.get("Type"), "age": session_age(sid)})
    return out


def session_age(sid):
    """Seconds since the session was opened (loginctl TimestampMonotonic vs uptime), None if unknown."""
    r = run_quiet(["loginctl", "show-session", sid, "-p", "TimestampMonotonic", "--value"], timeout=10)
    try:
        started = int((r.stdout or "").strip()) / 1e6
        with open("/proc/uptime") as f:
            return max(0.0, float(f.read().split()[0]) - started)
    except (ValueError, OSError):
        return None


TRAY_PROCESS_RE = r"^(/usr/bin/)?python3(\.[0-9]+)? /opt/dukiwi-shield/dukiwi-shield\.py"


def network_identity():
    """Current network: {key, name, type, device}. Stable key = NetworkManager connection carrying the default
    route (uuid), otherwise the gateway MAC address. None when offline."""
    r = run_quiet(["ip", "-j", "route", "show", "default"], timeout=10)
    try:
        routes = json.loads(r.stdout or "[]")
    except ValueError:
        routes = []
    routes = [x for x in routes if x.get("dev")]
    if not routes:
        return None
    routes.sort(key=lambda x: x.get("metric", 0))
    dev, gw = routes[0]["dev"], routes[0].get("gateway", "")
    mac = gateway_mac(gw) if gw else ""
    if shutil.which("nmcli"):
        r = run_quiet(["nmcli", "-t", "-f", "UUID,NAME,TYPE,DEVICE", "connection", "show", "--active"], timeout=10)
        for ln in (r.stdout or "").splitlines():
            parts = [x.replace("\\:", ":") for x in re.split(r"(?<!\\):", ln.strip())]
            if len(parts) < 4 or parts[3] != dev or parts[2] in NETWORK_SKIP_TYPES:
                continue
            kind = "wifi" if "wireless" in parts[2] else "ethernet" if "ethernet" in parts[2] else "other"
            return {"key": f"nm:{parts[0]}", "name": parts[1] or dev, "type": kind, "device": dev, "gw": gw, "gw_mac": mac}
    return {"key": f"gw:{mac or gw or dev}", "name": gw or dev, "type": "ethernet", "device": dev, "gw": gw, "gw_mac": mac}


def gateway_mac(gw):
    """Hardware address of the gateway (neighbour table). A change on a known network = router replaced,
    or a device impersonating it (ARP poisoning, man in the middle)."""
    r = run_quiet(["ip", "-j", "neigh", "show", gw], timeout=10)
    try:
        return next((x.get("lladdr", "").lower() for x in json.loads(r.stdout or "[]") if x.get("lladdr")), "")
    except ValueError:
        return ""


def wifi_security(device=""):
    """Encryption of the active Wi-Fi: "open" (none), "wep" (broken), "secured", or "" if unknown."""
    if not shutil.which("nmcli"):
        return ""
    r = run_quiet(["nmcli", "-t", "-f", "ACTIVE,SECURITY,SSID", "dev", "wifi"] + (["ifname", device] if device else []), timeout=15)
    for ln in (r.stdout or "").splitlines():
        parts = [x.replace("\\:", ":") for x in re.split(r"(?<!\\):", ln.strip())]
        if len(parts) >= 2 and parts[0] == "yes":
            sec = parts[1].strip()
            if sec in ("", "--"):
                return "open"
            return "wep" if "WEP" in sec.upper() else "secured"
    return ""


def vpn_active():
    """Is a VPN active (NetworkManager vpn/wireguard connection, or tun/wg/tap/ppp interface up)?"""
    if shutil.which("nmcli"):
        r = run_quiet(["nmcli", "-t", "-f", "NAME,TYPE", "connection", "show", "--active"], timeout=10)
        for ln in (r.stdout or "").splitlines():
            if ln.rsplit(":", 1)[-1].strip() in ("vpn", "wireguard", "tun", "ip-tunnel"):
                return True
    r = run_quiet(["ip", "-j", "link", "show", "up"], timeout=10)
    try:
        return any(re.match(r"^(tun|wg|tap|ppp|proton|nordlynx)\d*", x.get("ifname", "")) for x in json.loads(r.stdout or "[]"))
    except ValueError:
        return False


UFW_RULE_COMMANDS = ("allow", "deny", "reject", "limit", "insert", "prepend")
FEATURES_OPT_IN = ("honeypot",)
URLGUARD_DIR = os.path.join(SYSTEM_STATE_DIR, "urlguard")          # index of the malicious site lists
MAIL_TMP_PREFIX = "/tmp/dukiwi-shield-mail-"                       # attachments dropped by the native host (per uid)
BROWSER_BINARIES = {"thunderbird": ("thunderbird",), "firefox": ("firefox", "firefox-esr"), "chrome": ("google-chrome", "google-chrome-stable"),
                    "chromium": ("chromium", "chromium-browser"), "edge": ("microsoft-edge", "microsoft-edge-stable"), "brave": ("brave-browser", "brave")}               # advanced protections offered to the user (never enabled automatically)


UFW_INIT = os.environ.get("DUKIWI_SHIELD_UFW_INIT") or next((p for p in ("/lib/ufw/ufw-init", "/usr/lib/ufw/ufw-init") if os.path.exists(p)), "/lib/ufw/ufw-init")


def ufw_chains_loaded():
    """The UFW chains exist in the kernel (same test as ufw-init: "Firewall already started"),
    independent of the language and of ufw.conf. Root only; False if iptables is missing."""
    if os.geteuid() != 0 and not os.environ.get("DUKIWI_SHIELD_UFW_INIT"):
        return False
    r = run_quiet(["iptables", "-L", "ufw-user-input", "-n"], timeout=15)
    return r.returncode == 0


def firewall_running():
    """True if the UFW chains are actually loaded: "Status: active", or chains present (fallback if the
    ufw output cannot be parsed)."""
    r = run_quiet(["ufw", "status"], timeout=20)
    if r.returncode == 0 and parse_ufw_verbose(r.stdout).get("active"):
        return True
    return ufw_chains_loaded()


# ── firewalld (Fedora) : zones home / public / work ↔ profils Maison / Public / Entreprise ──
FIREWALLD_ZONES = {"home": "home", "public": "public", "enterprise": "work"}
FIREWALLD_SERVICE_PORTS = {"ssh": "22/tcp", "http": "80/tcp", "https": "443/tcp", "mdns": "5353/udp", "samba": "139,445/tcp",
                           "ipp": "631/tcp", "kdeconnect": "1714:1764/tcp", "dhcpv6-client": "546/udp", "dhcp": "67/udp",
                           "dns": "53/tcp", "cockpit": "9090/tcp", "ftp": "21/tcp", "smtp": "25/tcp", "vnc-server": "5900:5903/tcp",
                           "rdp": "3389/tcp", "mysql": "3306/tcp", "postgresql": "5432/tcp", "nfs": "2049/tcp", "ntp": "123/udp"}
PROFILE_FIREWALLD_SERVICES = {"ssh": "ssh", "cups": "ipp", "samba": "samba", "mdns": "mdns", "kdeconnect": "kdeconnect"}


def fwcmd(*args, timeout=60):
    r = run_quiet(["firewall-cmd", *args], timeout=timeout)
    return r.returncode == 0, ((r.stdout or "") + (r.stderr or "")).strip()


def firewalld_zone():
    ok, out = fwcmd("--get-default-zone", timeout=15)
    return out.strip() if ok and out.strip() else "public"


def firewalld_rules(zone):
    """Services, ports and rich rules of the zone, in the ufw rule format (to / action / from / comment)
    for the interface and ufw_port_allowed; kind/spec are used for deletion."""
    rules = []

    def add(to, action, frm, comment, kind, spec):
        rules.append({"number": len(rules) + 1, "to": to, "action": action, "from": frm, "comment": comment,
                      "v6": False, "raw": spec, "kind": kind, "spec": spec})
    ok, svcs = fwcmd("--zone", zone, "--list-services", timeout=15)
    for s in (svcs.split() if ok else []):
        add(FIREWALLD_SERVICE_PORTS.get(s, f"service {s}"), "ALLOW IN", "Anywhere", s, "service", s)
    ok, ports = fwcmd("--zone", zone, "--list-ports", timeout=15)
    for p in (ports.split() if ok else []):
        add(p, "ALLOW IN", "Anywhere", "", "port", p)
    ok, rich = fwcmd("--zone", zone, "--list-rich-rules", timeout=15)
    for ln in (rich.splitlines() if ok else []):
        ln = ln.strip()
        if not ln:
            continue
        src = re.search(r'source address="([^"]+)"', ln)
        port = re.search(r'port port="([^"]+)" protocol="([^"]+)"', ln)
        svc = re.search(r'service name="([^"]+)"', ln)
        if " accept" in ln:
            verdict = "LIMIT IN" if "limit value" in ln else "ALLOW IN"
        elif " reject" in ln:
            verdict = "REJECT IN"
        else:
            verdict = "DENY IN"
        to = f"{port.group(1).replace('-', ':')}/{port.group(2)}" if port else \
            (FIREWALLD_SERVICE_PORTS.get(svc.group(1), f"service {svc.group(1)}") if svc else "Anywhere")
        add(to, verdict, src.group(1) if src else "Anywhere", "rich", "rich", ln)
    return rules


def firewalld_status():
    fw = {"installed": shutil.which("firewall-cmd") is not None, "backend": "firewalld", "active": False, "enabled": False,
          "default_incoming": "", "default_outgoing": "allow", "rules": [], "error": "", "zone": "", "conflicts": [], "unit_enabled": False}
    if not fw["installed"]:
        return fw
    fw["enabled"] = fw["unit_enabled"] = unit_enabled("firewalld")
    ok, state = fwcmd("--state", timeout=15)
    fw["active"] = ok and "running" in state
    if not fw["active"]:
        fw["error"] = "" if (not state or "not running" in state) else state[:200]
        return fw
    zone = firewalld_zone()
    fw["zone"] = zone
    ok, target = fwcmd("--permanent", "--zone", zone, "--get-target", timeout=15)
    fw["default_incoming"] = "allow" if ok and target.strip() == "ACCEPT" else ("reject" if "REJECT" in target else "deny")
    fw["rules"] = firewalld_rules(zone)
    fw["conflicts"] = firewall_conflicts()
    return fw


def firewall_conflicts():
    """Other firewall managers likely to wipe the rules (at boot or on the fly)."""
    out = []
    backend = distro.firewall_backend()
    if backend == "firewalld" and systemd_is_active("ufw"):
        out.append("ufw")
    if backend != "firewalld" and systemd_is_active("firewalld"):
        out.append("firewalld")
    if systemd_is_active("nftables"):
        try:
            with open("/etc/nftables.conf", encoding="utf-8", errors="replace") as f:
                if "flush ruleset" in f.read():
                    out.append("nftables")
        except OSError:
            out.append("nftables")
    if systemd_is_active("netfilter-persistent"):
        out.append("netfilter-persistent")
    return out


def firewall_unit_persist(log_fn):
    """ufw.service unmasked, enabled and started: the rules are reloaded at boot and
    "systemctl is-active ufw" reflects the actual state."""
    if TEST_MODE and not os.environ.get("DUKIWI_SHIELD_UFW_INIT"):
        return
    r = run_quiet(["systemctl", "is-enabled", "ufw"], timeout=10)
    st = (r.stdout or "").strip()
    if st == "masked":
        run_quiet(["systemctl", "unmask", "ufw"], timeout=30)
    if st != "enabled":
        run_quiet(["systemctl", "enable", "ufw"], timeout=30)
        log_fn(f"ufw.service was {st or 'unknown'}: enabled at boot")
    if not systemd_is_active("ufw"):
        run_quiet(["systemctl", "start", "ufw"], timeout=60)       # ufw-init start quiet: no effect if already loaded


def firewall_enable_checked(ufw, log_fn):
    """Verified "Enable the firewall". `ufw enable` returns 0 with "Firewall is active" even when ufw-init fails,
    as soon as ufw.conf already said ENABLED=yes (frontend.set_enabled only reports the error if the state
    changed): the firewall looks enabled but stays inactive. So we check the actual state; if it is not loaded,
    we force disable → enable (the real error shows up), then ufw-init start, and return the error to the user."""
    ok, text = ufw("enable")
    if ok and firewall_running():
        firewall_unit_persist(log_fn)
        return True, text
    ufw("disable")
    ok2, text2 = ufw("enable")
    if ok2 and firewall_running():
        firewall_unit_persist(log_fn)
        return True, text2
    init = run_quiet([UFW_INIT, "start"], timeout=60)
    init_out = ((init.stdout or "") + (init.stderr or "")).strip()
    if firewall_running():
        firewall_unit_persist(log_fn)
        log_fn(f"firewall loaded by ufw-init after a silent ufw enable: {init_out[:160]}")
        return True, init_out or "loaded by ufw-init"
    parts = [x.strip() for x in ((text2 if not ok2 else ""), init_out) if x and x.strip()]
    detail = " | ".join(dict.fromkeys(parts)) or "firewall not active after enable"
    conflicts = firewall_conflicts()
    log_fn(f"firewall enable failed: {detail[:300]}" + (f" (conflicts: {', '.join(conflicts)})" if conflicts else ""))
    return False, detail[:300]


def ufw_args(args):
    """Full arguments of a ufw call. ufw only inserts the implicit "rule" keyword if the command comes
    first: "ufw --force allow …" answers "Invalid syntax" (frontend.parse_command). So we write
    "rule" explicitly for rule commands; "delete N" (by number) stays as is."""
    args = [str(a) for a in args]
    if args and (args[0] in UFW_RULE_COMMANDS or (args[0] == "delete" and len(args) > 1 and not args[1].isdigit())):
        args = ["rule"] + args
    return ["ufw", "--force"] + args


# ═══════════════════════════════════════════════════════════════════════════
# USB device monitoring (udev)
# ═══════════════════════════════════════════════════════════════════════════

def usb_identity(info):
    """Stable identity of a USB medium for "Trust this key": serial number and file system UUID
    (either one may be missing depending on the medium)."""
    serial, uuid = (info or {}).get("serial") or "", (info or {}).get("uuid") or ""
    return f"{serial}|{uuid}" if (serial or uuid) else ""


HID_POINTER_PROPS = ("ID_INPUT_MOUSE", "ID_INPUT_TOUCHPAD", "ID_INPUT_POINTINGSTICK", "ID_INPUT_TOUCHSCREEN", "ID_INPUT_TABLET")


class HidGuard(threading.Thread):
    """BadUSB: a rigged key presents itself as a keyboard and types commands in place of the user. Any new USB
    device declaring itself a keyboard (udev: ID_INPUT_KEYBOARD) is cut off as soon as it appears ("authorized" = 0,
    the kernel removes it) and a popup asks whether to allow it; consent remembered (vendor:product:serial id).
    Safeguards so the user is never locked out: the computer's only keyboard, or a keyboard+mouse receiver with no
    other pointer → allowed automatically (information popup). Keyboards present when the service starts are known."""

    def __init__(self, daemon):
        super().__init__(daemon=True, name="hid-guard")
        self.daemon_ref = daemon
        self.active = False
        self.pending = {}            # ident -> info (keyboards disabled, awaiting decision)
        self.session_seen = set()    # keyboards present when the service started
        self.lock = threading.Lock()
        self.ctx = None

    # ── identification ───────────────────────────────────────────────────────
    @staticmethod
    def _attr(dev, name):
        try:
            return (dev.attributes.asstring(name) or "").strip()
        except Exception:  # noqa: BLE001
            return ""

    @staticmethod
    def usb_parent(device):
        try:
            return device.find_parent("usb", "usb_device")
        except Exception:  # noqa: BLE001
            return None

    def describe(self, usb):
        vendor = (usb.get("ID_VENDOR_ID") or self._attr(usb, "idVendor")).lower()
        product = (usb.get("ID_MODEL_ID") or self._attr(usb, "idProduct")).lower()
        serial = usb.get("ID_SERIAL_SHORT") or self._attr(usb, "serial")
        name = " ".join(x for x in ((usb.get("ID_VENDOR") or self._attr(usb, "manufacturer")).replace("_", " ").strip(),
                                    (usb.get("ID_MODEL") or self._attr(usb, "product")).replace("_", " ").strip()) if x)
        return {"id": f"{vendor}:{product}:{serial}", "name": name or f"USB {vendor}:{product}", "vendor": vendor, "product": product,
                "serial": serial, "sys_path": usb.sys_path}

    def input_devices(self):
        if self.ctx is None:
            return []
        try:
            return [d for d in self.ctx.list_devices(subsystem="input") if d.sys_name.startswith("input")]
        except Exception:  # noqa: BLE001
            return []

    def other_keyboards(self, usb_sys_path):
        return sum(1 for d in self.input_devices() if d.get("ID_INPUT_KEYBOARD") == "1" and not d.sys_path.startswith(usb_sys_path))

    def other_pointers(self, usb_sys_path):
        return sum(1 for d in self.input_devices() if any(d.get(p) == "1" for p in HID_POINTER_PROPS) and not d.sys_path.startswith(usb_sys_path))

    def device_has_pointer(self, usb_sys_path):
        return any(any(d.get(p) == "1" for p in HID_POINTER_PROPS) for d in self.input_devices() if d.sys_path.startswith(usb_sys_path))

    @staticmethod
    def set_authorized(sys_path, value):
        with open(os.path.join(sys_path, "authorized"), "w") as f:
            f.write("1" if value else "0")

    # ── boucle udev ──────────────────────────────────────────────────────────
    def run(self):
        try:
            import pyudev
        except ImportError:
            log("pyudev absent — garde des claviers USB désactivée")
            return
        try:
            self.ctx = pyudev.Context()
            for d in self.input_devices():
                usb = self.usb_parent(d) if d.get("ID_INPUT_KEYBOARD") == "1" else None
                if usb is not None:
                    self.session_seen.add(self.describe(usb)["id"])
            monitor = pyudev.Monitor.from_netlink(self.ctx)
            monitor.filter_by("input")
            monitor.start()
        except Exception as e:  # noqa: BLE001
            log(f"Garde des claviers USB indisponible ({e})")
            return
        self.active = True
        log(f"Garde des claviers USB (udev) active, {len(self.session_seen)} clavier(s) USB connu(s)")
        while not self.daemon_ref.shutdown.is_set():
            device = monitor.poll(timeout=1)
            if device is None:
                continue
            try:
                self.handle(device)
            except Exception as e:  # noqa: BLE001
                log(f"Clavier USB : {e}")
        self.active = False

    def handle(self, device):
        if device.action != "add" or not device.sys_name.startswith("input") or device.get("ID_INPUT_KEYBOARD") != "1":
            return
        usb = self.usb_parent(device)
        if usb is None:
            return
        self.decide(self.describe(usb))

    def decide(self, info):
        """USB keyboard that just appeared: known → nothing; only keyboard or only pointer → allowed (information);
otherwise cut off."""
        if self.daemon_ref.settings.get("usb_keyboard_guard") is False:
            return "off"
        ident = info["id"]
        trusted = self.daemon_ref.state.get("trusted_hid") or {}
        if ident in trusted or ident in self.session_seen:
            log(f"Clavier USB connu : {info['name']} [{ident}]")
            return "known"
        reason = ""
        if self.other_keyboards(info["sys_path"]) == 0:
            reason = "only_keyboard"
        elif self.device_has_pointer(info["sys_path"]) and self.other_pointers(info["sys_path"]) == 0:
            reason = "only_pointer"
        base = {"kind": "usb_keyboard", "time": now_iso(), "title": info["name"], "detail": ident, "id": ident, "sys_path": info["sys_path"],
                "pid": 0, "comm": "", "exe": "", "count": 0, "top_dir": "", "sample": []}
        if reason:
            self.session_seen.add(ident)
            self.daemon_ref.write_log(f"USB keyboard allowed ({reason}): {info['name']} [{ident}]")
            self.daemon_ref.publish_alert(dict(base, severity="info", blocked=False, reason=reason, reasons=[reason]))
            return reason
        try:
            self.set_authorized(info["sys_path"], False)
        except OSError as e:
            log(f"Clavier USB {info['name']} : impossible de le couper ({e})")
            self.daemon_ref.publish_alert(dict(base, severity="danger", blocked=False, reason="block_failed", reasons=["block_failed"]))
            return "block_failed"
        with self.lock:
            self.pending[ident] = dict(info, time=now_iso())
        self.daemon_ref.write_log(f"⚠ USB keyboard BLOCKED pending approval: {info['name']} [{ident}]")
        log(f"Nouveau clavier USB coupé en attente d'accord : {info['name']} [{ident}]")
        self.daemon_ref.publish_alert(dict(base, severity="danger", blocked=True, reason="new_keyboard", reasons=["new_keyboard"]))
        return "blocked"

    def allow(self, ident, remember=True):
        """"Allow this keyboard": re-enabled (the kernel re-enumerates it) and remembered."""
        with self.lock:
            info = self.pending.pop(ident, None)
        if info is None:
            return None
        try:
            self.set_authorized(info["sys_path"], True)
        except OSError as e:
            log(f"Clavier USB {info['name']} : réactivation impossible ({e})")
        self.session_seen.add(ident)
        if remember:
            trusted = dict(self.daemon_ref.state.get("trusted_hid") or {})
            trusted[ident] = {"name": info["name"], "vendor": info["vendor"], "product": info["product"], "serial": info["serial"], "at": now_iso()}
            self.daemon_ref.state.update(trusted_hid=trusted)
        return info


class UsbWatcher(threading.Thread):
    """Scans USB keys before mounting them; asks for USB hard drives."""

    def __init__(self, daemon):
        super().__init__(daemon=True, name="usb-watcher")
        self.daemon_ref = daemon
        self.active = False
        self.pending = {}           # devnode -> info (large disks awaiting decision)
        self.mounted = {}           # devnode -> mountpoint (daemon private mounts)
        self.present = {}           # devnode -> info of the USB drives plugged in now (mount diagnosis)
        self.diagnosed = {}         # devnode -> cached answer of diagnose() for this plug
        self.lock = threading.Lock()

    def run(self):
        try:
            import pyudev
        except ImportError:
            log("pyudev absent — surveillance USB désactivée")
            return
        try:
            ctx = pyudev.Context()
            monitor = pyudev.Monitor.from_netlink(ctx)
            monitor.filter_by("block")
            monitor.start()
        except Exception as e:  # noqa: BLE001
            log(f"Surveillance USB indisponible ({e})")
            return
        self.active = True
        log("Surveillance USB (udev) active")
        while not self.daemon_ref.shutdown.is_set():
            device = monitor.poll(timeout=1)
            if device is None:
                continue
            try:
                self.handle(device)
            except Exception as e:  # noqa: BLE001
                log(f"USB : {e}")
        self.active = False

    def describe(self, device):
        """Useful information about a USB partition/disk carrying a file system."""
        settings = self.daemon_ref.settings
        max_bytes = int(settings.get("usb_auto_scan_max_gib")) * 1024 ** 3
        auto = bool(settings.get("usb_auto_scan"))
        bus = device.get("ID_BUS")
        parent = device.find_parent("block", "disk") if device.get("DEVTYPE") == "partition" else None
        if bus != "usb" and (parent is None or parent.get("ID_BUS") != "usb"):
            return None
        fstype = device.get("ID_FS_TYPE") or ""
        if not fstype or fstype in ("swap", "LVM2_member", "crypto_LUKS", "linux_raid_member"):
            return None
        try:
            size = int(device.attributes.asstring("size")) * 512
        except Exception:  # noqa: BLE001
            size = 0
        src = parent if parent is not None else device
        try:
            removable = src.attributes.asstring("removable") == "1"
        except Exception:  # noqa: BLE001
            removable = False
        return {
            "devnode": device.device_node,
            "label": device.get("ID_FS_LABEL") or "",
            "fstype": fstype,
            "size": size,
            "vendor": (device.get("ID_VENDOR") or src.get("ID_VENDOR") or "").replace("_", " ").strip(),
            "model": (device.get("ID_MODEL") or src.get("ID_MODEL") or "").replace("_", " ").strip(),
            "serial": device.get("ID_SERIAL_SHORT") or src.get("ID_SERIAL_SHORT") or "",
            "uuid": device.get("ID_FS_UUID") or "",
            "removable": removable,
            "kind": "key" if (auto and size <= max_bytes) else "hdd",
        }

    def handle(self, device):
        action = device.action
        devnode = device.device_node
        if action == "add":
            info = self.describe(device)
            if not info:
                return
            ident = usb_identity(info)
            info["trusted"] = bool(ident and (self.daemon_ref.state.get("trusted_usb") or {}).get(ident))
            with self.lock:
                self.present[devnode] = info
                self.diagnosed.pop(devnode, None)
            log(f"USB détecté : {devnode} ({info['label'] or info['model']}, "
                f"{info['size'] // 2**20} MiB, {info['kind']}{', de confiance' if info['trusted'] else ''})")
            self.daemon_ref.broadcast({"event": "usb_added", "usb": info})
            if info["trusted"]:
                # "Trust this key": handed to the user without scanning (choice revocable in Settings)
                self.daemon_ref.write_log(f"USB trusted, mounted without scan: {devnode} ({info['label'] or info['model']})")
                self.daemon_ref.broadcast({"event": "usb_trusted", "usb": info})
            elif info["kind"] == "key":
                self.daemon_ref.start_usb_scan(info)
            else:
                with self.lock:
                    self.pending[devnode] = info
                self.daemon_ref.broadcast({"event": "usb_ask", "usb": info})
        elif action == "remove":
            with self.lock:
                info = self.pending.pop(devnode, None)
                self.present.pop(devnode, None)
                self.diagnosed.pop(devnode, None)
            job = self.daemon_ref.current_job()
            if job and job.usb and job.usb.get("devnode") == devnode:
                log(f"USB retiré pendant l'analyse : {devnode}")
                job.usb["removed"] = True
                job.cancel(by_user=True)
            self.unmount(devnode)
            self.daemon_ref.broadcast({"event": "usb_removed", "devnode": devnode, "usb": info})

    # ── Private mount ────────────────────────────────────────────────────
    def mount(self, info):
        devnode = info["devnode"]
        mountpoint = os.path.join(USB_MOUNT_ROOT, os.path.basename(devnode))
        os.makedirs(mountpoint, exist_ok=True)
        # nosymfollow: a symbolic link stored on the drive is never followed (root writes the manifest there)
        opts = "nosuid,nodev,noexec,nosymfollow"
        if info["fstype"] in ("vfat", "exfat", "ntfs"):
            opts += ",umask=077"
        if info["fstype"] in ("vfat", "iso9660"):
            # File names in UTF-8, like the desktop mount. Without this option the kernel returns them in ISO 8859-1:
            # "é" becomes byte 0xE9, invalid in UTF-8, and the drive inventory failed ("Internal error:
            # 'utf-8' codec can't decode byte 0xe9"), which left the key inaccessible.
            opts += ",utf8"
        r = run_quiet(["mount", "-o", opts, devnode, mountpoint], timeout=60)
        # Fallbacks: without the file system options, then without nosymfollow (kernels before 5.10); the manifest
        # writer does not follow links anyway
        for fallback in ("nosuid,nodev,noexec,nosymfollow", "nosuid,nodev,noexec"):
            if r.returncode == 0:
                break
            r = run_quiet(["mount", "-o", fallback, devnode, mountpoint], timeout=60)
        if r.returncode != 0:
            try:
                os.rmdir(mountpoint)
            except OSError:
                pass
            raise OSError(f"mount {devnode}: {(r.stderr or '').strip()}")
        with self.lock:
            self.mounted[devnode] = mountpoint
        return mountpoint

    def unmount(self, devnode):
        with self.lock:
            mountpoint = self.mounted.pop(devnode, None)
        if not mountpoint:
            return
        for _ in range(5):
            r = run_quiet(["umount", mountpoint], timeout=60)
            if r.returncode == 0:
                break
            time.sleep(1)
        else:
            run_quiet(["umount", "-l", mountpoint], timeout=60)
        try:
            os.rmdir(mountpoint)
        except OSError:
            pass

    def diagnose(self, devnode):
        """Why a plugged USB drive does not mount for the user (2.9.2): for NTFS, the volume state read by
        `ntfsfix --no-action` (read-only) → "hibernated" / "inconsistent" / "unclean" / "". Only for a drive this
        watcher announced and still sees, once per plug. udisks itself only reports "Unknown error when mounting"."""
        with self.lock:
            info = self.present.get(devnode)
            if info is None:
                return None
            if devnode in self.diagnosed:
                return self.diagnosed[devnode]
        problem = ""
        ntfsfix = shutil.which("ntfsfix")
        if info.get("fstype") == "ntfs" and ntfsfix and not self.mounted.get(devnode):
            r = run_quiet([ntfsfix, "--no-action", devnode], timeout=60)
            problem = ntfs_mount_problem((r.stdout or "") + "\n" + (r.stderr or ""))
            log(f"USB : diagnostic NTFS {devnode} → {problem or 'rien de connu'}")
        with self.lock:
            if devnode in self.present:
                self.diagnosed[devnode] = problem
        return problem

    def take_pending(self, devnode):
        with self.lock:
            return self.pending.pop(devnode, None)

    def pending_list(self):
        with self.lock:
            return list(self.pending.values())


# ═══════════════════════════════════════════════════════════════════════════
# System status: security updates and CVEs (apt)
# ═══════════════════════════════════════════════════════════════════════════

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}")
CHANGELOG_HEADER_RE = re.compile(r"^(\S+) \(([^)]+)\) ([^;]+); urgency=", re.M)


def parse_changelog_cves(text, installed_version, compare):
    """CVEs mentioned in changelog entries newer than the installed version.
    Returns {cve: title}."""
    cves = {}
    entries = list(CHANGELOG_HEADER_RE.finditer(text))
    for i, m in enumerate(entries):
        version = m.group(2)
        if installed_version and compare(version, installed_version) <= 0:
            break
        body = text[m.end(): entries[i + 1].start() if i + 1 < len(entries) else len(text)]
        title = ""
        in_title = False
        for line in body.splitlines():
            stripped = line.strip()
            if stripped.startswith("* "):
                title = stripped[2:].strip()
                if title.upper().startswith("SECURITY UPDATE:"):
                    title = title.split(":", 1)[1].strip()
                in_title = True
            elif in_title and stripped and not stripped.startswith("- "):
                title = f"{title} {stripped}"          # title continues on the next line
            else:
                in_title = False
            for cve in CVE_RE.findall(stripped):
                if cve not in cves or not cves[cve]:
                    cves[cve] = title.rstrip(" .:")
    return cves


def collect_system_status(previous=None):
    """System status report: packages to update, security, CVEs, reboot."""
    status = {
        "checked_at": now_iso(), "ok": True, "error": "",
        "os": "", "kernel": "", "reboot_required": False, "reboot_pkgs": [],
        "lists_updated": None, "upgradable": 0, "security": 0,
        "packages": [], "cves": [], "cve_count": 0, "changelog_errors": 0,
    }
    try:
        with open("/etc/os-release") as f:
            for line in f:
                if line.startswith("PRETTY_NAME="):
                    status["os"] = line.split("=", 1)[1].strip().strip('"')
    except OSError:
        pass
    status["kernel"] = os.uname().release
    status["reboot_required"] = os.path.exists("/var/run/reboot-required")
    try:
        with open("/var/run/reboot-required.pkgs") as f:
            status["reboot_pkgs"] = sorted({line.strip() for line in f if line.strip()})
    except OSError:
        pass
    try:
        newest = max(os.stat(os.path.join("/var/lib/apt/lists", n)).st_mtime
                     for n in os.listdir("/var/lib/apt/lists") if n.endswith("Release"))
        status["lists_updated"] = datetime.fromtimestamp(newest).isoformat(timespec="seconds")
    except (OSError, ValueError):
        pass

    if distro.is_rpm():
        status["reboot_required"] = False
        return distro.pending_updates(status)          # dnf check-update + updateinfo (security advisories and CVEs)
    try:
        import apt
        import apt_pkg
        cache = apt.Cache()
        compare = apt_pkg.version_compare
    except Exception as e:  # noqa: BLE001
        status["ok"] = False
        status["error"] = f"python3-apt: {e}"
        return status
    try:
        cache.upgrade(dist_upgrade=False)   # in-memory simulation (nothing is installed): what "apt upgrade" would really install
        sim_ok = True
    except Exception:  # noqa: BLE001
        sim_ok = False

    packages = []
    for pkg in cache:
        try:
            if not pkg.installed:
                continue
            if pkg.is_upgradable:
                cand = pkg.candidate
                origins = cand.origins if cand else []
                security = any((o.archive or "").endswith("-security") or (o.label or "") == "Debian-Security"
                               for o in origins)
                phase = cand.record.get("Phased-Update-Percentage") if cand else None
                # "apt upgrade" would not install it: deferred (phasing) or held (dependencies, "kept back")
                held = sim_ok and not pkg.marked_upgrade
                category = "security" if security else "recommended"
                if held:
                    category = "phased" if phase is not None else "held"
                packages.append({
                    "name": pkg.name, "installed": pkg.installed.version if pkg.installed else "",
                    "candidate": cand.version if cand else "", "security": security,
                    "category": category, "phase": phase if category == "phased" else None,
                    "archive": origins[0].archive if origins else "", "cves": {},
                })
                continue
            # "Phased" update: a newer version exists but apt holds it back
            for ver in pkg.versions:
                if ver > pkg.installed and ver != pkg.candidate and ver.record.get("Phased-Update-Percentage") is not None:
                    origins = ver.origins
                    packages.append({
                        "name": pkg.name, "installed": pkg.installed.version, "candidate": ver.version,
                        "security": any((o.archive or "").endswith("-security") for o in origins),
                        "category": "phased", "phase": ver.record.get("Phased-Update-Percentage"),
                        "archive": origins[0].archive if origins else "", "cves": {},
                    })
                    break
        except Exception:  # noqa: BLE001
            continue
    status["upgradable"] = sum(1 for p in packages if p["category"] in ("security", "recommended"))   # installables maintenant
    status["security"] = sum(1 for p in packages if p["security"] and p["category"] != "phased")       # including held ones (to watch)
    status["recommended"] = sum(1 for p in packages if p["category"] == "recommended")
    status["phased"] = sum(1 for p in packages if p["category"] == "phased")
    status["held"] = sum(1 for p in packages if p["category"] == "held")

    # CVE: changelog of security packages (and the kernel), limited to stay reasonable
    prev_pkgs = {p["name"]: p for p in ((previous or {}).get("packages") or [])}
    targets = [p for p in packages if p["security"] or p["name"].startswith("linux-image")][:40]
    env = dict(os.environ, APT_PAGER="cat", LC_ALL="C")
    for p in targets:
        prev = prev_pkgs.get(p["name"])
        if prev and prev.get("candidate") == p["candidate"] and prev.get("cves"):
            p["cves"] = prev["cves"]
            continue
        try:
            r = subprocess.run(["apt-get", "changelog", "-qq", p["name"]], capture_output=True,
                               text=True, timeout=40, env=env)
            if r.returncode == 0 and r.stdout:
                p["cves"] = parse_changelog_cves(r.stdout, p["installed"], compare)
            else:
                status["changelog_errors"] += 1
        except Exception:  # noqa: BLE001
            status["changelog_errors"] += 1
    cves = []
    for p in packages:
        for cve, title in sorted(p["cves"].items(), reverse=True):
            cves.append({"id": cve, "package": p["name"], "candidate": p["candidate"],
                         "installed": p["installed"], "title": title,
                         "url": f"https://ubuntu.com/security/{cve}"})
    status["packages"] = sorted(packages, key=lambda p: ({"security": 0, "recommended": 1, "phased": 2, "held": 3}.get(p["category"], 4), p["name"]))
    status["cves"] = cves
    status["cve_count"] = len(cves)
    return status


# ═══════════════════════════════════════════════════════════════════════════
# Application updates (signed manifest) and file integrity
# ═══════════════════════════════════════════════════════════════════════════

class UpdateChecker:
    def __init__(self, daemon):
        self.daemon_ref = daemon
        self.lock = threading.Lock()

    def check(self, force=False):
        """Downloads manifest.json + .sig, checks the signature, prepares the .deb if newer."""
        with self.lock:
            os.makedirs(UPDATES_DIR, exist_ok=True)
            info = {"checked_at": now_iso(), "current": VERSION, "available": False, "verified": False,
                    "downloaded": False, "version": "", "path": "", "sha256": "", "url": "", "error": "",
                    "date": "", "size": 0}
            if not self.daemon_ref.settings.get("app_update_check") and not force:
                info["error"] = "disabled"
                return info
            manifest_path = os.path.join(UPDATES_DIR, "manifest.json")
            sig_path = manifest_path + ".sig"
            try:
                with open(manifest_path, "wb") as f:
                    f.write(http_get(MANIFEST_URL, timeout=30))
                with open(sig_path, "wb") as f:
                    f.write(http_get(MANIFEST_URL + ".sig", timeout=30))
            except Exception as e:  # noqa: BLE001
                info["error"] = f"download:{e}"
                return info
            ok, detail = gpg_verify(sig_path, manifest_path)
            if not ok:
                info["error"] = f"signature:{detail}"
                self.daemon_ref.write_log(f"⚠ update manifest signature INVALID: {detail}")
                return info
            info["verified"] = True
            try:
                with open(manifest_path) as f:
                    manifest = json.load(f)
            except Exception as e:  # noqa: BLE001
                info["error"] = f"manifest:{e}"
                return info
            info.update({k: manifest.get(k, "") for k in ("version", "url", "sha256", "date")})
            info["size"] = int(manifest.get("size") or 0)
            if distro.is_rpm():
                rpm = manifest.get("rpm") or {}
                if not rpm.get("url"):
                    info["error"] = "manifest:no_rpm"
                    return info
                info.update({"url": rpm.get("url", ""), "sha256": rpm.get("sha256", ""), "size": int(rpm.get("size") or 0)})
            if manifest.get("package") != "dukiwi-shield" or not info["version"]:
                info["error"] = "manifest:invalid"
                return info
            # Replay protection: never a manifest older than the newest one already seen (an old signed manifest
            # served again would hide a security update)
            seen = str(self.daemon_ref.state.get("manifest_seen_date") or "")
            date = str(manifest.get("date") or "")
            if seen and date < seen:
                info["error"] = "manifest:older"
                self.daemon_ref.write_log(f"⚠ update manifest older than the last one seen ({date} < {seen}): refused")
                return info
            if date > seen:
                self.daemon_ref.state.update(manifest_seen_date=date)
            if not version_gt(info["version"], VERSION):
                return info
            info["available"] = True
            info["changes"] = manifest_changes(manifest, VERSION)
            pkg_name = (manifest.get("rpm") or {}).get("file") if distro.is_rpm() else manifest.get("deb")
            deb_path = os.path.join(UPDATES_DIR, os.path.basename(pkg_name or (f"dukiwi-shield-{info['version']}-1.noarch.rpm" if distro.is_rpm() else f"dukiwi-shield_{info['version']}_all.deb")))
            if not (os.path.exists(deb_path) and sha256_file(deb_path) == info["sha256"]):
                try:
                    with open(deb_path + ".part", "wb") as f:
                        f.write(http_get(info["url"], timeout=300))
                    if sha256_file(deb_path + ".part") != info["sha256"]:
                        os.remove(deb_path + ".part")
                        info["error"] = "sha256_mismatch"
                        self.daemon_ref.write_log("⚠ update .deb sha256 MISMATCH — refusé")
                        return info
                    os.replace(deb_path + ".part", deb_path)
                except Exception as e:  # noqa: BLE001
                    info["error"] = f"download_deb:{e}"
                    return info
            info["downloaded"] = True
            info["path"] = deb_path
            return info

    def install(self, info):
        """Installs the verified .deb in a transient unit (survives a restart of the daemon)."""
        path = info.get("path", "")
        if not (info.get("available") and info.get("verified") and path and os.path.exists(path)):
            return False, "not_ready"
        if sha256_file(path) != info.get("sha256"):
            return False, "sha256_mismatch"
        # The stored offer may be older than a version installed since through apt: never go back
        if not version_gt(str(info.get("version") or ""), VERSION):
            return False, "not_newer"
        if not re.fullmatch(r"/[0-9A-Za-z._+~/-]+\.(deb|rpm)", path):
            return False, "bad_path"
        if TEST_MODE:
            return True, "test_mode"
        unit = f"dukiwi-shield-upgrade-{int(time.time())}"
        # Argument list, no shell: the file name never reaches a command line parser
        cmd = ["dnf", "-y", "install", path] if distro.is_rpm() else ["apt-get", "install", "-y", path]
        r = run_quiet(["systemd-run", "--unit", unit, "--collect", "--quiet",
                       "-p", "Environment=DEBIAN_FRONTEND=noninteractive"] + cmd, timeout=30)
        return r.returncode == 0, ((r.stderr or "") + (r.stdout or "")).strip()[-200:]


def app_integrity():
    """Compares the installed files with the integrity manifest shipped in the package."""
    result = {"checked_at": now_iso(), "available": os.path.exists(INTEGRITY_FILE), "signed": False,
              "verified": False, "modified": [], "missing": [], "count": 0, "version": ""}
    if not result["available"]:
        return result
    sig = INTEGRITY_FILE + ".sig"
    if os.path.exists(sig):
        result["signed"] = True
        result["verified"], _ = gpg_verify(sig, INTEGRITY_FILE)
    try:
        with open(INTEGRITY_FILE) as f:
            manifest = json.load(f)
    except Exception:  # noqa: BLE001
        result["available"] = False
        return result
    result["version"] = manifest.get("version", "")
    files = manifest.get("files") or {}
    result["count"] = len(files)
    for rel, digest in files.items():
        full = "/" + rel
        if not os.path.exists(full):
            result["missing"].append(full)
        elif sha256_file(full) != digest:
            result["modified"].append(full)
    return result


# ═══════════════════════════════════════════════════════════════════════════
# Inventory of open vulnerabilities (OSV.dev, Ubuntu ecosystem) + Flatpak/Snap
# ═══════════════════════════════════════════════════════════════════════════

PRIORITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "negligible": 4, "untriaged": 5, "": 6}


def installed_sources():
    """{source_package: {"version": source_version, "binaries": [...]}} of the installed packages."""
    r = run_quiet(["dpkg-query", "-W", "-f", "${Package}\t${source:Package}\t${source:Version}\t${Version}\t${db:Status-Status}\n"], timeout=60)
    sources = {}
    for line in (r.stdout or "").splitlines():
        parts = line.split("\t")
        if len(parts) < 5 or parts[4] != "installed":
            continue
        binary, source, sversion, version = parts[0], parts[1] or parts[0], parts[2] or parts[3], parts[3]
        entry = sources.setdefault(source, {"version": sversion, "binaries": []})
        entry["binaries"].append(binary)
        # Several versions of the same source can coexist (kernels linux-image-6.8.0-101/-139…):
        # the version that counts is the newest, otherwise already fixed vulnerabilities show up.
        if sversion != entry["version"] and version_gt(sversion, entry["version"]):
            entry["version"] = sversion
    return sources


KERNEL_SOURCE_RE = re.compile(r"^linux(-signed)?(-(hwe|oem|lowlatency|generic|aws|azure|gcp|gke|gkeop|ibm|kvm|raspi|nvidia|riscv|realtime|intel|xilinx|oracle|bluefield|laptop|fde)(-[\d.]+)?)*$")


def running_kernel_source(sources):
    """Source package of the running kernel (uname -r), e.g. linux (6.8 GA) or linux-hwe-7.0."""
    release = os.uname().release
    r = run_quiet(["dpkg-query", "-W", "-f", "${source:Package}", f"linux-image-{release}"], timeout=15)
    src = (r.stdout or "").strip()
    if not src:
        r = run_quiet(["dpkg-query", "-W", "-f", "${source:Package}", f"linux-image-unsigned-{release}"], timeout=15)
        src = (r.stdout or "").strip()
    if not src:
        for name, info in sources.items():
            if f"linux-image-{release}" in info.get("binaries", []) or f"linux-image-unsigned-{release}" in info.get("binaries", []):
                src = name
                break
    return src.replace("linux-signed", "linux") if src else "", release


def hwe_version_key(name):
    """linux-hwe-6.14 → (6, 14): numeric sort of HWE kernels (6.8 before 6.11, 7.0 after)."""
    m = re.search(r"(\d+)\.(\d+)$", name)
    return (int(m.group(1)), int(m.group(2))) if m else (0, 0)


def osv_query(sources, ecosystem, skip=()):
    """Queries OSV in batches, with pagination (a kernel exceeds the 1000 records of a page); {source: [ids]}."""
    names = sorted(n for n in sources if n not in skip)
    found = {}
    for i in range(0, len(names), 1000):
        chunk = names[i:i + 1000]
        pending = [(n, {"package": {"name": n, "ecosystem": ecosystem}, "version": sources[n]["version"]}) for n in chunk]
        for _page in range(8):
            payload = {"queries": [q for _, q in pending]}
            data = http_get(OSV_BATCH_URL, timeout=120, data=json.dumps(payload).encode(),
                            headers={"Content-Type": "application/json"})
            results = json.loads(data).get("results", [])
            nxt = []
            for (name, q), res in zip(pending, results):
                ids = [v["id"] for v in (res or {}).get("vulns", []) if v.get("id")]
                if ids:
                    found.setdefault(name, []).extend(ids)
                token = (res or {}).get("next_page_token")
                if token:
                    nxt.append((name, dict(q, page_token=token)))
            pending = nxt
            if not pending:
                break
    return {n: sorted(set(ids)) for n, ids in found.items()}


def osv_details(ids, cache, ecosystem, max_workers=8):
    """OSV details (cached by id). Returns {id: simplified_detail}."""
    def fetch(vid):
        try:
            d = json.loads(http_get(OSV_VULN_URL + vid, timeout=30))
        except Exception:  # noqa: BLE001
            return vid, None
        priority, cvss = "", ""
        for sev in d.get("severity") or []:
            if sev.get("type") == "Ubuntu":
                priority = str(sev.get("score", "")).lower()
            elif sev.get("type", "").startswith("CVSS") and not cvss:
                cvss = sev.get("score", "")
        # An Ubuntu OSV record covers several source packages (linux, linux-aws, linux-hwe-6.11…):
        # the fixed version and availability (Ubuntu Pro) are read PER PACKAGE, never globally.
        fixed_by_pkg, pro_by_pkg = {}, {}
        for aff in d.get("affected") or []:
            pkg = aff.get("package", {})
            if pkg.get("ecosystem") != ecosystem:
                continue
            name = pkg.get("name", "")
            fixed_by_pkg.setdefault(name, "")
            for rng in aff.get("ranges") or []:
                for ev in rng.get("events") or []:
                    if ev.get("fixed"):
                        fixed_by_pkg[name] = ev["fixed"]
            if "Ubuntu Pro" in (aff.get("ecosystem_specific") or {}).get("availability", ""):
                pro_by_pkg[name] = True
        summary = d.get("summary") or (d.get("details") or "").strip().split("\n")[0]
        cve = ""
        for alias in [d.get("id", "")] + list(d.get("aliases") or []) + list(d.get("upstream") or []):
            if alias.startswith("CVE-"):
                cve = alias
                break
        if not cve and d.get("id", "").startswith("UBUNTU-CVE-"):
            cve = d["id"][7:]
        return vid, {"id": d.get("id", vid), "cve": cve, "modified": d.get("modified", ""),
                     "published": d.get("published", ""), "priority": priority, "cvss": cvss,
                     "fixed_by_pkg": fixed_by_pkg, "pro_by_pkg": pro_by_pkg, "summary": summary[:240]}

    usable = lambda vid: vid in cache and "fixed_by_pkg" in cache[vid]      # old caches (< 1.8.4): re-downloaded
    todo = [vid for vid in ids if not usable(vid)]
    out = {vid: cache[vid] for vid in ids if usable(vid)}
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        for vid, detail in pool.map(fetch, todo[:3000]):
            if detail:
                out[vid] = detail
    return out


EMBEDDED_ENGINE_RE = re.compile(r"^mozjs\d*$")          # SpiderMonkey extrait de Firefox ESR (cjs, gjs, polkit)
ENGINE_TERMS = re.compile(r"\b(SpiderMonkey|JavaScript engine|JS engine|JIT|garbage collect\w*|WebAssembly|wasm|"
                          r"typed array|ArrayBuffer|regular expression|regex|JSON|BigInt|Intl)\b", re.I)


def embedded_engine_users(binaries):
    """Installed packages that depend on the engine (apt-cache rdepends), for the explanation to the user."""
    def rdepends(pkg):
        r = run_quiet(["apt-cache", "rdepends", "--installed", pkg], timeout=30)
        return {ln.strip().lstrip("|").strip() for ln in (r.stdout or "").splitlines()[2:]
                if ln.strip() and ":" not in ln and not ln.strip().lstrip("|").strip().startswith("libmozjs")}
    direct = set()
    for b in binaries:
        if b.startswith("libmozjs"):
            direct |= rdepends(b)
    users = {u for u in direct if not u.startswith("lib")}
    for lib in [u for u in direct if u.startswith("lib")]:      # libcjs0 → cjs, cinnamon… (one more level)
        users |= {u for u in rdepends(lib) if not u.startswith("lib")}
    return sorted(users or direct)[:12]


# Famous vulnerabilities with no possible fix (design flaw): built-in explanation, actual usage checked
CVE_KNOWLEDGE = {"CVE-2024-3661": "tunnelvision"}


def vpn_connections():
    """VPN connections configured in NetworkManager (names), to tell whether TunnelVision affects this computer."""
    r = run_quiet(["nmcli", "-t", "-f", "NAME,TYPE", "connection", "show"], timeout=15)
    out = []
    for ln in (r.stdout or "").splitlines():
        parts = re.split(r"(?<!\\):", ln.strip())
        if len(parts) >= 2 and parts[1] in ("vpn", "wireguard", "tun", "ip-tunnel"):
            out.append(parts[0].replace("\\:", ":"))
    return out[:10]


def annotate_vulns(vulns):
    """Built-in notes per CVE (translation key) and machine context (configured VPNs)."""
    for it in vulns.get("items") or []:
        note = CVE_KNOWLEDGE.get(it.get("cve") or "")
        if note:
            it["note"] = note
    vulns["context"] = {"vpn_connections": vpn_connections()}
    return vulns


VULN_ACK_STATUSES = ("unfixed", "pro_only")
VULN_ACK_MAX = 20000


def apply_vuln_acks(vulns, acks):
    """"Ignore": CVEs approved by the user no longer count (tray, score, simple view) but remain
    listed in a collapsed section. Recomputes the counters and the breakdown by priority from the items."""
    out = dict(vulns or {})
    acks = acks or {}
    items = []
    counts = dict(out.get("counts") or {})
    for k in ("unfixed", "pro_only", "fix_available", "acknowledged"):
        counts[k] = 0
    by_priority = {}
    acked_cves = set()
    for it in out.get("items") or []:
        it = dict(it)
        acked = it.get("status") in VULN_ACK_STATUSES and (it.get("cve") or it.get("id")) in acks
        it["acknowledged"] = acked
        if acked:
            it["acknowledged_at"] = (acks.get(it.get("cve") or it.get("id")) or {}).get("at")
            acked_cves.add(it.get("cve") or it.get("id"))
        else:
            it.pop("acknowledged_at", None)
        items.append(it)
        if it.get("dormant"):
            continue
        if acked:
            counts["acknowledged"] += 1
            continue
        st = it.get("status")
        if st in ("unfixed", "pro_only", "fix_available"):
            counts[st] += 1
        if st not in ("kernel_pending", "not_applicable"):
            pr = it.get("priority") or "untriaged"
            by_priority[pr] = by_priority.get(pr, 0) + 1
    counts["acknowledged_cves"] = len(acked_cves)
    out.update(items=items, counts=counts, by_priority=by_priority)
    return out


def reclassify_vulns(vulns):
    """Report saved by a previous version: applies the "not applicable" classification (embedded engine)
    without network, at startup, so that the display is right immediately."""
    out = dict(vulns or {})
    counts = dict(out.get("counts") or {})
    counts.setdefault("not_applicable", 0)
    embedded = dict(out.get("embedded") or {})
    vendor = dict(out.get("vendor") or {})
    headers = dict(out.get("headers") or {})
    by_priority, items = {}, []
    r = run_quiet(["dpkg-query", "-W", "-f", "${Package}\n", "libmozjs*"], timeout=30)
    mozjs_bins = [ln.strip() for ln in (r.stdout or "").splitlines() if ln.strip()]
    r = run_quiet(["dpkg-query", "-W", "-f", "${source:Package}\n", "linux-image-*", "linux-modules-*"], timeout=30)
    image_sources = {ln.strip().replace("linux-signed", "linux") for ln in (r.stdout or "").splitlines() if ln.strip()}
    running = (out.get("running_kernel") or {}).get("source") or ""
    for it in out.get("items") or []:
        it = dict(it)
        if it.get("status") == "unfixed" and EMBEDDED_ENGINE_RE.match(it.get("package") or "") \
                and not ENGINE_TERMS.search(it.get("summary") or ""):
            it["status"] = "not_applicable"
            counts["unfixed"] = max(0, int(counts.get("unfixed") or 0) - 1)
            counts["not_applicable"] += 1
            if it["package"] not in embedded:
                embedded[it["package"]] = {"users": embedded_engine_users(mozjs_bins)}
        elif it.get("status") == "unfixed" and "linuxmint" in (it.get("installed") or ""):
            it["status"] = "not_applicable"
            counts["unfixed"] = max(0, int(counts.get("unfixed") or 0) - 1)
            counts["not_applicable"] += 1
            vendor[it["package"]] = it.get("installed") or ""
        elif it.get("status") in ("unfixed", "pro_only") and KERNEL_SOURCE_RE.match(it.get("package") or "") \
                and it["package"] not in image_sources and it["package"].replace("linux-signed", "linux") not in image_sources:
            counts[it["status"]] = max(0, int(counts.get(it["status"]) or 0) - 1)
            it["status"] = "not_applicable"     # headers / tools only: this kernel is not installed
            counts["not_applicable"] += 1
            headers[it["package"]] = it.get("installed") or ""
        if it.get("hwe_fixed") and (it.get("package") != "linux" or running != "linux" or it.get("status") not in ("unfixed", "kernel_pending")):
            it["hwe_fixed"] = ""                # HWE advice only when the original kernel is actually running
        if it.get("status") not in ("kernel_pending", "not_applicable") and not it.get("dormant"):
            pr = it.get("priority") or "untriaged"
            by_priority[pr] = by_priority.get(pr, 0) + 1
        items.append(it)
    counts["na_embedded"] = sum(1 for it in items if it.get("status") == "not_applicable" and it.get("package") in embedded)
    counts["na_vendor"] = sum(1 for it in items if it.get("status") == "not_applicable" and it.get("package") in vendor)
    counts["na_headers"] = sum(1 for it in items if it.get("status") == "not_applicable" and it.get("package") in headers)
    counts["kernel_hwe_fixed"] = sum(1 for it in items if it.get("hwe_fixed"))
    out.update(items=items, counts=counts, by_priority=by_priority, embedded=embedded, vendor=vendor, headers=headers)
    return annotate_vulns(out)


def collect_vulnerabilities(previous=None):
    """Known vulnerabilities affecting installed packages: no fix, Pro fix, or fix available."""
    ecosystem = ubuntu_osv_ecosystem()
    result = {"checked_at": now_iso(), "ok": True, "error": "", "ecosystem": ecosystem,
              "sources": 0, "items": [], "counts": {"unfixed": 0, "pro_only": 0, "fix_available": 0, "kernel_pending": 0, "not_applicable": 0, "na_embedded": 0, "na_vendor": 0,
                         "na_headers": 0, "kernel_hwe_fixed": 0, "dormant": 0},
              "embedded": {}, "vendor": {}, "headers": {},
              "running_kernel": {}, "dormant_kernels": [],
              "by_priority": {}, "flatpak": [], "snap": [], "cache": {}}
    if distro.is_rpm() or not ecosystem:
        # OSV does not cover Fedora (CVE advisories come from dnf updateinfo, System status); without a known
        # Ubuntu version (LMDE, Debian…), no inventory rather than an inventory made for another version.
        result.update(ecosystem="unsupported", unsupported=True)
        return result
    try:
        sources = installed_sources()
        result["sources"] = len(sources)
        # Kernels installed but not booted (e.g. linux 6.8 GA while linux-hwe-7.0 is running): their
        # vulnerabilities do not affect the running system; they are neither queried, counted nor displayed.
        running_src, release = running_kernel_source(sources)
        def kernel_family(name):              # linux-signed-hwe-7.0 and linux-hwe-7.0: same kernel
            return "linux" + name[len("linux-signed"):] if name.startswith("linux-signed") else name
        kernel_sources = {n for n, info in sources.items() if n.startswith("linux")
                          and any(re.match(r"linux-(image|modules)(-unsigned)?-\d", b) for b in info.get("binaries", []))}
        dormant = {n for n in kernel_sources if running_src and kernel_family(n) != kernel_family(running_src)}
        # Kernel source present only through its headers or tools (linux-libc-dev, linux-headers, linux-tools): no
        # image of this kernel is installed (Mint shipped with HWE 6.14: "linux" 6.8 only exists through
        # linux-libc-dev). Its vulnerabilities target a kernel that does not run here → not applicable, and above
        # all no "install the HWE kernel" advice.
        headers_only = {n for n in sources if KERNEL_SOURCE_RE.match(n) and n not in kernel_sources}
        ubuntu_rel = distro.ubuntu_release()
        result["running_kernel"] = {"release": release, "source": running_src,
                                    "version": (sources.get(running_src) or {}).get("version", ""),
                                    "ubuntu": ubuntu_rel, "hwe_package": f"linux-generic-hwe-{ubuntu_rel}", "hwe_sources": []}
        result["dormant_kernels"] = sorted(dormant)
        hwe_sources = set()
        found = osv_query(sources, ecosystem, skip=dormant)
        ids = sorted({vid for lst in found.values() for vid in lst})
        # Cached details (fixed versions, Ubuntu Pro) are specific to one ecosystem: data from another Ubuntu
        # version (upgrade, or 24.04 assumed by default before 1.24.3) → re-download everything.
        cache = ((previous or {}).get("cache") or {}) if (previous or {}).get("ecosystem") == ecosystem else {}
        details = osv_details(ids, cache, ecosystem)
        result["cache"] = details
        for source, vids in found.items():
            installed = sources[source]["version"]
            for vid in vids:
                d = details.get(vid)
                if not d:
                    continue
                fixed = (d.get("fixed_by_pkg") or {}).get(source, "")
                if fixed and not version_gt(fixed, installed):
                    continue                    # already fixed in the installed version: do not show it
                if (d.get("pro_by_pkg") or {}).get(source):
                    status = "pro_only"         # fix reserved for Ubuntu Pro (esm)
                elif fixed:
                    status = "fix_available"    # an update installs it
                else:
                    status = "unfixed"          # no fix published by Ubuntu for this package
                if status == "unfixed" and running_src and kernel_family(source) == kernel_family(running_src):
                    status = "kernel_pending"   # running kernel: fix expected from Ubuntu, delivered by updates
                elif status in ("unfixed", "pro_only") and source in headers_only:
                    status = "not_applicable"   # headers / tools only: this kernel is not installed
                    result["counts"]["na_headers"] += 1
                    result["headers"][source] = installed
                elif status == "unfixed" and EMBEDDED_ENGINE_RE.match(source) and not ENGINE_TERMS.search(d.get("summary") or ""):
                    # JavaScript engine extracted from Firefox: Ubuntu attaches all the browser's vulnerabilities to
                    # it ("needed") without ever fixing them; those describing the browser (web content, media,
                    # tabs…) do not apply to the engine alone. Vulnerabilities specific to the engine (JIT, wasm, GC)
                    # stay "unfixed".
                    status = "not_applicable"
                    result["counts"]["na_embedded"] += 1
                    if source not in result["embedded"]:
                        result["embedded"][source] = {"users": embedded_engine_users(sources[source].get("binaries", []))}
                elif status == "unfixed" and "linuxmint" in installed:
                    # Package built by Linux Mint (Firefox, Thunderbird…): Ubuntu's CVE tracking targets ITS version,
                    # not this one; Mint ships up-to-date Mozilla versions.
                    status = "not_applicable"
                    result["counts"]["na_vendor"] += 1
                    result["vendor"][source] = installed
                is_dormant = source in dormant
                if is_dormant:
                    result["counts"]["dormant"] += 1
                else:
                    result["counts"][status] += 1
                # Original kernel of the release (source "linux", e.g. 6.8 on 24.04): the vulnerability is often
                # already fixed in an HWE kernel of the same Ubuntu release (linux-hwe-6.14, linux-hwe-7.0…); a
                # release without HWE (26.04 on 7.0 today) has nothing of the kind, the OSV record only lists its own
                # packages.
                hwe = ""
                if status in ("unfixed", "kernel_pending") and source == "linux" and not is_dormant \
                        and kernel_family(running_src) == "linux":          # only if the original kernel is actually running
                    fixed_hwe = {k: v for k, v in (d.get("fixed_by_pkg") or {}).items() if k.startswith("linux-hwe-") and v}
                    if fixed_hwe:
                        k = min(fixed_hwe, key=hwe_version_key)
                        hwe = f"{k} {fixed_hwe[k]}"
                        hwe_sources.add(k)
                        result["counts"]["kernel_hwe_fixed"] += 1
                pr = d["priority"] or "untriaged"
                if status not in ("kernel_pending", "not_applicable"):
                    result["by_priority"][pr] = result["by_priority"].get(pr, 0) + 1
                result["items"].append({"id": d["id"], "cve": d["cve"] or d["id"], "package": source,
                                        "installed": installed, "fixed": fixed, "status": status, "hwe_fixed": hwe, "dormant": is_dormant,
                                        "priority": pr, "cvss": d["cvss"], "summary": d["summary"],
                                        "url": f"https://ubuntu.com/security/{d['cve']}" if d["cve"] else f"https://osv.dev/vulnerability/{d['id']}"})
        result["running_kernel"]["hwe_sources"] = sorted(hwe_sources, key=hwe_version_key)
        result["items"].sort(key=lambda it: (PRIORITY_RANK.get(it["priority"], 6), it["status"] != "unfixed", it["package"]))
        annotate_vulns(result)
    except Exception as e:  # noqa: BLE001
        result["ok"] = False
        result["error"] = str(e)[:200]
    # Flatpak / Snap: available updates
    if shutil.which("flatpak"):
        r = run_quiet(["flatpak", "remote-ls", "--updates", "--app", "--columns=application,version,name"], timeout=120)
        for line in (r.stdout or "").splitlines():
            parts = line.split("\t")
            if parts and parts[0].strip():
                result["flatpak"].append({"id": parts[0].strip(), "version": parts[1].strip() if len(parts) > 1 else "",
                                          "name": parts[2].strip() if len(parts) > 2 else parts[0].strip()})
    if shutil.which("snap"):
        r = run_quiet(["snap", "refresh", "--list"], timeout=120)
        for line in (r.stdout or "").splitlines()[1:]:
            parts = line.split()
            if parts:
                result["snap"].append({"id": parts[0], "version": parts[1] if len(parts) > 1 else "", "name": parts[0]})
    return result


# ═══════════════════════════════════════════════════════════════════════════
# Security checklist and score
# ═══════════════════════════════════════════════════════════════════════════

KNOWN_PORTS = {22: "ssh", 25: "smtp", 53: "dns", 67: "dhcp", 68: "dhcp", 80: "http", 110: "pop3", 111: "rpcbind", 139: "samba", 143: "imap", 443: "https", 465: "smtps", 587: "submission", 993: "imaps",
               445: "samba", 546: "dhcpv6", 631: "cups", 1716: "kdeconnect", 3306: "mysql", 3389: "rdp",
               5353: "mdns", 5432: "postgresql", 5900: "vnc", 5901: "vnc", 6000: "x11", 8000: "dev-server",
               8080: "http-alt", 8443: "https-alt", 9050: "tor", 27017: "mongodb", 32400: "plex"}


def sudoers_file_origin(path):
    """(package, modified) for a sudoers file: shipped by a dpkg package (mintupdate, mintdrivers, mintsystem…)
    and, as root, verified unchanged compared with the package (dpkg -V)."""
    if distro.is_rpm():
        return distro.owner_verify(path)
    r = run_quiet(["dpkg", "-S", path], timeout=15)
    if r.returncode != 0 or ":" not in (r.stdout or ""):
        return "", False
    pkg = (r.stdout or "").split(":", 1)[0].strip()
    modified = False
    if os.geteuid() == 0:
        v = run_quiet(["dpkg", "-V", pkg], timeout=120)
        for ln in (v.stdout or "").splitlines():
            parts = ln.split()
            if len(parts) >= 2 and parts[-1] == path and "5" in parts[0]:
                modified = True
    return pkg, modified


def ufw_port_allowed(rules, port, proto):
    """Does an ALLOW IN rule cover this port? ("22/tcp", "80,443/tcp", "8000:8100/udp", "22", "Anywhere")."""
    for r in rules:
        action = (r.get("action") or "").upper()
        if not action.startswith("ALLOW") or "OUT" in action:
            continue
        to = (r.get("to") or "").strip()
        spec = to.split()[-1] if to else ""          # "192.168.1.5 22/tcp" → "22/tcp"
        if spec.lower() in ("anywhere", "anywhere (v6)", ""):
            return True
        if "/" in spec:
            ports_part, rproto = spec.rsplit("/", 1)
            if rproto.lower() not in (proto.lower(), "any"):
                continue
        else:
            ports_part = spec
        for chunk in ports_part.split(","):
            chunk = chunk.strip()
            try:
                if ":" in chunk:
                    lo, hi = chunk.split(":", 1)
                    if int(lo) <= port <= int(hi):
                        return True
                elif int(chunk) == port:
                    return True
            except ValueError:
                continue
    return False


def port_key(p):
    """Key of a listening port for "Ignore": port, protocol and program (another program on the same port
    is reported again)."""
    return f"{p.get('port')}/{p.get('proto')}:{p.get('process') or p.get('service') or ''}"


def listening_ports():
    r = run_quiet(["ss", "-tulnpH"], timeout=15)
    ports = []
    for line in (r.stdout or "").splitlines():
        parts = line.split()
        if len(parts) < 5:
            continue
        proto, local = parts[0], parts[4]
        addr, _, port = local.rpartition(":")
        addr = addr.split("%")[0].strip("[]")
        try:
            port = int(port)
        except ValueError:
            continue
        proc, pid = "", 0
        m = re.search(r'users:\(\("([^"]+)",pid=(\d+)', line)
        if m:
            proc, pid = m.group(1), int(m.group(2))
        if addr in ("0.0.0.0", "::", "*", ""):
            exposed = True
        else:
            try:
                ip = ipaddress.ip_address(addr)
                exposed = not (ip.is_loopback or ip.is_link_local)
            except ValueError:
                exposed = False
        ports.append({"proto": proto, "addr": addr or "*", "port": port, "process": proc, "pid": pid,
                      "service": KNOWN_PORTS.get(port, ""), "exposed": bool(exposed)})
    ports.sort(key=lambda p: (not p["exposed"], p["port"]))
    return ports


def human_users():
    """Human accounts with a home folder (uid ≥ 1000 under /home, and root)."""
    out = []
    for pw in pwd.getpwall():
        if (pw.pw_uid >= 1000 or pw.pw_uid == 0) and pw.pw_dir.startswith(("/home/", "/root")) and os.path.isdir(pw.pw_dir):
            out.append(pw)
    return out


def autologin_users(root="/"):
    """Automatic login without a password: LightDM (autologin-user), GDM (AutomaticLoginEnable), SDDM ([Autologin] User).
    A stolen laptop then opens straight to the desktop."""
    users = []
    j = lambda p: os.path.join(root, p.lstrip("/"))
    for path in [j("etc/lightdm/lightdm.conf")] + sorted(glob.glob(j("etc/lightdm/lightdm.conf.d/*.conf"))) + sorted(glob.glob(j("usr/share/lightdm/lightdm.conf.d/*.conf"))):
        for ln in _read_text(path).splitlines():
            m = re.match(r"^\s*autologin-user\s*=\s*(\S+)", ln)
            if m:
                users.append(m.group(1))
    for path in (j("etc/gdm3/custom.conf"), j("etc/gdm/custom.conf"), j("etc/gdm3/daemon.conf")):
        txt = _read_text(path)
        if re.search(r"^\s*AutomaticLoginEnable\s*=\s*true", txt, re.I | re.M):
            m = re.search(r"^\s*AutomaticLogin\s*=\s*(\S+)", txt, re.M)
            users.append(m.group(1) if m else "gdm")
    for path in [j("etc/sddm.conf")] + sorted(glob.glob(j("etc/sddm.conf.d/*.conf"))):
        m = re.search(r"^\s*\[Autologin\]\s*$(.*?)(?=^\s*\[|\Z)", _read_text(path), re.M | re.S)
        if m:
            u = re.search(r"^\s*User\s*=\s*(\S+)", m.group(1), re.M)
            if u:
                users.append(u.group(1))
    return sorted(set(users))


def dconf_read(pw, key):
    """dconf value of a user (read directly from their database, without a session bus); "" = default value."""
    if not shutil.which("dconf"):
        return ""
    if os.geteuid() == 0 and pw.pw_uid != 0:
        cmd = ["runuser", "-u", pw.pw_name, "--", "env", f"HOME={pw.pw_dir}", f"XDG_CONFIG_HOME={pw.pw_dir}/.config", "dconf", "read", key]
    elif pw.pw_uid == os.geteuid():
        cmd = ["dconf", "read", key]
    else:
        return ""
    r = run_quiet(cmd, timeout=10)
    return (r.stdout or "").strip() if r.returncode == 0 else ""


def screen_lock_off_users(users):
    """Users whose screen does not lock by itself: Cinnamon / GNOME (dconf: lock-enabled false or idle-delay 0),
    KDE (kscreenlockerrc Autolock=false). Default value (key missing) = lock enabled."""
    off = []
    for pw in users:
        if not os.path.isdir(os.path.join(pw.pw_dir, ".config")):
            continue
        bad = False
        for key in ("/org/cinnamon/desktop/screensaver/lock-enabled", "/org/gnome/desktop/screensaver/lock-enabled"):
            if dconf_read(pw, key) == "false":
                bad = True
        for key in ("/org/cinnamon/desktop/session/idle-delay", "/org/gnome/desktop/session/idle-delay"):
            v = dconf_read(pw, key)
            if v and v.split()[-1] == "0":
                bad = True
        kde = os.path.join(pw.pw_dir, ".config", "kscreenlockerrc")
        if os.path.isfile(kde) and re.search(r"^\s*Autolock\s*=\s*false", _read_text(kde), re.I | re.M):
            bad = True
        if bad:
            off.append(pw.pw_name)
    return off


def thunderbolt_security(root="/"):
    """Thunderbolt / USB4 security level (domain*/security): "none" = any plugged-in device has direct memory
    access (DMA attack), unless the IOMMU protects it (iommu_dma_protection). None without a controller."""
    levels = []
    for p in sorted(glob.glob(os.path.join(root, "sys/bus/thunderbolt/devices/domain*/security"))):
        level = _read_text(p)
        if level == "none" and _read_text(os.path.join(os.path.dirname(p), "iommu_dma_protection")) == "1":
            level = "iommu"
        levels.append(level)
    if not levels:
        return None
    return "none" if "none" in levels else sorted(set(levels))[0]


SECRET_FILES = ((".netrc", "netrc"), (".aws/credentials", "aws"), (".git-credentials", "git"), (".docker/config.json", "docker"))


def secrets_exposure(users):
    """Plain-text secrets in home folders: private SSH keys without a passphrase, keys or ~/.ssh readable by
    other accounts, .netrc, plain-text AWS / git / Docker credentials. {user: [{name, kind}]}."""
    found = {}
    for pw in users:
        items = []
        sshd = os.path.join(pw.pw_dir, ".ssh")
        try:
            if os.path.isdir(sshd):
                if os.stat(sshd).st_mode & 0o077:
                    items.append({"name": ".ssh", "kind": "dir_open"})
                for f in sorted(os.listdir(sshd)):
                    p = os.path.join(sshd, f)
                    if not os.path.isfile(p) or f.endswith(".pub") or f in ("known_hosts", "known_hosts.old", "config", "authorized_keys", "environment", "rc"):
                        continue
                    with open(p, "rb") as fh:
                        head = fh.read(80)
                    if b"PRIVATE KEY" not in head:
                        continue
                    if os.stat(p).st_mode & 0o077:
                        items.append({"name": f, "kind": "readable"})
                    if shutil.which("ssh-keygen"):
                        r = run_quiet(["ssh-keygen", "-y", "-P", "", "-f", p], timeout=10)
                        if r.returncode == 0:
                            items.append({"name": f, "kind": "nopass"})
        except OSError:
            pass
        for rel, kind in SECRET_FILES:
            p = os.path.join(pw.pw_dir, rel)
            try:
                if os.path.isfile(p) and os.path.getsize(p) > 0 and (kind != "docker" or '"auth"' in _read_text(p)):
                    items.append({"name": rel, "kind": kind})
            except OSError:
                pass
        if items:
            found[pw.pw_name] = items
    return found


def login_failures(hours=24):
    """Authentication failures over the last hours according to the journal: PAM ("authentication failure": login,
    sudo, lock screen), SSH ("Failed password", "Invalid user")."""
    counts = {"sudo": 0, "ssh": 0, "login": 0}
    if not shutil.which("journalctl"):
        return counts
    r = run_quiet(["journalctl", "-q", "--no-pager", "--since", f"-{int(hours)}h", "-o", "cat"], timeout=90)
    for ln in (r.stdout or "").splitlines():
        if "Failed password" in ln or "Invalid user" in ln:
            counts["ssh"] += 1
        elif "authentication failure" in ln:
            counts["sudo" if "sudo" in ln else "login"] += 1
    return counts


def firmware_updates():
    """Available firmware updates (fwupd, LVFS repository): [{name, version, new}]; None if fwupd is missing or
unreachable."""
    if not shutil.which("fwupdmgr"):
        return None
    r = run_quiet(["fwupdmgr", "get-updates", "--json", "--no-unreported-check", "--no-metadata-check"], timeout=120)
    try:
        data = json.loads(r.stdout or "{}")
    except ValueError:
        data = {}
    devs = data.get("Devices")
    if devs is None and r.returncode not in (0, 2):
        return None
    out = []
    for d in devs or []:
        rel = (d.get("Releases") or [{}])[0]
        out.append({"name": d.get("Name") or d.get("DeviceId") or "?", "version": d.get("Version") or "", "new": rel.get("Version") or ""})
    return out


# Security log categories (lines of the service log, by keywords)
JOURNAL_RULES = [
    ("privacy", ("privacy:",)), ("network", ("⚠ certificate", "⚠ redirect")),
    ("integrity", ("⚠ extension", "⚠ ssh key", "⚠ suid", "ssh key", "suid", "malicious pypi", "malicious npm")),
    ("accounts", ("⚠ login:", "login: night")), ("behaviour", ("keyboard read by", "protected folders")),
    ("behaviour", ("⚠ info:", "⚠ danger:", "burst")), ("network", ("⚠ connection", "connection ")),
    ("firewall", ("firewall", "ufw", "firewalld", "port ", "profile ", "--force ")), ("approvals", ("admin unlock", "admin lock")),
    ("scan", ("■ interrupted", "■ clean", "■ infected", "▶ scan")), ("network", ("network", "gateway", "wi-fi", "wifi")),
    ("honeypot", ("honeypot",)), ("usb", ("usb", "keyboard")), ("scan", ("scan", "quarantin", "infected", "on-access", "clamd")),
    ("integrity", ("integrity", "lynis", "chkrootkit", "debsums", "watch", "rootkit", "persistence")), ("hardening", ("harden",)),
    ("updates", ("update", "upgrade", "freshclam", "firmware", "signature")), ("approvals", ("acknowledg", "trusted", "trust ", "ignored", "allowed", "sudoers")),
    ("settings", ("settings", "policy")), ("mail", ("mail",)), ("backup", ("timeshift", "backup")),
]
JOURNAL_NOISE = ("tray relaunched", "duplicate tray", "honeypot: listening", "honeypot: stopped", "legacy tray stopped")
ALERT_CATEGORY = {"burst": "behaviour", "connection": "network", "download": "scan", "integrity": "integrity", "persistence": "integrity",
                  "usb_keyboard": "usb", "network": "network", "account": "accounts", "honeypot": "honeypot", "mail": "mail",
                  "update": "updates", "upload": "network", "timeshift": "backup", "ransomware": "behaviour",
                  "miner": "behaviour", "privacy": "privacy", "certificate": "network", "redirect": "network",
                  "extension": "integrity", "ssh_key": "integrity", "suid": "integrity", "keylogger": "behaviour", "login": "accounts",
                  "dev_package": "integrity", "protected": "behaviour"}


def journal_category(text):
    low = text.lower()
    for cat, words in JOURNAL_RULES:
        if any(w in low for w in words):
            return cat
    return "system"


def security_journal(daemon, days=30):
    """Alerts (structured) and actions from the service log (firewall, approvals, hardening, scans,
    updates…) over the last `days` days, newest first."""
    cutoff = datetime.fromtimestamp(time.time() - days * 86400).isoformat(timespec="seconds")
    events = []
    for a in daemon.state.get("alerts") or []:
        t = str(a.get("time") or "")
        if t < cutoff:
            continue
        text = " — ".join(x for x in (str(a.get("comm") or a.get("title") or "").strip(), str(a.get("detail") or "").strip()) if x)
        events.append({"t": t, "src": "alert", "kind": a.get("kind") or "", "cat": ALERT_CATEGORY.get(a.get("kind"), "system"),
                       "sev": a.get("severity") if a.get("severity") in ("danger", "warn", "info") else "info", "text": text[:400]})
    lines = []
    for path in (SYSTEM_LOG_FILE + ".1", SYSTEM_LOG_FILE):
        try:
            with open(path, encoding="utf-8", errors="replace") as f:
                lines += f.readlines()[-20000:]
        except OSError:
            pass
    for ln in lines:
        m = re.match(r"^\[(\d{4}-\d\d-\d\dT[\d:]+)\] (.*)$", ln.rstrip("\n"))
        if not m or m.group(1) < cutoff:
            continue
        text = m.group(2).strip()
        if not text or text.startswith("WARNING:") or any(n in text for n in JOURNAL_NOISE):
            continue                                       # technical warnings from the scan engine: not events
        sev = "info" if text.startswith("⚠ info:") else ("danger" if text.startswith("⚠ danger") else ("warn" if text.startswith("⚠") else "info"))
        events.append({"t": m.group(1), "src": "log", "kind": "", "cat": journal_category(text), "sev": sev, "text": text.lstrip("⚠✔✘⏸ ").strip()[:400]})
    events.sort(key=lambda e: e["t"], reverse=True)
    return events[:5000]


def user_backup_states(states):
    """File backup states sent by the users' application, limited to accounts that still exist:
    {uid: {"state": ok | none | missing | old, "last", "at"}}."""
    out = {}
    for uid, b in (states or {}).items():
        try:
            pwd.getpwuid(int(uid))
        except (KeyError, ValueError):
            continue
        if isinstance(b, dict) and b.get("state") in ("ok", "none", "missing", "old"):
            out[str(uid)] = b
    return out


def collect_checklist(daemon):
    """List of weighted checks → score 0-100."""
    items = []
    settings = daemon.settings
    sec = daemon.security or {}
    ufw, ssh = sec.get("ufw", {}), sec.get("ssh", {})
    sysst = daemon.state.get("system_status") or {}
    vulns = daemon.state.get("vulns") or {}
    persistence = daemon.state.get("persistence") or {}

    def add(key, status, weight, detail="", params=None):
        items.append({"key": key, "status": status, "weight": weight, "detail": str(detail)[:200]})
        if params:
            items[-1]["params"] = params           # parameterized hint / fix texts ({kernel}, {pkg}…)

    add("firewall", "ok" if ufw.get("active") else ("fail" if ufw.get("installed") else "warn"), 15,
        f"{ufw.get('default_incoming', '')}/{ufw.get('default_outgoing', '')}" if ufw.get("active") else "")
    if ssh.get("installed") and ssh.get("active"):
        add("ssh", "ok" if (ufw.get("active") and ssh.get("allowed_by_firewall")) else "warn", 6, f"port {ssh.get('port')}")
    else:
        add("ssh", "ok", 6, "off")
    # Disk encryption: system disk (LUKS), or at least the home folders; with only the home folders encrypted, a swap area
    # written to disk in clear can still hold pieces of the session (opened documents, passwords in memory)
    enc = hygiene.encryption_status()
    if enc["root"]:
        add("disk_encryption", "ok", 8, params={"scope": "disk"})
    elif enc["home"] and enc["swap_clear"]:
        add("disk_encryption", "warn", 8, ", ".join(enc["swap_clear"]), params={"scope": "home", "swap": enc["swap_clear"]})
        items[-1]["detail_key"] = "check.disk_encryption.swap_clear"
        items[-1]["detail_params"] = {"swap": ", ".join(enc["swap_clear"])}
    else:
        add("disk_encryption", "ok" if enc["home"] else "warn", 8, params={"scope": "home" if enc["home"] else ""})
    # Secure Boot
    sb = "unknown"
    if shutil.which("mokutil"):
        r = run_quiet(["mokutil", "--sb-state"], timeout=10)
        out = (r.stdout or "").lower()
        sb = "ok" if "enabled" in out and "disabled" not in out else ("warn" if out else "unknown")
    elif not os.path.isdir("/sys/firmware/efi"):
        sb = "na"
    add("secure_boot", sb, 5)
    # Mandatory access control: AppArmor (Debian/Mint) or SELinux (Fedora)
    mac_name, mac_on = distro.mac()
    add(mac_name, "ok" if mac_on else "warn", 6)
    # Automatic updates
    auto = False
    try:
        with open("/etc/apt/apt.conf.d/20auto-upgrades") as f:
            auto = 'Unattended-Upgrade "1"' in f.read()
    except OSError:
        pass
    # Linux Mint: Update Manager automation (systemd timer + flag file)
    auto = auto or unit_enabled("mintupdate-automation-upgrade.timer") or os.path.exists(MINT_AUTO_UPGRADE_FLAG) or distro.auto_updates_enabled()
    add("auto_updates", "ok" if auto else "warn", 6)
    add("security_updates", "ok" if not sysst.get("security") else "fail", 12, sysst.get("security", 0))
    add("reboot", "ok" if not sysst.get("reboot_required") else "warn", 3)
    # Accounts without a password / passwordless sudo (root only)
    if os.geteuid() == 0:
        empty = []
        try:
            with open("/etc/shadow") as f:
                for line in f:
                    parts = line.split(":")
                    if len(parts) > 1 and parts[1] == "":
                        empty.append(parts[0])
        except OSError:
            pass
        add("empty_passwords", "fail" if empty else "ok", 10, ", ".join(empty))
        nopass, mint_ok, sudo_ignored, sudo_flagged = [], [], [], {}
        sudo_acks = daemon.state.get("acknowledged_sudoers") or {}
        for path in ["/etc/sudoers"] + sorted(str(p) for p in Path("/etc/sudoers.d").glob("*") if p.is_file()):
            try:
                with open(path, "rb") as f:
                    raw = f.read()
                has_rule = any(b"NOPASSWD" in line and not line.strip().startswith(b"#") for line in raw.splitlines())
            except OSError:
                continue
            if not has_rule:
                continue
            # File deployed by the system (dpkg package: mintupdate, mintdrivers…) and unchanged: normal.
            # File added by hand, or modified since the package: risk to report.
            pkg, modified = sudoers_file_origin(path) if path != "/etc/sudoers" else ("", False)
            if pkg and not modified:
                mint_ok.append(f"{os.path.basename(path)} ({pkg})")
                continue
            # "Ignore": intended rule (keyboard shortcut, home-made script…) approved by the user for THIS content;
            # any change to the file makes it reappear
            digest = hashlib.sha256(raw).hexdigest()
            if (sudo_acks.get(path) or {}).get("sha256") == digest:
                sudo_ignored.append(os.path.basename(path))
                continue
            sudo_flagged[path] = digest
            nopass.append(os.path.basename(path) + (" (modifié)" if modified else ""))
        nopass, mint_ok = sorted(set(nopass)), sorted(set(mint_ok))
        daemon.sudoers_flagged = sudo_flagged
        add("nopasswd_sudo", "warn" if nopass else "ok", 5, ", ".join(nopass))
        if not nopass and sudo_ignored:
            items[-1].update(detail_key="check.nopasswd_sudo.acknowledged", detail_params={"files": ", ".join(sorted(sudo_ignored))})
        elif not nopass and mint_ok:
            items[-1].update(detail_key="check.nopasswd_sudo.mint", detail_params={"files": ", ".join(mint_ok)})
    else:
        add("empty_passwords", "unknown", 10)
        add("nopasswd_sudo", "unknown", 5)
    # Exposed ports
    ports = listening_ports()
    filtering = bool(ufw.get("active")) and (ufw.get("default_incoming") or "").lower().startswith("deny")
    for p in ports:
        if not p["exposed"]:
            p["verdict"] = "local"
        elif filtering and not ufw_port_allowed(ufw.get("rules") or [], p["port"], p["proto"]):
            p["verdict"] = "filtered"           # listening, but blocked by the firewall: unreachable from the network
        else:
            p["verdict"] = "reachable"
    acks = daemon.state.get("acknowledged_ports") or {}
    hp_ports = set(daemon.honeypot.ports)
    for p in ports:
        if p["port"] in hp_ports and p["proto"] == "tcp" and (p["pid"] == os.getpid() or not p["pid"]):
            p["verdict"] = "honeypot"                   # honeypot decoy: intended, monitored
        p["key"] = port_key(p)
        p["acknowledged"] = p["verdict"] == "reachable" and p["key"] in acks     # "Ignore": intended port (web development…)
    exposed = [p for p in ports if p["verdict"] == "reachable" and not p["acknowledged"] and p["port"] not in (5353, 68, 546, 67)]
    acknowledged = [p for p in ports if p["acknowledged"]]
    filtered = [p for p in ports if p["verdict"] == "filtered"]
    add("open_ports", "ok" if not exposed else ("warn" if ufw.get("active") else "fail"), 8,
        ", ".join(f"{p['port']}/{p['proto']} {p['process'] or p['service']}".strip() for p in exposed[:8]))
    if not exposed and acknowledged:
        items[-1].update(detail_key="check.open_ports.acknowledged", detail_params={"n": len(acknowledged)})
    elif not exposed and filtered:
        items[-1].update(detail_key="check.open_ports.filtered", detail_params={"n": len(filtered)})
    # Common exposed services (reachable)
    exposed_services = sorted({p["service"] or p["process"] for p in exposed if p["port"] in (139, 445, 631, 5900, 5901, 3389, 3306, 5432, 27017)})
    add("exposed_services", "ok" if not exposed_services else "warn", 5, ", ".join(exposed_services))
    # ld.so.preload (persistance de rootkit)
    add("ld_preload", "fail" if os.path.exists("/etc/ld.so.preload") and os.path.getsize("/etc/ld.so.preload") > 0 else "ok", 8)
    # Antivirus
    db = db_last_update()
    age_days = (datetime.now() - db).days if db else 99
    add("signatures", "ok" if age_days < 1 else ("warn" if age_days < 2 else "fail"), 8, f"{age_days} d")
    add("realtime", "ok" if daemon.monitor.active else "warn", 6)
    add("weekly_scan", "ok" if settings.get("weekly_scan") else "warn", 3)
    last_scan = daemon.state.get("last_scan")
    try:
        scan_age = (datetime.now() - datetime.fromisoformat(last_scan)).days if last_scan else 99
    except ValueError:
        scan_age = 99
    add("recent_scan", "ok" if scan_age <= 7 else ("warn" if scan_age <= 30 else "fail"), 4, f"{scan_age} d")
    # Failles ouvertes
    counts = vulns.get("counts") or {}
    high = len({it.get("cve") or it.get("id") for it in vulns.get("items", [])
                if it.get("status") == "unfixed" and it.get("priority") in ("critical", "high")
                and not it.get("acknowledged")})   # distinct CVEs, excluding vulnerabilities ignored by the user
    add("open_vulns", "na" if vulns.get("unsupported") else ("unknown" if not vulns else ("ok" if not high else "warn")), 6,
        f"{counts.get('unfixed', 0)} unfixed, {high} high/critical")
    # Persistance inconnue
    unknown = [it for it in persistence.get("items", []) if not it.get("trusted")]
    add("persistence", "ok" if not unknown else "warn", 4, f"{len(unknown)}")
    # System hardening (Lynis index 0-100, recorded during the integrity check)
    lynis = (daemon.state.get("integrity") or {}).get("lynis") or {}
    idx = lynis.get("index")
    add("hardening", "unknown" if idx is None else ("ok" if idx >= 65 else ("warn" if idx >= 45 else "fail")), 5,
        f"{idx}/100" if idx is not None else "")
    # GA kernel: vulnerabilities already fixed in an HWE kernel (information only, the distribution handles
    # deployment)
    hwe_fixed = ((vulns or {}).get("counts") or {}).get("kernel_hwe_fixed") or 0
    rk = (vulns or {}).get("running_kernel") or {}
    ubuntu_rel = rk.get("ubuntu") or distro.ubuntu_release()
    add("kernel_hwe", "na" if (vulns or {}).get("unsupported") or distro.is_rpm() else ("unknown" if not vulns else ("warn" if hwe_fixed else "ok")), 3,
        f"{hwe_fixed}" if hwe_fixed else "",
        params={"kernel": rk.get("release") or os.uname().release, "release": ubuntu_rel,
                "hwe": ", ".join(rk.get("hwe_sources") or []) or "HWE", "pkg": rk.get("hwe_package") or f"linux-generic-hwe-{ubuntu_rel}"})
    # Automatic login without a password (LightDM, GDM, SDDM): a stolen laptop opens by itself
    auto_users = autologin_users()
    add("autologin", "warn" if auto_users else "ok", 6, ", ".join(auto_users))
    users = human_users()
    # Screen lock after inactivity (per user)
    unlocked = daemon.cached("screen_lock", 600, lambda: screen_lock_off_users(users))
    add("screen_lock", "warn" if unlocked else "ok", 4, ", ".join(unlocked))
    # Firmware (fwupd / LVFS): daily check, "Fix" runs fwupdmgr update
    fw = daemon.state.get("firmware") or {}
    add("firmware", "na" if not fw or fw.get("available") is None or fw.get("available") is False else ("warn" if fw.get("updates") else "ok"), 3,
        ", ".join(u.get("name", "?") for u in (fw.get("updates") or [])[:4]))
    # Thunderbolt / USB4: direct memory access by a plugged-in device
    tb = thunderbolt_security()
    add("thunderbolt", "na" if tb is None else ("warn" if tb == "none" else "ok"), 2, tb or "")
    # Plaintext secrets in home folders
    secrets = daemon.cached("secrets", 600, lambda: secrets_exposure(users))
    add("secrets", "warn" if secrets else "ok", 4, str(sum(len(v) for v in secrets.values())) if secrets else "",
        params={"secrets": [dict(s, user=u) for u, lst in secrets.items() for s in lst][:12]})
    # Authentication failures in the last 24 hours (login, sudo, SSH)
    fails = daemon.cached("login_failures", 600, login_failures)
    total = sum(fails.values())
    add("login_failures", "warn" if total >= 5 else "ok", 3, str(total) if total else "",
        params={"n": total, "sudo": fails.get("sudo", 0), "ssh": fails.get("ssh", 0), "login": fails.get("login", 0)})
    # New user account: reported (alert), list remembered
    names = sorted(pw.pw_name for pw in users if pw.pw_uid >= 1000)
    known = daemon.state.get("known_users")
    if known is None:
        daemon.state.update(known_users=names)
    elif names != list(known):
        for n in names:
            if n not in known:
                daemon.write_log(f"⚠ new user account: {n}")
                daemon.publish_alert({"kind": "account", "severity": "warn", "time": now_iso(), "title": n, "detail": "",
                                      "pid": 0, "comm": "", "exe": "", "count": 0, "top_dir": "", "reasons": ["new_account"], "sample": []})
        daemon.state.update(known_users=names)
    # Quality of new passwords (pam_pwquality)
    pol = daemon.cached("password_policy", 600, hygiene.password_policy)
    # Step 2 once the rules are set: passwords chosen before them were never checked → change them
    stale = hygiene.passwords_older_than_policy() if pol["ok"] else []
    add("password_policy", "ok" if pol["ok"] and not stale else "warn", 2,
        f"pam_{pol['module']} · minlen {pol['minlen']}" if pol["module"] else "pam_pwquality —",
        params={"minlen": hygiene.PWQ_MINLEN, "stale": stale})
    if stale:
        items[-1]["detail_key"] = "check.password_policy.change"
        items[-1]["detail_params"] = {"users": ", ".join(stale)}
    # Browser security settings
    browsers = daemon.cached("browser_security", 600, lambda: hygiene.browser_security(users))
    issues = [b for b in browsers if b["issues"]]
    add("browser_security", "na" if not browsers else ("warn" if issues else "ok"), 3,
        ", ".join(f"{b['browser']} ({b['user']}): " + "/".join(b["issues"]) for b in issues[:4]),
        params={"browsers": [{k: b[k] for k in ("browser", "user", "profile", "issues")} for b in issues[:10]]})
    # Internet exposure (test on demand) and UPnP (ports opened by the router to this computer)
    expo = daemon.state.get("exposure") or {}
    upnp = daemon.state.get("upnp") or {}
    mine = [m for m in (upnp.get("mappings") or []) if m.get("this_host") and m.get("enabled")]
    open_ports = expo.get("open") or [] if expo.get("ok") else []
    sensitive = [p_ for p_ in open_ports if p_ in (22, 23, 139, 445, 3389, 5900, 5901, 3306, 5432, 6379, 27017)]
    add("internet_exposure", "fail" if sensitive else ("warn" if open_ports or mine else ("ok" if expo.get("ok") else "unknown")), 4,
        ", ".join([f"{p_}/tcp" for p_ in open_ports[:8]] + [f"UPnP {m['external']}/{m['protocol']} → {m['internal']}" for m in mine[:4]]),
        params={"open": open_ports, "upnp": mine[:8], "tested_at": expo.get("at")})
    # Availability: system snapshots (Timeshift) and backup of personal files (reported by each user's application,
    # backup_state_report). "Ignore" on the reminder turns the shield green, but the score still takes it into
    # account: having no backup remains a risk, whether or not one wants to hear about it.
    ts = daemon.state.get("timeshift") or {}
    if not ts.get("checked_at"):
        snap = "unknown"
    elif not ts.get("installed") or not ts.get("configured"):
        snap = "fail"
    elif not ts.get("schedule"):
        snap = "warn"
    else:
        try:
            late = not ts.get("last") or (time.time() - datetime.fromisoformat(ts["last"]).timestamp()) > 30 * 86400
        except ValueError:
            late = True
        snap = "warn" if late else "ok"
    add("system_snapshots", snap, 4)
    if snap in ("warn", "fail") and settings.get("timeshift_check") is False:
        items[-1]["detail_key"] = "check.reminder_ignored"
    reported = {b.get("state") for b in user_backup_states(daemon.state.get("backup_states")).values()}
    files = "unknown" if not reported else "fail" if "none" in reported else "warn" if reported & {"missing", "old"} else "ok"
    add("file_backups", files, 5)
    if files in ("warn", "fail") and settings.get("backup_check") is False:
        items[-1]["detail_key"] = "check.reminder_ignored"
    # Restore test: Timeshift snapshots (service) and file backups (each user's application)
    tests = [t for t in [daemon.state.get("timeshift_test")] + list((daemon.state.get("backup_tests") or {}).values())
             if t and t.get("error") not in ("btrfs", "not_configured", "device_unmounted")]

    def test_age(t_):
        try:
            return (time.time() - datetime.fromisoformat(t_.get("date", "")).timestamp()) / 86400
        except ValueError:
            return 999
    bad = [t_ for t_ in tests if not t_.get("ok")]
    stale = [t_ for t_ in tests if test_age(t_) > 40]
    has_backups = bool((daemon.state.get("timeshift") or {}).get("snapshots"))
    add("restore_test", ("warn" if bad or stale else "ok") if tests else ("unknown" if has_backups else "na"), 3,
        ", ".join(t_.get("dest_label") or "Timeshift" for t_ in bad) if bad else "")
    # Filtered DNS (malicious domains blocked before the connection)
    dns = protect.dns_status()
    dns_state = daemon.state.get("dns_filter") or {}
    add("filtered_dns", "na" if not dns["usable"] and not dns["active"] else ("ok" if dns["active"] or dns_state.get("suspended") else "warn"), 2,
        dns["provider"] or ("enterprise" if dns_state.get("suspended") else ""))
    # Containers: open Docker socket, docker/lxd groups (administrator equivalent), privileged containers
    cont = daemon.cached("containers", 600, lambda: audit.container_audit(users))
    c_issues = [i for i in cont["issues"] if i["level"] != "info"]
    add("containers", "na" if not cont["available"] and not c_issues else ("fail" if any(i["level"] == "fail" for i in c_issues) else ("warn" if c_issues else "ok")), 3,
        ", ".join(f"{i['key']}: {i['detail']}" for i in c_issues[:5]), params={"issues": cont["issues"][:12]})
    # Flatpak applications that leave their sandbox (whole disk, Flatpak service)
    fp_apps = daemon.flatpak_status()
    fp_bad = [a for a in fp_apps if not a["acknowledged"] and set(a["risks"]) & {"fs_host", "sandbox_escape"}]
    add("flatpak_permissions", "na" if not shutil.which("flatpak") else ("warn" if fp_bad else "ok"), 2,
        ", ".join(a["app"] for a in fp_bad[:6]), params={"apps": [{k: a[k] for k in ("app", "user", "risks", "acknowledged")} for a in fp_apps[:20]]})
    # Paquets pip / npm malveillants
    devp = daemon.state.get("dev_packages") or {}
    add("dev_packages", "unknown" if not devp else ("fail" if devp.get("malicious") else "ok"), 4,
        ", ".join(f"{m['name']} {m['version']} ({m['ecosystem']}) — " + (f"npm uninstall -g {m['name']}" if m["ecosystem"] == "npm" else f"pip uninstall {m['name']}")
                  for m in (devp.get("malicious") or [])[:5]),
        params={"counts": devp.get("counts") or {}, "malicious": (devp.get("malicious") or [])[:10]})
    # SUID / SGID files that no package ships (classic backdoor to become root again)
    suid = daemon.suid_status()
    unowned = [u for u in suid.get("unowned") or [] if not u.get("acknowledged")]
    bad_place = [u for u in unowned if u["path"].startswith(("/tmp/", "/var/tmp/", "/dev/shm/", "/home/", "/run/"))]
    add("suid_files", "unknown" if not suid.get("checked_at") else ("fail" if bad_place else ("warn" if unowned else "ok")), 4,
        ", ".join(u["path"] for u in unowned[:6]), params={"files": [{k: u.get(k) for k in ("path", "owner", "suid", "sgid", "mtime")} for u in unowned[:12]]})
    # Added root certificates (HTTPS interception possible) and network hijacking (hosts, proxy, DNS)
    certs = [c for c in daemon.guard.root_cas() if not c["acknowledged"]]
    add("root_ca", "warn" if certs else "ok", 4, ", ".join(c["name"] for c in certs[:6]),
        params={"certs": [{k: c.get(k) for k in ("fp", "name", "stores", "until")} for c in certs[:12]]})
    redirects = [r for r in daemon.guard.redirects() if not r["acknowledged"]]
    add("network_redirect", "warn" if redirects else "ok", 4, ", ".join(r["value"] for r in redirects[:6]),
        params={"redirects": [{k: r.get(k) for k in ("key", "type", "value", "where")} for r in redirects[:12]]})
    # Automatic response
    add("auto_response", "ok" if settings.get("auto_response") else "warn", 2)
    # Protected folders: only approved programs write to Documents, Pictures, Desktop (ransomware blocked)
    add("protected_folders", "ok" if settings.get("protected_folders") else "warn", 4)

    applicable = [it for it in items if it["status"] in ("ok", "warn", "fail")]
    total = sum(it["weight"] for it in applicable) or 1
    earned = sum(it["weight"] for it in applicable if it["status"] == "ok") + \
        sum(it["weight"] * 0.5 for it in applicable if it["status"] == "warn")
    score = int(round(100 * earned / total))
    grade = "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 60 else "D" if score >= 40 else "E"
    return {"checked_at": now_iso(), "score": score, "grade": grade, "items": items, "ports": ports[:40]}


# ═══════════════════════════════════════════════════════════════════════════
# Outgoing connections: unknown programs, malicious IPs, geolocation
# ═══════════════════════════════════════════════════════════════════════════

class ConnectionMonitor(threading.Thread):
    INTERVAL = 20

    def __init__(self, daemon):
        super().__init__(daemon=True, name="connection-monitor")
        self.daemon_ref = daemon
        self.active = False
        self.seen = {}             # (pid, ip) -> first seen
        self.reported = {}         # pid -> last alert time
        self.blocklist = set()
        self.blocklist_loaded = 0
        self.geo = {ip: v for ip, v in (daemon.state.get("geo_cache") or {}).items()
                    if isinstance(v, dict) and time.time() - v.get("ts", 0) < 86400}   # ip -> {country, countryCode, org, ts}
        self.geo_requests = []     # request timestamps (rolling 24 h)
        self.geo_last_request = 0.0
        self.geo_backoff_until = 0.0
        self.geo_last_error = ""
        self.geo_last_saved = time.time()
        self.current = {"checked_at": None, "processes": []}
        self.lock = threading.Lock()

    def load_blocklist(self, refresh=False):
        try:
            age = time.time() - os.path.getmtime(BLOCKLIST_FILE) if os.path.exists(BLOCKLIST_FILE) else 1e9
        except OSError:
            age = 1e9
        if refresh or age > 86400:
            ips = set()
            for name, url in BLOCKLIST_URLS.items():
                try:
                    text = http_get(url, timeout=60).decode(errors="replace")
                    for line in text.splitlines():
                        line = line.strip()
                        if line and not line.startswith("#"):
                            ip = line.split(",")[0].strip()
                            try:
                                ipaddress.ip_address(ip)
                                ips.add(ip)
                            except ValueError:
                                pass
                except Exception as e:  # noqa: BLE001
                    log(f"Liste {name} indisponible : {e}")
            if ips:
                with open(BLOCKLIST_FILE, "w") as f:
                    f.write("\n".join(sorted(ips)))
        try:
            with open(BLOCKLIST_FILE) as f:
                self.blocklist = {line.strip() for line in f if line.strip()}
            self.blocklist_loaded = time.time()
        except OSError:
            self.blocklist = set()

    def geolocate(self, ips):
        if not self.daemon_ref.settings.get("geoip_lookup"):
            return
        now = time.time()
        todo = [ip for ip in ips if is_public_ip(ip) and (ip not in self.geo or now - self.geo[ip]["ts"] > 86400)]
        if not todo or now < self.geo_backoff_until or now - self.geo_last_request < GEOIP_MIN_INTERVAL:
            return                      # the remaining addresses will be handled on the next pass
        self.geo_last_request = now
        self.geo_requests = [t for t in self.geo_requests if now - t < 86400] + [now]
        try:
            data = json.dumps([{"query": ip} for ip in todo[:100]]).encode()
            for entry in json.loads(http_get(geoip_url(self.daemon_ref.settings.get("geoip_api_key")), timeout=20, data=data,
                                             headers={"Content-Type": "application/json"})):
                if entry.get("status") == "success":
                    self.geo[entry["query"]] = {"country": entry.get("country", ""), "countryCode": entry.get("countryCode", ""),
                                                "org": entry.get("org") or entry.get("isp", ""), "ts": now}
            self.geo_last_error = ""
        except urllib.error.HTTPError as e:
            self.geo_last_error = f"HTTP {e.code}"
            self.geo_backoff_until = now + (300 if e.code in (401, 403) else 60)   # 429: quota exceeded → pause 1 min
            log(f"GeoIP : HTTP {e.code} (pause)")
        except Exception as e:  # noqa: BLE001
            self.geo_last_error = str(e)[:120]
            log(f"GeoIP : {e}")
        if len(self.geo) > GEOIP_CACHE_MAX:
            for ip in sorted(self.geo, key=lambda k: self.geo[k]["ts"])[:len(self.geo) - GEOIP_CACHE_MAX]:
                self.geo.pop(ip, None)
        if now - self.geo_last_saved > 300:     # persisted cache (survives a service restart)
            self.geo_last_saved = now
            self.daemon_ref.state.update(geo_cache=self.geo)

    def geoip_stats(self):
        now = time.time()
        return {"requests_24h": sum(1 for t in self.geo_requests if now - t < 86400), "cached": len(self.geo),
                "provider": "pro" if (self.daemon_ref.settings.get("geoip_api_key") or "").strip() else "free",
                "last_error": self.geo_last_error, "paused": now < self.geo_backoff_until}

    @staticmethod
    def parse_ss():
        r = run_quiet(["ss", "-Htnp", "state", "established"], timeout=15)
        conns = []
        for line in (r.stdout or "").splitlines():
            parts = line.split()
            if len(parts) < 4:
                continue
            peer = parts[3]
            host, _, port = peer.rpartition(":")
            host = host.strip("[]").split("%")[0]
            for m in re.finditer(r'\("([^"]+)",pid=(\d+)', line):
                conns.append({"comm": m.group(1), "pid": int(m.group(2)), "ip": host, "port": port})
        return conns

    def run(self):
        self.active = True
        try:
            self.load_blocklist()
        except Exception as e:  # noqa: BLE001
            log(f"Blocklist : {e}")
        while not self.daemon_ref.shutdown.is_set():
            try:
                if self.daemon_ref.settings.get("connection_monitor"):
                    self.tick()
            except Exception as e:  # noqa: BLE001
                log(f"Connexions : {e}")
            self.daemon_ref.shutdown.wait(self.INTERVAL)
        self.active = False

    def tick(self):
        if time.time() - self.blocklist_loaded > 86400:
            self.load_blocklist()
        conns = self.parse_ss()
        now = time.time()
        procs = {}
        new_pairs = []
        for c in conns:
            if not is_public_ip(c["ip"]):
                continue
            key = (c["pid"], c["ip"])
            if key not in self.seen:
                self.seen[key] = now
                new_pairs.append(c)
            p = procs.setdefault(c["pid"], {"pid": c["pid"], "comm": c["comm"], "exe": "", "trusted": None, "remotes": {}})
            p["remotes"].setdefault(c["ip"], {"ip": c["ip"], "ports": set(), "flagged": c["ip"] in self.blocklist})
            p["remotes"][c["ip"]]["ports"].add(c["port"])
        if len(self.seen) > 5000:
            cutoff = now - 3600
            self.seen = {k: v for k, v in self.seen.items() if v >= cutoff}
        self.geolocate([c["ip"] for c in new_pairs])
        monitor = self.daemon_ref.monitor
        for p in procs.values():
            info = monitor.process_info(p["pid"])
            p["exe"] = info["exe"]
            p["user"] = info["user"]
            p["trusted"] = monitor.exe_trusted(info["exe"]) if info["exe"] else None
            p["exe_replaced"] = info["exe"].endswith(" (deleted)")
            for r in p["remotes"].values():
                r["ports"] = sorted(r["ports"])[:6]
                g = self.geo.get(r["ip"], {})
                r["country"] = g.get("countryCode", "")
                r["org"] = g.get("org", "")
        with self.lock:
            self.current = {"checked_at": now_iso(), "processes": sorted(procs.values(), key=lambda p: (p["trusted"] is not False, p["comm"]))}
        # Alerts: unknown program connecting, or malicious IP
        for c in new_pairs:
            p = procs.get(c["pid"])
            if not p:
                continue
            flagged = c["ip"] in self.blocklist
            if not flagged and p["trusted"] is not False:
                continue
            if now - self.reported.get(c["pid"], 0) < 600 and not flagged:
                continue
            self.reported[c["pid"]] = now
            g = self.geo.get(c["ip"], {})
            alert = {"kind": "connection", "severity": "danger" if flagged else "warn", "time": now_iso(),
                     "pid": c["pid"], "comm": c["comm"], "exe": p["exe"], "user": p.get("user", ""),
                     "trusted": bool(p["trusted"]), "exe_replaced": bool(p.get("exe_replaced")), "ip": c["ip"], "port": c["port"], "flagged": flagged,
                     "country": g.get("country", ""), "org": g.get("org", ""),
                     "reasons": ["ip_blocklisted"] if flagged else ["untrusted_connection"],
                     "count": 0, "top_dir": os.path.dirname(p["exe"]) if p["exe"] else "", "sample": [], "cmdline": ""}
            self.daemon_ref.publish_alert(alert)

    def mark_trusted(self, exe):
        """Immediately marks a program of the current list as approved."""
        with self.lock:
            for p in (self.current.get("processes") or []):
                if normalize_exe(p.get("exe")) == exe:
                    p["trusted"] = True

    def snapshot(self):
        with self.lock:
            return dict(self.current, blocklist_size=len(self.blocklist))


# ═══════════════════════════════════════════════════════════════════════════
# Persistence (autostarts, cron, units) and browser extensions
# ═══════════════════════════════════════════════════════════════════════════

def dpkg_owners(paths):
    """{path: package} for a list of paths, in a single dpkg -S call per batch (rpm -qf on Fedora)."""
    if distro.is_rpm():
        return distro.owners(paths)
    owners = {}
    paths = [p for p in dict.fromkeys(paths)]
    for i in range(0, len(paths), 150):
        chunk = paths[i:i + 150]
        r = run_quiet(["dpkg", "-S"] + chunk, timeout=120)
        for line in (r.stdout or "").splitlines():
            if ": " not in line:
                continue
            pkgs, _, path = line.partition(": ")
            path = path.strip()
            if path in chunk and path not in owners:
                owners[path] = pkgs.split(",")[0].split(":")[0].strip()
    return owners


RISKY_EXT_PERMS = ("nativeMessaging", "debugger", "proxy", "management", "webRequestBlocking", "cookies", "history",
                   "clipboardRead", "downloads", "privacy", "browsingData", "declarativeNetRequestWithHostAccess")
ALL_SITES = ("<all_urls>", "*://*/*", "http://*/*", "https://*/*", "*://*/", "http://*/", "https://*/")


def extension_risks(perms):
    """Sensitive permissions of an extension: "all_sites" (read and change all pages) and the list of
    powerful permissions (messages to a program on the computer, debugging, proxy, cookies…)."""
    out = {p_ for p_ in perms if p_ in RISKY_EXT_PERMS}
    if any(p_ in ALL_SITES for p_ in perms):
        out.add("all_sites")
    return sorted(out)


def desktop_exec(path):
    try:
        with open(path, errors="replace") as f:
            for line in f:
                if line.startswith("Exec="):
                    return line[5:].strip()
    except OSError:
        pass
    return ""


def user_homes():
    """(name, folder) of human accounts whose home folder is readable now (an unmounted eCryptfs encrypted folder,
    before login, is left out: it would look empty)."""
    homes = []
    for pw in pwd.getpwall():
        if (pw.pw_uid >= 1000 or pw.pw_uid == 0) and pw.pw_dir.startswith(("/home/", "/root")) and os.path.isdir(pw.pw_dir) and home_mounted(pw):
            homes.append((pw.pw_name, pw.pw_dir))
    return homes


def pending_homes():
    """Accounts whose encrypted home folder is not mounted: their previous reports are kept as-is."""
    return sorted(pw.pw_name for pw in pwd.getpwall() if pw.pw_uid >= 1000 and pw.pw_dir.startswith("/home/") and not home_mounted(pw))


# Dukiwi applications (DukiwiLink, Gleeder, Dukiwi Shield, OpenVPN GUI): recognized automatically, without approval
# or central whitelist. System locations only — never a home folder, where any program can write.
DUKIWI_PROGRAMS = ("/usr/bin/dukiwilink-*", "/usr/lib/dukiwilink*/*", "/opt/dukiwilink*/*",
                   "/opt/gleeder-*/*", "/usr/bin/gleeder-*",
                   "/opt/dukiwi-*/*", "/usr/bin/dukiwi-*", "/usr/bin/openvpn-gui")


def dukiwi_program(path):
    """Program of a Dukiwi application: known path, file present, owned by root, not writable by other accounts
    (nor its folder) — a known path is not enough if anyone can drop a file there."""
    path = os.path.normpath(path or "")
    if not path.startswith("/") or not any(fnmatch.fnmatch(path, pat) for pat in DUKIWI_PROGRAMS):
        return False
    return root_owned_chain(path)


def startup_program(kind, path, exec_line=""):
    """Program launched by a startup entry: first word of Exec= (.desktop) or of ExecStart= (systemd unit).
    "" if it is not an absolute path (command passed to a shell, variable…)."""
    line = exec_line or ""
    if kind in ("system_unit", "user_unit"):
        line = ""
        try:
            with open(path, errors="replace") as f:
                for ln in f:
                    if ln.startswith("ExecStart=") and ln[10:].strip():
                        line = ln[10:].strip().lstrip("-@+!:")
                        break
        except OSError:
            pass
    try:
        argv = shlex.split(line)
    except ValueError:
        return ""
    return argv[0] if argv and argv[0].startswith("/") else ""


def collect_persistence():
    items = []

    def add(kind, path, name, exec_line="", user="", trusted=None):
        items.append({"kind": kind, "path": path, "name": name, "exec": exec_line[:200], "user": user,
                      "trusted": trusted, "owner": "", "key": f"{kind}:{path}"})

    for p in sorted(Path("/etc/xdg/autostart").glob("*.desktop")):
        add("autostart", str(p), p.stem, desktop_exec(str(p)))
    def safe_glob(base, pattern):
        try:
            return sorted(Path(base).glob(pattern))
        except OSError:
            return []

    for user, home in user_homes():
        for p in safe_glob(Path(home, ".config/autostart"), "*.desktop"):
            add("autostart", str(p), p.stem, desktop_exec(str(p)), user, trusted=False)
        for p in safe_glob(Path(home, ".config/systemd/user"), "*.service"):
            add("user_unit", str(p), p.stem, "", user, trusted=False)
        for p in safe_glob(Path(home, ".config/systemd/user"), "*.timer"):
            add("user_timer", str(p), p.stem, "", user, trusted=False)
        cron = Path("/var/spool/cron/crontabs", user)
        try:
            lines = [ln for ln in cron.read_text(errors="replace").splitlines() if ln.strip() and not ln.startswith("#")] if cron.exists() else []
        except OSError:
            lines = []
        if lines:
            add("crontab", str(cron), user, " | ".join(lines)[:200], user, trusted=False)
    for d in ("/etc/cron.d", "/etc/cron.hourly", "/etc/cron.daily", "/etc/cron.weekly", "/etc/cron.monthly"):
        for p in safe_glob(d, "*"):
            if p.is_file() and not p.name.startswith("."):
                add("cron", str(p), p.name)
    for p in safe_glob("/etc/systemd/system", "*.service"):
        if p.is_file() and not p.is_symlink():
            add("system_unit", str(p), p.stem)
    for p in safe_glob("/etc/systemd/system", "*.timer"):
        if p.is_file() and not p.is_symlink():
            add("system_timer", str(p), p.stem)
    # Pending "at" jobs (deferred one-time execution)
    for d in ("/var/spool/cron/atjobs", "/var/spool/at"):
        for p in safe_glob(d, "*"):
            if p.is_file() and not p.name.startswith("."):
                cmd = ""
                try:
                    lines = [ln for ln in p.read_text(errors="replace").splitlines() if ln.strip() and not ln.startswith(("#", "umask", "cd ", "export ", "OLDPWD", "SHELL="))]
                    cmd = lines[-1] if lines else ""
                except OSError:
                    pass
                add("at_job", str(p), p.name, cmd, trusted=False)
    for p in safe_glob("/etc/profile.d", "*.sh"):
        add("profile", str(p), p.name)
    for path in ("/etc/rc.local", "/etc/ld.so.preload"):
        if os.path.exists(path) and os.path.getsize(path) > 0:
            add("rc", path, os.path.basename(path), trusted=False)

    owners = dpkg_owners([it["path"] for it in items if it["trusted"] is None])
    for it in items:
        if it["trusted"] is None:
            it["owner"] = owners.get(it["path"], "")
            it["trusted"] = bool(it["owner"])
    # Autostart of a Dukiwi application (DukiwiLink in the session, Gleeder agent…): recognized automatically,
    # without a "new autostart" alert or approval to give.
    for it in items:
        if not it["trusted"] and it["kind"] in ("autostart", "user_unit", "system_unit") \
                and dukiwi_program(startup_program(it["kind"], it["path"], it["exec"])):
            it["trusted"], it["owner"] = True, "Dukiwi"

    extensions = []
    for user, home in user_homes():
        for browser, sub in (("chrome", ".config/google-chrome"), ("chromium", ".config/chromium"),
                             ("brave", ".config/BraveSoftware/Brave-Browser"), ("edge", ".config/microsoft-edge")):
            base = Path(home, sub)
            try:
                if not base.is_dir():
                    continue
            except OSError:
                continue
            for profile in safe_glob(base, "Default") + safe_glob(base, "Profile *"):
                prefs = {}
                for pref_name in ("Secure Preferences", "Preferences"):
                    try:
                        with open(profile / pref_name, errors="replace") as f:
                            prefs.update((json.load(f).get("extensions") or {}).get("settings") or {})
                    except Exception:  # noqa: BLE001
                        pass
                for ext_dir in safe_glob(profile / "Extensions", "*"):
                    if not ext_dir.is_dir():
                        continue
                    versions = sorted(ext_dir.glob("*"))
                    if not versions:
                        continue
                    manifest_path = versions[-1] / "manifest.json"
                    name, version, man = ext_dir.name, versions[-1].name, {}
                    try:
                        with open(manifest_path, errors="replace") as f:
                            man = json.load(f)
                        name = man.get("name", name)
                        version = man.get("version", version)
                        if name.startswith("__MSG_"):
                            key = name[6:-2]
                            locales = [man.get("default_locale", "en"), "en", "en_US", "en_GB", "fr", "de", "it"]
                            locales += [d.name for d in safe_glob(versions[-1] / "_locales", "*")]
                            for loc in locales:
                                msg_file = versions[-1] / "_locales" / str(loc) / "messages.json"
                                if msg_file.exists():
                                    with open(msg_file, errors="replace") as f:
                                        msgs = json.load(f)
                                    entry = msgs.get(key) or msgs.get(key.lower()) or {}
                                    if entry.get("message"):
                                        name = entry["message"]
                                        break
                    except Exception:  # noqa: BLE001
                        pass
                    pref = prefs.get(ext_dir.name) or {}
                    scripts = [m_ for cs in (man.get("content_scripts") or []) if isinstance(cs, dict) for m_ in (cs.get("matches") or [])]
                    perms = extension_risks([str(x) for x in list(man.get("permissions") or []) + list(man.get("host_permissions") or []) + scripts])
                    extensions.append({"browser": browser, "user": user, "profile": profile.name, "id": ext_dir.name, "perms": perms,
                                       "name": str(name)[:80], "version": str(version), "from_store": bool(pref.get("from_webstore", True)),
                                       "enabled": pref.get("state", 1) == 1, "key": f"{browser}:{user}:{ext_dir.name}"})
        for ext_json in safe_glob(Path(home, ".mozilla/firefox"), "*/extensions.json"):
            try:
                with open(ext_json, errors="replace") as f:
                    addons = json.load(f).get("addons") or []
            except Exception:  # noqa: BLE001
                continue
            for a in addons:
                if a.get("type") != "extension" or a.get("location") == "app-builtin":
                    continue
                up = a.get("userPermissions") or {}
                extensions.append({"browser": "firefox", "user": user, "profile": ext_json.parent.name, "id": a.get("id", ""),
                                   "perms": extension_risks(list(up.get("permissions") or []) + list(up.get("origins") or [])),
                                   "name": str(a.get("defaultLocale", {}).get("name") or a.get("id", ""))[:80],
                                   "version": str(a.get("version", "")), "from_store": a.get("signedState", 0) not in (0, None) or a.get("location") == "app-system-defaults",
                                   "enabled": bool(a.get("active")), "key": f"firefox:{user}:{a.get('id', '')}"})
    for user, home in user_homes():
        try:
            extensions += audit.editor_extensions(user, home)       # VS Code, VSCodium, Cursor, Windsurf
        except Exception:  # noqa: BLE001
            pass
    return {"checked_at": now_iso(), "items": items, "extensions": extensions, "pending": pending_homes(),
            "counts": {"items": len(items), "untrusted": sum(1 for it in items if not it["trusted"]),
                       "extensions": len(extensions), "ext_outside_store": sum(1 for e in extensions if not e["from_store"])}}


# ═══════════════════════════════════════════════════════════════════════════
# Integrity: Lynis, unhide, chkrootkit, debsums + application files
# ═══════════════════════════════════════════════════════════════════════════

def debsums_verified_paths(failed_lines):
    """Hashes of the package files whose integrity debsums confirmed:
    entries of /var/lib/dpkg/info/*.md5sums, minus conffiles (not checked without -a) and reported files."""
    failed = set()
    for ln in failed_lines or []:
        for m in re.finditer(r"(/[^\s]+)", ln):
            failed.add(m.group(1))
    conffiles = set()
    info = "/var/lib/dpkg/info"
    try:
        names = os.listdir(info)
    except OSError:
        return set()
    for n in names:
        if n.endswith(".conffiles"):
            try:
                with open(os.path.join(info, n), encoding="utf-8", errors="replace") as f:
                    conffiles.update(ln.strip() for ln in f if ln.strip())
            except OSError:
                pass
    verified = set()
    for n in names:
        if not n.endswith(".md5sums"):
            continue
        try:
            with open(os.path.join(info, n), encoding="utf-8", errors="replace") as f:
                for ln in f:
                    parts = ln.rstrip("\n").split("  ", 1)
                    if len(parts) == 2:
                        path = "/" + parts[1]
                        if path not in conffiles and path not in failed:
                            verified.add(hash(path))
        except OSError:
            continue
    return verified


INTEGRITY_TOOLS = {"kernel": "uname", "processes": "ps",            # built-in checks (always available)
                   "lynis": "lynis", "unhide": "unhide", "unhide-tcp": "unhide-tcp", "chkrootkit": "chkrootkit"}
INTEGRITY_TOOLS["rpmverify" if distro.is_rpm() else "debsums"] = "rpm" if distro.is_rpm() else "debsums"   # package verification
RPM_VERIFY_RE = re.compile(r"^(missing|[S.M5DLUGTP?]{9})\s+(?:([cdglr])\s+)?(/.*)$")
RPM_VERIFY_RULES_VERSION = 1


def rpm_verify_analysis(lines):
    """rpm -Va output → {warnings, benign, notes}. Modified configuration files (attribute c, or under /etc):
    normal (benign); documentation / ghosts: ignored; timestamp only: ignored; content changed (5, S, L, M, U, G)
    or missing file: to check."""
    warnings, benign, notes = [], [], {}
    for raw in lines:
        m = RPM_VERIFY_RE.match(raw.strip())
        if not m:
            continue
        flags, attr, path = m.group(1), m.group(2) or "", m.group(3)
        if attr in ("d", "g", "r", "l") or path.startswith(("/usr/share/doc/", "/usr/share/man/", "/usr/share/info/", "/usr/share/locale/", "/usr/share/licenses/")):
            continue                                   # documentation, ghosts, licenses: of no interest
        is_conf = attr == "c" or path.startswith("/etc/")
        if flags == "missing":
            if is_conf:
                benign.append({"text": raw.strip(), "notes": [{"path": path, "verdict": "benign", "reason": "config_removed"}]})
            else:
                warnings.append(raw.strip())
                notes[raw.strip()] = [{"path": path, "verdict": "unknown", "reason": "missing_file"}]
            continue
        if not any(ch in flags for ch in "5SLMUG"):
            continue                                   # only the timestamp or capabilities differ
        if is_conf:
            benign.append({"text": raw.strip(), "notes": [{"path": path, "verdict": "benign", "reason": "config_modified"}]})
        elif path.endswith((".pyc", ".pyo")) and "5" in flags:
            benign.append({"text": raw.strip(), "notes": [{"path": path, "verdict": "benign", "reason": "pyc_rebuilt"}]})
        else:
            warnings.append(raw.strip())
            notes[raw.strip()] = [{"path": path, "verdict": "unknown", "reason": "modified"}]
    return {"warnings": warnings[:80], "benign": benign[:80], "notes": notes}
BUILTIN_CHECKS = ("kernel", "processes")
KERNEL_RULES_VERSION = 1
PROC_RULES_VERSION = 1
TAINT_FLAGS = {0: "P", 1: "F", 2: "S", 3: "R", 4: "M", 5: "B", 6: "U", 7: "D", 8: "A", 9: "W", 10: "C", 11: "I", 12: "O",
               13: "E", 14: "L", 15: "K", 16: "X", 17: "T", 18: "N"}


def _read_text(path, default=""):
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.read().strip()
    except OSError:
        return default


def loaded_modules():
    return {ln.split()[0] for ln in _read_text("/proc/modules").splitlines() if ln.strip()}


def sysfs_live_modules():
    """Live loadable modules seen by sysfs (modules built into the kernel have no initstate)."""
    out = set()
    try:
        names = os.listdir("/sys/module")
    except OSError:
        return out
    for n in names:
        if _read_text(f"/sys/module/{n}/initstate") == "live":
            out.add(n)
    return out


def modules_dep_index(release):
    """normalized module name ('-' → '_') → relative path of the .ko file for this kernel (modules.dep)."""
    idx = {}
    for ln in _read_text(f"/lib/modules/{release}/modules.dep").splitlines():
        rel = ln.split(":", 1)[0].strip()
        if not rel:
            continue
        base = os.path.basename(rel)
        for ext in (".ko.zst", ".ko.xz", ".ko.gz", ".ko"):
            if base.endswith(ext):
                base = base[:-len(ext)]
                break
        idx[base.replace("-", "_")] = rel
    return idx


def kernel_check():
    """Kernel check: hidden module (alive in /sys/module but missing from the /proc/modules list — signature
    of an LKM rootkit), module loaded without a file for this kernel (injected from memory), out-of-tree modules
    (DKMS: benign, listed), "force-loaded" taint, lockdown / signature / modules_disabled state."""
    release = os.uname().release
    loaded = loaded_modules()
    hidden = sorted(sysfs_live_modules() - loaded)
    dep = modules_dep_index(release)
    nofile, dkms, extra = [], [], []
    for name in sorted(loaded):
        rel = dep.get(name.replace("-", "_"))
        if rel is None:
            nofile.append(name)
        elif "dkms" in rel:
            dkms.append(f"{name} ({rel})")
        elif rel.startswith(("updates/", "extra/")):
            extra.append(f"{name} ({rel})")
    warnings, benign, notes = [], [], {}
    if hidden:
        text = "Hidden kernel module(s): alive in /sys/module but absent from /proc/modules: " + ", ".join(hidden)
        warnings.append(text)
        notes[text] = [{"path": n, "verdict": "unknown", "reason": "module_hidden"} for n in hidden]
    if nofile:
        if not dep or len(nofile) > 10:          # module tree missing or from another kernel: not an injection
            text = f"Module tree for the running kernel {release} is missing or stale ({len(nofile)} loaded module(s) without file): reboot after the kernel update"
            benign.append({"text": text, "notes": [{"path": release, "verdict": "benign", "reason": "module_tree_stale"}]})
        else:
            text = f"Loaded kernel module(s) without a module file for kernel {release}: " + ", ".join(nofile)
            warnings.append(text)
            notes[text] = [{"path": n, "verdict": "unknown", "reason": "module_nofile"} for n in nofile]
    if dkms or extra:
        text = "Out-of-tree kernel module(s): " + ", ".join(dkms + extra)
        benign.append({"text": text, "notes": [{"path": x, "verdict": "benign", "reason": "module_dkms" if x in dkms else "module_extra"} for x in dkms + extra]})
    try:
        taint = int(_read_text("/proc/sys/kernel/tainted", "0") or 0)
    except ValueError:
        taint = 0
    flags = "".join(TAINT_FLAGS[b] for b in TAINT_FLAGS if taint & (1 << b))
    if taint & (1 << 1) or taint & (1 << 3):
        text = f"Kernel taint flags {flags}: a module was force-loaded or force-unloaded (modprobe -f / rmmod -f)"
        warnings.append(text)
        notes[text] = [{"path": flags, "verdict": "unknown", "reason": "taint_forced"}]
    info = {"release": release, "loaded": len(loaded), "taint": taint, "taint_flags": flags,
            "lockdown": _read_text("/sys/kernel/security/lockdown"), "sig_enforce": _read_text("/sys/module/module/parameters/sig_enforce"),
            "modules_disabled": _read_text("/proc/sys/kernel/modules_disabled")}
    return {"installed": True, "ran": True, "rc": 0, "warnings": warnings[:80], "benign": benign[:40], "notes": notes,
            "rules": KERNEL_RULES_VERSION, "info": info}


SYSTEM_EXE_DIRS = ("/usr/", "/opt/", "/snap/", "/var/lib/flatpak/", "/app/", "/lib/", "/lib64/", "/bin/", "/sbin/", "/etc/", "/nix/")
TMP_EXE_DIRS = ("/tmp/", "/var/tmp/", "/dev/shm/", "/run/user/", "/run/shm/")
DEBUGGER_NAMES = {"gdb", "strace", "ltrace", "lldb", "lldb-server", "rr", "valgrind", "perf", "gdbserver", "py-spy", "bpftrace", "ltrace"}
STEAM_PRELOAD_RE = re.compile(r"/(\.steam|\.local/share/Steam|Steam)/")


def preload_digest(lib, procs):
    """First 12 characters of the sha256 of a preloaded library, read as seen by one of the processes that carry it
    (mount namespace of a container, a Flatpak…), otherwise by its path. "" if it is unreadable or huge."""
    for cand in [f"/proc/{p.split(' ', 1)[0]}/root{lib}" for p in procs[:3]] + [lib]:
        try:
            if os.path.isfile(cand) and os.path.getsize(cand) <= 64 << 20:
                return sha256_file(cand)[:12]
        except OSError:
            continue
    return ""


def process_check(trusted=None):
    """Scan of /proc (behaviour): executable deleted from disk, execution from a temporary folder,
    library injected via LD_PRELOAD, process traced by ptrace. Built-in verdicts: updated program
    (file replaced), AppImage, library shipped by a package / Steam / store, known debugger → benign.
    `trusted` {exe: name} ("Trust"): program trusted by path, or by name when the trusted path is
    itself a temporary folder (test binary recompiled under /tmp every time)."""
    findings = {"exe_deleted": [], "exe_upgraded": [], "exe_tmp": [], "exe_appimage": [], "exe_trusted": []}
    preload_libs, tracers = {}, {}
    trusted = trusted or {}
    tmp_trusted_names = {c for e, c in trusted.items() if e.startswith(TMP_EXE_DIRS) and c}
    scanned = 0
    for pid in os.listdir("/proc"):
        if not pid.isdigit():
            continue
        base = f"/proc/{pid}"
        try:
            exe = os.readlink(f"{base}/exe")
        except OSError:
            continue                                   # kernel thread, or process already finished
        scanned += 1
        comm = _read_text(f"{base}/comm") or "?"
        deleted = exe.endswith(" (deleted)")
        path = exe[:-10] if deleted else exe
        label = f"{pid} {comm} {path}"
        is_trusted = path in trusted or (path.startswith(TMP_EXE_DIRS) and comm in tmp_trusted_names)
        if deleted:
            if os.path.exists(path) or path.startswith(SYSTEM_EXE_DIRS):
                findings["exe_upgraded"].append(label)     # program updated (or package removed) while it is running
            elif is_trusted:
                findings["exe_trusted"].append(label)
            else:
                findings["exe_deleted"].append(label)
        elif path.startswith(TMP_EXE_DIRS):
            if "/.mount_" in path or "appimage" in path.lower():
                findings["exe_appimage"].append(label)
            elif is_trusted:
                findings["exe_trusted"].append(label)
            else:
                findings["exe_tmp"].append(label)
        try:
            with open(f"{base}/environ", "rb") as f:
                env = f.read()
        except OSError:
            env = b""
        for chunk in env.split(b"\0"):
            if chunk.startswith(b"LD_PRELOAD="):
                for lib in re.split(r"[:\s]+", chunk[11:].decode(errors="replace").strip()):
                    if lib:
                        preload_libs.setdefault(lib, []).append(label)
        m = re.search(r"^TracerPid:\s*(\d+)", _read_text(f"{base}/status"), flags=re.M)
        if m and m.group(1) != "0":
            tracers.setdefault(m.group(1), []).append(label)
    warnings, benign, notes = [], [], {}

    def add(items, verdict, reason, head):
        if not items:
            return
        text = head + "\n" + "\n".join(items[:40])
        ns = [{"path": it, "verdict": verdict, "reason": reason} for it in items[:40]]
        if verdict == "benign":
            benign.append({"text": text, "notes": ns})
        else:
            warnings.append(text)
            notes[text] = ns
    add(findings["exe_deleted"], "unknown", "exe_deleted", "Running process(es) whose executable was deleted from disk:")
    add(findings["exe_tmp"], "unknown", "exe_tmp", "Process(es) running from a temporary directory:")
    add(findings["exe_upgraded"], "benign", "exe_upgraded", "Process(es) still running an executable replaced on disk (program updated):")
    add(findings["exe_appimage"], "benign", "exe_appimage", "AppImage(s) mounted under /tmp:")
    add(findings["exe_trusted"], "benign", "trusted_program", "Process(es) of a trusted program:")
    if preload_libs:
        owners = dpkg_owners([lib for lib in preload_libs if lib.startswith("/")])
        ns_b = []
        for lib, procs in sorted(preload_libs.items()):
            who = ", ".join(sorted({p.split(" ", 2)[1] for p in procs})[:6])
            path = f"{lib} <- {who}"
            if lib in owners:
                ns_b.append({"path": path, "verdict": "benign", "reason": "preload_dpkg", "package": owners[lib].split(", ")[0]})
            elif STEAM_PRELOAD_RE.search(lib):
                ns_b.append({"path": path, "verdict": "benign", "reason": "preload_steam"})
            elif not lib.startswith("/") or lib.startswith(("/snap/", "/var/lib/flatpak/", "/app/", "/usr/lib/", "/lib/")):
                ns_b.append({"path": path, "verdict": "benign", "reason": "preload_app"})
            else:
                # One warning per unknown library, identified by its path and content, never by the list of programs
                # (it changes with every application launched, see integrity_warning_norm): "That's normal" holds
                # from one pass to the next, and is dropped if the file is replaced or another library appears.
                digest = preload_digest(lib, procs)
                note = {"path": f"{lib} (sha256 {digest}) <- {who}" if digest else path, "verdict": "unknown", "reason": "preload_unknown"}
                text = "LD_PRELOAD library injected into process(es):\n" + note["path"]
                warnings.append(text)
                notes[text] = [note]
        if ns_b:
            text = "LD_PRELOAD in use (known libraries):\n" + "\n".join(n["path"] for n in ns_b)
            benign.append({"text": text, "notes": ns_b})
    if tracers:
        tr_exe = {}
        for tpid in tracers:
            try:
                tr_exe[tpid] = os.readlink(f"/proc/{tpid}/exe").split(" (deleted)")[0]
            except OSError:
                tr_exe[tpid] = ""
        owners = dpkg_owners([e for e in tr_exe.values() if e])
        ns_b, ns_u = [], []
        for tpid, victims in tracers.items():
            tcomm = _read_text(f"/proc/{tpid}/comm") or "?"
            path = f"{tcomm} ({tpid}) -> " + ", ".join(v.split(" ", 2)[1] for v in victims[:6])
            texe = tr_exe.get(tpid, "")
            if tcomm in DEBUGGER_NAMES or texe in owners:
                ns_b.append({"path": path, "verdict": "benign", "reason": "traced_dpkg", "package": (owners.get(texe) or tcomm).split(", ")[0]})
            else:
                ns_u.append({"path": path, "verdict": "unknown", "reason": "traced"})
        if ns_u:
            text = "Process(es) being traced (ptrace) by an unknown program:\n" + "\n".join(n["path"] for n in ns_u + ns_b)
            warnings.append(text)
            notes[text] = ns_u + ns_b
        else:
            text = "Process(es) traced by a known debugger:\n" + "\n".join(n["path"] for n in ns_b)
            benign.append({"text": text, "notes": ns_b})
    return {"installed": True, "ran": True, "rc": 0, "warnings": warnings[:80], "benign": benign[:40], "notes": notes,
            "rules": PROC_RULES_VERSION, "info": {"scanned": scanned}}


def builtin_check(name, trusted=None):
    return kernel_check() if name == "kernel" else process_check(trusted)


def integrity_tools_now():
    """Current availability of the integrity tools (independent of the last saved report)."""
    return {name: shutil.which(cmd) is not None for name, cmd in INTEGRITY_TOOLS.items()}


def with_tools_now(integrity):
    out = dict(integrity or {})
    out["tools_now"] = integrity_tools_now()
    return out


HARDEN_CATALOG = harden.catalog_public()       # Lynis test → kind/caution/no_revert/action (for the interface)


def parse_lynis_report(path="/var/log/lynis-report.dat", log_path="/var/log/lynis.log"):
    """Lynis report: hardening index (0-100), warnings, suggestions (deduplicated per test, with
    details) and, from the log, the sysctl keys and permissions reported (missing from the report)."""
    rep = {"index": None, "warnings": [], "suggestions": 0, "items": [], "tests": None, "version": "",
           "sysctl_diffs": [], "file_perms": []}
    seen = {}
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            for ln in f:
                ln = ln.strip()
                if ln.startswith("hardening_index="):
                    rep["index"] = int(ln.split("=", 1)[1].strip() or 0)
                elif ln.startswith("warning[]="):
                    parts = ln.split("=", 1)[1].split("|")
                    rep["warnings"].append(f"{parts[0]}: {parts[1]}" if len(parts) > 1 and parts[1] else parts[0])
                elif ln.startswith("suggestion[]="):
                    parts = (ln.split("=", 1)[1] + "|||").split("|")
                    test, text, details = parts[0].strip(), parts[1].strip(), parts[2].strip()
                    details = "" if details == "-" else details
                    if not test:
                        continue
                    if test in seen:
                        seen[test]["count"] += 1
                        if details and details not in seen[test]["details"]:
                            seen[test]["details"] = "; ".join(x for x in (seen[test]["details"], details) if x)
                    else:
                        seen[test] = {"test": test, "text": text, "details": details, "count": 1}
                        rep["items"].append(seen[test])
                elif ln.startswith(("lynis_tests_done=", "tests_executed=")):
                    rep["tests"] = ln.split("=", 1)[1].strip()
                elif ln.startswith("lynis_version="):
                    rep["version"] = ln.split("=", 1)[1].strip()
    except (OSError, ValueError):
        pass
    rep["suggestions"] = len(rep["items"])
    diffs, perms = {}, {}
    try:
        with open(log_path, encoding="utf-8", errors="replace") as f:
            for ln in f:
                m = re.search(r"sysctl key (\S+) has a different value than expected in scan profile\. Expected=(\S+), Real=(\S+)", ln)
                if m:
                    diffs[m.group(1)] = {"key": m.group(1), "expected": m.group(2), "current": m.group(3)}
                    continue
                m = re.search(r"permissions of file (\S+) are not matching expected value \((\d+) != (\d+)\)", ln)
                if m:
                    perms[m.group(1)] = {"path": m.group(1), "current": m.group(2), "expected": m.group(3)}
    except OSError:
        pass
    rep["sysctl_diffs"], rep["file_perms"] = list(diffs.values()), list(perms.values())
    for it in rep["items"]:
        if it["test"] == "KRNL-6000" and diffs:
            it["details"] = ", ".join(f"{x['key']} {x['current']}→{x['expected']}" for x in rep["sysctl_diffs"][:40])
        elif it["test"] == "FILE-7524" and perms:
            it["details"] = ", ".join(f"{x['path']} ({x['current']}→{x['expected']})" for x in rep["file_perms"][:40])
    return rep


CHK_RULES_VERSION = 9              # built-in classification rules; an older report is redone at startup
CHK_NOISE = ("RTNETLINK answers", "ip: ", "ifconfig:", "ls: ", "find: ", "grep: ", "netstat:", "ss: ", "Usage:",
             "/usr/sbin/chkrootkit:", "chkrootkit:", "chkproc:", "chkdirs:", "chkutmp:", "eth", "wlan")   # tool messages, not findings
CHK_NOISE = tuple(x for x in CHK_NOISE if x not in ("eth", "wlan"))
LYNIS_SECTIONS = 44                # "[+]" sections of a full audit (progress)
CHK_TESTS = 108                    # "Searching for …" + "Checking `bin'…" of a chkrootkit pass


def _md5sums_entries():
    """Number of files debsums will check (lines of the *.md5sums), for the progress display."""
    total = 0
    try:
        for n in os.listdir("/var/lib/dpkg/info"):
            if n.endswith(".md5sums"):
                with open(os.path.join("/var/lib/dpkg/info", n), "rb") as f:
                    total += sum(1 for _ in f)
    except OSError:
        pass
    return total or 500000


# Integrity tool timeouts, in seconds: (maximum silence, maximum total duration). A tool that stops responding
# is stopped and the scan continues with the next one — without this a full scan stayed stuck indefinitely.
# No silence timeout for unhide (buffered output, written at the end) or rpm -Va (only writes anomalies).
TOOL_LIMITS = {"lynis": (900, 2700), "unhide": (None, 1800), "unhide-tcp": (None, 1800), "chkrootkit": (900, 2700),
               "debsums": (900, 5400), "rpmverify": (None, 5400)}
BUILTIN_TIMEOUT = 120              # built-in checks (kernel, processes): a few seconds normally
TOOL_HEARTBEAT = 5                 # progress rebroadcast even without new output (the interface resyncs)


def tool_limits(name):
    """(maximum silence, maximum duration) of the tool; DUKIWI_SHIELD_TOOL_STALL / _LIMIT override them (tests)."""
    stall, limit = TOOL_LIMITS.get(name, (900, 2700))
    try:
        stall = int(os.environ["DUKIWI_SHIELD_TOOL_STALL"]) if "DUKIWI_SHIELD_TOOL_STALL" in os.environ else stall
        limit = int(os.environ.get("DUKIWI_SHIELD_TOOL_LIMIT") or limit)
    except ValueError:
        pass
    return stall, limit


def _stop_tool(proc):
    """Stops the tool and all its child processes (it is its session leader): TERM, then KILL 5 s later."""
    for sig in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.killpg(proc.pid, sig)
        except OSError:
            pass
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            continue
        if sig == signal.SIGTERM:
            try:
                os.killpg(proc.pid, signal.SIGKILL)   # children that would have survived the script (they hold the output)
            except OSError:
                pass
        return


def run_bounded(fn, timeout):
    """fn() in a helper thread; TimeoutError if it does not return (blocked read of /proc or sysfs)."""
    box = {}

    def target():
        try:
            box["value"] = fn()
        except Exception as e:  # noqa: BLE001
            box["error"] = e
    th = threading.Thread(target=target, daemon=True, name="bounded-check")
    th.start()
    th.join(timeout)
    if th.is_alive():
        raise TimeoutError(f"no answer after {timeout} s")
    if "error" in box:
        raise box["error"]
    return box["value"]


def _stream_tool(name, cmd, cancel_event, tick):
    """Runs an integrity tool while reading its output as it comes; tick(percentage, step) according to its markers.
    Returns (useful lines, return code, stop). For debsums, only anomalies are kept (one line per file
    otherwise). `stop` is None, or {"reason": "stalled" | "limit", "after": seconds, "last": last line}
    when the tool was stopped for not responding (tool_limits). Cancellation is handled within a second,
    even if the tool writes nothing."""
    try:
        proc = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                                bufsize=1, errors="replace", start_new_session=True)
    except OSError as e:
        return [f"{name}: {e}"], 1, None
    lines = _queue.Queue()

    def pump():                                         # blocking read outside the scan thread
        try:
            for raw in proc.stdout:
                lines.put(raw)
        except (OSError, ValueError):
            pass
        lines.put(None)
    threading.Thread(target=pump, daemon=True, name=f"integrity-{name}").start()
    totals = {"lynis": LYNIS_SECTIONS, "chkrootkit": CHK_TESTS, "unhide": 3, "unhide-tcp": 2}
    total = _md5sums_entries() if name == "debsums" else totals.get(name, 1)
    stall, limit = tool_limits(name)
    out, done, detail, last_tick, last_line, stopped = [], 0, "", 0.0, "", None
    started = last_out = time.time()
    while True:
        try:
            raw = lines.get(timeout=1)
        except _queue.Empty:
            raw = ""
        if raw is None:                                 # end of output: the tool has finished
            break
        now = time.time()
        if cancel_event is not None and cancel_event.is_set():
            _stop_tool(proc)
            break
        if not raw and stall and now - last_out >= stall:
            stopped = {"reason": "stalled", "after": int(now - last_out), "last": last_line[:200]}
        elif limit and now - started >= limit:
            stopped = {"reason": "limit", "after": int(now - started), "last": last_line[:200]}
        if stopped:
            _stop_tool(proc)
            break
        if not raw:                                     # rien de nouveau : battement, l'outil travaille en silence
            if now - last_tick >= TOOL_HEARTBEAT:
                last_tick = now
                tick(min(97, int(done * 100 / max(1, total))), detail)
            continue
        last_out = now
        line = raw.rstrip("\n")
        if line.strip():
            last_line = line.strip()
        if name == "debsums":
            done += 1
            if line and not line.endswith(" OK"):
                out.append(line)
        else:
            out.append(line)
            s = line.strip()
            if name == "lynis" and s.startswith("[+] "):
                done += 1
                detail = s[4:].strip()[:60]
            elif name == "chkrootkit" and (s.startswith("Checking `") or s.startswith("Searching for ")):
                done += 1
                detail = (s.split("`", 1)[1].split("'", 1)[0] if s.startswith("Checking `") else s[14:].split("...", 1)[0]).strip()[:60]
            elif name in ("unhide", "unhide-tcp") and s.startswith("[*]"):
                done += 1
                detail = s[3:].strip()[:60]
            else:
                continue
        if now - last_tick >= 0.4:
            last_tick = now
            tick(min(97, int(done * 100 / max(1, total))), detail)
    try:
        proc.wait(timeout=30)
    except subprocess.TimeoutExpired:
        _stop_tool(proc)
    return out, proc.returncode, stopped
NETMGR_NAMES = {"NetworkManager", "wpa_supplicant", "iwd", "dhclient", "dhcpcd", "avahi-daemon", "systemd-networkd",
                "dnsmasq", "libvirtd", "dockerd", "tcpdump", "dumpcap", "wireshark", "nmap", "arp-scan", "lldpd",
                "connmand", "hostapd", "NetworkManager-dispatcher"}


def parse_chkrootkit(out):
    """chkrootkit -q output → findings. A "WARNING: … :" is followed by the affected paths on the following
    lines (hidden files, etc.): they stay attached to the finding instead of being lost."""
    findings, cur, prev_blank = [], [], True
    for raw in out:
        s = raw.strip()
        if not s:
            prev_blank = True
            continue
        if s.startswith("ROOTDIR") or s.lower().startswith(("not tested", "not infected", "not found", "nothing found")) \
                or s.startswith(CHK_NOISE) or s == "WARNING":
            # "WARNING" alone: end of the "Checking …" line separated by a tool message (verbose mode);
            # the detailed "WARNING: …" finding always follows (_warn of chkrootkit)
            prev_blank = False
            continue
        m = re.match(r"^(?:Checking `[^']*'\.\.\.|Searching for .*?\.\.\.)\s*(.*)$", s)
        if m:                                       # verbose mode: the test result follows on the same line
            rest = m.group(1).strip().lower()
            if not rest or rest.startswith(("not infected", "not found", "not tested", "nothing", "ok", "warning", "no ", "started", "finished")) \
                    or "nothing detected" in rest or "nothing deleted" in rest or rest.startswith(tuple(x.lower() for x in CHK_NOISE)):
                prev_blank = False
                continue                            # test without a finding (a detailed WARNING follows on its own lines)
            if cur:                                 # non-trivial result (e.g. "Checking `ls'... INFECTED"): whole finding
                findings.append("\n".join(cur))
                cur = []
            cur.append(s)
            prev_blank = False
            continue
        # Attaches to the current finding: path or table row, or header ending with ":" (announced list)
        attach = s.startswith(("/", "!")) or (bool(cur) and cur[0].rstrip().endswith(":"))
        if cur and (s.startswith(("WARNING", "INFECTED", "Possible", "Checking")) or prev_blank or not attach):
            findings.append("\n".join(cur))
            cur = []
        cur.append(s)
        prev_blank = False
    if cur:
        findings.append("\n".join(cur))
    return findings[:80]


# Legitimate hidden names in /usr/lib and /lib (chkrootkit reports any name starting with a dot)
HIDDEN_KNOWN = {
    "debug": {".build-id", ".dwz"},                                   # debugging symbols, kernel vdso
    "perl": {".packlist"},                                            # modules Perl
    "devfile": {".gitignore", ".gitkeep", ".gitattributes", ".keep", ".placeholder", ".dirstamp", ".mkdir",
                ".npmignore", ".npmrc", ".yarnrc", ".editorconfig", ".babelrc", ".eslintrc", ".eslintrc.js",
                ".eslintrc.json", ".eslintignore", ".prettierrc", ".prettierignore", ".jshintrc", ".nycrc",
                ".travis.yml", ".mailmap", ".flake8", ".pylintrc", ".coveragerc", ".dockerignore"},
}
HIDDEN_KNOWN_BY_NAME = {n: cat for cat, names in HIDDEN_KNOWN.items() for n in names}
MODULE_TREES = ("/usr/lib/node_modules/", "/usr/lib/python3/dist-packages/", "/usr/lib/python3.", "/usr/local/lib/python3.",
                "/usr/local/lib/node_modules/")


def dpkg_owners(paths):
    """{path: 'package, package'} for paths shipped by an installed package (dpkg -S in batches; rpm -qf on Fedora)."""
    if distro.is_rpm():
        return distro.owners(paths)
    owners = {}
    paths = [p for p in paths if p.startswith("/")]
    for i in range(0, len(paths), 200):
        r = run_quiet(["dpkg", "-S"] + paths[i:i + 200], timeout=120)
        for ln in (r.stdout or "").splitlines():
            if ": " not in ln or ln.startswith("diversion"):
                continue
            pkgs, _, path = ln.rpartition(": ")
            if path in paths and pkgs:
                owners[path] = pkgs
    return owners


def _module_file(p):
    """Small hidden file inside an npm/Python module tree (installed outside dpkg)."""
    try:
        return any(p.startswith(t) for t in MODULE_TREES) and os.path.isfile(p) and os.path.getsize(p) < 1_000_000
    except OSError:
        return False


CHK_PACKAGE_NOTE = re.compile(r"\s+\[From [A-Za-z]+ package: [^\]]*\]$")


def chk_path(line):
    """Path of a chkrootkit path line. Debian's chkrootkit (0.58b-2 and later) appends the owning package:
    "/usr/lib/firmware/…/.notice.zst [From Debian package: linux-firmware-qualcomm-wireless]". The note is
    dropped and never trusted: ownership is checked with dpkg on the bare path (a file can be named after it)."""
    return CHK_PACKAGE_NOTE.sub("", line.strip())


def classify_hidden_paths(paths):
    """Built-in verdict for each hidden path reported by chkrootkit: benign (shipped by a package, known name,
    file of an npm/Python module) or unknown (to check). The knowledge lives in the program, not with the user."""
    owners = dpkg_owners(paths)
    notes = []
    for p in paths:
        name = os.path.basename(p.rstrip("/"))
        if p in owners:
            notes.append({"path": p, "verdict": "benign", "reason": "dpkg", "package": owners[p].split(", ")[0]})
        elif name in HIDDEN_KNOWN_BY_NAME:
            notes.append({"path": p, "verdict": "benign", "reason": HIDDEN_KNOWN_BY_NAME[name]})
        elif _module_file(p):
            notes.append({"path": p, "verdict": "benign", "reason": "module"})
        else:
            notes.append({"path": p, "verdict": "unknown", "reason": "unknown"})
    return notes


TMP_KNOWN = (
    ("/tmp/scoped_dir", "chrome"),        # installation d'extensions Chrome/Chromium (CRX_INSTALL/manifest.json)
    ("/tmp/timeshift-", "timeshift"),     # scripts temporaires de Timeshift
    ("/tmp/pip-", "build_tmp"), ("/tmp/cargo", "build_tmp"), ("/tmp/rustc", "build_tmp"), ("/tmp/go-build", "build_tmp"),
    ("/tmp/tmp", "build_tmp"), ("/tmp/npm-", "build_tmp"), ("/tmp/yarn-", "build_tmp"),
)


def classify_tmp_paths(paths):
    """Built-in verdict for "Linux.Xor.DDoS": chkrootkit simply lists every executable file in /tmp there.
    The real Xor.DDoS drops ELF binaries with random names: a text or script file, a Chrome extension
    install, a Timeshift script or a build folder are not rootkits."""
    notes = []
    for p in paths:
        if not os.path.exists(p):
            notes.append({"path": p, "verdict": "benign", "reason": "tmp_gone"})
            continue
        known = next((reason for prefix, reason in TMP_KNOWN if p.startswith(prefix)), None)
        if known:
            notes.append({"path": p, "verdict": "benign", "reason": known})
            continue
        try:
            with open(p, "rb") as f:
                head = f.read(4)
        except OSError:
            head = b""
        if head != b"\x7fELF":
            notes.append({"path": p, "verdict": "benign", "reason": "tmp_text"})
        else:
            notes.append({"path": p, "verdict": "unknown", "reason": "elf_tmp"})
    return notes


BPFDOOR_STACK = re.compile(r"^/proc/(\d+)/stack:\s*(?:\[<[0-9a-fA-F]+>\]\s*)?([\w.]+)\+")


def classify_bpfdoor(lines):
    """Built-in verdict for "Possible Linux BPFDoor Malware installed" (2.9.5). chkrootkit runs
    `egrep packet_recvmsg /proc/*/stack`, which also matches unix_seqpacket_recvmsg: any program waiting on a local
    UNIX socket (Chromium/Electron sandbox broker, systemd…). BPFDoor waits on a raw packet socket, so its stack
    shows packet_recvmsg itself: that one stays to check."""
    notes = []
    for ln in lines:
        s = ln.strip()
        if not s:
            continue
        m = BPFDOOR_STACK.match(s)
        if not m:
            notes.append({"path": s, "verdict": "unknown", "reason": "bpfdoor"})
            continue
        pid, sym = m.group(1), m.group(2)
        try:
            exe = os.readlink(f"/proc/{pid}/exe")
        except OSError:
            exe = "?"
        who = f"{exe} (pid {pid}, {sym})"
        if sym != "packet_recvmsg" and sym.endswith("_seqpacket_recvmsg"):
            notes.append({"path": who, "verdict": "benign", "reason": "bpfdoor_unix"})
        else:
            notes.append({"path": who, "verdict": "unknown", "reason": "bpfdoor"})
    return notes or None


def classify_promisc(lines):
    """Built-in verdict for "Output from ifpromisc": a Wi-Fi interface managed by NetworkManager/wpa_supplicant
    shows up as PACKET SNIFFER (legitimate raw socket). Known process or shipped by a package → benign; otherwise
    to check."""
    notes, exes = [], []
    for ln in lines:
        s = ln.strip()
        m = re.search(r"PACKET SNIFFER\((.*)\)", s)
        if m:
            for part in m.group(1).split(","):
                exe = part.strip().split("[", 1)[0].strip()
                if exe:
                    exes.append(exe)
        elif s.endswith(": PROMISC") or " PROMISC" in s:
            notes.append({"path": s.split(":", 1)[0], "verdict": "unknown", "reason": "promisc"})
    owners = dpkg_owners(exes)
    for exe in exes:
        if os.path.basename(exe) in NETMGR_NAMES:
            notes.append({"path": exe, "verdict": "benign", "reason": "netmgr"})
        elif exe in owners:
            notes.append({"path": exe, "verdict": "benign", "reason": "dpkg", "package": owners[exe].split(", ")[0]})
        else:
            notes.append({"path": exe, "verdict": "unknown", "reason": "sniffer"})
    return notes


def local_ip_octets():
    """Last octets of the local IPv4 addresses: the chkrootkit bindshell test (regex "[.:]PORT[^0-9.:]" on
    netstat/ss) mistakes an address 192.168.0.145 for port 145."""
    r = run_quiet(["ip", "-4", "-o", "addr"], timeout=10)
    return set(re.findall(r"inet \d+\.\d+\.\d+\.(\d+)/", r.stdout or ""))


APP_STORE_PREFIXES = ("/app/", "/snap/", "/var/lib/flatpak/", "/var/lib/snapd/")


SLAPPER_PORTS = (2002, 4156, 1978, 1812, 2015)      # TCP ports of chkrootkit's "Slapper Worm" test
SCALPER_PORTS = (2001,)                              # TCP port of the "Scalper Worm" test
CHK_BIN_DIRS = ("/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin")


def package_file_origin(path):
    """(package, modified) for a file: shipped by a package (dpkg -S / rpm -qf) and, as root, verified unchanged
    against the package (dpkg -V / rpm -V)."""
    return sudoers_file_origin(path)


def classify_infected_binary(head):
    """Built-in verdict for "Checking `ls'... INFECTED": chkrootkit found known rootkit patterns in the binary.
    Binary shipped by a package and intact according to it (checksum) → the patterns are in the original
    program: false positive. Modified or not from a package → check urgently."""
    m = re.search(r"Checking `([^']+)'", head)
    if not m:
        return None
    name = m.group(1)
    path = shutil.which(name, path=":".join(CHK_BIN_DIRS)) or shutil.which(name) or ""
    if not path:
        return [{"path": name, "verdict": "unknown", "reason": "binary_missing"}]
    real = os.path.realpath(path)
    pkg, modified = package_file_origin(real)
    if not pkg:
        return [{"path": real, "verdict": "unknown", "reason": "binary_unknown"}]
    if modified:
        return [{"path": real, "verdict": "unknown", "reason": "binary_modified", "package": pkg}]
    return [{"path": real, "verdict": "benign", "reason": "binary_verified", "package": pkg}]


def classify_init(head):
    """"Possible Suckit: /sbin/init INFECTED": real init (systemd…) shipped by a package and intact → false positive."""
    real = os.path.realpath("/sbin/init")
    pkg, modified = package_file_origin(real)
    if not pkg:
        return [{"path": real, "verdict": "unknown", "reason": "init_unknown"}]
    if modified:
        return [{"path": real, "verdict": "unknown", "reason": "init_modified", "package": pkg}]
    return [{"path": real, "verdict": "benign", "reason": "init_verified", "package": pkg}]


# Shell error messages mixed into a tool's output: never a finding (2.9.7). chkproc moves into /proc/<pid> to read
# each process and runs ps from there; when that process has just ended, the shell prints "sh: 0: getcwd() failed:
# No such file or directory" — the same short-lived process that made chkproc report a difference.
SHELL_NOISE = re.compile(r"^(?:/bin/|/usr/bin/)?(?:sh|bash|dash)(?:: \d+)?: ")
CHKPROC_PATHS = ("/usr/lib/chkrootkit/chkproc", "/usr/lib64/chkrootkit/chkproc", "/usr/libexec/chkrootkit/chkproc")


def chkproc_verbose():
    """Runs chkproc again in verbose mode (chkrootkit -q runs it without -v: it only says "something differs", never
    which process). (exit code, output), or None when chkproc is not found."""
    exe = next((p for p in CHKPROC_PATHS if os.access(p, os.X_OK)), None)
    if not exe:
        return None
    try:
        r = subprocess.run([exe, "-v", "-v", "-p", "2"], capture_output=True, text=True, timeout=120, cwd="/",
                           env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"})
    except Exception:  # noqa: BLE001
        return None
    return r.returncode, (r.stdout or "") + (r.stderr or "")


def classify_lkm(lines):
    """"chkproc: Possible LKM Trojan installed": chkproc compares /proc and ps at two moments; a process that ended
    in between (or is now visible normally) is a false positive; a process present but missing from ps
    still needs checking (kernel-module rootkit). Without process numbers (chkrootkit runs chkproc without -v),
    chkproc is run again in verbose mode (2.9.7): nothing hidden any more → transient."""
    lines = [ln for ln in lines if ln.strip() and not SHELL_NOISE.match(ln.strip())]

    def pids_in(texts):
        found = []
        for ln in texts:
            for m in re.finditer(r"PID\s+(\d+)", ln):
                if int(m.group(1)) not in found:
                    found.append(int(m.group(1)))
        return found

    pids = pids_in(lines)
    if not pids:
        again = chkproc_verbose()
        if again is not None and again[0] == 0:
            return [{"path": "chkproc", "verdict": "benign", "reason": "lkm_transient"}]
        pids = pids_in(again[1].splitlines()) if again else []
    if not pids:
        return [{"path": "chkproc", "verdict": "unknown", "reason": "lkm"}]
    visible = set()
    r = run_quiet(["ps", "-eo", "pid="], timeout=20)
    for tok in (r.stdout or "").split():
        if tok.isdigit():
            visible.add(int(tok))
    notes = []
    for pid in pids:
        if not os.path.exists(f"/proc/{pid}"):
            notes.append({"path": f"PID {pid}", "verdict": "benign", "reason": "pid_transient"})
        elif pid in visible:
            notes.append({"path": f"PID {pid} ({_read_text(f'/proc/{pid}/comm') or '?'})", "verdict": "benign", "reason": "pid_visible"})
        else:
            notes.append({"path": f"PID {pid}", "verdict": "unknown", "reason": "pid_hidden"})
    return notes


def classify_ports(ports):
    """Who is really listening on these ports? Shipped by a package or a store application → benign; no process
    (transient detection, or last octet of an IP address taken for a port) → benign; program not from a
    package → to check."""
    listeners = listening_ports()
    octets = local_ip_octets()
    notes, exes = [], {}
    for port in ports:
        ls = [p for p in listeners if p["port"] == port]
        if not ls:
            reason = "port_ip_octet" if str(port) in octets else "port_closed"
            notes.append({"path": str(port), "verdict": "benign", "reason": reason})
            continue
        for p in ls:
            exe = ""
            try:
                exe = os.readlink(f"/proc/{p['pid']}/exe").split(" (deleted)")[0] if p.get("pid") else ""
            except OSError:
                exe = ""
            exes[(port, p["proto"], p["process"], exe)] = exe
    owners = dpkg_owners([e for e in exes.values() if e])
    for (port, proto, proc, exe), _ in exes.items():
        path = f"{port}/{proto} {proc or '?'}" + (f" ({exe})" if exe else "")
        if exe in owners:
            notes.append({"path": path, "verdict": "benign", "reason": "port_dpkg", "package": owners[exe].split(", ")[0]})
        elif exe.startswith(APP_STORE_PREFIXES):
            notes.append({"path": path, "verdict": "benign", "reason": "port_app"})
        else:
            notes.append({"path": path, "verdict": "unknown", "reason": "port_unknown"})
    return notes


def classify_bindshell(head):
    """Built-in verdict for "Potential bindshell installed: infected ports: …" (see classify_ports)."""
    m = re.search(r"infected ports:\s*(.*)", head, flags=re.I)
    if not m:
        return None
    ports = [int(p) for p in re.findall(r"\d+", m.group(1))]
    if not ports:
        return None
    return classify_ports(ports)


def chkrootkit_analysis(out):
    """chkrootkit -q output → {warnings, benign, notes}: "suspicious files" findings whose paths are all
    benign become known false positives (not counted); the others keep one note per path."""
    warnings, benign, notes = [], [], {}
    for text in parse_chkrootkit(out):
        lines = text.splitlines()
        head = lines[0].lower()
        verdicts = None
        if "bindshell" in head:
            verdicts = classify_bindshell(lines[0])
        elif head.startswith("checking `") and "infected" in head:
            verdicts = classify_infected_binary(lines[0])          # "Checking `ls'... INFECTED"
        elif "suckit" in head and "init" in head:
            verdicts = classify_init(lines[0])
        elif "chkproc" in head and "lkm" in head:
            verdicts = classify_lkm(lines[1:])
        elif "chkdirs" in head and "lkm" in head:
            verdicts = [{"path": ln.strip(), "verdict": "unknown", "reason": "lkm_dirs"} for ln in lines[1:]
                        if ln.strip() and not SHELL_NOISE.match(ln.strip())] or [{"path": "chkdirs", "verdict": "unknown", "reason": "lkm_dirs"}]
        elif "slapper" in head:
            verdicts = classify_ports(list(SLAPPER_PORTS))
        elif "scalper" in head:
            verdicts = classify_ports(list(SCALPER_PORTS))
        elif "bpfdoor" in head:
            verdicts = classify_bpfdoor(lines[1:])
        elif len(lines) > 1:
            paths = [chk_path(ln) for ln in lines[1:] if ln.strip().startswith("/")]
            if "suspicious files" in head:
                verdicts = classify_hidden_paths(paths)
            elif "xor.ddos" in head:
                verdicts = classify_tmp_paths(paths)
            elif "ifpromisc" in head:
                verdicts = classify_promisc(lines[1:])
        if verdicts is not None:
            if verdicts and all(n["verdict"] == "benign" for n in verdicts):
                benign.append({"text": text, "notes": verdicts})
                continue
            notes[text] = verdicts
        warnings.append(text)
    return {"warnings": warnings[:80], "benign": benign[:40], "notes": notes}


DEBSUMS_RULES_VERSION = 1
MINT_ADJUST_DIRS = ("/usr/share/linuxmint/adjustments", "/etc/linuxmint/adjustments")
_MINT_ADJ = {"at": 0.0, "patterns": [], "paths": set()}


def mint_adjustments():
    """Files that Linux Mint itself replaces or modifies at every boot (mintsystem "adjustments"):
    destination patterns of the .overwrite files (glob) and paths cited by the .execute/.menu files. 10 min cache."""
    if distro.is_rpm():
        return [], set()
    if time.time() - _MINT_ADJ["at"] < 600:
        return _MINT_ADJ["patterns"], _MINT_ADJ["paths"]
    patterns, paths = [], set()
    for base in MINT_ADJUST_DIRS:
        try:
            names = sorted(os.listdir(base))
        except OSError:
            continue
        for n in names:
            full = os.path.join(base, n)
            try:
                with open(full, encoding="utf-8", errors="replace") as f:
                    for ln in f:
                        ln = ln.strip()
                        if not ln or ln.startswith("#"):
                            continue
                        if n.endswith(".overwrite"):
                            parts = ln.split()
                            if len(parts) >= 2 and parts[1].startswith("/"):
                                patterns.append(parts[1])
                        else:
                            paths.update(m.group(1) for m in re.finditer(r"(/usr/[^\s'\"]+)", ln))
            except OSError:
                pass
    _MINT_ADJ.update(at=time.time(), patterns=patterns, paths=paths)
    return patterns, paths


def dpkg_diversions():
    if distro.is_rpm():
        return set()
    r = run_quiet(["dpkg-divert", "--list"], timeout=30)
    return set(re.findall(r"^diversion of (\S+) to ", r.stdout or "", flags=re.M))


# Images of icon themes, logos and wallpapers: often replaced on purpose (branding, a customised theme); they never run,
# so a change is reported as normal rather than as a modified system file
COSMETIC_DIRS = ("/usr/share/icons/", "/usr/share/pixmaps/", "/usr/share/backgrounds/", "/usr/share/wallpapers/")
COSMETIC_EXT = (".png", ".svg", ".svgz", ".xpm", ".jpg", ".jpeg", ".ico", ".gif", ".webp")


def classify_debsums(lines):
    """Built-in verdict for each file reported by debsums: replaced by the Mint adjustments, diverted by
    dpkg-divert (benign), otherwise modified since installation (to check)."""
    patterns, mentioned = mint_adjustments()
    diverted = dpkg_diversions()
    notes = []
    for ln in lines:
        path = ln.split()[0] if ln.strip() else ""
        if not path.startswith("/"):
            notes.append({"path": ln[:120], "verdict": "unknown", "reason": "modified"})
            continue
        if path in mentioned or any(fnmatch.fnmatch(path, p) for p in patterns):
            notes.append({"path": path, "verdict": "benign", "reason": "mint_adjustment"})
        elif path in diverted:
            notes.append({"path": path, "verdict": "benign", "reason": "diverted"})
        elif path.startswith(COSMETIC_DIRS) and path.lower().endswith(COSMETIC_EXT):
            notes.append({"path": path, "verdict": "benign", "reason": "cosmetic"})
        else:
            notes.append({"path": path, "verdict": "unknown", "reason": "modified"})
    return notes


def debsums_analysis(lines):
    """debsums lines (FAILED/REPLACED/missing) → {warnings, benign, notes} as for chkrootkit and Lynis."""
    out, benign, notes = [], [], {}
    for ln, note in zip(lines, classify_debsums(lines)):
        if note["verdict"] == "benign":
            benign.append({"text": ln, "notes": [note]})
        else:
            notes[ln] = [note]
            out.append(ln)
    return {"warnings": out[:80], "benign": benign[:80], "notes": notes}


_PROC_PID_RE = re.compile(r"^\d+ (?=\S)")        # "1234 comm /path" → "comm /path"
_TRACER_PID_RE = re.compile(r" \(\d+\) -> ")      # "gdb (4321) -> victim" → "gdb -> victim"
_PRELOAD_WHO_RE = re.compile(r" <- .*$")           # "lib.so (sha256 …) <- bash, plank" → "lib.so (sha256 …)"


def integrity_warning_norm(tool, text):
    """Text of a warning without what changes from one run to the next. For the process watch: without the
    PIDs or the line order, otherwise a restarted program is a "new" warning on every pass (red alert
    every 5 min, "That's normal" ineffective as soon as the PID changes). For a preloaded library
    (LD_PRELOAD): without the list of programs that carry it, inherited by everything they launch — it changed
    with every application opened, and the approval along with it."""
    if tool == "processes":
        lines = [re.sub(r"\s+", " ", ln).strip() for ln in (text or "").strip().splitlines() if ln.strip()]
        if len(lines) > 1:
            rest = {_TRACER_PID_RE.sub(" -> ", _PROC_PID_RE.sub("", ln)) for ln in lines[1:]}
            if lines[0].startswith("LD_PRELOAD"):
                rest = {_PRELOAD_WHO_RE.sub("", ln) for ln in rest}
            return "\n".join([lines[0]] + sorted(rest))
    return re.sub(r"\s+", " ", (text or "").strip())


def integrity_ack_key(tool, text):
    """Key of an approved warning ("That's normal"): tool + hash of the normalized text."""
    return f"{tool}:{hashlib.sha1(integrity_warning_norm(tool, text).encode()).hexdigest()[:16]}"


def watch_alert_fields(tool, text, notes):
    """Program, executable, reason and lines of a kernel/process watch warning, for a readable alert
    ("evilsleep — executable deleted from disk" rather than "1 — processes")."""
    lines = [ln.strip() for ln in (text or "").splitlines() if ln.strip()]
    note = next((x for x in (notes or []) if x.get("verdict") == "unknown"), None) or {}
    label = note.get("path") or (lines[1] if len(lines) > 1 else "")
    parts = label.split(" ", 2)
    by_pid = len(parts) >= 2 and parts[0].isdigit()
    comm = parts[1] if by_pid else (label.split(" (")[0].split(" <- ")[0].strip() or tool)
    return {"pid": int(parts[0]) if by_pid else 0, "comm": comm, "exe": parts[2] if by_pid and len(parts) == 3 else "",
            "reason": note.get("reason") or "", "items": lines[1:7], "head": lines[0] if lines else "", "label": label}


LYNIS_RULES_VERSION = 1


def classify_lynis_warning(test, text):
    """Built-in verdict for a known Lynis warning (the actual state is checked); None if unknown."""
    if test == "TIME-3185":
        # Lynis requires a flag file touched less than 2048 s ago; systemd-timesyncd spaces its adjustments
        # up to exactly 2048 s once the time is stable → frequent false positive. The actual state is authoritative.
        r = run_quiet(["timedatectl", "show", "-p", "NTP", "-p", "NTPSynchronized", "--value"], timeout=15)
        vals = (r.stdout or "").split()
        ntp_on, synced = (vals + ["", ""])[0] == "yes", (vals + ["", ""])[1] == "yes"
        if synced:
            return {"path": test, "verdict": "benign", "reason": "time_synced"}
        if not ntp_on:
            return {"path": test, "verdict": "unknown", "reason": "ntp_off", "fix": "TIME-3104"}
        return {"path": test, "verdict": "unknown", "reason": "time_stale", "fix": "TIME-3185"}
    if test == "KRNL-5788":
        return {"path": test, "verdict": "unknown", "reason": "reboot"}
    return None


def lynis_analysis(warnings):
    """Lynis warnings "TEST: text" → {warnings, benign, notes} as for chkrootkit."""
    out, benign, notes = [], [], {}
    for w in warnings or []:
        test = w.split(":", 1)[0].strip() if ":" in w else ""
        note = classify_lynis_warning(test, w) if re.fullmatch(r"[A-Z]{3,5}-\d{4}", test) else None
        if note and note["verdict"] == "benign":
            benign.append({"text": w, "notes": [note]})
            continue
        if note:
            notes[w] = [note]
        out.append(w)
    return {"warnings": out[:80], "benign": benign[:40], "notes": notes}


def run_integrity_checks(collect_verified=False, cancel_event=None, progress=None, trusted=None):
    """Lynis (hardening audit), unhide (hidden processes and ports), chkrootkit, debsums and the application's
    files. With collect_verified, also returns the set (hashes) of system files verified by debsums,
    which the antivirus can skip. `progress(name, percent, detail, state, warnings)` is called as things
    progress (tool output read continuously) for the display."""
    result = {"checked_at": now_iso(), "tools": {}, "app": app_integrity(), "warnings": 0, "verified_files": 0}
    verified = set()
    tools = {"kernel": ["uname"], "processes": ["ps"],
             "lynis": ["lynis", "audit", "system", "--quick", "--no-colors"],
             "unhide": ["unhide", "quick"],
             "unhide-tcp": ["unhide-tcp"],
             "chkrootkit": ["chkrootkit"]}
    if distro.is_rpm():
        tools["rpmverify"] = ["rpm", "-Va"]
    else:
        tools["debsums"] = ["debsums"]

    def report(name, percent, detail="", state="running", warnings=None):
        if progress is not None:
            try:
                progress(name, percent, detail, state, warnings)
            except Exception as e:  # noqa: BLE001
                log(f"Progression intégrité : {e}")

    for name, cmd in tools.items():
        if name in BUILTIN_CHECKS:
            report(name, 0, "", "running")
            try:
                entry = run_bounded(lambda _n=name: builtin_check(_n, trusted), BUILTIN_TIMEOUT)
            except Exception as e:  # noqa: BLE001
                log(f"Contrôle intégré {name} : {e}")
                entry = {"installed": True, "ran": False, "warnings": [], "rc": 1}
            report(name, 100, "", "done", len(entry["warnings"]))
            result["tools"][name] = entry
            result["warnings"] += len(entry["warnings"])
            continue
        entry = {"installed": shutil.which(cmd[0]) is not None, "ran": False, "warnings": [], "rc": None}
        if cancel_event is not None and cancel_event.is_set():
            result["tools"][name] = entry
            continue
        if not (entry["installed"] and os.geteuid() == 0):
            report(name, 100, "", "skipped")
        if entry["installed"] and os.geteuid() == 0:
            report(name, 0, "", "running")
            t0 = time.time()
            out, rc, stopped = _stream_tool(name, cmd, cancel_event, lambda pct, det, _n=name: report(_n, pct, det))
            entry["ran"] = True
            entry["rc"] = rc
            entry["seconds"] = int(time.time() - t0)
            partial = bool(stopped) or (cancel_event is not None and cancel_event.is_set())
            if stopped:                                 # tool stopped for lack of response: partial result, we continue
                entry["timed_out"] = stopped
                log(f"Intégrité : {name} arrêté ({stopped['reason']}, {stopped['after']} s) — dernière ligne : {stopped['last']!r}")
            lines = [ln.strip() for ln in out if ln.strip()]
            if name == "lynis" and partial:
                lines = []                              # unfinished report (index missing): no Lynis data this time
            elif name == "lynis":
                rep = parse_lynis_report()
                result["lynis"] = rep
                la = lynis_analysis(rep.get("warnings") or [])
                lines = la["warnings"]
                entry["benign"], entry["notes"], entry["rules"] = la["benign"], la["notes"], LYNIS_RULES_VERSION
            elif name in ("unhide", "unhide-tcp"):
                lines = [ln for ln in lines if "HIDDEN" in ln.upper() and "Found" in ln]
            elif name == "chkrootkit":
                chk = chkrootkit_analysis(out)
                lines = chk["warnings"]
                entry["benign"], entry["notes"], entry["rules"] = chk["benign"], chk["notes"], CHK_RULES_VERSION
            elif name == "rpmverify":
                ra = rpm_verify_analysis(lines)
                lines = ra["warnings"]
                entry["benign"], entry["notes"], entry["rules"] = ra["benign"], ra["notes"], RPM_VERIFY_RULES_VERSION
            elif name == "debsums":
                lines = [ln for ln in lines if "FAILED" in ln or "REPLACED" in ln or "missing file" in ln][:160]
                if collect_verified and not partial:              # interrupted pass: nothing is considered verified
                    verified = debsums_verified_paths(lines)      # every reported file remains to be scanned, benign or not
                    result["verified_files"] = len(verified)
                da = debsums_analysis(lines)
                lines = da["warnings"]
                entry["benign"], entry["notes"], entry["rules"] = da["benign"], da["notes"], DEBSUMS_RULES_VERSION
            entry["warnings"] = lines[:80]
            if stopped:
                report(name, 100, f"{stopped['reason']} {stopped['after']} s: {stopped['last']}"[:160], "timeout", len(entry["warnings"]))
            else:
                report(name, 100, "", "done", len(entry["warnings"]))
        result["tools"][name] = entry
        result["warnings"] += len(entry["warnings"])
    result["warnings"] += len(result["app"]["modified"]) + len(result["app"]["missing"])
    return (result, verified) if collect_verified else result


# ═══════════════════════════════════════════════════════════════════════════
# Daemon
# ═══════════════════════════════════════════════════════════════════════════

# ═══════════════════════════════════════════════════════════════════════════
# Email notifications (msmtp or any system mail server, via sendmail)
# ═══════════════════════════════════════════════════════════════════════════

MAIL_CONFIG_FILE = os.path.join(SYSTEM_STATE_DIR, "msmtprc") if TEST_MODE else "/etc/msmtprc"
MAIL_LOG_FILE = os.path.join(SYSTEM_LOG_DIR, "msmtp.log")
MAIL_MAX_PER_DAY = 30
MAIL_QUEUE_MAX = 200
MAIL_DEFAULT = {"enabled": False, "host": "", "port": 587, "security": "starttls", "user": "", "from": "", "to": [],
                "frequency": "daily", "hour": 8, "day": 0, "events": {"danger": True, "scan": False, "report": True, "monthly": True},
                "lang": "fr", "password_set": False, "last_sent": None, "last_error": "", "last_digest": "", "sent_day": "", "sent_today": 0}
MAIL_ADDR_RE = re.compile(r"^[A-Za-z0-9._%+'-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")
MAIL_HOST_RE = re.compile(r"^[A-Za-z0-9.-]{1,253}$")


def sendmail_path():
    return os.environ.get("DUKIWI_SHIELD_SENDMAIL") or shutil.which("sendmail") or "/usr/sbin/sendmail"


def mail_transport():
    """"msmtp" if sendmail is msmtp (SMTP settings written to /etc/msmtprc), otherwise the name of the system's mail
    server (postfix, exim4…), which will be used as is, or "" with no transport at all."""
    p = sendmail_path()
    if not os.path.exists(p):
        return ""
    real = os.path.basename(os.path.realpath(p))
    return "msmtp" if "msmtp" in real else (real or "sendmail")


def mail_read_password():
    try:
        with open(MAIL_CONFIG_FILE, encoding="utf-8") as f:
            for ln in f:
                if ln.startswith("password "):
                    return ln[len("password "):].rstrip("\n")
    except OSError:
        pass
    return ""


def mail_write_config(cfg, password):
    """/etc/msmtprc (root, 600): default account used by any program on the system that calls sendmail."""
    lines = ["# Généré par Dukiwi Shield — Paramètres › Notifications par courrier. Lisible par root seulement.",
             "defaults", f"logfile {MAIL_LOG_FILE}", "tls_trust_file /etc/ssl/certs/ca-certificates.crt", "",
             "account default", f"host {cfg['host']}", f"port {cfg['port']}", f"from {cfg['from']}"]
    sec = cfg.get("security")
    lines += ["tls on", "tls_starttls on"] if sec == "starttls" else (["tls on", "tls_starttls off"] if sec == "tls" else ["tls off"])
    if cfg.get("user"):
        lines += ["auth on", f"user {cfg['user']}", f"password {password}"]
    else:
        lines += ["auth off"]
    tmp = MAIL_CONFIG_FILE + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    os.chmod(tmp, 0o600)
    os.replace(tmp, MAIL_CONFIG_FILE)


def mail_build(cfg, subject, body):
    msg = email.message.EmailMessage()
    host = socket.gethostname()
    msg["From"] = cfg.get("from") or f"dukiwi-shield@{host}"
    msg["To"] = ", ".join(cfg.get("to") or [])
    msg["Subject"] = f"[Dukiwi Shield · {host}] {subject}"
    msg["Date"] = email.utils.formatdate(localtime=True)
    msg["Message-ID"] = email.utils.make_msgid(domain=host)
    msg["X-Mailer"] = f"Dukiwi Shield {VERSION}"
    msg.set_content(body)
    return msg.as_bytes()


def mail_send_now(cfg, subject, body):
    """Sends via sendmail -t (msmtp reads /etc/msmtprc; another mail server uses its own configuration)."""
    if not cfg.get("to"):
        return False, "no recipient"
    cmd = distro.sendmail_cmd()
    try:
        r = subprocess.run(cmd, input=mail_build(cfg, subject, body), capture_output=True, timeout=120)
    except Exception as e:  # noqa: BLE001
        return False, str(e)[:300]
    err = (r.stderr or b"").decode("utf-8", "replace").strip()
    return r.returncode == 0, ("" if r.returncode == 0 else (err or f"sendmail exit {r.returncode}")[-300:])


def mail_sanitize(incoming, current):
    """Settings received from the interface → valid configuration (without password) or (None, error)."""
    cfg = dict(MAIL_DEFAULT, **(current or {}))
    inc = incoming if isinstance(incoming, dict) else {}
    cfg["enabled"] = bool(inc.get("enabled", cfg["enabled"]))
    host = str(inc.get("host", cfg["host"]) or "").strip().lower()
    if host and not MAIL_HOST_RE.match(host):
        return None, "invalid_host"
    cfg["host"] = host
    try:
        port = int(inc.get("port", cfg["port"]))
    except (TypeError, ValueError):
        return None, "invalid_port"
    if not 1 <= port <= 65535:
        return None, "invalid_port"
    cfg["port"] = port
    sec = str(inc.get("security", cfg["security"]) or "starttls")
    if sec not in ("starttls", "tls", "none"):
        return None, "invalid_security"
    cfg["security"] = sec
    cfg["user"] = str(inc.get("user", cfg["user"]) or "").strip()[:200]
    sender = str(inc.get("from", cfg["from"]) or "").strip()
    if sender and not MAIL_ADDR_RE.match(sender):
        return None, "invalid_from"
    cfg["from"] = sender
    to_raw = inc.get("to", cfg["to"])
    if isinstance(to_raw, str):
        to_raw = re.split(r"[,;\s]+", to_raw)
    to = [a.strip() for a in (to_raw or []) if a and a.strip()]
    for a in to:
        if not MAIL_ADDR_RE.match(a):
            return None, "invalid_to"
    cfg["to"] = to[:10]
    freq = str(inc.get("frequency", cfg["frequency"]) or "daily")
    if freq not in ("immediate", "daily", "weekly"):
        return None, "invalid_frequency"
    cfg["frequency"] = freq
    try:
        cfg["hour"] = max(0, min(23, int(inc.get("hour", cfg["hour"]))))
        cfg["day"] = max(0, min(6, int(inc.get("day", cfg["day"]))))
    except (TypeError, ValueError):
        return None, "invalid_time"
    ev = inc.get("events", cfg["events"])
    if isinstance(ev, dict):
        cfg["events"] = {k: bool(ev.get(k, (cfg["events"] or {}).get(k, MAIL_DEFAULT["events"][k]))) for k in ("danger", "scan", "report", "monthly")}
    lang = str(inc.get("lang", cfg["lang"]) or "fr")
    cfg["lang"] = lang if lang in LANGUAGES else "fr"
    if cfg["enabled"] and (not cfg["to"] or (mail_transport() == "msmtp" and not cfg["host"])):
        return None, "incomplete"
    return cfg, ""


class Daemon:
    def __init__(self):
        self.state = State()
        self.subscribers = []
        self.sub_lock = threading.Lock()
        self.queue = deque()
        self.usb_priority_job = None            # USB key scanned while a scan is paused
        self.last_mail_tick = 0.0
        self.queue_lock = threading.Condition()
        self.current = None
        self.shutdown = threading.Event()
        self.server = None
        self.last_first_scan_attempt = 0
        self.settings = Settings()
        self._check_cache = {}
        self.monitor = ActivityMonitor(self)
        self.onaccess = OnAccessScanner(self)
        self.hid_guard = HidGuard(self)
        self.guard = dukiwi_shield_guard.SecurityGuard(self, {"log": log, "write_log": self.write_log, "exe_trusted": self.monitor.exe_trusted,
                                                               "dconf_read": dconf_read, "human_users": human_users})
        self.folders = dukiwi_shield_folders.ProtectedFolders(self, {"log": log, "write_log": self.write_log})
        self.network = NetworkMonitor(self)
        self.connections = ConnectionMonitor(self)
        self.updater = UpdateChecker(self)
        self.usb = UsbWatcher(self)
        self.honeypot = dukiwi_shield_honeypot.Honeypot(self, {"log": log, "write_log": self.write_log, "ufw": self.ufw,
                                                         "parse_ufw_numbered": parse_ufw_numbered})
        self.urlguard = dukiwi_shield_urlguard.UrlGuard(self, URLGUARD_DIR, log=log)
        self.last_urlguard_check = 0.0
        self.unlocked = {}          # uid -> (expiry, token): administrator session, valid only with its token
        self.suspended = {}         # pid -> info (processes suspended by the automatic response)
        self._dns_lock = threading.Lock()
        self._persistence_lock = threading.Lock()
        programs = self.state.get("trusted_programs") or []
        # Old approvals of an AppImage recorded by mount path: that path will never come back
        stale = [p for p in programs if APPIMAGE_MOUNT_RE.match(p.get("exe") or "") and not p.get("sha256")
                 and not os.path.exists(p.get("exe") or "")]
        if stale:
            programs = [p for p in programs if p not in stale]
            self.state.update(trusted_programs=programs)
            log(f"Programmes de confiance : {len(stale)} ancienne(s) approbation(s) d'AppImage retirée(s) (montage disparu)")
        self._trusted_set = TrustedPrograms(programs)
        self.policy = {}
        self.locked_settings = set()
        self.central_patterns = []
        self.load_central_allowlist()
        try:
            stored_vulns = self.state.get("vulns") or {}
            current_eco = ubuntu_osv_ecosystem() if not distro.is_rpm() else ""
            if stored_vulns and stored_vulns.get("ecosystem") != (current_eco or "unsupported"):
                # Report made for another Ubuntu version (upgrade, or 24.04 assumed by default before 1.24.3):
                # discarded, the daily check redoes it within the minute on the right ecosystem.
                log(f"Failles : relevé {stored_vulns.get('ecosystem')!r} écarté, le système est {current_eco or 'unsupported'!r}")
                stored_vulns = {}
            if stored_vulns.get("items") and any(k not in (stored_vulns.get("counts") or {}) for k in ("na_vendor", "na_headers")) \
                    or (stored_vulns.get("items") and "context" not in stored_vulns):
                stored_vulns = reclassify_vulns(stored_vulns)
                log("Failles : relevé reclassé (moteur JavaScript intégré)")
            if stored_vulns.get("items") and (self.state.get("acknowledged_vulns") or "acknowledged" not in (stored_vulns.get("counts") or {})):
                stored_vulns = apply_vuln_acks(stored_vulns, self.state.get("acknowledged_vulns") or {})
            if stored_vulns is not (self.state.get("vulns") or {}):
                self.state.update(vulns=stored_vulns)
        except Exception as e:  # noqa: BLE001
            log(f"Reclassement des failles : {e}")
        self.apply_policy(startup=True)
        self.last_daily = 0
        self.timeshift_enabling = False
        self.hardening_running = False
        self.integrity_progress = None         # {"tools": {outil: {percent, detail, state, warnings}}, "current", "started_at"}
        self.tray_stopped = {}                 # uid → {session ids} where the administrator quit the shield
        self.tray_launched = {}                # uid → dernier lancement (anti-rafale)
        self.last_tray_check = 0.0
        self.last_integrity_emit = 0.0
        self.current_network = None            # current network {key, name, type, device}, None when offline
        self.network_lock = threading.Lock()
        self.last_integrity = 0
        self.integrity_running = False
        self.daily_running = False
        self.overall = {"color": "green", "reasons": []}
        self.security = None
        self.security_lock = threading.Lock()
        self.last_security = 0
        self.last_weekly_check = 0
        self.system_status_lock = threading.Lock()
        self.system_status_running = False
        self.system_upgrade_running = False
        self.last_system_status = 0

    def current_job(self):
        with self.queue_lock:
            return self.current

    # ── Broadcast to subscribers ─────────────────────────────────────────
    def broadcast(self, event, private=None, may_see=None):
        """Sends event to every GUI. With may_see(uid): subscribers for whom it is False get `private` instead
        (None: nothing) — file names of a scan only reach the account that started it and the administrators."""
        with self.sub_lock:
            dead = []
            for sub in self.subscribers:
                try:
                    if may_see is None or may_see(getattr(sub, "uid", -1)):
                        sub.send(event)
                    elif private is not None:
                        sub.send(private)
                except (OSError, socket.timeout):
                    dead.append(sub)
            for sub in dead:
                self.subscribers.remove(sub)
                sub.close()

    def job_viewer(self, job):
        """Who may see the file names of a job: the account that started it, root and administrators (system jobs:
        administrators only)."""
        owner = getattr(job, "requested_by", None) if job else None

        def may_see(uid):
            if uid == 0 or (isinstance(owner, int) and uid == owner):
                return True
            return uid > 0 and any(g in ADMIN_GROUPS for g in uid_groups(uid))
        return may_see

    def emit_line(self, kind, text):
        self.broadcast({"event": "line", "kind": kind, "text": text}, may_see=self.job_viewer(self.current))

    def emit_progress(self, job):
        payload = job.public()
        if job.phase == "integrity" and self.integrity_progress:
            payload["integrity_progress"] = self.integrity_progress
        public = dict(payload, file="", threats=[], path=payload.get("path") if job.kind != "scan" else "")
        self.broadcast({"event": "progress", **payload}, private={"event": "progress", **public}, may_see=self.job_viewer(job))

    def integrity_progress_cb(self, name, percent, detail, state, warnings):
        """Callback of the integrity tools: per-tool state broadcast (at most every 0.4 s, unless the state changes)."""
        if self.integrity_progress is None:
            self.integrity_progress = {"tools": {}, "current": None, "started_at": now_iso()}
        prev = self.integrity_progress["tools"].get(name) or {}
        now = time.time()
        since = (prev.get("since") if prev.get("state") == "running" else None) or now
        self.integrity_progress["tools"][name] = {"percent": percent, "detail": detail, "state": state, "warnings": warnings, "since": since}
        self.integrity_progress["current"] = name if state == "running" else self.integrity_progress.get("current")
        if state != prev.get("state") and state in ("done", "timeout"):
            # One line per tool in the log: in case of slowness or a hang, you see which one and for how long
            took = int(now - since)
            if state == "timeout":
                self.write_log(f"⚠ integrity: {name} stopped after {took} s, no answer ({detail})")
                self.emit_line("info", f"⚠ integrity: {name} stopped after {took} s (no answer), continuing")
            elif name not in BUILTIN_CHECKS:
                self.write_log(f"integrity: {name} done in {took} s, {warnings or 0} warning(s)")
        if state != prev.get("state") or now - self.last_integrity_emit >= 0.4:
            self.last_integrity_emit = now
            self.broadcast({"event": "integrity_progress", **self.integrity_progress})

    def publish_alert(self, alert):
        pid = alert.get("pid") or 0
        if alert.get("severity") == "danger" and pid > 1 and pid != os.getpid() \
                and self.settings.get("auto_response") and alert.get("kind") in ("burst", "connection", "ransomware", "miner"):
            try:
                os.kill(pid, signal.SIGSTOP)
                alert["suspended"] = True
                self.suspended[pid] = {"pid": pid, "comm": alert.get("comm"), "exe": alert.get("exe"),
                                       "time": now_iso(), "kind": alert.get("kind")}
                self.write_log(f"⏸ suspended pid {pid} ({alert.get('comm')})")
            except OSError:
                alert["suspended"] = False
        self.state.prepend("alerts", alert, ALERTS_MAX)
        if alert.get("severity") == "danger":
            self.mail_alert_event(alert)
        if alert.get("kind") == "upload":
            self.write_log(f"⚠ upload: {alert.get('gb')} GB sent in {alert.get('window_hours')} h "
                           f"(threshold {alert.get('threshold_gb')} GB)")
            log(f"Alerte envoi Internet : {alert.get('gb')} Go en {alert.get('window_hours')} h")
        elif alert.get("kind") == "connection":
            self.write_log(f"⚠ connection {alert['severity']}: {alert.get('comm')} (pid {alert.get('pid')}) → {alert.get('ip')}:{alert.get('port')} {alert.get('country', '')}")
        elif alert.get("kind") in ("persistence", "integrity", "update", "timeshift", "download", "usb_keyboard", "network", "account"):
            self.write_log(f"⚠ {alert.get('kind')}: {alert.get('title', '')} {alert.get('detail', '')}")
        elif alert.get("kind") in ("mail", "url"):
            self.write_log(f"⚠ {alert.get('kind')} {alert.get('severity')}: {alert.get('title', '')} — {alert.get('detail', '')} ({alert.get('source', '')})")
        elif alert.get("kind") in ("ransomware", "privacy", "miner", "certificate", "redirect", "extension", "ssh_key", "suid", "keylogger", "login", "dev_package", "protected"):
            pass                                        # logged by the security centre (dukiwi_shield_guard)
        elif alert.get("kind") == "honeypot":
            self.write_log(f"⚠ honeypot {alert.get('severity')}: {alert.get('ip')} ({alert.get('host') or '?'}) "
                           f"{alert.get('detail', '')} — {', '.join(alert.get('reasons') or [])}")
        else:
            self.write_log(f"⚠ {alert['severity']}: {alert['comm']} (pid {alert['pid']}, {alert.get('exe')}) "
                           f"modified {alert['count']} files in {alert['window']} s — {alert['top_dir']}")
            log(f"Alerte {alert['severity']} : {alert['comm']} pid {alert['pid']} {alert['count']} fichiers")
        self.broadcast({"event": "alert", "alert": alert})
        self.refresh_overall()

    # ── Journal ──────────────────────────────────────────────────────────
    def write_log(self, text):
        try:
            with open(SYSTEM_LOG_FILE, "a") as f:
                f.write(f"[{now_iso()}] {text}\n")
        except OSError:
            pass

    def rotate_log(self):
        try:
            if os.path.getsize(SYSTEM_LOG_FILE) > LOG_MAX_BYTES:
                with open(SYSTEM_LOG_FILE) as f:
                    lines = f.readlines()[-2000:]
                with open(SYSTEM_LOG_FILE, "w") as f:
                    f.writelines(lines)
        except OSError:
            pass

    # ── File d'attente ───────────────────────────────────────────────────
    def enqueue(self, job):
        with self.queue_lock:
            waiting = self.current is not None or len(self.queue) > 0
            self.queue.append(job)
            self.queue_lock.notify()
        self.broadcast({"event": "job_queued", "job": job.public(), "waiting": waiting})
        return job

    def worker(self):
        while not self.shutdown.is_set():
            with self.queue_lock:
                while not self.queue and not self.shutdown.is_set():
                    self.queue_lock.wait(timeout=1)
                if self.shutdown.is_set():
                    return
                job = self.queue.popleft()
                self.current = job
            try:
                job.started_at = time.time()
                job.phase = "prepare"
                self.broadcast({"event": "job_started", "job": job.public()})
                if job.kind == "scan":
                    self.run_scan(job)
                else:
                    self.run_update(job)
            except Exception as e:  # noqa: BLE001
                log(f"Erreur job {job.kind}: {e}")
                self.finish(job, "error", "msg.scan.internal", {"error": str(e)})
            finally:
                with self.queue_lock:
                    self.current = None
                self._after_job(job)

    def _after_job(self, job):
        """Removable media: unmount of the private mount and usb_done event (result popup)."""
        if job.usb:
            if job.usb.get("private_mount"):
                self.usb.unmount(job.usb["devnode"])
            status, key, params = job.result or ("error", "msg.scan.internal", {})
            self.broadcast({
                "event": "usb_done", "usb": job.usb, "status": status,
                "msg_key": key, "msg_params": params, "infected": job.infected,
                "files": job.total + job.cached, "cached": job.cached, "threats": job.threats[-50:],
                "removed": bool(job.usb.get("removed")), "skipped": bool(job.usb.get("skipped")),
            })

    def _run_priority(self, job, paused):
        """USB key during a scan: the scan is paused, the key is scanned right away, then the scan resumes."""
        paused.pause()
        self.usb_priority_job = job
        self.write_log(f"⏸ paused {paused.path} for USB {job.usb.get('label') or job.usb.get('devnode')}")
        self.emit_line("info", f"⏸ paused for USB {job.usb.get('label') or job.usb.get('devnode')}")
        self.broadcast({"event": "job_paused", "job": paused.public()})
        try:
            job.started_at = time.time()
            job.phase = "prepare"
            self.broadcast({"event": "job_started", "job": job.public()})
            self.run_scan(job)
        except Exception as e:  # noqa: BLE001
            log(f"Erreur job USB : {e}")
            self.finish(job, "error", "msg.scan.internal", {"error": str(e)})
        finally:
            try:
                self._after_job(job)
            except Exception as e:  # noqa: BLE001
                log(f"Fin du job USB : {e}")
            self.usb_priority_job = None
            paused.unpause()
            self.write_log(f"▶ resumed {paused.path}")
            self.emit_line("info", "▶ resumed")
            self.broadcast({"event": "job_started", "job": paused.public(), "resumed": True})

    def finish(self, job, status, key, params=None, summary=None):
        job.phase = "done"
        params = params or {}
        job.result = (status, key, params)
        self.broadcast({
            "event": "job_done", "id": job.id, "kind": job.kind, "path": job.path,
            "status": status, "msg_key": key, "msg_params": params,
            "message": t("en", key, **params), "summary": summary or {},
            "auto": job.auto, "usb": job.usb, "integrity": getattr(job, "integrity", False),
            "integrity_warnings": getattr(job, "integrity_warnings", None), "skipped": getattr(job, "skipped", 0),
            "elapsed": time.time() - (job.started_at or time.time()),
        })
        if job.kind == "scan" and status in ("clean", "infected") and (not job.usb or job.infected):
            self.mail_scan_event(job, status)
        if job.kind == "scan" and not job.usb and status in ("clean", "infected") and self.settings.get("telemetry") \
                and not self.state.get("telemetry_scan_sent"):
            # First full scan since consent: report sent without waiting for the week (performance measurements)
            self.state.update(telemetry_scan_sent=True)
            threading.Thread(target=lambda: self.send_telemetry(force=True), daemon=True).start()

    # ── Scan ─────────────────────────────────────────────────────────────
    def _save_progress(self, job, in_progress=True):
        if job.usb:
            return   # no resume for a removable drive
        try:
            tmp = SYSTEM_PROGRESS_FILE + ".tmp"
            with open(tmp, "w") as f:
                json.dump({
                    "path": job.path, "total": job.total, "scanned": job.scanned,
                    "last_file": job.current_file, "in_progress": in_progress,
                    "auto": job.auto, "infected": job.infected,
                }, f)
            os.chmod(tmp, 0o644)
            os.replace(tmp, SYSTEM_PROGRESS_FILE)
        except OSError:
            pass

    def load_progress(self):
        try:
            with open(SYSTEM_PROGRESS_FILE) as f:
                return json.load(f)
        except Exception:
            return {}

    def _count_files(self, job, cache, skip=None, scache=None, manifest=None):
        """Inventory phase: find (with hashes) → cache file, streamed.
        `skip`: hashes of the system files verified by debsums. `scache`: cache of clean files (disk);
        `manifest`: .clamav manifest of the removable media. Unchanged files already checked are not reread."""
        job.phase = "counting"
        job.found = 0
        job.cached = 0
        self.emit_progress(job)
        if job.usb:
            cmd = find_command(job.path, exclude=[], stat=True)
        elif job.paths:
            cmd = find_command(job.paths, exclude=QUICK_SCAN_EXCLUDE, stat=True)
        else:
            cmd = find_command(job.path, stat=True)
        with job.proc_lock:
            job.proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
                                        errors="surrogateescape", bufsize=1)
        last_emit = time.time()
        batch = []
        bad_names = 0
        mf_files = (manifest or {}).get("files") or {}
        root = job.path.rstrip("/") + "/"

        def flush(out):
            nonlocal batch
            if not batch:
                return
            keep, batch = batch, []
            clean = set()
            if scache is not None and job.use_cache:
                try:
                    clean = scache.lookup(keep)
                except Exception as e:  # noqa: BLE001
                    log(f"Cache de scan : {e}")
            for e in keep:
                if e[0] in clean:
                    job.cached += 1
                    continue
                out.write("\t".join(str(x) for x in e) + "\n")
                job.found += 1

        with open(cache, "w") as out:
            for line in job.proc.stdout:
                if job.cancel_event.is_set():
                    break
                if not line.strip():
                    continue
                e = parse_find_line(line)
                try:
                    e[0].encode("utf-8")
                except UnicodeEncodeError:
                    bad_names += 1                                # name that is not UTF-8: reported further down
                    continue
                if skip and hash(e[0]) in skip:
                    job.skipped += 1
                    continue
                if job.usb:
                    rel = e[0][len(root):] if e[0].startswith(root) else os.path.relpath(e[0], job.path)
                    if rel in (USB_MANIFEST, USB_MANIFEST + ".tmp", USB_MANIFEST_LEGACY):
                        continue                                  # the manifest itself
                    m = mf_files.get(rel)
                    if m and len(m) >= 2 and m[0] == e[1] and m[1] == e[2]:
                        job.cached += 1                           # unchanged since the last scan
                        job.manifest_keep[rel] = [e[1], e[2]]
                        continue
                batch.append(e)
                if len(batch) >= 500:
                    flush(out)
                if time.time() - last_emit >= PROGRESS_INTERVAL:
                    self.emit_progress(job)
                    last_emit = time.time()
            flush(out)
        job.proc.wait()
        if bad_names:
            # File name that is not UTF-8 (old encoding on an ext4 disk, drive mounted without the utf8
            # option…): the rest of the scan handles paths as text and cannot pass it to the engine.
            # The file is not scanned, but it is counted and reported — before, a single such name made the
            # whole scan fail ("Internal error: 'utf-8' codec can't decode byte…").
            job.errors += bad_names
            msg = f"⚠ {bad_names} file(s) not scanned: file name is not valid UTF-8"
            self.write_log(msg)
            self.emit_line("error", msg)
        return job.found

    def _resume_offset(self, job):
        """Resume index in the cache, or None if resuming is impossible."""
        prog = self.load_progress()
        if not (prog.get("in_progress") and prog.get("path") == job.path):
            return None
        if not os.path.exists(SYSTEM_FILELIST_CACHE):
            return None
        last_file = prog.get("last_file") or ""
        total = 0
        idx = None
        with open(SYSTEM_FILELIST_CACHE) as f:
            for i, line in enumerate(f):
                total += 1
                if idx is None and last_file and line.split("\t", 1)[0] == last_file:
                    idx = i + 1
        job.total = total
        job.infected = int(prog.get("infected", 0) or 0)
        return idx if idx is not None else 0

    def run_scan(self, job):
        self.rotate_log()
        start_idx = 0
        resumed = False
        cache = SYSTEM_FILELIST_CACHE + (".usb" if job.usb else "")
        days = int(self.settings.get("scan_cache_days") or 0)
        scache = None
        manifest = None
        if job.usb:
            manifest = usb_manifest_read(job.path) if job.use_cache else None
            if manifest and not manifest_fresh(manifest, days):
                manifest = None
        else:
            try:
                scache = ScanCache(SYSTEM_SCAN_CACHE_DB, days)
            except Exception as e:  # noqa: BLE001
                log(f"Cache de scan indisponible : {e}")

        if job.resume and not job.usb:
            idx = self._resume_offset(job)
            if idx is not None:
                start_idx, resumed = idx, True
            else:
                job.resume = False

        skip = None
        if not resumed:
            label = "usb " if job.usb else ("auto " if job.auto else "")
            self.write_log(f"▶ scan {label}{job.path}" + ("" if job.use_cache else " (cache ignored)")
                           + (" (manifest)" if manifest else ""))
            self.emit_line("info", f"▶ {job.path}")
            if job.integrity and not job.usb:
                # Full scan: integrity first (rootkits, packages, application files);
                # system files confirmed intact by debsums are then skipped by the antivirus.
                job.phase = "integrity"
                self.emit_progress(job)
                self.emit_line("info", "▶ integrity (Lynis, unhide, chkrootkit, debsums)")
                self.integrity_progress = None
                result, skip = run_integrity_checks(collect_verified=True, cancel_event=job.cancel_event,
                                                    progress=self.integrity_progress_cb, trusted=self.trusted_map())
                self.integrity_progress = None
                if not job.cancel_event.is_set():
                    self._store_integrity(result, after_scan=True)
                    job.integrity_warnings = result.get("warnings", 0)
                    self.write_log(f"integrity: {result.get('warnings', 0)} warning(s), {len(skip)} verified system files")
                    self.emit_line("info", f"✓ integrity: {result.get('warnings', 0)} warning(s), {len(skip)} verified files skipped")
            total = self._count_files(job, cache, skip, scache=scache, manifest=manifest)
            skip = None
            if job.cancel_event.is_set():
                if job.cancelled_by_user:
                    self._forget_auto(job)
                self._save_progress(job, in_progress=False)
                self._close_cache(scache)
                self.finish(job, "cancelled", "msg.scan.cancelled_counting", {}, self._summary(job))
                return
            job.total = total
            job.infected = 0
            job.scanned = 0
            self._save_progress(job, in_progress=True)
        else:
            job.scanned = start_idx
            self.write_log(f"▶ resume {job.path} ({start_idx}/{job.total})")
            self.emit_line("info", f"▶ {start_idx} / {job.total}")

        if job.total == 0:
            self._save_progress(job, in_progress=False)
            self._record_scan(job, "clean")
            if job.usb:
                self._write_usb_manifest(job)
            self._close_cache(scache)
            if job.cached:
                key, params = "msg.scan.clean_cached", {"files": job.cached, "cached": job.cached}
            else:
                key, params = "msg.scan.nofiles", {}
            self.write_log(f"■ done: nothing to scan ({job.cached} cached)")
            self.finish(job, "clean", key, params, self._summary(job))
            return

        # List of remaining files (streaming copy)
        tmp_list = cache + ".tmp"
        with open(cache) as src, open(tmp_list, "w") as dst:
            for i, line in enumerate(src):
                if i >= start_idx:
                    dst.write(line)

        job.phase = "scanning"
        self.emit_progress(job)
        use_clamd = shutil.which("clamdscan") is not None and not os.environ.get("DUKIWI_SHIELD_NO_CLAMD") \
            and (clamd_ping() if TEST_MODE else ensure_clamd())
        job.engine = "clamd" if use_clamd else "clamscan"
        self.emit_line("info", f"▶ {job.engine} × {job.total}"
                       + (f" · {job.cached} unchanged (already verified)" if job.cached else "")
                       + (f" · {job.skipped} verified by debsums" if job.skipped else ""))
        if use_clamd:
            rc = self._scan_with_clamd(job, tmp_list, scache)
        else:
            rc = self._scan_with_clamscan(job, tmp_list, scache)

        if job.cancel_event.is_set():
            if job.cancelled_by_user:
                self._forget_auto(job)
            self._save_progress(job, in_progress=True)
            self._close_cache(scache)
            self.write_log(f"■ interrupted {job.scanned}/{job.total}")
            self.finish(job, "cancelled", "msg.scan.cancelled",
                        {"scanned": job.scanned, "total": job.total}, self._summary(job))
            return

        job.scanned = job.total
        job.current_file = ""
        self._save_progress(job, in_progress=False)
        for p in (tmp_list, tmp_list + ".paths"):
            try:
                os.remove(p)
            except OSError:
                pass

        if rc not in (0, 1, 2):
            self._record_scan(job, "error")
            self._close_cache(scache)
            self.finish(job, "error", "msg.scan.failed", {"code": rc}, self._summary(job))
            return

        status = "infected" if job.infected > 0 else "clean"
        self._record_scan(job, status)
        if job.usb:
            self._write_usb_manifest(job)
        if scache is not None:
            try:
                scache.purge(max(90, days * 3))
            except Exception:  # noqa: BLE001
                pass
        self._close_cache(scache)
        if job.infected:
            key, params = "msg.scan.infected", {"count": job.infected}
        elif job.cached:
            key, params = "msg.scan.clean_cached", {"files": job.total + job.cached, "cached": job.cached}
        else:
            key, params = "msg.scan.clean", {"files": job.total}
        self.write_log(f"■ done: {job.infected} infected / {job.total} files ({job.engine}, {job.cached} cached, "
                       f"{round(time.time() - (job.started_at or time.time()))} s)")
        self.finish(job, status, key, params, self._summary(job))

    @staticmethod
    def _close_cache(scache):
        if scache is not None:
            try:
                scache.close()
            except Exception:  # noqa: BLE001
                pass

    def _write_usb_manifest(self, job):
        """.clamav manifest at the root of the media: clean files (hashes) for a quick scan next time."""
        files = dict(job.manifest_keep)
        if len(files) > MANIFEST_MAX_FILES:
            self.write_log(f"usb manifest skipped ({len(files)} files)")
            return
        ok = usb_manifest_write(job.path, files, signature_db_version(), job.usb_infected)
        self.write_log(f"usb manifest {'written' if ok else 'not written'}: {len(files)} clean file(s)")

    def _record_clean(self, job, clean, scache):
        """Clean files of a batch: disk cache (hash taken during the inventory) or manifest of the media."""
        if not clean:
            return
        if job.usb:
            root = job.path.rstrip("/") + "/"
            with job.count_lock:
                for e in clean:
                    rel = e[0][len(root):] if e[0].startswith(root) else os.path.relpath(e[0], job.path)
                    job.manifest_keep[rel] = [e[1], e[2]]
        elif scache is not None:
            try:
                scache.record(clean)
            except Exception as e:  # noqa: BLE001
                log(f"Cache de scan : {e}")

    def _scan_line(self, job, line, by_path, clean):
        """One clamdscan line: "path: OK", "path: Signature FOUND", "path: … ERROR"."""
        if line.endswith(": OK"):
            path = line[:-4]
            with job.count_lock:
                job.scanned += 1
                job.current_file = path
            e = by_path.get(path)
            if e:
                clean.append(e)
            return True
        if line.endswith(" FOUND"):
            path, _, sig = line[:-6].rpartition(": ")
            with job.count_lock:
                job.scanned += 1
                job.infected += 1
                job.current_file = path
                job.threats.append({"path": path, "signature": sig, "time": now_iso()})
                job.found_sigs[path] = sig
                if job.usb:
                    job.usb_infected.add(os.path.relpath(path, job.path))
            self.write_log(line)
            self.emit_line("found", line)
            return True
        if line.endswith(" ERROR"):
            path, _, msg = line[:-6].rpartition(": ")
            denied = "denied" in msg.lower() or "permission" in msg.lower()
            with job.count_lock:
                if path in by_path:
                    job.scanned += 1
                    job.current_file = path
                if denied:
                    job.denied += 1
                else:
                    job.errors += 1
            self.write_log(line)
            self.emit_line("denied" if denied else "error", line)
            return True
        if " moved to " in line:
            moved = parse_moved_line(line)
            if moved:
                quarantine_index_add(SYSTEM_QUARANTINE_DIR, moved[1], moved[0], job.found_sigs.get(moved[0], ""))
            self.emit_line("info", line)
            return False
        if not is_noise_line(line):
            self.emit_line(classify_line(line), line)
        return False

    def _scan_with_clamd(self, job, tmp_list, scache):
        """clamd keeps the database in memory: several clamdscan --fdpass in parallel, each on a batch of files
        (the descriptor is passed to clamd, which reads the files with the service's rights)."""
        cpu = os.cpu_count() or 2
        workers = max(2, min(SCAN_WORKERS_MAX, cpu // 2))
        if job.usb:
            workers = min(workers, 3)              # a key's throughput comes from the drive, not the CPU
        prefix = ["nice", "-n", "15", "ionice", "-c", "2", "-n", "7"] if job.auto else ["nice", "-n", "5", "ionice", "-c", "2", "-n", "4"]
        if not shutil.which("ionice"):
            prefix = prefix[:2]
        src = open(tmp_list)
        src_lock = threading.Lock()
        state = {"rc": 0, "fatal": False, "fallbacks": 0, "fallback_lock": threading.Lock(),
                 "last_emit": time.time(), "last_save": time.time()}
        emit_lock = threading.Lock()

        def next_batch():
            with src_lock:
                batch = []
                for line in src:
                    if line.strip():
                        batch.append(parse_find_line(line))
                        if len(batch) >= SCAN_BATCH:
                            break
                return batch

        def tick():
            now = time.time()
            with emit_lock:
                if now - state["last_emit"] >= PROGRESS_INTERVAL:
                    state["last_emit"] = now
                    self.emit_progress(job)
                if now - state["last_save"] >= PROGRESS_SAVE_INTERVAL:
                    state["last_save"] = now
                    self._save_progress(job, in_progress=True)

        def worker(idx):
            list_path = f"{tmp_list}.w{idx}"
            while not job.cancel_event.is_set() and not state["fatal"]:
                while job.pause_event.is_set() and not job.cancel_event.is_set():
                    time.sleep(0.5)
                batch = next_batch()
                if not batch:
                    break
                by_path = {e[0]: e for e in batch}
                with open(list_path, "w") as f:
                    f.write("".join(e[0] + "\n" for e in batch))
                cmd = prefix + ["clamdscan"] + distro.clamdscan_args() + ["--fdpass", "--no-summary", "--stdout",
                                f"--move={SYSTEM_QUARANTINE_DIR}", f"--file-list={list_path}"]
                clean, seen, rc_b, tail = self._run_clamdscan_batch(job, cmd, by_path, tick)
                if rc_b == 2 and seen == 0 and not job.cancel_event.is_set():
                    # Batch refused without any file being processed (clamd unreachable, descriptor refused…):
                    # wait for clamd and retry once, otherwise this batch goes through clamscan; at the 5th failed
                    # batch, the rest of the scan switches to clamscan instead of failing.
                    self.write_log(f"clamdscan batch failed (rc 2, {len(batch)} files): {tail[:200]}")
                    if ensure_clamd(wait=60):
                        clean, seen, rc_b, tail = self._run_clamdscan_batch(job, cmd, by_path, tick)
                    if rc_b == 2 and seen == 0 and not job.cancel_event.is_set():
                        state["fallbacks"] += 1
                        with state["fallback_lock"]:
                            rc_b = self._scan_batch_with_clamscan(job, batch, list_path + ".fb", scache)
                        clean = []
                        if state["fallbacks"] >= 5:
                            state["fatal"] = True
                if rc_b not in (0, 1, 2):
                    state["rc"] = rc_b
                self._record_clean(job, clean, scache)
            try:
                os.remove(list_path)
            except OSError:
                pass

        threads = [threading.Thread(target=worker, args=(i,), daemon=True, name=f"scan-{i}") for i in range(workers)]
        for th in threads:
            th.start()
        for th in threads:
            th.join()
        if state["fatal"] and not job.cancel_event.is_set():
            # clamd out of service: the rest of the list through clamscan (slower, but the scan completes)
            rest, n = tmp_list + ".rest", 0
            with open(rest, "w") as f:
                for line in src:
                    if line.strip():
                        f.write(line)
                        n += 1
            src.close()
            self.write_log(f"clamd engine unavailable: {n} remaining file(s) scanned with clamscan")
            self.emit_line("info", f"▶ clamscan × {n} (clamd unavailable)")
            job.engine = "clamscan"
            rc = self._scan_with_clamscan(job, rest, scache) if n else 0
            for p in (rest, rest + ".paths"):
                try:
                    os.remove(p)
                except OSError:
                    pass
            return 1 if job.infected else rc
        src.close()
        return 1 if job.infected else state["rc"]

    def _run_clamdscan_batch(self, job, cmd, by_path, tick):
        """One batch per clamdscan: (clean files, processed files, return code, last non-file lines)."""
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
        except OSError as e:
            return [], 0, 2, str(e)
        with job.proc_lock:
            job.procs.append(proc)
        clean, seen, tail = [], 0, []
        for raw in proc.stdout:
            line = raw.rstrip("\n")
            if not line:
                continue
            if self._scan_line(job, line, by_path, clean):
                seen += 1
                tick()
            else:
                tail.append(line)
        proc.wait()
        with job.proc_lock:
            if proc in job.procs:
                job.procs.remove(proc)
        return clean, seen, proc.returncode, " | ".join(tail[-3:])

    def _scan_batch_with_clamscan(self, job, batch, list_path, scache):
        """Fallback for a batch that clamd could not process."""
        with open(list_path, "w") as f:
            f.write("".join("\t".join(str(x) for x in e) + "\n" for e in batch))
        try:
            return self._scan_with_clamscan(job, list_path, scache)
        finally:
            for p in (list_path, list_path + ".paths"):
                try:
                    os.remove(p)
                except OSError:
                    pass

    def _scan_with_clamscan(self, job, tmp_list, scache):
        """Fallback without clamd: a single clamscan on the list (database loaded once), single-threaded."""
        paths_list = tmp_list + ".paths"
        with open(tmp_list) as src, open(paths_list, "w") as dst:
            for line in src:
                if line.strip():
                    dst.write(line.split("\t", 1)[0] + "\n")
        prefix = ["nice", "-n", "15", "ionice", "-c", "2", "-n", "7"] if job.auto else ["nice", "-n", "5", "ionice", "-c", "2", "-n", "4"]
        if not shutil.which("ionice"):
            prefix = prefix[:2]
        cmd = prefix + ["clamscan", "--verbose", "--suppress-ok-results",
                        f"--move={SYSTEM_QUARANTINE_DIR}", f"--file-list={paths_list}"]
        with job.proc_lock:
            job.proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                        stderr=subprocess.STDOUT, text=True, bufsize=1)
        entries = open(tmp_list)            # parallel read of the list: fingerprint of the current file
        cur, cur_dirty, clean = None, False, []

        def advance_to(path):
            for _ in range(5000):
                line = entries.readline()
                if not line:
                    return None
                e = parse_find_line(line)
                if e[0] == path:
                    return e
            return None

        last_emit = last_save = time.time()
        for raw in job.proc.stdout:
            line = raw.rstrip("\n")
            if not line:
                continue
            counted = False
            if line.startswith("Scanning "):
                if cur and not cur_dirty:
                    clean.append(cur)
                    if len(clean) >= 500:
                        self._record_clean(job, clean, scache)
                        clean = []
                job.current_file = line[9:]
                cur, cur_dirty = advance_to(line[9:]), False
                counted = True
            elif line.endswith((": Empty file", ": No such file or directory", ": Excluded")):
                job.current_file = line.rsplit(": ", 1)[0]
                cur_dirty = True
                counted = True
            elif line.endswith(" FOUND"):
                cur_dirty = True
                job.infected += 1
                path, _, sig = line[:-6].rpartition(": ")
                job.threats.append({"path": path, "signature": sig, "time": now_iso()})
                job.found_sigs[path] = sig
                if job.usb:
                    job.usb_infected.add(os.path.relpath(path, job.path))
                self.write_log(line)
                self.emit_line("found", line)
            elif " moved to " in line:
                moved = parse_moved_line(line)
                if moved:
                    quarantine_index_add(SYSTEM_QUARANTINE_DIR, moved[1], moved[0], job.found_sigs.get(moved[0], ""))
                self.emit_line("info", line)
            elif not is_noise_line(line):
                kind = classify_line(line)
                if kind == "denied":
                    job.denied += 1
                    cur_dirty = True
                elif kind == "error":
                    job.errors += 1
                    cur_dirty = True
                if kind in ("error", "summary", "denied"):
                    self.write_log(line)
                self.emit_line(kind, line)

            if counted:
                job.scanned += 1
                now = time.time()
                if now - last_emit >= PROGRESS_INTERVAL:
                    self.emit_progress(job)
                    last_emit = now
                if now - last_save >= PROGRESS_SAVE_INTERVAL:
                    self._save_progress(job, in_progress=True)
                    last_save = now
        rc = job.proc.wait()
        if cur and not cur_dirty and rc in (0, 1):
            clean.append(cur)
        self._record_clean(job, clean, scache)
        entries.close()
        return rc

    def _forget_auto(self, job):
        """The user cancelled an automatic scan: do not restart it on its own."""
        job.auto = False
        try:
            os.remove(FIRST_SCAN_FLAG)
        except OSError:
            pass

    def _summary(self, job):
        return {
            "path": job.path, "files": job.total, "infected": job.infected,
            "denied": job.denied, "errors": job.errors,
            "duration": time.time() - (job.started_at or time.time()),
            "threats": job.threats[-50:], "auto": job.auto, "usb": job.usb,
            "skipped": job.skipped, "integrity_warnings": job.integrity_warnings,
            "cached": job.cached, "engine": job.engine,
        }

    def _record_scan(self, job, status):
        duration = time.time() - (job.started_at or time.time())
        entry = {
            "date": now_iso(), "path": job.path, "files": job.total,
            "infected": job.infected, "duration": round(duration),
            "status": status, "source": "daemon", "auto": job.auto,
            "usb": {k: job.usb.get(k) for k in ("label", "model", "size", "devnode")} if job.usb else None,
            "cached": job.cached, "skipped": job.skipped, "engine": job.engine,
        }
        self.state.update(last_scan=entry["date"], last_scan_path=job.path,
                          last_scan_infected=job.infected, last_scan_files=job.total,
                          last_scan_duration=round(duration), last_scan_status=status)
        self.state.prepend("history", entry, HISTORY_MAX)
        if job.auto and os.path.exists(FIRST_SCAN_FLAG):
            try:
                os.remove(FIRST_SCAN_FLAG)
            except OSError:
                pass
            self.state.update(first_scan_done=entry["date"])

    # ── USB ──────────────────────────────────────────────────────────────
    def start_usb_scan(self, info):
        """USB key: private mount, scan, then handed over to the user (job_done event)."""
        try:
            mountpoint = self.usb.mount(info)
        except OSError as e:
            log(f"USB : {e}")
            self.broadcast({"event": "usb_error", "usb": info, "error": str(e)})
            return
        usb = dict(info, private_mount=True, mountpoint=mountpoint)
        self._start_usb_job(Job("scan", path=mountpoint, usb=usb, requested_by="system"))

    def _start_usb_job(self, job):
        """A key goes first: if a (disk) scan is running, it is paused while the key is scanned."""
        with self.queue_lock:
            cur = self.current
        if cur and cur.kind == "scan" and not cur.usb and not cur.paused \
                and cur.phase in ("counting", "scanning", "integrity") and not cur.cancel_event.is_set():
            threading.Thread(target=self._run_priority, args=(job, cur), daemon=True, name="usb-priority").start()
        else:
            self.enqueue(job)

    # ── Signature update ─────────────────────────────────────────────────
    def run_update(self, job):
        job.phase = "updating"
        self.emit_progress(job)
        self.write_log("▶ update")
        self.emit_line("info", "→ systemctl stop clamav-freshclam")
        run_quiet(["systemctl", "stop", "clamav-freshclam"], timeout=60)
        output = []
        try:
            self.emit_line("info", "→ freshclam")
            with job.proc_lock:
                job.proc = subprocess.Popen(["freshclam", "--stdout"],
                                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                            text=True, bufsize=1)
            for raw in job.proc.stdout:
                line = raw.strip()
                if line:
                    output.append(line)
                    self.emit_line("info", line)
            rc = job.proc.wait()
        finally:
            self.emit_line("info", "→ systemctl start clamav-freshclam")
            run_quiet(["systemctl", "start", "clamav-freshclam"], timeout=60)

        if job.cancel_event.is_set():
            self.finish(job, "cancelled", "msg.update.cancelled")
            return
        db = db_last_update()
        if rc == 0:
            changed = any("updated (" in line or "Testing database" in line for line in output)
            self.state.update(last_update=now_iso(), last_update_status="success",
                              last_update_db=db.isoformat(timespec="seconds") if db else None)
            self.write_log("■ signatures up to date")
            key = "msg.update.updated" if changed else "msg.update.uptodate"
            self.finish(job, "success", key, {"date": db.strftime("%d.%m.%Y %H:%M") if db else ""},
                        {"db_files": db_files_info(), "changed": changed})
            threading.Thread(target=self.refresh_system_status, daemon=True).start()
        else:
            self.state.update(last_update_attempt=now_iso(), last_update_status="error")
            self.write_log(f"■ update failed ({rc})")
            self.finish(job, "error", "msg.update.failed", {"code": rc})

    # ── System status (apt / CVE) ────────────────────────────────────────
    def _system_upgrade_worker(self, unit):
        ok, detail = True, "test_mode"
        try:
            if unit:
                r = run_quiet(["systemd-run", "--unit", unit, "--collect", "--quiet", "--wait", "--pipe",
                               "-p", "Environment=DEBIAN_FRONTEND=noninteractive",
                               "/bin/sh", "-c", distro.upgrade_shell()], timeout=3600)
                ok, detail = r.returncode == 0, ((r.stderr or "") + (r.stdout or "")).strip()[-300:]
            else:
                time.sleep(2)
            self.write_log(f"system upgrade → {'ok' if ok else 'FAILED'} {detail[-120:]}")
        except Exception as e:  # noqa: BLE001
            ok, detail = False, str(e)
        finally:
            with self.system_status_lock:
                self.system_upgrade_running = False
        self.refresh_system_status(force=True)
        self.broadcast({"event": "system_upgrade_done", "ok": ok, "detail": detail})
        self.refresh_overall()

    def refresh_system_status(self, force=False):
        with self.system_status_lock:
            if self.system_status_running:
                return False
            if not force and time.time() - self.last_system_status < SYSTEM_STATUS_MIN_INTERVAL:
                return False
            self.system_status_running = True
        try:
            self.broadcast({"event": "system_status_refreshing"})
            status = collect_system_status(self.state.get("system_status"))
            self.state.update(system_status=status)
            self.last_system_status = time.time()
            log(f"État du système : {status['upgradable']} MàJ ({status['security']} sécurité), "
                f"{status['cve_count']} CVE, redémarrage={'oui' if status['reboot_required'] else 'non'}")
            self.broadcast({"event": "system_status", "status": status})
            return True
        except Exception as e:  # noqa: BLE001
            log(f"État du système : {e}")
            return False
        finally:
            with self.system_status_lock:
                self.system_status_running = False

    # ── Network security (UFW / SSH) ─────────────────────────────────────
    def _timeshift_first_snapshot(self):
        """First snapshot right after activation (a few minutes), then state refreshed."""
        r = run_quiet(["timeshift", "--check", "--scripted"], timeout=1800)
        if r.returncode != 0 or "snapshot" not in ((r.stdout or "") + (r.stderr or "")).lower():
            r = run_quiet(["timeshift", "--create", "--scripted", "--tags", "D", "--comments", "Dukiwi Shield"], timeout=1800)
        self.write_log(f"timeshift first snapshot → {r.returncode}")
        self.refresh_backup(force=True)
        self.refresh_overall()

    def _timeshift_state_quick(self):
        """Immediate Timeshift state (configuration only, without "timeshift --list", which can take minutes):
        the snapshot counters of the last survey are kept. Used right after enabling/disabling to
        answer the interface without delay; the full survey follows in the background."""
        cached = self.state.get("timeshift") or {}
        ts = collect_timeshift_status(list_snapshots=False)
        ts["snapshots"], ts["last"] = cached.get("snapshots"), cached.get("last")
        ts["suspended"] = self.state.get("timeshift_suspended") or None
        self.state.update(timeshift=ts)
        self.broadcast({"event": "timeshift", "timeshift": ts})
        return ts

    def cached_system_size(self, max_age=7 * 86400):
        info = self.state.get("system_size") or {}
        try:
            age = time.time() - datetime.fromisoformat(info.get("checked_at", "")).timestamp()
        except ValueError:
            return None
        return info.get("bytes") if age < max_age and info.get("bytes") else None

    def refresh_system_size(self, force=False):
        """Size of the system (Timeshift safeguard), measured at most once a week; None if unavailable."""
        size = None if force else self.cached_system_size()
        if size is not None:
            return size
        size = estimate_system_size()
        if size is None:   # du unavailable: usage of the main disk, a cautious upper bound
            try:
                st = os.statvfs("/")
                size = (st.f_blocks - st.f_bfree) * st.f_frsize
            except OSError:
                return None
        self.state.update(system_size={"bytes": size, "checked_at": now_iso()})
        log(f"Taille du système : {size // 10**9} Go")
        return size

    def _timeshift_enable_now(self, existing, size, device_uuid=""):
        """Safeguard then activation: refused if free space is less than 1.2 × the system + 10 GB. `device_uuid`: snapshots
        on another drive (rsync mode), offered when the main disk has no room; Timeshift takes them while it is plugged."""
        cfg, btrfs = timeshift_best_practice_config(existing)
        if device_uuid:
            target = next((d for d in timeshift_targets(0) if d["uuid"] == device_uuid), None)
            if not target:
                return {"ok": False, "error": "timeshift_target_missing"}
            cfg.update(backup_device_uuid=device_uuid, btrfs_mode="false", exclude=["/root/**", "/home/*/**"])
            btrfs = False
        free, path = timeshift_free_bytes(cfg if device_uuid else None)
        needed = timeshift_space_needed(size, btrfs)
        if free is not None and free < needed:
            self.write_log(f"timeshift refused: {free // 10**9} GB free on {path}, {needed // 10**9} GB needed "
                           f"(system {size // 10**9} GB)")
            return {"ok": False, "error": "timeshift_no_space", "free": free, "needed": needed, "size": size, "path": path,
                    "targets": [d for d in timeshift_targets(needed) if d["uuid"] != device_uuid][:4]}
        timeshift_write_config(cfg)
        with open(TIMESHIFT_CRON, "w") as f:
            f.write(TIMESHIFT_GUARD_CRON)
        os.chmod(TIMESHIFT_CRON, 0o644)
        self.state.update(timeshift_suspended=None)
        self.write_log(f"timeshift enabled ({'btrfs' if btrfs else 'rsync'}, daily 5 / weekly 3 / monthly 2, "
                       f"{'?' if free is None else free // 10**9} GB free for a {size // 10**9} GB system"
                       + (f", on {path}" if device_uuid else "") + ")")
        self._timeshift_state_quick()                     # immediate answer; full status check after the first snapshot
        threading.Thread(target=self._timeshift_first_snapshot, daemon=True).start()
        self.refresh_overall()
        return {"ok": True, "mode": "btrfs" if btrfs else "rsync", "started": True, "free": free, "size": size,
                "device": path if device_uuid else ""}

    def _timeshift_enable_worker(self, existing, device_uuid=""):
        """Deferred activation: system measurement (one to two minutes), safeguard, activation; result broadcast."""
        try:
            size = self.refresh_system_size(force=True)
            result = self._timeshift_enable_now(existing, size, device_uuid) if size is not None \
                else {"ok": False, "error": "command_failed", "detail": "du"}
        except Exception as e:  # noqa: BLE001
            log(f"Timeshift : {e}")
            result = {"ok": False, "error": "command_failed", "detail": str(e)[:200]}
        finally:
            self.timeshift_enabling = False
        self.broadcast({"event": "timeshift_enable", "result": result})

    def _timeshift_suspend(self, ts):
        """Safeguard: disk almost full → Timeshift schedules turned off (existing snapshots remain)
        and alert. To be re-enabled from the Backups tab once space has been freed."""
        try:
            with open(TIMESHIFT_CONF, encoding="utf-8") as f:
                cfg = json.load(f)
            for k in ("schedule_monthly", "schedule_weekly", "schedule_daily", "schedule_hourly", "schedule_boot"):
                cfg[k] = "false"
            timeshift_write_config(cfg)
        except (OSError, ValueError) as e:
            log(f"Timeshift : suspension impossible : {e}")
            return ts
        try:
            os.remove(TIMESHIFT_CRON)
        except OSError:
            pass
        free_gb = round((ts.get("free_bytes") or 0) / 1e9, 1)
        self.state.update(timeshift_suspended={"at": now_iso(), "free_bytes": ts.get("free_bytes")})
        self.write_log(f"timeshift schedules suspended: only {free_gb} GB free")
        if self.settings.get("timeshift_check") is not False:          # Timeshift state ignored by the user: no alert
            self.publish_alert({"kind": "timeshift", "severity": "warn", "time": now_iso(), "title": "low_space",
                                "detail": f"{free_gb} GB free", "free_gb": free_gb})
        new = collect_timeshift_status(list_snapshots=False)
        new["snapshots"], new["last"] = ts.get("snapshots"), ts.get("last")
        return new

    def refresh_backup(self, force=False):
        """Timeshift state, at most once an hour (timeshift --list may mount the backup disk)."""
        with self.security_lock:
            cached = self.state.get("timeshift") or {}
            try:
                age = time.time() - datetime.fromisoformat(cached.get("checked_at", "")).timestamp()
            except ValueError:
                age = 1e9
            if not force and cached and age < 3600:
                return cached
        ts = collect_timeshift_status()
        if ts.get("low_space") and ts.get("schedule") and os.geteuid() == 0:
            ts = self._timeshift_suspend(ts)
        ts["suspended"] = self.state.get("timeshift_suspended") or None
        self.state.update(timeshift=ts)
        self.broadcast({"event": "timeshift", "timeshift": ts})
        return ts

    def refresh_security(self, force=False, broadcast=True):
        with self.security_lock:
            if not force and self.security and time.time() - self.last_security < 60:
                return self.security
            self.security = collect_security_status()
            try:
                self.security["ufw"]["profile"] = self.settings.get("firewall_profile") or ""
                self.security["ufw"]["profiles"] = {p: {"services": profile_services(p), "nets": profile_nets(p)} for p in FIREWALL_PROFILES}
                self.security["network"] = self.network_info()
            except Exception as e:  # noqa: BLE001
                log(f"Profil pare-feu : {e}")
            self.last_security = time.time()
            result = self.security
        if broadcast:
            self.broadcast({"event": "security_status", "security": result})
        return result

    # ── Current network and profile remembered per network ────────────────
    def network_loop(self):
        """Monitors the current network (default route, NetworkManager connection) every 10 s,
        and the shield (tray) of each graphical session every 20 s."""
        time.sleep(8)
        while not self.shutdown.is_set():
            try:
                self.check_network()
            except Exception as e:  # noqa: BLE001
                log(f"Réseau : {e}")
            try:
                if time.time() - self.last_tray_check >= 20:
                    self.last_tray_check = time.time()
                    self.check_tray()
            except Exception as e:  # noqa: BLE001
                log(f"Tray : {e}")
            try:
                if time.time() - getattr(self, "last_builtin_watch", 0) >= 300:
                    self.last_builtin_watch = time.time()
                    self._builtin_refresh()             # kernel and processes: behavioural watch every 5 min
            except Exception as e:  # noqa: BLE001
                log(f"Veille noyau/processus : {e}")
            try:
                if time.time() - getattr(self, "last_gateway_check", 0) >= 60:
                    self.last_gateway_check = time.time()
                    self.check_gateway()                # gateway: hardware address unchanged (man in the middle)
            except Exception as e:  # noqa: BLE001
                log(f"Passerelle : {e}")
            try:
                if time.time() - self.last_mail_tick >= 60:
                    self.last_mail_tick = time.time()
                    self.mail_tick()
            except Exception as e:  # noqa: BLE001
                log(f"Courrier : {e}")
            self.shutdown.wait(10)

    def stop_legacy_tray(self, s):
        """Shield of the previous package still in memory after the migration (its Restart=always user service
        restarted it just before its files were deleted): user service stopped, process terminated, once."""
        uid = s["uid"]
        legacy = "/opt/" + "clamav" + "-antivirus/"
        r = run_quiet(["pgrep", "-u", str(uid), "-f", legacy], timeout=10)
        pids = [int(p) for p in (r.stdout or "").split() if p.isdigit()]
        if not pids:
            return
        if os.path.exists(f"/run/user/{uid}/bus"):
            env = {"XDG_RUNTIME_DIR": f"/run/user/{uid}", "DBUS_SESSION_BUS_ADDRESS": f"unix:path=/run/user/{uid}/bus"}
            run_quiet(["runuser", "-u", s["user"], "--", "env"] + [f"{k}={v}" for k, v in env.items()]
                      + ["systemctl", "--user", "stop", "clamav" + "-antivirus-tray.service"], timeout=20)
        for pid in pids:
            try:
                os.kill(pid, signal.SIGTERM)
            except OSError:
                pass
        self.tray_launched.pop(uid, None)                 # new shield launched right away, without waiting 60 s
        self.write_log(f"legacy tray stopped for {s['user']}: {pids}")

    def check_tray(self):
        """The shield must be present in every active graphical session: if it was killed, it is restarted
        in the session (transient user service), unless an administrator quit it in that session."""
        if os.geteuid() != 0 or TEST_MODE or not os.path.exists(TRAY_LAUNCHER):
            return
        for s in graphical_sessions():
            uid = s["uid"]
            self.stop_legacy_tray(s)
            if s["id"] in (self.tray_stopped.get(uid) or set()):
                continue
            r = run_quiet(["pgrep", "-u", str(uid), "-f", TRAY_PROCESS_RE], timeout=10)
            pids = sorted(int(p) for p in (r.stdout or "").split() if p.isdigit())
            if len(pids) > 1:
                # Duplicates (two shields, duplicate notifications): keep the oldest
                for pid in pids[1:]:
                    try:
                        os.kill(pid, signal.SIGTERM)
                    except OSError:
                        pass
                self.write_log(f"duplicate tray for {s['user']}: terminated {pids[1:]}, kept {pids[0]}")
            if pids:
                continue
            # Right after login, the shield is launched by the desktop autostart:
            # give it 90 s, and the user bus must exist (systemd --user manager ready)
            if s.get("age") is not None and s["age"] < 90:
                continue
            if not os.path.exists(f"/run/user/{uid}/bus"):
                continue
            if time.time() - self.tray_launched.get(uid, 0) < 60:
                continue
            self.tray_launched[uid] = time.time()
            env = {"XDG_RUNTIME_DIR": f"/run/user/{uid}", "DBUS_SESSION_BUS_ADDRESS": f"unix:path=/run/user/{uid}/bus", "HOME": pwd.getpwuid(uid).pw_dir}
            cmd = ["runuser", "-u", s["user"], "--", "env"] + [f"{k}={v}" for k, v in env.items()] + [TRAY_LAUNCHER]
            rr = run_quiet(cmd, timeout=40)
            self.write_log(f"tray relaunched for {s['user']} (session {s['id']}) → {rr.returncode}")

    def network_info(self):
        known = self.state.get("network_profiles") or {}
        return {"current": self.current_network,
                "known": sorted(({"key": k, **v} for k, v in known.items()), key=lambda x: x.get("last_seen") or "", reverse=True)[:30]}

    def remember_network_profile(self, profile):
        """The profile chosen by the user is remembered for the current network."""
        net = self.current_network
        if not net:
            return
        known = dict(self.state.get("network_profiles") or {})
        entry = dict(known.get(net["key"]) or {"first_seen": now_iso()})
        entry.update({"profile": profile, "name": net["name"], "type": net["type"], "last_seen": now_iso()})
        known[net["key"]] = entry
        self.state.update(network_profiles=known)

    def check_network(self, force=False):
        """Known network: its remembered profile is applied. Unknown network: Public by default, remembered, and the
        user is notified (popup with "Change"). First time after an update: the current network inherits the
        profile already chosen."""
        net = network_identity()
        with self.network_lock:
            prev_key = (self.current_network or {}).get("key")
            if net and net["key"] == prev_key and not force:
                return
            self.current_network = net
            if not net:
                if prev_key:
                    self.write_log("network: offline")
                return
            known = dict(self.state.get("network_profiles") or {})
            current_profile = self.settings.get("firewall_profile") or ""
            migrate = not self.state.get("network_profiles_init")      # first time (update): inherit the chosen profile
            entry = known.get(net["key"])
            new = entry is None
            if new:
                inherit = bool(migrate and current_profile)
                profile = current_profile if inherit else "public"
                entry = {"profile": profile, "name": net["name"], "type": net["type"], "first_seen": now_iso()}
                new = not inherit                                          # silent inheritance, otherwise "New network" popup
            else:
                profile = entry.get("profile") or "public"
            if migrate:
                self.state.update(network_profiles_init=True)
            entry.update({"name": net["name"], "type": net["type"], "last_seen": now_iso()})
            traps = []
            gw_mac = net.get("gw_mac") or ""
            if gw_mac:
                if not entry.get("gw_mac"):
                    entry["gw_mac"] = gw_mac                                 # first time: remembered silently
                elif entry["gw_mac"] != gw_mac and not new:
                    traps.append(("gateway_changed", {"old": entry["gw_mac"], "new": gw_mac}))
            if net.get("type") == "wifi":
                sec = wifi_security(net.get("device") or "")
                if sec:
                    entry["wifi_security"] = sec
                if sec in ("open", "wep") and time.time() - float(entry.get("open_warned") or 0) > 86400 and not vpn_active():
                    entry["open_warned"] = time.time()
                    traps.append(("open_wifi", {"security": sec}))
            known[net["key"]] = entry
            self.state.update(network_profiles=known)
            changed = profile != current_profile
            if changed or new:
                if os.geteuid() == 0 and not TEST_MODE:
                    ok, text = self.apply_firewall_profile(profile)
                    if not ok:
                        self.write_log(f"network {net['name']}: profile {profile} failed: {text[:120]}")
                self.settings.update({"firewall_profile": profile})
            self.write_log(f"network {net['name']} [{net['type']}] ({net['key']}): profile {profile}"
                           + (" — new network → public" if new else ""))
        if changed or new or force:
            self.refresh_security(force=True)
            self.refresh_overall()
            if self.settings.get("filtered_dns"):
                threading.Thread(target=self.sync_filtered_dns, daemon=True, name="dns-filter").start()   # Entreprise : suspendu
        self.broadcast({"event": "network_changed", "network": net, "profile": profile, "new": new, "changed": changed})
        for subtype, extra in traps:
            self.network_trap(subtype, net, extra)

    def network_trap(self, subtype, net, extra):
        """Rogue network: gateway whose hardware address has changed (possible man-in-the-middle) or unencrypted Wi-Fi
        without VPN. Alert (popup, event, mail), only once per network and per hour."""
        key = net.get("key") or ""
        for a in (self.state.get("alerts") or [])[:20]:
            if a.get("kind") == "network" and a.get("subtype") == subtype and a.get("key") == key and not a.get("resolved"):
                try:
                    if time.time() - datetime.fromisoformat(a.get("time", "")).timestamp() < 3600:
                        return
                except ValueError:
                    pass
        self.write_log(f"⚠ network trap {subtype} on {net.get('name')} ({key}): {extra}")
        self.publish_alert({"kind": "network", "severity": "danger" if subtype == "gateway_changed" else "warn", "time": now_iso(),
                            "subtype": subtype, "key": key, "title": net.get("name") or "?", "detail": ", ".join(f"{k} {v}" for k, v in extra.items()),
                            "old": extra.get("old", ""), "new": extra.get("new", ""), "security": extra.get("security", ""),
                            "pid": 0, "comm": "", "exe": "", "count": 0, "top_dir": "", "reasons": [subtype], "sample": []})

    def check_gateway(self):
        """Every 60 s: the hardware address of the current network's gateway has not changed during the session
        (ARP poisoning). Compared with the one seen at connection time, then updated so as to alert only once
        per change."""
        with self.network_lock:
            net = dict(self.current_network or {})
        if not net.get("gw") or not net.get("gw_mac"):
            return
        mac = gateway_mac(net["gw"])
        if mac and mac != net["gw_mac"]:
            with self.network_lock:
                if self.current_network and self.current_network.get("key") == net.get("key"):
                    self.current_network["gw_mac"] = mac
            self.network_trap("gateway_changed", net, {"old": net["gw_mac"], "new": mac})

    def firewalld_apply_profile(self, profile):
        """Fedora: default zone home / public / work, interface of the current network (and its NetworkManager
        connection) attached to the zone, profile services added to the zone, firewalld started."""
        zone = FIREWALLD_ZONES[profile]
        errors = []
        if not systemd_is_active("firewalld"):
            run_quiet(["systemctl", "enable", "--now", "firewalld"], timeout=90)
        ok, text = fwcmd("--set-default-zone", zone)
        if not ok:
            errors.append(text[:80])
        net = network_identity() or {}
        if net.get("device"):
            fwcmd("--permanent", "--zone", zone, "--change-interface", net["device"])
            if shutil.which("nmcli") and str(net.get("key", "")).startswith("nm:"):
                run_quiet(["nmcli", "connection", "modify", net["key"][3:], "connection.zone", zone], timeout=20)
        wanted = {PROFILE_FIREWALLD_SERVICES[s] for s in profile_services(profile) if s in PROFILE_FIREWALLD_SERVICES}
        ok2, current = fwcmd("--permanent", "--zone", zone, "--list-services")
        current = set(current.split()) if ok2 else set()
        for s in sorted(wanted - current):
            ok3, t = fwcmd("--permanent", "--zone", zone, "--add-service", s)
            if not ok3:
                errors.append(t[:80])
        for s in sorted((current & set(PROFILE_FIREWALLD_SERVICES.values())) - wanted):
            fwcmd("--permanent", "--zone", zone, "--remove-service", s)
        if profile == "public":
            fwcmd("--permanent", "--zone", zone, "--remove-service", "ssh")   # Public : aucun service ouvert
        fwcmd("--reload")
        self.write_log(f"firewalld profile {profile} (zone {zone}): services {sorted(wanted)}, {len(errors)} error(s)")
        return not errors, "; ".join(errors)[:300]

    def firewalld_command(self, cmd, req):
        """Commands of the Firewall page on firewalld (enable, policies, rules)."""
        zone = firewalld_zone()
        if cmd == "firewall_set":
            if req.get("enabled"):
                r = run_quiet(["systemctl", "enable", "--now", "firewalld"], timeout=90)
                if req.get("allow_ssh"):
                    fwcmd("--permanent", "--zone", zone, "--add-service", "ssh")
                    fwcmd("--reload")
                ok, state = fwcmd("--state", timeout=20)
                self.write_log(f"firewalld enable → {r.returncode} ({state})")
                return ok and "running" in state, "" if ok and "running" in state else (state or (r.stderr or "").strip())[:300]
            r = run_quiet(["systemctl", "disable", "--now", "firewalld"], timeout=90)
            self.write_log(f"firewalld disable → {r.returncode}")
            return r.returncode == 0, ((r.stderr or "") + (r.stdout or "")).strip()[:300]
        if cmd == "firewall_defaults":
            policy = str(req.get("incoming", "")).lower()
            if policy not in VALID_POLICY:
                return False, "invalid_policy"
            target = {"allow": "ACCEPT", "deny": "DROP", "reject": "%%REJECT%%"}[policy]
            ok, text = fwcmd("--permanent", "--zone", zone, "--set-target", target)
            fwcmd("--reload")
            return ok, text[:300]
        if cmd == "firewall_rule_add":
            action = str(req.get("rule_action") or req.get("action") or "allow").lower()
            proto = str(req.get("proto", "tcp")).lower()
            port = str(req.get("port", "")).strip()
            if action not in VALID_ACTION or proto not in VALID_PROTO or not re.fullmatch(r"\d{1,5}(:\d{1,5})?(,\d{1,5})*", port):
                return False, "invalid_rule"
            errors = []
            for pr in (["tcp", "udp"] if proto == "any" else [proto]):
                for single in port.split(","):
                    single = single.replace(":", "-")
                    if action == "allow":
                        ok, t = fwcmd("--permanent", "--zone", zone, "--add-port", f"{single}/{pr}")
                    else:
                        verb = {"deny": "drop", "reject": "reject", "limit": 'accept limit value="25/m"'}[action]
                        ok, t = fwcmd("--permanent", "--zone", zone, "--add-rich-rule", f'rule family="ipv4" port port="{single}" protocol="{pr}" {verb}')
                    if not ok:
                        errors.append(t[:80])
            fwcmd("--reload")
            self.write_log(f"firewalld rule add {action} {port}/{proto} → {len(errors)} error(s)")
            return not errors, "; ".join(errors)[:300]
        if cmd == "firewall_rule_delete":
            try:
                number = int(req.get("number"))
            except (TypeError, ValueError):
                return False, "invalid_rule"
            rule = next((r for r in firewalld_rules(zone) if r["number"] == number), None)
            if not rule:
                return False, "invalid_rule"
            flag = {"service": "--remove-service", "port": "--remove-port"}.get(rule["kind"], "--remove-rich-rule")
            ok, t = fwcmd("--permanent", "--zone", zone, flag, rule["spec"])
            fwcmd("--reload")
            return ok, t[:300]
        return False, "unknown"

    def apply_firewall_profile(self, profile):
        """Removes the old profile rules, applies the policies, adds the profile rules, enables UFW."""
        if distro.firewall_backend() == "firewalld":
            return self.firewalld_apply_profile(profile)
        r = run_quiet(["ufw", "status", "numbered"], timeout=30)
        for rule in sorted(parse_ufw_numbered(r.stdout or ""), key=lambda x: -x["number"]):
            if PROFILE_TAG in (rule.get("comment") or "") or PROFILE_TAG in (rule.get("raw") or ""):
                self.ufw("delete", str(rule["number"]))
        self.ufw("default", "deny", "incoming")
        self.ufw("default", "allow", "outgoing")
        errors = []
        rules = profile_rules(profile)
        for args in rules:
            ok, text = self.ufw(*args)
            if not ok:
                errors.append(text[:80])
        self.ufw("logging", "medium" if profile == "enterprise" else "low")
        ok, text = self.ufw("enable")
        self.write_log(f"firewall profile {profile}: {len(rules)} rule(s), {len(errors)} error(s)")
        return ok and not errors, ("; ".join(errors) or text)[:300]

    def ufw(self, *args):
        cmd = ufw_args(args)
        r = run_quiet(cmd, timeout=60)
        text = ((r.stdout or "") + (r.stderr or "")).strip()
        self.write_log(f"{' '.join(cmd[1:])} → {r.returncode}" + (f" : {text[:160]}" if r.returncode != 0 else ""))
        return r.returncode == 0, text[:300]

    # ── Applying settings ─────────────────────────────────────────────────
    def apply_settings(self, changed):
        applied = []
        if "update_hour" in changed or "update_minute" in changed:
            hour, minute = int(self.settings.get("update_hour")), int(self.settings.get("update_minute"))
            if not TEST_MODE:
                dropin_dir = "/etc/systemd/system/dukiwi-shield-update.timer.d"
                try:
                    os.makedirs(dropin_dir, exist_ok=True)
                    with open(os.path.join(dropin_dir, "override.conf"), "w") as f:
                        f.write("[Timer]\nOnCalendar=\n"
                                f"OnCalendar=*-*-* {hour:02d}:{minute:02d}:00\nOnBootSec=5min\n")
                    run_quiet(["systemctl", "daemon-reload"], timeout=60)
                    run_quiet(["systemctl", "restart", "dukiwi-shield-update.timer"], timeout=60)
                    applied.append("update_time")
                except OSError as e:
                    log(f"Réglage heure de MàJ : {e}")
            else:
                applied.append("update_time")
        if "upload_window_hours" in changed:
            self.network.samples.clear()
            applied.append("upload_window")
        if "honeypot" in changed:
            applied.append("honeypot")                  # the honeypot thread follows the setting (≤ 2 s)
        if "filtered_dns" in changed:
            threading.Thread(target=self.sync_filtered_dns, daemon=True, name="dns-filter").start()
            applied.append("filtered_dns")
        return applied

    # ── Autostart, scheduled tasks, extensions ────────────────────────────
    def refresh_persistence(self, reason="daily"):
        """Survey of persistence (autostart, cron, timers, at, services, extensions); any new item, and any
        extension that obtains new sensitive permissions, triggers an alert. Called every day and by the
        security centre watch as soon as one of the watched folders changes."""
        with self._persistence_lock:
            prev = self.state.get("persistence") or {}
            prev_keys = {it["key"] for it in prev.get("items", [])}
            prev_ext = {e["key"]: e for e in prev.get("extensions", [])}
            pers = self.apply_acknowledged(collect_persistence())
            # Encrypted home folder not mounted yet (service started before the session): its entries from the
            # previous scan are carried over as-is, otherwise they would all reappear as "new" at login.
            for name in pers.get("pending") or []:
                pers["items"] += [it for it in prev.get("items", []) if it.get("user") == name]
                pers["extensions"] += [e for e in prev.get("extensions", []) if e.get("user") == name]
            if pers.get("pending"):
                pers["counts"] = {"items": len(pers["items"]), "untrusted": sum(1 for it in pers["items"] if not it.get("trusted")),
                                  "extensions": len(pers["extensions"]), "ext_outside_store": sum(1 for e in pers["extensions"] if not e.get("from_store"))}
            self.state.update(persistence=pers)
            if prev.get("items") is not None and (prev_keys or prev_ext):
                new_items = [it for it in pers["items"] if it["key"] not in prev_keys]
                new_ext = [e for e in pers["extensions"] if e["key"] not in prev_ext]
                # More than four new items at once: not an installation but a change of baseline (imported
                # profile, new account, restore) → a single notice, not a burst of popups.
                if len(new_items) > 4:
                    self.write_log(f"⚠ persistence: {len(new_items)} new entries at once: " + ", ".join(it["name"] for it in new_items[:8]))
                    self.publish_alert({"kind": "persistence", "subtype": "many", "severity": "warn", "time": now_iso(), "title": str(len(new_items)),
                                        "detail": ", ".join(it["name"] for it in new_items[:8]), "pid": 0, "comm": "", "exe": "", "count": len(new_items),
                                        "top_dir": "", "reasons": ["many_at_once"], "sample": []})
                    new_items = []
                if len(new_ext) > 4:
                    self.write_log(f"⚠ extension: {len(new_ext)} new extensions at once: " + ", ".join(e["name"] for e in new_ext[:8]))
                    self.publish_alert({"kind": "extension", "subtype": "many", "severity": "info", "time": now_iso(), "title": str(len(new_ext)),
                                        "detail": ", ".join(sorted({e["browser"] for e in new_ext})), "perms": [], "names": [e["name"] for e in new_ext[:12]],
                                        "pid": 0, "comm": "", "exe": "", "count": len(new_ext), "top_dir": "", "reasons": ["many_at_once"], "sample": []})
                    new_ext = []
                for it in new_items:
                    self.publish_alert({"kind": "persistence", "severity": "warn" if not it["trusted"] else "info",
                                        "time": now_iso(), "title": it["name"], "detail": it["path"],
                                        "item": it, "pid": 0, "comm": it["name"], "exe": it["path"], "count": 0,
                                        "top_dir": os.path.dirname(it["path"]), "reasons": [it.get("kind", "")], "sample": []})
                for e in new_ext:
                    severity = "warn" if (not e["from_store"] or any(p_ in (e.get("perms") or []) for p_ in ("all_sites", "nativeMessaging", "sideloaded"))) else "info"
                    self.write_log(f"⚠ extension: new {e['browser']} extension {e['name']} ({e['user']}) perms {','.join(e.get('perms') or []) or '-'}")
                    self.publish_alert({"kind": "extension", "subtype": "new", "severity": severity, "time": now_iso(), "title": e["name"],
                                        "detail": f"{e['browser']} · {e['user']}", "extension": e, "perms": e.get("perms") or [],
                                        "pid": 0, "comm": "", "exe": "", "count": 0, "top_dir": "", "reasons": ["ext_new"], "sample": []})
                for e in pers["extensions"]:
                    old = prev_ext.get(e["key"])
                    if old is None:
                        continue
                    added = sorted(set(e.get("perms") or []) - set(old.get("perms") or []))
                    if added and "perms" in old:
                        self.write_log(f"⚠ extension: {e['browser']} extension {e['name']} ({e['user']}) gained {','.join(added)} (v{old.get('version')} → v{e.get('version')})")
                        self.publish_alert({"kind": "extension", "subtype": "permissions", "severity": "warn", "time": now_iso(), "title": e["name"],
                                            "detail": f"{e['browser']} · {e['user']}", "extension": e, "perms": added,
                                            "old_version": old.get("version"), "pid": 0, "comm": "", "exe": "", "count": 0,
                                            "top_dir": "", "reasons": ["ext_permissions"], "sample": []})
            self.broadcast({"event": "persistence", "persistence": pers})
            return pers

    # ── Fichiers SUID / SGID hors paquets ────────────────────────────────
    def refresh_suid(self):
        """Survey of SUID/SGID files; those shipped by no package are kept (hash, owner, permissions).
        A new file of this kind triggers an alert (danger in a temporary or personal folder)."""
        paths = self.guard.suid_scan()
        owners = dpkg_owners(paths)
        missing = [p_ for p_ in paths if p_ not in owners]
        if missing and not distro.is_rpm():
            # merged /usr: dpkg may know /bin/su for /usr/bin/su (and vice versa)
            alt = {(p_[4:] if p_.startswith("/usr/") else "/usr" + p_): p_ for p_ in missing}
            for a, orig in alt.items():
                if a in dpkg_owners(list(alt)):
                    owners[orig] = "usrmerge"
        unowned = []
        for p_ in paths:
            if p_ in owners:
                continue
            try:
                st = os.lstat(p_)
                unowned.append({"path": p_, "suid": bool(st.st_mode & 0o4000), "sgid": bool(st.st_mode & 0o2000),
                                "owner": pwd.getpwuid(st.st_uid).pw_name if st.st_uid in {u.pw_uid for u in pwd.getpwall()} else str(st.st_uid),
                                "size": st.st_size, "mtime": datetime.fromtimestamp(st.st_mtime).isoformat(timespec="seconds"),
                                "sha256": sha256_file(p_) if st.st_size < 200 * 1024 * 1024 else ""})
            except OSError:
                continue
        prev = self.state.get("suid")
        pending = tuple(pwd.getpwnam(n).pw_dir.rstrip("/") + "/" for n in pending_homes())
        if prev is not None and pending:
            seen = {u["path"] for u in unowned}
            unowned += [u for u in prev.get("unowned") or [] if u["path"].startswith(pending) and u["path"] not in seen]   # folder not mounted
        info = {"checked_at": now_iso(), "total": len(paths), "unowned": unowned}
        self.state.update(suid=info)
        if prev is not None:
            known = {u["path"]: u.get("sha256") for u in prev.get("unowned") or []}
            acks = self.state.get("acknowledged_suid") or {}
            new = [u for u in unowned if known.get(u["path"]) != u["sha256"] and acks.get(u["path"], {}).get("sha256") != u["sha256"]]
            if len(new) > 4:
                # Many at once is a copy of the system (backup, image, restored folder), not a planted backdoor: one summary
                # alert listing a few paths instead of one popup each; the checklist keeps the full list
                self.write_log(f"⚠ suid: {len(new)} new files outside packages at once: " + ", ".join(u["path"] for u in new[:6]))
                self.publish_alert({"kind": "suid", "subtype": "many", "severity": "warn", "time": now_iso(), "title": str(len(new)),
                                    "detail": ", ".join(u["path"] for u in new[:6]), "path": "", "owner": "", "pid": 0, "comm": "",
                                    "exe": "", "count": len(new), "top_dir": os.path.commonpath([u["path"] for u in new]) if new else "",
                                    "reasons": ["suid_unowned", "many_at_once"], "sample": [u["path"] for u in new[:20]]})
                new = []
            for u in new:
                bad_place = u["path"].startswith(("/tmp/", "/var/tmp/", "/dev/shm/", "/home/", "/run/"))
                self.write_log(f"⚠ suid file outside packages: {u['path']} ({'suid' if u['suid'] else 'sgid'} {u['owner']})")
                self.publish_alert({"kind": "suid", "severity": "danger" if bad_place else "warn", "time": now_iso(), "title": os.path.basename(u["path"]),
                                    "detail": u["path"], "path": u["path"], "owner": u["owner"], "suid": u["suid"], "pid": 0, "comm": "",
                                    "exe": u["path"], "count": 0, "top_dir": os.path.dirname(u["path"]), "reasons": ["suid_unowned"], "sample": []})
        log(f"SUID/SGID : {len(paths)} fichier(s), {len(unowned)} hors paquets")
        return info

    def flatpak_status(self):
        """Flatpak applications with sensitive permissions, with the "ignored" state (per application and set of rights)."""
        apps = self.cached("flatpak_audit", 3600, lambda: audit.flatpak_audit(human_users()))
        acks = self.state.get("acknowledged_flatpak") or {}
        return [dict(a, acknowledged=set((acks.get(a["app"]) or {}).get("risks") or []) >= set(a["risks"])) for a in apps]

    def suid_status(self):
        info = dict(self.state.get("suid") or {})
        acks = self.state.get("acknowledged_suid") or {}
        info["unowned"] = [dict(u, acknowledged=acks.get(u["path"], {}).get("sha256") == u.get("sha256")) for u in info.get("unowned") or []]
        return info

    # ── Malicious development packages (pip, npm) ────────────────────────
    def refresh_dev_packages(self):
        """pip/npm packages installed outside the system, compared with the OSV "MAL-" entries; a new one → red alert."""
        res = audit.malicious_packages(human_users(), osv_query)
        prev = {(m["ecosystem"], m["name"], m["version"]) for m in ((self.state.get("dev_packages") or {}).get("malicious") or [])}
        self.state.update(dev_packages=res)
        for m in res["malicious"]:
            if (m["ecosystem"], m["name"], m["version"]) in prev:
                continue
            self.write_log(f"⚠ danger: malicious {m['ecosystem']} package {m['name']} {m['version']} ({m['where']}) {', '.join(m['ids'])}")
            self.publish_alert({"kind": "dev_package", "severity": "danger", "time": now_iso(), "title": m["name"], "detail": m["where"],
                                "ecosystem": m["ecosystem"], "version": m["version"], "ids": m["ids"], "path": m["where"],
                                "pid": 0, "comm": "", "exe": "", "count": 0, "top_dir": m["where"], "reasons": ["malicious_package"], "sample": []})
        log(f"Paquets de développement : {res['counts']} — {len(res['malicious'])} malveillant(s)")
        return res

    # ── Weekly summary ───────────────────────────────────────────────────
    def weekly_summary(self, days=7):
        """Summary of the last 7 days: score and its trend, scans, threats, what was blocked or suspended,
        events by category, items to fix."""
        cutoff = time.time() - days * 86400

        def recent(iso):
            try:
                return datetime.fromisoformat(str(iso)[:19]).timestamp() >= cutoff
            except ValueError:
                return False
        alerts = [a for a in (self.state.get("alerts") or []) if recent(a.get("time"))]
        scans = [h for h in (self.state.get("history") or []) if recent(h.get("date"))]
        events = security_journal(self, days)
        by_cat = {}
        for e in events:
            if e["sev"] in ("warn", "danger"):
                by_cat[e["cat"]] = by_cat.get(e["cat"], 0) + 1
        hist = [h for h in (self.state.get("score_history") or []) if isinstance(h, dict)]
        ck = self.state.get("checklist") or {}
        before = next((h for h in reversed(hist) if h.get("d", "") <= datetime.fromtimestamp(cutoff).strftime("%Y-%m-%d")), hist[0] if hist else None)
        url_events = list(getattr(self.urlguard, "events", []) or [])
        kinds = lambda *k: sum(1 for a in alerts if a.get("kind") in k)
        blocked = {"threats": sum(int(h.get("infected") or 0) for h in scans) + kinds("download", "mail"),
                   "suspended": sum(1 for a in alerts if a.get("suspended")),
                   "links": sum(1 for e in url_events if e.get("action") == "blocked" and recent(e.get("t"))),
                   "network": kinds("honeypot", "network", "connection"), "usb_keyboards": sum(1 for a in alerts if a.get("kind") == "usb_keyboard" and a.get("blocked")),
                   "ransomware": kinds("ransomware"), "miners": kinds("miner"), "changes": kinds("persistence", "extension", "ssh_key", "suid", "certificate", "redirect")}
        todo = sorted((it for it in ck.get("items") or [] if it.get("status") in ("fail", "warn")), key=lambda it: (it["status"] != "fail", -it.get("weight", 0)))
        return {"date": now_iso(), "days": days, "score": ck.get("score"), "grade": ck.get("grade"),
                "score_before": (before or {}).get("s"), "scans": len(scans), "files": sum(int(h.get("files") or 0) for h in scans),
                "alerts": len(alerts), "danger": sum(1 for a in alerts if a.get("severity") == "danger"), "blocked": blocked,
                "by_cat": by_cat, "todo": [it["key"] for it in todo[:5]], "isolated": bool(self.state.get("isolated"))}

    def check_weekly_summary(self):
        """On Monday from 8 a.m. (or at the first start after that): summary saved, broadcast to the application,
        sent by email if notifications are configured."""
        now = datetime.now()
        last = self.state.get("weekly_summary_at") or ""
        try:
            age = (now - datetime.fromisoformat(last)).days if last else 99
        except ValueError:
            age = 99
        if age < 6 or (now.weekday() != 0 and age < 8) or now.hour < 8:
            return
        summary = self.weekly_summary()
        keep = ([summary] + list(self.state.get("weekly_summaries") or []))[:8]
        self.state.update(weekly_summaries=keep, weekly_summary_at=now.isoformat(timespec="seconds"))
        self.write_log(f"weekly summary: score {summary['score']} (was {summary['score_before']}), {summary['alerts']} alert(s), "
                       f"{summary['blocked']['threats']} threat(s), {summary['blocked']['links']} link(s) blocked")
        self.broadcast({"event": "weekly_summary", "weekly_summary": summary})
        cfg = self.mail_cfg()
        if cfg.get("enabled") and cfg.get("weekly_summary", True) is not False:
            lang = cfg.get("lang") or "fr"
            self.mail_deliver(t(lang, "mail.weekly.subject", score=summary["score"] if summary["score"] is not None else "—"),
                              self.weekly_summary_text(summary, lang), kind="weekly")

    def check_monthly_report(self):
        """On the 1st of the month from 8 a.m. (or at the first start after that): report of the past month sent by
        e-mail, only when e-mail notifications work (a message already delivered, no error since) and the user has not
        turned the monthly report off."""
        now = datetime.now()
        month = now.strftime("%Y-%m")
        if self.state.get("monthly_report_month") == month or now.hour < 8:
            return
        cfg = self.mail_cfg()
        if not cfg.get("enabled") or not cfg.get("last_sent") or cfg.get("last_error") \
                or (cfg.get("events") or {}).get("monthly", True) is False or not cfg.get("to"):
            return
        lang = cfg.get("lang") or "fr"
        summary = self.weekly_summary(days=30)
        ok, err = self.mail_deliver(t(lang, "mail.monthly.subject", month=datetime.fromtimestamp(now.replace(day=1).timestamp() - 86400).strftime("%m/%Y"),
                                      score=summary["score"] if summary["score"] is not None else "—"),
                                    self.monthly_report_text(summary, lang), kind="monthly")
        if ok:
            self.state.update(monthly_report_month=month)

    def monthly_report_text(self, s_, lang):
        """Weekly summary lines over 30 days, plus backups, system snapshots, pending updates and versions."""
        lines = self.weekly_summary_text(s_, lang).split("\n")
        lines[0] = t(lang, "mail.monthly.title")
        states = [b.get("state") for b in user_backup_states(self.state.get("backup_states")).values()]
        worst = next((st for st in ("none", "missing", "old", "ok") if st in states), "")
        ts = self.state.get("timeshift") or {}
        snaps = "ignored" if self.settings.get("timeshift_check") is False and not ts.get("schedule") else ("on" if ts.get("schedule") else "off")
        sysst = self.state.get("system_status") or {}
        db = db_last_update()
        extra = ["", t(lang, "mail.monthly.availability"),
                 f"- {t(lang, 'mail.monthly.files')} : {t(lang, f'mail.monthly.backup.{worst}') if worst else '—'}",
                 f"- {t(lang, 'mail.monthly.snapshots')} : {t(lang, f'mail.monthly.snap.{snaps}')}",
                 "", t(lang, "mail.monthly.maintenance"),
                 f"- {t(lang, 'mail.summary.updates')} : {sysst.get('security', 0)} / {sysst.get('upgradable', 0)}",
                 f"- {t(lang, 'mail.summary.signatures')} : {db.strftime('%Y-%m-%d') if db else '—'}",
                 f"- Dukiwi Shield : {VERSION}"]
        todo_at = lines.index("") if "" in lines else len(lines)
        return "\n".join(lines[:todo_at] + extra + lines[todo_at:])

    def weekly_summary_text(self, s_, lang):
        b = s_["blocked"]
        delta = ""
        if s_.get("score") is not None and s_.get("score_before") is not None and s_["score"] != s_["score_before"]:
            delta = f" ({'+' if s_['score'] > s_['score_before'] else ''}{s_['score'] - s_['score_before']})"
        lines = [t(lang, "mail.weekly.title"), "",
                 f"- {t(lang, 'mail.summary.score')} : {s_.get('score', '—')} ({s_.get('grade') or '—'}){delta}",
                 f"- {t(lang, 'mail.weekly.scans', n=s_['scans'], files=s_['files'])}",
                 f"- {t(lang, 'mail.weekly.alerts', n=s_['alerts'], danger=s_['danger'])}",
                 f"- {t(lang, 'mail.weekly.blocked', threats=b['threats'], links=b['links'], suspended=b['suspended'], network=b['network'])}"]
        if b.get("changes"):
            lines.append(f"- {t(lang, 'mail.weekly.changes', n=b['changes'])}")
        if s_.get("todo"):
            lines += ["", t(lang, "mail.weekly.todo")] + [f"- {t(lang, f'check.{k}.title')}" for k in s_["todo"]]
        return "\n".join(lines)

    # ── Filtered DNS (systemd-resolved) ──────────────────────────────────
    def sync_filtered_dns(self):
        """Applies the chosen filtered DNS, or removes it; suspended on a network with the Business profile (internal DNS)."""
        if os.geteuid() != 0 or TEST_MODE:
            return
        with self._dns_lock:
            provider = self.settings.get("filtered_dns") or ""
            enterprise = (self.settings.get("firewall_profile") or "") == "enterprise"
            info = {"provider": provider, "suspended": bool(provider and enterprise), "error": "", "at": now_iso()}
            if not provider or enterprise:
                if protect.dns_remove():
                    self.write_log("filtered DNS removed" + (" (enterprise network)" if enterprise and provider else ""))
            else:
                ok, err = protect.dns_apply(provider)
                info["error"] = err
                self.write_log(f"filtered DNS {provider}: " + ("applied" if ok else f"failed ({err})"))
            self.state.update(dns_filter=info)
            self.broadcast({"event": "dns_filter", "dns_filter": self.dns_filter_status()})

    def dns_filter_status(self):
        return dict(protect.dns_status(), **{k: v for k, v in (self.state.get("dns_filter") or {}).items() if k in ("suspended", "error", "at")},
                    setting=self.settings.get("filtered_dns") or "")

    # ── Isoler l'ordinateur ──────────────────────────────────────────────
    def isolate(self, uid):
        """Emergency: network cut off, suspicious programs suspended, full scan. No password."""
        if self.state.get("isolated"):
            return {"ok": True, "already": True, "isolated": self.state.get("isolated")}
        if os.geteuid() != 0 or TEST_MODE:
            return {"ok": False, "error": "root_required"}
        method, prev = protect.network_cut()
        if not method:
            return {"ok": False, "error": "isolate_failed"}
        cutoff = time.time() - 86400
        alert_pids = set()
        for a in (self.state.get("alerts") or [])[:50]:
            try:
                if a.get("severity") == "danger" and a.get("pid") and datetime.fromisoformat(a.get("time", "")).timestamp() > cutoff:
                    alert_pids.add(int(a["pid"]))
            except (ValueError, TypeError):
                pass
        stopped = []
        for p in protect.suspicious_processes(alert_pids, self.user_trusted()):
            try:
                os.kill(p["pid"], signal.SIGSTOP)
            except OSError:
                continue
            self.suspended[p["pid"]] = {"pid": p["pid"], "comm": p["comm"], "exe": p["exe"], "time": now_iso(), "kind": "isolate"}
            stopped.append(p)
        scan = False
        with self.queue_lock:
            busy = self.current is not None or bool(self.queue)
        if not busy:
            self.enqueue(Job("scan", path="/", requested_by=uid))
            scan = True
        info = {"at": now_iso(), "method": method, "prev": prev, "suspended": stopped[:40], "scan": scan, "by": uid}
        self.state.update(isolated=info)
        self.write_log(f"⚠ danger: computer ISOLATED by uid {uid} ({method}), {len(stopped)} process(es) suspended"
                       + (", full scan started" if scan else ""))
        self.broadcast({"event": "isolated", "isolated": info})
        self.refresh_overall()
        return {"ok": True, "isolated": info}

    def unisolate(self, uid):
        info = self.state.get("isolated")
        if not info:
            return {"ok": False, "error": "not_isolated"}
        ok = protect.network_restore(info.get("method"), info.get("prev"))
        if not ok:
            return {"ok": False, "error": "restore_failed"}
        self.state.update(isolated=None)
        self.write_log(f"network restored by uid {uid} (isolation ended)")
        self.broadcast({"event": "isolated", "isolated": None})
        self.refresh_overall()
        return {"ok": True}

    def check_weekly_scan(self):
        if not self.settings.get("weekly_scan"):
            return
        now = datetime.now()
        if now.weekday() != int(self.settings.get("weekly_scan_day")) or now.hour != int(self.settings.get("weekly_scan_hour")):
            return
        last = self.state.get("last_weekly_scan")
        if last:
            try:
                if (now - datetime.fromisoformat(last)).days < 6:
                    return
            except ValueError:
                pass
        with self.queue_lock:
            busy = self.current is not None or bool(self.queue)
        if busy:
            return
        self.state.update(last_weekly_scan=now.isoformat(timespec="seconds"))
        log("Scan complet hebdomadaire planifié")
        self.enqueue(Job("scan", path="/", auto=True, requested_by="system"))

    # ── Daily tasks: vulnerabilities, persistence, app update, checklist ───────────────
    def daily_tasks(self, force=False):
        if self.daily_running:
            return
        self.daily_running = True
        try:
            self.last_daily = time.time()
            # System snapshots (Timeshift)
            try:
                self.refresh_backup(force=True)
            except Exception as e:  # noqa: BLE001
                log(f"Timeshift : {e}")
            # UPnP router: ports opened automatically to this computer (local network only)
            try:
                self.state.update(upnp=hygiene.upnp_mappings())
            except Exception as e:  # noqa: BLE001
                log(f"UPnP : {e}")
            # Monthly restore test of the Timeshift snapshots
            try:
                last_test = (self.state.get("timeshift_test") or {}).get("date") or ""
                ts = self.state.get("timeshift") or {}
                if ts.get("configured") and ts.get("snapshots") and os.geteuid() == 0 and \
                        (not last_test or time.time() - datetime.fromisoformat(last_test).timestamp() > 30 * 86400):
                    res = timeshift_restore_test()
                    if res.get("error") not in ("device_unmounted",):
                        self.state.update(timeshift_test=res)
                        self.write_log(f"restore test timeshift {res.get('snapshot', '')}: " + ("ok" if res["ok"] else
                                       f"⚠ {res.get('error') or str(len(res['failed'])) + ' failed'}") + f" ({res['restored']}/{res['checked']} read, {res['identical']}/{res['compared']} identical)")
            except Exception as e:  # noqa: BLE001
                log(f"Test de restauration Timeshift : {e}")
            if shutil.which("timeshift") and not TEST_MODE:
                try:
                    self.refresh_system_size()
                except Exception as e:  # noqa: BLE001
                    log(f"Taille du système : {e}")
            # Failles ouvertes
            vulns = apply_vuln_acks(collect_vulnerabilities(self.state.get("vulns")), self.state.get("acknowledged_vulns") or {})
            self.state.update(vulns=vulns)
            self.broadcast({"event": "vulns", "vulns": self.public_vulns(vulns)})
            log(f"Failles : {vulns['counts']} ({vulns['sources']} paquets sources)")
            # Firmware (fwupd / LVFS)
            try:
                fw = firmware_updates()
                self.state.update(firmware={"checked_at": now_iso(), "available": fw is not None, "updates": fw or []})
                if fw:
                    log(f"Firmware : {len(fw)} mise(s) à jour disponible(s) : " + ", ".join(u["name"] for u in fw[:4]))
            except Exception as e:  # noqa: BLE001
                log(f"Firmware : {e}")
            # Persistance & extensions
            self.refresh_persistence()
            # Paquets pip / npm malveillants (fiches MAL- d'OSV)
            try:
                self.refresh_dev_packages()
            except Exception as e:  # noqa: BLE001
                log(f"Paquets de développement : {e}")
            # Fichiers SUID / SGID hors paquets
            if os.geteuid() == 0 and not TEST_MODE:
                try:
                    self.refresh_suid()
                except Exception as e:  # noqa: BLE001
                    log(f"SUID : {e}")
            # Listes d'IP malveillantes
            try:
                self.connections.load_blocklist(refresh=True)
            except Exception as e:  # noqa: BLE001
                log(f"Blocklist : {e}")
            # Integrity check: never done, or done with a different list of tools (application update)
            stored = self.state.get("integrity") or {}
            if stored.get("tools") and any(n not in stored["tools"] for n in BUILTIN_CHECKS):
                self._builtin_refresh(initial=True)       # kernel / processes: added without rerunning the whole audit
                stored = self.state.get("integrity") or {}
            if os.geteuid() == 0 and not self.integrity_running and set((stored.get("tools") or {}).keys()) != set(INTEGRITY_TOOLS):
                log("Vérification d'intégrité relancée (outils modifiés)")
                threading.Thread(target=self.run_integrity, daemon=True).start()
            else:
                # Lynis warnings from an earlier scan: reclassified in place (actual state checked),
                # without rerunning the audit
                ly = (stored.get("tools") or {}).get("lynis") or {}
                if ly.get("ran") and ly.get("rules") != LYNIS_RULES_VERSION:
                    try:
                        la = lynis_analysis(ly.get("all_warnings") or ly.get("warnings") or [])
                        integ = dict(stored)
                        tools = dict(integ.get("tools") or {})
                        tools["lynis"] = dict(ly, all_warnings=list(la["warnings"]), warnings=list(la["warnings"]),
                                              benign=la["benign"], notes=la["notes"], rules=LYNIS_RULES_VERSION)
                        integ["tools"] = tools
                        self.apply_integrity_acks(integ)
                        self.state.update(integrity=integ)
                        stored = integ
                        self.broadcast({"event": "integrity", "integrity": self.integrity_payload()})
                        self.refresh_overall()
                        log(f"Avertissements Lynis reclassés : {len(la['benign'])} faux positif(s) connu(s)")
                    except Exception as e:  # noqa: BLE001
                        log(f"Reclassement Lynis : {e}")
                # debsums files from an earlier scan: reclassified in place (Mint adjustments, diversions)
                ds = (stored.get("tools") or {}).get("debsums") or {}
                if ds.get("ran") and ds.get("rules") != DEBSUMS_RULES_VERSION:
                    try:
                        src = list(ds.get("all_warnings") or ds.get("warnings") or []) + [b.get("text") for b in (ds.get("benign") or [])]
                        da = debsums_analysis([x for x in src if x])
                        integ = dict(stored)
                        tools = dict(integ.get("tools") or {})
                        tools["debsums"] = dict(ds, all_warnings=list(da["warnings"]), warnings=list(da["warnings"]),
                                                benign=da["benign"], notes=da["notes"], rules=DEBSUMS_RULES_VERSION)
                        integ["tools"] = tools
                        self.apply_integrity_acks(integ)
                        self.state.update(integrity=integ)
                        stored = integ
                        self.broadcast({"event": "integrity", "integrity": self.integrity_payload()})
                        self.refresh_overall()
                        log(f"Fichiers debsums reclassés : {len(da['benign'])} bénin(s), {len(da['warnings'])} à vérifier")
                    except Exception as e:  # noqa: BLE001
                        log(f"Reclassement debsums : {e}")
                # Incomplete chkrootkit scan (header without its paths, versions < 1.12.1) or without classification
                chk = (stored.get("tools") or {}).get("chkrootkit") or {}
                old_style = any(str(w).rstrip().endswith(":") for w in (chk.get("all_warnings") or chk.get("warnings") or []))
                if os.geteuid() == 0 and not self.integrity_running and chk.get("ran") \
                        and (old_style or chk.get("rules") != CHK_RULES_VERSION):
                    log("chkrootkit relancé (relevé incomplet)")
                    threading.Thread(target=self._chkrootkit_rescan, daemon=True).start()
            # Central whitelist (signed), enterprise policy, opt-in telemetry
            try:
                self.refresh_central_allowlist()
                self.apply_policy()
                self.send_telemetry()
            except Exception as e:  # noqa: BLE001
                log(f"Liste blanche / politique / télémétrie : {e}")
            # Application update
            self.check_app_update()
            # Checklist
            self.refresh_checklist()
        except Exception as e:  # noqa: BLE001
            log(f"Tâches quotidiennes : {e}")
        finally:
            self.daily_running = False

    def check_app_update(self, force=False):
        info = self.updater.check(force=force)
        prev = self.state.get("app_update") or {}
        self.state.update(app_update=info)
        if info.get("available") and info.get("verified") and info.get("version") != prev.get("version"):
            self.publish_alert({"kind": "update", "severity": "info", "time": now_iso(),
                                "title": info["version"], "detail": info.get("date", ""), "update": info,
                                "pid": 0, "comm": "", "exe": "", "count": 0, "top_dir": "", "reasons": [], "sample": []})
            if self.settings.get("app_update_auto"):
                ok, detail = self.updater.install(info)
                self.write_log(f"auto-update {info['version']}: {ok} {detail}")
        self.broadcast({"event": "app_update", "update": info})
        self.refresh_overall()
        return info

    def refresh_checklist_async(self):
        """Checklist and score recomputed in the background (ss, sudoers… a few seconds) after a security action."""
        th = getattr(self, "_checklist_thread", None)
        if th and th.is_alive():
            return

        def run():
            try:
                self.refresh_checklist()
            except Exception as e:  # noqa: BLE001
                log(f"Checklist : {e}")
        self._checklist_thread = threading.Thread(target=run, daemon=True)
        self._checklist_thread.start()

    def refresh_checklist(self):
        checklist = collect_checklist(self)
        # Score history: one value per day (the last one of the day), 400 days at most
        hist = [h for h in (self.state.get("score_history") or []) if isinstance(h, dict)]
        today = now_iso()[:10]
        hist = [h for h in hist if h.get("d") != today] + [{"d": today, "s": checklist.get("score"), "g": checklist.get("grade")}]
        hist = hist[-400:]
        self.state.update(score_history=hist)
        checklist["history"] = hist
        self.state.update(checklist=checklist)
        self.broadcast({"event": "checklist", "checklist": checklist})
        self.refresh_overall()
        return checklist

    # ── Durcissement (recommandations Lynis) ─────────────────────────────
    def integrity_summary(self):
        """Summary for the simple view and the tray: warnings from the rootkit tools (except Lynis), modified
        application files (→ red), Lynis recommendations (→ yellow)."""
        integ = self.state.get("integrity") or {}
        if not integ:
            return None
        tools = integ.get("tools") or {}
        app = integ.get("app") or {}
        per_tool = {n: len(t.get("warnings") or []) for n, t in tools.items()}
        return {"checked_at": integ.get("checked_at"), "warnings": integ.get("warnings"),
                "rootkit": sum(v for n, v in per_tool.items() if n != "lynis"),
                "lynis": per_tool.get("lynis", 0),
                "app_modified": len(app.get("modified") or []) + len(app.get("missing") or []),
                "tools": per_tool}

    def integrity_payload(self):
        """Integrity result + current availability of the tools + hardening state (for the interface)."""
        out = with_tools_now(self.state.get("integrity"))
        h = dict(self.state.get("hardening") or {})
        h.pop("prev", None)
        h["running"] = self.hardening_running
        h["catalog"] = HARDEN_CATALOG
        out["hardening"] = h
        return out

    def pending_safe_hardening(self, integrity):
        """Lynis tests found, safe to apply, neither applied nor failed within the last 7 days."""
        h = self.state.get("hardening") or {}
        applied, failed = h.get("applied") or {}, h.get("failed") or {}
        out = []
        for it in ((integrity or {}).get("lynis") or {}).get("items") or []:
            test = it.get("test")
            if not harden.is_safe(test) or test in applied:
                continue
            try:
                if test in failed and time.time() - datetime.fromisoformat(failed[test]["at"]).timestamp() < 7 * 86400:
                    continue
            except (KeyError, ValueError, TypeError):
                pass
            out.append(test)
        return out

    def start_hardening(self, tests, revert=False, auto=False):
        with self.security_lock:
            if self.hardening_running:
                return False
            self.hardening_running = True
        threading.Thread(target=self._harden_worker, args=(tests, revert, auto), daemon=True).start()
        return True

    def _harden_worker(self, tests, revert, auto):
        """Applies (or reverts) each recommendation, records the result, reruns Lynis, then broadcasts."""
        h = dict(self.state.get("hardening") or {})
        for k in ("applied", "prev", "failed"):
            h[k] = dict(h.get(k) or {})
        ctx = {"file_perms": ((self.state.get("integrity") or {}).get("lynis") or {}).get("file_perms") or []}
        ok = fail = 0
        done_fns = set()
        try:
            for test in tests:
                fn = (harden.CATALOG.get(test) or {}).get("fn")
                if not fn or fn in done_fns:
                    continue
                done_fns.add(fn)
                same = harden.tests_sharing(test)
                try:
                    if TEST_MODE:
                        detail, prev = "test_mode", {}
                    elif revert:
                        detail, prev = harden.revert(fn, h["prev"].get(fn) or {}), None
                    else:
                        detail, prev = harden.apply(fn, ctx)
                except Exception as e:  # noqa: BLE001
                    fail += 1
                    for t in same:
                        h["failed"][t] = {"at": now_iso(), "detail": str(e)[:300], "revert": revert}
                    self.write_log(f"hardening {'revert' if revert else 'apply'} {test} failed: {str(e)[:200]}")
                    continue
                ok += 1
                for t in same:
                    h["failed"].pop(t, None)
                    if revert:
                        h["applied"].pop(t, None)
                    else:
                        h["applied"][t] = {"at": now_iso(), "detail": detail, "fn": fn}
                if revert:
                    h["prev"].pop(fn, None)
                else:
                    h["prev"][fn] = prev or {}
                self.write_log(f"hardening {'reverted' if revert else 'applied'} {test}: {detail}")
            h["last"] = now_iso()
            self.state.update(hardening=h)
            if ok and not TEST_MODE and shutil.which("lynis"):
                self._lynis_rescan()
                self.refresh_checklist()
        except Exception as e:  # noqa: BLE001
            log(f"Durcissement : {e}")
        finally:
            self.hardening_running = False
        index = ((self.state.get("integrity") or {}).get("lynis") or {}).get("index")
        self.broadcast({"event": "integrity", "integrity": self.integrity_payload()})
        self.broadcast({"event": "hardening_done", "ok": ok, "failed": fail, "revert": revert, "auto": auto, "index": index})

    def _lynis_rescan(self):
        """New Lynis audit alone (one to two minutes) after hardening: index and suggestions up to date without
        rerunning the whole integrity check."""
        if self.integrity_running:
            return
        r = run_quiet(["lynis", "audit", "system", "--quick", "--no-colors", "--quiet"], timeout=1800)
        rep = parse_lynis_report()
        integ = dict(self.state.get("integrity") or {})
        if not integ:
            return
        tools = dict(integ.get("tools") or {})
        la = lynis_analysis(rep.get("warnings") or [])
        tools["lynis"] = {"installed": True, "ran": True, "rc": r.returncode, "warnings": list(la["warnings"]),
                          "all_warnings": list(la["warnings"]), "benign": la["benign"], "notes": la["notes"],
                          "rules": LYNIS_RULES_VERSION}
        integ["tools"], integ["lynis"] = tools, rep
        self.apply_integrity_acks(integ)
        self.state.update(integrity=integ)
        self.write_log(f"lynis rescan → index {rep.get('index')}")

    def apply_integrity_acks(self, result):
        """Integrity warnings approved by the user ("That's normal"): set aside, not counted."""
        if not result:
            return result
        acks = set(self.state.get("acknowledged_integrity") or [])
        total = 0
        for name, entry in (result.get("tools") or {}).items():
            allw = entry.get("all_warnings")
            if allw is None:
                allw = entry["all_warnings"] = list(entry.get("warnings") or [])
            entry["warnings"] = [w for w in allw if integrity_ack_key(name, w) not in acks]
            entry["ignored"] = [w for w in allw if integrity_ack_key(name, w) in acks]
            total += len(entry["warnings"])
        app = result.get("app") or {}
        result["warnings"] = total + len(app.get("modified") or []) + len(app.get("missing") or [])
        return result

    # ── Notifications par courrier ────────────────────────────────────────
    def mail_cfg(self):
        return dict(MAIL_DEFAULT, **(self.state.get("mail") or {}))

    def mail_public(self):
        cfg = self.mail_cfg()
        return dict(cfg, transport=mail_transport(), queued=len(self.state.get("mail_queue") or []), hostname=socket.gethostname())

    def mail_event(self, kind, title, body):
        """Event to notify (if mails are enabled and this type is selected): sent right away (immediate)
        or grouped into the next summary (daily, weekly)."""
        cfg = self.mail_cfg()
        if not cfg.get("enabled") or not (cfg.get("events") or {}).get(kind):
            return
        queue = list(self.state.get("mail_queue") or [])
        queue.append({"t": now_iso(), "kind": kind, "title": str(title)[:200], "body": str(body)[:2000]})
        self.state.update(mail_queue=queue[-MAIL_QUEUE_MAX:])
        if cfg.get("frequency") == "immediate":
            self.last_mail_tick = 0                 # the next loop iteration (≤ 10 s) sends it

    def mail_alert_event(self, alert):
        lang = self.mail_cfg().get("lang") or "fr"
        kind = alert.get("kind") or "?"
        title = t(lang, f"mail.alert.{kind}") if t(lang, f"mail.alert.{kind}") != f"mail.alert.{kind}" else t(lang, "mail.alert.generic", kind=kind)
        lines = []
        for k, label in (("comm", "mail.field.program"), ("exe", "mail.field.path"), ("title", "mail.field.title"), ("detail", "mail.field.detail"),
                         ("ip", "mail.field.ip"), ("top_dir", "mail.field.folder"), ("count", "mail.field.count")):
            v = alert.get(k)
            if v not in (None, "", 0, []):
                lines.append(f"{t(lang, label)} : {v}")
        for r in (alert.get("reasons") or [])[:5]:
            lines.append(f"- {t(lang, f'alert.reason.{r}') if t(lang, f'alert.reason.{r}') != f'alert.reason.{r}' else r}")
        self.mail_event("danger", title, "\n".join(lines))

    def mail_scan_event(self, job, status):
        lang = self.mail_cfg().get("lang") or "fr"
        title = t(lang, "mail.scan.infected" if status == "infected" else "mail.scan.clean", n=job.infected)
        body = t(lang, "mail.scan.body", path=job.path, files=job.total + job.cached, infected=job.infected,
                 minutes=int((time.time() - (job.started_at or time.time())) // 60))
        if job.threats:
            body += "\n" + "\n".join(f"- {th}" for th in job.threats[-20:])
        self.mail_event("scan", title, body)

    def mail_summary(self, lang):
        """Summary of the system state in a few lines (for the daily / weekly mails)."""
        ov = self.overall or {}
        color = ov.get("color") or "green"
        reasons = ", ".join(t(lang, f"overall.reason.{r}") for r in (ov.get("reasons") or [])[:5])
        ck = self.state.get("checklist") or {}
        db = db_last_update()
        last = self.state.get("last_scan") or {}
        vulns = (self.state.get("vulns") or {}).get("counts") or {}
        sysst = self.state.get("system_status") or {}
        integ = self.state.get("integrity") or {}
        lines = [t(lang, "mail.summary.title"),
                 f"- {t(lang, 'mail.summary.overall')} : {t(lang, f'mail.color.{color}')}" + (f" ({reasons})" if reasons else ""),
                 f"- {t(lang, 'mail.summary.score')} : {ck.get('score', '—')} ({ck.get('grade', '—')})",
                 f"- {t(lang, 'mail.summary.signatures')} : {db.strftime('%Y-%m-%d %H:%M') if db else '—'}",
                 f"- {t(lang, 'mail.summary.last_scan')} : {str(last.get('date', '—'))[:16]} — {last.get('infected', 0)} {t(lang, 'mail.summary.threats')}",
                 f"- {t(lang, 'mail.summary.updates')} : {sysst.get('security', 0)} / {sysst.get('upgradable', 0)}",
                 f"- {t(lang, 'mail.summary.vulns')} : {vulns.get('unfixed', 0)}",
                 f"- {t(lang, 'mail.summary.integrity')} : {integ.get('warnings', '—')}"]
        return "\n".join(lines)

    def mail_deliver(self, subject, body, kind="digest"):
        """Sending with a daily cap and log; updates last_sent / last_error."""
        cfg = self.mail_cfg()
        today = gmdate_today = time.strftime("%Y-%m-%d")
        sent_today = cfg.get("sent_today") or 0 if cfg.get("sent_day") == today else 0
        if sent_today >= MAIL_MAX_PER_DAY:
            self.write_log(f"mail: daily cap reached ({MAIL_MAX_PER_DAY}), {kind} not sent")
            return False, "daily_cap"
        lang = cfg.get("lang") or "fr"
        footer = "\n\n-- \n" + t(lang, "mail.footer", host=socket.gethostname(), version=VERSION)
        ok, err = mail_send_now(cfg, subject, body + footer)
        mail = dict(self.state.get("mail") or {})
        mail.update(sent_day=today, sent_today=sent_today + (1 if ok else 0), last_error=err if not ok else "",
                    last_sent=now_iso() if ok else mail.get("last_sent"))
        self.state.update(mail=mail)
        self.write_log(f"mail {kind} → {'sent' if ok else 'FAILED: ' + err[:120]} ({', '.join(cfg.get('to') or [])})")
        self.broadcast({"event": "mail", "mail": self.mail_public()})
        return ok, err

    def mail_flush(self, force=False):
        """Sends what is pending: right away (immediate) or as a summary (daily / weekly)."""
        cfg = self.mail_cfg()
        lang = cfg.get("lang") or "fr"
        queue = list(self.state.get("mail_queue") or [])
        with_summary = bool((cfg.get("events") or {}).get("report")) and (force or cfg.get("frequency") != "immediate")
        if not queue and not with_summary:
            return True, "nothing"
        if queue and cfg.get("frequency") == "immediate" and not force:
            subject = queue[0]["title"] if len(queue) == 1 else t(lang, "mail.subject.events", n=len(queue))
        else:
            subject = t(lang, "mail.subject.digest") + (f" — {queue[0]['title']}" if len(queue) == 1 else (f" — {t(lang, 'mail.subject.events', n=len(queue))}" if queue else ""))
        parts = []
        for e in queue:
            parts.append(f"{e['t'][:16].replace('T', ' ')} · {e['title']}" + (f"\n{e['body']}" if e.get("body") else ""))
        body = "\n\n".join(parts) if parts else t(lang, "mail.none")
        if with_summary:
            body += "\n\n" + self.mail_summary(lang)
        ok, err = self.mail_deliver(subject, body, "digest" if with_summary else "events")
        if ok or err == "no recipient":
            self.state.update(mail_queue=[])
            if with_summary:
                mail = dict(self.state.get("mail") or {})
                mail["last_digest"] = time.strftime("%Y-%m-%d")
                self.state.update(mail=mail)
        return ok, err

    def mail_tick(self):
        cfg = self.mail_cfg()
        if not cfg.get("enabled"):
            return
        now = time.localtime()
        queue = self.state.get("mail_queue") or []
        if cfg.get("frequency") == "immediate":
            if queue:
                self.mail_flush()
            return
        due = now.tm_hour == int(cfg.get("hour") or 0) and cfg.get("last_digest") != time.strftime("%Y-%m-%d")
        if cfg.get("frequency") == "weekly":
            due = due and now.tm_wday == int(cfg.get("day") or 0)
        if due:
            self.mail_flush()

    def cached(self, name, ttl, fn):
        """Result of a costly check (per-user dconf, SSH keys, journal) kept for `ttl` seconds."""
        now = time.time()
        hit = self._check_cache.get(name)
        if hit and now - hit[0] < ttl:
            return hit[1]
        value = fn()
        self._check_cache[name] = (now, value)
        return value

    def trusted_map(self):
        """{exe: name} of trusted programs ("Trust"), for the process watch."""
        return {p["exe"]: p.get("comm") or os.path.basename(p["exe"]) for p in (self.state.get("trusted_programs") or []) if p.get("exe")}

    def _builtin_refresh(self, initial=False):
        """Built-in checks (kernel, processes) recomputed in place: new unapproved warning → alert
        (popup) and red shield; disappearance (process ended) → back to green. The tools are not rerun."""
        if (os.geteuid() != 0 and not TEST_MODE) or self.integrity_running:
            return
        stored = self.state.get("integrity") or {}
        if not stored.get("tools"):
            return                                       # never scanned: the first full scan will create them
        integ = dict(stored)
        tools = dict(integ.get("tools") or {})
        new_unknown = []
        trusted = self.trusted_map()
        for name in BUILTIN_CHECKS:
            try:
                entry = builtin_check(name, trusted)
            except Exception as e:  # noqa: BLE001
                log(f"Contrôle intégré {name} : {e}")
                continue
            prev = tools.get(name) or {}
            prev_all = {integrity_warning_norm(name, w) for w in (prev.get("all_warnings") or prev.get("warnings") or [])}
            new_unknown += [(name, w) for w in entry["warnings"] if integrity_warning_norm(name, w) not in prev_all]
            entry["all_warnings"] = list(entry["warnings"])
            tools[name] = entry
        integ["tools"] = tools
        integ = self.apply_integrity_acks(integ) or integ

        def signature(t):
            return json.dumps({n: (e.get("warnings"), [b.get("text") for b in e.get("benign") or []], e.get("ignored"))
                               for n, e in (t or {}).items() if n in BUILTIN_CHECKS}, sort_keys=True, default=str)
        if signature(tools) == signature(stored.get("tools")) and integ.get("warnings") == stored.get("warnings"):
            return
        self.state.update(integrity=integ)
        self.broadcast({"event": "integrity", "integrity": self.integrity_payload()})
        self.refresh_overall()
        fresh = [(n, w) for n, w in new_unknown if w in (tools[n].get("warnings") or [])]
        if fresh and not initial:
            n, w = fresh[0]
            f = watch_alert_fields(n, w, (tools[n].get("notes") or {}).get(w))
            self.write_log("⚠ kernel/process watch: " + "; ".join(
                f"{t}: {x.splitlines()[0][:100]} {' | '.join(ln.strip() for ln in x.splitlines()[1:4])[:200]}" for t, x in fresh[:4]))
            self.publish_alert({"kind": "integrity", "severity": "danger", "time": now_iso(), "title": f["comm"],
                                "detail": f"{f['head']} {f['label']}"[:300] + (f" (+{len(fresh) - 1})" if len(fresh) > 1 else ""),
                                "check": n, "reason": f["reason"], "items": f["items"], "text": w,
                                "pid": f["pid"], "comm": f["comm"], "exe": f["exe"], "count": len(fresh), "top_dir": "", "reasons": [], "sample": []})

    def _chkrootkit_rescan(self):
        """chkrootkit alone (under a minute) when the stored survey is incomplete; built-in classification."""
        if self.integrity_running or not shutil.which("chkrootkit"):
            return
        r = run_quiet(["chkrootkit", "-q"], timeout=1800)
        out = ((r.stdout or "") + (r.stderr or "")).strip().splitlines()
        chk = chkrootkit_analysis(out)
        integ = dict(self.state.get("integrity") or {})
        if not integ:
            return
        tools = dict(integ.get("tools") or {})
        tools["chkrootkit"] = {"installed": True, "ran": True, "rc": r.returncode, "warnings": list(chk["warnings"]),
                               "all_warnings": list(chk["warnings"]), "benign": chk["benign"], "notes": chk["notes"],
                               "rules": CHK_RULES_VERSION}
        integ["tools"] = tools
        self.apply_integrity_acks(integ)
        self.state.update(integrity=integ)
        self.write_log(f"chkrootkit rescan → {len(chk['warnings'])} warning(s), {len(chk['benign'])} known false positive(s)")
        self.broadcast({"event": "integrity", "integrity": self.integrity_payload()})
        self.refresh_overall()

    def _store_integrity(self, result, after_scan=False):
        if "lynis" not in result and ((result.get("tools") or {}).get("lynis") or {}).get("timed_out"):
            prev = (self.state.get("integrity") or {}).get("lynis")
            if prev:
                result["lynis"] = prev                   # audit interrupted: the last full scan stays displayed
        self.apply_integrity_acks(result)
        self.last_integrity = time.time()
        self.state.update(integrity=result, last_integrity=now_iso())
        if result["warnings"]:
            self.publish_alert({"kind": "integrity", "severity": "warn", "time": now_iso(),
                                "title": str(result["warnings"]), "detail": ", ".join(
                                    [n for n, t in result["tools"].items() if t["warnings"]] +
                                    (["app"] if result["app"]["modified"] or result["app"]["missing"] else [])),
                                "pid": 0, "comm": "", "exe": "", "count": 0, "top_dir": "", "reasons": [], "sample": []})
        self.broadcast({"event": "integrity", "integrity": self.integrity_payload(), "after_scan": after_scan})
        self.refresh_overall()
        # Automatic hardening (setting): safe Lynis recommendations not applied yet
        if self.settings.get("auto_harden") and not TEST_MODE:
            tests = self.pending_safe_hardening(result)
            if tests and self.start_hardening(tests, auto=True):
                self.write_log("auto hardening: " + ", ".join(tests))

    def run_integrity(self, after_scan=False):
        if self.integrity_running:
            return False
        self.integrity_running = True
        try:
            self.broadcast({"event": "integrity_running"})
            self.integrity_progress = None
            self._store_integrity(run_integrity_checks(progress=self.integrity_progress_cb, trusted=self.trusted_map()), after_scan=after_scan)
            return True
        finally:
            self.integrity_running = False
            self.integrity_progress = None

    def check_weekly_integrity(self):
        if not self.settings.get("integrity_weekly"):
            return
        now = datetime.now()
        if now.weekday() != int(self.settings.get("integrity_day")) or now.hour != int(self.settings.get("integrity_hour")):
            return
        last = self.state.get("last_integrity")
        try:
            if last and (now - datetime.fromisoformat(last)).days < 6:
                return
        except ValueError:
            pass
        threading.Thread(target=self.run_integrity, daemon=True).start()

    @staticmethod
    def public_vulns(vulns):
        return {k: v for k, v in (vulns or {}).items() if k != "cache"}

    # ── Overall color (tray icon, simple view) ───────────────────────────
    def user_trusted(self):
        """Executables approved by the user ("It's me"): never alerted on again."""
        return self._trusted_set

    # ── Learned habits: write bursts that the user declared normal ("It's OK") ──
    @staticmethod
    def habit_key(exe, top_dir):
        """What is remembered from a burst: its program when known, otherwise the exact folder it writes to
        (never wider: automatically ignoring a whole documents folder would open the door to ransomware)."""
        exe = normalize_exe(exe)
        if exe:
            # Never an interpreter: "python3 is OK" would cover every Python script, malware included
            if is_interpreter(exe):
                return ""
            return "" if exe.startswith(("/tmp/", "/var/tmp/", "/dev/shm/")) else exe
        top_dir = os.path.normpath(top_dir or "/")
        return "dir:" + top_dir if top_dir.count("/") >= 3 else ""

    def habit_learned(self, key):
        return bool(key) and int(((self.state.get("habits") or {}).get(key) or {}).get("n") or 0) >= HABIT_LEARNED_AT

    def habit_note(self, key, delta=1):
        if not key:
            return
        habits = dict(self.state.get("habits") or {})
        entry = dict(habits.get(key) or {})
        entry["n"] = max(0, int(entry.get("n") or 0) + delta)
        entry["last"] = now_iso()
        if entry["n"]:
            habits[key] = entry
        else:
            habits.pop(key, None)
        if len(habits) > 300:
            for old in sorted(habits, key=lambda k: habits[k].get("last", ""))[:len(habits) - 300]:
                habits.pop(old, None)
        self.state.update(habits=habits)
        if delta > 0 and entry["n"] == HABIT_LEARNED_AT:
            self.write_log(f"habit learned: file bursts of {key} are now ignored automatically")

    def central_trusted(self, exe):
        """Dukiwi central allowlist (signed) + trusted programs of the business policy + the Dukiwi
        applications themselves (recognized automatically)."""
        if dukiwi_program(exe):
            return True
        for pat in self.central_patterns:
            # Folder patterns of home directories (~/.steam/*…) describe where applications write, never which
            # program to trust: any program of the account can copy itself there
            if pat.startswith("/home/"):
                continue
            if fnmatch.fnmatch(exe, pat) and root_owned_chain(exe):
                return True
        return False

    def load_central_allowlist(self):
        """Loads allowlist.json (already verified) and the programs of the policy."""
        patterns = []
        try:
            with open(ALLOWLIST_FILE, encoding="utf-8") as f:
                data = json.load(f)
            for pat in data.get("programs") or []:
                pat = str(pat)
                patterns.append(pat.replace("~/", "/home/*/") if pat.startswith("~/") else pat)
            self.state.update(allowlist_version=data.get("version"), allowlist_updated=data.get("updated"))
        except (OSError, ValueError):
            pass
        for pat in (self.policy or {}).get("trusted_programs") or []:
            patterns.append(str(pat))
        self.central_patterns = patterns

    def refresh_central_allowlist(self):
        """Downloads allowlist.json + .sig, checks the Dukiwi signature, replaces the local file."""
        tmp = ALLOWLIST_FILE + ".new"
        try:
            data = http_get(ALLOWLIST_URL, timeout=30)
            sig = http_get(ALLOWLIST_URL + ".sig", timeout=30)
            with open(tmp, "wb") as f:
                f.write(data)
            with open(tmp + ".sig", "wb") as f:
                f.write(sig)
            ok, detail = gpg_verify(tmp + ".sig", tmp)
            if not ok:
                log(f"Liste blanche : signature refusée ({detail})")
                return False
            doc = json.loads(data.decode("utf-8"))
            # Any document signed with the Dukiwi key verifies: only an allowlist (programs list, numbered) is
            # taken, and never an older one than the list already in use (a replayed old list would bring back
            # entries removed since)
            if not isinstance(doc, dict) or not isinstance(doc.get("programs"), list) or doc.get("type", "allowlist") != "allowlist":
                log("Liste blanche : document signé qui n'est pas une liste blanche, ignoré")
                return False
            try:
                newer = int(doc.get("version") or 0) >= int(self.state.get("allowlist_version") or 0)
            except (TypeError, ValueError):
                newer = False
            if not newer:
                self.write_log(f"⚠ central allowlist: version {doc.get('version')} older than {self.state.get('allowlist_version')}, refused")
                return False
            os.replace(tmp, ALLOWLIST_FILE)
            os.replace(tmp + ".sig", ALLOWLIST_FILE + ".sig")
            self.load_central_allowlist()
            self.monitor.dpkg_cache.clear()
            log(f"Liste blanche centrale : {len(self.central_patterns)} motif(s)")
            return True
        except Exception as e:  # noqa: BLE001
            log(f"Liste blanche : {e}")
            return False
        finally:
            for p in (tmp, tmp + ".sig"):
                try:
                    os.remove(p)
                except OSError:
                    pass

    def apply_policy(self, startup=False):
        """Applies the business policy: enforced settings (locked), firewall profile, trusted programs."""
        policy = load_policy()
        if not policy:
            if self.policy:
                self.policy, self.locked_settings = {}, set()
                self.load_central_allowlist()
            return
        if policy.get("_mtime") == (self.policy or {}).get("_mtime") and not startup:
            return
        self.policy = policy
        settings = policy.get("settings") or {}
        if isinstance(settings, dict) and settings:
            changed, errors = self.settings.update(settings)
            if changed and not startup:
                self.apply_settings(changed)
            if errors:
                log(f"Politique : réglages ignorés {errors}")
        locked = set(policy.get("locked") or [])
        if policy.get("lock_all"):
            locked |= set(settings.keys())
        self.locked_settings = {k for k in locked if k in DEFAULT_SETTINGS}
        self.load_central_allowlist()
        profile = policy.get("firewall_profile")
        if profile in FIREWALL_PROFILES and os.geteuid() == 0 and self.settings.get("firewall_profile") != profile:
            ok, text = self.apply_firewall_profile(profile)
            if ok:
                self.settings.update({"firewall_profile": profile})
        log(f"Politique d'entreprise appliquée : {policy.get('name', 'sans nom')}, {len(self.locked_settings)} réglage(s) verrouillé(s)"
            + (" (signée)" if policy.get("_signed") else ""))
        self.write_log(f"policy applied: {policy.get('name', '')}")

    def telemetry_extra(self):
        """Telemetry fields that feed the built-in rules and the performance measurement (no identifier):
        approved integrity warnings, benign classifications, integrity warnings still open (2.9.6: first line, up to
        three detail lines and the built-in reasons, anonymised, so false positives seen elsewhere can be fixed),
        last scan, hardening, packages with high-severity vulnerabilities."""
        integ = self.state.get("integrity") or {}
        tools = integ.get("tools") or {}
        acked, benign, opened = [], {}, []
        for name, t in tools.items():
            notes = t.get("notes") or {}
            for w in (t.get("warnings") or [])[:10]:
                lines = [ln.strip() for ln in str(w).splitlines() if ln.strip()]
                if not lines:
                    continue
                reasons = sorted({n.get("reason") for n in notes.get(w) or []
                                  if n.get("verdict") != "benign" and n.get("reason")})[:5]
                opened.append({"tool": name, "text": anonymize_path(lines[0])[:160],
                               "detail": [anonymize_path(ln)[:160] for ln in lines[1:4]], "reasons": reasons})
            for w in (t.get("ignored") or [])[:10]:
                acked.append({"tool": name, "text": anonymize_path(str(w).splitlines()[0])[:160]})
            for b in t.get("benign") or []:
                for n in b.get("notes") or []:
                    key = f"{name}:{n.get('reason', '?')}"
                    benign[key] = benign.get(key, 0) + 1
        vulns = self.state.get("vulns") or {}
        high = {}
        for it in vulns.get("items") or []:
            if it.get("status") == "unfixed" and it.get("priority") in ("critical", "high") and not it.get("acknowledged"):
                high[it.get("package") or "?"] = high.get(it.get("package") or "?", 0) + 1
        history = self.state.get("history") or []
        last = next((h for h in history if not h.get("usb")), None) or {}
        cutoff = (datetime.now().timestamp() - 30 * 86400)
        usb30 = 0
        for h in history:
            try:
                if h.get("usb") and datetime.fromisoformat(h.get("date", "")).timestamp() >= cutoff:
                    usb30 += 1
            except ValueError:
                pass
        hard = self.state.get("hardening") or {}
        return {
            "acknowledged_integrity": acked[:30],
            "open_integrity": opened[:30],
            "benign_findings": benign,
            "integrity_tools": {n: len(t.get("warnings") or []) for n, t in tools.items()},
            "lynis_index": (integ.get("lynis") or {}).get("index"),
            "hardening": {"applied": sorted(hard.get("applied") or {})[:40], "failed": len(hard.get("failed") or {})},
            "vulns_high": dict(sorted(high.items(), key=lambda kv: -kv[1])[:20]),
            "vulns_acknowledged": (vulns.get("counts") or {}).get("acknowledged_cves") or 0,
            "scan": {k: last.get(k) for k in ("duration", "files", "cached", "skipped", "engine", "infected", "status", "auto")} if last else None,
            "usb_scans_30d": usb30,
            "onaccess": {"scanned": self.onaccess.stats.get("scanned", 0), "infected": self.onaccess.stats.get("infected", 0)},
            "known_networks": len(self.state.get("network_profiles") or {}),
        }

    def send_telemetry(self, force=False):
        """Anonymous telemetry, opt-in, once a week (force: on demand, or after the first full scan):
        version, system, score, approved false positives (anonymized paths). Also right after an update of the
        application (first daily tasks, 90 s after the service starts), so a version that goes wrong shows up within
        hours instead of waiting for the weekly report."""
        if not self.settings.get("telemetry"):
            return False
        last = self.state.get("telemetry_sent") or ""
        # Version of the last report; missing: the last report was sent by a version older than 2.7.10
        sent_version = self.state.get("telemetry_version") or ("before-2.7.10" if last else "")
        updated = bool(sent_version) and sent_version != VERSION
        try:
            if last and not force and not updated and (time.time() - datetime.fromisoformat(last).timestamp()) < 7 * 86400:
                return False
        except ValueError:
            pass
        payload = self.build_telemetry_payload()
        if updated:
            payload["updated_from"] = sent_version
        try:
            http_get(TELEMETRY_URL, timeout=30, data=json.dumps(payload).encode(), headers={"Content-Type": "application/json"})
            self.state.update(telemetry_sent=now_iso(), telemetry_version=VERSION)
            self.write_log("telemetry sent (opt-in)" + (f" after update from {sent_version}" if updated else ""))
            return True
        except Exception as e:  # noqa: BLE001
            log(f"Télémétrie : {e}")
            return False

    def build_telemetry_payload(self):
        """Exactly what would be sent (also shown to the user before they decide)."""
        install_id = self.state.get("install_id")
        if not install_id:
            install_id = uuid.uuid4().hex
            self.state.update(install_id=install_id)
        pretty = ""
        try:
            with open("/etc/os-release") as f:
                for line in f:
                    if line.startswith("PRETTY_NAME="):
                        pretty = line.split("=", 1)[1].strip().strip('"')
        except OSError:
            pass
        cutoff = time.time() - 7 * 86400
        alerts = []
        for a in self.state.get("alerts") or []:
            try:
                if datetime.fromisoformat(a.get("time", "")).timestamp() >= cutoff:
                    alerts.append(a.get("kind", "?"))
            except ValueError:
                continue
        checklist = self.state.get("checklist") or {}
        vulns = (self.state.get("vulns") or {}).get("counts") or {}
        payload = {
            "install_id": install_id, "version": VERSION, "os": pretty, "kernel": os.uname().release, "arch": os.uname().machine,
            "settings": {k: self.settings.get(k) for k in ("family_mode", "firewall_profile", "backup_check", "timeshift_check", "auto_response", "auto_ignore_known", "connection_monitor", "honeypot", "url_guard",
                                                             "auto_harden", "scan_cache_days", "integrity_weekly", "weekly_scan")},
            "checklist": {"score": checklist.get("score"), "grade": checklist.get("grade"),
                          "fail": [i["key"] for i in checklist.get("items", []) if i.get("status") == "fail"],
                          "warn": [i["key"] for i in checklist.get("items", []) if i.get("status") == "warn"]},
            "alerts_7d": {k: alerts.count(k) for k in set(alerts)},
            "trusted_programs": anonymize_list(t.get("exe") for t in (self.state.get("trusted_programs") or [])),
            "acknowledged_persistence": anonymize_list(self.state.get("acknowledged_persistence") or []),
            "vulns": {k: vulns.get(k) for k in ("unfixed", "fix_available", "pro_only", "kernel_pending", "not_applicable", "na_embedded", "na_vendor", "na_headers", "kernel_hwe_fixed")},
            "integrity_warnings": (self.state.get("integrity") or {}).get("warnings"),
            "timeshift": bool((self.state.get("timeshift") or {}).get("schedule")),
            "policy": bool(self.policy),
        }
        try:
            payload.update(self.telemetry_extra())
        except Exception as e:  # noqa: BLE001
            log(f"Télémétrie (champs) : {e}")
        return payload

    def apply_acknowledged(self, pers):
        """Applies the persistence entries approved by the user and recomputes the counters."""
        if not pers:
            return pers
        ack = set(self.state.get("acknowledged_persistence") or [])
        items, exts = pers.get("items") or [], pers.get("extensions") or []
        for it in items:
            base = it.get("trusted_base", it.get("trusted"))   # original dpkg trust, kept so the approval can be withdrawn
            it["trusted_base"] = base
            it["approved"] = it.get("key") in ack
            it["trusted"] = bool(base) or it["approved"]
        for e in exts:
            e["approved"] = e.get("key") in ack
        pers["counts"] = {"items": len(items), "untrusted": sum(1 for it in items if not it.get("trusted")),
                          "extensions": len(exts),
                          "ext_outside_store": sum(1 for e in exts if not e.get("from_store") and not e.get("approved"))}
        return pers

    def compute_overall(self):
        reasons = []
        color = "green"

        def raise_to(level, reason):
            nonlocal color
            order = {"green": 0, "yellow": 1, "blue": 2, "red": 3}
            if order[level] > order[color]:
                color = level
            reasons.append(reason)

        db = db_last_update()
        age_days = (datetime.now() - db).days if db else 99
        if age_days >= 2:
            raise_to("red", "signatures_old")
        elif age_days >= 1:
            raise_to("blue", "signatures_stale")
        sysst = self.state.get("system_status") or {}
        if sysst.get("security"):
            raise_to("red", "security_updates")
        elif sysst.get("upgradable"):
            raise_to("yellow", "updates")
        if sysst.get("reboot_required"):
            raise_to("yellow", "reboot")
        sec = self.security or {}
        ufw, ssh = sec.get("ufw", {}), sec.get("ssh", {})
        if ufw.get("installed") and not ufw.get("active"):
            raise_to("red", "firewall_off")
        elif not ufw.get("installed"):
            raise_to("red", "firewall_missing")
        if ssh.get("active"):
            raise_to("red" if not ufw.get("active") else "yellow", "ssh_exposed" if not ufw.get("active") else "ssh_active")
        cutoff = time.time() - 86400
        for a in (self.state.get("alerts") or [])[:20]:
            try:
                ts = datetime.fromisoformat(a.get("time", "")).timestamp()
            except ValueError:
                continue
            if ts < cutoff or a.get("ignored"):
                continue                                 # "It's OK": the alert stays listed but no longer counts
            # Kernel/process watch (kind integrity): the current integrity scan is authoritative (red as long as
            # the warning is there, green once the process is gone or has been approved), not the 24 h alert.
            if a.get("severity") == "danger" and a.get("kind") not in ("honeypot", "integrity"):
                raise_to("red", "danger_alert")
                break
        if (self.honeypot.summary() or {}).get("danger_24h"):
            raise_to("yellow", "network_scan")           # a device is scanning this computer: block or ignore
        if self.suspended:
            raise_to("red", "suspended_process")
        if self.state.get("isolated"):
            raise_to("red", "isolated")
        integ = self.state.get("integrity") or {}
        app = integ.get("app") or {}
        rootkit_warns = sum(len(t.get("warnings") or []) for name, t in (integ.get("tools") or {}).items() if name != "lynis") \
            + len(app.get("modified") or []) + len(app.get("missing") or [])
        if rootkit_warns:
            raise_to("red", "integrity_warnings")          # rootkits, modified package or application files
        elif integ.get("warnings"):
            raise_to("yellow", "hardening_warnings")       # Lynis warnings only (hardening): not a compromise
        vulns = self.state.get("vulns") or {}
        counts = vulns.get("counts") or {}
        if counts.get("unfixed") or counts.get("pro_only"):
            raise_to("blue", "open_vulns")
        if vulns.get("flatpak") or vulns.get("snap"):
            raise_to("yellow", "app_store_updates")
        upd = self.state.get("app_update") or {}
        if upd.get("available") and upd.get("verified"):
            raise_to("yellow", "app_update")
        pers = self.state.get("persistence") or {}
        if (pers.get("counts") or {}).get("untrusted"):
            raise_to("yellow", "unknown_persistence")
        if not self.monitor.active and not TEST_MODE:
            raise_to("yellow", "monitor_inactive")
        # Availability (CIA): Timeshift system snapshots
        ts = self.state.get("timeshift") or {}
        if self.settings.get("timeshift_check") is not False and ts.get("checked_at"):     # backup_check = fichiers seulement
            if not ts.get("installed") or not ts.get("configured") or not ts.get("schedule"):
                raise_to("yellow", "timeshift_off")
            elif ts.get("last"):
                try:
                    if (time.time() - datetime.fromisoformat(ts["last"]).timestamp()) > 30 * 86400:
                        raise_to("yellow", "timeshift_old")
                except ValueError:
                    pass
        return {"color": color, "reasons": reasons}

    def refresh_overall(self):
        new = self.compute_overall()
        if new != self.overall:
            self.overall = new
            self.broadcast({"event": "overall", "overall": new})
        return new

    # ── Sessions administrateur ──────────────────────────────────────────
    def is_unlocked(self, uid, req=None):
        """True for root, or for a request carrying the token handed out by the last unlock of this uid. The token
        only reaches the program that ran pkexec (the GUI): other programs of the same account get nothing from the
        unlock."""
        if uid == 0:
            return True
        exp, token = self.unlocked.get(uid) or (0, "")
        if not exp or exp <= time.time():
            self.unlocked.pop(uid, None)
            return False
        given = str((req or {}).get("admin_token") or "")
        return bool(given) and hmac.compare_digest(given, token)

    def admin_required(self, cmd, req, uid):
        """Actions reserved for an authenticated administrator (pkexec → unlock)."""
        # Protected folders: any program can talk to the service; malware must not be able to allow itself,
        # turn off the protection, or remove a folder without the administrator password.
        if cmd in ("protected_allow", "protected_folder_remove"):
            return not (cmd == "protected_allow" and req.get("remove"))
        if cmd == "set_settings" and (req.get("settings") or {}).get("protected_folders") is False and self.settings.get("protected_folders"):
            return True
        if cmd == "firewall_set":
            return not req.get("enabled")
        if cmd == "firewall_profile":
            # The user knows which network they are on: the service applies the profile without a password, even in
            # family mode and for an account without administrator rights (decision 2026-09-29).
            return False
        if cmd in ("timeshift_disable", "harden_revert", "mail_configure", "mail_test", "mail_flush"):
            return True
        # Wiping the evidence (service log, alerts of every user) or removing system-wide browser policies
        if cmd in ("clear_log", "clear_alerts") or (cmd == "browser_harden" and req.get("remove")):
            return True
        # Snapshots of the whole system (/etc/shadow included) on a drive the caller brings: administrator
        if cmd == "timeshift_enable" and req.get("device_uuid"):
            return True
        if cmd == "ssh_set":
            return bool(req.get("enabled"))
        if cmd == "feature_answer":
            # Offering / enabling an advanced protection: never a password. Disabling it: administrator in family
            # mode.
            feature = str(req.get("feature") or "")
            return bool(self.settings.get("family_mode")) and not req.get("enabled") and bool(self.settings.get(feature))
        if cmd in ("firewall_defaults", "firewall_rule_add", "firewall_rule_delete", "install_update", "install_tools",
                   "install_phased", "install_package", "firmware_update", "password_policy_apply"):
            return True
        # "Ignore" an unfixed vulnerability or an intended open port, mount a USB key without scanning or trust it:
        # never a password, even in family mode (acknowledge_vuln, acknowledge_port, ignore_check, usb_skip,
        # untrust_usb are not listed here). The choice is logged; we trust the user.
        if (cmd == "isolate" and req.get("on", True) is False) or cmd == "browser_harden":
            return bool(self.settings.get("family_mode"))
        if cmd == "ssh_key_remove":
            # Own key: no password; another account's key: administrator
            try:
                return os.stat(str(req.get("path") or "")).st_uid != uid
            except OSError:
                return True
        # Any program of any account can talk to the service: trusting a program (it would no longer be stopped) or
        # weakening a protection must come from someone who knows the administrator password (2.9.0)
        if cmd == "trust_program":
            return True
        if cmd == "set_settings" and self.settings_lowering(req.get("settings") or {}):
            return True
        if cmd in ("set_settings", "untrust_program", "acknowledge_persistence", "acknowledge_integrity", "acknowledge_alert", "acknowledge_sudoers", "hid_allow", "hid_forget", "network_gateway_accept",
                   "system_upgrade", "harden_apply", "forget_network"):
            return bool(self.settings.get("family_mode"))
        return False

    # Settings whose False means less protection, numbers where a larger (or smaller) value means fewer alerts
    PROTECTIVE_SWITCHES = ("upload_monitor", "burst_monitor", "usb_auto_scan", "auto_response", "connection_monitor",
                           "on_access_scan", "usb_keyboard_guard", "ransomware_decoys", "privacy_watch", "miner_watch",
                           "keylogger_watch", "login_watch", "protected_folders", "integrity_weekly", "honeypot",
                           "url_guard", "mail_scan_attachments", "app_update_check")
    LOOSER_IF_HIGHER = ("burst_info_threshold", "burst_danger_threshold", "upload_alert_gb")
    LOOSER_IF_LOWER = ("burst_window_sec", "usb_auto_scan_max_gib")

    def settings_lowering(self, incoming):
        """True if these settings would weaken the protection compared with the current ones."""
        if not isinstance(incoming, dict):
            return False
        cur = self.settings.snapshot() if hasattr(self.settings, "snapshot") else dict(self.settings)
        for k in self.PROTECTIVE_SWITCHES:
            if k in incoming and incoming[k] is False and cur.get(k) is not False:
                return True
        if incoming.get("auto_ignore_known") is True and cur.get("auto_ignore_known") is False:
            return True
        if "filtered_dns" in incoming and not incoming["filtered_dns"] and cur.get("filtered_dns"):
            return True
        if incoming.get("family_mode") is False and cur.get("family_mode"):
            return True
        try:
            for k in self.LOOSER_IF_HIGHER:
                if k in incoming and float(incoming[k]) > float(cur.get(k) or 0):
                    return True
            for k in self.LOOSER_IF_LOWER:
                if k in incoming and float(incoming[k]) < float(cur.get(k) or 0):
                    return True
        except (TypeError, ValueError):
            return True
        return False

    # ── First installation / automatic resume ────────────────────────────
    def check_first_scan(self):
        """Schedules the initial full scan (and an update first if the databases are missing)."""
        if self.shutdown.is_set():
            return
        with self.queue_lock:
            busy = self.current is not None or bool(self.queue)
        if busy:
            return
        prog = self.load_progress()
        if prog.get("in_progress") and prog.get("auto"):
            log(f"Reprise du scan automatique interrompu de {prog.get('path')}")
            self.enqueue(Job("scan", path=prog.get("path", "/"), resume=True, auto=True,
                             requested_by="system"))
            return
        if not os.path.exists(FIRST_SCAN_FLAG):
            return
        if time.time() - self.last_first_scan_attempt < 600:
            return
        self.last_first_scan_attempt = time.time()
        if db_last_update() is None:
            log("Bases virales absentes : mise à jour avant le scan initial")
            self.enqueue(Job("update", auto=True, requested_by="system"))
        log("Scan complet initial du système (première installation)")
        self.enqueue(Job("scan", path="/", auto=True, requested_by="system"))

    def maintenance_loop(self):
        time.sleep(15)  # let the system finish booting
        first_status_done = False
        while not self.shutdown.is_set():
            try:
                self.check_first_scan()
                self.check_weekly_scan()
                if not first_status_done:
                    first_status_done = True
                    threading.Thread(target=self.refresh_system_status, daemon=True).start()
                if time.time() - self.last_security > 300:
                    self.refresh_security(force=True)
                    self.refresh_overall()
                if time.time() - self.last_daily > 86400 and not self.daily_running:
                    threading.Thread(target=self.daily_tasks, daemon=True).start()
                self.check_weekly_integrity()
                self.check_weekly_summary()
                self.check_monthly_report()
                if time.time() - self.last_urlguard_check > 900 and self.settings.get("url_guard") is not False \
                        and self.urlguard.feeds_stale() and not self.urlguard.refreshing:
                    self.last_urlguard_check = time.time()
                    threading.Thread(target=self.urlguard.refresh, daemon=True, name="urlguard-refresh").start()
                for uid, (exp, _token) in list(self.unlocked.items()):
                    if exp < time.time():
                        self.unlocked.pop(uid, None)
            except Exception as e:  # noqa: BLE001
                log(f"Maintenance : {e}")
            self.shutdown.wait(60)

    # ── Statut ───────────────────────────────────────────────────────────
    def status(self, uid=-1, req=None):
        with self.queue_lock:
            job = self.current.public() if self.current else None
            queue = [j.public() for j in self.queue]
        if job and job.get("phase") == "integrity" and self.integrity_progress:
            job["integrity_progress"] = self.integrity_progress
        prog = self.load_progress()
        resumable = None
        if prog.get("in_progress") and not job:
            resumable = {"path": prog.get("path"), "scanned": prog.get("scanned", 0),
                         "total": prog.get("total", 0), "auto": prog.get("auto", False)}
        db = db_last_update()
        state = self.state.snapshot()
        sys_status = state.get("system_status") or {}
        return {
            "ok": True, "version": VERSION, "job": job, "queue": queue,
            "distro": {"family": distro.FAMILY, "id": distro.DISTRO["id"], "pretty": distro.DISTRO["pretty"]},
            "hostname": socket.gethostname(), "kernel": os.uname().release,
            "onaccess": dict(self.onaccess.stats, enabled=self.settings.get("on_access_scan") is not False),
            "isolated": self.state.get("isolated"),
            "state": {k: v for k, v in state.items() if k not in ("system_status", "alerts", "vulns", "checklist", "integrity", "persistence", "app_update", "trusted_programs", "acknowledged_persistence")
                      and k not in STATE_SECRET_KEYS},
            "resumable": resumable,
            "first_scan_pending": os.path.exists(FIRST_SCAN_FLAG),
            "db_last_update": db.isoformat(timespec="seconds") if db else None,
            "db_files": db_files_info(),
            "monitor_active": self.monitor.active,
            "network_active": self.network.active,
            "upload_gb": round(self.network.current_gb, 2),
            "usb_active": self.usb.active,
            "usb_pending": self.usb.pending_list(),
            "settings": self.settings.snapshot(),
            "security": self.security or self.refresh_security(broadcast=False),
            "timeshift": self.state.get("timeshift"),
            "overall": self.overall,
            "unlocked": self.is_unlocked(uid, req) if uid >= 0 else False,
            "family_mode": bool(self.settings.get("family_mode")),
            "admin_groups": [g for g in uid_groups(uid) if g in ADMIN_GROUPS] if uid > 0 else [],
            "suspended": list(self.suspended.values()),
            "app_update": {k: v for k, v in (state.get("app_update") or {}).items() if k != "path"},
            "vulns_summary": {k: (state.get("vulns") or {}).get(k) for k in ("checked_at", "counts", "by_priority", "ok", "error")}
                              | {"flatpak": len((state.get("vulns") or {}).get("flatpak", [])), "snap": len((state.get("vulns") or {}).get("snap", []))}
                              if state.get("vulns") else None,
            "checklist_summary": dict({k: (state.get("checklist") or {}).get(k) for k in ("checked_at", "score", "grade")},
                                      todo=sum(1 for i in (state.get("checklist") or {}).get("items", []) if i.get("status") in ("warn", "fail")))
            if state.get("checklist") else None,
            "integrity_summary": self.integrity_summary(),
            "honeypot_summary": self.honeypot.summary(),
            "urlguard_summary": self.urlguard.summary(),
            "persistence_summary": (state.get("persistence") or {}).get("counts"),
            "connections_active": self.connections.active,
            "alerts": (state.get("alerts") or [])[:10],
            "system_status": {k: sys_status.get(k) for k in
                              ("checked_at", "ok", "upgradable", "security", "recommended", "phased", "held", "cve_count",
                               "reboot_required", "os", "kernel", "lists_updated")} if sys_status else None,
        }

    # ── System quarantine ────────────────────────────────────────────────
    def quarantine_list(self):
        files = []
        try:
            for f in sorted(Path(SYSTEM_QUARANTINE_DIR).iterdir(),
                            key=lambda x: x.stat().st_mtime, reverse=True):
                if f.is_file() and not f.name.startswith(".clamav-quarantine-lock"):
                    st = f.stat()
                    files.append({
                        "name": f.name, "path": str(f), "size": st.st_size,
                        "date": datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M"),
                        "scope": "system",
                    })
        except OSError:
            pass
        return quarantine_enrich(files, SYSTEM_QUARANTINE_DIR)

    @staticmethod
    def admin_member(uid):
        """Root or a member of an administrator group (sees every account's alerts, logs and quarantine)."""
        return uid == 0 or (uid > 0 and any(g in ADMIN_GROUPS for g in uid_groups(uid)))

    @staticmethod
    def _user_name(uid):
        try:
            return pwd.getpwuid(uid).pw_name
        except (KeyError, TypeError):
            return ""

    def visible_alerts(self, uid):
        alerts = self.state.get("alerts", []) or []
        if self.admin_member(uid):
            return alerts
        me = self._user_name(uid)
        return [a for a in alerts if str(a.get("user") or "") in ("", me)]

    @staticmethod
    def _quarantine_owner(path):
        """uid of the user a quarantined file was taken from (index, else the file owner); 0 when unknown."""
        owner = (quarantine_index_load(SYSTEM_QUARANTINE_DIR).get(os.path.basename(path)) or {}).get("owner")
        if owner is None:
            try:
                owner = os.lstat(path).st_uid
            except OSError:
                owner = 0
        try:
            return int(owner)
        except (TypeError, ValueError):
            return 0

    def _quarantine_fd(self, src, path, st):
        """Copies the open file src into quarantine, then removes path only if it is still that very file (same
        device and inode, looked up without following a symbolic link)."""
        dest = OnAccessScanner.quarantine_copy(src, path)
        if not dest:
            return ""
        try:
            pfd = os.open(os.path.dirname(path) or "/", os.O_RDONLY | os.O_DIRECTORY)
            try:
                cur = os.stat(os.path.basename(path), dir_fd=pfd, follow_symlinks=False)
                if (cur.st_dev, cur.st_ino) == (st.st_dev, st.st_ino):
                    os.unlink(os.path.basename(path), dir_fd=pfd)
            finally:
                os.close(pfd)
        except OSError as e:
            self.write_log(f"quarantine: {path} copied but not removed: {e}")
        quarantine_index_add(SYSTEM_QUARANTINE_DIR, dest, path, "", owner=st.st_uid)
        return dest

    @staticmethod
    def _in_quarantine(path):
        try:
            p = Path(path).resolve()
            return p.parent == Path(SYSTEM_QUARANTINE_DIR).resolve() and p.is_file()
        except OSError:
            return False

    # ── Autorisations ────────────────────────────────────────────────────
    @staticmethod
    def _home_of(uid):
        try:
            return pwd.getpwuid(uid).pw_dir
        except KeyError:
            return None

    def _scan_path_allowed(self, path, uid):
        if uid == 0:
            return True
        norm = os.path.normpath(path)
        if norm in DAEMON_ALLOWED_ROOTS:
            return True
        if norm.startswith(("/media/", "/mnt/")):
            return True          # mounted removable media
        home = self._home_of(uid)
        if home and home != "/" and (norm == home or norm.startswith(home.rstrip("/") + "/")):
            return True
        return False

    def _dest_allowed(self, dest, uid):
        if uid == 0:
            return True
        home = self._home_of(uid)
        norm = os.path.normpath(dest)
        return bool(home and home != "/" and (norm == home or norm.startswith(home.rstrip("/") + "/")))

    # ── Command handling ─────────────────────────────────────────────────
    def handle(self, req, uid):
        cmd = req.get("cmd")

        if cmd == "ping":
            return {"ok": True, "version": VERSION}

        if cmd == "status":
            return self.status(uid, req)

        if cmd == "unlock":
            target = int(req.get("uid", -1))
            if uid != 0 and not TEST_MODE:
                return {"ok": False, "error": "forbidden"}
            if target < 0:
                return {"ok": False, "error": "invalid_uid"}
            token = secrets.token_hex(24)
            self.unlocked[target] = (time.time() + UNLOCK_TTL, token)
            self.write_log(f"admin unlock uid {target}")
            # The token goes back to the unlock helper only (printed for the GUI that ran pkexec), never broadcast
            self.broadcast({"event": "unlocked", "uid": target, "ttl": UNLOCK_TTL})
            return {"ok": True, "ttl": UNLOCK_TTL, "token": token}

        if cmd == "lock":
            self.unlocked.pop(uid, None)
            self.broadcast({"event": "locked", "uid": uid})
            return {"ok": True}

        if cmd == "auth_status":
            return {"ok": True, "unlocked": self.is_unlocked(uid, req), "family_mode": bool(self.settings.get("family_mode")),
                    "admin_groups": [g for g in uid_groups(uid) if g in ADMIN_GROUPS] if uid > 0 else []}

        if self.admin_required(cmd, req, uid) and not self.is_unlocked(uid, req):
            return {"ok": False, "error": "admin_required"}

        if cmd == "overall":
            return {"ok": True, "overall": self.refresh_overall()}

        if cmd == "check_update":
            info = self.check_app_update(force=True)
            return {"ok": True, "update": {k: v for k, v in info.items() if k != "path"}}

        if cmd == "install_update":
            info = self.state.get("app_update") or {}
            ok, detail = self.updater.install(info)
            self.write_log(f"install update {info.get('version')}: {ok} {detail}")
            return {"ok": ok, "error": "" if ok else "command_failed", "detail": detail}

        if cmd == "app_integrity":
            return {"ok": True, "integrity": app_integrity()}

        if cmd == "vulns":
            if req.get("refresh") and not self.daily_running:
                threading.Thread(target=self.daily_tasks, kwargs={"force": True}, daemon=True).start()
                return {"ok": True, "refreshing": True, "vulns": self.public_vulns(self.state.get("vulns"))}
            return {"ok": True, "refreshing": self.daily_running, "vulns": self.public_vulns(self.state.get("vulns"))}

        if cmd == "checklist":
            if req.get("refresh"):
                self.refresh_security(force=True, broadcast=False)
                return {"ok": True, "checklist": self.refresh_checklist()}
            return {"ok": True, "checklist": self.state.get("checklist")}

        if cmd == "connections":
            return {"ok": True, "connections": self.connections.snapshot()}

        if cmd == "honeypot":
            return {"ok": True, "honeypot": self.honeypot.snapshot()}

        # ── Link and email checks (Thunderbird / browser extensions, via the native host) ──
        if cmd == "url_check":
            if self.settings.get("url_guard") is False:
                return {"ok": True, "enabled": False, "results": []}
            urls = req.get("urls") if isinstance(req.get("urls"), list) else [req.get("url")]
            results = self.urlguard.check_many([u for u in urls if u][:200], req.get("context") or {}, str(req.get("source") or "")[:20], uid=uid)
            return {"ok": True, "enabled": True, "results": results}

        if cmd == "url_report":
            verdict, action = str(req.get("verdict") or "")[:10], str(req.get("action") or "")[:20]
            self.urlguard.report(req.get("url") or "", verdict, action, str(req.get("source") or "")[:20])
            if action == "opened" and verdict == "danger":
                self.write_log(f"⚠ url opened anyway ({req.get('source')}): {str(req.get('url'))[:200]}")
            self.broadcast({"event": "urlguard", "summary": self.urlguard.summary()})
            return {"ok": True}

        if cmd == "url_allow":
            ok = self.urlguard.allow(req.get("host") or "", remove=bool(req.get("remove")), by=str(req.get("source") or "")[:20], uid=uid)
            self.write_log(f"url {'unallow' if req.get('remove') else 'allow'} {req.get('host')} (uid {uid})")
            return {"ok": ok, "error": "" if ok else "invalid_host"}

        if cmd == "urlguard_hello":
            self.urlguard.hello(str(req.get("app") or "other"), str(req.get("version") or ""), uid)
            return {"ok": True, "version": VERSION, "enabled": self.settings.get("url_guard") is not False,
                    "mail_scan": self.settings.get("mail_scan_attachments") is not False}

        if cmd == "urlguard":
            snap = self.urlguard.snapshot()
            snap["browsers"] = {app: any(shutil.which(b) for b in bins) or any(os.path.exists(p) for p in (f"/snap/bin/{bins[0]}", f"/var/lib/flatpak/exports/bin/{bins[0]}"))
                                for app, bins in BROWSER_BINARIES.items()}
            return {"ok": True, "urlguard": snap}

        if cmd == "urlguard_refresh":
            if not self.urlguard.refreshing:
                threading.Thread(target=self.urlguard.refresh, kwargs={"force": True}, daemon=True).start()
            return {"ok": True, "refreshing": True}

        if cmd == "url_scan":
            # Attachment dropped by the native host in /tmp/dukiwi-shield-mail-<uid>/: ownership check, clamd
            if self.settings.get("mail_scan_attachments") is False:
                return {"ok": True, "enabled": False, "infected": False}
            path = os.path.realpath(str(req.get("path") or ""))
            name = str(req.get("name") or os.path.basename(path))[:200]
            if not (path.startswith(f"{MAIL_TMP_PREFIX}{uid}/") or re.match(rf"{re.escape(MAIL_TMP_PREFIX)}{uid}-[^/]+/[^/]+$", path)) \
                    or not os.path.isfile(path) or os.stat(os.path.dirname(path)).st_uid != uid:
                return {"ok": False, "error": "forbidden"}
            try:
                st = os.stat(path)
            except OSError:
                return {"ok": False, "error": "not_found"}
            if st.st_uid != uid or st.st_size > 200 * 1024 ** 2:
                return {"ok": False, "error": "forbidden"}
            if not clamd_ping():
                return {"ok": False, "error": "clamd_unavailable"}
            found = ActivityMonitor.clamd_check([path])
            signature = found[0].rsplit(":", 1)[-1].replace(" FOUND", "").strip() if found else ""
            source = str(req.get("source") or "thunderbird")[:20]
            if found:
                self.urlguard.record({"t": now_iso(), "source": source, "url": name, "host": "", "verdict": "danger",
                                      "reasons": ["infected_attachment"], "action": "attachment_infected", "signature": signature})
                self.publish_alert({"kind": "mail", "severity": "danger", "time": now_iso(), "title": name, "detail": signature,
                                    "source": source, "sender": str(req.get("sender") or "")[:120], "subject": str(req.get("subject") or "")[:200],
                                    "reasons": ["infected_attachment"], "comm": "", "exe": "", "pid": 0, "user": "", "count": 0,
                                    "top_dir": "", "sample": [], "cmdline": ""})
            else:
                with self.urlguard.lock:
                    self.urlguard.counters["attachments"] = self.urlguard.counters.get("attachments", 0) + 1
            return {"ok": True, "enabled": True, "infected": bool(found), "signature": signature, "engine": "clamd"}

        if cmd == "honeypot_block":
            ok, text = self.honeypot.block(str(req.get("ip") or ""), remove=bool(req.get("remove")))
            if ok:
                self.refresh_overall()
                threading.Thread(target=self.refresh_security, kwargs={"force": True}, daemon=True).start()
            return {"ok": ok, "error": "" if ok else ("invalid_ip" if text == "invalid_ip" else "command_failed"), "detail": text}

        if cmd == "honeypot_ignore":
            ip, remove = str(req.get("ip") or "").strip(), bool(req.get("remove"))
            ok = self.honeypot.ignore(ip, remove=remove)
            if ok:
                # Alerts already listed for this device: ignored too (blue in the list), or counted again
                alerts = list(self.state.get("alerts") or [])
                marked = [a for a in alerts if a.get("kind") == "honeypot" and a.get("ip") == ip]
                for a in marked:
                    a["ignored"] = not remove
                if marked:
                    self.state.update(alerts=alerts)
            self.refresh_overall()
            return {"ok": ok, "error": "" if ok else "invalid_ip"}

        if cmd == "honeypot_forget":
            self.honeypot.forget(str(req.get("ip") or ""))
            self.refresh_overall()
            return {"ok": True}

        if cmd == "feature_answer":
            # Advanced protections (honeypot…): always offered, never enabled without the user's consent
            feature = str(req.get("feature") or "")
            if feature not in FEATURES_OPT_IN:
                return {"ok": False, "error": "invalid_feature"}
            enabled = bool(req.get("enabled"))
            changed, _ = self.settings.update({feature: enabled})
            self.state.update(**{f"{feature}_answered": now_iso()})
            self.apply_settings(changed)
            self.write_log(f"feature {feature}: {'enabled' if enabled else 'declined'} (uid {uid})")
            self.broadcast({"event": "settings", "settings": self.settings.snapshot()})
            self.refresh_overall()
            return {"ok": True, "feature": feature, "enabled": enabled}

        if cmd == "persistence":
            if req.get("refresh"):
                pers = self.apply_acknowledged(collect_persistence())
                self.state.update(persistence=pers)
                return {"ok": True, "persistence": pers}
            return {"ok": True, "persistence": self.state.get("persistence")}

        if cmd == "integrity":
            if req.get("run"):
                started = not self.integrity_running
                if started:
                    threading.Thread(target=self.run_integrity, daemon=True).start()
                return {"ok": True, "running": True, "started": started, "integrity": self.integrity_payload()}
            return {"ok": True, "running": self.integrity_running, "integrity": self.integrity_payload()}

        if cmd == "backup_status":
            return {"ok": True, "timeshift": self.refresh_backup(force=bool(req.get("refresh")))}

        if cmd in ("timeshift_enable", "timeshift_disable"):
            # Enable: no password (protects the system). Disable: administrator (see admin_required).
            if os.geteuid() != 0:
                return {"ok": False, "error": "root_required"}
            if not shutil.which("timeshift"):
                return {"ok": False, "error": "timeshift_missing"}
            try:
                with open(TIMESHIFT_CONF, encoding="utf-8") as f:
                    existing = json.load(f)
            except (OSError, ValueError):
                existing = {}
            if cmd == "timeshift_enable":
                # Safeguard: never without measuring the space first (the first rsync copy is the whole system)
                if self.timeshift_enabling:
                    return {"ok": False, "error": "busy_timeshift"}
                device_uuid = re.sub(r"[^0-9A-Za-z-]", "", str(req.get("device_uuid") or ""))[:64]
                size = self.cached_system_size()
                if size is None:
                    self.timeshift_enabling = True
                    threading.Thread(target=self._timeshift_enable_worker, args=(existing, device_uuid), daemon=True).start()
                    return {"ok": True, "pending": True}
                return self._timeshift_enable_now(existing, size, device_uuid)
            for k in ("schedule_monthly", "schedule_weekly", "schedule_daily", "schedule_hourly", "schedule_boot"):
                existing[k] = "false"
            timeshift_write_config(existing)
            try:
                os.remove(TIMESHIFT_CRON)
            except OSError:
                pass
            self.state.update(timeshift_suspended=None)
            self.write_log("timeshift schedules disabled")
            self._timeshift_state_quick()
            self.refresh_overall()
            threading.Thread(target=lambda: self.refresh_backup(force=True), daemon=True).start()
            return {"ok": True}

        if cmd in ("harden_apply", "harden_revert"):
            # Lynis recommendations: apply (no password, protects the system; family mode: administrator)
            # or revert (administrator). Background task; result broadcast by the hardening_done event.
            revert = cmd == "harden_revert"
            tests = [str(t) for t in (req.get("tests") or []) if (harden.CATALOG.get(str(t)) or {}).get("kind") == "apply"]
            if req.get("all") and not revert:
                tests = self.pending_safe_hardening(self.state.get("integrity"))
            if not tests:
                return {"ok": False, "error": "nothing_to_harden"}
            if os.geteuid() != 0 and not TEST_MODE:
                return {"ok": False, "error": "root_required"}
            if not self.start_hardening(tests, revert=revert):
                return {"ok": False, "error": "busy_hardening"}
            return {"ok": True, "started": True, "tests": tests}

        if cmd == "auto_updates_enable":
            # "Enable" (no password: protects the system): Linux Mint Update Manager automation,
            # otherwise unattended-upgrades. User settings (Spices, Flatpak) are done by the interface.
            if TEST_MODE:
                return {"ok": True, "method": "test"}
            if os.geteuid() != 0:
                return {"ok": False, "error": "root_required"}
            if distro.is_rpm():
                ok, method, detail = distro.auto_updates_enable()
            elif os.path.exists(MINT_AUTOMATION):
                r = run_quiet([MINT_AUTOMATION, "upgrade", "enable"], timeout=120)
                ok = r.returncode == 0 and (unit_enabled("mintupdate-automation-upgrade.timer")
                                            or os.path.exists(MINT_AUTO_UPGRADE_FLAG))
                method, detail = "mintupdate", ((r.stderr or "") + (r.stdout or "")).strip()[-200:]
            elif os.path.exists("/usr/bin/unattended-upgrade"):
                try:
                    with open(APT_AUTO_CONF, "w") as f:
                        f.write('APT::Periodic::Update-Package-Lists "1";\nAPT::Periodic::Unattended-Upgrade "1";\n')
                    ok, method, detail = True, "unattended", ""
                except OSError as e:
                    ok, method, detail = False, "unattended", str(e)
            else:
                return {"ok": False, "error": "auto_updates_unavailable"}
            self.write_log(f"automatic updates enable ({method}) → {'ok' if ok else 'failed'} {detail}")
            if ok:
                threading.Thread(target=self.refresh_checklist, daemon=True).start()
            return {"ok": ok, "error": "" if ok else "command_failed", "method": method, "detail": detail}

        if cmd == "install_package":
            name = str(req.get("name") or "")
            if name not in ("rclone", "timeshift", "gocryptfs", "firejail", "fscrypt", "libpam-fscrypt"):
                return {"ok": False, "error": "forbidden", "forbidden": True}
            if TEST_MODE:
                return {"ok": True, "detail": "test_mode"}
            r = run_quiet(["systemd-run", "--unit", f"dukiwi-shield-pkg-{int(time.time())}", "--collect", "--quiet",
                           "-p", "Environment=DEBIAN_FRONTEND=noninteractive",
                           "/bin/sh", "-c", distro.install_shell([name])], timeout=30)
            return {"ok": r.returncode == 0, "error": "" if r.returncode == 0 else "command_failed",
                    "detail": ((r.stderr or "") + (r.stdout or "")).strip()[-200:]}

        if cmd == "install_tools":
            if TEST_MODE:
                return {"ok": True, "detail": "test_mode"}
            r = run_quiet(["systemd-run", "--unit", f"dukiwi-shield-tools-{int(time.time())}", "--collect", "--quiet",
                           "-p", "Environment=DEBIAN_FRONTEND=noninteractive",
                           "/bin/sh", "-c", distro.install_shell(distro.tools_packages())], timeout=30)
            return {"ok": r.returncode == 0, "error": "" if r.returncode == 0 else "command_failed",
                    "detail": ((r.stderr or "") + (r.stdout or "")).strip()[-200:]}

        if cmd == "system_upgrade":
            # "Update": apt-get update && apt-get upgrade in a transient unit, then new system status
            sysst = self.state.get("system_status") or {}
            if not sysst.get("upgradable") and not req.get("force"):
                return {"ok": False, "error": "nothing_to_upgrade"}
            with self.system_status_lock:
                if self.system_upgrade_running:
                    return {"ok": False, "error": "busy_upgrade"}
                self.system_upgrade_running = True
            unit = None if TEST_MODE else f"dukiwi-shield-sysupgrade-{int(time.time())}"
            threading.Thread(target=self._system_upgrade_worker, args=(unit,), daemon=True).start()
            self.write_log("system upgrade requested" + (" (test mode)" if TEST_MODE else ""))
            return {"ok": True, "detail": "test_mode" if TEST_MODE else ""}

        if cmd == "firmware_update":
            # "Fix" on the Firmware check: fwupdmgr update in a transient unit (LVFS download, installed at the
            # next reboot for UEFI capsules), then a new scan and the firmware_done event
            if not shutil.which("fwupdmgr"):
                return {"ok": False, "error": "fwupd_missing"}
            if TEST_MODE:
                return {"ok": True, "detail": "test_mode"}
            def fw_worker():
                r = run_quiet(["systemd-run", "--unit", f"dukiwi-shield-fwupd-{int(time.time())}", "--collect", "--quiet", "--wait", "--pipe",
                               "fwupdmgr", "update", "-y", "--no-reboot-check"], timeout=1800)
                ok = r.returncode in (0, 2)
                self.write_log(f"firmware update: rc={r.returncode}")
                try:
                    fw = firmware_updates()
                    self.state.update(firmware={"checked_at": now_iso(), "available": fw is not None, "updates": fw or []})
                except Exception as e:  # noqa: BLE001
                    log(f"Firmware : {e}")
                self.broadcast({"event": "firmware_done", "ok": ok, "output": ((r.stdout or "") + (r.stderr or "")).strip()[-400:]})
                self.refresh_security(force=True)
            threading.Thread(target=fw_worker, daemon=True).start()
            self.write_log(f"firmware update requested by uid {uid}")
            return {"ok": True}

        if cmd == "install_phased":
            sysst = self.state.get("system_status") or {}
            names = sorted({p["name"] for p in sysst.get("packages", []) if p.get("category") == "phased"})
            if not names or distro.is_rpm():
                return {"ok": False, "error": "nothing_phased"}
            if TEST_MODE:
                return {"ok": True, "detail": "test_mode", "packages": names}
            r = run_quiet(["systemd-run", "--unit", f"dukiwi-shield-phased-{int(time.time())}", "--collect", "--quiet",
                           "-p", "Environment=DEBIAN_FRONTEND=noninteractive",
                           "/bin/sh", "-c", "apt-get install -y -o APT::Get::Always-Include-Phased-Updates=true " + " ".join(names)], timeout=30)
            self.write_log(f"install phased: {names} → {r.returncode}")
            return {"ok": r.returncode == 0, "error": "" if r.returncode == 0 else "command_failed",
                    "detail": ((r.stderr or "") + (r.stdout or "")).strip()[-200:], "packages": names}

        if cmd == "process_action":
            try:
                pid = int(req.get("pid"))
            except (TypeError, ValueError):
                return {"ok": False, "error": "invalid_pid"}
            info = self.suspended.get(pid)
            if not info:
                return {"ok": False, "error": "not_suspended"}
            action = req.get("action")
            try:
                owner = os.stat(f"/proc/{pid}").st_uid
            except OSError:
                owner = -1
            # Resuming a process the shield stopped, or acting on someone else's, needs the administrator
            if uid != 0 and (action == "continue" or owner != uid) and not self.is_unlocked(uid, req):
                return {"ok": False, "error": "admin_required"}
            try:
                if action == "continue":
                    os.kill(pid, signal.SIGCONT)
                elif action in ("kill", "quarantine"):
                    src = -1
                    if action == "quarantine":
                        # Evidence taken from the running image (/proc/<pid>/exe), opened before the kill: a path
                        # string could have been pointed at /etc in the meantime
                        try:
                            src = os.open(f"/proc/{pid}/exe", os.O_RDONLY)
                        except OSError:
                            src = -1
                    os.kill(pid, signal.SIGKILL)
                    if src >= 0:
                        try:
                            exe = (info.get("exe") or "").replace(" (deleted)", "")
                            st = os.fstat(src)
                            if _stat.S_ISREG(st.st_mode) and not exe.startswith(("/usr/", "/bin/", "/sbin/", "/lib")):
                                self._quarantine_fd(src, exe, st)
                        finally:
                            os.close(src)
                else:
                    return {"ok": False, "error": "invalid_action"}
            except OSError as e:
                return {"ok": False, "error": "command_failed", "detail": str(e)}
            self.suspended.pop(pid, None)
            self.write_log(f"process {pid} ({info.get('comm')}): {action}")
            self.broadcast({"event": "suspended", "suspended": list(self.suspended.values())})
            self.refresh_overall()
            return {"ok": True}

        if cmd == "scan" and req.get("path") == QUICK_SCAN:
            with self.queue_lock:
                if self.current or self.queue:
                    busy = (self.current or self.queue[0]).public()
                    return {"ok": False, "error": "busy", "busy": busy}
            job = self.enqueue(Job("scan", path=QUICK_SCAN, paths=quick_scan_paths(), resume=bool(req.get("resume")),
                                   requested_by=uid, use_cache=not bool(req.get("nocache"))))
            return {"ok": True, "job_id": job.id, "queued": False}

        if cmd == "scan":
            path = req.get("path", "/")
            if not os.path.isabs(path) or not os.path.isdir(path):
                return {"ok": False, "error": "not_found", "path": path}
            if not self._scan_path_allowed(path, uid):
                return {"ok": False, "error": "forbidden", "forbidden": True}
            with self.queue_lock:
                if self.current or self.queue:
                    busy = (self.current or self.queue[0]).public()
                    return {"ok": False, "error": "busy", "busy": busy}
            usb = None
            if req.get("usb_devnode"):
                # Only a drive the daemon itself announced: a made-up devnode would have made root write the drive
                # manifest into any folder the caller chose
                usb = self.usb.take_pending(req["usb_devnode"])
                if usb:
                    usb = dict(usb, private_mount=False, mountpoint=os.path.normpath(path))
            job = self.enqueue(Job("scan", path=os.path.normpath(path),
                                   resume=bool(req.get("resume")), requested_by=uid, usb=usb,
                                   integrity=bool(req.get("integrity")), use_cache=not bool(req.get("nocache"))))
            return {"ok": True, "job_id": job.id, "queued": False}

        if cmd == "update":
            with self.queue_lock:
                if any(j.kind == "update" for j in self.queue) or \
                        (self.current and self.current.kind == "update"):
                    return {"ok": True, "job_id": self.current.id if self.current else None,
                            "queued": True, "already": True}
                queued = self.current is not None or bool(self.queue)
            job = self.enqueue(Job("update", requested_by=uid))
            return {"ok": True, "job_id": job.id, "queued": queued}

        if cmd == "cancel":
            with self.queue_lock:
                job = self.current
                self.queue.clear()
            if job:
                job.cancel(by_user=True)
                return {"ok": True}
            return {"ok": False, "error": "idle"}

        if cmd == "usb_decision":
            info = self.usb.take_pending(req.get("devnode", ""))
            return {"ok": True, "usb": info}

        if cmd == "usb_mount_diagnose":
            # Read-only, limited to a USB drive plugged in now: no administrator needed
            problem = self.usb.diagnose(str(req.get("devnode") or "")[:64])
            if problem is None:
                return {"ok": False, "error": "not_found"}
            return {"ok": True, "problem": problem}

        if cmd == "usb_pending":
            return {"ok": True, "pending": self.usb.pending_list()}

        if cmd == "usb_skip":
            # "Continue without scanning" / "Trust this key": the user accepts the risk, the key is handed over
            # immediately (running scan cancelled, or pending one removed). No password except in family mode.
            devnode = str(req.get("devnode") or "")[:64]
            trust = bool(req.get("trust"))
            info = self.usb.take_pending(devnode)
            with self.queue_lock:
                cur = self.current
                queued = [j for j in self.queue if j.usb and j.usb.get("devnode") == devnode]
                for j in queued:
                    self.queue.remove(j)
            running = next((j for j in (cur, self.usb_priority_job)
                            if j and j.usb and j.usb.get("devnode") == devnode and not j.cancel_event.is_set()), None)
            if running:
                info = info or running.usb
                running.usb["skipped"] = True
                running.cancel(by_user=True)            # usb_done {skipped} follows, the private mount is released
            for j in queued:
                info = info or j.usb
                if j.usb.get("private_mount"):
                    self.usb.unmount(devnode)
                self.broadcast({"event": "usb_done", "usb": dict(j.usb, skipped=True), "status": "skipped",
                                "msg_key": "msg.scan.cancelled", "msg_params": {}, "infected": 0, "files": 0, "cached": 0,
                                "threats": [], "removed": False, "skipped": True})
            if not info:
                return {"ok": False, "error": "not_found"}
            trusted_now = False
            if trust:
                ident = usb_identity(info)
                if ident:
                    trusted = dict(self.state.get("trusted_usb") or {})
                    trusted[ident] = {"label": info.get("label") or "", "model": ((info.get("vendor") or "") + " " + (info.get("model") or "")).strip(),
                                      "size": info.get("size") or 0, "at": now_iso(), "uid": uid}
                    self.state.update(trusted_usb=trusted)
                    self.write_log(f"✔ trusted USB (no scan on insert): {info.get('label') or info.get('model')} [{ident}]")
                    trusted_now = True
            self.write_log(f"USB scan skipped by user: {devnode} ({info.get('label') or info.get('model')})")
            return {"ok": True, "trusted": trusted_now, "mount_now": running is None, "usb": info}

        if cmd == "mail_status":
            return {"ok": True, "mail": self.mail_public()}

        if cmd == "mail_configure":
            # SMTP settings (administrator): /etc/msmtprc rewritten (password kept if not provided), state saved
            cfg, err = mail_sanitize(req.get("mail"), self.state.get("mail"))
            if cfg is None:
                return {"ok": False, "error": err}
            password = str(req.get("password") or "")
            if not password:
                password = mail_read_password()
            if mail_transport() == "msmtp" and cfg.get("host"):
                try:
                    mail_write_config(cfg, password)
                except OSError as e:
                    return {"ok": False, "error": "command_failed", "detail": str(e)[:200]}
            cfg["password_set"] = bool(password) or not cfg.get("user")
            for k in ("last_sent", "last_error", "last_digest", "sent_day", "sent_today"):
                cfg[k] = (self.state.get("mail") or {}).get(k, MAIL_DEFAULT[k])
            self.state.update(mail=cfg)
            self.write_log(f"mail configured: {'enabled' if cfg['enabled'] else 'disabled'}, {cfg['frequency']}, to {', '.join(cfg['to'])}, "
                           f"{cfg['host'] or mail_transport()}:{cfg['port']} {cfg['security']}")
            self.broadcast({"event": "mail", "mail": self.mail_public()})
            return {"ok": True, "mail": self.mail_public()}

        if cmd == "mail_test":
            cfg = self.mail_cfg()
            lang = cfg.get("lang") or "fr"
            ok, err = self.mail_deliver(t(lang, "mail.subject.test"), t(lang, "mail.test.body", host=socket.gethostname()) + "\n\n" + self.mail_summary(lang), "test")
            return {"ok": ok, "error": "" if ok else "mail_failed", "detail": err}

        if cmd == "mail_flush":
            ok, err = self.mail_flush(force=True)
            return {"ok": ok, "error": "" if ok else "mail_failed", "detail": err}

        if cmd == "ignore_check":
            # "Ignore" an availability check (file backup, Timeshift): never a password
            setting = str(req.get("setting") or "")
            if setting not in ("backup_check", "timeshift_check"):
                return {"ok": False, "error": "invalid_key"}
            changed, _errors = self.settings.update({setting: not bool(req.get("ignore", True))})
            self.write_log(f"settings: {setting}={self.settings.get(setting)} (ignore_check)")
            self.broadcast({"event": "settings", "settings": self.settings.snapshot()})
            self.refresh_overall()
            self.refresh_checklist_async()               # the check still counts in the score, marked "reminder ignored"
            return {"ok": True, "changed": changed, "settings": {k: self.settings.get(k) for k in ("backup_check", "timeshift_check")}}

        if cmd == "untrust_usb":
            ident = str(req.get("id") or "")[:200]
            trusted = dict(self.state.get("trusted_usb") or {})
            entry = trusted.pop(ident, None)
            if entry is None:
                return {"ok": False, "error": "not_found"}
            self.state.update(trusted_usb=trusted)
            self.write_log(f"✘ untrusted USB: {entry.get('label') or entry.get('model')} [{ident}]")
            return {"ok": True, "usb": [dict(v, id=k) for k, v in trusted.items()]}

        if cmd == "system_status":
            if req.get("refresh"):
                started = self.refresh_system_status(force=bool(req.get("force")))
                return {"ok": True, "refreshing": started, "status": self.state.get("system_status")}
            return {"ok": True, "status": self.state.get("system_status")}

        if cmd == "get_settings":
            return {"ok": True, "settings": self.settings.snapshot(), "stats": {"geoip": self.connections.geoip_stats()},
                    "locked": sorted(self.locked_settings),
                    "policy": {"name": self.policy.get("name", ""), "signed": bool(self.policy.get("_signed"))} if self.policy else None,
                    "allowlist": {"version": self.state.get("allowlist_version"), "updated": self.state.get("allowlist_updated"),
                                  "patterns": len(self.central_patterns)},
                    "telemetry_sent": self.state.get("telemetry_sent")}

        if cmd == "set_settings":
            incoming = dict(req.get("settings") or {})
            locked = [k for k in incoming if k in self.locked_settings]
            for k in locked:
                incoming.pop(k, None)
            changed, errors = self.settings.update(incoming)
            errors = list(errors) + [f"locked:{k}" for k in locked]
            applied = self.apply_settings(changed)
            if changed:
                self.write_log(f"settings: {', '.join(f'{k}={v}' for k, v in changed.items())}")
                self.broadcast({"event": "settings", "settings": self.settings.snapshot()})
                self.refresh_overall()
            return {"ok": True, "settings": self.settings.snapshot(), "changed": changed,
                    "applied": applied, "errors": errors}

        if cmd == "security_status":
            return {"ok": True, "security": self.refresh_security(force=bool(req.get("refresh")), broadcast=False)}

        if cmd == "firewall_profile":
            profile = str(req.get("profile") or "")
            if profile not in FIREWALL_PROFILES:
                return {"ok": False, "error": "invalid_profile"}
            if os.geteuid() != 0:
                return {"ok": False, "error": "root_required"}
            if uid not in (0,) and uid < 1000:
                return {"ok": False, "error": "forbidden"}
            ok, text = self.apply_firewall_profile(profile)
            if ok:
                self.settings.update({"firewall_profile": profile})
                self.remember_network_profile(profile)
            self.refresh_security(force=True)
            self.refresh_overall()
            return {"ok": ok, "error": "" if ok else "command_failed", "detail": text, "profile": profile,
                    "rules": len(profile_rules(profile))}

        if cmd in ("firewall_set", "firewall_defaults", "firewall_rule_add", "firewall_rule_delete", "ssh_set"):
            if os.geteuid() != 0:
                return {"ok": False, "error": "root_required"}
            if uid not in (0,) and uid < 1000:
                return {"ok": False, "error": "forbidden"}
            ok, text = self.security_command(cmd, req)
            sec = self.refresh_security(force=True)
            self.refresh_overall()
            self.refresh_checklist_async()                      # score, "Firewall" and badge follow immediately
            ufw_now = (sec or {}).get("ufw") or {}
            enabling = cmd == "firewall_set" and bool(req.get("enabled"))
            if enabling and ok and not ufw_now.get("active"):
                ok, text = False, text or "firewall not active after enable"
            err = "" if ok else ("firewall_not_active" if enabling else "command_failed")
            return {"ok": ok, "error": err, "detail": text, "conflicts": ufw_now.get("conflicts") or []}

        if cmd == "alerts":
            return {"ok": True, "alerts": self.visible_alerts(uid)}

        if cmd == "forget_habit":
            # Forget a learned habit: bursts from this program / this folder are reported again
            key = str(req.get("key") or "")[:400]
            habits = dict(self.state.get("habits") or {})
            if key not in habits:
                return {"ok": False, "error": "not_found"}
            habits.pop(key)
            self.state.update(habits=habits)
            self.write_log(f"habit forgotten: {key}")
            return {"ok": True}

        if cmd == "trusted_programs":
            return {"ok": True, "programs": self.state.get("trusted_programs") or [],
                    "habits": [dict(v, key=k) for k, v in sorted((self.state.get("habits") or {}).items())
                               if int(v.get("n") or 0) >= HABIT_LEARNED_AT],
                    "acknowledged": self.state.get("acknowledged_persistence") or [],
                    "usb": [dict(v, id=k) for k, v in (self.state.get("trusted_usb") or {}).items()],
                    "hid": [dict(v, id=k) for k, v in (self.state.get("trusted_hid") or {}).items()],
                    "sudoers": [dict(v, path=k) for k, v in (self.state.get("acknowledged_sudoers") or {}).items()],
                    "privacy": [dict(v, exe=k) for k, v in (self.state.get("privacy_allowed") or {}).items()],
                    "certs": [dict(v, fp=k) for k, v in (self.state.get("acknowledged_certs") or {}).items()],
                    "redirects": [dict(v, key=k) for k, v in (self.state.get("acknowledged_redirects") or {}).items()],
                    "suid": [dict(v, path=k) for k, v in (self.state.get("acknowledged_suid") or {}).items()],
                    "flatpak": [dict(v, app=k) for k, v in (self.state.get("acknowledged_flatpak") or {}).items()]}

        if cmd == "protected_status":
            return {"ok": True, "protected": self.folders.snapshot()}

        if cmd == "protected_allow":
            exe = str(req.get("exe") or "")[:400]
            if not exe.startswith("/"):
                return {"ok": False, "error": "invalid_exe"}
            allowed = [e for e in (self.state.get("protected_allowed") or []) if e != exe]
            if not req.get("remove"):
                allowed.append(exe)
            self.state.update(protected_allowed=sorted(set(allowed)))
            self.folders.reload.set()
            self.write_log(f"protected folders: {'removed' if req.get('remove') else 'allowed'} {exe} by uid {uid}")
            return {"ok": True, "protected": self.folders.snapshot()}

        if cmd in ("protected_folder_add", "protected_folder_remove"):
            path = os.path.realpath(str(req.get("path") or ""))
            extra = [x for x in (self.state.get("protected_extra") or []) if x != path]
            if cmd == "protected_folder_add":
                if not os.path.isdir(path) or path in ("/", "/home", "/usr", "/etc", "/var", "/tmp") or path.startswith(("/proc", "/sys", "/dev", "/run")):
                    return {"ok": False, "error": "invalid_path"}
                path = os.path.realpath(path)
                try:
                    home = (pwd.getpwuid(uid).pw_dir if uid else "/").rstrip("/") + "/"
                    # Only one's own folders, inside one's home (resolved: a link to / is not a home folder)
                    if uid != 0 and (os.stat(path).st_uid != uid or not path.startswith(os.path.realpath(home).rstrip("/") + "/")):
                        return {"ok": False, "error": "forbidden"}
                except (OSError, KeyError):
                    return {"ok": False, "error": "invalid_path"}
                extra.append(path)
            self.state.update(protected_extra=sorted(set(extra)))
            self.folders.reload.set()
            self.write_log(f"protected folders: {'added' if cmd.endswith('add') else 'removed'} {path} by uid {uid}")
            return {"ok": True, "protected": self.folders.snapshot()}

        if cmd == "dev_packages":
            if req.get("refresh"):
                return {"ok": True, "dev_packages": self.refresh_dev_packages()}
            return {"ok": True, "dev_packages": self.state.get("dev_packages") or {}}

        if cmd == "ssh_keys":
            keys = self.guard.ssh_keys()
            if not self.admin_member(uid):
                # Another account's keys (and their comments) are none of this account's business
                me = self._user_name(uid)
                keys = [k for k in keys if isinstance(k, dict) and k.get("user") == me] if isinstance(keys, list) else keys
            return {"ok": True, "ssh_keys": keys}

        if cmd == "ssh_key_remove":
            path, fp = str(req.get("path") or ""), str(req.get("fp") or "")
            if path not in {p_ for _u, p_ in self.guard.ssh_key_files()}:
                return {"ok": False, "error": "not_found"}
            if not self.guard.remove_ssh_key(path, fp):
                return {"ok": False, "error": "not_found"}
            self.write_log(f"ssh key removed by uid {uid}: {fp} from {path}")
            return {"ok": True, "ssh_keys": self.guard.ssh_keys()}

        if cmd == "suid":
            if req.get("refresh") and os.geteuid() == 0:
                threading.Thread(target=self.refresh_suid, daemon=True, name="suid-scan").start()
                return {"ok": True, "suid": self.suid_status(), "running": True}
            return {"ok": True, "suid": self.suid_status()}

        if cmd == "weekly_summary":
            if req.get("now"):
                return {"ok": True, "weekly_summary": self.weekly_summary()}
            return {"ok": True, "weekly_summary": (self.state.get("weekly_summaries") or [None])[0] or self.weekly_summary(),
                    "weekly_summaries": self.state.get("weekly_summaries") or []}

        if cmd == "password_policy":
            return {"ok": True, "password_policy": hygiene.password_policy()}

        if cmd == "password_policy_apply":
            if os.geteuid() != 0 or TEST_MODE:
                return {"ok": False, "error": "root_required"}
            ok, err = hygiene.password_policy_apply()
            self.write_log(f"password policy (minlen {hygiene.PWQ_MINLEN}) by uid {uid}: " + ("applied" if ok else f"failed ({err})"))
            return {"ok": ok, "error": err, "password_policy": hygiene.password_policy(), "checklist": self.refresh_checklist()}

        if cmd == "browser_security":
            if req.get("refresh"):
                self._check_cache.pop("browser_security", None)
            return {"ok": True, "browser_security": self.cached("browser_security", 600, lambda: hygiene.browser_security(human_users()))}

        if cmd == "browser_harden":
            # Firefox: user.js in the profiles of the requesting user; Chrome, Chromium, Brave, Edge: recommended
            # policies
            try:
                pw = pwd.getpwuid(uid)
            except KeyError:
                return {"ok": False, "error": "forbidden"}
            profiles = hygiene.browser_security([pw])
            fx = [p_ for p_ in profiles if p_["browser"] == "firefox"]
            for p_ in fx:
                try:
                    if req.get("remove"):
                        hygiene.firefox_unharden(p_["path"], pw)
                    else:
                        hygiene.firefox_harden(p_["path"], pw)
                except (OSError, subprocess.SubprocessError, ValueError) as e:
                    self.write_log(f"browser security: {p_['path']}: {e}")
            dirs = [] if req.get("remove") else hygiene.chrome_harden([p_["browser"] for p_ in profiles if p_["browser"] != "firefox"])
            if req.get("remove"):
                for d in hygiene.CHROME_POLICY_DIRS:
                    try:
                        os.unlink(os.path.join(d, hygiene.CHROME_POLICY_FILE))
                    except OSError:
                        pass
            self._check_cache.pop("browser_security", None)
            self.write_log(f"browser security settings {'removed' if req.get('remove') else 'applied'} by uid {uid}: {len(fx)} Firefox profile(s), {len(dirs)} policy dir(s)")
            return {"ok": True, "firefox": len(fx), "policies": len(dirs), "checklist": self.refresh_checklist()}

        if cmd == "exposure_test":
            # Test from the Internet: only on explicit request (consent in the application, for each test)
            if req.get("consent") is not True:
                return {"ok": False, "error": "consent_required"}
            ports = [p_["port"] for p_ in ((self.state.get("checklist") or {}).get("ports") or []) if p_.get("exposed") and p_.get("proto") == "tcp"]
            res = hygiene.exposure_test(ports)
            res["at"] = now_iso()
            upnp = hygiene.upnp_mappings()
            self.state.update(exposure=res, upnp=upnp)
            self.write_log(f"internet exposure test by uid {uid}: " + (f"{len(res.get('open') or [])} open port(s) {res.get('open')}" if res.get("ok") else f"failed ({res.get('error')})")
                           + f", UPnP router {upnp.get('router') or 'none'} ({len(upnp.get('mappings') or [])} mapping(s))")
            return {"ok": bool(res.get("ok")), "error": res.get("error", ""), "exposure": res, "upnp": upnp, "checklist": self.refresh_checklist()}

        if cmd == "exposure":
            return {"ok": True, "exposure": {"test": self.state.get("exposure"), "upnp": self.state.get("upnp")}}

        if cmd == "incident_step":
            # "After an attack" page: checked steps (shared by all users of the computer)
            inc = dict(self.state.get("incident") or {})
            if req.get("reset"):
                inc = {}
            else:
                key = re.sub(r"[^a-z_]", "", str(req.get("key") or ""))[:40]
                steps = dict(inc.get("steps") or {})
                if req.get("done", True):
                    steps[key] = now_iso()
                else:
                    steps.pop(key, None)
                inc = {"started_at": inc.get("started_at") or now_iso(), "steps": steps}
            self.state.update(incident=inc)
            return {"ok": True, "incident": inc}

        if cmd == "incident":
            return {"ok": True, "incident": self.state.get("incident") or {}}

        if cmd == "backup_state_report":
            # State of the user's file backups (their settings, their media), reported by their application:
            # it counts in the security score, whether the reminder is ignored or not.
            reported = str(req.get("state") or "")
            if reported not in ("ok", "none", "missing", "old"):
                return {"ok": False, "error": "invalid_key"}
            states = user_backup_states(self.state.get("backup_states"))
            changed = (states.get(str(uid)) or {}).get("state") != reported
            states[str(uid)] = {"state": reported, "last": str(req.get("last") or "")[:19], "at": now_iso()}
            self.state.update(backup_states=states)
            if changed:
                self.refresh_checklist_async()
            return {"ok": True, "changed": changed}

        if cmd == "backup_test_report":
            # Restore test of the file backups, run by the user's application (with their rights)
            r = req.get("result") or {}
            tests = dict(self.state.get("backup_tests") or {})
            tests[str(uid)] = {"date": str(r.get("date") or now_iso())[:19], "ok": bool(r.get("ok")), "dest_label": str(r.get("dest_label") or "")[:80],
                               "checked": int(r.get("checked") or 0), "restored": int(r.get("restored") or 0),
                               "failed": int(len(r.get("failed") or [])), "error": str(r.get("error") or "")[:60]}
            self.state.update(backup_tests=tests)
            self.write_log(f"restore test files uid {uid} ({tests[str(uid)]['dest_label']}): " + ("ok" if r.get("ok") else f"⚠ {r.get('error') or 'failed'}"))
            self.refresh_checklist_async()
            return {"ok": True}

        if cmd == "timeshift_restore_test":
            if os.geteuid() != 0:
                return {"ok": False, "error": "root_required"}
            res = timeshift_restore_test()
            self.state.update(timeshift_test=res)
            self.refresh_checklist_async()
            return {"ok": True, "timeshift_test": res}

        if cmd == "dns_filter":
            return {"ok": True, "dns_filter": self.dns_filter_status()}

        if cmd == "isolate":
            # Isolate: never a password (emergency). Restore the network: administrator in family mode.
            return self.isolate(uid) if req.get("on", True) is not False else self.unisolate(uid)

        if cmd == "home_encryption":
            def check():
                uids = {s["uid"] for s in graphical_sessions()}
                return protect.home_encryption_check(human_users(), uids)
            if req.get("refresh"):
                self._check_cache.pop("home_encryption", None)
            return {"ok": True, "home_encryption": self.cached("home_encryption", 600, check)}

        if cmd == "privacy_allow":
            # "Always allow" a program on the camera / microphone (or remove it): personal choice, no password
            exe = str(req.get("exe") or "")[:400]
            if not exe:
                return {"ok": False, "error": "invalid_exe"}
            allowed = dict(self.state.get("privacy_allowed") or {})
            if req.get("remove"):
                allowed.pop(exe, None)
            else:
                allowed[exe] = {"comm": str(req.get("comm") or os.path.basename(exe))[:80], "device": str(req.get("device") or "")[:20], "at": now_iso()}
            self.state.update(privacy_allowed=allowed)
            self.write_log(f"privacy {'allowance removed' if req.get('remove') else 'allowed'} by uid {uid}: {exe}")
            return {"ok": True}

        if cmd == "guard_ack":
            # "Ignore" a root certificate (fingerprint), an intended network redirection (corporate proxy, hosts…)
            # or a SUID file installed by hand (path + fingerprint)
            group = req.get("group")
            if group not in ("certs", "redirects", "suid", "flatpak"):
                return {"ok": False, "error": "invalid_group"}
            state_key = {"certs": "acknowledged_certs", "redirects": "acknowledged_redirects", "suid": "acknowledged_suid",
                         "flatpak": "acknowledged_flatpak"}[group]
            acks = dict(self.state.get(state_key) or {})
            if req.get("remove"):
                keys = [str(k) for k in (req.get("keys") or [])][:50]
                for k in keys:
                    acks.pop(k, None)
            else:
                current = {"certs": self.guard.root_cas, "redirects": self.guard.redirects,
                           "suid": lambda: self.suid_status().get("unowned") or [],
                           "flatpak": lambda: self.flatpak_status()}[group]()
                wanted = set(str(k) for k in (req.get("keys") or []))
                field = {"certs": "fp", "redirects": "key", "suid": "path", "flatpak": "app"}[group]
                items = [c for c in current if not c["acknowledged"] and (not wanted or c[field] in wanted)]
                if not items:
                    return {"ok": False, "error": "nothing_to_ignore"}
                for c in items:
                    acks[c[field]] = {"name": c.get("name") or c.get("value") or c.get("path") or c.get("app") or "", "at": now_iso()}
                    if group == "flatpak":
                        acks[c[field]]["risks"] = c.get("risks")              # reappears if the application gets other permissions
                    if group == "suid":
                        acks[c[field]]["sha256"] = c.get("sha256")          # reappears if the file changes
                keys = [c[field] for c in items]
            self.state.update(**{state_key: acks})
            self.guard.invalidate()
            self._check_cache.pop("flatpak_audit", None)
            self.write_log(f"{group} {'re-enabled' if req.get('remove') else 'acknowledged'} by uid {uid}: {', '.join(k[:40] for k in keys)}")
            checklist = self.refresh_checklist()
            return {"ok": True, "n": len(keys), "checklist": checklist}

        if cmd == "hid_allow":
            # "Allow this keyboard" (BadUSB): re-enabled and remembered; the alert is marked resolved
            ident = str(req.get("id") or "")[:200]
            info = self.hid_guard.allow(ident, remember=req.get("remember", True) is not False)
            if info is None and ident not in (self.state.get("trusted_hid") or {}):
                return {"ok": False, "error": "not_found"}
            alerts = list(self.state.get("alerts") or [])
            for a in alerts:
                if a.get("kind") == "usb_keyboard" and a.get("id") == ident:
                    a["resolved"] = True
                    a["blocked"] = False
            self.state.update(alerts=alerts)
            self.write_log(f"✔ USB keyboard allowed by uid {uid}: {ident}")
            self.refresh_overall()
            return {"ok": True, "hid": [dict(v, id=k) for k, v in (self.state.get("trusted_hid") or {}).items()]}

        if cmd == "hid_forget":
            ident = str(req.get("id") or "")[:200]
            trusted = dict(self.state.get("trusted_hid") or {})
            if trusted.pop(ident, None) is None:
                return {"ok": False, "error": "not_found"}
            self.state.update(trusted_hid=trusted)
            self.write_log(f"✘ USB keyboard forgotten: {ident}")
            return {"ok": True, "hid": [dict(v, id=k) for k, v in trusted.items()]}

        if cmd == "network_gateway_accept":
            # "This is my new router": the gateway's current hardware address becomes the network's reference
            key = str(req.get("key") or "")[:200]
            with self.network_lock:
                net = dict(self.current_network or {})
            known = dict(self.state.get("network_profiles") or {})
            if key not in known:
                return {"ok": False, "error": "not_found"}
            mac = net.get("gw_mac") if net.get("key") == key else ""
            if not mac:
                mac = str(req.get("mac") or "")[:40]
            if mac:
                known[key]["gw_mac"] = mac
                self.state.update(network_profiles=known)
            alerts = list(self.state.get("alerts") or [])
            for a in alerts:
                if a.get("kind") == "network" and a.get("subtype") == "gateway_changed" and a.get("key") == key:
                    a["resolved"] = True
                    a["severity"] = "info"
            self.state.update(alerts=alerts)
            self.write_log(f"network {known[key].get('name')}: new gateway accepted ({mac}) by uid {uid}")
            self.refresh_overall()
            return {"ok": True}

        if cmd == "trust_program":
            # "It's me": the program no longer triggers alerts (burst, connection), even if dpkg does not know it
            exe = normalize_exe(req.get("exe"))
            if not exe or not os.path.isabs(exe):
                return {"ok": False, "error": "invalid_path"}
            if is_interpreter(exe):
                # Trusting python3 or bash would trust every script: trust the script itself instead
                return {"ok": False, "error": "interpreter"}
            try:
                who = pwd.getpwuid(uid).pw_name
            except KeyError:
                who = str(uid)
            entry = {"exe": exe, "comm": str(req.get("comm") or os.path.basename(exe))[:64], "added": now_iso(), "by": who}
            if APPIMAGE_MOUNT_RE.match(exe):
                # AppImage: approved by its content, valid for future launches (different mount folder)
                entry["sha256"] = TrustedPrograms.digest(exe)
                if not entry["sha256"]:
                    return {"ok": False, "error": "not_found"}
                entry["kind"] = "appimage"
            programs = [p for p in (self.state.get("trusted_programs") or [])
                        if p.get("exe") != exe and not (entry.get("sha256") and p.get("sha256") == entry["sha256"])]
            programs.insert(0, entry)
            programs = programs[:200]
            self.state.update(trusted_programs=programs)
            self._trusted_set = TrustedPrograms(programs)
            alerts = [a for a in (self.state.get("alerts") or [])
                      if not (a.get("kind") in ("burst", "connection") and normalize_exe(a.get("exe")) == exe)]
            for a in alerts:                                   # process watch: alert "approved"
                if a.get("kind") == "integrity" and a.get("exe") and normalize_exe(a.get("exe")) == exe:
                    a["approved"] = True
            self.state.update(alerts=alerts)
            threading.Thread(target=self._builtin_refresh, daemon=True).start()   # warning removed without waiting 5 min
            for spid, info in list(self.suspended.items()):
                if normalize_exe(info.get("exe")) == exe:
                    try:
                        os.kill(spid, signal.SIGCONT)
                    except OSError:
                        pass
                    self.suspended.pop(spid, None)
            self.connections.mark_trusted(exe)
            self.write_log(f"✔ trusted program: {exe} (by {who})")
            self.broadcast({"event": "trusted", "programs": programs, "acknowledged": self.state.get("acknowledged_persistence") or []})
            self.broadcast({"event": "suspended", "suspended": list(self.suspended.values())})
            self.refresh_overall()
            return {"ok": True, "programs": programs}

        if cmd == "untrust_program":
            exe = normalize_exe(req.get("exe"))
            programs = [p for p in (self.state.get("trusted_programs") or []) if p.get("exe") != exe]
            self.state.update(trusted_programs=programs)
            self._trusted_set = TrustedPrograms(programs)
            self.monitor.dpkg_cache.pop(exe, None)
            self.write_log(f"✘ untrusted program: {exe}")
            self.broadcast({"event": "trusted", "programs": programs, "acknowledged": self.state.get("acknowledged_persistence") or []})
            return {"ok": True, "programs": programs}

        if cmd == "tray_quit":
            # "Quit" authorized by an administrator: do not relaunch the shield in this session
            ids = {s["id"] for s in graphical_sessions() if s["uid"] == uid} if not TEST_MODE else {"test"}
            self.tray_stopped[uid] = ids
            self.write_log(f"tray quit by uid {uid} (sessions {sorted(ids)})")
            return {"ok": True, "sessions": sorted(ids)}

        if cmd == "telemetry_send":
            # "Send now" (Settings): immediate anonymous report if telemetry is accepted
            if not self.settings.get("telemetry"):
                return {"ok": False, "error": "telemetry_disabled"}
            ok = self.send_telemetry(force=True)
            return {"ok": ok, "error": "" if ok else "telemetry_failed", "sent": self.state.get("telemetry_sent")}

        if cmd == "telemetry_preview":
            # Preview of the payload as it would be sent (nothing is transmitted)
            try:
                payload = self.build_telemetry_payload()
            except Exception as e:  # noqa: BLE001
                return {"ok": False, "error": "internal", "detail": str(e)[:200]}
            return {"ok": True, "payload": payload, "url": TELEMETRY_URL}

        if cmd == "forget_network":
            # The network becomes unknown again: Public by default at the next connection (immediately if it is
            # the current network)
            key = str(req.get("key") or "")
            known = dict(self.state.get("network_profiles") or {})
            if key not in known:
                return {"ok": False, "error": "not_found"}
            known.pop(key)
            self.state.update(network_profiles=known)
            self.write_log(f"network forgotten: {key}")
            if self.current_network and self.current_network.get("key") == key:
                self.check_network(force=True)
            else:
                self.refresh_security(force=True)
            return {"ok": True}

        if cmd == "acknowledge_integrity":
            # "That's normal": an approved integrity warning (chkrootkit, debsums, unhide, Lynis) no longer counts
            tool, text = str(req.get("tool") or "")[:32], str(req.get("text") or "")[:4000]
            if tool not in INTEGRITY_TOOLS or not text.strip():
                return {"ok": False, "error": "invalid_key"}
            key = integrity_ack_key(tool, text)
            ack = [k for k in (self.state.get("acknowledged_integrity") or []) if k != key]
            if not req.get("remove"):
                ack.insert(0, key)
            self.state.update(acknowledged_integrity=ack[:500])
            # Watch alerts carrying this warning: "approved" in the events ("That's normal" button)
            alerts = list(self.state.get("alerts") or [])
            marked = [a for a in alerts if a.get("kind") == "integrity" and a.get("text")
                      and integrity_ack_key(a.get("check") or tool, a["text"]) == key]
            for a in marked:
                a["approved"] = not req.get("remove")
            if marked:
                self.state.update(alerts=alerts)
            integ = self.apply_integrity_acks(dict(self.state.get("integrity") or {}))
            if integ:
                self.state.update(integrity=integ)
            self.write_log(f"integrity warning {'re-enabled' if req.get('remove') else 'acknowledged'} ({tool}): {text.splitlines()[0][:120]}")
            self.broadcast({"event": "integrity", "integrity": self.integrity_payload()})
            self.refresh_overall()
            return {"ok": True, "key": key}

        if cmd == "acknowledge_alert":
            # "It's OK" on a serious alert in the list: it stays there, marked ignored, but no longer keeps the shield
            # red for 24 h (remove: count it again). A new alert of the same kind counts again.
            when, kind = str(req.get("time") or "")[:40], str(req.get("kind") or "")[:40]
            title = req.get("title")
            alerts = list(self.state.get("alerts") or [])
            marked = [a for a in alerts if when and a.get("time") == when and a.get("kind") == kind
                      and (title is None or str(a.get("title") or a.get("comm") or "") == str(title))]
            if not marked:
                return {"ok": False, "error": "not_found"}
            # Only the account the alert is about may call it normal (another account, or a program trying to train
            # the shield, needs the administrator)
            try:
                me = pwd.getpwuid(uid).pw_name if uid > 0 else ""
            except KeyError:
                me = ""
            if uid != 0 and any(str(a.get("user") or "") not in ("", me) for a in marked) and not self.is_unlocked(uid, req):
                return {"ok": False, "error": "admin_required"}
            for a in marked:
                if a.get("kind") == "burst" and bool(a.get("ignored")) == bool(req.get("remove")) \
                        and not a.get("infected_exe") and not a.get("infected_files"):
                    # Burst declared normal: remembered; the second time, later ones are ignored automatically
                    self.habit_note(self.habit_key(a.get("exe"), a.get("top_dir")), -1 if req.get("remove") else 1)
                a["ignored"] = not req.get("remove")
            self.state.update(alerts=alerts)
            self.write_log(f"alert {'counted again' if req.get('remove') else 'ignored'} ({kind}): "
                           f"{str(marked[0].get('title') or marked[0].get('comm') or '')[:120]}")
            self.refresh_overall()
            return {"ok": True, "n": len(marked)}

        if cmd == "acknowledge_vuln":
            # "Ignore" one or more unfixed vulnerabilities (by CVE, across all packages); remove shows them again
            vulns = self.state.get("vulns") or {}
            acks = dict(self.state.get("acknowledged_vulns") or {})
            wanted = req.get("cves")
            if req.get("all_open"):
                wanted = [it.get("cve") or it.get("id") for it in vulns.get("items") or []
                          if it.get("status") in VULN_ACK_STATUSES and not it.get("dormant")]
            if not isinstance(wanted, list):
                wanted = [req.get("cve")]
            cves = []
            for c in wanted[:VULN_ACK_MAX]:
                c = str(c or "").strip()[:64]
                if re.match(r"^[A-Za-z0-9._:-]{4,64}$", c) and c not in cves:
                    cves.append(c)
            if not cves:
                return {"ok": False, "error": "invalid_key"}
            remove = bool(req.get("remove"))
            if remove:
                for c in cves:
                    acks.pop(c, None)
            else:
                pkgs = {}
                for it in vulns.get("items") or []:
                    if it.get("status") in VULN_ACK_STATUSES:
                        pkgs.setdefault(it.get("cve") or it.get("id"), set()).add(it.get("package") or "")
                now = now_iso()
                for c in cves:
                    acks[c] = {"at": now, "packages": sorted(pkgs.get(c) or [])[:20]}
                if len(acks) > VULN_ACK_MAX:
                    acks = dict(sorted(acks.items(), key=lambda kv: kv[1].get("at") or "")[-VULN_ACK_MAX:])
            self.state.update(acknowledged_vulns=acks)
            vulns = apply_vuln_acks(vulns, acks)
            self.state.update(vulns=vulns)
            self.write_log(f"{len(cves)} vulnerability(ies) {'re-enabled' if remove else 'acknowledged'}: {', '.join(cves[:8])}{'…' if len(cves) > 8 else ''}")
            self.broadcast({"event": "vulns", "vulns": self.public_vulns(vulns)})
            self.refresh_overall()
            return {"ok": True, "count": len(cves), "acknowledged": (vulns.get("counts") or {}).get("acknowledged_cves") or 0}

        if cmd == "acknowledge_sudoers":
            # "Ignore" an intended sudo NOPASSWD rule: remembered with the file fingerprint (reappears if it
            # changes)
            acks = dict(self.state.get("acknowledged_sudoers") or {})
            if req.get("remove"):
                path = str(req.get("path") or "")
                if path not in acks:
                    return {"ok": False, "error": "not_found"}
                acks.pop(path)
                done = [path]
            else:
                flagged = dict(getattr(self, "sudoers_flagged", None) or {})
                if not flagged:
                    self.refresh_checklist()
                    flagged = dict(getattr(self, "sudoers_flagged", None) or {})
                if not flagged:
                    return {"ok": False, "error": "nothing_to_ignore"}
                now = now_iso()
                for path, digest in flagged.items():
                    acks[path] = {"sha256": digest, "at": now}
                done = sorted(flagged)
            self.state.update(acknowledged_sudoers=acks)
            self.write_log(f"sudoers {'re-enabled' if req.get('remove') else 'acknowledged'} by uid {uid}: {', '.join(done)}")
            checklist = self.refresh_checklist()
            return {"ok": True, "n": len(done), "checklist": checklist}

        if cmd == "acknowledge_port":
            # "Ignore" an intended reachable port (development web server…): no longer counts in the checklist
            acks = dict(self.state.get("acknowledged_ports") or {})
            ports = (self.state.get("checklist") or {}).get("ports") or []
            wanted = req.get("keys")
            if req.get("all_reachable"):
                wanted = [p.get("key") or port_key(p) for p in ports if p.get("verdict") == "reachable"]
            if not isinstance(wanted, list):
                wanted = [req.get("key")]
            keys = []
            for k in wanted[:200]:
                k = str(k or "").strip()[:120]
                if re.match(r"^\d{1,5}/(tcp|udp):[A-Za-z0-9._+@ -]{0,80}$", k) and k not in keys:
                    keys.append(k)
            if not keys:
                return {"ok": False, "error": "invalid_key"}
            remove = bool(req.get("remove"))
            if remove:
                for k in keys:
                    acks.pop(k, None)
            else:
                now = now_iso()
                for k in keys:
                    acks[k] = {"at": now}
                if len(acks) > 500:
                    acks = dict(sorted(acks.items(), key=lambda kv: kv[1].get("at") or "")[-500:])
            self.state.update(acknowledged_ports=acks)
            self.write_log(f"{len(keys)} listening port(s) {'re-enabled' if remove else 'acknowledged'}: {', '.join(keys[:8])}")
            checklist = self.refresh_checklist()
            return {"ok": True, "count": len(keys), "checklist": checklist}

        if cmd == "acknowledge_persistence":
            key = str(req.get("key") or "")[:500]
            if not key:
                return {"ok": False, "error": "invalid_key"}
            ack = [k for k in (self.state.get("acknowledged_persistence") or []) if k != key]
            if not req.get("remove"):
                ack.insert(0, key)
            ack = ack[:500]
            self.state.update(acknowledged_persistence=ack)
            pers = self.apply_acknowledged(self.state.get("persistence") or {})
            self.state.update(persistence=pers)
            if not req.get("remove"):
                alerts = [a for a in (self.state.get("alerts") or [])
                          if not (a.get("kind") == "persistence" and key in ((a.get("item") or {}).get("key"), (a.get("extension") or {}).get("key")))]
                self.state.update(alerts=alerts)
            self.write_log(f"{'✘ un' if req.get('remove') else '✔ '}acknowledged persistence: {key}")
            self.broadcast({"event": "persistence", "persistence": pers})
            self.broadcast({"event": "trusted", "programs": self.state.get("trusted_programs") or [], "acknowledged": ack})
            self.refresh_overall()
            return {"ok": True, "acknowledged": ack}

        if cmd == "clear_alerts":
            self.state.update(alerts=[])
            return {"ok": True}

        if cmd == "quarantine_list":
            files = self.quarantine_list()
            if not self.admin_member(uid):
                files = [f for f in files if self._quarantine_owner(f["path"]) == uid]
            return {"ok": True, "files": files}

        if cmd == "quarantine_delete":
            p = req.get("path", "")
            if not self._in_quarantine(p):
                return {"ok": False, "error": "forbidden"}
            if uid != 0 and self._quarantine_owner(p) != uid and not self.is_unlocked(uid, req):
                return {"ok": False, "error": "admin_required"}
            os.remove(p)
            self.write_log(f"quarantine: deleted {os.path.basename(p)}")
            return {"ok": True, "msg_key": "msg.quarantine.deleted",
                    "msg_params": {"name": os.path.basename(p)}}

        if cmd == "quarantine_restore":
            p, dest = req.get("path", ""), req.get("dest", "")
            if not self._in_quarantine(p):
                return {"ok": False, "error": "forbidden"}
            if not (os.path.isabs(dest) and os.path.isdir(dest) and self._dest_allowed(os.path.realpath(dest), uid)):
                return {"ok": False, "error": "restore_dest"}
            # Only the owner of the file (or an administrator) may take it back
            name = os.path.basename(p)
            if uid != 0 and self._quarantine_owner(p) != uid and not self.is_unlocked(uid, req):
                return {"ok": False, "error": "admin_required"}
            # The copy is written by a process with the user's rights, never by root into a folder the user picked
            # (a symbolic link there would have pointed root's write at /etc)
            try:
                pw = pwd.getpwuid(uid)
                src = os.open(p, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            except (KeyError, OSError):
                return {"ok": False, "error": "restore_dest"}
            try:
                if not _stat.S_ISREG(os.fstat(src).st_mode):
                    return {"ok": False, "error": "forbidden"}
                target = run_as_user(pw.pw_uid, pw.pw_gid, "dukiwi_shield_common", "restore_copy", src, dest, name,
                                     pass_fds=(src,), timeout=600)
            except (OSError, subprocess.SubprocessError, ValueError) as e:
                self.write_log(f"quarantine: restore of {name} failed: {e}")
                return {"ok": False, "error": "restore_dest"}
            finally:
                os.close(src)
            os.unlink(p)
            self.write_log(f"quarantine: restored {os.path.basename(p)} -> {dest}")
            return {"ok": True, "msg_key": "msg.quarantine.restored",
                    "msg_params": {"name": os.path.basename(p)}}

        if cmd == "quarantine_empty":
            # A user empties their own files; everything only as administrator
            everything = uid == 0 or self.is_unlocked(uid, req)
            count = 0
            for f in Path(SYSTEM_QUARANTINE_DIR).iterdir():
                if f.is_file() and not f.name.startswith(".clamav-quarantine-lock") and \
                        (everything or self._quarantine_owner(str(f)) == uid):
                    f.unlink()
                    count += 1
            self.write_log(f"quarantine: emptied ({count})")
            return {"ok": True, "msg_key": "msg.quarantine.emptied_system", "msg_params": {"count": count}}

        if cmd == "security_journal":
            # Unified security journal: structured alerts + actions from the service log, sorted by category
            try:
                days = max(1, min(400, int(req.get("days") or 30)))
            except (TypeError, ValueError):
                days = 30
            if not self.admin_member(uid):
                return {"ok": True, "journal": {"days": days, "events": []}}     # the service log covers every account
            return {"ok": True, "journal": {"days": days, "events": security_journal(self, days)}}

        if cmd == "get_log":
            if not self.admin_member(uid):
                return {"ok": True, "lines": []}
            n = int(req.get("lines", 200))
            try:
                with open(SYSTEM_LOG_FILE) as f:
                    lines = f.readlines()[-n:]
            except OSError:
                lines = []
            return {"ok": True, "lines": lines}

        if cmd == "clear_log":
            open(SYSTEM_LOG_FILE, "w").close()
            return {"ok": True}

        if cmd == "test_event" and TEST_MODE:
            # Test mode only (non-root daemon): inject an event for the GUI
            event = req.get("payload") or {}
            if event.get("event") == "alert":
                self.publish_alert(event["alert"])
            elif event.get("event") == "usb_priority":
                # Simulates a key inserted during a scan: folder already mounted, scanned first
                path = os.path.normpath(str(event.get("path") or ""))
                usb = {"devnode": "test", "label": event.get("label") or "TEST", "model": "", "size": 0, "fstype": "vfat",
                       "private_mount": False, "mountpoint": path}
                self._start_usb_job(Job("scan", path=path, usb=usb, requested_by="system"))
            else:
                self.broadcast(event)
            return {"ok": True}

        return {"ok": False, "error": "unknown_command", "cmd": cmd}

    def security_command(self, cmd, req):
        """Firewall / SSH actions requested from the Firewall page."""
        if cmd != "ssh_set" and distro.firewall_backend() == "firewalld":
            return self.firewalld_command(cmd, req)
        if cmd == "firewall_set":
            if req.get("enabled"):
                if req.get("allow_ssh"):
                    self.ufw("allow", f"{ssh_port()}/tcp", "comment", "SSH")
                return firewall_enable_checked(self.ufw, self.write_log)
            return self.ufw("disable")
        if cmd == "firewall_defaults":
            results = []
            for direction in ("incoming", "outgoing"):
                policy = str(req.get(direction, "")).lower()
                if policy in VALID_POLICY:
                    results.append(self.ufw("default", policy, direction))
            if not results:
                return False, "invalid_policy"
            return all(ok for ok, _ in results), " | ".join(text for _, text in results)
        if cmd == "firewall_rule_add":
            action = str(req.get("rule_action") or req.get("action") or "allow").lower()
            proto = str(req.get("proto", "tcp")).lower()
            port = str(req.get("port", "")).strip()
            if action not in VALID_ACTION or proto not in VALID_PROTO or not re.fullmatch(r"\d{1,5}(:\d{1,5})?(,\d{1,5})*", port):
                return False, "invalid_rule"
            target = port if proto == "any" else f"{port}/{proto}"
            args = [action, target]
            comment = re.sub(r"[^\w .-]", "", str(req.get("comment", "")))[:40]
            if comment:
                args += ["comment", comment]
            return self.ufw(*args)
        if cmd == "firewall_rule_delete":
            try:
                number = int(req.get("number"))
            except (TypeError, ValueError):
                return False, "invalid_rule"
            return self.ufw("delete", str(number))
        if cmd == "ssh_set":
            if not (shutil.which("sshd") or os.path.exists("/usr/sbin/sshd")):
                return False, "ssh_not_installed"
            action = "enable" if req.get("enabled") else "disable"
            r = run_quiet(["systemctl", action, "--now", distro.ssh_unit()], timeout=60)
            self.write_log(f"ssh: {action} → {r.returncode}")
            return r.returncode == 0, ((r.stdout or "") + (r.stderr or "")).strip()[:300]
        return False, "unknown"

    def handle_connection(self, sock):
        try:
            _pid, uid, _gid = peer_credentials(sock)
        except OSError:
            uid = -1
        sock.settimeout(30)
        conn = LineSocket(sock)
        try:
            req = conn.recv()
            if req is None:
                return
            if req.get("cmd") == "subscribe":
                conn.send(self.status(uid, req))
                sock.settimeout(5)   # never block broadcasting on a slow client
                conn.uid = uid
                with self.sub_lock:
                    self.subscribers.append(conn)
                return               # the connection stays open, handled by broadcast()
            try:
                resp = self.handle(req, uid)
            except Exception as e:  # noqa: BLE001
                resp = {"ok": False, "error": "internal", "detail": str(e)}
            conn.send(resp)
        except (OSError, ValueError, socket.timeout) as e:
            log(f"Connexion : {e}")
        finally:
            with self.sub_lock:
                if conn not in self.subscribers:
                    conn.close()

    # ── Serveur ──────────────────────────────────────────────────────────
    def serve(self):
        for d in (SYSTEM_STATE_DIR, SYSTEM_LOG_DIR, SYSTEM_QUARANTINE_DIR,
                  os.path.dirname(DAEMON_SOCKET), USB_MOUNT_ROOT):
            os.makedirs(d, exist_ok=True)
        os.chmod(SYSTEM_QUARANTINE_DIR, 0o700)
        if not TEST_MODE:
            # State, logs and the private USB mounts: root only (decoy names, every account's file lists, keys being
            # scanned); the socket folder stays reachable by all accounts
            for d in (SYSTEM_STATE_DIR, SYSTEM_LOG_DIR, USB_MOUNT_ROOT):
                os.chmod(d, 0o700)
            os.chmod(os.path.dirname(DAEMON_SOCKET), 0o755)

        # Refuse to start if a daemon already answers on the socket
        if daemon_request("ping", timeout=1).get("ok"):
            log("Un daemon est déjà actif sur ce socket — arrêt.")
            sys.exit(1)
        try:
            os.unlink(DAEMON_SOCKET)
        except FileNotFoundError:
            pass

        self.server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.server.bind(DAEMON_SOCKET)
        os.chmod(DAEMON_SOCKET, 0o666)
        self.server.listen(16)
        self.server.settimeout(1)

        threading.Thread(target=self.worker, daemon=True, name="worker").start()
        threading.Thread(target=self.maintenance_loop, daemon=True, name="maintenance").start()
        try:
            self._builtin_refresh(initial=True)      # kernel / processes: up-to-date state right at startup (a few ms)
        except Exception as e:  # noqa: BLE001
            log(f"Contrôles intégrés : {e}")
        threading.Thread(target=self.network_loop, daemon=True, name="network").start()
        self.monitor.start()
        self.onaccess.start()
        self.hid_guard.start()
        self.guard.start()
        self.folders.start()
        self.network.start()
        self.connections.start()
        self.usb.start()
        self.honeypot.start()
        os.makedirs(UPDATES_DIR, exist_ok=True)

        def warmup():
            try:
                self.sync_filtered_dns()
            except Exception as e:  # noqa: BLE001
                log(f"DNS filtré : {e}")
            self.refresh_security(force=True, broadcast=False)
            self.refresh_overall()
            if self.settings.get("url_guard") is not False and self.urlguard.feeds_stale():
                try:
                    self.urlguard.refresh()
                except Exception as e:  # noqa: BLE001
                    log(f"Listes de sites malveillants : {e}")
            time.sleep(90)
            if not self.shutdown.is_set():
                self.daily_tasks()
        threading.Thread(target=warmup, daemon=True).start()

        log(f"Dukiwi Shield daemon v{VERSION} à l'écoute sur {DAEMON_SOCKET}"
            + (" (mode test)" if TEST_MODE else ""))
        while not self.shutdown.is_set():
            try:
                sock, _ = self.server.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self.handle_connection, args=(sock,), daemon=True).start()

        self.stop()

    def stop(self):
        self.shutdown.set()
        with self.queue_lock:
            job = self.current
            self.queue_lock.notify_all()
        if job:
            log("Arrêt : interruption de l'opération en cours (reprise possible)")
            job.cancel()
            deadline = time.time() + 10
            while self.current is not None and time.time() < deadline:
                time.sleep(0.2)
        self.monitor.stop()
        try:
            self.honeypot.close()
        except Exception as e:  # noqa: BLE001
            log(f"Pot de miel : arrêt : {e}")
        for devnode in list(self.usb.mounted):
            self.usb.unmount(devnode)
        with self.sub_lock:
            for sub in self.subscribers:
                sub.close()
            self.subscribers.clear()
        try:
            self.server.close()
        except OSError:
            pass
        try:
            os.unlink(DAEMON_SOCKET)
        except OSError:
            pass
        log("Daemon arrêté")


# ═══════════════════════════════════════════════════════════════════════════
# Client mode (used by the systemd timer and for diagnostics)
# ═══════════════════════════════════════════════════════════════════════════

def client_request(kind, path="/"):
    """Sends a request to the daemon and follows its execution until the end. Return code 0 = OK."""
    if kind == "status":
        resp = daemon_request("status", timeout=3)
        print(json.dumps(resp, indent=2, ensure_ascii=False))
        return 0 if resp.get("ok") else 1
    if kind == "system-status":
        resp = daemon_request("system_status", timeout=3, refresh=True, force=True)
        print(json.dumps(resp, indent=2, ensure_ascii=False))
        return 0 if resp.get("ok") else 1
    if kind in ("check-update", "checklist", "vulns", "integrity", "connections", "persistence"):
        cmd = {"check-update": "check_update"}.get(kind, kind)
        resp = daemon_request(cmd, timeout=600, refresh=True, run=(kind == "integrity"))
        print(json.dumps(resp, indent=2, ensure_ascii=False)[:20000])
        return 0 if resp.get("ok") else 1

    # Subscribe before launching so that no event is missed
    try:
        sub = daemon_connect(timeout=None)
        sub.send({"cmd": "subscribe"})
        sub.recv()
    except OSError as e:
        print(f"Service unavailable ({e})", flush=True)
        if kind == "update" and os.geteuid() == 0:
            print("Running freshclam directly.", flush=True)
            subprocess.run(["systemctl", "stop", "clamav-freshclam"], capture_output=True)
            rc = subprocess.run(["freshclam", "--stdout"]).returncode
            subprocess.run(["systemctl", "start", "clamav-freshclam"], capture_output=True)
            return rc
        return 1

    if kind == "update":
        resp = daemon_request("update", timeout=5)
    else:
        resp = daemon_request("scan", timeout=5, path=path)
    if not resp.get("ok"):
        print(f"Refused: {resp.get('error')}", flush=True)
        return 1
    job_id = resp.get("job_id")
    if resp.get("queued"):
        print(f"{kind} queued (job {job_id}) behind the running operation.", flush=True)
        return 0

    last_pct = -1
    while True:
        ev = sub.recv()
        if ev is None:
            print("Connection to daemon lost", flush=True)
            return 1
        et = ev.get("event")
        if et == "line":
            print(ev.get("text", ""), flush=True)
        elif et == "progress" and ev.get("total"):
            pct = int(ev["scanned"] * 100 / ev["total"])
            if pct != last_pct and pct % 5 == 0:
                print(f"… {pct}% ({ev['scanned']}/{ev['total']})", flush=True)
                last_pct = pct
        elif et == "job_done" and ev.get("id") == job_id:
            print(f"{ev.get('status')}: {ev.get('message')}", flush=True)
            return 0 if ev.get("status") in ("success", "clean", "infected") else 1


def main():
    args = sys.argv[1:]
    if args and args[0] == "--request":
        kind = args[1] if len(args) > 1 else "status"
        path = args[2] if len(args) > 2 else "/"
        sys.exit(client_request(kind, path))
    if args and args[0] in ("-h", "--help"):
        print(__doc__)
        return

    if os.geteuid() != 0 and "DUKIWI_SHIELD_SOCKET" not in os.environ:
        print("Ce service doit être lancé en root (ou avec DUKIWI_SHIELD_SOCKET pour les tests).",
              file=sys.stderr)
        sys.exit(1)

    daemon = Daemon()

    def on_signal(signum, _frame):
        log(f"Signal {signum} reçu")
        daemon.shutdown.set()

    signal.signal(signal.SIGTERM, on_signal)
    signal.signal(signal.SIGINT, on_signal)
    daemon.serve()
    # Immediate exit: thread pools still in flight (OSV requests from the daily tasks…) are joined by
    # concurrent.futures at interpreter shutdown and kept the service alive for several minutes after
    # "Daemon arrêté" (systemd stop / package upgrade). All state is already written synchronously.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.flush()
        except (OSError, ValueError):
            pass
    os._exit(0)


if __name__ == "__main__":
    main()
