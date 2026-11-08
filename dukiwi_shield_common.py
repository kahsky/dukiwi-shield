#!/usr/bin/env python3
"""
Dukiwi Shield — module shared between the GUI and the system daemon.
Paths, scan exclusions, socket protocol (JSON per line) and utilities.
(c) 2026 Dukiwi SA - Estavayer-le-Lac
"""

import json
import os
import re
import socket
import struct
import subprocess
from datetime import datetime

VERSION = "2.9.8"

# ─── System paths (root daemon) ─────────────────────────────────────────────
# Can be overridden by environment variables for tests without root.
SYSTEM_STATE_DIR = os.environ.get("DUKIWI_SHIELD_STATE_DIR", "/var/lib/dukiwi-shield")
SYSTEM_LOG_DIR   = os.environ.get("DUKIWI_SHIELD_LOG_DIR",   "/var/log/dukiwi-shield")
DAEMON_SOCKET    = os.environ.get("DUKIWI_SHIELD_SOCKET",    "/run/dukiwi-shield/daemon.sock")

SYSTEM_STATE_FILE      = os.path.join(SYSTEM_STATE_DIR, "state.json")
SYSTEM_QUARANTINE_DIR  = os.path.join(SYSTEM_STATE_DIR, "quarantine")
SYSTEM_PROGRESS_FILE   = os.path.join(SYSTEM_STATE_DIR, "scan_progress.json")
SYSTEM_FILELIST_CACHE  = os.path.join(SYSTEM_STATE_DIR, "scan_filelist.txt")
SYSTEM_SCAN_CACHE_DB   = os.path.join(SYSTEM_STATE_DIR, "scan-cache.db")     # clean files already checked (fingerprints)
SYSTEM_SECRET_FILE     = os.path.join(SYSTEM_STATE_DIR, "secret")            # HMAC of the .clamav manifests (never on the key)
FIRST_SCAN_FLAG        = os.path.join(SYSTEM_STATE_DIR, "first-scan-pending")
SYSTEM_LOG_FILE        = os.path.join(SYSTEM_LOG_DIR, "scan.log")
SYSTEM_SETTINGS_FILE   = os.path.join(SYSTEM_STATE_DIR, "settings.json")

CLAMAV_DB_DIR = "/var/lib/clamav"

USB_MOUNT_ROOT         = os.path.join(os.path.dirname(DAEMON_SOCKET), "mnt")

# systemd units
UPDATE_TIMER_UNIT  = "dukiwi-shield-update.timer"
DAEMON_UNIT        = "dukiwi-shield-daemon.service"

# ─── Advanced detection ─────────────────────────────────────────────────────
# USB media: below this size, automatic scan before mounting;
# above it (USB hard disk), the user is asked.
USB_AUTO_SCAN_MAX_BYTES = 128 * 1024 ** 3
# Write bursts: a process that modifies this many distinct files
# within the given window triggers an alert (info, or danger if suspicious).
BURST_WINDOW_SEC        = 15
BURST_INFO_THRESHOLD    = 50
BURST_DANGER_THRESHOLD  = 25      # files in the home directory, untrusted process
BURST_PID_COOLDOWN_SEC  = 600
BURST_GLOBAL_COOLDOWN   = 30
# Writes ignored by the monitor (caches, logs, temporary files)
BURST_IGNORE_PREFIXES = (
    "/proc/", "/sys/", "/dev/", "/run/", "/tmp/", "/var/tmp/", "/var/log/",
    "/var/cache/", "/var/lib/apt/lists/", "/var/lib/clamav/", "/var/lib/dukiwi-shield/",
    "/var/log/journal/", "/var/lib/systemd/", "/home/.ecryptfs/",
)
BURST_IGNORE_PARTS = (
    "/.cache/", "/Cache/", "/cache2/", "/CachedData/", "/.local/share/Trash/",
    "/.thumbnails/", "/node_modules/", "/.git/", "/__pycache__/", "/.npm/", "/.cargo/registry/",
    "/.local/share/dukiwi-shield/", "/.config/Code/", "/.vscode/", "/.mozilla/firefox/",
    "/.config/google-chrome/", "/.config/chromium/", "/.config/BraveSoftware/",
)

LANGUAGES = ("fr", "en", "de", "it")

# ─── System settings (editable from the Settings page, applied by the daemon) ──
DEFAULT_SETTINGS = {
    # Internet upload: popup when the volume sent exceeds the threshold within the given window
    "upload_monitor": True,
    "upload_alert_gb": 5.0,
    "upload_window_hours": 1,
    # Write bursts (fanotify)
    "burst_monitor": True,
    "burst_info_threshold": BURST_INFO_THRESHOLD,
    "burst_danger_threshold": BURST_DANGER_THRESHOLD,
    "burst_window_sec": BURST_WINDOW_SEC,
    # Supports USB
    "usb_auto_scan": True,
    "usb_auto_scan_max_gib": 128,
    # Signature update check (systemd timer)
    "update_hour": 7,
    "update_minute": 0,
    # Scan complet automatique hebdomadaire (0 = lundi … 6 = dimanche)
    "weekly_scan": False,
    "weekly_scan_day": 6,
    "weekly_scan_hour": 12,
    # Scan cache: a clean, unchanged file (size, dates, inode) is not read again for N days (0 = disabled)
    "scan_cache_days": 30,
    # Family mode: sensitive settings and actions reserved for an authenticated administrator
    "family_mode": False,
    # Automatic response: suspend (SIGSTOP) a program judged dangerous, then ask
    "auto_response": True,
    # Learn from the user's choices: known write bursts ignored automatically (action started by a
    # package manager, application in its own folder, burst already declared normal twice)
    "auto_ignore_known": True,
    # Outgoing connections: unknown programs, malicious IP lists, geolocation
    "connection_monitor": True,
    # On-arrival scan: files written to download folders, the desktop or removable media
    # passed to clamd as soon as they are closed; infected → quarantine before being opened
    "on_access_scan": True,
    # BadUSB: a new USB keyboard is blocked as soon as it is plugged in until the user approves (popup)
    "usb_keyboard_guard": True,
    # Security centre: anti-ransomware decoys (watched hidden files), camera and microphone, cryptocurrency miners
    "ransomware_decoys": True,
    "privacy_watch": True,
    "miner_watch": True,
    # Keyboard spies (direct reads of /dev/input) and unusual logins (SSH, night)
    "keylogger_watch": True,
    "login_watch": True,
    # Protected folders: only approved programs open Documents, Pictures, Desktop (disabled by default)
    "protected_folders": False,
    # Filtered DNS (systemd-resolved): "" (disabled), "quad9", "cloudflare"; suspended on an Enterprise network
    "filtered_dns": "",
    "geoip_lookup": True,
    # ip-api.com Pro key (optional): HTTPS and unlimited; empty = free service (15 batched requests/min, HTTP)
    "geoip_api_key": "",
    # Availability: backup of the user's files counted in the overall state (False = "Ignore")
    "backup_check": True,
    # Timeshift state counted in the overall state (False = "Ignore": PC without room for snapshots)
    "timeshift_check": True,
    # Firewall network profile: "" (not chosen), "home", "public", "enterprise"
    "firewall_profile": "",
    # Anonymous telemetry (opt-in): version, system, score, approved false positives, no personal identifier
    "telemetry": False,
    # Automatic hardening: risk-free Lynis recommendations applied after each audit
    "auto_harden": False,
    # Weekly integrity check (Lynis, unhide, chkrootkit, debsums, app files)
    "integrity_weekly": True,
    "integrity_day": 6,
    "integrity_hour": 13,
    # Application updates (signed manifest on the Dukiwi repository)
    "app_update_check": True,
    "app_update_auto": False,
    # Network honeypot: decoy ports listening, scans reported. Enabled by default (decision 2026-10-15),
    # can be disabled in Settings › Security and family (administrator in family mode)
    "honeypot": True,
    # Link checking (Thunderbird and browser extensions): malicious site lists + heuristics;
    # shorteners resolved by the service; email attachments scanned by clamd
    "url_guard": True,
    "url_guard_resolve": True,
    "mail_scan_attachments": True,
}

SETTINGS_LIMITS = {
    "upload_alert_gb": (0.1, 10000.0), "upload_window_hours": (1, 168),
    "burst_info_threshold": (5, 100000), "burst_danger_threshold": (5, 100000), "burst_window_sec": (5, 600),
    "usb_auto_scan_max_gib": (1, 100000),
    "update_hour": (0, 23), "update_minute": (0, 59),
    "weekly_scan_day": (0, 6), "weekly_scan_hour": (0, 23),
    "scan_cache_days": (0, 365),
    "integrity_day": (0, 6), "integrity_hour": (0, 23),
}


def sanitize_settings(current, incoming):
    """Merges incoming settings (dict) into `current`, respecting types and limits.
    Returns (settings, errors)."""
    result = dict(DEFAULT_SETTINGS)
    result.update(current or {})
    errors = []
    for key, value in (incoming or {}).items():
        if key not in DEFAULT_SETTINGS:
            errors.append(f"unknown:{key}")
            continue
        default = DEFAULT_SETTINGS[key]
        try:
            if isinstance(default, bool):
                value = value if isinstance(value, bool) else str(value).lower() in ("1", "true", "yes", "on")
            elif isinstance(default, int):
                value = int(float(value))
            elif isinstance(default, float):
                value = float(value)
            elif isinstance(default, str):
                value = "".join(ch for ch in str(value).strip() if ch.isalnum() or ch in "-_")[:128]
        except (TypeError, ValueError):
            errors.append(f"invalid:{key}")
            continue
        if key in SETTINGS_LIMITS:
            lo, hi = SETTINGS_LIMITS[key]
            value = max(lo, min(hi, value))
        result[key] = value
    return result, errors

# ─── Paths the daemon agrees to scan for any user ──────────────────────────
# (in addition to the home directory of the requesting user)
DAEMON_ALLOWED_ROOTS = ["/", "/home", "/etc", "/var", "/opt", "/usr", "/tmp", "/boot", "/root", "/srv"]

# ─── Directories excluded from the scan (useless or problematic on Linux Mint 22) ─
SCAN_EXCLUDE = [
    '/proc/*', '/sys/*', '/dev/*', '/run/*',           # virtual file systems
    '/home/.ecryptfs/*',                               # eCryptFS vault (encrypted)
    '/snap/*', '/var/lib/snapd/*',                     # snap packages (protected squashfs)
    '/var/cache/apt/*', '/var/cache/debconf/*',        # cache paquets APT
    '/var/cache/man/*',                                # cache man pages
    '/var/lib/clamav/*',                               # bases virales (faux positifs garantis)
    '/var/lib/dukiwi-shield/quarantine/*',          # system quarantine
    '/usr/share/doc/*', '/usr/share/man/*',            # documentation
    '/usr/share/info/*', '/usr/share/locale/*',        # locale data
    '/usr/share/i18n/*', '/usr/share/fonts/*',         # polices
    '/usr/share/icons/*', '/usr/share/themes/*',       # icons / themes
    '/usr/share/pixmaps/*', '/usr/share/backgrounds/*',# decorative images
    '/home/*/.cache/*',                                # caches utilisateurs
    '/home/*/.local/share/Trash/*',                    # corbeilles
    '/home/*/.local/share/dukiwi-shield/*',         # quarantaine / logs utilisateur
    '/home/*/.thumbnails/*',                           # miniatures
    '/home/*/.mozilla/*/Cache*/*',                     # cache Firefox
    '/home/*/.config/google-chrome/*/Cache*/*',        # cache Chrome
    '/root/.cache/*',                                  # cache root
]

# clamscan --verbose output lines that are noise (do not log)
NOISE_PREFIXES = ("traverse_to:", "LibClamAV", "Scanning ")
NOISE_SUFFIXES = (": Empty file", ": No such file or directory", ": Excluded", ": Symbolic link")


# ── Quarantine index: isolated file → original path and signature (fed by the "moved to" lines) ──
# ═══ Doing file work as the user ════════════════════════════════════════
# The root daemon must never open, create or rename files in a folder a user controls: a symbolic link put there in
# advance would turn the write into one on /etc/passwd or the read into one of /etc/shadow. Such work runs in a child
# process with the user's uid, gid and no supplementary group, so the kernel applies that user's rights.
_CODE_DIR = os.path.dirname(os.path.abspath(__file__))
_AS_USER_CODE = ("import json, sys; sys.path.insert(0, sys.argv[1]); import importlib; "
                 "a = json.load(sys.stdin); r = getattr(importlib.import_module(sys.argv[2]), sys.argv[3])(*a); "
                 "sys.stdout.write(json.dumps(r))")


def open_user_file(path, mode="r", limit=4 << 20):
    """Reads a file found in a folder a user controls, safely for root: never blocks (a FIFO put in its place is
    refused instead of freezing the thread), only a regular file (not /dev/zero through a link), at most `limit`
    bytes. Returns an in-memory file (text decoded as UTF-8 with replacement, or bytes for mode "rb")."""
    import io
    import stat as _st
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        st = os.fstat(fd)
        if not _st.S_ISREG(st.st_mode) or st.st_size > limit:
            raise OSError(22, "not a regular file or too large", path)
        chunks, total = [], 0
        while total <= limit:
            b = os.read(fd, min(1 << 20, limit + 1 - total))
            if not b:
                break
            chunks.append(b)
            total += len(b)
    finally:
        os.close(fd)
    data = b"".join(chunks)
    if len(data) > limit:
        raise OSError(27, "file too large", path)
    return io.BytesIO(data) if "b" in mode else io.StringIO(data.decode("utf-8", "replace"))


def run_as_user(uid, gid, module, func, *args, timeout=60, pass_fds=()):
    """Calls module.func(*args) in a child process running as uid:gid; returns its JSON result.
    Raises OSError with the child's last error line when it fails."""
    import sys
    kw = {}
    if os.geteuid() == 0 and uid != 0:
        kw = {"user": uid, "group": gid, "extra_groups": []}
    elif uid != os.geteuid():
        raise PermissionError("cannot switch user")
    r = subprocess.run([sys.executable, "-I", "-c", _AS_USER_CODE, _CODE_DIR, module, func],
                       input=json.dumps(list(args)), capture_output=True, text=True, timeout=timeout, cwd="/", pass_fds=pass_fds,
                       env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}, **kw)
    if r.returncode != 0:
        lines = (r.stderr or "").strip().splitlines()
        raise OSError(lines[-1] if lines else f"exit {r.returncode}")
    return json.loads(r.stdout or "null")


def write_file_atomic(path, text, mode=0o644):
    """Replaces path with text through a new temporary file in the same folder (never follows a symbolic link)."""
    d, name = os.path.split(path)
    tmp = os.path.join(d, f".{name}.dukiwi-{os.getpid()}")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "w") as f:
            f.write(text)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def write_decoy_file(path, hexdata, mtime):
    """Writes a ransomware decoy (bytes given in hex) with an old date. Run as the owner of the folder (see
    run_as_user): root never creates files in a folder a user controls. Returns [inode, size, mtime]."""
    data = bytes.fromhex(hexdata)
    d, name = os.path.split(path)
    tmp = os.path.join(d, f".{name}.{os.getpid()}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
    try:
        os.write(fd, data)
    finally:
        os.close(fd)
    os.replace(tmp, path)
    os.utime(path, (mtime, mtime), follow_symlinks=False)
    st = os.lstat(path)
    return [st.st_ino, st.st_size, st.st_mtime]


def drop_lines(path, lines, mode):
    """Rewrites path without the given lines (exact text). Run as the file owner (see run_as_user)."""
    if os.path.islink(path):
        raise OSError("symbolic link")
    with open(path, errors="replace") as f:
        current = f.read().splitlines()
    drop = set(lines)
    kept = [ln for ln in current if ln not in drop]
    if len(kept) != len(current):
        write_file_atomic(path, "\n".join(kept) + ("\n" if kept else ""), mode)
    return len(current) - len(kept)


def restore_copy(src_fd, dest_dir, name):
    """Copies the open file src_fd to a new file dest_dir/name (name.1, name.2… if taken). Run as the user who
    restores (see run_as_user): the folder and the new file are then subject to that user's rights only."""
    base, n = os.path.basename(name) or "restored", 0
    dfd = os.open(dest_dir, os.O_RDONLY | os.O_DIRECTORY)
    try:
        while True:
            target = base if n == 0 else f"{base}.{n}"
            try:
                out = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644, dir_fd=dfd)
                break
            except FileExistsError:
                n += 1
                if n > 999:
                    raise
        os.lseek(src_fd, 0, os.SEEK_SET)
        with os.fdopen(out, "wb") as f:
            while True:
                chunk = os.read(src_fd, 1 << 20)
                if not chunk:
                    break
                f.write(chunk)
        return os.path.join(dest_dir, target)
    finally:
        os.close(dfd)


def quarantine_index_path(quarantine_dir):
    return os.path.join(os.path.dirname(quarantine_dir.rstrip("/")), "quarantine-index.json")


def quarantine_index_load(quarantine_dir):
    try:
        with open(quarantine_index_path(quarantine_dir), encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def quarantine_index_add(quarantine_dir, dest, origin, signature, owner=None):
    """Records, for the isolated file `dest`, its original path, the detected signature and the uid of its owner
    (only that user, or an administrator, may restore it)."""
    if owner is None:
        try:
            owner = os.lstat(dest).st_uid
        except OSError:
            owner = 0
    index = quarantine_index_load(quarantine_dir)
    index[os.path.basename(dest)] = {"origin": origin, "signature": signature or "", "owner": int(owner),
                                     "time": datetime.now().isoformat(timespec="seconds")}
    if len(index) > 5000:
        for k in sorted(index, key=lambda k: index[k].get("time", ""))[:-5000]:
            index.pop(k, None)
    path = quarantine_index_path(quarantine_dir)
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(index, f, ensure_ascii=False)
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except OSError:
        pass


def parse_moved_line(line):
    """"/path/origin: moved to '/quarantine/name'" → (origin, destination) or None."""
    m = re.match(r"^(.*): moved to '(.*)'$", line)
    return (m.group(1), m.group(2)) if m else None


def quarantine_enrich(files, quarantine_dir):
    """Adds origin, signature and detection date to the quarantine list entries."""
    index = quarantine_index_load(quarantine_dir)
    for f in files:
        info = index.get(f.get("name") or "")
        if info:
            f["origin"] = info.get("origin") or ""
            f["signature"] = info.get("signature") or ""
            f["found_at"] = info.get("time") or ""
    return files


def find_command(path, exclude=SCAN_EXCLUDE, stat=False):
    """find command listing the regular files to scan under `path` (a path or a list of paths). With `stat`, each
    line also carries the fingerprint (size, mtime, ctime, inode) separated by tabs, for the clean-file cache."""
    paths = list(path) if isinstance(path, (list, tuple)) else [path]
    # A path starting with "-" would be read by find as an option (-delete…)
    cmd = ['find'] + [p if p.startswith("/") else "./" + p for p in paths] + ['-type', 'f']
    for excl in exclude:
        cmd += ['!', '-path', excl]
    # One file per line in the list given to clamdscan: a name containing a line break could otherwise add any
    # path (another account's files, /root) to the list root scans
    cmd += ['!', '-name', '*\n*', '!', '-name', '*\t*']
    if stat:
        cmd += ['-printf', '%p\t%s\t%T@\t%C@\t%i\n']
    return cmd


def is_noise_line(line):
    """True if the clamscan line is of no use to the user."""
    if not line:
        return True
    if line.startswith(NOISE_PREFIXES):
        return True
    return line.endswith(NOISE_SUFFIXES)


def classify_line(line):
    """Classifies a clamscan output line: 'found', 'denied', 'error', 'summary', 'info'."""
    if line.endswith(" FOUND"):
        return "found"
    if line.endswith(": Access denied") or line.endswith(": Permission denied"):
        return "denied"
    if line.startswith("-----------") or line.startswith("Known viruses") \
            or line.startswith("Engine version") or line.startswith("Scanned ") \
            or line.startswith("Infected files") or line.startswith("Data ") \
            or line.startswith("Time:") or line.startswith("Start Date") \
            or line.startswith("End Date") or line.startswith("Total errors"):
        return "summary"
    if "ERROR" in line or line.endswith(": Can't open file") or "Can't" in line:
        return "error"
    return "info"


def db_last_update():
    """Date (datetime) of the most recent signature in /var/lib/clamav, or None."""
    newest = None
    try:
        for name in os.listdir(CLAMAV_DB_DIR):
            if name.endswith((".cvd", ".cld")):
                mtime = os.stat(os.path.join(CLAMAV_DB_DIR, name)).st_mtime
                if newest is None or mtime > newest:
                    newest = mtime
    except OSError:
        return None
    return datetime.fromtimestamp(newest) if newest else None


def db_files_info():
    """List of signature files with size and date."""
    files = []
    try:
        for name in sorted(os.listdir(CLAMAV_DB_DIR)):
            if name.endswith((".cvd", ".cld")):
                st = os.stat(os.path.join(CLAMAV_DB_DIR, name))
                files.append({
                    "name": name,
                    "size": str(st.st_size),
                    "date": datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M"),
                })
    except OSError:
        pass
    return files


def systemd_next_elapse(unit=UPDATE_TIMER_UNIT):
    """Next run of a systemd timer (datetime) or None. Works without root."""
    try:
        r = subprocess.run(
            ["systemctl", "show", unit, "-p", "NextElapseUSecRealtime", "--value"],
            capture_output=True, text=True, timeout=5,
        )
        value = r.stdout.strip()
        if not value or value in ("n/a", "infinity"):
            return None
        # Format : "Mon 2026-09-28 07:00:00 CEST"
        parts = value.split()
        if len(parts) >= 3:
            return datetime.strptime(f"{parts[1]} {parts[2]}", "%Y-%m-%d %H:%M:%S")
    except Exception:
        pass
    return None


def systemd_is_active(unit):
    """True if the systemd unit is active. Works without root."""
    try:
        r = subprocess.run(["systemctl", "is-active", unit],
                           capture_output=True, text=True, timeout=5)
        return r.stdout.strip() == "active"
    except Exception:
        return False


# ─── UFW firewall: parsing command output ───────────────────────────────────

def parse_ufw_verbose(text):
    """Parses `ufw status verbose`: status and default policies."""
    info = {"active": False, "default_incoming": "", "default_outgoing": "", "default_routed": "", "logging": ""}
    for line in (text or "").splitlines():
        line = line.strip()
        if line.lower().startswith("status:"):
            info["active"] = "active" in line.lower() and "inactive" not in line.lower()
        elif line.lower().startswith("default:"):
            for part in line.split(":", 1)[1].split(","):
                part = part.strip()
                if "(incoming)" in part:
                    info["default_incoming"] = part.split()[0]
                elif "(outgoing)" in part:
                    info["default_outgoing"] = part.split()[0]
                elif "(routed)" in part:
                    info["default_routed"] = part.split()[0]
        elif line.lower().startswith("logging:"):
            info["logging"] = line.split(":", 1)[1].strip()
    return info


def parse_ufw_numbered(text):
    """Parses `ufw status numbered`: list of rules [{number, to, action, from, v6, raw}]."""
    rules = []
    for line in (text or "").splitlines():
        line = line.rstrip()
        if not line.startswith("["):
            continue
        try:
            number = int(line[1:line.index("]")].strip())
        except ValueError:
            continue
        rest = line[line.index("]") + 1:].strip()
        v6 = "(v6)" in rest
        rest = rest.replace("(v6)", "").strip()
        # Columns separated by 2 or more spaces: To | Action | From
        cols = [c.strip() for c in re.split(r"\s{2,}", rest) if c.strip()]
        to = cols[0] if cols else rest
        action = cols[1] if len(cols) > 1 else ""
        src = " ".join(cols[2:]) if len(cols) > 2 else ""
        comment = ""
        if "#" in src:
            src, comment = src.split("#", 1)
            src, comment = src.strip(), comment.strip()
        rules.append({"number": number, "to": to, "action": action, "from": src, "v6": v6,
                      "comment": comment, "raw": line.strip()})
    return rules


# ─── Internationalisation ────────────────────────────────────────────────────

_I18N_CACHE = None


def load_i18n():
    """Loads ui/i18n.js (window.I18N = {...};) and returns the per-language dictionary."""
    global _I18N_CACHE
    if _I18N_CACHE is not None:
        return _I18N_CACHE
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ui", "i18n.js")
    try:
        with open(path, encoding="utf-8") as f:
            raw = f.read()
        start, end = raw.index("{"), raw.rindex("}")
        _I18N_CACHE = json.loads(raw[start:end + 1])
    except Exception:
        _I18N_CACHE = {}
    return _I18N_CACHE


def home_mounted(pw):
    """False while the eCryptfs-encrypted home folder is not mounted (before login, after
    logout): /home/<name> is then the empty folder hidden under the mount. Writing there would leave files that are
    invisible once the session is open, and its real files are not there."""
    if not os.path.isdir(f"/home/.ecryptfs/{pw.pw_name}/.Private"):
        return True
    home = pw.pw_dir.rstrip("/")
    try:
        with open("/proc/mounts") as f:
            for ln in f:
                parts = ln.split()
                if len(parts) >= 3 and parts[1].replace("\\040", " ") == home and parts[2] == "ecryptfs":
                    return True
    except OSError:
        return True
    return False


def migrate_user_data():
    """User data folder of previous versions (backups, vault, interface settings) taken over
    once, on the first launch of Dukiwi Shield."""
    if os.geteuid() == 0:
        return
    new = os.path.expanduser("~/.local/share/dukiwi-shield")
    old = os.path.expanduser("~/.local/share/" + "clamav" + "-antivirus")
    try:
        if os.path.isdir(old) and not os.path.islink(old) and not os.path.exists(new):
            os.rename(old, new)
    except OSError:
        pass


migrate_user_data()


LOCALE_FILES = ("/etc/default/locale", "/etc/locale.conf")      # system locale (Debian / Ubuntu / Mint, then Fedora)


def system_locale(files=LOCALE_FILES):
    """LANG of the configured system locale ("fr_CH.UTF-8"), when the environment provides none: shield restarted
    by the service, session without language variables. Empty string if nothing is configured."""
    for path in files:
        try:
            with open(path, encoding="utf-8", errors="replace") as f:
                values = {}
                for ln in f:
                    ln = ln.strip()
                    if "=" in ln and not ln.startswith("#"):
                        k, v = ln.split("=", 1)
                        values[k.strip()] = v.strip().strip('"').strip("'")
                for k in ("LANGUAGE", "LC_ALL", "LC_MESSAGES", "LANG"):
                    if values.get(k):
                        return values[k]
        except OSError:
            continue
    return ""


def _language_code(value):
    """"fr_CH.UTF-8" / "en_US:fr" → "fr" / "en"; empty for C / POSIX."""
    code = (value or "").split(":")[0].split("_")[0].split(".")[0].split("@")[0].lower()
    return "" if code in ("", "c", "posix") else code


def pick_language(preferred=None):
    """Interface language: explicit preference (Settings), otherwise the system language (environment variables,
    then the locale configured in /etc), otherwise English. A system language without a translation gives English."""
    if preferred in LANGUAGES:
        return preferred
    for var in ("LANGUAGE", "LC_ALL", "LC_MESSAGES", "LANG"):
        code = _language_code(os.environ.get(var))
        if code:
            return code if code in LANGUAGES else "en"
    code = _language_code(system_locale())
    return code if code in LANGUAGES else "en"


def t(lang, key, **params):
    """Translates a key (fallback: English, then French, then the key itself)."""
    i18n = load_i18n()
    text = None
    for candidate in (lang, "en", "fr"):
        text = (i18n.get(candidate) or {}).get(key)
        if text is not None:
            break
    if text is None:
        text = key
    if params:
        try:
            text = text.format(**params)
        except (KeyError, IndexError, ValueError):
            pass
    return text


def format_duration(seconds):
    """Readable duration: '1 h 12 min', '4 min 05 s', '32 s'."""
    seconds = int(max(0, seconds))
    h, rem = divmod(seconds, 3600)
    m, s = divmod(rem, 60)
    if h:
        return f"{h} h {m:02d} min"
    if m:
        return f"{m} min {s:02d} s"
    return f"{s} s"


# ─── Socket protocol: one JSON line per message ─────────────────────────────

class LineSocket:
    """Wraps a Unix socket to exchange JSON messages line by line."""

    def __init__(self, sock):
        self.sock = sock
        self._buf = b""

    def send(self, obj):
        data = (json.dumps(obj, ensure_ascii=False) + "\n").encode("utf-8")
        self.sock.sendall(data)

    def recv(self):
        """Returns the next JSON object, or None if the connection is closed."""
        while b"\n" not in self._buf:
            chunk = self.sock.recv(65536)
            if not chunk:
                return None
            self._buf += chunk
        line, _, self._buf = self._buf.partition(b"\n")
        line = line.strip()
        if not line:
            return self.recv()
        return json.loads(line.decode("utf-8"))

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


def peer_credentials(sock):
    """(pid, uid, gid) of the process connected on a Unix socket (SO_PEERCRED)."""
    creds = sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
    return struct.unpack("3i", creds)


def daemon_connect(timeout=2.0):
    """Opens a connection to the daemon. Raises OSError if unavailable."""
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    sock.connect(DAEMON_SOCKET)
    return LineSocket(sock)


# Administrator session token of this process (set by the GUI after pkexec), sent with every request
ADMIN_TOKEN = None


def admin_token_from(output):
    """Token printed by dukiwi-shield-unlock ("token=…"), or None."""
    for line in (output or "").splitlines():
        if line.startswith("token=") and len(line) > 6:
            return line[6:].strip()
    return None


def daemon_request(cmd, timeout=2.0, **kwargs):
    """Sends a single command to the daemon and returns the response (dict).
    Returns {"ok": False, "error": ..., "unavailable": True} if the daemon does not respond."""
    if ADMIN_TOKEN and "admin_token" not in kwargs:
        kwargs["admin_token"] = ADMIN_TOKEN
    try:
        conn = daemon_connect(timeout=timeout)
    except OSError as e:
        return {"ok": False, "error": f"Service indisponible ({e})", "unavailable": True}
    try:
        conn.send(dict(cmd=cmd, **kwargs))
        resp = conn.recv()
        return resp if resp is not None else {"ok": False, "error": "Connexion fermée", "unavailable": True}
    except (OSError, ValueError) as e:
        return {"ok": False, "error": str(e), "unavailable": True}
    finally:
        conn.close()


def ntfs_mount_problem(text):
    """Why an NTFS volume refuses to mount, from the messages of ntfs-3g / ntfsfix / udisks (2.9.2).
    "hibernated": Windows hibernated or shut down with fast startup while the drive was attached;
    "inconsistent": the file system needs a repair ($MFTMirr mismatch, I/O error on the metadata);
    "unclean": the volume is marked dirty (removed without ejecting it under Windows); "" when unknown."""
    low = (text or "").lower()
    if any(k in low for k in ("hibernat", "metadata kept in windows cache", "fast restart", "fast startup")):
        return "hibernated"
    if any(k in low for k in ("$mftmirr does not match", "is either inconsistent", "input/output error",
                              "corrupt", "chkdsk /f")):
        return "inconsistent"
    if any(k in low for k in ("unclean file system", "volume is dirty", "dirty volume", "is marked dirty")):
        return "unclean"
    return ""
