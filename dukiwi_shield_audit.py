#!/usr/bin/env python3
"""
Dukiwi Shield — contrôles d'audit du centre de sécurité (service système).

1. Espions du clavier : programme qui lit directement un clavier (/dev/input/event*) sans être le serveur graphique,
   le gestionnaire de sessions ou un outil de remappage connu ; enregistreurs X11 connus (logkeys, xinput test…).
2. Connexions inhabituelles : connexion SSH depuis une adresse ou un pays jamais vu pour ce compte, connexion root,
   connexion (SSH ou locale) au milieu de la nuit. Référence : les 30 derniers jours du journal.
3. Conteneurs : socket Docker accessible à tous ou ouvert sur le réseau, comptes des groupes docker/lxd (équivalent
   administrateur), conteneurs privilégiés ou qui montent / ou le socket Docker.
4. Permissions Flatpak : applications qui voient tout le système de fichiers ou le dossier personnel, tous les
   périphériques, ou qui peuvent parler au service Flatpak (sortie du bac à sable).
5. Paquets de développement malveillants : paquets pip et npm installés hors du système comparés aux fiches « MAL- »
   d'OSV (paquets publiés pour voler des données ou ouvrir une porte dérobée).
(c) 2026 Dukiwi SA - Estavayer-le-Lac
"""

import glob
import ipaddress
import json
import os
import pwd
import re
import shutil
import subprocess
import time
from datetime import datetime

# Programmes qui lisent normalement les claviers : serveur graphique, compositeurs, gestion des sessions et de
# l'alimentation, outils de remappage et de gestes, manettes de jeu
INPUT_READERS = {"Xorg", "Xwayland", "X", "gnome-shell", "mutter", "kwin_wayland", "kwin_wayland_wr", "sway", "Hyprland",
                 "weston", "labwc", "wayfire", "river", "niri", "cosmic-comp", "muffin", "cinnamon", "systemd-logind",
                 "gdm-wayland-ses", "gdm-x-session", "sddm-greeter", "lightdm", "gsd-media-keys", "gsd-power", "acpid",
                 "upowerd", "thermald", "input-remapper", "input-remapper-service", "keyd", "kanata", "kmonad", "xremap",
                 "interception", "udevmon", "evsieve", "touchegg", "fusuma", "libinput-gestures", "solaar", "steam",
                 "antimicrox", "gpm", "ydotoold", "evtest", "libinput", "triggerhappy", "thd", "inputplumber", "handygccs",
                 "iio-sensor-pro", "plasmashell", "kded6", "kded5", "maliit-server", "ibus-daemon", "fcitx5", "orca"}
KEYLOGGER_CMD_RE = re.compile(r"\b(logkeys|lkl|pykeylogger|xkeylogger|keylogger|xspy|keysniffer)\b|xinput\s+(--)?test(-xi2)?\b", re.I)
SYSTEM_EXE_PREFIXES = ("/usr/", "/bin/", "/sbin/", "/lib/", "/lib64/", "/snap/", "/app/", "/var/lib/flatpak/", "/opt/")
NIGHT_HOURS = range(1, 5)                 # 01:00–04:59 heure locale
LOGIN_RE = re.compile(r"Accepted (\w+) for (\S+) from (\S+) port \d+")
SESSION_RE = re.compile(r"pam_unix\((\S+?):session\): session opened for user (\S+?)(?:\(uid=\d+\))?\b")
FLATPAK_RISKY_FS = {"host", "host-os", "host-etc", "home", "~"}


def run(cmd, timeout=60, env=None):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env)
    except (OSError, subprocess.SubprocessError) as e:
        return subprocess.CompletedProcess(cmd, 1, "", str(e))


def is_public(ip):
    try:
        a = ipaddress.ip_address(ip.split("%")[0])
    except ValueError:
        return False
    return a.is_global and not a.is_multicast


# ═══ 1. Espions du clavier ════════════════════════════════════════════════
def keyboard_devices():
    """{"/dev/input/eventN": nom} des périphériques que udev déclare claviers."""
    out = {}
    for ev in glob.glob("/sys/class/input/event*"):
        name = os.path.basename(ev)
        try:
            with open(os.path.join(ev, "dev")) as f:
                major, minor = f.read().strip().split(":")
            with open(f"/run/udev/data/c{major}:{minor}") as f:
                props = f.read()
        except (OSError, ValueError):
            continue
        if "E:ID_INPUT_KEYBOARD=1" in props:
            try:
                with open(os.path.join(ev, "device", "name")) as f:
                    label = f.read().strip()
            except OSError:
                label = name
            out[f"/dev/input/{name}"] = label
    return out


def keyboard_readers(self_pid=None):
    """[{pid, comm, exe, cmdline, uid, device, reason}] des programmes qui ont un clavier ouvert, ou qui ressemblent à un
    enregistreur de frappes X11, sans être un lecteur légitime connu."""
    kbds = keyboard_devices()
    out = []
    for entry in os.listdir("/proc"):
        if not entry.isdigit() or int(entry) in (1, self_pid or os.getpid()):
            continue
        pid = int(entry)
        try:
            with open(f"/proc/{pid}/comm") as f:
                comm = f.read().strip()
            with open(f"/proc/{pid}/cmdline", "rb") as f:
                cmdline = f.read().replace(b"\0", b" ").decode(errors="replace").strip()[:300]
        except OSError:
            continue
        try:
            exe = os.readlink(f"/proc/{pid}/exe")
        except OSError:
            exe = ""
        device = ""
        if kbds:
            try:
                for fd in os.listdir(f"/proc/{pid}/fd"):
                    try:
                        target = os.readlink(f"/proc/{pid}/fd/{fd}")
                    except OSError:
                        continue
                    if target in kbds:
                        device = target
                        break
            except OSError:
                pass
        x11 = bool(KEYLOGGER_CMD_RE.search(cmdline))
        if not device and not x11:
            continue
        clean = exe.replace(" (deleted)", "")
        trusted_place = clean.startswith(SYSTEM_EXE_PREFIXES) and not exe.endswith(" (deleted)")
        if device and comm in INPUT_READERS and trusted_place:
            continue
        try:
            uid = os.stat(f"/proc/{pid}").st_uid
        except OSError:
            uid = -1
        reason = "x11_logger" if x11 else ("untrusted_reader" if not trusted_place else "unknown_reader")
        out.append({"pid": pid, "comm": comm, "exe": exe, "cmdline": cmdline, "uid": uid, "device": device,
                    "device_name": kbds.get(device, ""), "reason": reason})
    return out


# ═══ 2. Connexions inhabituelles ══════════════════════════════════════════
def journal_logins(since=None, cursor=None):
    """([événements], curseur) : connexions SSH acceptées et ouvertures de session locales depuis `cursor` (ou `since`)."""
    if not shutil.which("journalctl"):
        return [], cursor
    cmd = ["journalctl", "-o", "json", "--no-pager", "-q"]
    if cursor:
        cmd += ["--after-cursor", cursor]
    else:
        cmd += ["--since", since or "-30d"]
    cmd += ["SYSLOG_IDENTIFIER=sshd", "+", "SYSLOG_IDENTIFIER=sshd-session", "+", "SYSLOG_IDENTIFIER=login", "+",
            "SYSLOG_IDENTIFIER=gdm-password]", "+", "SYSLOG_IDENTIFIER=gdm-autologin]", "+", "SYSLOG_IDENTIFIER=lightdm", "+", "SYSLOG_IDENTIFIER=sddm-helper"]
    r = run(cmd, timeout=120)
    events, last = [], cursor
    for ln in (r.stdout or "").splitlines():
        try:
            e = json.loads(ln)
        except ValueError:
            continue
        last = e.get("__CURSOR") or last
        msg = e.get("MESSAGE") or ""
        if isinstance(msg, list):
            msg = bytes(msg).decode(errors="replace")
        ts = int(e.get("__REALTIME_TIMESTAMP") or 0) / 1e6
        m = LOGIN_RE.search(msg)
        if m:
            events.append({"t": ts, "kind": "ssh", "method": m.group(1), "user": m.group(2), "ip": m.group(3)})
            continue
        m = SESSION_RE.search(msg)
        if m and m.group(1) not in ("sshd", "sudo", "su", "cron", "systemd-user", "polkit-1", "runuser", "pkexec"):
            events.append({"t": ts, "kind": "local", "service": m.group(1), "user": m.group(2), "ip": ""})
    return events, last


def journal_cursor():
    """Curseur de la dernière entrée du journal (point de départ de la veille des connexions)."""
    r = run(["journalctl", "-n", "1", "-o", "json", "--no-pager", "-q"], timeout=30)
    try:
        return json.loads((r.stdout or "").strip().splitlines()[-1]).get("__CURSOR")
    except (ValueError, IndexError):
        return None


# ═══ 3. Conteneurs ════════════════════════════════════════════════════════
def container_audit(users):
    """{available, issues:[{key, level, detail}]} pour Docker, Podman (root) et LXD."""
    issues = []
    docker = shutil.which("docker")
    sock = "/var/run/docker.sock"
    if os.path.exists(sock):
        mode = os.stat(sock).st_mode
        if mode & 0o002:
            issues.append({"key": "docker_sock_world", "level": "fail", "detail": sock})
    r = run(["ss", "-Htlnp"], timeout=10)
    for ln in (r.stdout or "").splitlines():
        if "dockerd" in ln or "containerd" in ln:
            m = re.search(r"\s(\S+):(2375|2376)\s", ln)
            if m and not m.group(1).startswith(("127.", "[::1]")):
                issues.append({"key": "docker_tcp" if m.group(2) == "2375" else "docker_tls", "level": "fail" if m.group(2) == "2375" else "warn",
                               "detail": f"{m.group(1)}:{m.group(2)}"})
    names = {pw.pw_name for pw in users if pw.pw_uid >= 1000}
    for group in ("docker", "lxd"):
        try:
            import grp
            members = sorted(set(grp.getgrnam(group).gr_mem) & names)
        except KeyError:
            members = []
        if members:
            issues.append({"key": f"{group}_group", "level": "warn", "detail": ", ".join(members)})
    for tool in ("docker", "podman"):
        if not shutil.which(tool):
            continue
        r = run([tool, "ps", "-q"], timeout=20)
        ids = (r.stdout or "").split()[:50]
        if not ids:
            continue
        r = run([tool, "inspect", "--format", "{{.Name}}\t{{.HostConfig.Privileged}}\t{{.HostConfig.NetworkMode}}\t{{range .Mounts}}{{.Source}},{{end}}"] + ids, timeout=30)
        for ln in (r.stdout or "").splitlines():
            parts = ln.split("\t")
            if len(parts) < 4:
                continue
            name, priv, net, mounts = parts[0].lstrip("/"), parts[1] == "true", parts[2], [m for m in parts[3].split(",") if m]
            if priv:
                issues.append({"key": "privileged", "level": "warn", "detail": f"{tool}:{name}"})
            if "/" in mounts or any(m.endswith("docker.sock") for m in mounts):
                issues.append({"key": "host_mount", "level": "warn", "detail": f"{tool}:{name}"})
            if net == "host":
                issues.append({"key": "host_network", "level": "info", "detail": f"{tool}:{name}"})
    return {"available": bool(docker or shutil.which("podman") or shutil.which("lxc")), "issues": issues}


# ═══ 4. Permissions Flatpak ═══════════════════════════════════════════════
def flatpak_apps(users):
    """[{app, user, installation}] des applications Flatpak (installation système + installation de chaque utilisateur)."""
    if not shutil.which("flatpak"):
        return []
    apps = []
    r = run(["flatpak", "list", "--app", "--system", "--columns=application"], timeout=60)
    apps += [{"app": a.strip(), "user": "", "installation": "system"} for a in (r.stdout or "").splitlines() if a.strip()]
    for pw in users:
        if pw.pw_uid < 1000 or not os.path.isdir(os.path.join(pw.pw_dir, ".local/share/flatpak/app")):
            continue
        for a in sorted(os.listdir(os.path.join(pw.pw_dir, ".local/share/flatpak/app"))):
            apps.append({"app": a, "user": pw.pw_name, "installation": "user", "home": pw.pw_dir})
    return apps


def parse_flatpak_permissions(text):
    """Permissions sensibles d'un bloc « flatpak info --show-permissions » (ou d'un fichier metadata / override)."""
    risks = set()
    section = ""
    for ln in text.splitlines():
        ln = ln.strip()
        if ln.startswith("["):
            section = ln
            continue
        if "=" not in ln:
            continue
        key, val = ln.split("=", 1)
        items = [x for x in val.split(";") if x]
        if section == "[Context]":
            if key == "filesystems":
                for x in items:
                    base = x.split(":")[0]
                    if base.startswith("!"):
                        continue
                    if base in ("host", "host-os", "host-etc"):
                        risks.add("fs_host")
                    elif base in ("home", "~"):
                        risks.add("fs_home")
            elif key == "devices" and "all" in items:
                risks.add("devices_all")
            elif key == "sockets" and "system-bus" in items:
                risks.add("system_bus")
        elif section == "[Session Bus Policy]" and key in ("org.freedesktop.Flatpak", "org.freedesktop.Flatpak.*") and val in ("talk", "own"):
            risks.add("sandbox_escape")
    return sorted(risks)


def flatpak_audit(users):
    out = []
    for a in flatpak_apps(users):
        if a["installation"] == "system":
            text = run(["flatpak", "info", "--system", "--show-permissions", a["app"]], timeout=30).stdout or ""
        else:
            meta = glob.glob(os.path.join(a["home"], ".local/share/flatpak/app", a["app"], "current/active/metadata"))
            text = open(meta[0], errors="replace").read() if meta else ""
            override = os.path.join(a["home"], ".local/share/flatpak/overrides", a["app"])
            if os.path.isfile(override):
                text += "\n" + open(override, errors="replace").read()
        for path in (f"/var/lib/flatpak/overrides/{a['app']}",):
            if os.path.isfile(path):
                text += "\n" + open(path, errors="replace").read()
        risks = parse_flatpak_permissions(text)
        if risks:
            out.append({"app": a["app"], "user": a["user"], "installation": a["installation"], "risks": risks})
    return out


# ═══ 5. Paquets de développement (pip, npm) ═══════════════════════════════
def pip_packages(users):
    """{nom: {version, where}} des paquets Python installés hors des paquets du système (pip --user, /usr/local, pipx)."""
    out = {}
    dirs = glob.glob("/usr/local/lib/python3*/dist-packages") + glob.glob("/usr/local/lib/python3*/site-packages")
    for pw in users:
        if pw.pw_uid < 1000:
            continue
        dirs += glob.glob(os.path.join(pw.pw_dir, ".local/lib/python3*/site-packages"))
        dirs += glob.glob(os.path.join(pw.pw_dir, ".local/share/pipx/venvs/*/lib/python3*/site-packages"))
        dirs += glob.glob(os.path.join(pw.pw_dir, ".local/pipx/venvs/*/lib/python3*/site-packages"))
    for d in dirs:
        for meta in glob.glob(os.path.join(d, "*.dist-info", "METADATA")):
            name = version = ""
            try:
                with open(meta, errors="replace") as f:
                    for ln in f:
                        if ln.startswith("Name:"):
                            name = ln.split(":", 1)[1].strip()
                        elif ln.startswith("Version:"):
                            version = ln.split(":", 1)[1].strip()
                        if (name and version) or not ln.strip():
                            break
            except OSError:
                continue
            if name and version:
                out.setdefault(name.lower(), {"name": name, "version": version, "where": d})
    return out


def npm_packages(users):
    """{nom: {version, where}} des paquets npm installés globalement (système, ~/.npm-global, nvm)."""
    out = {}
    dirs = ["/usr/lib/node_modules", "/usr/local/lib/node_modules"]
    for pw in users:
        if pw.pw_uid < 1000:
            continue
        dirs += [os.path.join(pw.pw_dir, ".npm-global/lib/node_modules"), os.path.join(pw.pw_dir, ".local/lib/node_modules")]
        dirs += glob.glob(os.path.join(pw.pw_dir, ".nvm/versions/node/*/lib/node_modules"))
    for d in dirs:
        if not os.path.isdir(d):
            continue
        for pkg in glob.glob(os.path.join(d, "*/package.json")) + glob.glob(os.path.join(d, "@*/*/package.json")):
            try:
                with open(pkg, errors="replace") as f:
                    meta = json.load(f)
            except (OSError, ValueError):
                continue
            name, version = meta.get("name"), meta.get("version")
            if isinstance(name, str) and isinstance(version, str):
                out.setdefault(name, {"name": name, "version": version, "where": os.path.dirname(pkg)})
    return out


_ADVISORY_CACHE = {}
MALWARE_RE = re.compile(r"malicious (package|code|version)|embedded malicious|malware|considered malicious|backdoor|credential[- ]steal", re.I)


def is_malware_advisory(vuln_id):
    """Fiche OSV qui décrit un paquet malveillant (et non une simple faille) : MAL-, CWE-506 ou résumé explicite."""
    if vuln_id in _ADVISORY_CACHE:
        return _ADVISORY_CACHE[vuln_id]
    import urllib.request
    verdict = False
    try:
        with urllib.request.urlopen(f"https://api.osv.dev/v1/vulns/{vuln_id}", timeout=20) as r:
            d = json.loads(r.read(1 << 20).decode())
        cwes = (d.get("database_specific") or {}).get("cwe_ids") or []
        verdict = "CWE-506" in cwes or bool(MALWARE_RE.search((d.get("summary") or "") + " " + (d.get("details") or "")[:600]))
    except (OSError, ValueError):
        return False                                   # réessayé au prochain relevé
    _ADVISORY_CACHE[vuln_id] = verdict
    return verdict


def malicious_packages(users, osv_query):
    """Paquets pip/npm qui ont une fiche OSV « MAL- » (paquet malveillant). `osv_query(sources, écosystème)` vient du service."""
    found = []
    counts = {}
    for eco, pkgs in (("PyPI", pip_packages(users)), ("npm", npm_packages(users))):
        counts[eco] = len(pkgs)
        if not pkgs:
            continue
        sources = {p["name"]: {"version": p["version"]} for p in pkgs.values()}
        for name, ids in osv_query(sources, eco).items():
            mal = [i for i in ids if i.startswith("MAL-") or is_malware_advisory(i)]
            if mal:
                p = next(v for v in pkgs.values() if v["name"] == name)
                found.append({"ecosystem": eco, "name": name, "version": p["version"], "where": p["where"], "ids": mal[:5]})
    return {"checked_at": datetime.now().isoformat(timespec="seconds"), "counts": counts, "malicious": found}


# ═══ 6. Extensions des éditeurs de code ═══════════════════════════════════
EDITOR_DIRS = (("vscode", ".vscode/extensions"), ("vscodium", ".vscode-oss/extensions"), ("cursor", ".cursor/extensions"),
               ("windsurf", ".windsurf/extensions"), ("vscode-server", ".vscode-server/extensions"),
               ("vscodium", ".var/app/com.vscodium.codium/data/codium/extensions"))


def editor_extensions(user, home):
    """Extensions VS Code, VSCodium, Cursor, Windsurf : [{browser, user, profile, id, name, version, from_store, enabled,
    perms, key}] au même format que les extensions des navigateurs (veille et alertes communes)."""
    out = []
    for editor, sub in EDITOR_DIRS:
        base = os.path.join(home, sub)
        if not os.path.isdir(base):
            continue
        sources = {}
        try:
            with open(os.path.join(base, "extensions.json"), errors="replace") as f:
                for e in json.load(f):
                    ident = ((e.get("identifier") or {}).get("id") or "").lower()
                    sources[ident] = (e.get("metadata") or {}).get("source") or ""
        except (OSError, ValueError, AttributeError):
            pass
        for d in sorted(os.listdir(base)):
            pkg = os.path.join(base, d, "package.json")
            if not os.path.isfile(pkg):
                continue
            try:
                with open(pkg, errors="replace") as f:
                    meta = json.load(f)
            except (OSError, ValueError):
                continue
            ident = f"{meta.get('publisher', '')}.{meta.get('name', '')}".lower()
            events = meta.get("activationEvents") or []
            perms = []
            if "*" in events or "onStartupFinished" in events:
                perms.append("startup")
            if sources.get(ident) == "vsix":
                perms.append("sideloaded")
            name = meta.get("displayName") or meta.get("name") or d
            if isinstance(name, str) and name.startswith("%"):
                name = meta.get("name") or d
            entry = {"browser": editor, "user": user, "profile": "", "id": ident, "name": str(name)[:80],
                     "version": str(meta.get("version", "")), "from_store": sources.get(ident) != "vsix",
                     "enabled": True, "perms": perms, "key": f"{editor}:{user}:{ident}"}
            prev = next((x for x in out if x["key"] == entry["key"]), None)
            if prev is None:
                out.append(entry)
            elif _version_key(entry["version"]) > _version_key(prev["version"]):
                out[out.index(prev)] = entry           # anciennes versions laissées sur le disque par l'éditeur
    return out


def _version_key(v):
    return [(0, int(x), "") if x.isdigit() else (1, 0, x) for x in re.split(r"[.\-+]", str(v))]
