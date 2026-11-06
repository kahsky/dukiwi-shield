#!/usr/bin/env python3
"""
Dukiwi Shield — security hygiene (system service).

1. Password quality: pam_pwquality module active and minimum length (12 characters, dictionary words
   and user name rejected) for new passwords; single file 90-dukiwi-shield.conf.
2. Browser security settings: Firefox (protection against deceptive sites, HTTPS-only mode,
   signed extensions) and Chrome/Chromium/Brave (safe browsing). Fix: Firefox user.js for the
   user who asks for it, "recommended" policies (changeable by the user) for Chrome.
3. Internet exposure: the Dukiwi server tries to reach the public address (consent for each test);
   UPnP: does the router answer, and which ports has it opened on its own to this computer?
(c) 2026 Dukiwi SA - Estavayer-le-Lac
"""

import glob
import json
import os
import re
import shutil
import socket
import subprocess
import time
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET

from dukiwi_shield_common import open_user_file, run_as_user, write_file_atomic

PWQ_DROPIN = "/etc/security/pwquality.conf.d/90-dukiwi-shield.conf"
PWQ_MINLEN = 12
FIREFOX_MARK_BEGIN = "// ── Dukiwi Shield : réglages de sécurité (début) ──"
FIREFOX_MARK_END = "// ── Dukiwi Shield : réglages de sécurité (fin) ──"
FIREFOX_PREFS = {"browser.safebrowsing.malware.enabled": "true", "browser.safebrowsing.phishing.enabled": "true",
                 "browser.safebrowsing.downloads.enabled": "true", "dom.security.https_only_mode": "true",
                 "xpinstall.signatures.required": "true"}
CHROME_POLICY_DIRS = ("/etc/opt/chrome/policies/recommended", "/etc/chromium/policies/recommended",
                      "/etc/chromium-browser/policies/recommended", "/etc/brave/policies/recommended", "/etc/opt/edge/policies/recommended")
CHROME_POLICY_FILE = "dukiwi-shield-security.json"
CHROME_POLICY = {"SafeBrowsingProtectionLevel": 1}        # Chrome already switches to HTTPS on its own (HTTPS-Upgrades, v115+)
EXPOSURE_URL = "https://www.dukiwi.com/repo/api/exposure.php"


def run(cmd, timeout=60, env=None):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env)
    except (OSError, subprocess.SubprocessError) as e:
        return subprocess.CompletedProcess(cmd, 1, "", str(e))


def _read(path):
    try:
        with open_user_file(path) as f:
            return f.read()
    except OSError:
        return ""


# ═══ 1. Password quality ══════════════════════════════════════════════════
def password_policy():
    """{module, minlen, dictcheck, ok}: pam_pwquality (or pam_passwdqc) in the password PAM stack, and settings."""
    stack = "".join(_read(p) for p in ("/etc/pam.d/common-password", "/etc/pam.d/system-auth", "/etc/pam.d/password-auth",
                                       "/etc/pam.d/passwd"))
    active = [ln for ln in stack.splitlines() if not ln.strip().startswith("#")]
    module = "pwquality" if any("pam_pwquality" in ln for ln in active) else ("passwdqc" if any("pam_passwdqc" in ln for ln in active) else "")
    conf = {}
    for path in ["/etc/security/pwquality.conf"] + sorted(glob.glob("/etc/security/pwquality.conf.d/*.conf")):
        for ln in _read(path).splitlines():
            m = re.match(r"^\s*(\w+)\s*=\s*(\S+)", ln)
            if m:
                conf[m.group(1)] = m.group(2)
    for ln in active:                                   # options passed to the module in the PAM stack: take precedence
        if "pam_pwquality" in ln:
            conf.update(dict(re.findall(r"\b(minlen|dictcheck|usercheck)=(\S+)", ln)))
    try:
        minlen = int(conf.get("minlen", 8))
    except ValueError:
        minlen = 8
    dictcheck = conf.get("dictcheck", "1") != "0"
    return {"module": module, "minlen": minlen, "dictcheck": dictcheck, "dropin": os.path.exists(PWQ_DROPIN),
            "ok": module == "pwquality" and minlen >= PWQ_MINLEN and dictcheck, "installable": bool(shutil.which("apt-get") or shutil.which("dnf"))}


SHADOW_FILE = "/etc/shadow"


def passwords_older_than_policy():
    """Accounts (uid ≥ 1000, home under /home, with a password) whose password was last changed before Dukiwi Shield set
    the quality rules: their current password was never checked against them. [] when unknown (rules not set by
    Dukiwi Shield, /etc/shadow unreadable)."""
    import pwd
    try:
        since = int(os.stat(PWQ_DROPIN).st_mtime // 86400)          # /etc/shadow counts days since 1970-01-01
    except OSError:
        return []
    users = {pw.pw_name for pw in pwd.getpwall() if pw.pw_uid >= 1000 and pw.pw_dir.startswith("/home/")
             and not pw.pw_shell.endswith(("nologin", "false"))}
    try:
        lines = open(SHADOW_FILE, encoding="utf-8", errors="replace").read().splitlines()
    except OSError:
        return []
    out = []
    for ln in lines:
        f = ln.split(":")
        if len(f) < 3 or f[0] not in users or not f[1] or f[1][0] in "!*":
            continue
        try:
            if int(f[2]) < since:
                out.append(f[0])
        except ValueError:
            continue
    return sorted(out)


def _ancestor_types(dev):
    """Device types of `dev` and of everything below it (lsblk --inverse): contains "crypt" for LUKS / dm-crypt."""
    r = run(["lsblk", "-s", "-n", "-o", "TYPE", dev], timeout=10)
    return set((r.stdout or "").split()) if r.returncode == 0 else set()


def encryption_status():
    """What is encrypted on this computer: {"root", "home", "swap_clear": [swap areas written to disk in clear]}.
    Root: the file system of / sits on dm-crypt (LUKS, possibly under LVM). Home: eCryptfs, or /home on dm-crypt.
    Swap: a partition is fine on dm-crypt, a swap file only if its file system is; zram stays in memory."""
    src = (run(["findmnt", "-no", "SOURCE", "/"], timeout=10).stdout or "").strip()
    root = bool(src.startswith("/dev/")) and "crypt" in _ancestor_types(src)
    home_src = (run(["findmnt", "-no", "SOURCE", "--target", "/home"], timeout=10).stdout or "").strip()
    home = root or (home_src.startswith("/dev/") and "crypt" in _ancestor_types(home_src)) \
        or (os.path.isdir("/home/.ecryptfs") and any(os.scandir("/home/.ecryptfs")))
    swap_clear = []
    for ln in _read("/proc/swaps").splitlines()[1:]:
        parts = ln.split()
        if len(parts) < 2 or parts[0].startswith("/dev/zram"):
            continue
        if parts[1] == "partition":
            enc = "crypt" in _ancestor_types(parts[0])
        else:
            fs = (run(["findmnt", "-no", "SOURCE", "--target", parts[0]], timeout=10).stdout or "").strip()
            enc = fs.startswith("/dev/") and "crypt" in _ancestor_types(fs)
        if not enc:
            swap_clear.append(parts[0])
    return {"root": root, "home": bool(home), "swap_clear": swap_clear}


def password_policy_apply():
    """Installs the module if needed (Debian/Ubuntu/Mint: libpam-pwquality adds it to common-password) then writes the
    settings. Never touches the PAM files themselves. Returns (ok, error)."""
    if not password_policy()["module"]:
        if shutil.which("apt-get"):
            r = run(["apt-get", "install", "-y", "libpam-pwquality"], timeout=600,
                    env=dict(os.environ, DEBIAN_FRONTEND="noninteractive"))
        elif shutil.which("dnf"):
            r = run(["dnf", "install", "-y", "libpwquality"], timeout=600)
        else:
            return False, "no_package_manager"
        if r.returncode != 0:
            return False, "install_failed"
    os.makedirs(os.path.dirname(PWQ_DROPIN), exist_ok=True)
    with open(PWQ_DROPIN, "w") as f:
        f.write("# Dukiwi Shield — qualité des nouveaux mots de passe (la longueur compte plus que les symboles).\n"
                f"minlen = {PWQ_MINLEN}\ndictcheck = 1\nusercheck = 1\nmaxrepeat = 3\nenforcing = 1\n")
    os.chmod(PWQ_DROPIN, 0o644)
    pol = password_policy()
    return pol["ok"], "" if pol["ok"] else "policy_not_active"


# ═══ 2. Browser security settings ═════════════════════════════════════════
def firefox_profiles(home):
    out = []
    for pattern in (".mozilla/firefox/*", "snap/firefox/common/.mozilla/firefox/*", ".var/app/org.mozilla.firefox/.mozilla/firefox/*"):
        for d in glob.glob(os.path.join(home, pattern)):
            if os.path.isfile(os.path.join(d, "prefs.js")):
                out.append(d)
    return out


def firefox_issues(profile):
    prefs = {}
    for name in ("prefs.js", "user.js"):                # user.js wins at startup
        for k, v in re.findall(r'user_pref\("([^"]+)",\s*([^)]+)\);', _read(os.path.join(profile, name))):
            prefs[k] = v.strip()
    issues = []
    if prefs.get("browser.safebrowsing.malware.enabled") == "false" or prefs.get("browser.safebrowsing.phishing.enabled") == "false":
        issues.append("safebrowsing_off")
    if prefs.get("browser.safebrowsing.downloads.enabled") == "false":
        issues.append("download_check_off")
    if prefs.get("dom.security.https_only_mode") != "true":
        issues.append("https_only_off")
    if prefs.get("xpinstall.signatures.required") == "false":
        issues.append("unsigned_addons")
    return issues


def chrome_profiles(home):
    out = []
    for browser, sub in (("chrome", ".config/google-chrome"), ("chromium", ".config/chromium"), ("chromium", "snap/chromium/common/chromium"),
                         ("brave", ".config/BraveSoftware/Brave-Browser"), ("edge", ".config/microsoft-edge")):
        for prof in glob.glob(os.path.join(home, sub, "Default")) + glob.glob(os.path.join(home, sub, "Profile *")):
            if os.path.isfile(os.path.join(prof, "Preferences")):
                out.append((browser, prof))
    return out


def chrome_policy_applied(browser):
    d = {"chrome": CHROME_POLICY_DIRS[0], "brave": CHROME_POLICY_DIRS[3], "edge": CHROME_POLICY_DIRS[4]}.get(browser)
    dirs = [d] if d else list(CHROME_POLICY_DIRS[1:3])
    return any(os.path.exists(os.path.join(x, CHROME_POLICY_FILE)) for x in dirs)


def chrome_issues(browser, profile):
    try:
        with open(os.path.join(profile, "Preferences"), errors="replace") as f:
            prefs = json.load(f)
    except (OSError, ValueError):
        return []
    sb = prefs.get("safebrowsing") or {}
    issues = []
    if sb.get("enabled") is False and not chrome_policy_applied(browser):
        issues.append("safebrowsing_off")
    return issues


def browser_security(users):
    """[{browser, user, profile, issues}] for each profile found."""
    out = []
    for pw in users:
        if pw.pw_uid < 1000:
            continue
        for prof in firefox_profiles(pw.pw_dir):
            out.append({"browser": "firefox", "user": pw.pw_name, "profile": os.path.basename(prof), "path": prof, "issues": firefox_issues(prof)})
        for browser, prof in chrome_profiles(pw.pw_dir):
            out.append({"browser": browser, "user": pw.pw_name, "profile": os.path.basename(prof), "path": prof, "issues": chrome_issues(browser, prof)})
    return out


def firefox_user_js(profile, harden):
    """Adds (harden) or removes the Dukiwi block of <profile>/user.js. Runs as the profile owner (see firefox_harden)."""
    path = os.path.join(profile, "user.js")
    if os.path.islink(path):
        raise OSError("user.js is a symbolic link")
    text = _read(path)
    new = re.sub(re.escape(FIREFOX_MARK_BEGIN) + r".*?" + re.escape(FIREFOX_MARK_END) + r"\n?", "", text, flags=re.S)
    if harden:
        block = FIREFOX_MARK_BEGIN + "\n" + "".join(f'user_pref("{k}", {v});\n' for k, v in FIREFOX_PREFS.items()) + FIREFOX_MARK_END + "\n"
        new = new.rstrip("\n") + ("\n" if new.strip() else "") + block
    if new != text:
        write_file_atomic(path, new, 0o644)
    return True


def firefox_harden(profile, pw):
    """Block of settings added (or replaced) in user.js, the user's file; Firefox reads it at startup. The file is
    in the user's home folder, so the work is done with the user's rights, never root's."""
    return run_as_user(pw.pw_uid, pw.pw_gid, "dukiwi_shield_hygiene", "firefox_user_js", profile, True)


def firefox_unharden(profile, pw):
    return run_as_user(pw.pw_uid, pw.pw_gid, "dukiwi_shield_hygiene", "firefox_user_js", profile, False)


def chrome_harden(browsers):
    done = []
    for browser in sorted(set(browsers)):
        dirs = {"chrome": [CHROME_POLICY_DIRS[0]], "brave": [CHROME_POLICY_DIRS[3]], "edge": [CHROME_POLICY_DIRS[4]],
                "chromium": list(CHROME_POLICY_DIRS[1:3])}.get(browser, [])
        for d in dirs:
            if browser == "chromium" and not os.path.isdir(os.path.dirname(os.path.dirname(d))):
                continue
            os.makedirs(d, exist_ok=True)
            with open(os.path.join(d, CHROME_POLICY_FILE), "w") as f:
                json.dump(CHROME_POLICY, f, indent=2)
            os.chmod(os.path.join(d, CHROME_POLICY_FILE), 0o644)
            done.append(d)
    return done


# ═══ 3. Internet exposure and UPnP ════════════════════════════════════════
def exposure_test(ports, timeout=40):
    """Asks the Dukiwi server to test this computer's public address. Returns the JSON of the response."""
    body = json.dumps({"consent": True, "ports": sorted({int(p) for p in ports if 0 < int(p) < 65536})[:30]}).encode()
    req = urllib.request.Request(EXPOSURE_URL, data=body, headers={"Content-Type": "application/json", "User-Agent": "dukiwi-shield"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read(65536).decode())
    except urllib.error.HTTPError as e:
        try:
            return json.loads(e.read(4096).decode())
        except ValueError:
            return {"ok": False, "error": f"http_{e.code}"}
    except (OSError, ValueError) as e:
        return {"ok": False, "error": "unreachable", "detail": str(e)[:120]}


def _local_ips():
    ips = set()
    r = run(["ip", "-o", "addr", "show"], timeout=10)
    for m in re.finditer(r"\binet6?\s+([0-9a-fA-F.:]+)/", r.stdout or ""):
        ips.add(m.group(1))
    return ips


def upnp_discover(timeout=3.0):
    """UPnP router (InternetGatewayDevice) of the network: description address, or None."""
    msg = ("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\n"
           "ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\r\n").encode()
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    s.settimeout(timeout)
    try:
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        s.sendto(msg, ("239.255.255.250", 1900))
        end = time.time() + timeout
        while time.time() < end:
            try:
                data, _addr = s.recvfrom(4096)
            except socket.timeout:
                break
            m = re.search(rb"^location:\s*(\S+)", data, re.I | re.M)
            if m:
                return m.group(1).decode(errors="replace")
    except OSError:
        return None
    finally:
        s.close()
    return None


# Most common description addresses (FRITZ!Box, miniupnpd from OpenWrt and many routers, Broadcom…):
# tried over TCP to the gateway when the SSDP reply does not arrive (the local firewall often rejects it, because it
# comes from the router's address and not from the queried multicast address).
IGD_CANDIDATES = ((49000, "/igddesc.xml"), (5000, "/rootDesc.xml"), (1900, "/rootDesc.xml"), (49152, "/rootDesc.xml"),
                  (2189, "/rootDesc.xml"), (1780, "/InternetGatewayDevice.xml"), (52869, "/picsdesc.xml"), (80, "/rootDesc.xml"))


def default_gateway():
    m = re.search(r"default via (\d+\.\d+\.\d+\.\d+)", run(["ip", "-4", "route", "show", "default"], timeout=10).stdout or "")
    return m.group(1) if m else ""


def upnp_probe_gateway():
    gw = default_gateway()
    if not gw:
        return None
    for port, path in IGD_CANDIDATES:
        url = f"http://{gw}:{port}{path}"
        try:
            with urllib.request.urlopen(url, timeout=1.5) as r:
                if b"InternetGatewayDevice" in r.read(65536):
                    return url
        except (OSError, ValueError):
            continue
    return None


def _soap(control, service, action, args=""):
    body = (f'<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
            f's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body><u:{action} xmlns:u="{service}">{args}'
            f'</u:{action}></s:Body></s:Envelope>').encode()
    req = urllib.request.Request(control, data=body, headers={"Content-Type": 'text/xml; charset="utf-8"', "SOAPAction": f'"{service}#{action}"'})
    with urllib.request.urlopen(req, timeout=5) as r:
        return r.read(65536)


def upnp_mappings(max_entries=64):
    """{router, mappings:[{external, protocol, client, internal, description, enabled, this_host}]} ou {router: None}."""
    location = upnp_discover() or upnp_probe_gateway()
    if not location:
        return {"router": None, "mappings": [], "checked_at": time.strftime("%Y-%m-%dT%H:%M:%S")}
    out = {"router": urllib.parse.urlparse(location).hostname, "mappings": [], "error": "", "checked_at": time.strftime("%Y-%m-%dT%H:%M:%S")}
    try:
        with urllib.request.urlopen(location, timeout=5) as r:
            desc = r.read(262144)
        root = ET.fromstring(desc)
        ns = {"d": "urn:schemas-upnp-org:device-1-0"}
        out["model"] = " ".join(x for x in ((root.findtext(".//d:manufacturer", "", ns) or "").strip(),
                                            (root.findtext(".//d:modelName", "", ns) or "").strip()) if x)
        control = service = None
        for svc in root.iter("{urn:schemas-upnp-org:device-1-0}service"):
            st = svc.findtext("d:serviceType", "", ns)
            if "WANIPConnection" in st or "WANPPPConnection" in st:
                control = urllib.parse.urljoin(location, svc.findtext("d:controlURL", "", ns))
                service = st
                break
        if not control:
            out["error"] = "no_wan_service"
            return out
        mine = _local_ips()
        for i in range(max_entries):
            try:
                xml = _soap(control, service, "GetGenericPortMappingEntry", f"<NewPortMappingIndex>{i}</NewPortMappingIndex>")
            except (OSError, urllib.error.HTTPError):
                break                                   # end of the list (SpecifiedArrayIndexInvalid) or refusal
            vals = {el.tag.split("}")[-1]: (el.text or "") for el in ET.fromstring(xml).iter()}
            client = vals.get("NewInternalClient", "")
            out["mappings"].append({"external": vals.get("NewExternalPort", ""), "protocol": vals.get("NewProtocol", ""),
                                    "client": client, "internal": vals.get("NewInternalPort", ""),
                                    "description": vals.get("NewPortMappingDescription", "")[:80],
                                    "enabled": vals.get("NewEnabled", "1") == "1", "this_host": client in mine})
    except (OSError, ET.ParseError, ValueError) as e:
        out["error"] = str(e)[:120]
    return out
