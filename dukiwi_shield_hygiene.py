#!/usr/bin/env python3
"""
Dukiwi Shield — hygiène de sécurité (service système).

1. Qualité des mots de passe : module pam_pwquality actif et longueur minimale (12 caractères, mots du dictionnaire
   et nom d'utilisateur refusés) pour les nouveaux mots de passe ; fichier unique 90-dukiwi-shield.conf.
2. Réglages de sécurité des navigateurs : Firefox (protection contre les sites trompeurs, mode HTTPS uniquement,
   extensions signées) et Chrome/Chromium/Brave (navigation sécurisée). Correction : user.js de Firefox pour
   l'utilisateur qui le demande, règles « recommandées » (modifiables par l'utilisateur) pour Chrome.
3. Exposition sur Internet : le serveur Dukiwi essaie de joindre l'adresse publique (consentement à chaque test) ;
   UPnP : le routeur répond-il, et quels ports a-t-il ouverts tout seul vers cet ordinateur ?
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
CHROME_POLICY = {"SafeBrowsingProtectionLevel": 1}        # Chrome passe déjà en HTTPS tout seul (HTTPS-Upgrades, v115+)
EXPOSURE_URL = "https://www.dukiwi.com/repo/api/exposure.php"


def run(cmd, timeout=60, env=None):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env)
    except (OSError, subprocess.SubprocessError) as e:
        return subprocess.CompletedProcess(cmd, 1, "", str(e))


def _read(path):
    try:
        with open(path, errors="replace") as f:
            return f.read()
    except OSError:
        return ""


# ═══ 1. Qualité des mots de passe ═════════════════════════════════════════
def password_policy():
    """{module, minlen, dictcheck, ok} : pam_pwquality (ou pam_passwdqc) dans la pile PAM des mots de passe, et réglages."""
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
    for ln in active:                                   # options passées au module dans la pile PAM : prioritaires
        if "pam_pwquality" in ln:
            conf.update(dict(re.findall(r"\b(minlen|dictcheck|usercheck)=(\S+)", ln)))
    try:
        minlen = int(conf.get("minlen", 8))
    except ValueError:
        minlen = 8
    dictcheck = conf.get("dictcheck", "1") != "0"
    return {"module": module, "minlen": minlen, "dictcheck": dictcheck, "dropin": os.path.exists(PWQ_DROPIN),
            "ok": module == "pwquality" and minlen >= PWQ_MINLEN and dictcheck, "installable": bool(shutil.which("apt-get") or shutil.which("dnf"))}


def password_policy_apply():
    """Installe le module si besoin (Debian/Ubuntu/Mint : libpam-pwquality l'ajoute à common-password) puis écrit les
    réglages. Ne touche jamais aux fichiers PAM eux-mêmes. Retourne (ok, erreur)."""
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


# ═══ 2. Réglages de sécurité des navigateurs ══════════════════════════════
def firefox_profiles(home):
    out = []
    for pattern in (".mozilla/firefox/*", "snap/firefox/common/.mozilla/firefox/*", ".var/app/org.mozilla.firefox/.mozilla/firefox/*"):
        for d in glob.glob(os.path.join(home, pattern)):
            if os.path.isfile(os.path.join(d, "prefs.js")):
                out.append(d)
    return out


def firefox_issues(profile):
    prefs = {}
    for name in ("prefs.js", "user.js"):                # user.js l'emporte au démarrage
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
    """[{browser, user, profile, issues}] pour chaque profil trouvé."""
    out = []
    for pw in users:
        if pw.pw_uid < 1000:
            continue
        for prof in firefox_profiles(pw.pw_dir):
            out.append({"browser": "firefox", "user": pw.pw_name, "profile": os.path.basename(prof), "path": prof, "issues": firefox_issues(prof)})
        for browser, prof in chrome_profiles(pw.pw_dir):
            out.append({"browser": browser, "user": pw.pw_name, "profile": os.path.basename(prof), "path": prof, "issues": chrome_issues(browser, prof)})
    return out


def firefox_harden(profile, pw):
    """Bloc de réglages ajouté (ou remplacé) dans user.js, fichier de l'utilisateur ; Firefox le lit au démarrage."""
    path = os.path.join(profile, "user.js")
    text = _read(path)
    text = re.sub(re.escape(FIREFOX_MARK_BEGIN) + r".*?" + re.escape(FIREFOX_MARK_END) + r"\n?", "", text, flags=re.S)
    block = FIREFOX_MARK_BEGIN + "\n" + "".join(f'user_pref("{k}", {v});\n' for k, v in FIREFOX_PREFS.items()) + FIREFOX_MARK_END + "\n"
    tmp = path + ".dukiwi-tmp"
    with open(tmp, "w") as f:
        f.write(text.rstrip("\n") + ("\n" if text.strip() else "") + block)
    os.chown(tmp, pw.pw_uid, pw.pw_gid)
    os.chmod(tmp, 0o644)
    os.replace(tmp, path)


def firefox_unharden(profile):
    path = os.path.join(profile, "user.js")
    text = _read(path)
    new = re.sub(re.escape(FIREFOX_MARK_BEGIN) + r".*?" + re.escape(FIREFOX_MARK_END) + r"\n?", "", text, flags=re.S)
    if new != text:
        with open(path, "w") as f:
            f.write(new)


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


# ═══ 3. Exposition sur Internet et UPnP ═══════════════════════════════════
def exposure_test(ports, timeout=40):
    """Demande au serveur Dukiwi de tester l'adresse publique de cet ordinateur. Retourne le JSON de la réponse."""
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
    """Routeur UPnP (InternetGatewayDevice) du réseau : adresse de description, ou None."""
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


# Adresses de description les plus courantes (FRITZ!Box, miniupnpd d'OpenWrt et de nombreux routeurs, Broadcom…) :
# essayées en TCP vers la passerelle quand la réponse SSDP n'arrive pas (le pare-feu local la rejette souvent, car elle
# vient de l'adresse du routeur et non de l'adresse multicast interrogée).
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
                break                                   # fin de la liste (SpecifiedArrayIndexInvalid) ou refus
            vals = {el.tag.split("}")[-1]: (el.text or "") for el in ET.fromstring(xml).iter()}
            client = vals.get("NewInternalClient", "")
            out["mappings"].append({"external": vals.get("NewExternalPort", ""), "protocol": vals.get("NewProtocol", ""),
                                    "client": client, "internal": vals.get("NewInternalPort", ""),
                                    "description": vals.get("NewPortMappingDescription", "")[:80],
                                    "enabled": vals.get("NewEnabled", "1") == "1", "this_host": client in mine})
    except (OSError, ET.ParseError, ValueError) as e:
        out["error"] = str(e)[:120]
    return out
