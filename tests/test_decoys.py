"""Ransomware decoys (dukiwi_shield_guard) on a fake home folder, with a simulated eCryptfs mount.

Covers 2.7.5: reproducible content of the zip decoys, no decoys for a test instance, fingerprints kept while the
encrypted home is unmounted, real tampering detected. The real decoys of the home folder are left untouched (checked at
the end).
"""
import collections
import glob
import hashlib
import io
import os
import pwd
import threading
import time
import zipfile

import _harness as h

R = h.Results("Decoys")
h.isolate("decoys")
gm = h.load("dukiwi_shield_guard.py", "dukiwi_shield_guard_under_test")

REAL = sorted(glob.glob(os.path.expanduser("~/.dukiwi-guard-*")) + glob.glob(os.path.expanduser("~/*/.dukiwi-guard-*")))
real_before = {p: os.lstat(p).st_ctime_ns for p in REAL}

sandbox = h.tmpdir("decoy-home")
home = os.path.join(sandbox, "home")
for sub in ("Documents", "Pictures", "Desktop"):
    os.makedirs(os.path.join(home, sub))
PW = collections.namedtuple("PW", "pw_name pw_uid pw_gid pw_dir")
pw = PW(pwd.getpwuid(os.getuid()).pw_name, os.getuid(), os.getgid(), home)
MOUNTED = {"v": True}
gm.home_mounted = lambda _pw: MOUNTED["v"]


def unmount():
    os.rename(home, home + ".mounted")
    os.mkdir(home)
    MOUNTED["v"] = False


def mount():
    os.rmdir(home)
    os.rename(home + ".mounted", home)
    MOUNTED["v"] = True


class Settings:
    def __init__(self):
        self.v = {}

    def get(self, k):
        return self.v.get(k, True)


class Daemon:
    def __init__(self, state):
        self.state, self.settings, self.shutdown, self.alerts, self.monitor = state, Settings(), threading.Event(), [], None

    def publish_alert(self, a):
        self.alerts.append(a)

    def user_trusted(self):
        return set()


def make(state, owner=True):
    d = Daemon(state)
    g = gm.SecurityGuard(d, {"log": lambda *_: None, "write_log": lambda *_: None, "exe_trusted": lambda *_: False,
                              "dconf_read": lambda *a, **k: "", "human_users": lambda: [pw]})
    if owner is not None:
        g.owns_decoys = owner
    return g, d


def paths():
    tag = gm.machine_tag()
    return {ext: os.path.join(home, sub, f"{gm.DECOY_PREFIX}{tag}.{ext}") for sub, ext in
            (("Documents", "docx"), ("Pictures", "jpg"), ("Desktop", "pdf"), ("", "xlsx"))}


def sha(p):
    with open(p, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def snapshot():
    return {ext: (os.lstat(p).st_ino, sha(p)) if os.path.lexists(p) else None for ext, p in paths().items()}


def reasons(d, since=0):
    return sorted((a["reasons"][0], os.path.splitext(a["path"])[1][1:]) for a in d.alerts[since:])


def login(g):
    mount()
    g.last_decoy_sync = 0
    g.check_decoys()


b1 = {e: gm.decoy_bytes(e, "seed-" + e) for e in ("docx", "xlsx", "jpg", "pdf")}
time.sleep(2.1)
b2 = {e: gm.decoy_bytes(e, "seed-" + e) for e in ("docx", "xlsx", "jpg", "pdf")}
zok = all(zipfile.ZipFile(io.BytesIO(b1[e])).testzip() is None for e in ("docx", "xlsx"))
R.check("same bytes when written 2 s apart, valid zip, magic bytes",
        b1 == b2 and zok and b1["jpg"][:2] == b"\xff\xd8" and b1["pdf"][:4] == b"%PDF"
        and gm.decoy_bytes("docx", "a") != gm.decoy_bytes("docx", "b"), {e: b1[e] == b2[e] for e in b1})

state = h.St()
g1, d1 = make(state)
g1.sync_decoys()
snap1 = snapshot()
unmount()
g2, d2 = make(state)
g2.sync_decoys()
kept = len(state.get("decoys") or {})
login(g2)
R.check("boot with unmounted home keeps fingerprints; login rewrites nothing, no alert",
        kept == 4 and snapshot() == snap1 and not d2.alerts and len(g2.decoys) == 4,
        {"kept": kept, "unchanged": snapshot() == snap1, "alerts": reasons(d2)})

with open(paths()["docx"], "wb") as f:
    f.write(b"encrypted-by-something" * 40)
unmount()
g3, d3 = make(state)
g3.sync_decoys()
login(g3)
R.check("decoy changed while the service was stopped is reported and restored",
        reasons(d3) == [("decoy_changed_offline", "docx")] and sha(paths()["docx"]) == state.get("decoys")[paths()["docx"]]["sha"],
        reasons(d3))

before = snapshot()
st4 = h.St()
g4, d4 = make(st4, owner=None)                  # test instance: ownership decided by system_instance()
g4.sync_decoys()
g4.check_decoys()
d4.settings.v["ransomware_decoys"] = False
g4.sync_decoys()
g4.check_decoys()
g4.remove_decoys()
R.check("non-root / test instance leaves decoys, state and alerts untouched",
        getattr(g4, "owns_decoys", None) is False and snapshot() == before and not st4.get("decoys") and not d4.alerts,
        {"owns_decoys": getattr(g4, "owns_decoys", "absent"), "unchanged": snapshot() == before})

n = len(d3.alerts)
time.sleep(2.1)
g5, _d5 = make(h.St())
g5.sync_decoys()
after5 = snapshot()
g3.check_decoys()
R.check("identical rewrite by another instance raises no alert and is not undone",
        reasons(d3, n) == [] and snapshot() == after5, {"alerts": reasons(d3, n)})

n = len(d3.alerts)
with open(paths()["xlsx"], "wb") as f:
    f.write(os.urandom(700))
os.unlink(paths()["pdf"])
g3.check_decoys()
R.check("real tampering still reported: xlsx replaced, pdf removed, both restored",
        reasons(d3, n) == [("decoy_removed", "pdf"), ("decoy_replaced", "xlsx")] and all(snapshot().values()), reasons(d3, n))

n = len(d3.alerts)
snap7 = snapshot()
unmount()
g3.check_decoys()
g3.last_decoy_sync = 0
g3.check_decoys()
kept7 = len(state.get("decoys") or {})
login(g3)
R.check("logout then login keeps fingerprints; nothing rewritten, no alert",
        kept7 == 4 and snapshot() == snap7 and reasons(d3, n) == [], {"kept": kept7, "alerts": reasons(d3, n)})

unmount()
d3.settings.v["ransomware_decoys"] = False
g3.sync_decoys()
kept8 = len(state.get("decoys") or {})
mount()
g3.sync_decoys()
R.check("protection switched off while home unmounted: decoys removed once mounted, state cleared",
        kept8 == 4 and not any(snapshot().values()) and not state.get("decoys"), {"kept": kept8})

R.check("real decoys in the home folder were not touched",
        {p: os.lstat(p).st_ctime_ns for p in REAL if os.path.lexists(p)} == real_before)
R.done()
