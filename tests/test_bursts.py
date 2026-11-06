"""File-write bursts (2.7.8): program identified early, action started by a package manager, an application's own
folder, learned habits, the "Learn from my choices" setting. ClamAV is replaced by a fake result."""
import os
import shutil
import subprocess
import time

import _harness as h

R = h.Results("File-write bursts")
d = h.daemon_module()
BIN = h.home_tmpdir("burst")
DOCS = os.path.expanduser("~/Documents/dukiwi-test-burst")      # paths only: nothing is written to Documents


class Settings:
    def __init__(self):
        self.v = {"burst_monitor": True, "burst_window_sec": 15, "burst_info_threshold": 50, "burst_danger_threshold": 25}

    def get(self, k):
        return self.v.get(k, d.DEFAULT_SETTINGS.get(k))


def make():
    dm = object.__new__(d.Daemon)
    dm.state, dm.settings, dm.central_patterns, dm._trusted_set = h.St(), Settings(), [], d.TrustedPrograms([])
    dm.alerts, dm.logs = [], []
    dm.publish_alert, dm.write_log = dm.alerts.append, dm.logs.append
    mon = object.__new__(d.ActivityMonitor)
    mon.daemon_ref, mon.tracks, mon.reported, mon.last_report, mon.dpkg_cache, mon.self_pid = dm, {}, {}, 0, {}, os.getpid()
    mon.infected = []
    mon.clamd_check = lambda paths: list(mon.infected)
    return dm, mon


def burst(mon, pid, folder, n, kill=None, kill_at=None):
    for i in range(n):
        mon.record(pid, f"{folder}/file{i}.dat")
        if kill is not None and i + 1 == kill_at:
            kill.kill()
            kill.wait()
            time.sleep(0.1)


dm, mon = make()
p = h.spawn(BIN, "installer-x")
burst(mon, p.pid, DOCS, 25, kill=p, kill_at=5)
a = dm.alerts[-1] if dm.alerts else {}
R.check("a program that exits before the 25th write is still named in the alert (was \"?\")",
        len(dm.alerts) == 1 and a.get("comm") == "installer-x" and a.get("severity") == "danger", a)

dm, mon = make()
burst(mon, 4190001, os.path.expanduser("~/.local/share/Steam/steamapps/common/Game"), 60)
R.check("unknown program writing only inside an application's folder (Steam): ignored automatically, logged",
        dm.alerts == [] and any("application folder" in x for x in dm.logs), (dm.alerts, dm.logs))

dm, mon = make()
dm.settings.v["auto_ignore_known"] = False
burst(mon, 4190002, os.path.expanduser("~/.local/share/Steam/steamapps/common/Game"), 60)
R.check("same burst with \"Learn from my choices\" off: reported", len(dm.alerts) == 1, dm.alerts)

if shutil.which("rpm"):
    dm, mon = make()
    pidfile = os.path.join(BIN, "child.pid")
    child = os.path.join(BIN, "postinst-probe.sh")
    open(child, "w").write(f"#!/bin/sh\necho $$ > {pidfile}\nexec sleep 20\n")
    os.chmod(child, 0o755)
    rp = subprocess.Popen(["rpm", "--eval", f"%({child})"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(50):
        if os.path.exists(pidfile) and open(pidfile).read().strip():
            break
        time.sleep(0.1)
    cpid = int(open(pidfile).read().strip())
    burst(mon, cpid, DOCS, 60)
    R.check("program started by a package manager (rpm → sh → program): ignored automatically, logged",
            dm.alerts == [] and any("launched by rpm" in x for x in dm.logs), (dm.alerts, dm.logs))
    subprocess.run(["kill", str(cpid)], check=False)
    rp.wait(5)
else:
    R.skip("program started by a package manager", "rpm is not installed (used to build a real package-manager parent)")

dm, mon = make()
p = h.spawn(BIN, "my-tool")
burst(mon, p.pid, DOCS + "/a", 25)
key = dm.habit_key(dm.alerts[-1]["exe"], dm.alerts[-1]["top_dir"])
dm.habit_note(key)
once = dm.habit_learned(key)
dm.habit_note(key)
twice = dm.habit_learned(key)
p2 = h.spawn(BIN, "my-tool")
n = len(dm.alerts)
burst(mon, p2.pid, DOCS + "/b", 60)
quiet = len(dm.alerts) == n and any("learned" in x for x in dm.logs)
habits = dict(dm.state.get("habits") or {})
habits.pop(key, None)
dm.state.update(habits=habits)
p3 = h.spawn(BIN, "my-tool")
burst(mon, p3.pid, DOCS + "/b", 25)
R.check("after two \"It's OK\" for the same program its bursts are ignored; forgetting the habit brings the alert back",
        key.endswith("/my-tool") and not once and twice and quiet and len(dm.alerts) == n + 1, (key, once, twice, quiet))

dm, mon = make()
mon.infected = ["x: Win.Test FOUND"]
burst(mon, 4190003, os.path.expanduser("~/.steam/steam"), 60)
R.check("a burst with an infected file is never ignored automatically",
        len(dm.alerts) == 1 and "files_infected" in dm.alerts[0]["reasons"], dm.alerts)

dm, mon = make()
burst(mon, 4190004, DOCS + "/Compta/2026", 30)
k1 = dm.habit_key("", DOCS + "/Compta/2026")
R.check("unknown program in documents: serious alert; a folder habit covers that exact folder only",
        len(dm.alerts) == 1 and dm.alerts[0]["severity"] == "danger" and k1 == "dir:" + DOCS + "/Compta/2026"
        and dm.habit_key("", os.path.expanduser("~")) == "" and dm.habit_key("/tmp/x/evil", DOCS) == "", (dm.alerts, k1))
R.done()
