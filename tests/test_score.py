"""Security score (2.7.8): backups and snapshots counted even with the reminder ignored, protected folders; habits
learned from "It's OK" on two bursts of the same program. Through a test service."""
import time
from datetime import datetime

import _harness as h

R = h.Results("Security score and learned habits")
now = datetime.now().isoformat(timespec="seconds")
state = {"alerts": [
    {"kind": "burst", "severity": "danger", "time": now, "pid": 4242, "comm": "my-tool", "exe": "/home/x/bin/my-tool", "count": 60,
     "window": 15, "top_dir": "/home/x/Documents/a", "trusted": False, "reasons": ["untrusted_home_burst"], "sample": []},
    {"kind": "burst", "severity": "info", "time": "2026-01-01T08:00:00", "pid": 4243, "comm": "my-tool", "exe": "/home/x/bin/my-tool",
     "count": 80, "window": 15, "top_dir": "/home/x/Documents/b", "trusted": False, "reasons": [], "sample": []}]}

with h.TestDaemon(state=state, tag="score") as dm:
    def checklist():
        ck = dm.request("checklist", timeout=180, refresh=True).get("checklist") or {}
        return ck.get("score"), {i["key"]: i for i in ck.get("items") or []}

    def overall_reasons():
        return (dm.request("status").get("overall") or {}).get("reasons") or []

    dm.request("backup_state_report", state="none", last="")
    s0, it0 = checklist()
    fb, ss, pf = it0.get("file_backups") or {}, it0.get("system_snapshots") or {}, it0.get("protected_folders") or {}
    R.check("checklist has file backups (5), system snapshots (4) and protected folders (4)",
            fb.get("status") == "fail" and fb.get("weight") == 5 and ss.get("weight") == 4 and pf.get("status") == "warn"
            and pf.get("weight") == 4, {"file_backups": fb, "system_snapshots": ss, "protected_folders": pf})
    a = dm.request("ignore_check", setting="backup_check", ignore=True)
    b = dm.request("ignore_check", setting="timeshift_check", ignore=True)
    time.sleep(1.5)
    s1, it1 = checklist()
    fb1, ss1 = it1.get("file_backups") or {}, it1.get("system_snapshots") or {}
    R.check("ignoring the backup and Timeshift reminders keeps the score; the items stay, marked \"reminder ignored\"",
            a.get("ok") and b.get("ok") and s1 == s0 and fb1.get("detail_key") == "check.reminder_ignored"
            and (ss1.get("status") not in ("warn", "fail") or ss1.get("detail_key") == "check.reminder_ignored")
            and not any(r.startswith("timeshift") for r in overall_reasons()), {"scores": (s0, s1), "fb": fb1, "ss": ss1})
    dm.request("backup_state_report", state="ok", last=now)
    time.sleep(1.5)
    s2, it2 = checklist()
    R.check("once files are backed up the item turns ok and the score goes up",
            (it2.get("file_backups") or {}).get("status") == "ok" and s2 > s1, (s1, s2))
    R.check("an invalid backup state is refused", dm.request("backup_state_report", state="whatever").get("error") == "invalid_key")

    def habits():
        return [x["key"] for x in dm.request("trusted_programs").get("habits") or []]

    r1 = dm.request("acknowledge_alert", time=now, kind="burst", title="my-tool")
    h1 = habits()
    r2 = dm.request("acknowledge_alert", time="2026-01-01T08:00:00", kind="burst", title="my-tool")
    R.check("\"It's OK\" on two bursts of the same program: the habit is learned and listed",
            r1.get("ok") and r2.get("ok") and h1 == [] and habits() == ["/home/x/bin/my-tool"], (h1, habits()))
    dm.request("acknowledge_alert", time=now, kind="burst", title="my-tool", remove=True)
    R.check("\"Undo\" on one of them: the habit is no longer learned", habits() == [])
    dm.request("acknowledge_alert", time=now, kind="burst", title="my-tool")
    f = dm.request("forget_habit", key="/home/x/bin/my-tool")
    R.check("a learned habit can be forgotten; an unknown one is refused",
            f.get("ok") and habits() == [] and dm.request("forget_habit", key="/nope").get("error") == "not_found")
    R.check("the learning setting reaches the interface, on by default",
            (dm.request("status").get("settings") or {}).get("auto_ignore_known") is True)
R.done()
