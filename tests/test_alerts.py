"""\"It's OK\" on serious alerts, and ignored honeypot devices (2.7.7)."""
import time
from datetime import datetime

import os
import pwd

import _harness as h

R = h.Results("Alerts and honeypot")
now = datetime.now().isoformat(timespec="seconds")

# ── "It's OK" on a serious alert, through the service ──
state = {"alerts": [
    {"kind": "download", "severity": "danger", "time": now, "title": "facture.exe", "detail": "Win.Test", "top_dir": "/home/x/Downloads",
     "pid": 0, "comm": "", "exe": "", "user": pwd.getpwuid(os.getuid()).pw_name},
    {"kind": "download", "severity": "danger", "time": now, "title": "theirs.exe", "detail": "Win.Test", "top_dir": "/home/y/Downloads",
     "pid": 0, "comm": "", "exe": "", "user": "someone-else", "ignored": True},
    {"kind": "honeypot", "severity": "danger", "time": now, "ip": "192.168.1.50", "host": "printer", "title": "printer", "ports": [],
     "fw_ports": ["udp/161"], "reasons": ["port_scan"], "pid": 0, "comm": "", "exe": ""},
    {"kind": "honeypot", "severity": "danger", "time": now, "ip": "192.168.1.77", "host": "other", "title": "other", "ports": [],
     "fw_ports": [], "reasons": ["port_scan"], "pid": 0, "comm": "", "exe": ""},
]}
with h.TestDaemon(state=state, tag="alerts") as dm:
    def reasons():
        return (dm.request("status").get("overall") or {}).get("reasons") or []

    def flags(kind):
        return {a.get("ip") or a.get("title"): bool(a.get("ignored")) for a in dm.request("alerts").get("alerts", []) if a.get("kind") == kind}

    R.check("a serious alert of the last 24 h keeps the shield red", "danger_alert" in reasons(), reasons())
    a = dm.request("acknowledge_alert", time=now, kind="download", title="facture.exe")
    R.check("\"It's OK\": the alert stays listed, marked ignored, and no longer turns the shield red",
            a.get("ok") and a.get("n") == 1 and "danger_alert" not in reasons() and flags("download").get("facture.exe") is True, (a, reasons()))
    b = dm.request("acknowledge_alert", time=now, kind="download", title="facture.exe", remove=True)
    R.check("\"Undo\": the alert counts again", b.get("ok") and "danger_alert" in reasons(), reasons())
    n = dm.request("acknowledge_alert", time="2001-01-01T00:00:00", kind="download")
    w = dm.request("acknowledge_alert", time=now, kind="download", title="other.exe")
    other = dm.request("acknowledge_alert", time=now, kind="download", title="theirs.exe")
    R.check("an alert about another account needs the administrator to be called normal",
            other.get("error") == "admin_required", other)
    R.check("unknown alert or wrong title: refused", n.get("error") == "not_found" and w.get("error") == "not_found", (n, w))
    i1 = dm.request("honeypot_ignore", timeout=30, ip="192.168.1.50")
    f1 = flags("honeypot")
    i2 = dm.request("honeypot_ignore", timeout=30, ip="192.168.1.50", remove=True)
    f2 = flags("honeypot")
    R.check("ignoring a device marks its listed alerts only; \"Show again\" clears the mark",
            i1.get("ok") and f1 == {"192.168.1.50": True, "192.168.1.77": False} and i2.get("ok") and not any(f2.values()), (f1, f2))

# ── honeypot logic: ignored device → information, intrusion → red ──
hp = h.load("dukiwi_shield_honeypot.py", "dukiwi_shield_honeypot_under_test")


class D:
    def __init__(self):
        self.state, self.alerts = h.St(), []
        self.settings = type("S", (), {"get": lambda s, k: True})()

    def publish_alert(self, a):
        self.alerts.append(a)

    def broadcast(self, e):
        pass


dd = D()
pot = hp.Honeypot(dd, {"log": lambda *a: None, "write_log": lambda *a: None, "ufw": lambda *a: (True, ""), "parse_ufw_numbered": lambda t: []})
ip = "192.168.1.50"


def evaluate(age=None):
    src = pot.sources[ip]
    if age is not None:
        src["alerted_at"] = time.time() - age
    t = time.time()
    for i in range(7):
        k = f"fw:udp/{9100 + i}"
        src["port_times"][k] = t
        if k not in src["fw_ports"]:
            src["fw_ports"].append(k)
    src["last"] = hp._iso(t)
    n = len(dd.alerts)
    pot._evaluate(ip)
    return dd.alerts[n:]


pot.sources.setdefault(ip, pot._new_source(ip, time.time()))
a = evaluate()
R.check("a device scanning ports raises a red alert", len(a) == 1 and a[0]["severity"] == "danger" and pot.summary()["danger_24h"] == 1, a)
pot.ignore(ip)
R.check("ignoring it: it no longer counts for the shield", pot.summary()["danger_24h"] == 0)
R.check("ignored device scanning again 1 h later: nothing (one information every 6 h at most)", evaluate(age=3600) == [])
a = evaluate(age=7 * 3600)
R.check("ignored device scanning 7 h later: one blue information, shield unchanged",
        len(a) == 1 and a[0]["severity"] == "info" and a[0].get("ignored") is True and pot.summary()["danger_24h"] == 0, a)
pot.sources[ip]["intents"]["login"] = 1
a = evaluate(age=60)
R.check("ignored device attempting a login: red alert at once",
        len(a) == 1 and a[0]["severity"] == "danger" and "login_attempt" in a[0]["reasons"] and pot.summary()["danger_24h"] == 1, a)
pot.ignore(ip)
a = evaluate(age=7 * 3600)
R.check("ignored again after that attempt: back to information, the old attempt is not held against it",
        len(a) == 1 and a[0]["severity"] == "info" and "login_attempt" not in a[0]["reasons"], a)
pot.ignore(ip, remove=True)
a = evaluate(age=7 * 3600)
R.check("\"Show again\": the device is red again", len(a) == 1 and a[0]["severity"] == "danger", a)
R.done()
