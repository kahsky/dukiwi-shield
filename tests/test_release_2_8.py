"""2.8.0: what's new in the update offer, Timeshift on another drive, password step 2 and encryption detail, monthly
e-mail report, telemetry dashboard (lagging installations, adoption), transitional package for the old name."""
import json
import os
import shutil
import subprocess
import time
from datetime import datetime

import _harness as h

R = h.Results("2.8.0 features")
d = h.daemon_module()
hy = h.load("dukiwi_shield_hygiene.py", "dukiwi_shield_hygiene_under_test")

# ── 1. What's new, from the signed manifest ──
manifest = {"changes": [{"version": "2.8.1", "title": "Later", "text": "x"}, {"version": "2.8.0", "title": "New", "text": "y"},
                        {"version": "2.7.12", "title": "Old", "text": "z"}, "junk", {"title": "no version"}]}
got = d.manifest_changes(manifest, "2.7.12")
R.check("update offer lists only the versions newer than the installed one, newest first",
        [c["version"] for c in got] == ["2.8.1", "2.8.0"] and got[1]["title"] == "New", got)

# ── 2. Timeshift: other drives that can hold the snapshots ──
lsblk = {"blockdevices": [
    {"name": "nvme0n1", "model": "Disk", "children": [
        {"name": "p1", "uuid": "ROOT", "fstype": "ext4", "mountpoint": "/", "fsavail": "1000", "size": "5000"},
        {"name": "p2", "uuid": "EFI", "fstype": "vfat", "mountpoint": "/boot/efi", "fsavail": "1", "size": "2"}]},
    {"name": "sda", "model": "USB Disk", "children": [
        {"name": "sda1", "uuid": "BIG", "fstype": "ext4", "mountpoint": "/media/k/Backup", "fsavail": "900000000000", "size": "1000000000000", "label": "Backup"},
        {"name": "sda2", "uuid": "FAT", "fstype": "exfat", "mountpoint": "/media/k/Photos", "fsavail": "900000000000", "size": "1000000000000"},
        {"name": "sda3", "uuid": "SMALL", "fstype": "btrfs", "mountpoint": "/media/k/Small", "fsavail": "1000", "size": "2000"},
        {"name": "sda4", "uuid": "UNMOUNTED", "fstype": "ext4", "mountpoint": None, "fsavail": None, "size": "2000"}]}]}


class Out:
    def __init__(self, out): self.stdout, self.returncode, self.stderr = out, 0, ""


real = d.run_quiet
d.run_quiet = lambda cmd, **k: Out(json.dumps(lsblk) if cmd[0] == "lsblk" else "ROOT\n")
targets = d.timeshift_targets(50 * 10**9)
d.run_quiet = real
R.check("Timeshift targets: mounted Linux file systems other than the system disk, roomiest first, \"enough\" flag",
        [(t["uuid"], t["enough"]) for t in targets] == [("BIG", True), ("SMALL", False)] and targets[0]["label"] == "Backup", targets)

# ── 3. Encryption detail and password step 2 ──
def fake(answers):
    def run(cmd, timeout=60, env=None):
        key = " ".join(cmd)
        for k, v in answers.items():
            if key.startswith(k):
                return Out(v)
        return Out("")
    return run


cases = {
    "LUKS root": ({"findmnt -no SOURCE /": "/dev/mapper/vg-root\n", "lsblk -s -n -o TYPE /dev/mapper/vg-root": "lvm\ncrypt\npart\ndisk\n",
                   "findmnt -no SOURCE --target /swapfile": "/dev/mapper/vg-root\n"},
                  "Filename Type Size Used Priority\n/swapfile file 1 0 -1\n", (True, True, [])),
    "eCryptfs home, swap file in clear": ({"findmnt -no SOURCE /": "/dev/nvme0n1p5\n", "lsblk -s -n -o TYPE /dev/nvme0n1p5": "part\ndisk\n",
                                           "findmnt -no SOURCE --target /home": "/dev/nvme0n1p5\n",
                                           "findmnt -no SOURCE --target /swapfile": "/dev/nvme0n1p5\n"},
                                          "Filename Type Size Used Priority\n/swapfile file 1 0 -1\n/dev/zram0 partition 1 0 100\n", (False, True, ["/swapfile"])),
}
saved_run, saved_read, saved_isdir, saved_scandir = hy.run, hy._read, os.path.isdir, os.scandir
for name, (answers, swaps, expected) in cases.items():
    hy.run = fake(answers)
    hy._read = lambda p, s=swaps: s if p == "/proc/swaps" else ""
    ecr = name.startswith("eCryptfs")
    os.path.isdir = (lambda p, e=ecr: e if p == "/home/.ecryptfs" else saved_isdir(p))
    os.scandir = (lambda p, e=ecr: iter([1]) if p == "/home/.ecryptfs" else saved_scandir(p))
    st = hy.encryption_status()
    R.check(f"encryption: {name}", (st["root"], st["home"], st["swap_clear"]) == expected, st)
hy.run, hy._read, os.path.isdir, os.scandir = saved_run, saved_read, saved_isdir, saved_scandir

work = h.tmpdir("pw")
drop, shadow = os.path.join(work, "90-dukiwi-shield.conf"), os.path.join(work, "shadow")
open(drop, "w").write("minlen = 12\n")
day = int(time.time() // 86400)
os.utime(drop, (day * 86400, day * 86400))
me = __import__("pwd").getpwuid(os.getuid())
open(shadow, "w").write(f"root:$y$x:{day - 50}:0:99999:7:::\n{me.pw_name}:$y$hash:{day - 3}:0:99999:7:::\nlocked:!:{day - 3}:0:99999:7:::\n")
hy.PWQ_DROPIN, hy.SHADOW_FILE = drop, shadow
stale = hy.passwords_older_than_policy() if me.pw_dir.startswith("/home/") else None
open(shadow, "w").write(f"{me.pw_name}:$y$hash:{day + 1}:0:99999:7:::\n")
fresh = hy.passwords_older_than_policy() if me.pw_dir.startswith("/home/") else None
if stale is None:
    R.skip("password step 2", "test account has no home under /home")
else:
    R.check("password step 2: a password older than the rules is listed, root and locked accounts are not; changed → done",
            stale == [me.pw_name] and fresh == [], (stale, fresh))

# ── 6. Monthly report: only when e-mail delivery is known to work, once a month ──
sent = []
dm = object.__new__(d.Daemon)
dm.state = h.St(alerts=[], history=[], score_history=[], checklist={"score": 80, "grade": "B", "items": []})
dm.settings = type("S", (), {"get": lambda self, k: None})()
dm.urlguard = type("U", (), {"events": []})()
dm.write_log = lambda *a: None
dm.mail_deliver = lambda subject, body, kind="digest": (sent.append((subject, body, kind)), (True, ""))[1]
d.security_journal = lambda daemon, days: []
for cfg, expect in (({"enabled": True, "to": ["a@b.ch"]}, 0), ({"enabled": True, "to": ["a@b.ch"], "last_sent": "2026-11-01T08:00:00", "last_error": "auth"}, 0),
                    ({"enabled": True, "to": ["a@b.ch"], "last_sent": "2026-11-01T08:00:00", "events": {"monthly": False}}, 0),
                    ({"enabled": True, "to": ["a@b.ch"], "last_sent": "2026-11-01T08:00:00"}, 1)):
    n = len(sent)
    dm.state.update(mail=cfg, monthly_report_month="")
    real_now = d.datetime
    dm.check_monthly_report()
    if datetime.now().hour < 8:
        expect = 0
    R.check(f"monthly report {'sent' if expect else 'not sent'}: {sorted(k for k in cfg if k != 'to')}", len(sent) - n == expect, sent[n:])
if datetime.now().hour >= 8:
    n = len(sent)
    dm.check_monthly_report()
    R.check("monthly report: only once per month", len(sent) == n)
    body = sent[-1][1] if sent else ""
    R.check("monthly report contains backups, snapshots, updates and version", all(k in body for k in ("Dukiwi Shield :",)) and body.count("\n- ") >= 6, body)

# ── 4. Telemetry dashboard (PHP), when the web repository and php are here ──
api = os.environ.get("DUKIWI_TEST_API") or os.path.join(os.path.dirname(h.ROOT), "repo", "api")
if not shutil.which("php") or not os.path.isfile(os.path.join(api, "telemetry_stats.php")):
    R.skip("telemetry dashboard", "php or ../repo/api not found")
else:
    script = f"""<?php
require '{api}/telemetry_stats.php';
$rows = [['install_id' => 'aaaaaaaa1', 'version' => '2.7.3', 'received_at' => gmdate('c')],
         ['install_id' => 'bbbbbbbb2', 'version' => '9.9.9', 'received_at' => gmdate('c', time() - 30 * 86400)],
         ['install_id' => 'cccccccc3', 'version' => '9.9.9', 'received_at' => gmdate('c')]];
$up = [['at' => '2026-11-07T10:00:00', 'version' => '2.8.0', 'from' => '2.7.12', 'id' => 'a'],
       ['at' => '2026-11-07T12:00:00', 'version' => '2.8.0', 'from' => '2.7.12', 'id' => 'b'],
       ['at' => '2026-11-08T09:00:00', 'version' => '2.8.0', 'from' => '2.7.3', 'id' => 'a']];
echo json_encode(['lag' => tl_lagging($rows, '9.9.9'), 'adopt' => tl_adoption($up)]);
"""
    r = subprocess.run(["php"], input=script, capture_output=True, text=True)
    try:
        out = json.loads(r.stdout)
    except ValueError:
        out = {"error": r.stdout + r.stderr}
    lag = [(x["id"], x["behind"], x["silent"]) for x in out.get("lag", [])]
    adopt = out.get("adopt") or [{}]
    R.check("dashboard: installations behind the published version or silent for 14 days",
            lag == [("aaaaaaaa", True, False), ("bbbbbbbb", False, True)], out)
    R.check("dashboard: adoption per version from the after-update reports",
            adopt[0].get("version") == "2.8.0" and adopt[0].get("installations") == 2 and adopt[0].get("from") == {"2.7.12": 2, "2.7.3": 1}, adopt)

# ── 5. Transitional package ──
if not shutil.which("dpkg-deb"):
    R.skip("transitional package", "dpkg-deb not installed")
else:
    v = "0.0.0~test"
    r = subprocess.run([os.path.join(h.ROOT, "tools", "build-transitional.sh"), v], capture_output=True, text=True)
    deb = os.path.join(h.ROOT, f"clamav-antivirus_{v}_all.deb")
    fields = {}
    if os.path.exists(deb):
        for k in ("Package", "Version", "Depends", "Section"):
            fields[k] = subprocess.run(["dpkg-deb", "-f", deb, k], capture_output=True, text=True).stdout.strip()
        files = subprocess.run(["dpkg-deb", "-c", deb], capture_output=True, text=True).stdout
        os.remove(deb)
    R.check("transitional clamav-antivirus: empty, depends on the same dukiwi-shield version",
            fields == {"Package": "clamav-antivirus", "Version": v, "Depends": f"dukiwi-shield (>= {v})", "Section": "oldlibs"}
            and "/opt/" not in files, (r.stderr, fields))
    control = open(os.path.join(h.ROOT, "build-deb.sh"), encoding="utf-8").read()
    R.check("dukiwi-shield only conflicts with the old package before 2.0, so the transitional one can be installed",
            "Conflicts: clamav-antivirus (<< 2.0~)" in control and "Breaks: clamav-antivirus (<< 2.0~)" in control)
R.done()
