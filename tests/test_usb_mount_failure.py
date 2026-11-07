"""USB drive that refuses to mount (2.9.2).

A Seagate NTFS drive whose file system needed a repair ("$MFTMirr does not match $MFT"): udisks answered "Unknown
error when mounting", the interface posted its "Unable to mount" notification with GLib.idle_add(self.popup, ...),
and since popup() returns the Popup (a true value) GLib called it again on every turn of the main loop: thousands of
notifications, still coming after the drive was removed, until Cinnamon crashed.

- an idle callback that returns a true value runs once (idle_once);
- one mount attempt per drive at a time, one notification, with the NTFS reason when the service finds one;
- the reason read from ntfs-3g / ntfsfix messages;
- the service diagnosis: only for a plugged USB drive, NTFS only, once per plug;
- the udev rule keeps automount off on "change" events too.
"""
import os
import threading
import types

import _harness as h

R = h.Results("USB drive that refuses to mount")
g = h.load("dukiwi-shield.py", "dukiwi_shield_gui_under_test")
d = h.daemon_module()
from gi.repository import GLib  # noqa: E402

MFTMIRR = """$MFTMirr does not match $MFT (record 0).
Failed to mount '/dev/sdb1': Input/output error
NTFS is either inconsistent, or there is a hardware fault, or it's a
SoftRAID/FakeRAID hardware. In the first case run chkdsk /f on Windows
then reboot into Windows twice."""
HIBERNATED = """The disk contains an unclean file system (0, 0).
Metadata kept in Windows cache, refused to mount.
Please resume and shutdown Windows fully (no hibernation or fast restarting.)"""


def run_loop(seconds):
    loop = GLib.MainLoop()
    GLib.timeout_add(int(seconds * 1000), loop.quit)
    loop.run()


# ── idle_once ──
calls = []
g.idle_once(lambda: calls.append(1) or object())     # returns a true value, like popup()
run_loop(0.3)
R.check("a main-loop callback returning a true value runs once (it used to run forever)", calls == [1], calls)
R.check("no GLib.idle_add left outside idle_once in the interface",
        open(os.path.join(h.CODE, "dukiwi-shield.py")).read().count("GLib.idle_add(") == 1)

# ── reason from the messages ──
p = g.ntfs_mount_problem
R.check("ntfs-3g '$MFTMirr does not match $MFT' → file system to repair", p(MFTMIRR) == "inconsistent", p(MFTMIRR))
R.check("'Metadata kept in Windows cache' / hibernation → Windows still holds the drive", p(HIBERNATED) == "hibernated")
R.check("dirty volume → not closed cleanly", p("Volume is dirty.") == "unclean")
R.check("udisks 'Unknown error' alone → no reason", p("Error mounting /dev/sdb1: Unknown error when mounting /dev/sdb1") == "")

# ── interface: one attempt, one notification ──
App = g.ClamAVAntivirusApp
app = object.__new__(App)
popups, runs, diag = [], [], []
app.usb_mount_lock, app.usb_mounting = threading.Lock(), set()
app.T = lambda key, **params: key
app.popup = lambda kind, title, body, **kw: (popups.append((kind, body, kw)), types.SimpleNamespace(key=kw.get("key")))[1]
gate = threading.Event()


def fake_run(cmd, **kw):
    runs.append(cmd[0])
    if cmd[0] == "udisksctl":
        gate.wait(3)                     # the second request arrives while this one is still mounting
        return types.SimpleNamespace(returncode=1, stdout="",
                                     stderr="Error mounting /dev/sdb1: GDBus.Error:org.freedesktop.UDisks2.Error.Failed: "
                                            "Error mounting /dev/sdb1 at /media/x/Seagate: Unknown error when mounting /dev/sdb1")
    return types.SimpleNamespace(returncode=0, stdout="", stderr="")      # findmnt: not mounted


real_run, real_sleep, real_request = g.subprocess.run, g.time.sleep, g.DaemonClient.request
g.subprocess.run = fake_run
g.time.sleep = lambda s: None
g.DaemonClient.request = staticmethod(lambda cmd, **kw: (diag.append((cmd, kw)), {"ok": True, "problem": "inconsistent"})[1])
usb = {"devnode": "/dev/sdb1", "label": "Seagate Backup Plus Drive", "fstype": "ntfs"}
try:
    t1 = threading.Thread(target=app.mount_for_user, args=(usb, True, False))
    t1.start()
    while "udisksctl" not in runs:
        real_sleep(0.01)
    app.mount_for_user(usb, True, False)           # e.g. "Scan anyway" pressed meanwhile: ignored
    gate.set()
    t1.join(5)
    run_loop(0.5)
finally:
    g.subprocess.run, g.time.sleep, g.DaemonClient.request = real_run, real_sleep, real_request

R.check("two mount requests for the same drive → udisks asked once", runs.count("udisksctl") == 1, runs)
R.check("a failed mount gives exactly one notification", len(popups) == 1, len(popups))
kind, body, kw = popups[0] if popups else (None, None, {})
R.check("the notification names the reason found by the service (NTFS to repair)",
        body == "popup.usb.ntfs_inconsistent" and diag == [("usb_mount_diagnose", {"devnode": "/dev/sdb1"})], (body, diag))
R.check("the notification is keyed per drive and shows the device", kw.get("key") == "usb-mount:/dev/sdb1"
        and "/dev/sdb1" in (kw.get("meta") or ""), kw)
missing = [f"{lang}:{k}" for lang, table in g._common.load_i18n().items()
           for k in ("popup.usb.ntfs_hibernated", "popup.usb.ntfs_inconsistent", "popup.usb.ntfs_unclean") if k not in table]
R.check("the three reasons are translated in every language", not missing, missing)

# ── service: diagnosis ──
uw = object.__new__(d.UsbWatcher)
uw.lock, uw.mounted, uw.present, uw.diagnosed = threading.Lock(), {}, {}, {}
ran = []
real_quiet, real_which = d.run_quiet, d.shutil.which
d.run_quiet = lambda cmd, **k: (ran.append(cmd), types.SimpleNamespace(returncode=1, stdout=MFTMIRR, stderr=""))[1]
d.shutil.which = lambda name: "/usr/bin/ntfsfix" if name == "ntfsfix" else real_which(name)
try:
    R.check("a drive the service did not announce is not examined", uw.diagnose("/dev/sda") is None and not ran)
    uw.present["/dev/sdb1"] = {"devnode": "/dev/sdb1", "fstype": "ntfs"}
    first = uw.diagnose("/dev/sdb1")
    second = uw.diagnose("/dev/sdb1")
    R.check("NTFS drive: read-only ntfsfix, once per plug",
            first == second == "inconsistent" and ran == [["/usr/bin/ntfsfix", "--no-action", "/dev/sdb1"]], (first, ran))
    uw.present["/dev/sdc1"] = {"devnode": "/dev/sdc1", "fstype": "vfat"}
    R.check("other file systems: nothing run", uw.diagnose("/dev/sdc1") == "" and len(ran) == 1, ran)
finally:
    d.run_quiet, d.shutil.which = real_quiet, real_which

# ── udev ──
rule = open(os.path.join(h.CODE, "udev", "80-dukiwi-shield-usb.rules")).read()
R.check("udev: automount stays off on 'change' events, not only on 'add'",
        'ACTION!="remove"' in rule and 'ACTION=="add"' not in rule)
R.done()
