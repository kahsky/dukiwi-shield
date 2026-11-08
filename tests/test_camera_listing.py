"""Camera opened only to list the devices (2.9.4).

Claude Desktop (Electron/Chromium) opened /dev/video0 for about a second to list the cameras: the camera did not film
and its light stayed off, but the guard reported "claude-desktop is using the camera" (it only looked at /proc/*/fd).
A USB camera that films switches its Video Streaming interface to an alternate setting above 0.

- fake sysfs: isochronous camera idle / streaming, bulk camera, non-USB camera;
- open without filming → logged, no popup, checked every second; filming afterwards → popup;
- cannot tell (bulk, not USB) → popup as before.
"""
import os
import threading

import _harness as h

R = h.Results("Camera opened only to list the devices")
gm = h.load("dukiwi_shield_guard.py", "dukiwi_shield_guard_under_test")

root = h.tmpdir("sysfs")
v4l = os.path.join(root, "class", "video4linux")
usb = os.path.join(root, "devices", "pci0000:00", "usb3", "3-8")


def write(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(text + "\n")


def interface(name, sub, alt, eps=()):
    d = os.path.join(usb, name)
    write(os.path.join(d, "bInterfaceClass"), "0e")
    write(os.path.join(d, "bInterfaceSubClass"), sub)
    write(os.path.join(d, "bAlternateSetting"), f"{alt:2d}")
    for ep, kind in eps:
        write(os.path.join(d, ep, "type"), kind)


def link(node, target):
    os.makedirs(os.path.join(v4l, node), exist_ok=True)
    os.symlink(target, os.path.join(v4l, node, "device"))


interface("3-8:1.0", "01", 0, [("ep_83", "Interrupt")])        # Video Control
interface("3-8:1.1", "02", 0)                                   # Video Streaming, isochronous, idle
link("video0", os.path.join(usb, "3-8:1.0"))
link("video1", os.path.join(usb, "3-8:1.0"))                    # metadata node of the same camera
link("video9", os.path.join(root, "devices", "virtual", "v4l2loopback"))
gm.SYS_V4L = v4l
cs = gm.SecurityGuard.camera_streaming

R.check("isochronous USB camera, alternate setting 0 → open but not filming", cs("/dev/video0") is False and cs("/dev/video1") is False)
write(os.path.join(usb, "3-8:1.1", "bAlternateSetting"), " 3")
R.check("alternate setting 3 → filming", cs("/dev/video0") is True)
write(os.path.join(usb, "3-8:1.1", "bAlternateSetting"), " 0")
os.makedirs(os.path.join(usb, "3-8:1.1", "ep_81"))
write(os.path.join(usb, "3-8:1.1", "ep_81", "type"), "Bulk")
R.check("bulk-transfer camera (streams in setting 0) → cannot tell", cs("/dev/video0") is None)
write(os.path.join(usb, "3-8:1.1", "ep_81", "type"), "Isoc")
R.check("virtual / non-USB camera → cannot tell", cs("/dev/video9") is None and cs("/dev/nonsense") is None)


# ── the guard ──
class Settings:
    def get(self, k):
        return True


class Daemon:
    def __init__(self):
        self.state, self.settings, self.shutdown, self.alerts = {}, Settings(), threading.Event(), []

    def publish_alert(self, a):
        self.alerts.append(a)


logged = []
d = Daemon()
d.state = type("S", (), {"get": lambda self, k, default=None: default})()
g = gm.SecurityGuard(d, {"log": lambda *_: None, "write_log": logged.append, "exe_trusted": lambda *_: True,
                         "dconf_read": lambda *a, **k: "", "human_users": lambda: []})
CLAUDE = {"pid": 74977, "comm": "claude-desktop", "exe": "/usr/lib/claude-desktop/claude-desktop", "user": "kahsky",
          "device": "/dev/video0", "uid": 1000, "cmdline": ""}
g.camera_users = lambda: {(CLAUDE["exe"], "camera"): dict(CLAUDE)}
g.mic_users = lambda: {}

g.check_privacy()
g.check_privacy()
R.check("Claude Desktop listing the cameras: no popup, logged once, checked every second meanwhile",
        not d.alerts and len(logged) == 1 and "without filming" in logged[0] and g.camera_idle_open, (d.alerts, logged))
write(os.path.join(usb, "3-8:1.1", "bAlternateSetting"), " 5")
g.check_privacy()
R.check("the same program then films → popup", len(d.alerts) == 1 and d.alerts[0]["device"] == "camera"
        and not g.camera_idle_open, d.alerts)
g.camera_users = lambda: {}
g.check_privacy()
R.check("camera closed → back to the normal check interval", not g.camera_idle_open and not g.privacy_active)

d.alerts.clear()
g.privacy_alerted.clear()
gm.SYS_V4L = os.path.join(root, "nowhere")                     # no sysfs information
g.camera_users = lambda: {(CLAUDE["exe"], "camera"): dict(CLAUDE)}
g.check_privacy()
R.check("no sysfs information → reported as before", len(d.alerts) == 1, d.alerts)
R.done()
