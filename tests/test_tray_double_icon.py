"""Double shield in the taskbar (2.9.1): the panel's StatusNotifierWatcher registers the shield but answers after the
D-Bus timeout, so Ayatana adds its XEmbed fallback icon as well. The real TrayIcon class must notice it and keep a
single icon; with no watcher at all the fallback icon is the only one and must stay.
Each case runs on a private session bus (dbus-run-session) with a fake watcher, so the real panel is not involved;
the fallback icon does show for a moment in the desktop's legacy tray. Needs a graphical display: "run_all.py --gui".
Takes about one minute."""
import os
import subprocess
import sys

import _harness as h

FAKE_WATCHER = r'''
import os, sys
from gi.repository import Gio, GLib
XML = """<node><interface name="org.kde.StatusNotifierWatcher">
 <method name="RegisterStatusNotifierItem"><arg type="s" direction="in"/></method>
 <method name="RegisterStatusNotifierHost"><arg type="s" direction="in"/></method>
 <property name="RegisteredStatusNotifierItems" type="as" access="read"/>
 <property name="IsStatusNotifierHostRegistered" type="b" access="read"/>
 <property name="ProtocolVersion" type="i" access="read"/>
</interface></node>"""
items = []
iface = Gio.DBusNodeInfo.new_for_xml(XML).interfaces[0]
slow_first = int(sys.argv[1])          # seconds before answering the first registration (after the 25 s timeout)

def call(conn, sender, path, name, method, params, inv):
    if method == "RegisterStatusNotifierItem":
        items.append(sender + params.unpack()[0])
        if len(items) == 1 and slow_first:
            GLib.timeout_add_seconds(slow_first, lambda: inv.return_value(None) and False)
            return
    inv.return_value(None)

def prop(conn, sender, path, name, p):
    return {"RegisteredStatusNotifierItems": GLib.Variant("as", items),
            "IsStatusNotifierHostRegistered": GLib.Variant("b", True), "ProtocolVersion": GLib.Variant("i", 0)}[p]

Gio.bus_own_name(Gio.BusType.SESSION, "org.kde.StatusNotifierWatcher", 0,
                 lambda c, n: c.register_object("/StatusNotifierWatcher", iface, call, prop, None), None, None)
GLib.MainLoop().run()
'''


def child(case):
    """Runs inside dbus-run-session: one case, prints 'RESULT key=value' lines for the parent."""
    import time
    watcher = None
    if case == "slow":
        watcher = subprocess.Popen([sys.executable, "-c", FAKE_WATCHER, "40"])
        time.sleep(1)
    g = h.load("dukiwi-shield.py", "dukiwi_shield_gui_under_test")
    from gi.repository import GLib, Gtk

    class StubApp:
        lang = "en"
        last_daemon_status = None
        T = staticmethod(lambda key, **kw: key)
        overall_state = staticmethod(lambda: {"color": "yellow", "reasons": []})
        backup_summary = staticmethod(lambda: {"state": "ok"})
        report_backup_state = staticmethod(lambda bk: None)
        backup_check_enabled = staticmethod(lambda: False)
        run_js = staticmethod(lambda js: None)

    g.TrayIcon.DOUBLE_ICON_CHECK_S = 5
    tray = g.TrayIcon(StubApp())
    seen = {}

    def sample(tag):
        seen[tag] = tray.fallback_icon_shown()
        return False

    repair = tray.repair_double_icon

    def traced_repair():
        seen.setdefault("before", tray.fallback_icon_shown())    # state right when the guard steps in
        repair()

    tray.repair_double_icon = traced_repair
    if case == "slow":
        GLib.timeout_add_seconds(45, sample, "after")
        GLib.timeout_add_seconds(46, Gtk.main_quit)
    else:
        GLib.timeout_add_seconds(12, sample, "after")
        GLib.timeout_add_seconds(13, Gtk.main_quit)
    Gtk.main()
    item = ""
    if watcher:
        from gi.repository import Gio
        bus = Gio.bus_get_sync(Gio.BusType.SESSION, None)
        r = bus.call_sync("org.kde.StatusNotifierWatcher", "/StatusNotifierWatcher", "org.freedesktop.DBus.Properties",
                          "Get", GLib.Variant("(ss)", ("org.kde.StatusNotifierWatcher", "RegisteredStatusNotifierItems")),
                          None, 0, 3000, None)
        item = ",".join(r.unpack()[0])
        watcher.terminate()
    exported = tray.indicator.get_property("id") == "dukiwi-shield"
    print(f"RESULT before={seen.get('before')} after={seen.get('after')} repairs={tray.repairs} "
          f"item={item or '-'} indicator={exported} icon={tray.icon_args[0].endswith('shield-yellow.svg')}", flush=True)


def run_case(case):
    env = dict(os.environ, DUKIWI_TRAY_TEST_CASE=case)
    r = subprocess.run(["dbus-run-session", "--", sys.executable, os.path.abspath(__file__)],
                       env=env, capture_output=True, text=True, timeout=120)
    line = next((ln for ln in r.stdout.splitlines() if ln.startswith("RESULT ")), "")
    return dict(kv.split("=", 1) for kv in line[7:].split()) if line else {"crash": (r.stdout + r.stderr)[-500:]}


if os.environ.get("DUKIWI_TRAY_TEST_CASE"):
    child(os.environ["DUKIWI_TRAY_TEST_CASE"])
    sys.exit(0)

R = h.Results("Double tray icon (GUI)")
if not os.environ.get("DISPLAY"):
    R.skip("double tray icon", "no X display (the fallback icon is an XEmbed window)")
    R.done()
if subprocess.run(["sh", "-c", "command -v dbus-run-session"], capture_output=True).returncode:
    R.skip("double tray icon", "dbus-run-session missing")
    R.done()

slow = run_case("slow")
R.check("slow watcher: the fallback icon appears after the 25 s timeout and the guard sees it (bug reproduced)", slow.get("before") == "True", slow)
R.check("slow watcher: one indicator rebuild removes it, the process survives", slow.get("after") == "False" and slow.get("repairs") == "1", slow)
R.check("slow watcher: the shield is still listed by the watcher, with the current colour",
        "/org/ayatana/NotificationItem/dukiwi_shield" in slow.get("item", "") and slow.get("icon") == "True", slow)
none = run_case("none")
R.check("no watcher: the fallback icon is the only one and stays (no rebuild)", none.get("after") == "True" and none.get("repairs") == "0", none)
R.done()
