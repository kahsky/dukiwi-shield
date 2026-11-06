"""Notifications (2.7.8): two popups in each of the four corners, with the real application code, on the current
desktop. Checks they stay inside the usable area (clear of panels and docks) and in the right corner.
Needs a graphical display: only run with "run_all.py --gui"."""
import os

import _harness as h

R = h.Results("Notifications (GUI)")
if not os.environ.get("DISPLAY") and not os.environ.get("WAYLAND_DISPLAY"):
    R.skip("popups in the four corners", "no graphical display")
    R.done()

g = h.load("dukiwi-shield.py", "dukiwi_shield_gui_under_test")
from gi.repository import GLib, Gtk  # noqa: E402

corner = {"v": "right"}
real = g.user_settings
g.user_settings = lambda: dict(real(), popup_corner=corner["v"])
mgr = g.PopupManager()
x0, y0, x1, y1 = mgr.usable_area()
geo = mgr.monitor_geometry()
todo = ["right", "left", "top-right", "top-left"]
rows = {}


def run(c):
    corner["v"] = c
    pops = [g.Popup(mgr, "danger", f"Test {c} 1", "First notification."), g.Popup(mgr, "info", f"Test {c} 2", "Second notification.")]
    for p in pops:
        mgr.show(p)

    def measure():
        rows[c] = [p.get_position() + p.get_size() for p in pops]
        for p in pops:
            p.close()
        GLib.timeout_add(600, step)
        return False
    GLib.timeout_add(1000, measure)


def step():
    if todo:
        run(todo.pop(0))
    else:
        Gtk.main_quit()
    return False


GLib.idle_add(step)
GLib.timeout_add_seconds(40, Gtk.main_quit)
Gtk.main()
mid_x, mid_y = geo.x + geo.width / 2, geo.y + geo.height / 2
for c in ("right", "left", "top-right", "top-left"):
    boxes = rows.get(c) or []
    inside = boxes and all(x >= x0 and y >= y0 and x + w <= x1 and y + hh <= y1 for x, y, w, hh in boxes)
    left, top = c.endswith("left"), c.startswith("top")
    placed = boxes and all(((x + w / 2) < mid_x) == left and ((y + hh / 2) < mid_y) == top for x, y, w, hh in boxes)
    apart = len(boxes) == 2 and (boxes[0][1] + boxes[0][3] <= boxes[1][1] or boxes[1][1] + boxes[1][3] <= boxes[0][1])
    R.check(f"corner {c}: both popups inside the usable area {(x0, y0, x1, y1)}, in that corner, not overlapping",
            inside and placed and apart, boxes)
R.done()
