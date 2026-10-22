#!/usr/bin/env python3
"""Rendu hors écran de l'interface : webkit_shot.py <url> <largeur> <hauteur> <sortie.png> [js] [délai s]"""
import sys, gi
gi.require_version('Gtk', '3.0'); gi.require_version('WebKit2', '4.1')
from gi.repository import Gtk, WebKit2, GLib
url, w, h, out = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), sys.argv[4]
js = sys.argv[5] if len(sys.argv) > 5 else ""
delay = float(sys.argv[6]) if len(sys.argv) > 6 else 2.5
win = Gtk.OffscreenWindow()
view = WebKit2.WebView()
view.set_size_request(w, h)
import os
if os.environ.get('ZOOM'):
    view.set_zoom_level(float(os.environ['ZOOM']))   # GDK_SCALE=1 + zoom 2 : mise en page à w/2 px CSS, rendu net à 2×
win.add(view); win.show_all()
done_once = {"v": False}
def snap():
    view.get_snapshot(WebKit2.SnapshotRegion.VISIBLE, WebKit2.SnapshotOptions.NONE, None, finish, None); return False
def finish(v, res, _):
    surf = v.get_snapshot_finish(res); surf.write_to_png(out)
    print("ok", out, surf.get_width(), "x", surf.get_height()); Gtk.main_quit()
def js_done(v, res, _):
    try:
        val = v.run_javascript_finish(res).get_js_value().to_string()
        print("JS:", val)
    except Exception as e:
        print("JS error:", e)
def after_load():
    if js:
        view.run_javascript(js, None, js_done, None)
    GLib.timeout_add(int(delay * 1000), snap); return False
def on_load(v, ev):
    if ev == WebKit2.LoadEvent.FINISHED and not done_once["v"]:
        done_once["v"] = True; GLib.timeout_add(900, after_load)
view.connect('load-changed', on_load)
view.load_uri(url)
GLib.timeout_add(30000, Gtk.main_quit)
Gtk.main()
