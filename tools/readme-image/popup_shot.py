#!/usr/bin/env python3
"""Rend une popup GTK de Linux Shield hors écran (sans l'afficher) : popup_shot.py <sortie.png>"""
import importlib.util, os, sys, gi
gi.require_version('Gtk', '3.0'); gi.require_version('Gdk', '3.0')
from gi.repository import Gtk, Gdk, GLib
P = __import__('os').path.abspath(__import__('os').path.join(__import__('os').path.dirname(__file__), '..', '..'))
sys.path.insert(0, P)
spec = importlib.util.spec_from_file_location("cavgui", P + "/clamav-antivirus.py")
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
import clamav_common as c
T = lambda key, **p: c.t("en", key, **p)
mgr = m.PopupManager()
title = T("popup.honeypot.title")
body = T("popup.honeypot.body", who="printer-4f2a (192.168.1.37)", n=3, ports="23, 2323, 27415")
popup = m.Popup(mgr, "danger", title, body, buttons=[(T("popup.honeypot.block"), "danger", lambda: None) if c.t("en", "popup.honeypot.block") != "popup.honeypot.block" else ("Block this device", "danger", lambda: None),
                                                     (T("popup.btn.ignore") if c.t("en", "popup.btn.ignore") != "popup.btn.ignore" else "Ignore", None, lambda: None),
                                                     (T("popup.btn.details"), None, lambda: None)],
               meta="Probe, HTTP request, SSH login attempt · 2 min ago")
child = popup.get_child(); popup.remove(child)
off = Gtk.OffscreenWindow()
off.get_style_context().add_class("popup-window")
screen = off.get_screen(); visual = screen.get_rgba_visual()
if visual: off.set_visual(visual); off.set_app_paintable(True)
off.set_size_request(m.Popup.WIDTH, -1)
off.add(child); off.show_all()
def grab():
    surf = off.get_surface()
    try:
        surf.write_to_png(sys.argv[1]); print("ok surface", sys.argv[1], surf.get_width(), "x", surf.get_height())
    except Exception as e:
        pb = off.get_pixbuf(); pb.savev(sys.argv[1], "png", [], []); print("ok pixbuf", sys.argv[1], pb.get_width(), "x", pb.get_height(), e)
    Gtk.main_quit(); return False
GLib.timeout_add(600, grab); GLib.timeout_add(8000, Gtk.main_quit)
Gtk.main()
