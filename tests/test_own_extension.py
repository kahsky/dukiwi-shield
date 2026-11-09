"""The shield's own browser extensions are not reported as new extensions (2.9.10).

Link Guard, installed by the shield through the Edge/Chrome/Firefox policies, came back as « New extension
"Dukiwi Shield — Contrôle des liens" (edge · user). Sensitive permissions: read and change all sites, talk to a
program on the computer » and was listed in red as "outside store".

- our id in a Chromium profile (normal install) → own extension, no alert, not counted outside the store;
- the same id loaded unpacked (anyone can copy a public key into a manifest) → still a new extension;
- another extension with the same permissions → still reported;
- Firefox: our Gecko id from a normal location → own, a temporary add-on with our id → not;
- ids read from extensions/manifest-info.json complete the built-in list.
"""
import json
import os
import threading

import _harness as h

R = h.Results("Own browser extensions")
d = h.daemon_module()

OWN = d.OWN_EXTENSION_IDS[0]
EVIL = "a" * 32
home = h.tmpdir("ownext")


def chromium_ext(profile, ext_id, name_msg=None, version="2.9.9"):
    folder = os.path.join(home, ".config/microsoft-edge", profile, "Extensions", ext_id, version + "_0")
    os.makedirs(os.path.join(folder, "_locales", "fr"))
    man = {"manifest_version": 3, "name": "__MSG_ext_name__" if name_msg else "Totally Fine Helper", "version": version,
           "default_locale": "fr", "permissions": ["nativeMessaging", "webNavigation", "tabs", "storage"],
           "host_permissions": ["http://*/*", "https://*/*"]}
    json.dump(man, open(os.path.join(folder, "manifest.json"), "w"))
    json.dump({"ext_name": {"message": name_msg or "x"}}, open(os.path.join(folder, "_locales", "fr", "messages.json"), "w"))


def chromium_prefs(profile, settings):
    json.dump({"extensions": {"settings": settings}}, open(os.path.join(home, ".config/microsoft-edge", profile, "Preferences"), "w"))


chromium_ext("Default", OWN, "Dukiwi Shield — Contrôle des liens")
chromium_ext("Default", EVIL)
chromium_prefs("Default", {OWN: {"from_webstore": False, "location": 7, "state": 1}, EVIL: {"from_webstore": False, "location": 1, "state": 1}})
chromium_ext("Profile 1", OWN, "Dukiwi Shield — Contrôle des liens")              # same id, loaded unpacked
chromium_prefs("Profile 1", {OWN: {"from_webstore": False, "location": 4, "state": 1}})
ff = os.path.join(home, ".mozilla/firefox/abc.default-release")
os.makedirs(ff)
json.dump({"addons": [
    {"type": "extension", "id": "urlguard@dukiwi-shield.dukiwi.com", "location": "app-profile", "signedState": 0, "active": True, "version": "2.9.9",
     "defaultLocale": {"name": "Dukiwi Shield — Contrôle des liens"}, "userPermissions": {"permissions": ["nativeMessaging"], "origins": ["<all_urls>"]}},
    {"type": "extension", "id": "mailguard@dukiwi-shield.dukiwi.com", "location": "app-temporary", "signedState": 0, "active": True, "version": "1.0",
     "defaultLocale": {"name": "Spoof"}, "userPermissions": {"permissions": ["nativeMessaging"], "origins": ["<all_urls>"]}},
]}, open(os.path.join(ff, "extensions.json"), "w"))

d.user_homes = lambda: [("tim", home)]
d.pending_homes = lambda: []
d.audit.editor_extensions = lambda user, home_: []
pers = d.collect_persistence()
by = {(e["browser"], e["profile"], e["id"]): e for e in pers["extensions"]}
own = by[("edge", "Default", OWN)]
R.check("Link Guard in an Edge profile: our id, normal install → own extension, sensitive permissions still listed",
        own["own"] and not own["from_store"] and own["name"] == "Dukiwi Shield — Contrôle des liens" and "all_sites" in own["perms"] and "nativeMessaging" in own["perms"], own)
R.check("same id loaded unpacked (copied public key) → not ours", not by[("edge", "Profile 1", OWN)]["own"])
R.check("another extension with the same permissions → not ours", not by[("edge", "Default", EVIL)]["own"])
R.check("Firefox: our Gecko id from a normal location → own; a temporary add-on with our id → not",
        by[("firefox", "abc.default-release", "urlguard@dukiwi-shield.dukiwi.com")]["own"]
        and not by[("firefox", "abc.default-release", "mailguard@dukiwi-shield.dukiwi.com")]["own"])
R.check("counter 'outside the store' leaves our extensions out (unpacked spoof, other extension, temporary add-on counted)",
        pers["counts"]["ext_outside_store"] == 3, pers["counts"])

# Service: alerts on a new survey (the previous survey knew one unrelated extension, so alerts are armed)
dm = object.__new__(d.Daemon)
dm._persistence_lock = threading.Lock()
other = {"browser": "edge", "user": "tim", "profile": "Default", "id": "b" * 32, "perms": [], "name": "Other", "version": "1",
         "from_store": True, "enabled": True, "key": "edge:tim:" + "b" * 32}
dm.state = h.St(persistence={"items": [], "extensions": [other]}, acknowledged_persistence=[])
alerts, logs = [], []
dm.publish_alert = alerts.append
dm.write_log = logs.append
dm.broadcast = lambda ev: None
pers = dm.refresh_persistence(reason="test")
ext_alerts = {(a.get("extension") or {}).get("key") for a in alerts if a.get("kind") == "extension"}
R.check("no popup for our extensions; the unpacked spoof, the other extension and the temporary add-on are reported",
        ext_alerts == {f"edge:tim:{EVIL}", f"edge:tim:{OWN}", "firefox:tim:mailguard@dukiwi-shield.dukiwi.com"}
        and all((a.get("extension") or {}).get("key") != f"edge:tim:{OWN}" or (a.get("extension") or {}).get("profile") == "Profile 1" for a in alerts),
        sorted(ext_alerts))
R.check("the installation of our extension is written to the log instead", any("own edge extension" in x for x in logs), logs)
R.check("counters after approval pass: our extensions still not 'outside the store'", pers["counts"]["ext_outside_store"] == 3, pers["counts"])

# Ids shipped with the package complete the built-in list
app = h.tmpdir("ownapp")
os.makedirs(os.path.join(app, "extensions"))
json.dump({"chrome_id": "c" * 32, "gecko_ids": ["future@dukiwi-shield.dukiwi.com"]}, open(os.path.join(app, "extensions", "manifest-info.json"), "w"))
saved = d.APP_DIR
d.APP_DIR, d._OWN_EXTENSIONS["ids"] = app, None
ids = d.own_extension_ids()
d.APP_DIR, d._OWN_EXTENSIONS["ids"] = saved, None
R.check("ids of extensions/manifest-info.json are recognized too, with the built-in ones",
        {"c" * 32, "future@dukiwi-shield.dukiwi.com", OWN, "urlguard@dukiwi-shield.dukiwi.com"} <= ids, ids)
R.done()
