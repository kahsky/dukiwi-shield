"""Telemetry: path anonymisation (2.7.9), report right after an update (2.7.10), and, when the web repository sits next
to this one (../repo/api or DUKIWI_TEST_API) and php is installed, the server endpoint telemetry.php."""
import http.server
import json
import os
import shutil
import socket
import subprocess
import threading
import time
import urllib.request
from datetime import datetime, timedelta

import _harness as h

R = h.Results("Telemetry")
d = h.daemon_module()

cases = {"autostart:/home/papa/.config/autostart/kDrive.desktop": "autostart:/home/~/.config/autostart/kDrive.desktop",
         "crontab:/var/spool/cron/crontabs/papa": "crontab:/var/spool/cron/crontabs/~",
         "crontab:/var/spool/cron/alice": "crontab:/var/spool/cron/~",
         "/tmp/.mount_kDriveoflMIH/usr/bin/kDrive": "/tmp/.mount_~/usr/bin/kDrive",
         "files in /home/bob/x and /run/media/bob/USB/y, /run/user/1000/z": "files in /home/~/x and /run/media/~/USB/y, /run/user/~/z",
         "/home/~/.steam/steam": "/home/~/.steam/steam", "/usr/bin/dpkg": "/usr/bin/dpkg",
         "system_unit:/etc/systemd/system/x.service": "system_unit:/etc/systemd/system/x.service"}
got = {k: d.anonymize_path(k) for k in cases}
R.check("every personal path is anonymised wherever it sits in the string; system paths untouched", got == cases,
        {k: v for k, v in got.items() if v != cases[k]})
R.check("AppImage mounts collapse into one line",
        d.anonymize_list(["/tmp/.mount_kDriveAAA/usr/bin/kDrive", "/tmp/.mount_kDriveBBB/usr/bin/kDrive", "/usr/bin/x"])
        == ["/tmp/.mount_~/usr/bin/kDrive", "/usr/bin/x"])

state = {"trusted_programs": [{"exe": "/home/papa/.steam/steam", "comm": "steam"}],
         "acknowledged_persistence": ["autostart:/home/papa/.config/autostart/kDrive.desktop", "crontab:/var/spool/cron/crontabs/papa"]}
with h.TestDaemon(state=state, tag="tele") as dm:
    payload = dm.request("telemetry_preview", timeout=90).get("payload") or {}
text = json.dumps(payload, ensure_ascii=False)
R.check("the full payload of a running service contains no account name",
        payload and "papa" not in text and payload.get("trusted_programs") == ["/home/~/.steam/steam"], payload.get("acknowledged_persistence"))

# ── report right after an update: a fake local server receives the reports ──
received = []


class Handler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        received.append(json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0))))
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'{"ok":true}')

    def log_message(self, *a):
        pass


srv = http.server.HTTPServer(("127.0.0.1", 0), Handler)
threading.Thread(target=srv.serve_forever, daemon=True).start()
d.TELEMETRY_URL = f"http://127.0.0.1:{srv.server_address[1]}/telemetry.php"


def daemon(state, telemetry=True):
    dm = object.__new__(d.Daemon)
    dm.state, dm.logs = h.St(state), []
    dm.settings = type("S", (), {"get": lambda self, k: telemetry if k == "telemetry" else None})()
    dm.write_log = dm.logs.append
    dm.build_telemetry_payload = lambda: {"install_id": "0" * 32, "version": d.VERSION}
    return dm


recent = (datetime.now() - timedelta(days=1)).isoformat(timespec="seconds")
dm = daemon({"telemetry_sent": recent, "telemetry_version": d.VERSION})
R.check("same version, report sent yesterday: nothing until next week", dm.send_telemetry() is False and not received)
dm = daemon({"telemetry_sent": recent, "telemetry_version": "2.7.8"})
ok = dm.send_telemetry()
R.check("version changed since the last report: sent at once, with the previous version",
        ok and received and received[-1].get("updated_from") == "2.7.8" and dm.state.get("telemetry_version") == d.VERSION, received[-1:])
R.check("…and only once: the next daily check waits for the week again", dm.send_telemetry() is False and len(received) == 1)
dm = daemon({"telemetry_sent": recent})
R.check("install that reported with an older version (no version recorded): sent after the update",
        dm.send_telemetry() and received[-1].get("updated_from") == "before-2.7.10")
dm = daemon({"telemetry_version": "2.7.8"}, telemetry=False)
n = len(received)
R.check("telemetry not accepted: nothing is sent, even after an update", dm.send_telemetry() is False and len(received) == n)
srv.shutdown()

# ── server endpoint (neighbouring web repository) ──
api = os.environ.get("DUKIWI_TEST_API") or os.path.join(os.path.dirname(h.ROOT), "repo", "api")
if not shutil.which("php") or not os.path.isfile(os.path.join(api, "telemetry.php")):
    R.skip("server endpoint telemetry.php", "php or ../repo/api/telemetry.php not found")
else:
    web = h.tmpdir("php")
    shutil.copy(os.path.join(api, "telemetry.php"), web)
    os.makedirs(os.path.join(web, "data"))
    old = {"install_id": "1" * 32, "version": "2.7.3", "acknowledged_persistence": ["crontab:/var/spool/cron/crontabs/papa"]}
    with open(os.path.join(web, "data", f"telemetry-{datetime.utcnow():%Y-%m}.jsonl"), "w") as f:
        f.write(json.dumps(old) + "\n")
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    php = subprocess.Popen(["php", "-S", f"127.0.0.1:{port}"], cwd=web, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        time.sleep(1)
        body = json.dumps({"install_id": "0123456789abcdef0123456789abcdef", "version": "2.7.3", "updated_from": "2.7.2",
                           "acknowledged_persistence": ["autostart:/home/papa/.config/autostart/kDrive.desktop"],
                           "trusted_programs": ["/tmp/.mount_kDriveAAAAAA/usr/bin/kDrive", "/tmp/.mount_kDriveBBBBBB/usr/bin/kDrive"],
                           "not_allowed": "x"}).encode()
        reply = urllib.request.urlopen(urllib.request.Request(f"http://127.0.0.1:{port}/telemetry.php", data=body,
                                                              headers={"Content-Type": "application/json"}), timeout=10).read()
    finally:
        php.terminate()
        php.wait(5)
    rows = [json.loads(x) for x in open(os.path.join(web, "data", f"telemetry-{datetime.utcnow():%Y-%m}.jsonl")) if x.strip()]
    new = rows[-1]
    R.check("server: incoming report anonymised and deduplicated, updated_from kept, unknown fields dropped",
            reply == b'{"ok":true}' and new["trusted_programs"] == ["/tmp/.mount_~/usr/bin/kDrive"]
            and new["acknowledged_persistence"] == ["autostart:/home/~/.config/autostart/kDrive.desktop"]
            and new.get("updated_from") == "2.7.2" and "not_allowed" not in new, new)
    R.check("server: reports stored before are anonymised once (marker file)",
            len(rows) == 2 and rows[0]["acknowledged_persistence"] == ["crontab:/var/spool/cron/crontabs/~"]
            and os.path.exists(os.path.join(web, "data", ".anonymized-v1")), rows[0])
R.done()
