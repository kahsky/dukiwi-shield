"""USB media and LD_PRELOAD libraries (2.7.6).

- mount options: UTF-8 file names on FAT / ISO;
- a file name that is not UTF-8 no longer aborts a scan (when clamd answers);
- approval of an LD_PRELOAD library: key = path + content, never the list of programs.
"""
import hashlib
import os
import shutil
import threading
import time

import _harness as h

R = h.Results("USB and LD_PRELOAD")
d = h.daemon_module()
key = d.integrity_ack_key
HEAD = "LD_PRELOAD library injected into process(es):"

# ── mount options ──
calls = []


class Ok:
    returncode, stderr, stdout = 0, "", ""


real_run = d.run_quiet
d.run_quiet = lambda cmd, **k: (calls.append(cmd), Ok())[1]
d.USB_MOUNT_ROOT = h.tmpdir("mnt")
uw = object.__new__(d.UsbWatcher)
uw.lock, uw.mounted = threading.Lock(), {}
opts = {}
for fs in ("vfat", "iso9660", "exfat", "ntfs", "ext4"):
    calls.clear()
    uw.mount({"devnode": "/dev/sdz1", "fstype": fs})
    opts[fs] = calls[0][2].split(",")
d.run_quiet = real_run
R.check("FAT and ISO keys are mounted with UTF-8 file names; other file systems unchanged",
        "utf8" in opts["vfat"] and "umask=077" in opts["vfat"] and "utf8" in opts["iso9660"]
        and opts["exfat"] == ["nosuid", "nodev", "noexec", "nosymfollow", "umask=077"]
        and opts["ext4"] == ["nosuid", "nodev", "noexec", "nosymfollow"], opts)

# ── approval keys ──
a = f"{HEAD}\n/home/u/lib.so (sha256 aaaaaaaaaaaa) <- bash, plank"
b = f"{HEAD}\n/home/u/lib.so (sha256 aaaaaaaaaaaa) <- chrome, claude, plank, xed"
c = f"{HEAD}\n/home/u/lib.so (sha256 bbbbbbbbbbbb) <- bash, plank"
e = f"{HEAD}\n/home/u/other.so (sha256 aaaaaaaaaaaa) <- bash, plank"
R.check("approval key ignores the program list, changes with the file content or the library",
        key("processes", a) == key("processes", b) and len({key("processes", x) for x in (a, c, e)}) == 3)
# Reference keys (2.7.5): approvals already given on users' computers must keep applying
reference = {("processes", "Running process(es) whose executable was deleted from disk:\n1234 foo /tmp/x\n5678 bar /opt/y"): "processes:2201cc0066b24efc",
             ("processes", "Process(es) traced by another program (ptrace):\ngdb (4321) -> victim, other"): "processes:bd5335f1e2145202",
             ("chkrootkit", "WARNING: The following suspicious files were found:\n /usr/lib/x  /usr/lib/y"): "chkrootkit:b125d2a4ba72584a",
             ("lynis", "KRNL-5830: Reboot of system is most likely needed"): "lynis:aa96fed36f39671e"}
R.check("keys of the other integrity warnings are unchanged (existing approvals still apply)",
        all(key(t, x) == k for (t, x), k in reference.items()), {k: key(*tx) for tx, k in reference.items() if key(*tx) != k})

# ── real process watch: an unpackaged preloaded library carried by real processes ──
src_lib = next((p for p in ("/lib/x86_64-linux-gnu/libm.so.6", "/usr/lib64/libm.so.6", "/lib64/libm.so.6", "/usr/lib/libm.so.6") if os.path.exists(p)), None)
if not src_lib:
    R.skip("live process watch", "no libm to copy")
else:
    work = h.home_tmpdir("preload")
    lib = os.path.join(work, "libprobe.so")
    shutil.copy(src_lib, lib)
    bindir = os.path.join(work, "bin")
    os.makedirs(bindir)
    env = dict(os.environ, LD_PRELOAD=lib)

    def warnings_for(path):
        entry = d.builtin_check("processes", {})
        return [w for w in entry["warnings"] if w.startswith("LD_PRELOAD") and path in w], entry

    h.spawn(bindir, "probe-one", env=env)
    ws, entry = warnings_for(lib)
    digest = hashlib.sha256(open(lib, "rb").read()).hexdigest()[:12]
    R.check("one warning per unknown library, carrying the sha256 of the file",
            len(ws) == 1 and f"{lib} (sha256 {digest}) <- " in ws[0] and len(entry["notes"][ws[0]]) == 1, ws)
    k0 = key("processes", ws[0]) if ws else None
    h.spawn(bindir, "probe-two", env=env)
    ws2, _ = warnings_for(lib)
    R.check("a new program carrying the library changes the text but not the key",
            len(ws2) == 1 and "probe-two" in ws2[0] and key("processes", ws2[0]) == k0, ws2)
    with open(lib + ".new", "wb") as f:
        f.write(open(src_lib, "rb").read() + b"\0changed")
    os.replace(lib + ".new", lib)
    ws3, _ = warnings_for(lib)
    R.check("replacing the library file changes its key (approval no longer applies)",
            len(ws3) == 1 and key("processes", ws3[0]) != k0, ws3)

# ── scan of a folder with ISO 8859-1 file names ──
if not os.path.exists("/var/run/clamav/clamd.ctl") and not os.path.exists("/run/clamav/clamd.ctl"):
    R.skip("scan with non-UTF-8 file names", "clamd is not running")
else:
    tree = h.home_tmpdir("latin1")
    open(os.path.join(tree, "ok.txt"), "w").write("plain\n" * 20)
    open(os.path.join(tree.encode(), "r\xc3\xa9sum\xc3\xa9.txt".encode("latin-1")), "w").write("utf-8 name\n" * 20)
    open(os.path.join(tree.encode(), b"caf\xe9 latin1.txt"), "w").write("latin-1 name\n" * 20)
    with h.TestDaemon(tag="scan") as dm:
        r = dm.request("scan", timeout=10, path=tree, nocache=True)
        for _ in range(120):
            time.sleep(0.5)
            if not dm.request("status").get("job"):
                break
        log = dm.log()
        hist = (dm.request("status").get("last_scan") or {})
    R.check("a non-UTF-8 file name no longer aborts the scan: counted as not scanned, the rest is scanned",
            r.get("ok") and "1 file(s) not scanned: file name is not valid UTF-8" in log and "■ done: 0 infected / 2 files" in log
            and "codec can't decode" not in log, {"reply": r, "log": log[-600:]})
R.done()
