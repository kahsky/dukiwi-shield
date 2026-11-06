"""2.9.0 security fixes: the root service never writes, reads or moves files in a folder a user controls through a
symbolic link (Firefox user.js, authorized_keys, quarantine restore, USB manifest, on-access quarantine)."""
import json
import os

import _harness as h

R = h.Results("2.9.0 security")
d = h.daemon_module()
c = h.load("dukiwi_shield_common.py", "dukiwi_shield_common_under_test")
hy = h.load("dukiwi_shield_hygiene.py", "dukiwi_shield_hygiene_under_test")

w = h.tmpdir("sec")
victim = os.path.join(w, "victim")          # stands for /etc/passwd
with open(victim, "w") as f:
    f.write("root:x:0:0\n")


def victim_intact():
    with open(victim) as f:
        return f.read() == "root:x:0:0\n"


# ── 1. Atomic write: never through a link planted at the temporary name ──
target = os.path.join(w, "user.js")
os.symlink(victim, os.path.join(w, f".user.js.dukiwi-{os.getpid()}"))
try:
    c.write_file_atomic(target, "evil\n")
    raised = False
except OSError:
    raised = True
R.check("write_file_atomic refuses a symbolic link at its temporary name (no write through it)",
        raised and victim_intact() and not os.path.exists(target))
os.unlink(os.path.join(w, f".user.js.dukiwi-{os.getpid()}"))
c.write_file_atomic(target, "ok\n", 0o600)
R.check("write_file_atomic writes the file with the requested mode",
        open(target).read() == "ok\n" and (os.stat(target).st_mode & 0o777) == 0o600)

# ── 2. Firefox user.js: a link instead of user.js is refused (it pointed root's read at /etc/shadow) ──
prof = os.path.join(w, "ff")
os.makedirs(prof)
os.symlink(victim, os.path.join(prof, "user.js"))
try:
    hy.firefox_user_js(prof, True)
    raised = False
except OSError:
    raised = True
R.check("Firefox hardening refuses a user.js that is a symbolic link", raised and victim_intact())
os.unlink(os.path.join(prof, "user.js"))
with open(os.path.join(prof, "user.js"), "w") as f:
    f.write('user_pref("a", 1);\n')
hy.firefox_user_js(prof, True)
on = open(os.path.join(prof, "user.js")).read()
hy.firefox_user_js(prof, False)
off = open(os.path.join(prof, "user.js")).read()
R.check("Firefox hardening adds then removes its block, keeping the user's own lines",
        hy.FIREFOX_MARK_BEGIN in on and 'user_pref("a", 1);' in on and off == 'user_pref("a", 1);\n', (on, off))
uid, gid = os.getuid(), os.getgid()
R.check("firefox_harden runs through run_as_user (child process) and works for the current user",
        hy.firefox_harden(prof, type("P", (), {"pw_uid": uid, "pw_gid": gid})()) is True
        and hy.FIREFOX_MARK_BEGIN in open(os.path.join(prof, "user.js")).read())

# ── 3. authorized_keys: lines dropped by text, links refused ──
ak = os.path.join(w, "authorized_keys")
with open(ak, "w") as f:
    f.write("ssh-ed25519 AAAA one\nssh-ed25519 BBBB two\n")
os.chmod(ak, 0o600)
n = c.drop_lines(ak, ["ssh-ed25519 AAAA one"], 0o600)
R.check("drop_lines removes the given line and keeps the mode",
        n == 1 and open(ak).read() == "ssh-ed25519 BBBB two\n" and (os.stat(ak).st_mode & 0o777) == 0o600)
link = os.path.join(w, "ak_link")
os.symlink(victim, link)
try:
    c.drop_lines(link, ["root:x:0:0"], 0o600)
    raised = False
except OSError:
    raised = True
R.check("drop_lines refuses a symbolic link", raised and victim_intact())

# ── 4. Quarantine restore: copy made by the user, never through a link in the chosen folder ──
dest = os.path.join(w, "restore")
os.makedirs(dest)
src_file = os.path.join(w, "qfile")
with open(src_file, "w") as f:
    f.write("payload")
os.symlink(victim, os.path.join(dest, "passwd"))
fd = os.open(src_file, os.O_RDONLY)
try:
    got = c.run_as_user(uid, gid, "dukiwi_shield_common", "restore_copy", fd, dest, "passwd", pass_fds=(fd,))
finally:
    os.close(fd)
R.check("restore_copy never writes through a link named like the file: a new name is used",
        got == os.path.join(dest, "passwd.1") and open(got).read() == "payload" and victim_intact(), got)
try:
    c.run_as_user(uid + 1, gid, "dukiwi_shield_common", "drop_lines", ak, [], 0o600)
    raised = False
except PermissionError:
    raised = True
R.check("run_as_user refuses to act as another user when not root", raised or os.geteuid() == 0)

# ── 5. USB manifest: no link followed on the drive ──
mnt = os.path.join(w, "usb")
os.makedirs(mnt)
os.symlink(victim, os.path.join(mnt, d.USB_MANIFEST + ".tmp"))
ok = d.usb_manifest_write(mnt, {"a.txt": [1, 2]}, "db", [])
R.check("USB manifest: a link planted at the temporary name is replaced, never written through",
        ok and victim_intact() and not os.path.islink(os.path.join(mnt, d.USB_MANIFEST))
        and d.usb_manifest_read(mnt) is not None)
os.unlink(os.path.join(mnt, d.USB_MANIFEST))
os.symlink(victim, os.path.join(mnt, d.USB_MANIFEST))
R.check("USB manifest: a manifest that is a symbolic link is ignored", d.usb_manifest_read(mnt) is None)

# ── 6. On-access quarantine: the file is isolated only if it still is the scanned one ──
qdir = os.path.join(w, "quarantine")
d.SYSTEM_QUARANTINE_DIR = qdir
logs = []
dm = object.__new__(d.Daemon)
dm.write_log = logs.append
scanner = object.__new__(d.OnAccessScanner)
scanner.daemon_ref = dm
dl = os.path.join(w, "Downloads")
os.makedirs(dl)
bad = os.path.join(dl, "eicar.txt")
with open(bad, "w") as f:
    f.write("infected")
st = os.lstat(bad)
q = scanner.quarantine(bad, st)
R.check("on-access quarantine copies the scanned file into quarantine and removes the original",
        q and open(q).read() == "infected" and not os.path.exists(bad)
        and (os.stat(q).st_mode & 0o777) == 0o600, (q, logs))
with open(bad, "w") as f:
    f.write("infected")
st = os.lstat(bad)
os.unlink(bad)
os.symlink(victim, bad)
R.check("on-access quarantine refuses a file swapped for a link after the scan", scanner.quarantine(bad, st) == "" and victim_intact())
os.unlink(bad)
with open(bad, "w") as f:
    f.write("infected")
st = os.lstat(bad)
os.rename(bad, os.path.join(w, "kept"))      # kept alive so its inode number is not reused by the new file
with open(bad, "w") as f:
    f.write("other file")
R.check("on-access quarantine refuses a file replaced by another one after the scan",
        scanner.quarantine(bad, st) == "" and os.path.exists(bad))
idx = c.quarantine_index_load(qdir)
R.check("quarantine index records the owner of each isolated file",
        any(v.get("owner") == uid for v in idx.values()), idx)

# ── 8. Trust: scripts judged by their file, interpreters never trusted or learned ──
R.check("a script is identified from the interpreter's arguments; inline code and stdin give nothing to trust",
        d.script_of(["/usr/bin/python3", "-u", "x.py"], "/home/u") == "/home/u/x.py"
        and d.script_of(["python3", "-c", "import os"]) == "" and d.script_of(["python3", "-", "/usr/bin/dpkg"]) == ""
        and d.script_of(["/bin/sh", "-e", "/var/lib/dpkg/info/a.postinst"]) == "/var/lib/dpkg/info/a.postinst")
R.check("interpreters are recognised (python3.12, node, bash) and never become a habit",
        d.is_interpreter("/usr/bin/python3.12") and d.is_interpreter("/usr/bin/node") and not d.is_interpreter("/usr/bin/kdrive")
        and d.Daemon.habit_key("/usr/bin/python3.12", "/home/u/Documents") == "")
R.check("a file in a home folder is never root's; a system binary is", not d.root_owned_chain(victim) and d.root_owned_chain("/usr/bin/env"))
dm2 = object.__new__(d.Daemon)
dm2.central_patterns = ["/home/*/.local/bin/claude", "/home/*/.steam/*"]
R.check("central allowlist patterns of home folders never make a program trusted",
        not dm2.central_trusted(os.path.expanduser("~/.local/bin/claude")) and not dm2.central_trusted("/home/u/.steam/x"))

# ── 7. Socket: wiping the evidence needs the administrator; a process the caller does not own is refused ──
with h.TestDaemon(tag="sec-daemon") as dm:
    R.check("clear_log and clear_alerts ask for the administrator",
            dm.request("clear_log").get("error") == "admin_required" and dm.request("clear_alerts").get("error") == "admin_required")
    R.check("restoring browser policies system-wide (remove) asks for the administrator",
            dm.request("browser_harden", remove=True).get("error") == "admin_required")
    R.check("Timeshift on a drive chosen by the caller asks for the administrator",
            dm.request("timeshift_enable", device_uuid="X").get("error") == "admin_required")

R.done()
