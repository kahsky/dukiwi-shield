#!/usr/bin/env python3
"""
Dukiwi Shield — dossiers protégés (service système, désactivé par défaut).

Seuls les programmes approuvés peuvent ouvrir les fichiers des dossiers protégés (Documents, Images, Bureau et les
dossiers ajoutés) : programmes des paquets du système, /opt, snap, Flatpak, et ceux que l'utilisateur a autorisés.
Un programme déposé dans /tmp, dans un dossier personnel ou dans /usr/local, ou un interpréteur (python, bash…) qui
exécute un script venu d'un tel endroit, reçoit « permission refusée » et une alerte propose de l'autoriser.

Linux ne permet pas de bloquer seulement les écritures : la décision se prend à l'ouverture du fichier (fanotify,
FAN_OPEN_PERM), lecture comme écriture. Pendant la décision le programme attend ; le fil qui décide ne lit donc que
/proc, ne prend aucun verrou partagé et autorise en cas d'erreur. Un auto-test à chaque activation (programme du
système autorisé, copie hors système refusée, aucune attente) désactive la protection si quelque chose cloche.
(c) 2026 Dukiwi SA - Estavayer-le-Lac
"""

import ctypes
import os
import queue
import select
import shutil
import struct
import subprocess
import threading
import time

FAN_CLOEXEC = 0x01
FAN_NONBLOCK = 0x02
FAN_CLASS_CONTENT = 0x04
FAN_UNLIMITED_QUEUE = 0x10
FAN_UNLIMITED_MARKS = 0x20
FAN_MARK_ADD = 0x01
FAN_MARK_FLUSH = 0x80
FAN_OPEN_PERM = 0x00010000
FAN_EVENT_ON_CHILD = 0x08000000
FAN_ALLOW = 0x01
FAN_DENY = 0x02
AT_FDCWD = -100
O_LARGEFILE = 0o100000
EVENT = struct.Struct("=IBBHQii")            # event_len, vers, reserved, metadata_len, mask, fd, pid
RESPONSE = struct.Struct("=iI")               # fd, response

TRUSTED_PREFIXES = ("/usr/", "/bin/", "/sbin/", "/lib/", "/lib64/", "/opt/", "/snap/", "/app/", "/var/lib/flatpak/",
                    "/var/lib/snapd/", "/nix/store/")
UNTRUSTED_PREFIXES = ("/usr/local/", "/tmp/", "/var/tmp/", "/dev/shm/", "/run/", "/home/", "/root/", "/media/", "/mnt/")
INTERPRETERS = ("python", "perl", "ruby", "node", "bash", "sh", "dash", "zsh", "php", "lua", "java")
RESCAN_SEC = 120
ALERT_COOLDOWN = 600


class ProtectedFolders(threading.Thread):
    def __init__(self, daemon, helpers):
        super().__init__(daemon=True, name="protected-folders")
        self.d = daemon
        self.log = helpers["log"]
        self.write_log = helpers["write_log"]
        self.fd = None
        self.active = False
        self.allowed = set()                      # exécutables autorisés (copie lue par le fil de décision)
        self.verdicts = {}                        # (exe, script) → bool, cache du fil de décision
        self.pending_alerts = queue.Queue()
        self.alerted = {}
        self.marked = 0
        self.roots = []
        self.stop_event = threading.Event()
        self.reload = threading.Event()
        self.self_pid = os.getpid()
        self.test_pids = {}                       # pid de l'auto-test → résultat attendu
        self.status = {"active": False, "tested": False, "error": "", "marked": 0, "denied": 0}
        self.libc = None

    # ── réglage ──────────────────────────────────────────────────────────
    def enabled(self):
        return self.d.settings.get("protected_folders") is True

    def protected_roots(self):
        roots = list(self.d.state.get("protected_extra") or [])
        for pw in self.d_users():
            for key, default in (("DOCUMENTS", "Documents"), ("PICTURES", "Pictures"), ("DESKTOP", "Desktop")):
                p = xdg_dir(pw, key, default)
                if p and os.path.isdir(p):
                    roots.append(p)
        return sorted({os.path.realpath(r) for r in roots if os.path.isdir(r)})

    def d_users(self):
        return [pw for pw in self.d_human_users() if pw.pw_uid >= 1000]

    def d_human_users(self):
        import pwd
        return [pw for pw in pwd.getpwall() if pw.pw_uid >= 1000 and pw.pw_dir.startswith("/home/") and os.path.isdir(pw.pw_dir)]

    def refresh_allowed(self):
        # Seulement les programmes autorisés pour les dossiers protégés (par un administrateur) : la liste générale des
        # programmes de confiance se modifie sans mot de passe, un programme malveillant pourrait s'y inscrire lui-même.
        allowed = set(self.d.state.get("protected_allowed") or [])
        self.allowed = allowed
        self.verdicts = {}

    # ── fanotify ─────────────────────────────────────────────────────────
    def open_group(self):
        self.libc = ctypes.CDLL(None, use_errno=True)
        self.libc.fanotify_init.argtypes = [ctypes.c_uint, ctypes.c_uint]
        self.libc.fanotify_mark.argtypes = [ctypes.c_int, ctypes.c_uint, ctypes.c_uint64, ctypes.c_int, ctypes.c_char_p]
        fd = self.libc.fanotify_init(FAN_CLASS_CONTENT | FAN_CLOEXEC | FAN_NONBLOCK | FAN_UNLIMITED_QUEUE | FAN_UNLIMITED_MARKS,
                                     os.O_RDONLY | O_LARGEFILE | os.O_CLOEXEC)
        if fd < 0:
            raise OSError(ctypes.get_errno(), "fanotify_init")
        return fd

    def mark_tree(self, root, limit=200000):
        """Marque chaque dossier de l'arbre : les ouvertures de fichiers de ses enfants passent par la décision."""
        n = 0
        for dirpath, dirs, _files in os.walk(root):
            dirs[:] = [d for d in dirs if not os.path.islink(os.path.join(dirpath, d))]
            if self.libc.fanotify_mark(self.fd, FAN_MARK_ADD, FAN_OPEN_PERM | FAN_EVENT_ON_CHILD, AT_FDCWD, dirpath.encode()) == 0:
                n += 1
            if n >= limit:
                break
        return n

    def mark_all(self):
        self.roots = self.protected_roots()
        total = 0
        for r in self.roots:
            total += self.mark_tree(r)
        self.marked = total
        self.status["marked"] = total
        return total

    # ── décision (fil critique : /proc seulement, jamais de fichier des dossiers protégés) ──
    def trusted(self, pid):
        if pid == self.self_pid:
            return True
        expected = self.test_pids.get(pid)
        try:
            exe = os.readlink(f"/proc/{pid}/exe")
        except OSError:
            return True if expected is None else expected     # processus déjà terminé : rien à protéger
        deleted = exe.endswith(" (deleted)")
        exe = exe.replace(" (deleted)", "")
        if exe.startswith("/tmp/.mount_"):
            exe = appimage_of(pid) or exe                 # AppImage : identifiée par son fichier .AppImage, pas par le montage
        script = ""
        base = os.path.basename(exe)
        if base.startswith(INTERPRETERS):
            try:
                with open(f"/proc/{pid}/cmdline", "rb") as f:
                    args = [a.decode(errors="replace") for a in f.read().split(b"\0") if a]
                script = next((a for a in args[1:] if a.startswith("/") and not a.startswith("-")), "")
            except OSError:
                script = ""
        key = (exe, script, deleted)
        verdict = self.verdicts.get(key)
        if verdict is None:
            if exe in self.allowed or (script and script in self.allowed):
                verdict = True
            elif deleted:
                verdict = False
            elif script and script.startswith(("/tmp/", "/var/tmp/", "/dev/shm/")):
                verdict = False                           # interpréteur du système, script déposé dans un dossier temporaire
            elif exe.startswith(TRUSTED_PREFIXES) and not exe.startswith("/usr/local/"):
                verdict = True
            elif exe.startswith(UNTRUSTED_PREFIXES):
                verdict = False
            else:
                verdict = True                            # emplacement inhabituel mais pas suspect (ex. /srv) : pas de blocage
            if len(self.verdicts) > 5000:
                self.verdicts = {}
            self.verdicts[key] = verdict
        if not verdict:
            self.pending_alerts.put((pid, exe + (" (deleted)" if deleted else ""), script))
        return verdict

    def respond(self, fd, allow):
        try:
            os.write(self.fd, RESPONSE.pack(fd, FAN_ALLOW if allow else FAN_DENY))
        except OSError:
            pass

    def loop(self):
        poller = select.poll()
        poller.register(self.fd, select.POLLIN)
        last_rescan = time.time()
        while not self.stop_event.is_set() and not self.d.shutdown.is_set():
            if not self.enabled():
                break
            if self.reload.is_set() or time.time() - last_rescan > RESCAN_SEC:
                self.reload.clear()
                last_rescan = time.time()
                self.refresh_allowed()
                threading.Thread(target=self.mark_all, daemon=True, name="protected-mark").start()   # nouveaux sous-dossiers
            if not poller.poll(1000):
                continue
            try:
                buf = os.read(self.fd, 65536)
            except BlockingIOError:
                continue
            except OSError:
                break
            off = 0
            while off + EVENT.size <= len(buf):
                event_len, _v, _r, _ml, mask, fd, pid = EVENT.unpack_from(buf, off)
                if event_len < EVENT.size:
                    break
                off += event_len
                if fd < 0:
                    continue
                allow = True
                try:
                    if mask & FAN_OPEN_PERM:
                        allow = self.trusted(pid)
                except Exception:  # noqa: BLE001
                    allow = True                          # jamais de blocage sur une erreur du service
                finally:
                    if mask & FAN_OPEN_PERM:
                        self.respond(fd, allow)
                    os.close(fd)
                if not allow:
                    self.status["denied"] += 1

    # ── alertes (hors du fil critique) ───────────────────────────────────
    def alert_worker(self):
        while not self.d.shutdown.is_set():
            try:
                pid, exe, script = self.pending_alerts.get(timeout=2)
            except queue.Empty:
                continue
            if pid in self.test_pids or exe.startswith("/tmp/.dukiwi-protected-test"):
                continue
            key = script or exe
            now = time.time()
            if now - self.alerted.get(key, 0) < ALERT_COOLDOWN:
                continue
            self.alerted[key] = now
            try:
                with open(f"/proc/{pid}/comm") as f:
                    comm = f.read().strip()
            except OSError:
                comm = os.path.basename(exe)
            self.write_log(f"⚠ protected folders: blocked {comm} (pid {pid}, {exe}{' ' + script if script else ''})")
            self.d.publish_alert({"kind": "protected", "severity": "warn", "time": time.strftime("%Y-%m-%dT%H:%M:%S"), "pid": pid,
                                  "comm": comm, "exe": exe, "script": script, "title": comm, "detail": script or exe,
                                  "count": 0, "top_dir": "", "reasons": ["protected_blocked"], "sample": []})

    # ── auto-test ────────────────────────────────────────────────────────
    def self_test(self):
        """Un programme du système doit lire un fichier protégé, une copie hors système ne doit pas ; sans attente."""
        base = "/var/lib/dukiwi-shield/protected-test"
        os.makedirs(base, exist_ok=True)
        probe = os.path.join(base, "probe.txt")
        with open(probe, "w") as f:
            f.write("dukiwi")
        if self.libc.fanotify_mark(self.fd, FAN_MARK_ADD, FAN_OPEN_PERM | FAN_EVENT_ON_CHILD, AT_FDCWD, base.encode()) != 0:
            return False, "mark_failed"
        cat = shutil.which("cat") or "/usr/bin/cat"
        rogue = "/tmp/.dukiwi-protected-test"
        shutil.copy2(cat, rogue)
        try:
            ok_allowed = self._run_test([cat, probe], expect=True)
            ok_denied = self._run_test([rogue, probe], expect=False)
        finally:
            try:
                os.unlink(rogue)
            except OSError:
                pass
        if ok_allowed is None or ok_denied is None:
            return False, "timeout"
        if not ok_allowed:
            return False, "allowed_blocked"
        if not ok_denied:
            return False, "not_blocking"
        return True, ""

    def _run_test(self, cmd, expect):
        try:
            p = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except OSError:
            return None
        self.test_pids[p.pid] = expect
        try:
            rc = p.wait(timeout=8)
        except subprocess.TimeoutExpired:
            p.kill()
            return None
        finally:
            self.test_pids.pop(p.pid, None)
        return (rc == 0) == expect

    # ── cycle de vie ─────────────────────────────────────────────────────
    def run(self):
        threading.Thread(target=self.alert_worker, daemon=True, name="protected-alerts").start()
        while not self.d.shutdown.is_set():
            if not self.enabled():
                self.d.shutdown.wait(5)
                continue
            self.start_protection()
            if self.active:
                self.loop()
            self.stop_protection()
            self.d.shutdown.wait(5)                       # pas de boucle serrée si le groupe fanotify tombe

    def start_protection(self):
        self.stop_event.clear()
        self.status.update(active=False, tested=False, error="")
        try:
            self.fd = self.open_group()
        except OSError as e:
            self.status["error"] = f"fanotify: {e.strerror or e}"
            self.log(f"Dossiers protégés indisponibles : {e}")
            self.d.shutdown.wait(300)
            return
        self.refresh_allowed()
        # Le fil de décision doit tourner pendant l'auto-test (sinon le test attendrait sa propre réponse)
        tester = threading.Thread(target=self.loop, daemon=True, name="protected-test-loop")
        tester.start()
        ok, err = False, "internal"
        try:
            ok, err = self.self_test()
        except Exception as e:  # noqa: BLE001
            err = str(e)[:80]
        self.stop_event.set()
        tester.join(timeout=3)
        self.stop_event.clear()
        self.status.update(tested=True, error=err)
        if not ok:
            self.log(f"Dossiers protégés : auto-test en échec ({err}) — protection désactivée")
            self.write_log(f"⚠ protected folders self-test failed ({err}): protection turned off")
            self._close()
            self.d.settings.update({"protected_folders": False})
            self.d.publish_alert({"kind": "protected", "severity": "warn", "time": time.strftime("%Y-%m-%dT%H:%M:%S"), "pid": 0, "comm": "",
                                  "exe": "", "title": "", "detail": err, "count": 0, "top_dir": "", "reasons": ["protected_selftest_failed"], "sample": []})
            return
        n = self.mark_all()
        self.active = True
        self.status["active"] = True
        self.write_log(f"protected folders on: {len(self.roots)} folder(s), {n} directories marked")
        self.log(f"Dossiers protégés actifs : {', '.join(self.roots)} ({n} dossiers)")

    def stop_protection(self):
        if self.fd is not None:
            self.write_log("protected folders off")
        self._close()

    def _close(self):
        self.active = False
        self.status["active"] = False
        if self.fd is not None:
            try:
                os.close(self.fd)                         # le noyau autorise toute ouverture encore en attente
            except OSError:
                pass
            self.fd = None

    def snapshot(self):
        return dict(self.status, roots=self.roots or self.protected_roots(), allowed=sorted(self.d.state.get("protected_allowed") or []),
                    extra=list(self.d.state.get("protected_extra") or []), enabled=self.enabled())


def appimage_of(pid):
    try:
        with open(f"/proc/{pid}/environ", "rb") as f:
            for item in f.read().split(b"\0"):
                if item.startswith(b"APPIMAGE="):
                    return item[9:].decode(errors="replace")
    except OSError:
        pass
    return ""


def xdg_dir(pw, key, default):
    try:
        with open(os.path.join(pw.pw_dir, ".config", "user-dirs.dirs")) as f:
            for ln in f:
                if ln.strip().startswith(f"XDG_{key}_DIR="):
                    path = ln.split("=", 1)[1].strip().strip('"').replace("$HOME", pw.pw_dir)
                    return path if path.rstrip("/") != pw.pw_dir.rstrip("/") else ""
    except OSError:
        pass
    return os.path.join(pw.pw_dir, default)
