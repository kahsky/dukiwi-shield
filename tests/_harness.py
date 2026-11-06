"""Shared harness of the Dukiwi Shield tests.

Code under test: the repository root, or the folder named by DUKIWI_TEST_CODE (for example /opt/dukiwi-shield for the
installed version). No test needs root or touches the state of the installed service: each test file works in its own
temporary folders (state, log, socket) and runs the service there in test mode.
"""

import atexit
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CODE = os.path.abspath(os.environ.get("DUKIWI_TEST_CODE") or ROOT)


def tmpdir(tag):
    """Temporary folder, removed when the test file ends."""
    d = tempfile.mkdtemp(prefix=f"dukiwi-test-{tag}-")
    atexit.register(shutil.rmtree, d, True)
    return d


def home_tmpdir(tag):
    """Temporary folder inside the home folder (not /tmp, not ~/.cache): some rules of the service treat a program run
    from a temporary folder differently, and a scan is only allowed under the home folder."""
    base = os.path.expanduser("~/.local/state")
    os.makedirs(base, exist_ok=True)
    d = tempfile.mkdtemp(prefix=f"dukiwi-test-{tag}-", dir=base)
    atexit.register(shutil.rmtree, d, True)
    return d


_ISOLATED = None


def isolate(tag):
    """Private state and log folders and socket for this process. Call it before loading the code."""
    global _ISOLATED
    if _ISOLATED is None:
        _ISOLATED = tmpdir(tag)
        for sub in ("st", "lg"):
            os.makedirs(os.path.join(_ISOLATED, sub))
        os.environ.update(DUKIWI_SHIELD_STATE_DIR=_ISOLATED + "/st", DUKIWI_SHIELD_LOG_DIR=_ISOLATED + "/lg",
                          DUKIWI_SHIELD_SOCKET=_ISOLATED + "/d.sock")
        if CODE not in sys.path:
            sys.path.insert(0, CODE)
    return _ISOLATED


_MODULES = {}


def load(filename, name):
    """Load a file of the code under test as a module (the service is dukiwi-shield-daemon.py, with dashes)."""
    isolate("code")
    if name not in _MODULES:
        spec = importlib.util.spec_from_file_location(name, os.path.join(CODE, filename))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        _MODULES[name] = mod
    return _MODULES[name]


def daemon_module():
    return load("dukiwi-shield-daemon.py", "dukiwi_shield_daemon_under_test")


class Results:
    """Counts the tests of one file; done() exits with code 1 if a test failed."""

    def __init__(self, title):
        self.passed = self.failed = self.skipped = 0
        print(f"## {title}  [{CODE}]", flush=True)

    def check(self, name, ok, detail=""):
        ok = bool(ok)
        self.passed += ok
        self.failed += not ok
        print(("PASS" if ok else "FAIL"), "-", name, ("| " + str(detail)[:600]) if detail and not ok else "", flush=True)
        return ok

    def skip(self, name, why):
        self.skipped += 1
        print("SKIP -", name, "|", why, flush=True)

    def done(self):
        print(f"{self.passed} passed, {self.failed} failed, {self.skipped} skipped", flush=True)
        sys.exit(1 if self.failed else 0)


class St(dict):
    """In-memory service state (same interface as State.get / State.update)."""

    def update(self, **kw):
        dict.update(self, kw)


class TestDaemon:
    """Service started without privileges (test mode) on a given starting state, in its own folders:

        with TestDaemon(state={...}) as dm:
            dm.request("status")
    """

    def __init__(self, state=None, settings=None, tag="daemon", env=None):
        self.w = tmpdir(tag)
        for sub in ("st", "lg"):
            os.makedirs(os.path.join(self.w, sub))
        if state is not None:
            with open(os.path.join(self.w, "st", "state.json"), "w") as f:
                json.dump(state, f)
        if settings is not None:
            with open(os.path.join(self.w, "st", "settings.json"), "w") as f:
                json.dump(settings, f)
        self.sock = os.path.join(self.w, "d.sock")
        self.env = dict(os.environ, DUKIWI_SHIELD_STATE_DIR=self.w + "/st", DUKIWI_SHIELD_LOG_DIR=self.w + "/lg",
                        DUKIWI_SHIELD_SOCKET=self.sock, **(env or {}))
        self.proc = None

    def __enter__(self):
        self.out = open(os.path.join(self.w, "daemon.out"), "w")
        self.proc = subprocess.Popen([sys.executable, os.path.join(CODE, "dukiwi-shield-daemon.py")], env=self.env,
                                     stdout=self.out, stderr=subprocess.STDOUT, start_new_session=True)
        deadline = time.time() + 30
        while time.time() < deadline:
            if self.proc.poll() is not None:
                raise RuntimeError("the test service stopped while starting:\n" + self.output()[-2000:])
            if os.path.exists(self.sock) and self.request("status", timeout=5).get("ok"):
                return self
            time.sleep(0.3)
        self.__exit__(None, None, None)
        raise RuntimeError("the test service does not answer")

    def __exit__(self, *_exc):
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(10)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(5)
        self.out.close()

    def request(self, cmd, timeout=20, **kwargs):
        common = load("dukiwi_shield_common.py", "dukiwi_shield_common_under_test")
        common.DAEMON_SOCKET = self.sock
        try:
            return common.daemon_request(cmd, timeout=timeout, **kwargs)
        except OSError as e:
            return {"ok": False, "error": f"socket: {e}"}

    def log(self):
        try:
            with open(os.path.join(self.w, "lg", "scan.log"), errors="replace") as f:
                return f.read()
        except OSError:
            return ""

    def output(self):
        try:
            with open(os.path.join(self.w, "daemon.out"), errors="replace") as f:
                return f.read()
        except OSError:
            return ""


def spawn(exe_dir, name, seconds=30, env=None):
    """Process named `name` (a copy of sleep) run from `exe_dir`, a real program for the watchers to observe."""
    exe = os.path.join(exe_dir, name)
    if not os.path.exists(exe):
        shutil.copy("/bin/sleep", exe)
    p = subprocess.Popen([exe, str(seconds)], env=env)
    atexit.register(lambda: p.poll() is None and p.kill())
    time.sleep(0.3)
    return p
