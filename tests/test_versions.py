"""Version comparison (2.7.11): pure Python, same order as dpkg, so it also works on Fedora (no dpkg there).
Fixed cases always run; when dpkg is installed, the result is also compared with dpkg on the installed packages."""
import random
import shutil
import subprocess

import _harness as h

R = h.Results("Version comparison")
d = h.daemon_module()
gt = d.version_gt

cases = [("2.7.10", "2.7.9", True), ("2.7.9", "2.7.10", False), ("1.0", "1.0~rc1", True), ("1.0~rc1", "1.0~~", True),
         ("1.0+dfsg", "1.0", True), ("1.0-1ubuntu1", "1.0-1", True), ("1.0-1ubuntu0.1", "1.0-1", True), ("1:0.9", "2.0", True),
         ("0:1.0", "1.0", False), ("1.0.0", "1.0", True), ("1.00", "1.0", False), ("6.8.0-101.101", "6.8.0-39.39", True),
         ("1.2.3+git20240101", "1.2.3+git20231231", True), ("1.0a", "1.0", True), ("1.0", "1.0", False), ("10", "9.9", True)]
wrong = [(a, b, exp) for a, b, exp in cases if gt(a, b) != exp]
R.check("fixed cases: numeric segments, tilde, epoch, revision, letters", not wrong, wrong)

orig_run = d.run_quiet
d.run_quiet = lambda *a, **k: (_ for _ in ()).throw(AssertionError("version_gt started a process"))
try:
    ok = gt("2.7.10", "2.7.9")
    R.check("no external program is needed (works without dpkg)", ok)
except AssertionError as e:
    R.check("no external program is needed (works without dpkg)", False, e)
finally:
    d.run_quiet = orig_run

if not shutil.which("dpkg") or not shutil.which("dpkg-query"):
    R.skip("same result as dpkg on real versions", "dpkg is not installed")
else:
    real = sorted({v for v in subprocess.run(["dpkg-query", "-W", "-f=${Version}\\n"], capture_output=True, text=True).stdout.split() if v})
    rng = random.Random(7)
    pairs = [tuple(rng.sample(real, 2)) for _ in range(min(800, len(real) * 4))] + [(a, b) for a, b, _ in cases]
    diff = []
    for a, b in pairs:
        for op, fn in (("gt", lambda x, y: d.version_compare(x, y) > 0), ("lt", lambda x, y: d.version_compare(x, y) < 0)):
            exp = subprocess.run(["dpkg", "--compare-versions", a, op, b], capture_output=True).returncode == 0
            if exp != fn(a, b):
                diff.append((a, op, b, exp))
    R.check(f"same result as dpkg on {len(pairs)} pairs of installed package versions (greater and lower)", not diff, diff[:5])
R.done()
