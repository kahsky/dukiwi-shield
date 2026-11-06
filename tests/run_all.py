#!/usr/bin/env python3
"""Run every Dukiwi Shield test and print a summary.

    tests/run_all.py                       # code of the repository
    tests/run_all.py /opt/dukiwi-shield    # installed version
    tests/run_all.py --gui                 # also the tests that open windows (notifications)
    tests/run_all.py test_bursts           # one file (or several)

Exit code 1 if a test fails. No test needs root or touches the state of the installed service.
"""
import glob
import os
import re
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
GUI_ONLY = {"test_popups"}


def main(argv):
    gui = "--gui" in argv
    args = [a for a in argv if a != "--gui"]
    code = next((a for a in args if os.path.isdir(a)), None)
    names = [os.path.splitext(os.path.basename(a))[0] for a in args if not os.path.isdir(a)]
    files = sorted(glob.glob(os.path.join(HERE, "test_*.py")))
    if names:
        files = [f for f in files if os.path.splitext(os.path.basename(f))[0] in names]
    elif not gui:
        files = [f for f in files if os.path.splitext(os.path.basename(f))[0] not in GUI_ONLY]
    env = dict(os.environ)
    if code:
        env["DUKIWI_TEST_CODE"] = os.path.abspath(code)
    total = {"passed": 0, "failed": 0, "skipped": 0}
    failed_files = []
    for f in files:
        name = os.path.basename(f)
        t0 = time.time()
        r = subprocess.run([sys.executable, f], cwd=HERE, env=env, capture_output=True, text=True)
        out = r.stdout + (("\n" + r.stderr) if r.returncode and r.stderr else "")
        m = re.search(r"(\d+) passed, (\d+) failed, (\d+) skipped", r.stdout)
        if m:
            for k, v in zip(("passed", "failed", "skipped"), map(int, m.groups())):
                total[k] += v
        bad = r.returncode != 0 or not m
        if bad:
            failed_files.append(name)
        print(f"{'FAIL' if bad else 'ok  '} {name:28} {m.group(0) if m else 'crashed'}  ({time.time() - t0:.0f} s)", flush=True)
        if bad or "-v" in os.environ.get("DUKIWI_TEST_FLAGS", ""):
            print("\n".join("     " + ln for ln in out.strip().splitlines()[-40:]))
    print(f"\n{total['passed']} passed, {total['failed']} failed, {total['skipped']} skipped"
          + (f" — failing: {', '.join(failed_files)}" if failed_files else ""))
    return 1 if failed_files else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
