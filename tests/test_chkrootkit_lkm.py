"""chkrootkit "chkproc: Possible LKM Trojan installed" with no process number (2.9.7).

chkrootkit runs chkproc without -v: it only says that /proc and ps differ, never which process. The only line under
the header was a shell error, "sh: 0: getcwd() failed: No such file or directory", shown as the finding "to check".

- shell error lines are never findings;
- chkproc is run again in verbose mode: nothing hidden any more → known false positive (short-lived process);
- process numbers from the verbose run are classified as before; chkproc missing → still to check.
"""
import _harness as h

R = h.Results("chkrootkit chkproc without process number")
d = h.daemon_module()
HEAD = "WARNING: chkproc: Possible LKM Trojan installed:"
OUT = [HEAD, "sh: 0: getcwd() failed: No such file or directory", ""]
real = d.chkproc_verbose

try:
    d.chkproc_verbose = lambda: (0, "")
    res = d.chkrootkit_analysis(OUT)
    notes = (res["benign"] or [{}])[0].get("notes") or []
    R.check("chkproc finds nothing when run again → known false positive, the shell error is not shown as a finding",
            not res["warnings"] and [n["reason"] for n in notes] == ["lkm_transient"]
            and not any("getcwd" in n["path"] for n in notes), res)

    d.chkproc_verbose = lambda: (1, "PID 4194303(ghost): not in ps output\nYou have 1 process hidden for ps command\n")
    res = d.chkrootkit_analysis(OUT)
    notes = (res["benign"] or [{}])[0].get("notes") or []
    R.check("process number from the verbose run, process gone → classified as before (transient)",
            not res["warnings"] and [n["reason"] for n in notes] == ["pid_transient"], res)

    d.chkproc_verbose = lambda: None
    res = d.chkrootkit_analysis(OUT)
    note = next(iter(res["notes"].values()), [{}])[0]
    R.check("chkproc not found → still to check, named 'chkproc' (not the shell error)",
            len(res["warnings"]) == 1 and note.get("reason") == "lkm" and note.get("path") == "chkproc", res)
finally:
    d.chkproc_verbose = real

res = d.chkrootkit_analysis(["WARNING: chkdirs: Possible LKM Trojan installed:", "sh: 0: getcwd() failed: No such file or directory", ""])
note = next(iter(res["notes"].values()), [{}])[0]
R.check("chkdirs: the shell error is not listed as a hidden folder", len(res["warnings"]) == 1 and note.get("path") == "chkdirs", res)
R.check("shell messages recognised, real paths not",
        all(d.SHELL_NOISE.match(x) for x in ("sh: 0: getcwd() failed: x", "bash: line 1: x", "/bin/sh: 1: ps: not found"))
        and not d.SHELL_NOISE.match("/usr/lib/.sh: x"))
R.done()
