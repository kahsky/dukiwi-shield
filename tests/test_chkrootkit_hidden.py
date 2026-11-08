"""chkrootkit hidden files annotated by Debian (2.9.3).

Debian's chkrootkit 0.58b-2 and later append the owning package to each suspicious hidden file:
"/usr/lib/firmware/ath11k/QCN9074/hw1.0/.notice.zst [From Debian package: linux-firmware-qualcomm-wireless]".
The whole line was handed to dpkg -S, which knows no such path: every packaged file became "owned by no package".

- the note is removed and the bare path checked with dpkg → known false positive;
- the note itself is never trusted: a file named after it, owned by no package, stays "to check".
"""
import types

import _harness as h

R = h.Results("chkrootkit hidden files with a package note")
d = h.daemon_module()

FIRMWARE = "/usr/lib/firmware/ath11k/QCN9074/hw1.0/.notice.zst"
FORGED = "/usr/lib/x86_64-linux-gnu/.cache-d"
OUT = [
    "WARNING: The following suspicious files and directories were found:",
    f"{FIRMWARE} [From Debian package: linux-firmware-qualcomm-wireless]",
    "",
]
asked = []


def fake_run(cmd, **k):
    asked.extend(cmd[2:])
    known = {FIRMWARE: "linux-firmware-qualcomm-wireless"}
    out = "\n".join(f"{known[p]}: {p}" for p in cmd[2:] if p in known)
    return types.SimpleNamespace(returncode=0 if out else 1, stdout=out, stderr="")


real_run, real_rpm = d.run_quiet, d.distro.is_rpm
d.run_quiet, d.distro.is_rpm = fake_run, (lambda: False)
try:
    res = d.chkrootkit_analysis(OUT)
    R.check("dpkg is asked about the bare path, without the package note", asked == [FIRMWARE], asked)
    notes = (res["benign"] or [{}])[0].get("notes") or []
    R.check("a packaged hidden file is a known false positive (not a warning)",
            not res["warnings"] and len(res["benign"]) == 1 and notes[0].get("reason") == "dpkg"
            and notes[0].get("package") == "linux-firmware-qualcomm-wireless" and notes[0].get("path") == FIRMWARE, res)

    asked.clear()
    res = d.chkrootkit_analysis([OUT[0], f"{FORGED} [From Debian package: libc6]", ""])
    note = next(iter(res["notes"].values()), [{}])[0]
    R.check("the note alone proves nothing: a file owned by no package stays to check",
            len(res["warnings"]) == 1 and note.get("verdict") == "unknown" and note.get("path") == FORGED, res)

    asked.clear()
    res = d.chkrootkit_analysis([OUT[0], FIRMWARE, ""])
    R.check("older chkrootkit (no note) unchanged", not res["warnings"] and asked == [FIRMWARE], res)
finally:
    d.run_quiet, d.distro.is_rpm = real_run, real_rpm
R.done()
