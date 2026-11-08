"""chkrootkit "Possible Linux BPFDoor Malware installed" (2.9.5).

chkrootkit runs `egrep packet_recvmsg /proc/*/stack`, which also matches unix_seqpacket_recvmsg: Claude Desktop's
sandbox broker (any program waiting on a local UNIX socket) was reported as BPFDoor. BPFDoor waits on a raw packet
socket, so its stack shows packet_recvmsg itself.

- unix_seqpacket_recvmsg only → known false positive, the program is named;
- packet_recvmsg (raw socket) → still a warning, also when listed next to a benign one;
- unreadable line → still a warning.
"""
import os
import sys

import _harness as h

R = h.Results("chkrootkit BPFDoor rule")
d = h.daemon_module()
HEAD = "WARNING: Possible Linux BPFDoor Malware installed:"
me = os.getpid()

res = d.chkrootkit_analysis([HEAD, f"/proc/{me}/stack:[<0>] unix_seqpacket_recvmsg+0x3d/0x60", ""])
notes = (res["benign"] or [{}])[0].get("notes") or []
R.check("process waiting on a UNIX seqpacket socket → known false positive, program named",
        not res["warnings"] and len(notes) == 1 and notes[0]["reason"] == "bpfdoor_unix"
        and os.readlink(f"/proc/{me}/exe") in notes[0]["path"], res)

res = d.chkrootkit_analysis([HEAD, f"/proc/{me}/stack:[<0>] unix_seqpacket_recvmsg+0x3d/0x60",
                             "/proc/4242/stack:[<0>] packet_recvmsg+0x6e/0x90", ""])
verdicts = next(iter(res["notes"].values()), [])
R.check("a raw packet socket (packet_recvmsg) stays a warning, even next to a benign one",
        len(res["warnings"]) == 1 and [n["verdict"] for n in verdicts] == ["benign", "unknown"]
        and verdicts[1]["reason"] == "bpfdoor", res)

res = d.chkrootkit_analysis([HEAD, "/proc/4242/stack: something else", ""])
R.check("a line that cannot be read stays a warning", len(res["warnings"]) == 1, res)
tables = sys.modules["dukiwi_shield_common"].load_i18n()
missing = [lang for lang, table in tables.items() if "security.integrity.reason.bpfdoor_unix" not in table
           or "security.integrity.reason.bpfdoor" not in table]
R.check("both reasons translated in every language", len(tables) == 4 and not missing, missing)
R.done()
