#!/usr/bin/env python3
"""Build the Debian changelog of the package from the "Features" list of README.md.

    tools/changelog.py VERSION > changelog

Every entry that names a version ("- **2.7.11: title** — text" or "- **Title (2.5.1)** — text") becomes one
changelog version, newest first. The date is the one of the commit that added the entry to README.md (now when it is
not committed yet). An entry is required for VERSION; the build stops if it is missing.
"""
import email.utils
import os
import re
import subprocess
import sys
import textwrap
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MAINTAINER = "Dukiwi SA <info@dukiwi.com>"
SUITE = "noble"
VERSION_RE = re.compile(r"^(?:(\d+\.\d+(?:\.\d+)?):\s*(.+)|(.+?)\s*\((\d+\.\d+(?:\.\d+)?)\)|Dukiwi Shield (\d+\.\d+(?:\.\d+)?))$")


def full(v):
    return v if v.count(".") == 2 else v + ".0"


def entries(readme):
    """[(version, title, text, head snippet)] in README order (newest first)."""
    text = readme.split("\n## Features", 1)[1].split("\n## ", 1)[0]
    out = []
    for block in re.split(r"\n(?=- \*\*)", text):
        m = re.match(r"- \*\*(.+?)\*\*\s*(?:—\s*)?(.*)", block, re.S)
        if not m:
            continue
        head, body = " ".join(m.group(1).split()), " ".join(m.group(2).split())
        v = VERSION_RE.match(head)
        if not v:
            continue
        version = full(v.group(1) or v.group(4) or v.group(5))
        title = (v.group(2) or v.group(3) or "Dukiwi Shield " + version).strip()
        out.append((version, title, body, block[4:4 + 40].split("\n")[0]))
    return out


def added_date(snippet):
    """RFC 2822 date of the commit that added `snippet` to README.md, or now."""
    r = subprocess.run(["git", "-C", ROOT, "log", "--reverse", "--format=%aD", "-S", snippet, "--", "README.md"],
                       capture_output=True, text=True)
    dates = r.stdout.split("\n")
    return dates[0].strip() if r.returncode == 0 and dates[0].strip() else email.utils.formatdate(time.time(), localtime=True)


def render(version_wanted):
    readme = open(os.path.join(ROOT, "README.md"), encoding="utf-8").read()
    items, seen = [], set()
    for version, title, body, snippet in entries(readme):
        if version in seen:
            continue
        seen.add(version)
        items.append((version, title, body, snippet))
    if version_wanted not in seen:
        sys.exit(f"changelog: no README entry for {version_wanted} (add a '- **{version_wanted}: …**' line under ## Features)")
    out = []
    for version, title, body, snippet in items:
        line = f"{title[0].upper()}{title[1:]}" + (f": {body}" if body else ".")
        wrapped = textwrap.fill(line, width=78, initial_indent="  * ", subsequent_indent="    ",
                                break_long_words=False, break_on_hyphens=False)
        out.append(f"dukiwi-shield ({version}) {SUITE}; urgency=medium\n\n{wrapped}\n\n"
                   f" -- {MAINTAINER}  {added_date(snippet)}\n")
    return "\n".join(out)


if __name__ == "__main__":
    sys.stdout.write(render(sys.argv[1]))
