#!/bin/bash
# Regenerates clamav-antivirus.png (README montage): English UI rendered offscreen by WebKitGTK in dev mode
# (simulated backend), a real GTK popup rendered offscreen, composed by montage.py. Needs a running X display.
# GDK_SCALE=1 matters on HiDPI: the DPI zoom then renders at 2x without WebKit's doubled-scale snapshot crop.
set -e
D="$(cd "$(dirname "$0")" && pwd)"; P="$(cd "$D/../.." && pwd)"; W="$(mktemp -d)"
U="file://$P/ui/index.html?lang=en"
GDK_SCALE=1 python3 "$D/webkit_shot.py" "$U" 2080 1440 "$W/dash.png" "setViewMode('advanced', false); switchTab('dashboard');" 3
GDK_SCALE=1 python3 "$D/webkit_shot.py" "$U" 1640 1520 "$W/security.png" "setViewMode('advanced', false); switchTab('security');" 4
GDK_SCALE=1 python3 "$D/webkit_shot.py" "$U" 1400 1280 "$W/simple.png" "setViewMode('simple', false);" 3
GDK_SCALE=2 python3 "$D/popup_shot.py" "$W/popup2x.png"
python3 "$D/montage.py" "$W" "$P/clamav-antivirus.png"
rm -rf "$W"
