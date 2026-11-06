#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════
# Dukiwi Shield — Nemo right-click scan handler
# Scans selected file(s)/folder(s) and shows results in a dialog
# ═══════════════════════════════════════════════════════════════════════════

QUARANTINE_DIR="$HOME/.local/share/dukiwi-shield/quarantine"
LOG_FILE="$HOME/.local/share/dukiwi-shield/scan.log"
# Every selected item (%F gives them all), not only the first one
TARGETS=("$@")
TARGET="${1:-}"

# File names go into zenity's Pango markup: escape what markup and its \n handling would interpret, so a name
# such as "</i><b>No threats</b>" cannot fake the result
markup_escape() {
    printf '%s' "$1" | sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g' -e 's/\\/\\\\/g'
}

# Ensure directories exist
mkdir -p "$QUARANTINE_DIR"
mkdir -p "$(dirname "$LOG_FILE")"

# Check if clamscan is available
if ! command -v clamscan &> /dev/null; then
    zenity --error --title="Dukiwi Shield" \
        --text="ClamAV n'est pas installé.\nInstallez-le avec : sudo apt install clamav" \
        --width=350 2>/dev/null
    exit 1
fi

if [ -z "$TARGET" ]; then
    zenity --error --title="Dukiwi Shield" \
        --text="Aucun fichier ou dossier sélectionné." \
        --width=300 2>/dev/null
    exit 1
fi

BASENAME=$(basename -- "$TARGET")
[ "${#TARGETS[@]}" -gt 1 ] && BASENAME="$BASENAME (+$(( ${#TARGETS[@]} - 1 )))"
BASENAME_M=$(markup_escape "$BASENAME")
TMPFILE=$(mktemp /tmp/clamav-scan-XXXXXX.log)

# Run scan with progress
(
    echo "# Analyse de : $BASENAME"
    clamscan -r --infected --suppress-ok-results --move="$QUARANTINE_DIR" -- "${TARGETS[@]}" > "$TMPFILE" 2>&1
    echo "100"
) | zenity --progress --title="Dukiwi Shield" \
    --text="Analyse en cours..." \
    --pulsate --auto-close --no-cancel --width=400 2>/dev/null

# Parse results
INFECTED=$(grep -c "FOUND" "$TMPFILE" 2>/dev/null || echo "0")
SCANNED=$(grep "Scanned files:" "$TMPFILE" | awk '{print $NF}' 2>/dev/null || echo "?")
SCAN_TIME=$(grep "Time:" "$TMPFILE" | head -1 | sed 's/Time: *//' 2>/dev/null || echo "?")

# Log results
echo "[$(date -Iseconds)] Nemo scan: ${TARGETS[*]} — $INFECTED infected" >> "$LOG_FILE"
cat "$TMPFILE" >> "$LOG_FILE"

# Show results
if [ "$INFECTED" -gt 0 ]; then
    FOUND_FILES=$(markup_escape "$(grep "FOUND" "$TMPFILE" | sed 's/: .* FOUND$//' | sed 's|^|  • |')")
    zenity --warning --title="Dukiwi Shield — Menaces détectées !" \
        --text="<b>$INFECTED menace(s) détectée(s)</b> dans :\n<i>$BASENAME_M</i>\n\nFichiers infectés (déplacés en quarantaine) :\n$FOUND_FILES\n\nFichiers analysés : $SCANNED\nDurée : $SCAN_TIME" \
        --width=500 2>/dev/null
else
    zenity --info --title="Dukiwi Shield — Aucune menace" \
        --text="<b>Aucune menace détectée</b>\n\nCible : <i>$BASENAME_M</i>\nFichiers analysés : $SCANNED\nDurée : $SCAN_TIME" \
        --width=400 2>/dev/null
fi

# Cleanup
rm -f "$TMPFILE"
