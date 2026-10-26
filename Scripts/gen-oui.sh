#!/bin/bash
#
# gen-oui.sh — Download the IEEE OUI database and generate a compact JSON.
#
# Produces Sources/Pastoral/Resources/oui.json mapping "AABBCC" → vendor.
# Run before building to refresh the embedded OUI database.
#
# Usage: ./Scripts/gen-oui.sh
#
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUTPUT="$PROJECT_ROOT/Sources/Pastoral/Resources/oui.json"
URL="https://standards-oui.ieee.org/oui/oui.txt"
TMP=$(mktemp)

echo "Downloading IEEE OUI data…"
curl -sL "$URL" -o "$TMP"

echo "Parsing…"
python3 -c "
import json, re
oui = {}
with open('$TMP', 'r', errors='replace') as f:
    for line in f:
        m = re.match(r'^([0-9A-Fa-f]{2}-[0-9A-Fa-f]{2}-[0-9A-Fa-f]{2})\s+\(hex\)\s+(.+?)\s*\$', line)
        if m:
            prefix = m.group(1).replace('-', '').upper()
            vendor = m.group(2).strip()
            oui[prefix] = vendor
with open('$OUTPUT', 'w') as f:
    json.dump(oui, f, separators=(',', ':'))
print(f'Generated {len(oui)} OUI entries → $OUTPUT')
"

rm -f "$TMP"
