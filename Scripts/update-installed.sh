#!/bin/bash
#
# update-installed.sh — update the ALREADY-INSTALLED Pastoral in place:
#   1. replaces /usr/local/sbin/pastoral-helper (+ resets LaunchDaemons)
#   2. replaces /Applications/Pastoral.app
#   3. restarts the helper daemon and verifies it answers on the socket
#
# Quit the Pastoral app first (it holds the old binary open).
# Usage: sudo bash /Users/viniciusg./TESTMONEY/Pastoral/Scripts/update-installed.sh
#
set -euo pipefail

PROJECT="$(cd "$(dirname "$0")/.." && pwd)"
HELPER_PKG="$PROJECT/dist/pastoral-helper.pkg"
APP_BUNDLE="$PROJECT/dist/Pastoral.app"

[ "$(id -u)" = "0" ] || { echo "run with sudo"; exit 1; }
[ -f "$HELPER_PKG" ] || { echo "missing $HELPER_PKG (run ./Scripts/build-pkg.sh)"; exit 1; }
[ -d "$APP_BUNDLE" ] || { echo "missing $APP_BUNDLE (run make app)"; exit 1; }

if pgrep -x Pastoral >/dev/null 2>&1; then
    echo "WARN: Pastoral app is still running — quit it and re-run, or press on anyway."
fi

echo "[1/3] Installing helper pkg…"
installer -pkg "$HELPER_PKG" -target /

echo "[2/3] Replacing /Applications/Pastoral.app…"
rm -rf /Applications/Pastoral.app
cp -R "$APP_BUNDLE" /Applications/Pastoral.app
xattr -cr /Applications/Pastoral.app 2>/dev/null || true

echo "[3/3] Restarting helper daemon…"
launchctl bootstrap system /Library/LaunchDaemons/com.pastoral.helper.plist 2>/dev/null \
    || launchctl bootout system/com.pastoral.helper 2>/dev/null \
    && launchctl bootstrap system /Library/LaunchDaemons/com.pastoral.helper.plist 2>/dev/null || true
sleep 1

# A ping through the real socket proves the new binary is serving.
# Wire format = one JSON line: {"<caseName>":{fields…}}; "status" is the
# request, "statusReport" the reply.
ping_result=$( { printf '{"status":{}}\n' \
    | { nc -U /var/run/pastoral.sock 2>/dev/null || cat; }; } 2>/dev/null | head -1 || true )
if [ -n "$ping_result" ]; then
    echo "Helper respondeu: $ping_result"
else
    echo "WARN: helper não respondeu no socket ainda — rode:"
    echo "  launchctl kickstart -k system/com.pastoral.helper"
fi

echo ""
echo "Done. Reabra o app:  open -a Pastoral"
echo "Nota: se você criou o grupo access_bpf no passado, lembre de ter seu usuário nele"
echo "(o socket passa a ser 0660 root:access_bpf quando o grupo existe)."
