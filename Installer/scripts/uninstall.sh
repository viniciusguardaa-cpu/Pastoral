#!/bin/sh
# Pastoral uninstaller — removes all traces of Pastoral from the system.
# Must be run as root (via the helper or PrivilegedInstaller).
#
# Removes:
#   - LaunchDaemons (com.pastoral.helper, com.pastoral.reset)
#   - Helper binary (/usr/local/sbin/pastoral-helper)
#   - Reset script (/usr/local/sbin/pastoral-reset.sh)
#   - pf anchors (com.pastoral/kill, com.pastoral/sheep)
#   - pf.conf include lines (anchor "com.pastoral/kill", "com.pastoral/sheep")
#   - CA from Keychain (if present)
#   - State directory (~/Library/Application Support/Pastoral)
#   - Socket (/var/run/pastoral.sock)
#   - pf.conf backup (/var/db/pastoral/pf.conf.bak)

set -e

echo "Pastoral uninstaller"

# 1. Unload LaunchDaemons
echo "Unloading LaunchDaemons..."
launchctl bootout system/com.pastoral.helper 2>/dev/null || true
launchctl bootout system/com.pastoral.reset 2>/dev/null || true
launchctl unload /Library/LaunchDaemons/com.pastoral.helper.plist 2>/dev/null || true
launchctl unload /Library/LaunchDaemons/com.pastoral.reset.plist 2>/dev/null || true

# 2. Remove LaunchDaemon plists
echo "Removing LaunchDaemon plists..."
rm -f /Library/LaunchDaemons/com.pastoral.helper.plist
rm -f /Library/LaunchDaemons/com.pastoral.reset.plist

# 3. Remove helper and reset script
echo "Removing helper binaries..."
rm -f /usr/local/sbin/pastoral-helper
rm -f /usr/local/sbin/pastoral-reset.sh

# 4. Remove socket
echo "Removing socket..."
rm -f /var/run/pastoral.sock

# 5. Clear pf anchors
echo "Clearing pf anchors..."
pfctl -a com.pastoral/kill -F rules 2>/dev/null || true
pfctl -a com.pastoral/sheep -F rules 2>/dev/null || true

# 6. Remove pf.conf include lines (restore from backup if available)
echo "Restoring pf.conf..."
if [ -f /var/db/pastoral/pf.conf.bak ]; then
    cp /var/db/pastoral/pf.conf.bak /etc/pf.conf
    pfctl -f /etc/pf.conf 2>/dev/null || true
else
    # Remove the include lines manually
    if [ -f /etc/pf.conf ]; then
        sed -i '' '/anchor "com.pastoral\/kill"/d' /etc/pf.conf
        sed -i '' '/anchor "com.pastoral\/sheep"/d' /etc/pf.conf
        pfctl -f /etc/pf.conf 2>/dev/null || true
    fi
fi

# 7. Remove CA from Keychain (if the user installed it)
echo "Removing CA from Keychain..."
security delete-certificate -c "Pastoral CA" /Library/Keychains/System.keychain 2>/dev/null || true
security remove-trusted-cert -d /Library/Keychains/System.keychain 2>/dev/null || true

# 8. Remove state directory
echo "Removing state directory..."
rm -rf ~/Library/Application\ Support/Pastoral
rm -rf /var/db/pastoral

# 9. Remove access_bpf group (optional — only if no other tool uses it)
# We leave the group in place to avoid breaking Wireshark/other tools.
echo "Note: access_bpf group left in place (may be used by other tools)."

echo "Pastoral uninstalled successfully."
