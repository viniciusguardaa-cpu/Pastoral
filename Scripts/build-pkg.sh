#!/bin/bash
#
# build-pkg.sh — Build the pastoral-helper installer .pkg
#
# Produces dist/pastoral-helper.pkg containing:
#   /usr/local/sbin/pastoral-helper          (root:wheel 0755)
#   /usr/local/sbin/pastoral-reset.sh         (root:wheel 0755)
#   /Library/LaunchDaemons/com.pastoral.helper.plist
#   /Library/LaunchDaemons/com.pastoral.reset.plist
#
# Scripts (preinstall/postinstall) live in Installer/scripts/.
#
# Usage: ./Scripts/build-pkg.sh
#
set -euo pipefail
export COPYFILE_DISABLE=1   # avoid `._` AppleDouble files in the pkg

PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$PROJECT_ROOT"

VERSION="${PASTORAL_VERSION:-1.0}"
DIST_DIR="${PASTORAL_DIST_DIR:-$PROJECT_ROOT/dist}"
STAGING="$PROJECT_ROOT/.build/pkg-staging"
OUT="$DIST_DIR/pastoral-helper.pkg"

echo "=== Building pastoral-helper.pkg (v$VERSION) ==="

# 1) Build the helper binary in release mode.
echo "[1/4] Building release binary…"
swift build -c release
BINARY="$PROJECT_ROOT/.build/release/pastoral-helper"
if [ ! -f "$BINARY" ]; then
    echo "ERROR: helper binary not found at $BINARY" >&2
    exit 1
fi

# 2) Assemble the payload staging tree (mirrors install paths).
echo "[2/4] Assembling payload…"
rm -rf "$STAGING"
mkdir -p "$STAGING/usr/local/sbin"
mkdir -p "$STAGING/Library/LaunchDaemons"

cp "$BINARY"                              "$STAGING/usr/local/sbin/pastoral-helper"
cp "$PROJECT_ROOT/Installer/pastoral-reset.sh" "$STAGING/usr/local/sbin/pastoral-reset.sh"
cp "$PROJECT_ROOT/Installer/com.pastoral.helper.plist" "$STAGING/Library/LaunchDaemons/"
cp "$PROJECT_ROOT/Installer/com.pastoral.reset.plist"  "$STAGING/Library/LaunchDaemons/"

chmod 0755 "$STAGING/usr/local/sbin/pastoral-helper"
chmod 0755 "$STAGING/usr/local/sbin/pastoral-reset.sh"

# Strip extended attributes so the pkg doesn't carry `._` AppleDouble files.
xattr -cr "$STAGING"

# 3) Build the component pkg with preinstall/postinstall scripts.
echo "[3/4] pkgbuild…"
mkdir -p "$DIST_DIR"
pkgbuild \
    --root "$STAGING" \
    --scripts "$PROJECT_ROOT/Installer/scripts" \
    --identifier com.pastoral.helper \
    --version "$VERSION" \
    --ownership recommended \
    "$OUT"

# 4) Wrap in a distribution pkg (adds a nicer installer title).
echo "[4/4] productbuild…"
DIST="$DIST_DIR/pastoral-helper.dist.pkg"
productbuild \
    --package "$OUT" \
    --identifier com.pastoral.helper \
    --version "$VERSION" \
    "$DIST"
mv "$DIST" "$OUT"

echo ""
echo "=== Done ==="
echo "  $OUT"
echo ""
echo "Install with:  sudo installer -pkg $OUT -target /"
echo "Or open in Installer.app:  open $OUT"
