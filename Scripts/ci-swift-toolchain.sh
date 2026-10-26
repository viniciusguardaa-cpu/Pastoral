#!/bin/bash
set -euo pipefail

# Select an already-installed Swift 6+ Xcode only for this CI job.
# Never change the developer directory configured on a user's machine.
: "${GITHUB_ENV:?This script is for GitHub Actions only}"
for developer in "$(xcode-select -p)" /Applications/Xcode*.app/Contents/Developer; do
    compiler="$developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/swift"
    [ -x "$compiler" ] || continue
    version="$("$compiler" --version)"
    if [[ "$version" =~ Swift\ version\ ([0-9]+) ]] && (( BASH_REMATCH[1] >= 6 )); then
        echo "DEVELOPER_DIR=$developer" >> "$GITHUB_ENV"
        echo "$version"
        exit 0
    fi
done
echo "Pastoral requires an installed Xcode with Swift 6 or newer." >&2
exit 1
