#!/bin/bash
set -euo pipefail

# Select an already-installed Xcode for this CI job: the oldest toolchain that
# still satisfies the required Swift version, so a new compiler release cannot
# change the build unnoticed. Never changes the developer directory configured
# on a user's machine — only exports DEVELOPER_DIR for this job.
#
# Usage: ci-swift-toolchain.sh [minimum-swift-version]   (default: 6.2)
: "${GITHUB_ENV:?This script is for GitHub Actions only}"

minimum="${1:-6.2}"

candidates=()
for developer in "$(xcode-select -p)" /Applications/Xcode*.app/Contents/Developer; do
    compiler="$developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/swift"
    [ -x "$compiler" ] || continue
    version_line="$("$compiler" --version 2>/dev/null | head -n 1)" || continue
    if [[ "$version_line" =~ Swift\ version\ ([0-9]+)(\.([0-9]+))? ]]; then
        candidates+=("${BASH_REMATCH[1]}.${BASH_REMATCH[3]:-0}	$developer")
    fi
done

chosen=""
chosen_version=""
if [ ${#candidates[@]} -gt 0 ]; then
    # Lowest version first, so the pick stays stable as newer Xcodes land.
    while IFS=$'\t' read -r version developer; do
        [ -n "$developer" ] || continue
        if [ "$(printf '%s\n%s\n' "$minimum" "$version" | sort -V | head -n 1)" = "$minimum" ]; then
            chosen="$developer"
            chosen_version="$version"
            break
        fi
    done < <(printf '%s\n' "${candidates[@]}" | sort -u -V)
fi

if [ -z "$chosen" ]; then
    echo "Pastoral requires an installed Xcode with Swift $minimum or newer." >&2
    exit 1
fi

echo "DEVELOPER_DIR=$chosen" >> "$GITHUB_ENV"
echo "Swift $chosen_version — $chosen"
