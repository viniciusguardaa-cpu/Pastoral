#!/bin/bash
#
# pastoral-reset.sh — re-apply ChmodBPF at boot.
#
# /dev/bpf* devices are recreated by the kernel on demand with root:wheel
# 0600, so the access_bpf group + g+rw perms do NOT survive a reboot. This
# script (run by the com.pastoral.reset LaunchDaemon at RunAtLoad) redoes:
#   chgrp access_bpf /dev/bpf* ; chmod g+rw /dev/bpf*
# The helper also runs this on its own start as a belt-and-suspenders measure.
#
set -e

if dscl . -read /Groups/access_bpf >/dev/null 2>&1; then
    for f in /dev/bpf*; do
        [ -e "$f" ] || continue
        chgrp access_bpf "$f" 2>/dev/null || true
        chmod g+rw "$f" 2>/dev/null || true
    done
fi
