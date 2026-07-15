#!/bin/sh
#
# phase1-down.sh -- diagnostic hook, invoked by racoon when a Phase 1 SA
# tears down (see "script ... phase1_down;" in gateway.conf).
#
# The SPD entries phase1-up.sh installed are left in place on purpose:
# they reference the pool address/tunnel endpoints of the session that
# just ended and won't match anything new, so they're harmless. The
# next successful phase1-up.sh run (triggered by resolve-gateway.sh's
# active reconnect, not by leftover SPD state) replaces them via its
# own "spdflush;".
#
# The INTERNAL_ADDR4 alias address phase1-up.sh added *is* removed
# here, purely for hygiene (so "ip addr"/"ip route" don't show a pool
# address that belongs to a session that's no longer up) -- leaving it
# wouldn't break the next reconnect, "ip addr replace"/"ip route
# replace" in phase1-up.sh would just overwrite it again.

logger -t racoon-phase1-down \
    "phase1 down: local=${LOCAL_ADDR:-?}:${LOCAL_PORT:-?} remote=${REMOTE_ADDR:-?}:${REMOTE_PORT:-?} internal=${INTERNAL_ADDR4:-?}"

if [ -n "${INTERNAL_ADDR4:-}" ] && [ -n "${REMOTE_ADDR:-}" ]; then
    IFACE=$(ip -4 route get "$REMOTE_ADDR" 2>/dev/null \
        | awk '{for (i = 1; i <= NF; i++) if ($i == "dev") print $(i + 1)}')
    [ -n "${IFACE:-}" ] && ip addr del "${INTERNAL_ADDR4}/32" dev "$IFACE" 2>/dev/null
fi

exit 0
