#!/bin/sh
#
# phase1-up.sh -- diagnostic hook, invoked by racoon after a successful
# Phase 1 negotiation (see "script ... phase1_up;" in gateway.conf).
#
# Unlike src/racoon/samples/roadwarrior/client/phase1-up.sh (mode_cfg
# roadwarrior, which uses this hook to install the SPD trap policies
# from the negotiated LOCAL_ADDR/REMOTE_ADDR), this setup already
# maintains its SPD policies via resolve-gateway.sh -- they must exist
# *before* Phase 1 starts so the kernel's ACQUIRE can trigger it in the
# first place. This script only logs, and cross-checks that racoon
# negotiated the address resolve-gateway.sh expected.

logger -t racoon-phase1-up \
    "phase1 up: local=${LOCAL_ADDR:-?}:${LOCAL_PORT:-?} remote=${REMOTE_ADDR:-?}:${REMOTE_PORT:-?}"

STATE_FILE="/var/lib/racoon/gw-resolve.state"
EXPECTED="${REMOTE_ADDR:-}/${LOCAL_ADDR:-}"
# state file is "gateway/local/iface" -- compare only the address part
ACTUAL=$(cut -d/ -f1,2 "$STATE_FILE" 2>/dev/null || true)

if [ -n "${LOCAL_ADDR:-}" ] && [ "$EXPECTED" != "$ACTUAL" ]; then
    logger -t racoon-phase1-up \
        "warning: negotiated address ($EXPECTED) differs from resolve-gateway.sh state ($ACTUAL) -- SPD policies may be stale, a resolve-gateway.sh re-run is recommended"
fi

exit 0
