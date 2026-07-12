#!/bin/sh
#
# phase1-down.sh -- diagnostic hook, invoked by racoon when a Phase 1 SA
# tears down (see "script ... phase1_down;" in gateway.conf).
#
# The SPD trap policies are left in place on purpose: they are what
# lets the *next* SSSD/autofs connection attempt trigger a fresh Phase 1
# negotiation automatically. Nothing to clean up here beyond logging.

logger -t racoon-phase1-down \
    "phase1 down: local=${LOCAL_ADDR:-?}:${LOCAL_PORT:-?} remote=${REMOTE_ADDR:-?}:${REMOTE_PORT:-?}"

exit 0
