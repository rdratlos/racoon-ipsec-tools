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
# own "spdflush;". Nothing to clean up here beyond logging.

logger -t racoon-phase1-down \
    "phase1 down: local=${LOCAL_ADDR:-?}:${LOCAL_PORT:-?} remote=${REMOTE_ADDR:-?}:${REMOTE_PORT:-?}"

exit 0
