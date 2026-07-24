#!/bin/bash
# Task F: ACQUIRE-provenance investigation -- ready-to-run evidence capture
# for doc/dev/teardown-investigation.md.
#
# WHERE TO RUN THIS: a network-namespace-capable container with a real,
# unmodified kernel IPsec stack (Incus, privileged Docker with
# --cap-add=NET_ADMIN, or systemd-nspawn) -- NOT a minimal/stripped-kernel
# sandbox. This script itself checks for that in step 0 and aborts with a
# clear reason rather than producing a false negative if it's missing.
#
# WHAT THIS ASSUMES IS ALREADY IN PLACE: a working racoon.conf + hooks.conf
# on this host, already configured and already proven to connect to a real
# gateway (exactly the setup used for the Bionic/Arch/Noble roadwarrior
# testing earlier in this engagement) -- this script does not stand up a
# new IKEv1 lab from scratch, it orchestrates and captures evidence around
# your existing, already-working configuration.
#
# WHAT THIS SCRIPT DOES NOT DO: fix anything. It only observes and records.
# Branch A (a real external mechanism found) or Branch B (nothing left to
# find, on-demand reconnection is a design gap) are both valid, expected
# outcomes -- do not "fix" either one; report back to Claude with the
# results directory and let the write-up happen from real evidence.
#
# Usage:
#   sudo VPN_GATEWAY=<gateway-host-or-ip> \
#        INTERNAL_DNS_SERVER=<internal-dns-ip> \
#        [RACOON_SRC_DIR=/path/to/racoon-ipsec-tools] \
#        [SETKEY_BIN=setkey] [RACOONCTL_BIN=racoonctl] [RACOON_BIN=racoon] \
#        [STATE_DIR=/run/racoon] [RACOON_CONF=/etc/racoon/racoon.conf] \
#        ./task-f-acquire-investigation.sh
#
# Everything is captured under a timestamped results directory printed at
# the end -- tar it up and hand it back for the doc/dev/teardown-
# investigation.md write-up.

set -u

# --------------------------------------------------------------------------
# Configuration (env-overridable; defaults match this project's own
# conventions, verified against racoon-hook-lib.sh and racoonctl.c).
# --------------------------------------------------------------------------
: "${VPN_GATEWAY:?set VPN_GATEWAY to the real gateway address or hostname that racoon.conf already connects to}"
: "${INTERNAL_DNS_SERVER:?set INTERNAL_DNS_SERVER to an address behind the tunnel to ping in step 6 (the same one used in earlier live testing)}"
RACOON_SRC_DIR="${RACOON_SRC_DIR:-$(cd "$(dirname "$0")" >/dev/null 2>&1 && pwd)}"
SETKEY_BIN="${SETKEY_BIN:-setkey}"
RACOONCTL_BIN="${RACOONCTL_BIN:-racoonctl}"
RACOON_BIN="${RACOON_BIN:-racoon}"
RACOON_CONF="${RACOON_CONF:-/etc/racoon/racoon.conf}"
STATE_DIR="${STATE_DIR:-/run/racoon}"
CONNECT_TIMEOUT="${CONNECT_TIMEOUT:-30}"
PHASE1_DOWN_WAIT_TIMEOUT="${PHASE1_DOWN_WAIT_TIMEOUT:-15}"
ACQUIRE_WATCH_SECONDS="${ACQUIRE_WATCH_SECONDS:-8}"

TS="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="/root/task-f-results-${TS}"
mkdir -p "$OUT" || { echo "cannot create $OUT" >&2; exit 1; }

STEP_LOG="$OUT/00-narration.log"
SUMMARY="$OUT/SUMMARY.md"

narrate() {
	printf '[%s] %s\n' "$(date -u +%H:%M:%S)" "$1" | tee -a "$STEP_LOG"
}

fail_stop() {
	narrate "STOP: $1"
	printf '\n**STOPPED**: %s\n' "$1" >> "$SUMMARY"
	exit 1
}

# --------------------------------------------------------------------------
# The exact per-socket-policy filter from the task brief. per-socket
# policies are the kernel's own transport-mode bookkeeping for local
# sockets requesting IPsec, not anything the hook or racoon installed --
# always present, always noise for this investigation.
# --------------------------------------------------------------------------
filtered_spd() {
	"$SETKEY_BIN" -DP 2>&1 | awk 'BEGIN{RS="";ORS="\n\n"} !/\(per-socket policy\)/'
}

# ==========================================================================
# Step 0: capability preflight. Do not trust any negative result below
# without this passing first -- a permission/kernel-feature failure that
# looks like "no policy could be installed" is not evidence of anything.
# ==========================================================================
narrate "=== Step 0: capability preflight ==="
{
	echo "id: $(id)"
	echo "--- capsh --print ---"
	capsh --print 2>&1 || echo "(capsh not available -- not fatal, checked directly below instead)"
	echo "--- setkey -D (SAD dump; confirms PF_KEY socket works at all) ---"
	"$SETKEY_BIN" -D 2>&1
	SETKEY_RC=$?
	echo "rc=$SETKEY_RC"
	echo "--- ip xfrm policy show ---"
	ip xfrm policy show 2>&1
	echo "rc=$?"
	echo "--- ip route show ---"
	ip route show 2>&1
	echo "rc=$?"
	echo "--- kernel IPsec config (best effort) ---"
	zcat /proc/config.gz 2>/dev/null | grep -E "^CONFIG_(NET_KEY|INET_ESP|XFRM)" || echo "(no /proc/config.gz -- not fatal, setkey -D above is the real test)"
} > "$OUT/00-preflight.log" 2>&1

if ! "$SETKEY_BIN" -D >/dev/null 2>&1; then
	fail_stop "setkey -D failed -- PF_KEY (AF_KEY) is not usable in this environment (see $OUT/00-preflight.log). This is exactly the failure mode that made the original sandbox unusable for this task; you need a container with a full, unmodified kernel IPsec stack (CONFIG_NET_KEY, CONFIG_INET_ESP). Do not proceed."
fi
narrate "capability preflight passed: setkey -D works (see $OUT/00-preflight.log for full detail)"

# ==========================================================================
# Step 1: baseline. setkey -F is SAD only -- never touches SPD -- so a
# non-empty filtered -DP result here is itself evidence, not noise to
# clear away. Recorded, not auto-flushed.
# ==========================================================================
narrate "=== Step 1: baseline ==="
"$SETKEY_BIN" -F > "$OUT/01-setkey-F.log" 2>&1
narrate "setkey -F (SAD flush) done"
filtered_spd > "$OUT/01-baseline-filtered-spd.log"
if [ -s "$OUT/01-baseline-filtered-spd.log" ]; then
	narrate "WARNING: baseline filtered SPD is NOT empty -- see $OUT/01-baseline-filtered-spd.log. This predates racoon even starting; if it's still present after phase1-down in step 5, it did NOT come from this test run's own connection."
else
	narrate "baseline filtered SPD is empty, as expected"
fi

# ==========================================================================
# Step 2: start racoon with -f <conf> and deliberately WITHOUT -F, so it
# daemonizes normally and logs via syslog only -- sidesteps F5's stdout
# block-buffering/reordering bug entirely (see the comment right before
# the actual invocation below) rather than working around it while
# reading a corrupted log. Confirm the daemon is actually running via
# show-sa isakmp returning cleanly -- a daemonize failure here would
# otherwise look identical to success from the shell's point of view.
# ==========================================================================
narrate "=== Step 2: start racoon (daemonized, syslog-only) ==="

# Continuous background syslog capture for the rest of the run -- one
# capture, referenced by timestamp/grep at each step, rather than
# starting/stopping journalctl repeatedly.
RACOON_LOG="$OUT/racoon-syslog.log"
if command -v journalctl >/dev/null 2>&1; then
	journalctl -f -t racoon --no-pager > "$RACOON_LOG" 2>&1 &
	JOURNAL_PID=$!
	narrate "background log capture: journalctl -f -t racoon (pid $JOURNAL_PID) -> $RACOON_LOG"
else
	: > "$RACOON_LOG"
	narrate "WARNING: journalctl not found -- \$RACOON_LOG will stay empty unless you redirect racoon's own log there yourself; step 6's syslog watch depends on this"
	JOURNAL_PID=""
fi

# NOT backgrounded with '&': racoon's default mode (no -F) is to
# daemonize itself (fork, detach, parent exits) -- confirmed against
# src/racoon/main.c's usage() text ("-F: run in foreground, do not
# become daemon", "-f: pathname for configuration file", two distinct
# flags, not the same one) and doc/dev/daemon-issues.md's F5 entry
# (f_foreground/-F is specifically what routes plogv() through
# vprintf()-to-stdout, block-buffered and unreliable under a non-TTY;
# the default non-F path logs via syslog only, sidestepping it
# entirely). Backgrounding the invoking shell command here would only
# capture the quickly-exiting parent's PID, not the detached daemon's.
"$RACOON_BIN" -f "$RACOON_CONF" > "$OUT/02-racoon-stdout.log" 2>&1
sleep 2

if ! "$RACOONCTL_BIN" show-sa isakmp > "$OUT/02-show-sa-after-start.log" 2>&1; then
	cat "$OUT/02-show-sa-after-start.log"
	fail_stop "racoonctl show-sa isakmp failed right after starting racoon -f -- the daemon did not actually come up (this is exactly the silent-failure mode step 2 warns about). Check $OUT/02-racoon-stdout.log and $RACOON_LOG."
fi
narrate "racoon -f is up and answering racoonctl show-sa isakmp"

# ==========================================================================
# Step 3: filtered setkey -DP before any connect. If a real policy shows
# up here, stop -- this is the single cleanest way to catch a
# generate_policy or daemon-installed trap in the act, uncontaminated by
# anything the hook does later.
# ==========================================================================
narrate "=== Step 3: filtered SPD immediately after racoon start, before connect ==="
filtered_spd > "$OUT/03-post-start-filtered-spd.log"
if [ -s "$OUT/03-post-start-filtered-spd.log" ]; then
	narrate "!!! Real (non-per-socket) policy present immediately after racoon start, before any connect !!!"
	tee -a "$STEP_LOG" < "$OUT/03-post-start-filtered-spd.log"
	{
		echo "## Branch A candidate: policy present before any connect"
		echo
		echo "See 03-post-start-filtered-spd.log. Per the task brief, stop and identify"
		echo "this before proceeding -- do not treat it as noise. Likely sources, in"
		echo "order of likelihood: (1) generate_policy in racoon.conf, (2) a"
		echo "distribution-packaged setkey.service independent of racoon, (3) a"
		echo "leftover from a previous test cycle in this same container."
	} >> "$SUMMARY"
	fail_stop "real policy present before any connect -- see $OUT/03-post-start-filtered-spd.log and investigate before re-running (racoon.conf's own generate_policy setting, or a distro setkey.service, are the first two places to check per the task brief's step 7 -- see also 07-*.log below if you choose to continue manually)"
fi
narrate "no real policy present before connect, as expected -- continuing"

# ==========================================================================
# Step 4: full connect -> verified -> disconnect cycle, filtered -DP at
# each stage, cross-referenced against the hook's own state file.
# ==========================================================================
narrate "=== Step 4: racoonctl vpn-connect $VPN_GATEWAY ==="
if ! timeout "$CONNECT_TIMEOUT" "$RACOONCTL_BIN" vpn-connect "$VPN_GATEWAY" > "$OUT/04-vpn-connect.log" 2>&1; then
	cat "$OUT/04-vpn-connect.log"
	fail_stop "racoonctl vpn-connect $VPN_GATEWAY did not complete within ${CONNECT_TIMEOUT}s -- see $OUT/04-vpn-connect.log and $RACOON_LOG"
fi
narrate "vpn-connect returned (blocks on EVT_PHASE1_MODE_CFG, so Mode Config is confirmed complete)"

# racoonctl show-sa isakmp is still captured below as useful evidence
# (a populated table vs. empty after disconnect), but it is NOT the
# source for the SPI comparison -- confirmed against racoonctl.c's own
# dump_isakmp_sa()/pindex_isakmp(): its table has no "spi:"-prefixed
# field at all, that literal format is racoon's own plog() output
# ("ISAKMP-SA established %s-%s spi:%s\n", isakmp.c:2997), which is what
# the syslog capture already has. Pull it from there instead.
"$RACOONCTL_BIN" show-sa isakmp > "$OUT/04-show-sa-connected.log" 2>&1
ORIGINAL_SPI="$(grep -oE 'ISAKMP-SA established.*spi:[0-9a-fA-F]+:[0-9a-fA-F]+' "$RACOON_LOG" 2>/dev/null | grep -oE 'spi:[0-9a-fA-F]+:[0-9a-fA-F]+' | tail -1)"
narrate "connected ISAKMP-SA: ${ORIGINAL_SPI:-<not found in syslog yet -- check $RACOON_LOG manually, journalctl may lag slightly behind vpn-connect returning>}"

filtered_spd > "$OUT/04-connected-filtered-spd.log"
ls -la "$STATE_DIR"/hook-state.* > "$OUT/04-hook-state-listing.log" 2>&1
for f in "$STATE_DIR"/hook-state.*; do
	[ -f "$f" ] || continue
	{
		echo "=== $f ==="
		cat "$f"
		echo
	} >> "$OUT/04-hook-state-content.log"
done
narrate "captured connected-state filtered SPD ($OUT/04-connected-filtered-spd.log) and hook state file(s) ($OUT/04-hook-state-content.log) -- cross-reference these two by hand: every non-per-socket selector in the SPD dump should have a matching spdadd undo (spddelete) line in the state file"

narrate "=== disconnecting: racoonctl vpn-disconnect $VPN_GATEWAY ==="
if ! timeout "$CONNECT_TIMEOUT" "$RACOONCTL_BIN" vpn-disconnect "$VPN_GATEWAY" > "$OUT/04-vpn-disconnect.log" 2>&1; then
	cat "$OUT/04-vpn-disconnect.log"
	narrate "WARNING: racoonctl vpn-disconnect did not return cleanly within ${CONNECT_TIMEOUT}s -- continuing anyway, but treat step 5 with caution"
fi

# --------------------------------------------------------------------------
# Critical timing detail, confirmed against this tree's own
# src/racoon/isakmp.c (isakmp_ph1delete()): evt_phase1(EVT_PHASE1_DOWN) --
# what racoonctl vpn-disconnect blocks on -- fires BEFORE delph1() is
# called, and delph1() (handler.c) is what actually invokes
# script_hook(SCRIPT_PHASE1_DOWN), i.e. phase1-down.sh. So
# "vpn-disconnect returned" is NOT the same moment as "phase1-down.sh
# completed" -- there is a real ordering gap. Wait explicitly for the
# hook's own completion marker (its report's "result:" summary line,
# established throughout this whole engagement's live logs) rather than
# trusting vpn-disconnect's return alone.
# --------------------------------------------------------------------------
narrate "vpn-disconnect returned -- this is EVT_PHASE1_DOWN, NOT phase1-down.sh's own completion (confirmed against isakmp_ph1delete()'s ordering: evt_phase1() fires before delph1() calls script_hook(SCRIPT_PHASE1_DOWN)). Waiting explicitly for the hook's own report line..."

PHASE1_DOWN_CONFIRMED=0
i=0
while [ "$i" -lt "$PHASE1_DOWN_WAIT_TIMEOUT" ]; do
	if grep -q "racoon phase1-down report" "$RACOON_LOG" 2>/dev/null && \
	   grep -qE "^\s*result: (OK|PARTIAL)" "$RACOON_LOG" 2>/dev/null; then
		PHASE1_DOWN_CONFIRMED=1
		break
	fi
	sleep 1
	i=$((i + 1))
done

if [ "$PHASE1_DOWN_CONFIRMED" -eq 1 ]; then
	narrate "phase1-down.sh's own report line confirmed in syslog after ${i}s -- proceeding to the fork-in-the-road check now, at the correct moment"
else
	narrate "WARNING: did not see phase1-down.sh's report line in syslog within ${PHASE1_DOWN_WAIT_TIMEOUT}s -- either the hook isn't wired into racoon.conf's remote block (check for 'script ... phase1_down;'), or it's taking unusually long, or -f's syslog output has a delay. Proceeding anyway since the task's own step 5 still needs a result, but flag this explicitly in the write-up rather than treating the timing as clean."
fi
grep -A 30 "racoon phase1-down report" "$RACOON_LOG" > "$OUT/04-phase1-down-report.log" 2>/dev/null

# ==========================================================================
# Step 5: THE FORK IN THE ROAD. Filtered setkey -DP immediately after
# phase1-down.sh's own confirmed completion.
# ==========================================================================
narrate "=== Step 5: filtered SPD immediately after phase1-down.sh completion (the fork) ==="
filtered_spd > "$OUT/05-post-teardown-filtered-spd.log"

if [ -s "$OUT/05-post-teardown-filtered-spd.log" ]; then
	BRANCH="A"
	narrate "*** BRANCH A signal: something remains in the SPD after phase1-down.sh completed ***"
	tee -a "$STEP_LOG" < "$OUT/05-post-teardown-filtered-spd.log"
else
	BRANCH="B"
	narrate "*** BRANCH B signal: filtered SPD is empty after phase1-down.sh completed ***"
fi

{
	echo "# Task F results -- $TS"
	echo
	echo "VPN_GATEWAY=$VPN_GATEWAY"
	echo "INTERNAL_DNS_SERVER=$INTERNAL_DNS_SERVER"
	echo "Original connected ISAKMP-SA: ${ORIGINAL_SPI:-<not captured, see 04-show-sa-connected.log>}"
	echo "phase1-down.sh completion confirmed via syslog: $([ "$PHASE1_DOWN_CONFIRMED" -eq 1 ] && echo yes || echo NO -- see warning above)"
	echo
	echo "## Step 5 fork-in-the-road result: tentatively BRANCH $BRANCH"
	echo
	if [ "$BRANCH" = "A" ]; then
		echo '```'
		cat "$OUT/05-post-teardown-filtered-spd.log"
		echo '```'
		echo
		echo "Cross-reference this against 04-hook-state-content.log by hand:"
		echo "if a selector above exactly matches one whose undo (spddelete) is in the"
		echo "state file, the hook believed it tore this down but didn't -- that's a"
		echo "hook bug, not an external mechanism, and changes where to look next"
		echo "(re-check rhook_undo_replay()/phase1-down.sh's own execution, not"
		echo "generate_policy or a distro service). If it does NOT match anything in"
		echo "the state file, it was never the hook's to begin with -- proceed to"
		echo "step 7's narrowing below."
	else
		echo "Empty SPD (aside from per-socket entries) immediately after"
		echo "phase1-down.sh's own confirmed completion. Proceeding to step 6 to"
		echo "confirm: on an empty SPD, no ACQUIRE firing is the expected, POSITIVE"
		echo "confirmation of Branch B, not an inconclusive result."
	fi
} > "$SUMMARY"

# ==========================================================================
# Step 6: provoke the ACQUIRE deliberately, scripted rather than waiting
# for incidental traffic.
# ==========================================================================
narrate "=== Step 6: provoking ACQUIRE via ping to $INTERNAL_DNS_SERVER ==="
PRE_PING_LOGLINE_COUNT="$(wc -l < "$RACOON_LOG" 2>/dev/null || echo 0)"

ping -c1 -W2 "$INTERNAL_DNS_SERVER" > "$OUT/06-ping.log" 2>&1
PING_RC=$?
narrate "ping -c1 -W2 $INTERNAL_DNS_SERVER exit=$PING_RC (see $OUT/06-ping.log) -- watching syslog for ${ACQUIRE_WATCH_SECONDS}s"
sleep "$ACQUIRE_WATCH_SECONDS"

tail -n "+$((PRE_PING_LOGLINE_COUNT + 1))" "$RACOON_LOG" > "$OUT/06-post-ping-syslog-window.log" 2>/dev/null

ACQUIRE_FIRED=0
if grep -qE "queued due to no phase1 found|initiate new phase 1 negotiation" "$OUT/06-post-ping-syslog-window.log"; then
	ACQUIRE_FIRED=1
fi

# Same fix as ORIGINAL_SPI above: pull from the syslog capture's own
# plog() "ISAKMP-SA established ... spi:..." text, scoped to just the
# post-ping window so an unrelated earlier line can't be picked up by
# mistake, not from racoonctl's own show-sa table.
"$RACOONCTL_BIN" show-sa isakmp > "$OUT/06-show-sa-post-ping.log" 2>&1
NEW_SPI="$(grep -oE 'ISAKMP-SA established.*spi:[0-9a-fA-F]+:[0-9a-fA-F]+' "$OUT/06-post-ping-syslog-window.log" 2>/dev/null | grep -oE 'spi:[0-9a-fA-F]+:[0-9a-fA-F]+' | tail -1)"

{
	echo
	echo "## Step 6: ACQUIRE provocation"
	echo
	echo "ping exit code: $PING_RC"
	echo "ACQUIRE-related log lines seen within ${ACQUIRE_WATCH_SECONDS}s: $([ "$ACQUIRE_FIRED" -eq 1 ] && echo YES || echo no)"
	echo "Original SA: ${ORIGINAL_SPI:-<not captured>}"
	echo "Post-ping SA: ${NEW_SPI:-<none / no SA present>}"
	if [ "$ACQUIRE_FIRED" -eq 1 ] && [ -n "$ORIGINAL_SPI" ] && [ -n "$NEW_SPI" ]; then
		if [ "$ORIGINAL_SPI" = "$NEW_SPI" ]; then
			echo
			echo "SPI UNCHANGED despite an ACQUIRE-related log line -- this needs manual"
			echo "review of 06-post-ping-syslog-window.log; it may be a spurious/retried"
			echo "message rather than a genuine fresh re-negotiation."
		else
			echo
			echo "SPI CHANGED (${ORIGINAL_SPI} -> ${NEW_SPI}) -- racoon genuinely"
			echo "re-established a fresh ISAKMP-SA from scratch, matching the original"
			echo "Bionic on-demand evidence exactly."
		fi
	fi
	echo
	if [ "$BRANCH" = "B" ] && [ "$ACQUIRE_FIRED" -eq 0 ]; then
		echo "CONFIRMS BRANCH B: empty SPD after teardown, and no ACQUIRE fired."
		echo "Per the task brief, this is the expected, correct kernel behaviour given"
		echo "an empty SPD -- treat this as a clean positive confirmation, not an"
		echo "inconclusive result. On-demand reconnection after a clean disconnect is"
		echo "not currently functional; this is a design gap (arm/disarm), not a bug."
	elif [ "$BRANCH" = "B" ] && [ "$ACQUIRE_FIRED" -eq 1 ]; then
		echo "UNEXPECTED: SPD was empty after teardown (Branch B signal in step 5) but"
		echo "an ACQUIRE fired anyway. This contradicts the step-5 read -- re-examine"
		echo "05-post-teardown-filtered-spd.log and 06-post-ping-syslog-window.log"
		echo "together; something the filtered -DP view didn't show (a state/kernel SA"
		echo "cache, or a race between step 5's snapshot and the ping) may be involved."
		echo "Do not report this as clean Branch B without resolving the contradiction."
	elif [ "$BRANCH" = "A" ] && [ "$ACQUIRE_FIRED" -eq 1 ]; then
		echo "CONFIRMS BRANCH A: a real policy survived teardown, and it successfully"
		echo "triggered a fresh ACQUIRE/negotiation. Proceed to step 7's narrowing."
	else
		echo "Branch A signal in step 5 (policy survived teardown) but no ACQUIRE"
		echo "fired here -- the leftover policy exists but isn't (or isn't yet)"
		echo "provoking negotiation. Still worth identifying via step 7, but note this"
		echo "discrepancy explicitly rather than assuming it behaves like the original"
		echo "Bionic observation."
	fi
} >> "$SUMMARY"

# ==========================================================================
# Step 7: Branch A narrowing (only meaningfully needed if step 5/6 point
# at Branch A, but captured either way since it's cheap and useful
# context regardless).
# ==========================================================================
narrate "=== Step 7: Branch A narrowing checks (captured regardless of branch, for context) ==="

{
	echo "--- generate_policy in racoon.conf ---"
	grep -n "generate_policy" "$RACOON_CONF" 2>/dev/null || echo "(not found in $RACOON_CONF)"
	echo
	echo "--- generate_policy in racoon C source ($RACOON_SRC_DIR) ---"
	if [ -d "$RACOON_SRC_DIR/src/racoon" ]; then
		grep -rn "generate_policy" "$RACOON_SRC_DIR/src/racoon"/*.c "$RACOON_SRC_DIR/src/racoon"/*.h 2>/dev/null || echo "(no matches)"
	else
		echo "(RACOON_SRC_DIR=$RACOON_SRC_DIR does not contain src/racoon -- set RACOON_SRC_DIR to a checkout of this repo to run this check)"
	fi
} > "$OUT/07-generate-policy-grep.log" 2>&1

{
	echo "--- distro-packaged setkey/ipsec-tools units independent of racoon ---"
	if command -v systemctl >/dev/null 2>&1; then
		systemctl list-unit-files 2>/dev/null | grep -iE "setkey|ipsec-tools|ipsec" || echo "(no matching unit files)"
		echo
		for u in setkey.service ipsec-tools.service; do
			echo "-- systemctl status $u --"
			systemctl status "$u" 2>&1 | head -10
		done
	else
		echo "(systemctl not available -- check init scripts manually, e.g. /etc/init.d/setkey)"
	fi
} > "$OUT/07-distro-units.log" 2>&1

{
	echo "--- comparing step 5's leftover SPD (if any) against the hook's state file ---"
	if [ -s "$OUT/05-post-teardown-filtered-spd.log" ]; then
		echo "leftover SPD selectors:"
		grep -E "^src |^dst " "$OUT/05-post-teardown-filtered-spd.log" 2>/dev/null
		echo
		echo "spddelete lines the hook's state file records as this run's own undo commands:"
		grep -oE "spddelete [^;']+" "$OUT/04-hook-state-content.log" 2>/dev/null || echo "(none found in state file content)"
		echo
		echo "Manually compare the two lists above: an exact selector match means this"
		echo "is a hook bug (recorded as torn down but still present); no match means"
		echo "it was never the hook's own selector to begin with."
	else
		echo "(no leftover SPD in step 5 -- nothing to compare)"
	fi
} > "$OUT/07-spd-vs-state-file-compare.log" 2>&1

narrate "step 7 captures written: 07-generate-policy-grep.log, 07-distro-units.log, 07-spd-vs-state-file-compare.log"

# ==========================================================================
# Cleanup: stop the background log capture; leave racoon running or not,
# investigator's call (left running here since a re-run of steps 4-6 by
# hand may be useful before tearing the container down).
# ==========================================================================
[ -n "${JOURNAL_PID:-}" ] && kill "$JOURNAL_PID" 2>/dev/null

{
	echo
	echo "## Files in this results directory"
	echo
	ls -la "$OUT"
} >> "$SUMMARY"

narrate "=== DONE ==="
narrate "Results directory: $OUT"
narrate "Start with $SUMMARY, then cross-reference 04-hook-state-content.log against 04/05-*-filtered-spd.log by hand for the parts this script only captured rather than concluded."
narrate "Hand the whole directory back (tar czf task-f-results-${TS}.tar.gz -C /root task-f-results-${TS}) for the doc/dev/teardown-investigation.md write-up."
