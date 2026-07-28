#!/bin/bash
# racoon-hook-integration-test.sh -- live-host integration test and
# evidence-capture tool for the split-DNS/routing hooks
# (racoon-hook-lib.sh, phase1-up.sh, phase1-down.sh).
#
# Drives a full connect/verify/disconnect cycle against a real gateway on
# a real IPsec-capable host, capturing timestamped, reproducible evidence
# at every stage: capability preflight, network-management backend
# snapshot, SPD/SA/hook-state snapshots before and after each transition,
# and a small set of built-in live checks for specific correctness
# questions this project has needed to answer against real evidence
# rather than a sandbox:
#
#   - Steps 5/6 ("Branch A"/"Branch B"): does any SPD policy survive a
#     confirmed-complete phase1-down.sh, and does that provoke a kernel
#     ACQUIRE / on-demand reconnection? Originated as the Task F
#     ACQUIRE-provenance investigation (doc/dev/teardown-investigation.md);
#     kept as a standing regression check, not a one-off.
#   - Steps 3b/4b/5c (issue #90): does phase1-down.sh's state-file
#     generation matching pick this run's own generation, by its
#     IKE_COOKIE, or can it be fooled by an orphaned generation left
#     behind by an earlier, never-cleanly-torn-down session for the same
#     peer? A synthetic orphan is injected before connect (a fake
#     IKE_COOKIE no real negotiation could produce, and an undo_command
#     that only touches a marker file under $OUT) and its state is
#     inspected after teardown.
#
# This tool does not fix anything -- it only observes and records. Add a
# new built-in check here, following the same pattern, whenever a future
# question needs the same kind of live, reproducible evidence; that is
# the intent behind checking this in under version control rather than
# treating it as a one-off script.
#
# WHERE TO RUN THIS: a network-namespace-capable container or host with a
# real, unmodified kernel IPsec stack (Incus, privileged Docker with
# --cap-add=NET_ADMIN, systemd-nspawn, or a real machine) -- NOT a
# minimal/stripped-kernel sandbox. Step 0 checks for this itself and
# aborts with a clear reason rather than producing a false negative if
# it's missing (this repo's own CI sandbox cannot run PF_KEY at all).
#
# WHAT THIS ASSUMES IS ALREADY IN PLACE: a working racoon.conf + hooks.conf
# on this host, already configured and already proven to connect to a
# real gateway -- this script does not stand up a new IKEv1 lab from
# scratch, it orchestrates and captures evidence around your existing,
# already-working configuration.
#
# Usage:
#   sudo VPN_GATEWAY=<gateway-host-or-ip> \
#        INTERNAL_DNS_SERVER=<internal-dns-ip> \
#        [SCENARIO_LABEL="free text describing this run's network-management setup"] \
#        [RACOON_SRC_DIR=/path/to/racoon-ipsec-tools] \
#        [SETKEY_BIN=setkey] [RACOONCTL_BIN=racoonctl] [RACOON_BIN=racoon] \
#        [STATE_DIR=/run/racoon] [RACOON_CONF=/etc/racoon/racoon.conf] \
#        [PHASE1_DOWN_SCRIPT=/path/to/phase1-down.sh] \
#        ./racoon-hook-integration-test.sh
#
# SCENARIO_LABEL is optional free text (e.g. "NM, rc-manager=unmanaged,
# systemd-networkd also running" / "NM, rc-manager=auto" / "no NM, pure
# systemd-networkd") -- it's just echoed into SUMMARY.md's header so
# multiple runs stay identifiable after the fact. The script does NOT
# trust it as ground truth: step 0b independently captures the real,
# live NetworkManager/systemd-networkd/rc-manager state regardless of
# what this label says, so different network-management scenarios are
# distinguishable from the evidence itself, not just from a hand-typed
# tag.
#
# KEEP_RACOON_RUNNING=1 leaves the racoon instance this script started
# running at the end instead of terminating it (the default) -- only
# useful for manually poking at steps 4-6 afterward; leave it unset for
# back-to-back runs, since step 2's pre-existing-racoon guard will
# otherwise hard-stop the next run.
#
# VPN_GATEWAY CAVEAT (shared by step 5b and the issue #90 steps 3b/4b/5c):
# hook-state filenames are built from racoon's own REMOTE_ADDR, the
# resolved numeric peer address -- not necessarily the same string as
# VPN_GATEWAY if you pass a hostname. Pass VPN_GATEWAY as the literal
# address racoon.conf's remote{} block resolves to (check
# 04-hook-state-listing.log's actual filenames against what you passed if
# a step ever reports "none found" unexpectedly) for these checks to line
# up exactly.
#
# Everything is captured under a timestamped results directory printed at
# the end -- tar it up and hand it back for whoever is triaging the
# question this particular run was investigating. See
# doc/dev/teardown-investigation.md for the ACQUIRE-provenance
# investigation this tool originated from.

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
# Used only by step 5c's orphan cleanup/positive-path confirmation; empty
# means "auto-detect from the 'script ... phase1_down;' line in
# $RACOON_CONF", the same script racoon itself is already configured to
# run.
PHASE1_DOWN_SCRIPT="${PHASE1_DOWN_SCRIPT:-}"
CONNECT_TIMEOUT="${CONNECT_TIMEOUT:-30}"
PHASE1_UP_WAIT_TIMEOUT="${PHASE1_UP_WAIT_TIMEOUT:-15}"
PHASE1_DOWN_WAIT_TIMEOUT="${PHASE1_DOWN_WAIT_TIMEOUT:-15}"
ACQUIRE_WATCH_SECONDS="${ACQUIRE_WATCH_SECONDS:-8}"
SCENARIO_LABEL="${SCENARIO_LABEL:-<none given>}"

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
# per-socket policies are the kernel's own transport-mode bookkeeping for
# local sockets requesting IPsec, not anything the hook or racoon
# installed -- always present as soon as racoon is running (racoon's own
# PF_KEY registration creates them automatically, confirmed empirically:
# 03-post-start-filtered-spd.log has real content on every run from the
# moment racoon starts, before any connect), always noise for this
# investigation.
#
# Uses setkey's own native -N filter (confirmed present in this project's
# setkey.c: f_nosock, getopt string "...N?" at setkey.c:190) rather than
# the task brief's original suggested `setkey -DP | awk '!/(per-socket
# policy)/'` -- the kernel-side filter is simpler and doesn't depend on
# an awk regex staying in sync with setkey's own text formatting. This
# supersedes that awk pattern; do not reintroduce it.
#
# The raw output is still written verbatim (not further edited) so the
# artifact stays a faithful capture -- but setkey.c's postproc() (~713-819)
# confirms two banner lines that mean "nothing real here" and must NOT be
# treated as real content by callers:
#   "No SPD entries."                                  (SADB_X_SPDDUMP/ENOENT)
#   "<n> per-socket policy/policies not shown (filtered by -N)"
# Use spd_file_has_real_policy() below instead of a plain `[ -s file ]`
# test everywhere this matters -- a plain non-empty test would treat
# either banner as "real" and produce a false Branch-A signal on every
# single dump taken after racoon starts.
# --------------------------------------------------------------------------
filtered_spd() {
	"$SETKEY_BIN" -DPN 2>&1
}

spd_file_has_real_policy() {
	grep -v -E '^$|^No SPD entries\.$|^[0-9]+ per-socket (policy|policies) not shown \(filtered by -N\)$' "$1" 2>/dev/null | grep -q .
}

# --------------------------------------------------------------------------
# Waits for a hook's own one-line completion summary in the syslog
# capture, scoped to lines appended after a given line-count marker (so a
# stale line from an earlier phase in the same run, or a previous run's
# leftover log, can't produce a false-positive match).
#
# Deliberately does NOT grep for the "racoon phase1-up/down report --"
# header text: confirmed against racoon-hook-lib.sh (~line 122, ~768-775)
# that header is part of the multi-line report block gated behind
# `rhook_level >= 1`, and RHOOK_DEBUG_LEVEL defaults to 0 ("syslog only:
# errors, warnings, the final one-line summary") -- under default
# settings that header is never emitted at all, so waiting on it would
# hang for the full timeout on every run, every time, not just
# occasionally. The one-line "result: OK|PARTIAL" summary emitted via
# `logger -t "racoon-${RHOOK_HOOK_NAME}"` (racoon-hook-lib.sh ~line 785)
# is unconditional regardless of debug level -- that is the only
# reliable completion signal available without changing the hooks'
# configured verbosity.
# --------------------------------------------------------------------------
wait_for_hook_report() {
	hook_name="$1"
	since_line="$2"
	timeout_s="$3"
	i=0
	while [ "$i" -lt "$timeout_s" ]; do
		if tail -n "+$((since_line + 1))" "$RACOON_LOG" 2>/dev/null | \
		   grep -qE "racoon-${hook_name}(\[[0-9]+\])?: result: (OK|PARTIAL)"; then
			return 0
		fi
		sleep 1
		i=$((i + 1))
	done
	return 1
}

# --------------------------------------------------------------------------
# issue #90 live verification helpers (steps 3b/4b/5c below).
#
# peer_state_prefix() mirrors racoon-hook-lib.sh's rhook_state_file_prefix()
# exactly (same "$STATE_DIR/hook-state.<addr>" shape) -- see the
# VPN_GATEWAY CAVEAT in the header comment above for why this only lines
# up when VPN_GATEWAY is the literal resolved address.
#
# peer_max_generation() mirrors rhook_state_max_generation() exactly
# (counts both live and .consumed files; a .cookie sidecar or the .lock
# directory both fail the trailing-numeric check below without needing
# their own case arm, same as in the real implementation) -- so the
# synthetic orphan step 3b injects lands one past whatever this peer's
# real state already contains on disk, and this run's own real
# generation (allocated independently by the actual rhook_state_reset()
# when phase1-up.sh runs) lands one past THAT, preserving the original
# live bug's exact ordering: orphan older/lower, real session newer/
# higher.
# --------------------------------------------------------------------------
peer_state_prefix() {
	printf '%s/hook-state.%s' "$STATE_DIR" "$VPN_GATEWAY"
}

peer_max_generation() {
	local prefix f gen max=0
	prefix="$(peer_state_prefix)"
	for f in "$prefix".*; do
		[ -e "$f" ] || continue
		case "$f" in *.lock) continue ;; esac
		gen="${f#"$prefix".}"
		gen="${gen%.consumed}"
		case "$gen" in ''|*[!0-9]*) continue ;; esac
		if [ "$gen" -gt "$max" ] 2>/dev/null; then
			max="$gen"
		fi
	done
	printf '%s' "$max"
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
# Step 0b: network-management backend snapshot. Captures the REAL,
# live state (NetworkManager/systemd-networkd/systemd-resolved active or
# not, rc-manager, resolv.conf target) rather than trusting SCENARIO_LABEL
# alone -- this is what makes the three planned scenarios (NM w/
# rc-manager=unmanaged + networkd also running; NM w/ rc-manager=auto; no
# NM at all) distinguishable from the evidence itself when comparing runs
# later, independent of whether the label was typed correctly.
# ==========================================================================
narrate "=== Step 0b: network-management backend snapshot ==="
{
	echo "SCENARIO_LABEL=$SCENARIO_LABEL"
	echo
	echo "--- systemctl is-active NetworkManager / systemd-networkd / systemd-resolved ---"
	if command -v systemctl >/dev/null 2>&1; then
		for u in NetworkManager systemd-networkd systemd-resolved; do
			printf '%s: ' "$u"
			systemctl is-active "$u" 2>&1
		done
	else
		echo "(systemctl not available)"
	fi
	echo
	echo "--- busctl get-property org.freedesktop.NetworkManager (DnsManager Mode/RcManager) ---"
	if command -v busctl >/dev/null 2>&1; then
		busctl get-property org.freedesktop.NetworkManager /org/freedesktop/NetworkManager/DnsManager org.freedesktop.NetworkManager.DnsManager Mode 2>&1
		busctl get-property org.freedesktop.NetworkManager /org/freedesktop/NetworkManager/DnsManager org.freedesktop.NetworkManager.DnsManager RcManager 2>&1
	else
		echo "(busctl not available -- NetworkManager likely not installed/running)"
	fi
	echo
	echo "--- /etc/resolv.conf (readlink -f, and contents if a regular file) ---"
	readlink -f /etc/resolv.conf 2>&1
	if [ -L /etc/resolv.conf ]; then
		echo "(symlink)"
	elif [ -f /etc/resolv.conf ]; then
		echo "(regular file) contents:"
		cat /etc/resolv.conf 2>&1
	fi
	echo
	echo "--- /etc/NetworkManager/conf.d/*.conf (any rc-manager/dns overrides) ---"
	for f in /etc/NetworkManager/conf.d/*.conf; do
		[ -f "$f" ] || continue
		echo "=== $f ==="
		cat "$f"
		echo
	done
	echo
	echo "--- resolvectl status (best effort, non-fatal if unavailable) ---"
	if command -v resolvectl >/dev/null 2>&1; then
		resolvectl status --no-pager 2>&1 | head -40
	elif command -v systemd-resolve >/dev/null 2>&1; then
		systemd-resolve --status 2>&1 | head -40
	else
		echo "(neither resolvectl nor systemd-resolve available)"
	fi
} > "$OUT/00b-network-backend-snapshot.log" 2>&1
narrate "network-backend snapshot written to $OUT/00b-network-backend-snapshot.log -- verify it actually matches the scenario you intended to run before trusting the rest of this run's results"

# ==========================================================================
# Step 0c: three environmental assumptions this script relies on, made
# explicit as preflight checks instead of staying implicit (found via a
# review pass on PR #91, comment #36). None of these are as clear-cut as
# step 0/step 2's hard-stop guards, so none of them fail_stop:
#
# 1. A clean STATE_DIR for this peer -- step 3b's synthetic orphan is
#    numbered relative to whatever's already on disk (peer_max_generation()),
#    so it still lands correctly even with real leftovers present; what a
#    hard-stop would miss is that pre-existing live generations are
#    themselves worth knowing about (a previous run's own teardown that
#    never happened), not something to silently work around.
# 2. No other PF_KEY listener already running -- the same contamination
#    concern step 2's pre-existing-racoon guard covers, extended to other
#    IKE daemons. Deliberately checks for a *running process*
#    (pgrep), not `systemctl is-active`: a one-shot setkey.service that
#    loaded static SPD/SA at boot and exited reports "active (exited)"
#    under systemd -- confirmed on our own live Noble/Bionic/Arch runs'
#    own 07-distro-units.log captures -- and is not a competing listener
#    at all; `is-active` alone would false-positive on exactly the hosts
#    this script is meant to run on.
# 3. VPN_GATEWAY resolves to the literal address hook-state filenames
#    use -- upgrades the header comment's VPN_GATEWAY CAVEAT from
#    documentation into something this run actually checks for itself.
# ==========================================================================
narrate "=== Step 0c: preflight assumption checks ==="
{
	echo "--- 1. live (non-.consumed, non-.cookie) hook-state generations already on disk for $VPN_GATEWAY ---"
	rhook_preexisting_live=""
	for f in "$(peer_state_prefix)".*; do
		[ -f "$f" ] || continue
		case "$f" in *.consumed|*.cookie|*.lock) continue ;; esac
		echo "$f"
		rhook_preexisting_live="${rhook_preexisting_live:+$rhook_preexisting_live }$f"
	done
	[ -n "$rhook_preexisting_live" ] || echo "(none)"
	echo
	echo "--- 2. running processes for other IKE/IPsec daemons (charon, pluto) ---"
	pgrep -a -x charon 2>&1 || echo "(no charon)"
	pgrep -a -x pluto 2>&1 || echo "(no pluto)"
	echo
	echo "--- 3. VPN_GATEWAY resolution ---"
	rhook_resolved="$(getent ahostsv4 "$VPN_GATEWAY" 2>/dev/null | awk '{print $1; exit}')"
	echo "VPN_GATEWAY=$VPN_GATEWAY resolves to=${rhook_resolved:-<getent lookup failed>}"
} > "$OUT/00c-preflight-assumptions.log" 2>&1

if [ -n "$rhook_preexisting_live" ]; then
	narrate "WARNING: live hook-state generation(s) already on disk for $VPN_GATEWAY before this run touched anything -- an earlier session's own teardown may never have happened. Not stopping (step 3b's synthetic orphan still numbers correctly around them), but see $OUT/00c-preflight-assumptions.log and consider investigating separately from this run's own result."
fi
if pgrep -x charon >/dev/null 2>&1 || pgrep -x pluto >/dev/null 2>&1; then
	fail_stop "another IKE daemon (charon or pluto) is already running -- this invalidates PF_KEY/SPD attribution for the whole run, same reasoning as step 2's pre-existing-racoon guard. Stop it first and confirm neither 'pgrep -x charon' nor 'pgrep -x pluto' finds anything, then re-run."
fi
if [ -n "$rhook_resolved" ] && [ "$rhook_resolved" != "$VPN_GATEWAY" ]; then
	narrate "WARNING: VPN_GATEWAY=$VPN_GATEWAY resolves to $rhook_resolved -- racoon's own REMOTE_ADDR (and therefore every hook-state filename) will use $rhook_resolved, not the hostname you passed. Steps 5b/5c and the PRESUMED_OWN_GEN lookups below assume VPN_GATEWAY is already that literal address; re-run with VPN_GATEWAY=$rhook_resolved if those steps report 'none found' unexpectedly."
fi
narrate "preflight assumption checks done (see $OUT/00c-preflight-assumptions.log) -- continuing"

# ==========================================================================
# Step 1: baseline. setkey -F is SAD only -- never touches SPD -- so a
# non-empty filtered -DP result here is itself evidence, not noise to
# clear away. Recorded, not auto-flushed.
# ==========================================================================
narrate "=== Step 1: baseline ==="
"$SETKEY_BIN" -F > "$OUT/01-setkey-F.log" 2>&1
narrate "setkey -F (SAD flush) done"
filtered_spd > "$OUT/01-baseline-filtered-spd.log"
if spd_file_has_real_policy "$OUT/01-baseline-filtered-spd.log"; then
	narrate "WARNING: baseline filtered SPD is NOT empty -- see $OUT/01-baseline-filtered-spd.log. This predates racoon even starting; if it's still present after phase1-down in step 5, it did NOT come from this test run's own connection."
else
	narrate "baseline filtered SPD is empty, as expected (nothing is running yet, so setkey -DPN has nothing to filter either -- expect the literal 'No SPD entries.' line in the file, that's normal)"
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

# --------------------------------------------------------------------------
# Guard against a pre-existing racoon instance. Both real Task F runs so
# far showed two concurrent racoon PIDs -- the system's own racoon.service
# (already running, foreground-mode log signature) plus this script's
# freshly-started -f instance -- both registered as PF_KEY listeners at
# once. That contaminates every SPD/SA observation this script makes: it
# can no longer tell which process installed/owns what. Hard-stop rather
# than silently proceeding with two daemons, matching step 0's own
# precedent of refusing to produce evidence it can't vouch for.
# --------------------------------------------------------------------------
{
	echo "--- pgrep -x racoon (any already-running racoon process) ---"
	pgrep -a -x racoon 2>&1 || echo "(none found)"
	echo
	echo "--- racoonctl show-sa isakmp (before this script starts anything) ---"
	"$RACOONCTL_BIN" show-sa isakmp 2>&1
	echo
	echo "--- systemctl status racoon.service (if applicable) ---"
	command -v systemctl >/dev/null 2>&1 && systemctl status racoon.service 2>&1 | head -10 || echo "(systemctl not available or no racoon.service unit)"
} > "$OUT/02-pre-existing-racoon-check.log" 2>&1

if pgrep -x racoon >/dev/null 2>&1; then
	fail_stop "a racoon process is already running (see $OUT/02-pre-existing-racoon-check.log) -- this invalidates PF_KEY/SPD attribution for the whole run. Stop it first (e.g. 'systemctl stop racoon.service' if that's what owns it, or 'killall racoon' otherwise) and confirm 'pgrep -x racoon' returns nothing, then re-run this script."
fi
narrate "no pre-existing racoon process found -- proceeding (see $OUT/02-pre-existing-racoon-check.log)"

# Continuous background syslog capture for the rest of the run -- one
# capture, referenced by timestamp/grep at each step, rather than
# starting/stopping journalctl repeatedly.
RACOON_LOG="$OUT/racoon-syslog.log"
if command -v journalctl >/dev/null 2>&1; then
	# Three -t values, not one: racoon's own plog() output goes out under
	# syslog identifier "racoon", but the hooks' own one-line completion
	# summaries go out separately under "racoon-phase1-up"/
	# "racoon-phase1-down" (racoon-hook-lib.sh: `logger -t
	# "racoon-${RHOOK_HOOK_NAME}"`) -- a plain `-t racoon` filter never
	# sees those at all. journalctl ORs repeated -t values (matching its
	# documented behaviour for repeated same-field filters, same as -u),
	# so this captures all three streams into one interleaved,
	# chronologically-ordered log.
	journalctl -f -t racoon -t racoon-phase1-up -t racoon-phase1-down --no-pager > "$RACOON_LOG" 2>&1 &
	JOURNAL_PID=$!
	narrate "background log capture: journalctl -f -t racoon -t racoon-phase1-up -t racoon-phase1-down (pid $JOURNAL_PID) -> $RACOON_LOG"
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
# Racoon daemonized (forked, detached, parent exited) -- the PID the shell
# just ran is already gone. Capture the real daemon's PID now, while the
# pre-existing-racoon guard above still guarantees there's exactly one,
# so cleanup can terminate the right (and only) process later instead of
# leaving it running for the next scenario run to trip over.
RACOON_PID="$(pgrep -x racoon | head -1)"
narrate "racoon -f is up (pid ${RACOON_PID:-unknown}) and answering racoonctl show-sa isakmp"

# ==========================================================================
# Step 3: filtered setkey -DPN before any connect. If a real (non-
# per-socket) policy shows up here, stop -- this is the single cleanest
# way to catch a generate_policy or daemon-installed trap in the act,
# uncontaminated by anything the hook does later.
#
# Per-socket policies themselves are EXPECTED here and are not a signal
# of anything: racoon creates them automatically as soon as it starts
# (confirmed empirically -- this file legitimately contains the "<n>
# per-socket policy/policies not shown (filtered by -N)" banner on every
# run from this step onward, never "No SPD entries." again once racoon
# is up). spd_file_has_real_policy() already discounts that banner; do
# not "fix" this step by expecting the raw file to be byte-empty.
# ==========================================================================
narrate "=== Step 3: filtered SPD immediately after racoon start, before connect ==="
filtered_spd > "$OUT/03-post-start-filtered-spd.log"
if spd_file_has_real_policy "$OUT/03-post-start-filtered-spd.log"; then
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
narrate "no real (non-per-socket) policy present before connect, as expected -- continuing (see $OUT/03-post-start-filtered-spd.log -- a per-socket-only banner there is normal, not a finding)"

# ==========================================================================
# Step 3b: inject a synthetic orphan generation (issue #90 live setup).
# See the header comment block and peer_state_prefix()/peer_max_generation()
# above for the full rationale. Injected AFTER racoon has started (so
# $STATE_DIR exists) and BEFORE this run's own connect (so this run's
# real generation is allocated strictly after the synthetic one, exactly
# like the live Arch host's own accumulated orphans in
# doc/dev/teardown-investigation.md).
#
# The synthetic generation's single state-file line uses the same
# id/type/outcome/undo_command shape rhook_state_append() writes
# (racoon-hook-lib.sh); "outcome" must be exactly "ok" for
# rhook_undo_replay() to ever consider running its undo_command at all,
# and that undo_command only ever touches $ORPHAN_MARKER under $OUT --
# never a real route/policy/DNS command -- so this is safe to actually
# execute for real against a live host if the pre-fix bug is what's
# still deployed here.
# ==========================================================================
narrate "=== Step 3b: injecting a synthetic orphan generation for issue #90 live verification ==="
mkdir -p "$STATE_DIR" 2>/dev/null
ORPHAN_GEN="$(( $(peer_max_generation) + 1 ))"
ORPHAN_STATE_FILE="$(peer_state_prefix).${ORPHAN_GEN}"
ORPHAN_MARKER="$OUT/03b-orphan-was-wrongly-consumed.marker"
FAKE_COOKIE="deadbeefdeadbeef:cafefeedcafefeed"
rm -f "$ORPHAN_MARKER"
printf 'orphan_marker\ttest_synthetic\tok\ttouch "%s"\n' "$ORPHAN_MARKER" > "$ORPHAN_STATE_FILE" 2>/dev/null
printf '%s' "$FAKE_COOKIE" > "${ORPHAN_STATE_FILE}.cookie" 2>/dev/null
if [ -s "$ORPHAN_STATE_FILE" ] && [ -s "${ORPHAN_STATE_FILE}.cookie" ]; then
	narrate "synthetic orphan generation $ORPHAN_GEN injected at $ORPHAN_STATE_FILE (fake IKE_COOKIE=$FAKE_COOKIE) -- this run's own real generation must land at $(( ORPHAN_GEN + 1 )) or higher, and this run's own phase1-down.sh must consume only that one, never this orphan"
else
	narrate "WARNING: could not write the synthetic orphan files under $STATE_DIR (permissions?) -- skipping the issue #90 live verification in steps 4b/5c below; everything else in this script is unaffected"
	ORPHAN_GEN=""
fi

# ==========================================================================
# Step 4: full connect -> verified -> disconnect cycle, filtered -DP at
# each stage, cross-referenced against the hook's own state file.
# ==========================================================================
narrate "=== Step 4: racoonctl vpn-connect $VPN_GATEWAY ==="
PRE_CONNECT_LOGLINE_COUNT="$(wc -l < "$RACOON_LOG" 2>/dev/null || echo 0)"
if ! timeout "$CONNECT_TIMEOUT" "$RACOONCTL_BIN" vpn-connect "$VPN_GATEWAY" > "$OUT/04-vpn-connect.log" 2>&1; then
	cat "$OUT/04-vpn-connect.log"
	fail_stop "racoonctl vpn-connect $VPN_GATEWAY did not complete within ${CONNECT_TIMEOUT}s -- see $OUT/04-vpn-connect.log and $RACOON_LOG"
fi
narrate "vpn-connect returned (blocks on EVT_PHASE1_MODE_CFG, so Mode Config is confirmed complete)"

# --------------------------------------------------------------------------
# Same ordering gap as phase1-down, mirrored: confirmed against
# isakmp_cfg.c (script_hook(SCRIPT_PHASE1_UP) fires before
# evt_phase1(EVT_PHASE1_MODE_CFG)) and isakmp.c/privsep.c (script_hook()
# forks and returns immediately, never waits for the child). So
# "vpn-connect returned" is not the same moment as "phase1-up.sh
# finished" either -- confirmed empirically too: both earlier Bionic
# archives show 04-connected-filtered-spd.log coming back 0 bytes despite
# the hook's own state file (captured moments later) showing a fully
# successful, later-consumed run. Wait explicitly before snapshotting.
# --------------------------------------------------------------------------
narrate "waiting for phase1-up.sh's own completion summary before snapshotting connected-state SPD/hook-state..."
if wait_for_hook_report "phase1-up" "$PRE_CONNECT_LOGLINE_COUNT" "$PHASE1_UP_WAIT_TIMEOUT"; then
	PHASE1_UP_CONFIRMED=1
	narrate "phase1-up.sh's completion summary confirmed in syslog -- snapshotting now, at the correct moment"
else
	PHASE1_UP_CONFIRMED=0
	narrate "WARNING: did not see phase1-up.sh's completion summary within ${PHASE1_UP_WAIT_TIMEOUT}s -- either the hook isn't wired into racoon.conf's remote block (check for 'script ... phase1_up;'), or it's taking unusually long. Snapshotting anyway, but treat 04-connected-filtered-spd.log/04-hook-state-*.log with the same caution this produced in earlier runs."
fi

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

# --------------------------------------------------------------------------
# Best-guess identifier for "this run's own" generation, for step 5b's
# FIFO-consumption check below: the highest live (non-.consumed) generation
# number for this exact peer, captured right now -- i.e. moments after this
# run's own phase1-up.sh created it, before phase1-down.sh has had any
# chance to touch anything. Not proof by itself (a concurrent unrelated
# session for the same peer would break this assumption), just the best
# available signal without changing the hooks' own state-file format.
# --------------------------------------------------------------------------
PRESUMED_OWN_GEN="$(
	for f in "$STATE_DIR"/hook-state."$VPN_GATEWAY".*; do
		[ -f "$f" ] || continue
		case "$f" in *.consumed|*.lock) continue ;; esac
		gen="${f##*.}"
		case "$gen" in ''|*[!0-9]*) continue ;; esac
		printf '%s\n' "$gen"
	done | sort -n | tail -1
)"
narrate "presumed own generation for $VPN_GATEWAY (highest live one right now): ${PRESUMED_OWN_GEN:-<none found -- check $STATE_DIR/hook-state.* naming manually>}"

# --------------------------------------------------------------------------
# Step 4b: IKE_COOKIE cross-check (issue #90). script_hook()'s IKE_COOKIE
# export (src/racoon/isakmp.c) and the "ISAKMP-SA established ...
# spi:%s" log line (isakmp.c, log_ph1established()) are rendered from the
# exact same call -- isakmp_pindex(&iph1->index, 0) -- so this run's own
# .cookie sidecar must equal ORIGINAL_SPI's value verbatim if, and only
# if, the racoon binary actually running on this host is the patched
# one. This is the most direct live confirmation available that the
# fix's daemon-side half is actually deployed here, not just present in
# source -- everything downstream (rhook_state_own_generation()'s exact
# match) depends on IKE_COOKIE existing at all.
# --------------------------------------------------------------------------
IKE_COOKIE_LIVE=""
IKE_COOKIE_CHECK="not run (no presumed own generation found -- see 04-hook-state-listing.log)"
if [ -n "$PRESUMED_OWN_GEN" ]; then
	OWN_COOKIE_FILE="$(peer_state_prefix).${PRESUMED_OWN_GEN}.cookie"
	if [ -s "$OWN_COOKIE_FILE" ]; then
		IKE_COOKIE_LIVE="$(cat "$OWN_COOKIE_FILE" 2>/dev/null)"
		SPI_BARE="${ORIGINAL_SPI#spi:}"
		if [ -n "$SPI_BARE" ] && [ "$IKE_COOKIE_LIVE" = "$SPI_BARE" ]; then
			IKE_COOKIE_CHECK="MATCH: IKE_COOKIE ($IKE_COOKIE_LIVE) equals racoon's own logged SPI -- this host is running the issue #90 patch"
		else
			IKE_COOKIE_CHECK="MISMATCH: IKE_COOKIE ($IKE_COOKIE_LIVE) does not equal racoon's own logged SPI (${SPI_BARE:-<not captured>}) -- see $RACOON_LOG and $OWN_COOKIE_FILE by hand"
		fi
	else
		IKE_COOKIE_CHECK="NO .cookie SIDECAR FOUND at $OWN_COOKIE_FILE -- this host's racoon does not export IKE_COOKIE (pre-issue-90 build), or the hook library predates the fix. Steps 4b/5c below will show the pre-fix behaviour, if step 3b's injection succeeded."
	fi
fi
narrate "IKE_COOKIE cross-check: $IKE_COOKIE_CHECK"

narrate "=== disconnecting: racoonctl vpn-disconnect $VPN_GATEWAY ==="
PRE_DISCONNECT_LOGLINE_COUNT="$(wc -l < "$RACOON_LOG" 2>/dev/null || echo 0)"
if ! timeout "$CONNECT_TIMEOUT" "$RACOONCTL_BIN" vpn-disconnect "$VPN_GATEWAY" > "$OUT/04-vpn-disconnect.log" 2>&1; then
	cat "$OUT/04-vpn-disconnect.log"
	# A fast, silent nonzero exit here (0-byte log, well under
	# CONNECT_TIMEOUT) is NOT the same thing as an actual timeout, and is
	# not by itself evidence that the disconnect failed: confirmed against
	# this tree's own src/racoon/kmpstat.c com_recv() -- both its
	# MSG_PEEK-failure and short-read paths (~149-154) `goto bad1` with no
	# perror() at all, so if the admin socket EOFs before the
	# EVT_PHASE1_DOWN event arrives over that specific connection,
	# racoonctl's f_vc loop (racoonctl.c ~322-326) exits(1) completely
	# silently while racoon's own teardown proceeds independently and
	# usually still succeeds moments later. Only the explicit
	# wait-for-phase1-down-completion check right below is authoritative;
	# this message is a heads-up to look closer if that wait also fails,
	# not a standalone failure verdict.
	narrate "WARNING: racoonctl vpn-disconnect exited non-zero (see $OUT/04-vpn-disconnect.log, likely 0 bytes -- a known silent com_recv()/admin-socket race, not necessarily a real failure). Waiting for phase1-down.sh's own completion below is what actually decides this, not this exit code."
fi

# --------------------------------------------------------------------------
# Critical timing detail, confirmed against this tree's own
# src/racoon/isakmp.c (isakmp_ph1delete()): evt_phase1(EVT_PHASE1_DOWN) --
# what racoonctl vpn-disconnect blocks on -- fires BEFORE delph1() is
# called, and delph1() (handler.c) is what actually invokes
# script_hook(SCRIPT_PHASE1_DOWN), i.e. phase1-down.sh. So
# "vpn-disconnect returned" is NOT the same moment as "phase1-down.sh
# completed" -- there is a real ordering gap. Wait explicitly for the
# hook's own completion summary rather than trusting vpn-disconnect's
# return alone. (Earlier version of this script grepped for the
# "racoon phase1-down report --" header text; that header is part of the
# multi-line report gated behind hook debug level >= 1, and the default
# level is 0 -- under default settings it never appears at all, so that
# check could never actually succeed. Fixed to use the same
# always-emitted one-line summary the connect-side wait above uses.)
# --------------------------------------------------------------------------
narrate "vpn-disconnect returned -- this is EVT_PHASE1_DOWN, NOT phase1-down.sh's own completion (confirmed against isakmp_ph1delete()'s ordering: evt_phase1() fires before delph1() calls script_hook(SCRIPT_PHASE1_DOWN)). Waiting explicitly for the hook's own completion summary..."

if wait_for_hook_report "phase1-down" "$PRE_DISCONNECT_LOGLINE_COUNT" "$PHASE1_DOWN_WAIT_TIMEOUT"; then
	PHASE1_DOWN_CONFIRMED=1
	narrate "phase1-down.sh's completion summary confirmed in syslog -- proceeding to the fork-in-the-road check now, at the correct moment"
else
	PHASE1_DOWN_CONFIRMED=0
	narrate "WARNING: did not see phase1-down.sh's completion summary within ${PHASE1_DOWN_WAIT_TIMEOUT}s -- either the hook isn't wired into racoon.conf's remote block (check for 'script ... phase1_down;'), or it's taking unusually long. Proceeding anyway since the task's own step 5 still needs a result, but flag this explicitly in the write-up rather than treating the timing as clean."
fi
tail -n "+$((PRE_DISCONNECT_LOGLINE_COUNT + 1))" "$RACOON_LOG" 2>/dev/null | grep -E "racoon-phase1-down" > "$OUT/04-phase1-down-report.log" 2>/dev/null

# ==========================================================================
# Step 4c: racoon liveness check after disconnect. Found live (not
# hypothetical): a bug in admin.c's ADMIN_DELETE_ALL_SA_DST handling could
# make racoon's own main loop exit silently right after a real
# racoonctl vpn-disconnect, no core dump, logging only
# "ERROR: failed to send admin command: Broken pipe" /
# "ERROR: failed to select (Bad file descriptor)" moments before dying
# (doc/dev/daemon-issues.md's Issue 4 follow-up has the full trace). This
# run's own earlier evidence (task-f-results-20260727T172711Z) had exactly
# this in racoon-syslog.log at the time and still reported a clean run:
# the async SCRIPT_PHASE1_DOWN hook had already been fork()'d before
# racoon died, so it kept running and reporting success independently,
# and step 5's SPD check queries the kernel directly, not racoon --
# neither could see racoon was already gone. Only cleanup (the very last
# step) noticed at all, and only narrated it as benign ("already gone by
# cleanup time -- nothing to terminate"), not as a failure. Checking here,
# right after disconnect (when racoon is expected to still be running --
# nothing in this script's own design stops it before final cleanup),
# closes that gap.
# ==========================================================================
narrate "=== Step 4c: racoon liveness check after disconnect ==="
RACOON_DIED_AFTER_DISCONNECT=0
if [ -n "${RACOON_PID:-}" ] && ! kill -0 "$RACOON_PID" 2>/dev/null; then
	RACOON_DIED_AFTER_DISCONNECT=1
	narrate "*** FAIL: racoon (pid $RACOON_PID) is no longer running after vpn-disconnect -- it should still be alive here (this script does not stop it until final cleanup). See $RACOON_LOG around the disconnect timestamp for the ERROR line(s) that likely explain why. ***"
else
	narrate "racoon (pid ${RACOON_PID:-unknown}) still running after disconnect, as expected"
fi

RACOON_LOGGED_ERROR_AFTER_DISCONNECT=0
tail -n "+$((PRE_DISCONNECT_LOGLINE_COUNT + 1))" "$RACOON_LOG" 2>/dev/null | grep -E "ERROR:" > "$OUT/04c-post-disconnect-errors.log" 2>/dev/null
if [ -s "$OUT/04c-post-disconnect-errors.log" ]; then
	RACOON_LOGGED_ERROR_AFTER_DISCONNECT=1
	narrate "*** FAIL: racoon logged ERROR-level line(s) after vpn-disconnect -- see $OUT/04c-post-disconnect-errors.log ***"
fi

# ==========================================================================
# Step 5: THE FORK IN THE ROAD. Filtered setkey -DPN immediately after
# phase1-down.sh's own confirmed completion.
# ==========================================================================
narrate "=== Step 5: filtered SPD immediately after phase1-down.sh completion (the fork) ==="
filtered_spd > "$OUT/05-post-teardown-filtered-spd.log"

if spd_file_has_real_policy "$OUT/05-post-teardown-filtered-spd.log"; then
	BRANCH="A"
	narrate "*** BRANCH A signal: something remains in the SPD after phase1-down.sh completed ***"
	tee -a "$STEP_LOG" < "$OUT/05-post-teardown-filtered-spd.log"
else
	BRANCH="B"
	narrate "*** BRANCH B signal: filtered SPD is empty after phase1-down.sh completed ***"
fi

# ==========================================================================
# Step 5b: hook-state listing after phase1-down.sh completion -- verifies
# which generation phase1-down.sh's FIFO matching actually consumed.
#
# Added after finding, on a real, reused Arch host, that
# rhook_state_oldest_unconsumed() (racoon-hook-lib.sh ~299-324) picks the
# LOWEST live generation number for this peer -- not necessarily this
# run's own. rhook_state_reap() deliberately never touches live (never
# consumed) files, only aged .consumed ones, so an earlier session that
# was never cleanly torn down leaves a permanent live orphan behind; if
# one is already sitting there when this run's phase1-up creates its own
# (higher-numbered) generation, phase1-down.sh may consume the OLD orphan
# instead. This is invisible whenever every session's undo commands are
# byte-identical (same racoon.conf every time) -- which is exactly why
# step 5's empty-SPD result alone can't tell "own generation consumed"
# apart from "a different, coincidentally-identical generation consumed
# instead". This step makes that distinguishable directly.
# ==========================================================================
narrate "=== Step 5b: hook-state listing after teardown (FIFO generation verification) ==="
ls -la "$STATE_DIR"/hook-state.* > "$OUT/05-hook-state-listing.log" 2>&1
for f in "$STATE_DIR"/hook-state.*; do
	[ -f "$f" ] || continue
	{
		echo "=== $f ==="
		cat "$f"
		echo
	} >> "$OUT/05-hook-state-content.log"
done

NEWLY_CONSUMED="$(comm -13 \
	<(grep -oE "hook-state\.[^ ]*\.consumed" "$OUT/04-hook-state-listing.log" 2>/dev/null | sort -u) \
	<(grep -oE "hook-state\.[^ ]*\.consumed" "$OUT/05-hook-state-listing.log" 2>/dev/null | sort -u) 2>/dev/null)"

{
	echo "presumed own generation for $VPN_GATEWAY (highest live one seen right after this run's own phase1-up, step 4): ${PRESUMED_OWN_GEN:-<none found>}"
	echo
	echo "generation(s) that newly became .consumed between step 4 and step 5b (i.e. what phase1-down.sh actually replayed just now):"
	if [ -n "$NEWLY_CONSUMED" ]; then
		printf '%s\n' "$NEWLY_CONSUMED"
	else
		echo "(none detected -- either nothing changed, or hook-state.* filenames don't match the expected pattern; check 04/05-hook-state-listing.log by hand)"
	fi
} > "$OUT/05b-fifo-generation-check.log"

FIFO_MATCH="unknown"
if [ -n "$PRESUMED_OWN_GEN" ] && [ -n "$NEWLY_CONSUMED" ]; then
	if printf '%s\n' "$NEWLY_CONSUMED" | grep -q "\\.${PRESUMED_OWN_GEN}\\.consumed$"; then
		FIFO_MATCH="yes"
		narrate "FIFO generation check: phase1-down.sh consumed this run's OWN generation ($PRESUMED_OWN_GEN) -- see $OUT/05b-fifo-generation-check.log"
	else
		FIFO_MATCH="no"
		narrate "*** FIFO generation MISMATCH: phase1-down.sh consumed a DIFFERENT generation than this run's own ($PRESUMED_OWN_GEN) -- see $OUT/05b-fifo-generation-check.log. This run's own state file is now an orphan. If any earlier live generation for this peer used different routes/domains than this run, this would be a real correctness gap (wrong undo replayed), not just cosmetic -- worth checking $OUT/04-hook-state-content.log and $OUT/05-hook-state-content.log by hand for what each generation actually contains. ***"
	fi
else
	narrate "FIFO generation check inconclusive (see $OUT/05b-fifo-generation-check.log) -- cross-reference 04/05-hook-state-*.log by hand"
fi

# ==========================================================================
# Step 5c: issue #90 verdict -- did this run's real phase1-down.sh touch
# the synthetic orphan step 3b injected? 5b above already shows whether
# THIS run's own generation got consumed, but not by itself whether an
# unrelated orphan also got touched (5b only compares against
# PRESUMED_OWN_GEN, not every other live generation) -- the two together
# are what distinguish "consumed correctly" from "consumed correctly AND
# also stomped something else", which would be just as bad in
# production as consuming the wrong thing outright.
# ==========================================================================
narrate "=== Step 5c: issue #90 verdict (orphan-untouched check) ==="
ISSUE90_VERDICT="not applicable (step 3b's synthetic orphan injection did not run or failed -- see step 3b narration above)"
if [ -n "${ORPHAN_GEN:-}" ]; then
	if [ -f "$ORPHAN_MARKER" ]; then
		ISSUE90_VERDICT="FAIL: the synthetic orphan (generation $ORPHAN_GEN, fake IKE_COOKIE) WAS consumed by this run's real phase1-down.sh -- its undo command ran for real (see $ORPHAN_MARKER). This is the pre-fix oldest-first bug, reproduced live. Cross-check against step 4b's IKE_COOKIE result above before concluding anything else."
		narrate "*** ISSUE #90 LIVE VERDICT: FAIL -- see $ORPHAN_MARKER, the synthetic orphan's undo command ran for real ***"
	elif [ -f "${ORPHAN_STATE_FILE}.consumed" ]; then
		ISSUE90_VERDICT="FAIL: the synthetic orphan (generation $ORPHAN_GEN) was renamed to .consumed (see ${ORPHAN_STATE_FILE}.consumed) even though its marker command was not observed -- still means phase1-down.sh selected the wrong generation. Investigate before trusting anything else in this run."
		narrate "*** ISSUE #90 LIVE VERDICT: FAIL -- ${ORPHAN_STATE_FILE}.consumed exists, the orphan was selected ***"
	elif [ -f "$ORPHAN_STATE_FILE" ]; then
		ISSUE90_VERDICT="PASS: the synthetic orphan (generation $ORPHAN_GEN) is still live and untouched after this run's real teardown -- phase1-down.sh matched its own generation by IKE_COOKIE and left the unrelated orphan alone, exactly as issue #90's fix intends."
		narrate "ISSUE #90 LIVE VERDICT: PASS -- synthetic orphan (generation $ORPHAN_GEN) untouched, marker absent"
	else
		ISSUE90_VERDICT="INCONCLUSIVE: the synthetic orphan's state file ($ORPHAN_STATE_FILE) is gone entirely -- neither live nor .consumed. Unexpected; check $STATE_DIR by hand."
		narrate "WARNING: issue #90 verdict inconclusive -- $ORPHAN_STATE_FILE missing entirely, check $STATE_DIR by hand"
	fi

	# Cleanup, and a positive-path confirmation in the same move: consume
	# the synthetic orphan via a real phase1-down.sh invocation carrying
	# its own matching REMOTE_ADDR/IKE_COOKIE, rather than just deleting
	# the files. This exercises rhook_state_own_generation()'s positive
	# ("this IS mine") path live, complementing the negative path just
	# confirmed above, and leaves $STATE_DIR clean for the next run
	# instead of accumulating fake orphans forever. Safe regardless of
	# the verdict above: if the orphan was already consumed (the FAIL
	# case), this is a harmless no-op -- there is nothing left matching
	# $FAKE_COOKIE for it to find.
	P1D_SCRIPT="$PHASE1_DOWN_SCRIPT"
	if [ -z "$P1D_SCRIPT" ]; then
		P1D_SCRIPT="$(grep -oE '/[^ "]*phase1-down\.sh' "$RACOON_CONF" 2>/dev/null | head -1)"
	fi
	if [ -n "$P1D_SCRIPT" ] && [ -x "$P1D_SCRIPT" ] && [ -f "$ORPHAN_STATE_FILE" ]; then
		# RACOON_HOOK_STATE_DIR must match $STATE_DIR explicitly: racoon-hook-lib.sh
		# defaults RHOOK_STATE_DIR to /run/racoon regardless of what this
		# script's own STATE_DIR was overridden to, and a mismatch here would
		# make this cleanup invocation look at the wrong directory entirely.
		REMOTE_ADDR="$VPN_GATEWAY" IKE_COOKIE="$FAKE_COOKIE" RACOON_HOOK_STATE_DIR="$STATE_DIR" \
			"$P1D_SCRIPT" > "$OUT/05c-orphan-cleanup-phase1-down.log" 2>&1
		if [ -f "${ORPHAN_STATE_FILE}.consumed" ]; then
			narrate "synthetic orphan cleaned up: a direct phase1-down.sh run with its own matching IKE_COOKIE consumed it correctly (positive-path confirmation) -- see $OUT/05c-orphan-cleanup-phase1-down.log"
			rm -f "${ORPHAN_STATE_FILE}.consumed"
		else
			narrate "WARNING: the cleanup phase1-down.sh run did not consume the synthetic orphan as expected -- see $OUT/05c-orphan-cleanup-phase1-down.log, and remove ${ORPHAN_STATE_FILE}* by hand"
		fi
	elif [ -f "$ORPHAN_STATE_FILE" ]; then
		narrate "could not locate an executable phase1-down.sh for cleanup (set PHASE1_DOWN_SCRIPT explicitly) -- remove ${ORPHAN_STATE_FILE}* by hand"
	fi
	rm -f "$ORPHAN_MARKER"
fi

{
	echo "# Task F results -- $TS"
	echo
	echo "SCENARIO_LABEL=$SCENARIO_LABEL"
	echo "(verify against $OUT/00b-network-backend-snapshot.log -- that file is the ground truth, this label is just a human-typed tag)"
	echo
	echo "VPN_GATEWAY=$VPN_GATEWAY"
	echo "INTERNAL_DNS_SERVER=$INTERNAL_DNS_SERVER"
	echo "Original connected ISAKMP-SA: ${ORIGINAL_SPI:-<not captured, see 04-show-sa-connected.log>}"
	echo "phase1-up.sh completion confirmed via syslog: $([ "$PHASE1_UP_CONFIRMED" -eq 1 ] && echo yes || echo NO -- see warning above)"
	echo "phase1-down.sh completion confirmed via syslog: $([ "$PHASE1_DOWN_CONFIRMED" -eq 1 ] && echo yes || echo NO -- see warning above)"
	echo "racoon still running after disconnect: $([ "$RACOON_DIED_AFTER_DISCONNECT" -eq 0 ] && echo yes || echo "*** NO -- racoon died, see 00-narration.log's Step 4c and $RACOON_LOG ***")"
	echo "racoon logged an ERROR after disconnect: $([ "$RACOON_LOGGED_ERROR_AFTER_DISCONNECT" -eq 0 ] && echo no || echo "*** YES -- see $OUT/04c-post-disconnect-errors.log ***")"
	echo "FIFO generation check (did phase1-down.sh consume THIS run's own state, or an orphaned one?): $FIFO_MATCH -- see $OUT/05b-fifo-generation-check.log"
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

# This must come AFTER the block above: that block opens $SUMMARY with
# ">" (create/truncate), so anything appended before it would be wiped.
{
	echo
	echo "## Issue #90 live verification (phase1-down.sh generation matching)"
	echo
	echo "IKE_COOKIE cross-check (step 4b): $IKE_COOKIE_CHECK"
	echo
	echo "Orphan-untouched check (steps 3b/5c): $ISSUE90_VERDICT"
} >> "$SUMMARY"

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
	if [ "$RACOON_DIED_AFTER_DISCONNECT" -eq 1 ]; then
		echo "INCONCLUSIVE, NOT a Branch B confirmation: racoon itself was already dead"
		echo "before this ping (see Step 4c above) -- no ACQUIRE firing here proves"
		echo "nothing when there is no running daemon left to fire one. Fix racoon's"
		echo "own crash first (see $OUT/04c-post-disconnect-errors.log and $RACOON_LOG),"
		echo "then re-run this step's provocation against a daemon confirmed alive."
	elif [ "$BRANCH" = "B" ] && [ "$ACQUIRE_FIRED" -eq 0 ]; then
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
	if spd_file_has_real_policy "$OUT/05-post-teardown-filtered-spd.log"; then
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
# Cleanup: stop the background log capture, and terminate the racoon
# instance this script started. Earlier runs left it running "for
# convenience"; in practice that just meant the next run's own
# pre-existing-racoon guard (step 2) hard-stopped, forcing a manual kill
# before every subsequent scenario run. Terminate by default; set
# KEEP_RACOON_RUNNING=1 to opt back into the old behaviour for manual
# follow-up on this specific run.
# ==========================================================================
[ -n "${JOURNAL_PID:-}" ] && kill "$JOURNAL_PID" 2>/dev/null

if [ "${KEEP_RACOON_RUNNING:-0}" = "1" ]; then
	narrate "KEEP_RACOON_RUNNING=1 -- leaving racoon (pid ${RACOON_PID:-unknown}) running; stop it yourself before the next scenario run (pre-existing-racoon guard in step 2 will otherwise hard-stop)"
elif [ -n "${RACOON_PID:-}" ] && kill -0 "$RACOON_PID" 2>/dev/null; then
	kill "$RACOON_PID" 2>/dev/null
	j=0
	while [ "$j" -lt 5 ] && kill -0 "$RACOON_PID" 2>/dev/null; do
		sleep 1
		j=$((j + 1))
	done
	if kill -0 "$RACOON_PID" 2>/dev/null; then
		narrate "WARNING: racoon (pid $RACOON_PID) did not exit within 5s of SIGTERM -- still running, check/kill it manually before the next scenario run"
	else
		narrate "racoon (pid $RACOON_PID) terminated"
	fi
else
	if [ "$RACOON_DIED_AFTER_DISCONNECT" -eq 1 ]; then
		narrate "racoon (pid ${RACOON_PID:-unknown}) already gone by cleanup time -- nothing to terminate (already flagged as a FAILURE at Step 4c above, not a coincidence)"
	else
		narrate "racoon (pid ${RACOON_PID:-unknown}) already gone by cleanup time -- nothing to terminate (unexpected: Step 4c found it still alive right after disconnect, so it died somewhere between there and here -- check $RACOON_LOG for what happened in between)"
	fi
fi

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
