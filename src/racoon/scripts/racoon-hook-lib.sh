# SPDX-License-Identifier: BSD-3-Clause
# Copyright (C) 2024-2026 Thomas Reim and the racoon-ipsec-tools contributors
# Part of rdratlos/racoon-ipsec-tools — https://github.com/rdratlos/racoon-ipsec-tools
#
# racoon-hook-lib.sh - shared library for phase1-up.sh / phase1-down.sh
#
# Sourced by both hooks (and by racoon-dns-detect). Holds all detection,
# input validation, capability probing, logging and state I/O so that
# neither hook re-derives a decision the other already made. Nothing in
# this file executes on its own; it only defines functions and default
# variables, so `. racoon-hook-lib.sh` is always safe.
#
# POSIX sh only (dash / bash / NetBSD /bin/sh). `local` is used throughout
# for function-scoped variables; it is not POSIX but is supported by every
# shell in the target set (documented once, here, rather than at each use).
# No arrays, no `[[`, no `${var,,}`, no process substitution.
#
# shellcheck disable=SC3043
# ^ one file-wide justification for every `local` declaration below (the
# paragraph above), rather than repeating the same disable comment at
# each of the ~45 uses.
#
# Architecture: survey -> plan -> apply (see the top-level hooks for the
# phase breakdown). This file provides the plan/apply/state machinery and
# the primitives every phase needs; the step *types* a plan can contain are
# registered by rhook_register_steptypes(), called once by whichever hook
# needs them, right after sourcing this file.

# --------------------------------------------------------------------------
# Injectable external command paths.  Every external binary this library
# (or a hook) invokes goes through one of these, defaulting to the bare
# command name (resolved via PATH).  Tests point these at stub scripts that
# echo canned output and record their argv, so the whole plan/apply/undo
# machinery is exercisable without root, without a VPN and without a
# network -- that is the point of keeping every external call indirected.
# --------------------------------------------------------------------------
: "${RACOON_HOOK_IP:=ip}"
: "${RACOON_HOOK_NMCLI:=nmcli}"
: "${RACOON_HOOK_RESOLVECTL:=resolvectl}"
: "${RACOON_HOOK_SYSTEMD_RESOLVE:=systemd-resolve}"
: "${RACOON_HOOK_BUSCTL:=busctl}"
: "${RACOON_HOOK_SYSTEMCTL:=systemctl}"
: "${RACOON_HOOK_RESOLVCONF:=resolvconf}"
: "${RACOON_HOOK_LOGGER:=logger}"
: "${RACOON_HOOK_PKILL:=pkill}"
: "${RACOON_HOOK_UNBOUND_CONTROL:=unbound-control}"
: "${RACOON_HOOK_NETWORKMANAGER:=NetworkManager}"
: "${RACOON_HOOK_DATE:=date}"
: "${RACOON_HOOK_SS:=ss}"
: "${RACOON_HOOK_NETSTAT:=netstat}"
: "${RACOON_HOOK_SOCKSTAT:=sockstat}"
: "${RACOON_HOOK_SETKEY:=setkey}"

# --------------------------------------------------------------------------
# Configuration (etc/racoon/hooks.conf.sample documents each key).  Loaded
# by rhook_load_config(), which must run after rhook_log() is defined (it
# logs a warning for unknown keys) but before anything reads these values.
# --------------------------------------------------------------------------
RHOOK_CONF="${RACOON_HOOK_CONF:-/etc/racoon/hooks.conf}"
RHOOK_BACKEND="auto"
RHOOK_ON_DNS_FAILURE="warn"
RHOOK_DEBUG_LEVEL=0
RHOOK_DUMMY_IFACE="racoon0"
RHOOK_STATE_DIR="${RACOON_HOOK_STATE_DIR:-/run/racoon}"
RHOOK_ALLOW_RESOLV_CONF_OVERWRITE="no"

rhook_load_config() {
	[ -r "$RHOOK_CONF" ] || return 0
	local rhook_line rhook_k rhook_v
	while IFS= read -r rhook_line || [ -n "$rhook_line" ]; do
		rhook_line=$(printf '%s' "$rhook_line" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')
		case "$rhook_line" in
			''|'#'*) continue ;;
		esac
		rhook_k="${rhook_line%%=*}"
		rhook_v="${rhook_line#*=}"
		rhook_k=$(printf '%s' "$rhook_k" | sed -e 's/[[:space:]]*$//')
		rhook_v=$(printf '%s' "$rhook_v" | sed -e 's/^[[:space:]]*//')
		case "$rhook_k" in
			backend) RHOOK_BACKEND="$rhook_v" ;;
			on_dns_failure) RHOOK_ON_DNS_FAILURE="$rhook_v" ;;
			debug_level) RHOOK_DEBUG_LEVEL="$rhook_v" ;;
			dummy_iface) RHOOK_DUMMY_IFACE="$rhook_v" ;;
			allow_resolv_conf_overwrite) RHOOK_ALLOW_RESOLV_CONF_OVERWRITE="$rhook_v" ;;
			'') ;;
			*) rhook_log warn "hooks.conf: unknown key '$rhook_k', ignoring" ;;
		esac
	done < "$RHOOK_CONF"
	case "$RHOOK_ALLOW_RESOLV_CONF_OVERWRITE" in
		yes|no) ;;
		*)
			rhook_log warn "hooks.conf: allow_resolv_conf_overwrite='$RHOOK_ALLOW_RESOLV_CONF_OVERWRITE' invalid, using 'no'"
			RHOOK_ALLOW_RESOLV_CONF_OVERWRITE="no"
			;;
	esac
	case "$RHOOK_ON_DNS_FAILURE" in
		# Brief 3 §H: "abort" never meant "reject the tunnel" -- racoon
		# does not consult a hook's exit status when deciding whether to
		# keep an SA (verified: no caller of script_hook() anywhere in
		# src/racoon inspects privsep_script_exec()'s return value for
		# that purpose). "abort" only ever made the failure visible via
		# this script's own exit code. Kept as a deprecated alias for
		# "report" (identical behavior, honest name) rather than breaking
		# an existing hooks.conf outright.
		abort)
			rhook_log warn "hooks.conf: on_dns_failure=abort is a deprecated alias for 'report' -- racoon does not reject a tunnel based on the script's exit status, so 'abort' never aborted anything but this script's own exit code; use 'report' (same behavior) or 'rollback' (also undo this run's own changes before exiting) instead"
			RHOOK_ON_DNS_FAILURE="report"
			;;
		warn|report|rollback) ;;
		*)
			rhook_log warn "hooks.conf: on_dns_failure='$RHOOK_ON_DNS_FAILURE' invalid, using 'warn'"
			RHOOK_ON_DNS_FAILURE="warn"
			;;
	esac
}

# --------------------------------------------------------------------------
# Logging (§5.1, §5.2).
#
# Verbosity is controlled by RACOON_HOOK_DEBUG (env, wins) or debug_level
# (hooks.conf), 0-3:
#   0 quiet   - syslog only: errors, warnings, the final one-line summary
#   1 normal  - + stderr, one line per step outcome
#   2 verbose - + full command line and exit code per step, to a trace file
#   3 trace   - + captured stdout/stderr per step, survey record, and the
#               evidence behind each detection branch
#
# Categories map to a minimum level at which they appear on stderr; error/
# warn/summary always go to syslog regardless of level (§5.2: "syslog via
# logger always").  racoon captures hook stdout/stderr itself, so stderr
# output here is for a human running the hook by hand or via
# `racoon-dns-detect`, not a substitute for syslog.
# --------------------------------------------------------------------------
RHOOK_TRACE_FILE="$RHOOK_STATE_DIR/hook.trace"
RHOOK_TRACE_MAX_BYTES=1048576

rhook_effective_debug_level() {
	if [ -n "${RACOON_HOOK_DEBUG:-}" ]; then
		printf '%s' "$RACOON_HOOK_DEBUG"
	else
		printf '%s' "${RHOOK_DEBUG_LEVEL:-0}"
	fi
}

rhook_trace_init() {
	# Truncated at the start of phase1-up only, so a phase1-down run can
	# still see what the preceding phase1-up did (§5.2).
	[ "${RHOOK_HOOK_NAME:-}" = "phase1-up" ] || return 0
	mkdir -p "$RHOOK_STATE_DIR" 2>/dev/null || return 0
	: > "$RHOOK_TRACE_FILE" 2>/dev/null || return 0
	chmod 0640 "$RHOOK_TRACE_FILE" 2>/dev/null || true
}

rhook_trace_write() {
	local rhook_ts rhook_sz
	[ -w "$RHOOK_STATE_DIR" ] || return 0
	rhook_ts=$("$RACOON_HOOK_DATE" -Is 2>/dev/null || "$RACOON_HOOK_DATE")
	printf '%s %s\n' "$rhook_ts" "$1" >> "$RHOOK_TRACE_FILE" 2>/dev/null || return 0
	rhook_sz=$(wc -c < "$RHOOK_TRACE_FILE" 2>/dev/null || printf '0')
	if [ "$rhook_sz" -gt "$RHOOK_TRACE_MAX_BYTES" ] 2>/dev/null; then
		tail -c "$RHOOK_TRACE_MAX_BYTES" "$RHOOK_TRACE_FILE" > "$RHOOK_TRACE_FILE.tmp" 2>/dev/null \
			&& mv "$RHOOK_TRACE_FILE.tmp" "$RHOOK_TRACE_FILE" 2>/dev/null
	fi
}

# rhook_log <category> <message...>
# category: error | warn | step | verbose | trace | summary
rhook_log() {
	local rhook_cat rhook_msg rhook_min rhook_level
	rhook_cat="$1"; shift
	rhook_msg="$*"
	rhook_level=$(rhook_effective_debug_level)

	case "$rhook_cat" in
		error|warn|summary)
			"$RACOON_HOOK_LOGGER" -t "racoon-${RHOOK_HOOK_NAME:-script}" -- "[$rhook_cat] $rhook_msg" 2>/dev/null || true
			rhook_min=0
			;;
		step)    rhook_min=1 ;;
		verbose) rhook_min=2 ;;
		trace)   rhook_min=3 ;;
		*)       rhook_min=1 ;;
	esac

	if [ "$rhook_level" -ge "$rhook_min" ] 2>/dev/null; then
		echo "[$rhook_cat] $rhook_msg" >&2
	fi
	if [ "$rhook_level" -ge 2 ] 2>/dev/null; then
		rhook_trace_write "[$rhook_cat] $rhook_msg"
	fi
}

# --------------------------------------------------------------------------
# State directory (R8: /run/racoon, never /etc).  Created once, early,
# before anything can try to write into it -- the old scripts only created
# it on the NM success path, so the failure branches that ran first wrote
# their marker into a directory that didn't exist yet and silently lost it.
# --------------------------------------------------------------------------
rhook_ensure_state_dir() {
	# Reviewed (PR #91 comment #8): a failed mkdir here used to be
	# swallowed outright -- every subsequent state/trace write would then
	# fail the same silent way, with nothing anywhere explaining why.
	mkdir -p "$RHOOK_STATE_DIR" 2>/dev/null || rhook_log warn "cannot create state directory $RHOOK_STATE_DIR -- state/trace files will not be written"
}

# --------------------------------------------------------------------------
# Connection identity.  REMOTE_ADDR alone identifies the peer for the
# state directory layout (one generation sequence per address), sanitized
# to a token safe for use in a filename.
#
# REMOTE_PORT is deliberately NOT part of this (brief 3 §D, superseding
# brief 2 §C's "REMOTE_ADDR + single-file fallback" recommendation): it
# floats 500->4500 on a NAT-T rebind and changes across a reconnect, and
# a live field test showed phase1-down for an old SA and phase1-up for
# its replacement running within one second of each other for the same
# peer address -- a single-file-per-identity scheme (with or without the
# port) can match a teardown to the wrong generation and dismantle a
# tunnel that just came up. See rhook_state_file()/rhook_state_reset()
# below for the generation scheme that replaces it, and
# rhook_state_own_generation() for *which* generation a given
# phase1-down.sh run actually owns.
# --------------------------------------------------------------------------
rhook_conn_addr() {
	printf '%s' "${REMOTE_ADDR:-unknown}" | tr -c 'A-Za-z0-9._-' '_'
}

# racoon's own per-negotiation session token (issue #90): script_hook()
# (src/racoon/isakmp.c) exports IKE_COOKIE as the ISAKMP cookie pair
# (i_ck:r_ck), unique per Phase 1 negotiation and stable from
# SCRIPT_PHASE1_UP through SCRIPT_PHASE1_DOWN for the same connection
# attempt -- unlike REMOTE_ADDR/REMOTE_PORT, this lets phase1-down.sh
# identify its *own* generation instead of guessing from file order. See
# rhook_state_own_generation() below. Sanitized the same way
# rhook_conn_addr() sanitizes REMOTE_ADDR; empty if IKE_COOKIE is unset
# (e.g. a SCRIPT_PHASE1_DEAD invocation -- this project's own configs
# never wire phase1_dead to phase1-down.sh in the first place).
#
# PR #91 review row 23 (comment 5061097437): raised a concern that a
# NAT-T port float could cause IKE_COOKIE reuse across sessions. Not
# possible: the cookie pair is set once, from the negotiation's first
# packet, when the Phase 1 handle is created (isakmp.c, `iph1 =
# newph1()` followed by `memcpy(&iph1->index.i_ck, &isakmp->i_ck,
# ...)`) and is never touched again for that handle's lifetime -- RFC
# 2408 defines the cookie pair as identifying the SA for its whole
# duration. A NAT-T port
# float is tracked entirely separately, as a bit in `iph1->natt_flags`
# (`NAT_PORTS_CHANGED`, set right next to the cookie copy above but never
# written into `iph1->index`) -- it changes which UDP port the exchange
# rides on, not the SA's identity. What the general "crashed phase1-up
# leaves a live orphan" observation in that same row does describe is
# real and already handled; see the "crash" scenario in
# test-phase1-roundtrip.sh.
rhook_conn_cookie() {
	printf '%s' "${IKE_COOKIE:-}" | tr -c 'A-Za-z0-9:_-' '_'
}

rhook_state_file_prefix() {
	printf '%s/hook-state.%s' "$RHOOK_STATE_DIR" "$(rhook_conn_addr)"
}

# Highest existing generation number for this peer address, counting
# both live and .consumed files (a consumed file's number is never
# reused -- reusing a number would defeat the FIFO ordering the moment a
# consumed file is later reaped), or 0 if none exist yet.
rhook_state_max_generation() {
	local rhook_prefix rhook_f rhook_gen rhook_max
	rhook_prefix=$(rhook_state_file_prefix)
	rhook_max=0
	for rhook_f in "$rhook_prefix".*; do
		[ -e "$rhook_f" ] || continue
		rhook_gen="${rhook_f#"$rhook_prefix".}"
		rhook_gen="${rhook_gen%.consumed}"
		case "$rhook_gen" in
			''|*[!0-9]*) continue ;;
		esac
		if [ "$rhook_gen" -gt "$rhook_max" ] 2>/dev/null; then
			rhook_max="$rhook_gen"
		fi
	done
	printf '%s' "$rhook_max"
}

# RHOOK_STATE_GENERATION is allocated once per process by rhook_state_reset()
# (called once, early, by phase1-up.sh) and cached here -- rhook_state_file()
# must return the *same* path on every call within one run; re-deriving a
# fresh generation number on every call would defeat the whole point of
# numbering them; phase1-down.sh never calls rhook_state_reset() at all,
# since it consumes an existing generation rather than writing a new one
# (see rhook_state_oldest_unconsumed() below).
RHOOK_STATE_GENERATION=""
rhook_state_file() {
	printf '%s.%s' "$(rhook_state_file_prefix)" "$RHOOK_STATE_GENERATION"
}

# True if at least one live (not yet consumed) generation exists for this
# peer address -- i.e. there is something for phase1-down.sh to undo.
rhook_state_exists() {
	[ -n "$(rhook_state_oldest_unconsumed)" ]
}

# Allocates a new generation for this peer address and creates its
# (empty) state file, guarded by a short-lived mkdir lock so two
# phase1-up runs racing for the same peer address cannot both compute
# the same "next" generation number and silently clobber one another's
# state (mkdir is atomic on every POSIX filesystem, unlike a plain
# read-modify-write on a counter file). Capped retry: a held lock from a
# process that died mid-allocation must not wedge every future
# connection attempt to this peer forever -- past the cap, proceeds
# anyway (best-effort, consistent with this codebase's "a hook problem
# must never block a real VPN connection" rule) and logs why.
rhook_state_reset() {
	local rhook_lock rhook_tries
	rhook_ensure_state_dir
	rhook_lock="$(rhook_state_file_prefix).lock"
	rhook_tries=0
	while ! mkdir "$rhook_lock" 2>/dev/null; do
		rhook_tries=$((rhook_tries + 1))
		if [ "$rhook_tries" -ge 20 ]; then
			rhook_log warn "generation lock for $(rhook_conn_addr) still held after ${rhook_tries}s -- proceeding without it (a concurrent phase1-up for this exact peer address may race)"
			break
		fi
		sleep 1
	done
	RHOOK_STATE_GENERATION=$(( $(rhook_state_max_generation) + 1 ))
	: > "$(rhook_state_file)"
	# issue #90: record this generation's own IKE_COOKIE (racoon's
	# per-negotiation session token) in a sidecar file next to the state
	# file itself, so rhook_state_own_generation() can find it by exact
	# match later. Kept as a separate file rather than a header line
	# inside the state file: rhook_undo_replay() rewrites the state file
	# from scratch on a partial-failure retry (only the still-failing
	# entries survive), which would silently drop a header line on the
	# first retry.
	rhook_conn_cookie > "$(rhook_state_file).cookie" 2>/dev/null
	rmdir "$rhook_lock" 2>/dev/null
}

# The oldest (lowest generation number) live state file for this peer
# address, or empty if none. This -- not mtime, not the order `ls`
# happens to return -- gives a deterministic, race-free existence check
# (rhook_state_exists()): generation numbers are allocated under the same
# lock rhook_state_reset() uses, so their ordering is exact and
# unambiguous regardless of clock resolution or how close together two
# phase1-up runs happen. NOT used by phase1-down.sh to pick which
# generation to undo any more -- oldest-first can pick an orphaned
# generation from an earlier, never-cleanly-torn-down session for the same
# peer instead of the current teardown's own one (issue #90); see
# rhook_state_own_generation() below for that.
rhook_state_oldest_unconsumed() {
	local rhook_prefix rhook_f rhook_gen rhook_oldest rhook_oldest_path
	rhook_prefix=$(rhook_state_file_prefix)
	rhook_oldest=""
	rhook_oldest_path=""
	for rhook_f in "$rhook_prefix".*; do
		[ -f "$rhook_f" ] || continue
		case "$rhook_f" in *.consumed|*.lock|*.cookie) continue ;; esac
		rhook_gen="${rhook_f#"$rhook_prefix".}"
		case "$rhook_gen" in
			''|*[!0-9]*) continue ;;
		esac
		if [ -z "$rhook_oldest" ] || [ "$rhook_gen" -lt "$rhook_oldest" ] 2>/dev/null; then
			rhook_oldest="$rhook_gen"
			rhook_oldest_path="$rhook_f"
		fi
	done
	printf '%s' "$rhook_oldest_path"
}

# The live state file for this peer address whose recorded IKE_COOKIE
# sidecar (written by rhook_state_reset() above) matches this process's
# own $IKE_COOKIE, or empty if none does -- including the case where
# $IKE_COOKIE itself is empty (nothing to match, so nothing is returned;
# never falls back to guessing). This is phase1-down.sh's own generation
# selector (issue #90): an exact match on racoon's own per-negotiation
# session token, not a FIFO order that can only ever be a heuristic. A
# peer address can legitimately have other live generations on disk at
# the same time (an overlapping reconnect, or an orphan left behind by an
# earlier session that was never cleanly torn down) -- this function
# never returns any of those, only this exact connection attempt's own.
rhook_state_own_generation() {
	local rhook_prefix rhook_f rhook_want rhook_have
	rhook_want=$(rhook_conn_cookie)
	[ -n "$rhook_want" ] || return 0
	rhook_prefix=$(rhook_state_file_prefix)
	for rhook_f in "$rhook_prefix".*; do
		[ -f "$rhook_f" ] || continue
		case "$rhook_f" in *.consumed|*.lock|*.cookie) continue ;; esac
		rhook_have=$(cat "${rhook_f}.cookie" 2>/dev/null)
		if [ -n "$rhook_have" ] && [ "$rhook_have" = "$rhook_want" ]; then
			printf '%s' "$rhook_f"
			return 0
		fi
	done
	return 0
}

# Marks a generation's state file consumed (successfully torn down)
# rather than deleting it immediately, so the fact a teardown happened
# is briefly visible on disk; rhook_state_reap() (called at every
# phase1-up) is what actually deletes .consumed files, by count and age.
# The IKE_COOKIE sidecar is deleted outright here, not renamed alongside
# it -- rhook_state_own_generation() only ever looks at live generations,
# so a consumed generation's sidecar serves no further purpose.
rhook_state_mark_consumed() {
	local rhook_path
	rhook_path="$1"
	[ -f "$rhook_path" ] || return 0
	rm -f "${rhook_path}.cookie" 2>/dev/null
	mv -f "$rhook_path" "$rhook_path.consumed" 2>/dev/null
}

RHOOK_REAP_MAX_COUNT=5
RHOOK_REAP_MAX_AGE_SECONDS=86400

# Deletes .consumed generation files for this peer address beyond the
# newest RHOOK_REAP_MAX_COUNT, and any older than RHOOK_REAP_MAX_AGE_SECONDS
# regardless of count. Deliberately never touches *live* (unconsumed)
# files -- those represent real, possibly-outstanding undo state, and
# §3.4's "state file is the sole teardown guard" principle means only a
# successful phase1-down replay (rhook_state_mark_consumed) or an admin
# removes one, never an automatic age/count sweep. Called once, early,
# by phase1-up.sh -- "reap ... at every phase1-up" per the brief.
rhook_state_reap() {
	local rhook_prefix rhook_f rhook_now rhook_mtime rhook_age
	local rhook_gens rhook_gen rhook_count
	rhook_prefix=$(rhook_state_file_prefix)
	rhook_now=$("$RACOON_HOOK_DATE" +%s 2>/dev/null)
	[ -n "$rhook_now" ] || return 0

	for rhook_f in "$rhook_prefix".*.consumed; do
		[ -f "$rhook_f" ] || continue
		rhook_mtime=$(rhook_survey_mtime "$rhook_f")
		[ -n "$rhook_mtime" ] || continue
		rhook_age=$((rhook_now - rhook_mtime))
		if [ "$rhook_age" -gt "$RHOOK_REAP_MAX_AGE_SECONDS" ] 2>/dev/null; then
			rm -f "$rhook_f" 2>/dev/null
		fi
	done

	rhook_gens=""
	for rhook_f in "$rhook_prefix".*.consumed; do
		[ -f "$rhook_f" ] || continue
		rhook_gen="${rhook_f#"$rhook_prefix".}"
		rhook_gen="${rhook_gen%.consumed}"
		case "$rhook_gen" in ''|*[!0-9]*) continue ;; esac
		rhook_gens="${rhook_gens:+$rhook_gens }$rhook_gen"
	done
	rhook_count=0
	for rhook_gen in $rhook_gens; do rhook_count=$((rhook_count + 1)); done
	if [ "$rhook_count" -gt "$RHOOK_REAP_MAX_COUNT" ]; then
		# shellcheck disable=SC2086 # word-splitting the generation list on purpose
		printf '%s\n' $rhook_gens | sort -rn | awk -v keep="$RHOOK_REAP_MAX_COUNT" 'NR > keep' \
			| while IFS= read -r rhook_old_gen; do
				[ -n "$rhook_old_gen" ] || continue
				rm -f "${rhook_prefix}.${rhook_old_gen}.consumed" 2>/dev/null
			done
	fi
}

rhook_plan_file() {
	printf '%s/plan.%s.%s' "$RHOOK_STATE_DIR" "$(rhook_conn_addr)" "$$"
}

# --------------------------------------------------------------------------
# Plan storage.  A plan is a TAB-separated file, one line per step:
#   id  type  criticality  description  command  undo_command
#
# `command`/`undo_command` are plain, space-joined argv strings, later run
# via `eval`.  This is only safe because every token that can appear in
# them has already passed the whitelist validation in §4 before the plan
# is built -- IPv4 octets, CIDR characters, or domain-label characters --
# none of which include shell metacharacters or whitespace.  Validation
# happens strictly before plan-building; nothing peer-supplied ever reaches
# rhook_plan_add() unvalidated.  If that invariant is ever violated, this
# becomes a command-injection primitive, so do not relax it without
# re-auditing every caller.
# --------------------------------------------------------------------------
rhook_plan_reset() {
	rhook_ensure_state_dir
	: > "$(rhook_plan_file)"
}

# rhook_plan_add <id> <type> <criticality: required|optional> <description> <command> <undo_command>
rhook_plan_add() {
	printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" "$5" "$6" >> "$(rhook_plan_file)"
}

# --------------------------------------------------------------------------
# Step outcomes and the state file.
#
# The state file is what phase1-down replays; it must reflect what was
# *actually done*, appended as each step succeeds, so an interrupted
# apply is still fully revertible (§3.3, §3.4).  Format: one
# tab-separated line per completed-or-skipped step:
#   id  type  outcome  undo_command
# outcome in {ok, skipped, failed, not-attempted}; only "ok" steps carry a
# meaningful undo_command (others are recorded for the report, not replay).
# --------------------------------------------------------------------------
RHOOK_REPORT_FILE=""

rhook_report_init() {
	rhook_ensure_state_dir
	RHOOK_REPORT_FILE="$RHOOK_STATE_DIR/report.$(rhook_conn_addr).$$"
	: > "$RHOOK_REPORT_FILE" 2>/dev/null
}

rhook_state_append() {
	# $1 id  $2 type  $3 outcome  $4 undo_command
	printf '%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" >> "$(rhook_state_file)"
}

# Removes a single entry from the state file by exact id match (awk, not
# grep -v, so a step id that happens to be a substring of another id's
# text can never cause an over-broad removal). Used by the brief-3 §B.1
# in-transaction DNS rollback: once a step's change has been undone
# immediately (within the same apply run, not at teardown time), its
# "ok" state entry must go with it -- otherwise phase1-down.sh's later
# undo replay would run that step's undo command a second time, against
# a resource the rollback already removed.
rhook_state_remove_entry() {
	local rhook_id rhook_state rhook_tmp
	rhook_id="$1"
	rhook_state="$(rhook_state_file)"
	[ -f "$rhook_state" ] || return 0
	rhook_tmp="${rhook_state}.tmp.$$"
	awk -F'\t' -v id="$rhook_id" '$1 != id' "$rhook_state" > "$rhook_tmp" 2>/dev/null && mv "$rhook_tmp" "$rhook_state"
}

# Accumulates report lines only; rhook_emit_report() is the single place
# that decides where the assembled report goes (stderr/trace/syslog),
# based on debug level -- avoids double-emitting each line here as well as
# in the final report.
rhook_report_line() {
	[ -n "$RHOOK_REPORT_FILE" ] && printf '%s\n' "$1" >> "$RHOOK_REPORT_FILE" 2>/dev/null
}

# --------------------------------------------------------------------------
# run_step(): the single place in the codebase where an external command
# that changes system state is executed (§3.3).  Reads one plan line,
# checks its precondition (if the step type registered one), evaluates the
# command, records the outcome, and appends the undo command to the state
# file the moment the step succeeds.
#
# Returns 0 if the hook should continue, 1 if a required step failed and
# the caller must stop (apply the failure policy). Also sets
# RHOOK_LAST_STEP_OUTCOME to "ok"|"skipped"|"failed" -- the same value
# just passed to rhook_state_append() -- so rhook_apply_plan() can tell
# an actually-applied step from a merely-non-blocking one (skipped, or a
# failed optional step) without re-reading the state file it just wrote.
# --------------------------------------------------------------------------
RHOOK_LAST_STEP_OUTCOME=""
rhook_run_step() {
	local rhook_line rhook_id rhook_type rhook_crit rhook_desc rhook_cmd rhook_undo
	local rhook_precond_fn rhook_precond_reason rhook_postcond_fn rhook_postcond_reason rhook_out rhook_rc
	rhook_line="$1"
	rhook_id=$(printf '%s' "$rhook_line" | cut -f1)
	rhook_type=$(printf '%s' "$rhook_line" | cut -f2)
	rhook_crit=$(printf '%s' "$rhook_line" | cut -f3)
	rhook_desc=$(printf '%s' "$rhook_line" | cut -f4)
	rhook_cmd=$(printf '%s' "$rhook_line" | cut -f5)
	rhook_undo=$(printf '%s' "$rhook_line" | cut -f6)

	rhook_precond_fn="rhook_precond_${rhook_type}"
	if command -v "$rhook_precond_fn" >/dev/null 2>&1; then
		rhook_precond_reason=$("$rhook_precond_fn" "$rhook_id" 2>&1)
		if [ -n "$rhook_precond_reason" ]; then
			rhook_report_line "[ SKIPPED   ] $rhook_desc"
			rhook_report_line "              reason: $rhook_precond_reason"
			rhook_state_append "$rhook_id" "$rhook_type" "skipped" ""
			RHOOK_LAST_STEP_OUTCOME="skipped"
			return 0
		fi
	fi

	rhook_log verbose "apply $rhook_id: $rhook_cmd"
	rhook_out=$(eval "$rhook_cmd" 2>&1)
	rhook_rc=$?

	if [ "$rhook_rc" -eq 0 ]; then
		# §7.4: a step that reports success but produced no observable
		# change (wrote to a file nothing reads, or a link-scoped setting
		# a networkd-managed interface silently refused) is a failure,
		# not a success. Postcondition functions are pure re-checks, run
		# only after a successful apply; a non-empty reason downgrades
		# this step to failed exactly like a nonzero exit would have.
		rhook_postcond_fn="rhook_postcond_${rhook_type}"
		if command -v "$rhook_postcond_fn" >/dev/null 2>&1; then
			rhook_postcond_reason=$("$rhook_postcond_fn" "$rhook_id" 2>&1)
			if [ -n "$rhook_postcond_reason" ]; then
				rhook_report_line "[ FAILED    ] $rhook_desc (reported success, but had no effect)"
				rhook_report_line "              reason: $rhook_postcond_reason"
				rhook_log trace "  command: $rhook_cmd"
				rhook_log trace "  output: $rhook_out"
				rhook_state_append "$rhook_id" "$rhook_type" "failed" ""
				RHOOK_LAST_STEP_OUTCOME="failed"
				[ "$rhook_crit" = "required" ] && return 1
				return 0
			fi
		fi
		rhook_report_line "[ ok        ] $rhook_desc"
		rhook_log trace "  command: $rhook_cmd"
		rhook_log trace "  output: $rhook_out"
		rhook_state_append "$rhook_id" "$rhook_type" "ok" "$rhook_undo"
		RHOOK_LAST_STEP_OUTCOME="ok"
		return 0
	fi

	rhook_report_line "[ FAILED    ] $rhook_desc (exit $rhook_rc)"
	rhook_log trace "  command: $rhook_cmd"
	rhook_log trace "  output: $rhook_out"
	rhook_state_append "$rhook_id" "$rhook_type" "failed" ""
	RHOOK_LAST_STEP_OUTCOME="failed"

	[ "$rhook_crit" = "required" ] && return 1
	return 0
}

# True for every step type that changes a link's DNS configuration
# (either backend). Used only to decide the brief-3 §B.1 in-transaction
# rollback scope below -- dummy interface/address/route steps are
# deliberately excluded: those represent network-layer connectivity that
# stays valid regardless of whether DNS configuration succeeds, and
# rolling them back too would tear down more than the failure actually
# calls for.
rhook_is_dns_group() {
	case "$1" in
		set_dns|set_domains|default_route|resolved_no_scope|nm_dummy_profile|resolvconf_record|dnsmasq_conf|fallback_backup|fallback_resolv)
			return 0
			;;
		*)
			return 1
			;;
	esac
}

# rhook_apply_plan: run every line of the current plan in order through
# run_step().  Stops at the first failed *required* step, marking every
# remaining step "not-attempted" in both the report and the state file.
#
# §B.1 (brief 3, F4): a partially-applied DNS configuration is worse than
# none -- a server registered on a link with no routing-domain/default-
# route scoping yet applied became the traffic source for the observed
# reconnect loop. Every DNS-group step that actually applied ("ok", not
# "skipped") during this run is remembered as it happens; if a later
# required DNS-group step then fails, everything remembered so far is
# undone immediately, in reverse order, before the usual not-attempted
# bookkeeping runs -- the link ends the run either fully configured or
# untouched, never half-configured. Steps outside the DNS group are
# never part of this rollback (see rhook_is_dns_group() above).
rhook_apply_plan() {
	local rhook_stopped rhook_line rhook_id rhook_type rhook_desc rhook_undo
	local rhook_dns_applied rhook_rb_line rhook_rb_id rhook_rb_undo rhook_rb_out rhook_rb_rc
	rhook_stopped=0
	rhook_dns_applied=""
	while IFS= read -r rhook_line || [ -n "$rhook_line" ]; do
		[ -z "$rhook_line" ] && continue
		if [ "$rhook_stopped" -eq 1 ]; then
			rhook_id=$(printf '%s' "$rhook_line" | cut -f1)
			rhook_type=$(printf '%s' "$rhook_line" | cut -f2)
			rhook_desc=$(printf '%s' "$rhook_line" | cut -f4)
			rhook_report_line "[ not-run   ] $rhook_desc"
			rhook_state_append "$rhook_id" "$rhook_type" "not-attempted" ""
			continue
		fi

		rhook_id=$(printf '%s' "$rhook_line" | cut -f1)
		rhook_type=$(printf '%s' "$rhook_line" | cut -f2)
		if rhook_run_step "$rhook_line"; then
			if [ "$RHOOK_LAST_STEP_OUTCOME" = "ok" ] && rhook_is_dns_group "$rhook_type"; then
				rhook_undo=$(printf '%s' "$rhook_line" | cut -f6)
				if [ -n "$rhook_undo" ]; then
					# Prepend (not append): entries accumulate in apply
					# order, so reading top-to-bottom during rollback
					# below is already the correct reverse-of-apply order.
					rhook_dns_applied="$rhook_id	$rhook_undo
$rhook_dns_applied"
				fi
			fi
		else
			if rhook_is_dns_group "$rhook_type" && [ -n "$rhook_dns_applied" ]; then
				rhook_log warn "a required DNS step failed -- rolling back the DNS changes already applied to this link rather than leaving it half-configured"
				printf '%s\n' "$rhook_dns_applied" | while IFS= read -r rhook_rb_line; do
					[ -n "$rhook_rb_line" ] || continue
					rhook_rb_id=$(printf '%s' "$rhook_rb_line" | cut -f1)
					rhook_rb_undo=$(printf '%s' "$rhook_rb_line" | cut -f2)
					rhook_log verbose "rollback undo $rhook_rb_id: $rhook_rb_undo"
					rhook_rb_out=$(eval "$rhook_rb_undo" 2>&1)
					rhook_rb_rc=$?
					if [ "$rhook_rb_rc" -eq 0 ]; then
						rhook_report_line "[ ok        ] rollback undo $rhook_rb_id"
					else
						rhook_report_line "[ FAILED    ] rollback undo $rhook_rb_id (exit $rhook_rb_rc)"
					fi
					rhook_log trace "  command: $rhook_rb_undo"
					rhook_log trace "  output: $rhook_rb_out"
					rhook_state_remove_entry "$rhook_rb_id"
				done
				rhook_dns_applied=""
			fi
			rhook_stopped=1
		fi
	done < "$(rhook_plan_file)"
	return "$rhook_stopped"
}

# --------------------------------------------------------------------------
# rhook_undo_replay(): phase1-down's entire teardown logic (§3.4). The
# state file -- not Mode Config, not a re-run of the survey, not a
# re-derived plan -- is the *sole* source of what to undo: only lines
# recorded with outcome "ok" carry a meaningful undo_command (skipped/
# failed/not-attempted steps never changed anything, so there is nothing
# to reverse), and they are replayed in the opposite of apply order.
#
# Apply order writes dummy interface/address/routes first and DNS steps
# last (§3.2), so the state file's on-disk order is chronological apply
# order; reversing it for undo satisfies R4 (DNS torn down first, dummy
# interface/address removed last) for free, as a consequence of the file
# order rather than a separate rule to keep in sync.
#
# Best-effort: one failed undo does not stop the rest from being
# attempted, so a single stuck resource never blocks releasing everything
# else. Only entries whose undo failed are written back to the state
# file afterwards (in their original apply-chronological relative order,
# so a later retry's own reversal still undoes them in the right
# sequence) -- successfully undone entries are dropped. The state file is
# marked consumed (never deleted outright here -- rhook_state_reap()
# does that later, by count/age) only once nothing is left to undo
# (§3.4: "the state file is deleted only after a successful teardown";
# brief 3 §D changes *when* that deletion actually happens, not this
# function's own success condition for triggering it).
#
# rhook_undo_replay <state-file-path>: operates on exactly the file the
# caller names -- brief 3's FIFO generation scheme means "which state
# file" is now phase1-down.sh's own decision
# (rhook_state_oldest_unconsumed()), not something this function
# re-derives from the environment the way it used to.
#
# Returns 0 if every undo succeeded (or there was nothing to undo), 1 if
# at least one failed.
# --------------------------------------------------------------------------
rhook_undo_replay() {
	local rhook_state rhook_reversed_tmp rhook_line rhook_id rhook_type
	local rhook_outcome rhook_undo rhook_out rhook_rc rhook_had_failure
	local rhook_kept_lines

	rhook_state="$1"
	if [ -z "$rhook_state" ] || [ ! -s "$rhook_state" ]; then
		return 0
	fi
	# Reviewed (PR #91 comment #4): an existing, non-empty state file that
	# isn't readable (permissions, filesystem issue) must not fall through
	# to the same "nothing to undo" path as a genuinely empty/absent one --
	# that would silently report success while never having replayed a
	# single undo command, leaving real routes/SPD/DNS entries stuck with
	# no record of the failure anywhere. Warn and report failure instead,
	# same as any other undo step that didn't run.
	if [ ! -r "$rhook_state" ]; then
		rhook_log warn "state file exists but is not readable, cannot replay its undo commands: $rhook_state"
		return 1
	fi

	rhook_had_failure=0
	rhook_kept_lines=""

	# Portable line-reversal (classic sed idiom): `tac` is not POSIX and
	# is not guaranteed present on NetBSD, one of this codebase's target
	# shells' platforms.
	rhook_reversed_tmp="${rhook_state}.reversed.$$"
	sed '1!G;h;$!d' "$rhook_state" > "$rhook_reversed_tmp" 2>/dev/null

	while IFS= read -r rhook_line || [ -n "$rhook_line" ]; do
		[ -n "$rhook_line" ] || continue
		rhook_id=$(printf '%s' "$rhook_line" | cut -f1)
		rhook_type=$(printf '%s' "$rhook_line" | cut -f2)
		rhook_outcome=$(printf '%s' "$rhook_line" | cut -f3)
		rhook_undo=$(printf '%s' "$rhook_line" | cut -f4)

		[ "$rhook_outcome" = "ok" ] || continue
		[ -n "$rhook_undo" ] || continue

		rhook_log verbose "undo $rhook_id: $rhook_undo"
		rhook_out=$(eval "$rhook_undo" 2>&1)
		rhook_rc=$?
		if [ "$rhook_rc" -eq 0 ]; then
			rhook_report_line "[ ok        ] undo $rhook_id ($rhook_type)"
			rhook_log trace "  command: $rhook_undo"
			rhook_log trace "  output: $rhook_out"
		else
			rhook_report_line "[ FAILED    ] undo $rhook_id ($rhook_type) (exit $rhook_rc)"
			rhook_log trace "  command: $rhook_undo"
			rhook_log trace "  output: $rhook_out"
			rhook_had_failure=1
			if [ -z "$rhook_kept_lines" ]; then
				rhook_kept_lines="$rhook_line"
			else
				rhook_kept_lines="$rhook_line
$rhook_kept_lines"
			fi
		fi
	done < "$rhook_reversed_tmp"
	rm -f "$rhook_reversed_tmp" 2>/dev/null

	if [ "$rhook_had_failure" -eq 1 ]; then
		printf '%s\n' "$rhook_kept_lines" > "$rhook_state"
		rhook_log warn "some teardown steps failed to undo; state file retained for a future retry: $rhook_state"
	else
		rhook_state_mark_consumed "$rhook_state"
	fi
	[ "$rhook_had_failure" -eq 0 ]
}

# --------------------------------------------------------------------------
# Final report (§5.3) and the EXIT trap that guarantees it is emitted even
# on an abnormal exit -- replacing `set -e`, which is removed entirely
# (§3.3): every failure here is explicit, per step, and recorded, rather
# than an invisible early exit.
# --------------------------------------------------------------------------
rhook_emit_report() {
	local rhook_ok rhook_failed rhook_skipped rhook_notrun rhook_result
	local rhook_ts rhook_summary rhook_level
	[ -f "$RHOOK_REPORT_FILE" ] || return 0

	# `grep -c` always prints a count, including "0", even when it finds
	# no match -- its exit status just signals match/no-match, not
	# success/failure. A trailing `|| printf 0` therefore does not fall
	# back on the zero-match case, it *appends* a second "0" to grep's
	# own "0" output (both writes land in the same command substitution
	# regardless of grep's exit status), producing "0<newline>0" and
	# breaking every `-gt 0` integer test below on dash. `${var:-0}`
	# after a plain capture handles the one case that legitimately needs
	# a fallback -- grep itself missing or the report file vanishing.
	rhook_ok=$(grep -c '^\[ ok' "$RHOOK_REPORT_FILE" 2>/dev/null)
	rhook_ok="${rhook_ok:-0}"
	rhook_failed=$(grep -c '^\[ FAILED' "$RHOOK_REPORT_FILE" 2>/dev/null)
	rhook_failed="${rhook_failed:-0}"
	rhook_skipped=$(grep -c '^\[ SKIPPED' "$RHOOK_REPORT_FILE" 2>/dev/null)
	rhook_skipped="${rhook_skipped:-0}"
	rhook_notrun=$(grep -c '^\[ not-run' "$RHOOK_REPORT_FILE" 2>/dev/null)
	rhook_notrun="${rhook_notrun:-0}"

	if [ "$rhook_failed" -gt 0 ] || [ "$rhook_notrun" -gt 0 ] || [ "$rhook_skipped" -gt 0 ]; then
		rhook_result="PARTIAL"
	else
		rhook_result="OK"
	fi

	rhook_ts=$("$RACOON_HOOK_DATE" -Is 2>/dev/null || "$RACOON_HOOK_DATE")
	rhook_summary="result: $rhook_result ($rhook_ok ok, $rhook_skipped skipped, $rhook_failed failed, $rhook_notrun not attempted) -- policy '$RHOOK_ON_DNS_FAILURE'"
	rhook_level=$(rhook_effective_debug_level)

	# The assembled, multi-line report (§5.3) is the single most important
	# output of the whole design, but syslog only ever gets the one-line
	# summary (§5.1 level 0: "syslog only, errors and the one-line
	# summary") -- individual step lines were already sent to syslog as
	# warnings/errors, if any, when they happened.
	if [ "$rhook_level" -ge 1 ] 2>/dev/null; then
		{
			printf 'racoon %s report -- %s\n' "${RHOOK_HOOK_NAME:-script}" "$rhook_ts"
			[ -n "${RHOOK_REPORT_HEADER:-}" ] && printf '%s\n' "$RHOOK_REPORT_HEADER"
			cat "$RHOOK_REPORT_FILE"
			printf '\n  %s\n' "$rhook_summary"
		} >&2
	fi
	if [ "$rhook_level" -ge 2 ] 2>/dev/null; then
		rhook_trace_write "racoon ${RHOOK_HOOK_NAME:-script} report -- $rhook_ts"
		[ -n "${RHOOK_REPORT_HEADER:-}" ] && rhook_trace_write "$RHOOK_REPORT_HEADER"
		while IFS= read -r rhook_rline; do
			rhook_trace_write "$rhook_rline"
		done < "$RHOOK_REPORT_FILE"
		rhook_trace_write "$rhook_summary"
	fi

	"$RACOON_HOOK_LOGGER" -t "racoon-${RHOOK_HOOK_NAME:-script}" -- "$rhook_summary" 2>/dev/null || true

	rm -f "$RHOOK_REPORT_FILE" 2>/dev/null
	[ "$rhook_result" = "OK" ]
}

RHOOK_EXIT_HANDLED=0
rhook_exit_trap() {
	[ "$RHOOK_EXIT_HANDLED" -eq 1 ] && return
	RHOOK_EXIT_HANDLED=1
	rhook_emit_report
}

# --------------------------------------------------------------------------
# Input validation (§4, R3).
#
# Everything racoon exports from Mode Config -- INTERNAL_ADDR4,
# INTERNAL_DNS4, INTERNAL_DNS4_LIST, SPLIT_INCLUDE, SPLIT_INCLUDE_CIDR,
# INTERNAL_SPLITDNS_DOMAINS, DEFAULT_DOMAIN, LOCAL_ADDR, REMOTE_ADDR and
# the port variables -- arrives from the peer over the network and is
# consumed by a root process.  Every one of these is whitelist-validated
# here before use.  The rule throughout: reject the whole value on the
# first bad element, never trim/rewrite/"fix" one -- a partially-sanitized
# value that still gets used is exactly how injection survives review.
#
# On success each `rhook_validate_*_list` function prints the *original*
# input verbatim (nothing is rewritten) and returns 0.  On failure it
# prints nothing, sets RHOOK_VALIDATION_REASON, and returns 1.  Single-
# value validators (rhook_valid_ipv4 et al.) are pure predicates: no
# output, exit status only.
# --------------------------------------------------------------------------
RHOOK_MAX_DNS_SERVERS=8
RHOOK_MAX_DOMAINS=32
RHOOK_MAX_ROUTES=32
RHOOK_VALIDATION_REASON=""

# rhook_valid_ipv4 <token> -- dotted-quad, each octet 0-255, no leading
# zeros (which some parsers read as octal), exactly 4 fields.
rhook_valid_ipv4() {
	local rhook_tok rhook_o rhook_oldifs
	rhook_tok="$1"
	[ -n "$rhook_tok" ] || return 1
	case "$rhook_tok" in
		*[!0-9.]*) return 1 ;;
		.*|*.|*..*) return 1 ;;
	esac
	rhook_oldifs="$IFS"
	IFS=.
	# shellcheck disable=SC2086 # word-splitting on IFS=. is the point
	set -- $rhook_tok
	IFS="$rhook_oldifs"
	[ "$#" -eq 4 ] || return 1
	for rhook_o in "$@"; do
		case "$rhook_o" in
			0|[1-9]|[1-9][0-9]|[1-9][0-9][0-9]) ;;
			*) return 1 ;;
		esac
		[ "$rhook_o" -le 255 ] || return 1
	done
	return 0
}

# rhook_valid_cidr4 <token> -- IPv4 address with an optional /0..32.
# Rejects any character outside [0-9./] outright: this alone defeats the
# `default via 10.6.6.6` argument-injection vector (and any other
# letters/spaces/semicolons/newlines) before the address is even parsed.
rhook_valid_cidr4() {
	local rhook_tok rhook_addr rhook_len
	rhook_tok="$1"
	case "$rhook_tok" in
		*[!0-9./]*) return 1 ;;
	esac
	case "$rhook_tok" in
		*/*)
			rhook_addr="${rhook_tok%%/*}"
			rhook_len="${rhook_tok#*/}"
			case "$rhook_len" in */*) return 1 ;; esac
			case "$rhook_len" in
				0|[1-9]|[12][0-9]|3[0-2]) ;;
				*) return 1 ;;
			esac
			;;
		*)
			rhook_addr="$rhook_tok"
			;;
	esac
	rhook_valid_ipv4 "$rhook_addr"
}

# rhook_valid_port <token> -- 1-65535, digits only.
rhook_valid_port() {
	local rhook_tok
	rhook_tok="$1"
	case "$rhook_tok" in
		''|*[!0-9]*) return 1 ;;
	esac
	[ "$rhook_tok" -ge 1 ] 2>/dev/null && [ "$rhook_tok" -le 65535 ] 2>/dev/null
}

# rhook_valid_domain <token> -- [A-Za-z0-9.-] only, each label 1-63 bytes,
# total <= 253 bytes, no empty label, no label starting or ending with a
# hyphen (the brief requires no *leading* hyphen; trailing is rejected too
# as a superset per RFC 1035 label syntax -- noted as a self-resolved
# design choice, not a contradiction of the brief).
rhook_valid_domain() {
	local rhook_tok rhook_label rhook_oldifs
	rhook_tok="$1"
	[ -n "$rhook_tok" ] || return 1
	[ "${#rhook_tok}" -le 253 ] || return 1
	case "$rhook_tok" in
		*[!A-Za-z0-9.-]*) return 1 ;;
		.*|*.|*..*) return 1 ;;
	esac
	rhook_oldifs="$IFS"
	IFS=.
	# shellcheck disable=SC2086 # word-splitting on IFS=. is the point
	set -- $rhook_tok
	IFS="$rhook_oldifs"
	for rhook_label in "$@"; do
		[ -n "$rhook_label" ] || return 1
		[ "${#rhook_label}" -le 63 ] || return 1
		case "$rhook_label" in
			-*|*-) return 1 ;;
		esac
	done
	return 0
}

# rhook_validate_dns_list <space-separated tokens>
# Rejects 0.0.0.0/8, loopback (127.0.0.0/8), link-local (169.254.0.0/16),
# multicast (224.0.0.0/4) and reserved/broadcast (240.0.0.0/4, i.e. Class E
# plus 255.255.255.255) in addition to plain address-format validation
# (§4: "Reject 0.0.0.0, loopback, and multicast for DNS servers"; the
# link-local and reserved/Class E ranges were added later -- PR #91 review
# row 29a, comment 5061097437 -- these are bogon/reserved ranges that are
# never a valid DNS server address regardless of deployment, unlike the
# RFC1918 private ranges deliberately left alone below).
#
# RFC1918 private ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) are
# deliberately NOT rejected, and must never be: every one of this
# project's own live-tested internal DNS servers uses one (10.66.0.6
# throughout the issue #90 Task F evidence, the whole nepomuc.de test
# topology) -- rejecting RFC1918 by default would reject the project's
# own primary confirmed-working scenario. This is not a policy nuance
# left for later, it is a permanent constraint on this function.
rhook_validate_dns_list() {
	local rhook_list rhook_tok rhook_count
	rhook_list="$1"
	rhook_count=0
	RHOOK_VALIDATION_REASON=""
	for rhook_tok in $rhook_list; do
		rhook_count=$((rhook_count + 1))
		if [ "$rhook_count" -gt "$RHOOK_MAX_DNS_SERVERS" ]; then
			RHOOK_VALIDATION_REASON="more than $RHOOK_MAX_DNS_SERVERS DNS servers offered"
			return 1
		fi
		if ! rhook_valid_ipv4 "$rhook_tok"; then
			RHOOK_VALIDATION_REASON="DNS server '$rhook_tok' is not a valid IPv4 address"
			return 1
		fi
		case "$rhook_tok" in
			0.*)
				RHOOK_VALIDATION_REASON="DNS server '$rhook_tok' is in the reserved 0.0.0.0/8 range"
				return 1
				;;
			127.*)
				RHOOK_VALIDATION_REASON="DNS server '$rhook_tok' is a loopback address"
				return 1
				;;
			169.254.*)
				RHOOK_VALIDATION_REASON="DNS server '$rhook_tok' is a link-local address"
				return 1
				;;
			22[4-9].*|23[0-9].*)
				RHOOK_VALIDATION_REASON="DNS server '$rhook_tok' is a multicast address"
				return 1
				;;
			24[0-9].*|25[0-5].*)
				RHOOK_VALIDATION_REASON="DNS server '$rhook_tok' is in the reserved 240.0.0.0/4 range or is the broadcast address"
				return 1
				;;
		esac
	done
	printf '%s' "$rhook_list"
	return 0
}

# rhook_domain_has_punycode_label <domain> -- true if any dot-separated
# label starts with the "xn--" ACE prefix (RFC 3492/5890), case-
# insensitively (DNS labels are case-insensitive, and so is ACE-prefix
# comparison per RFC 3490). A pure predicate like rhook_valid_domain()
# above: no I/O, no log line of its own -- rhook_validate_domain_list()
# below decides what to do with the answer.
rhook_domain_has_punycode_label() {
	local rhook_dhp_tok rhook_dhp_label rhook_dhp_oldifs
	rhook_dhp_tok="$1"
	rhook_dhp_oldifs="$IFS"
	IFS=.
	# shellcheck disable=SC2086 # word-splitting on IFS=. is the point
	set -- $rhook_dhp_tok
	IFS="$rhook_dhp_oldifs"
	for rhook_dhp_label in "$@"; do
		case "$rhook_dhp_label" in
			[Xx][Nn]--*) return 0 ;;
		esac
	done
	return 1
}

# rhook_validate_domain_list <space-or-comma-separated tokens>
# Callers normalize comma/space mixed lists to spaces before calling this
# (racoon exports search domains comma-separated); kept as a single space-
# separated contract here to match rhook_validate_dns_list/cidr_list.
rhook_validate_domain_list() {
	local rhook_list rhook_tok rhook_count
	rhook_list="$1"
	rhook_count=0
	RHOOK_VALIDATION_REASON=""
	for rhook_tok in $rhook_list; do
		rhook_count=$((rhook_count + 1))
		if [ "$rhook_count" -gt "$RHOOK_MAX_DOMAINS" ]; then
			RHOOK_VALIDATION_REASON="more than $RHOOK_MAX_DOMAINS domains offered"
			return 1
		fi
		if ! rhook_valid_domain "$rhook_tok"; then
			RHOOK_VALIDATION_REASON="domain '$rhook_tok' failed validation"
			return 1
		fi
		# PR #91 review row 29c (comment 5061097437): a raw Unicode
		# homoglyph domain is already rejected as a side effect of the
		# [A-Za-z0-9.-] character-class check in rhook_valid_domain()
		# above -- it wouldn't match that class at all. Punycode-encoded
		# domains (xn--...) ARE plain ASCII and pass that check; the
		# residual gap is visibility, not validation: an operator has no
		# way to notice an unexpected ACE-encoded (possible lookalike)
		# domain from the report alone. Warns, never blocks -- comparing
		# against a confusables table to detect an actual homoglyph is a
		# much larger undertaking than this project's threat model here
		# (a malicious or compromised gateway sending Mode Config
		# attributes, not a sophisticated phishing scenario) warrants; a
		# warning that surfaces the raw Punycode form to a human is
		# sufficient for that threat model.
		if rhook_domain_has_punycode_label "$rhook_tok"; then
			rhook_log warn "split-DNS domain '$rhook_tok' is Punycode-encoded (ACE prefix xn--) -- passed validation, but worth reviewing: this could be a lookalike domain"
		fi
	done
	printf '%s' "$rhook_list"
	return 0
}

# rhook_validate_cidr_list <space-separated tokens>
rhook_validate_cidr_list() {
	local rhook_list rhook_tok rhook_count
	rhook_list="$1"
	rhook_count=0
	RHOOK_VALIDATION_REASON=""
	for rhook_tok in $rhook_list; do
		rhook_count=$((rhook_count + 1))
		if [ "$rhook_count" -gt "$RHOOK_MAX_ROUTES" ]; then
			RHOOK_VALIDATION_REASON="more than $RHOOK_MAX_ROUTES routes offered"
			return 1
		fi
		if ! rhook_valid_cidr4 "$rhook_tok"; then
			# shellcheck disable=SC2034
			# RHOOK_VALIDATION_REASON is a deliberate out-of-band return
			# channel: this function's caller reads it after a nonzero
			# return, in the caller's own scope, not this one -- see the
			# §4 comment block above rhook_valid_ipv4() for the full
			# convention.
			RHOOK_VALIDATION_REASON="route '$rhook_tok' is not a valid IPv4 CIDR"
			return 1
		fi
	done
	printf '%s' "$rhook_list"
	return 0
}

# --------------------------------------------------------------------------
# resolv.conf landscape survey (§7).
#
# Every location below has been observed, in the course of developing this
# hook set, to matter for who actually answers a DNS lookup:
#   /etc/resolv.conf                        - what glibc's classic resolver reads
#   /run/systemd/resolve/stub-resolv.conf   - systemd-resolved's 127.0.0.53 stub
#   /run/systemd/resolve/resolv.conf        - systemd-resolved's non-stub copy
#   /run/NetworkManager/resolv.conf         - NM's own canonical generated file
#   /run/NetworkManager/no-stub-resolv.conf - NM's real-upstream-servers copy,
#                                              written whenever its primary
#                                              copy would otherwise list a
#                                              local caching stub (dnsmasq
#                                              127.0.0.1 or resolved 127.0.0.53)
#   /run/resolvconf/resolv.conf             - openresolv/Debian resolvconf output
#   /etc/resolvconf/run/resolv.conf         - older Debian resolvconf layout
#
# A single symlink check is not enough: NetworkManager's own "symlink" mode
# writes /etc/resolv.conf as a *plain file* whenever it started out as one
# (extremely common on a fresh install), which looks identical on disk to
# rc-manager=file. And on at least one Arch Linux box seen in the field,
# NetworkManager maintained resolv.conf content in three of these locations
# in parallel with no symlink anywhere tying them together -- every
# symlink-only heuristic returned nothing useful there, and naive fallback
# logic degraded to "whichever service happens to be running", the weakest
# signal available. This survey instead inspects every location and lets
# the derivation functions below reason about the whole picture.
# --------------------------------------------------------------------------

# RHOOK_FS_ROOT: prefixed onto every filesystem path the survey touches.
# Empty (the default) means the real root. Fixture tests set this to a
# throwaway directory tree standing in for /etc and /run, which is what
# makes the whole survey exercisable without root or a real system.
RHOOK_FS_ROOT="${RACOON_HOOK_FS_ROOT:-}"

rhook_fs_path() {
	printf '%s%s' "$RHOOK_FS_ROOT" "$1"
}

RHOOK_SURVEY_PATHS="/etc/resolv.conf /run/systemd/resolve/stub-resolv.conf /run/systemd/resolve/resolv.conf /run/NetworkManager/resolv.conf /run/NetworkManager/no-stub-resolv.conf /run/resolvconf/resolv.conf /etc/resolvconf/run/resolv.conf"

rhook_survey_mtime() {
	stat -c %Y "$1" 2>/dev/null || stat -f %m "$1" 2>/dev/null || printf ''
}

rhook_survey_sha256() {
	local rhook_p
	rhook_p="$1"
	[ -r "$rhook_p" ] || return 0
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum "$rhook_p" 2>/dev/null | cut -d' ' -f1
	elif command -v shasum >/dev/null 2>&1; then
		shasum -a 256 "$rhook_p" 2>/dev/null | cut -d' ' -f1
	elif command -v openssl >/dev/null 2>&1; then
		openssl dgst -sha256 "$rhook_p" 2>/dev/null | sed 's/^.*= //'
	fi
}

# Content-signature scan, extended from field-tested detection: each
# backend that writes resolv.conf stamps a recognizable header comment.
# This is a stronger signal than symlink presence for the rc-manager=file
# / "symlink mode on a pre-existing plain file" case, both of which look
# identical to a bare static file otherwise.
# UNVERIFIED: the exact header text of /run/NetworkManager/resolv.conf
# itself (as opposed to /etc/resolv.conf's copy of it) has not been
# confirmed against a live system; assumed identical since both are
# written by the same NM code path.
rhook_survey_generator() {
	local rhook_p
	rhook_p="$1"
	[ -r "$rhook_p" ] || return 0
	if grep -Eqi 'generated by network[[:space:]]*manager' "$rhook_p" 2>/dev/null; then
		printf 'networkmanager'
	elif grep -Eqi 'generated by resolvconf|dynamic resolv\.conf\(5\)' "$rhook_p" 2>/dev/null; then
		printf 'resolvconf'
	elif grep -Eqi 'managed by man:systemd-resolved' "$rhook_p" 2>/dev/null; then
		printf 'systemd-resolved'
	fi
}

rhook_survey_nameservers() {
	local rhook_p
	rhook_p="$1"
	[ -r "$rhook_p" ] || return 0
	awk '/^[[:space:]]*nameserver[[:space:]]+/ {print $2}' "$rhook_p" 2>/dev/null | tr '\n' ',' | sed 's/,$//'
}

rhook_survey_file() {
	printf '%s/survey.%s' "$RHOOK_STATE_DIR" "$$"
}

# rhook_survey_build: writes one TAB-separated row per path in
# RHOOK_SURVEY_PATHS to the survey file, prints its path on stdout.
#   path  kind(symlink|file|absent)  target  size  mtime  sha256  generator  nameservers(comma-joined)
rhook_survey_build() {
	local rhook_out rhook_logical rhook_p rhook_kind rhook_target rhook_size rhook_mtime rhook_hash rhook_gen rhook_ns
	rhook_ensure_state_dir
	rhook_out="$(rhook_survey_file)"
	: > "$rhook_out"
	for rhook_logical in $RHOOK_SURVEY_PATHS; do
		rhook_p="$(rhook_fs_path "$rhook_logical")"
		if [ -L "$rhook_p" ]; then
			rhook_kind="symlink"
			rhook_target=$(readlink "$rhook_p" 2>/dev/null)
		elif [ -e "$rhook_p" ]; then
			rhook_kind="file"
			rhook_target=""
		else
			printf '%s\tabsent\t\t\t\t\t\t\n' "$rhook_logical" >> "$rhook_out"
			continue
		fi
		rhook_size=$(wc -c < "$rhook_p" 2>/dev/null | tr -d '[:space:]')
		rhook_mtime=$(rhook_survey_mtime "$rhook_p")
		rhook_hash=$(rhook_survey_sha256 "$rhook_p")
		rhook_gen=$(rhook_survey_generator "$rhook_p")
		rhook_ns=$(rhook_survey_nameservers "$rhook_p")
		printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
			"$rhook_logical" "$rhook_kind" "$rhook_target" "$rhook_size" "$rhook_mtime" "$rhook_hash" "$rhook_gen" "$rhook_ns" >> "$rhook_out"
	done
	printf '%s' "$rhook_out"
}

RHOOK_NSSWITCH="/etc/nsswitch.conf"

# §7.1: nss-resolve overrides file inspection entirely -- if hosts: lists
# "resolve", glibc talks to systemd-resolved over its NSS module (which in
# turn talks to it over D-Bus/varlink), never touching resolv.conf's
# content at all for name lookups. This must be checked and surfaced
# *before* trusting any file-based conclusion, not as a tiebreaker after.
rhook_survey_nss_uses_resolve() {
	local rhook_p
	rhook_p="$(rhook_fs_path "$RHOOK_NSSWITCH")"
	[ -r "$rhook_p" ] || return 1
	grep -E '^[[:space:]]*hosts:' "$rhook_p" 2>/dev/null | grep -qw 'resolve'
}

# The file glibc's classic nss_dns module actually reads, following
# /etc/resolv.conf's symlink chain to its final target. Independent of
# rhook_survey_nss_uses_resolve(): callers must check that separately and
# treat a "yes" there as overriding this answer, not merged into it, per
# §7.1 ("this inverts the conclusion and must be surfaced prominently").
rhook_survey_glibc_reader() {
	local rhook_p
	rhook_p="$(rhook_fs_path /etc/resolv.conf)"
	readlink -f "$rhook_p" 2>/dev/null || printf '%s' "$rhook_p"
}

# §7.2: group present, readable files by nameserver-list content; more
# than one distinct non-empty set among them is a DIVERGENT landscape --
# different backends disagree about what to serve, and picking one
# silently would be a guess dressed up as a decision.
#
# Parses each row with `cut -f<N>`, not `read` with a tab IFS: tab, like
# space and newline, is always classified as "IFS white space" by POSIX
# *regardless* of what IFS is currently set to, so adjacent tab delimiters
# still collapse and an empty middle field (survey rows have several --
# "target" for a plain file, every field but path/kind for an absent
# path) silently disappears, shifting every field after it one to the
# left. `cut` is purely positional and has no such behavior; run_step()
# already relies on this same distinction for plan lines.
rhook_survey_divergent() {
	local rhook_survey rhook_line rhook_kind rhook_ns rhook_seen
	rhook_survey="$1"
	rhook_seen=""
	while IFS= read -r rhook_line || [ -n "$rhook_line" ]; do
		[ -z "$rhook_line" ] && continue
		rhook_kind=$(printf '%s' "$rhook_line" | cut -f2)
		[ "$rhook_kind" = "absent" ] && continue
		rhook_ns=$(printf '%s' "$rhook_line" | cut -f8)
		[ -z "$rhook_ns" ] && continue
		case " $rhook_seen " in
			*" $rhook_ns "*) ;;
			*) rhook_seen="$rhook_seen $rhook_ns" ;;
		esac
	done < "$rhook_survey"
	rhook_seen=$(printf '%s' "$rhook_seen" | sed -e 's/^ *//' -e 's/ *$//')
	# shellcheck disable=SC2086 # counting space-separated tokens on purpose
	set -- $rhook_seen
	[ "$#" -gt 1 ] && printf 'DIVERGENT'
	return 0
}

# §7.3: the Arch case. /etc/resolv.conf is an ordinary plain file (no
# symlink tying it to anything) while two or more of the *other*
# locations are backend-generated -- i.e. real, redundant copies exist
# with nothing to say which one is authoritative. /etc/resolv.conf itself
# is deliberately excluded from that count: it having a generator
# signature is the starting condition being tested (rhook_etc_kind), not
# evidence of redundancy on its own. Without this exclusion, an entirely
# ordinary NetworkManager dns=dnsmasq setup -- /etc/resolv.conf plus
# exactly one no-stub-resolv.conf, which by design differs from it and is
# supposed to -- was misclassified as PARALLEL_UNLINKED.
rhook_survey_parallel_unlinked() {
	local rhook_survey rhook_line rhook_path rhook_kind rhook_gen
	local rhook_etc_kind rhook_generated_count
	rhook_survey="$1"
	rhook_etc_kind=""
	rhook_generated_count=0
	while IFS= read -r rhook_line || [ -n "$rhook_line" ]; do
		[ -z "$rhook_line" ] && continue
		rhook_path=$(printf '%s' "$rhook_line" | cut -f1)
		rhook_kind=$(printf '%s' "$rhook_line" | cut -f2)
		if [ "$rhook_path" = "/etc/resolv.conf" ]; then
			rhook_etc_kind="$rhook_kind"
			continue
		fi
		rhook_gen=$(printf '%s' "$rhook_line" | cut -f7)
		if [ "$rhook_kind" != "absent" ] && [ -n "$rhook_gen" ]; then
			rhook_generated_count=$((rhook_generated_count + 1))
		fi
	done < "$rhook_survey"
	if [ "$rhook_etc_kind" = "file" ] && [ "$rhook_generated_count" -ge 2 ]; then
		printf 'PARALLEL_UNLINKED'
	fi
	return 0
}

# R1: never perform a persistent system reconfiguration -- this returns
# text for the report, and is never fed to a command.
rhook_survey_remediation_text() {
	local rhook_survey rhook_reader
	rhook_survey="$1"
	rhook_reader=$(rhook_survey_glibc_reader)
	printf 'resolv.conf is written in parallel by multiple backends with no symlink tying /etc/resolv.conf to any one of them; only %s is what name resolution actually reads right now. Recommendation (not applied automatically): either symlink /etc/resolv.conf to the backend that should be authoritative, or set that backend'\''s own file-ownership setting (e.g. NetworkManager rc-manager=symlink) so /etc/resolv.conf and the generated copy converge.' "$rhook_reader"
}

# §7.4: a DNS-setting step that reports success but produced no observable
# change (wrote to a file nothing reads, or a link-scoped resolved setting
# that a networkd-managed interface silently refused) is a failure, not a
# success -- this is the check that catches that at runtime instead of in
# a bug report. File-based half only; the resolved/D-Bus half is wired in
# where the capability matrix and step emitters exist (§6).
rhook_survey_dns_effective_file() {
	local rhook_expect rhook_target
	rhook_expect="$1"
	rhook_target=$(rhook_survey_glibc_reader)
	[ -r "$rhook_target" ] || return 1
	case ",$(rhook_survey_nameservers "$rhook_target")," in
		*",$rhook_expect,"*) return 0 ;;
	esac
	return 1
}

# --------------------------------------------------------------------------
# Port 53 ownership survey (brief 3 §C). A first-class input of *equal
# weight* to the file-based survey and the NM D-Bus probe above -- not an
# override of either. It is the only signal that detects a resolver
# invisible to both: a forwarder (e.g. dnsmasq) bound to 127.0.0.1 behind
# a static /etc/resolv.conf that never mentions it, which the file/D-Bus
# survey alone would misclassify as "static" every time.
#
# Tool priority: `ss -lntup 'sport = :53'` (confirmed live against a real
# listener during development: UDP sockets report state UNCONN, not
# LISTEN, and the Process column is `users:(("name",pid=N,fd=M))` --
# possibly several comma-separated entries if a socket is shared).
# `netstat -lnpu`/`netstat -lnpt` where ss is absent (also confirmed
# live: UDP rows have no State column at all, one field fewer than TCP
# rows, so PID/Program must be read from the *last* awk field, never a
# fixed position). On NetBSD, `sockstat -l`, format modelled on FreeBSD's
# sockstat (which NetBSD's descends from) since no NetBSD host was
# available to confirm directly -- # UNVERIFIED: exact NetBSD sockstat(1)
# column layout. `netstat -an` is the final fallback everywhere (no owner
# information at all, but still detects that *something* is listening,
# which matters more than who).
rhook_survey_port53_tool() {
	command -v "$RACOON_HOOK_SS" >/dev/null 2>&1 && { printf 'ss'; return 0; }
	command -v "$RACOON_HOOK_NETSTAT" >/dev/null 2>&1 && { printf 'netstat'; return 0; }
	command -v "$RACOON_HOOK_SOCKSTAT" >/dev/null 2>&1 && { printf 'sockstat'; return 0; }
	command -v "$RACOON_HOOK_NETSTAT" >/dev/null 2>&1 && { printf 'netstat-an'; return 0; }
	return 1
}

# Prints one TSV row per listening tcp/udp socket the chosen tool
# reports, filtered to port 53: proto \t local_addr:port \t pid \t tool.
# pid is empty when the tool ran without permission to see it (ss/netstat
# as a non-root user) or the fallback tool has no PID concept at all
# (netstat -an) -- callers must treat an empty pid as owner=unknown, not
# an error.
rhook_survey_port53_raw() {
	local rhook_tool
	rhook_tool=$(rhook_survey_port53_tool) || return 1
	case "$rhook_tool" in
		ss)
			"$RACOON_HOOK_SS" -lntup 'sport = :53' 2>/dev/null | awk -v tool=ss '
				NR == 1 { next }
				{
					pid = ""
					if (match($7, /pid=[0-9]+/)) pid = substr($7, RSTART + 4, RLENGTH - 4)
					printf "%s\t%s\t%s\t%s\n", $1, $5, pid, tool
				}'
			;;
		netstat)
			{ "$RACOON_HOOK_NETSTAT" -lnpu 2>/dev/null; "$RACOON_HOOK_NETSTAT" -lnpt 2>/dev/null; } | awk -v tool=netstat '
				$1 == "tcp" || $1 == "udp" {
					pid = ""
					n = split($NF, pp, "/")
					if (n == 2 && pp[1] ~ /^[0-9]+$/) pid = pp[1]
					printf "%s\t%s\t%s\t%s\n", $1, $4, pid, tool
				}'
			;;
		sockstat)
			# UNVERIFIED column layout, see the header comment above.
			"$RACOON_HOOK_SOCKSTAT" -l 2>/dev/null | awk -v tool=sockstat '
				NR == 1 { next }
				$5 ~ /^(tcp|tcp4|tcp6|udp|udp4|udp6)$/ {
					printf "%s\t%s\t%s\t%s\n", $5, $6, $3, tool
				}'
			;;
		netstat-an)
			"$RACOON_HOOK_NETSTAT" -an 2>/dev/null | awk -v tool=netstat-an '
				$1 ~ /^(tcp|udp)/ {
					printf "%s\t%s\t%s\t%s\n", $1, $4, "", tool
				}'
			;;
	esac
}

# rhook_survey_port53(): rhook_survey_port53_raw(), filtered to exactly
# port 53 and with local_addr:port split into separate fields via POSIX
# parameter expansion on the *last* colon -- colon-count-agnostic, so a
# bracketed IPv6 address (`[::]:53`) splits the same way a plain IPv4
# one does, without replicating that logic once per tool's awk block
# above. One line per listener: proto \t addr \t port \t pid \t tool.
rhook_survey_port53() {
	local rhook_line rhook_proto rhook_addrport rhook_pid rhook_tool rhook_port rhook_addr
	rhook_survey_port53_raw | while IFS= read -r rhook_line || [ -n "$rhook_line" ]; do
		[ -n "$rhook_line" ] || continue
		rhook_proto=$(printf '%s' "$rhook_line" | cut -f1)
		rhook_addrport=$(printf '%s' "$rhook_line" | cut -f2)
		rhook_pid=$(printf '%s' "$rhook_line" | cut -f3)
		rhook_tool=$(printf '%s' "$rhook_line" | cut -f4)
		rhook_port="${rhook_addrport##*:}"
		[ "$rhook_port" = "53" ] || continue
		rhook_addr="${rhook_addrport%:*}"
		printf '%s\t%s\t%s\t%s\t%s\n' "$rhook_proto" "$rhook_addr" "$rhook_port" "$rhook_pid" "$rhook_tool"
	done
}

# rhook_survey_port53_owner <pid>: resolves a pid to its real binary path
# via /proc/<pid>/exe, falling back to the first NUL-terminated token of
# /proc/<pid>/cmdline. Never trusts `comm`/the process-name string a
# tool's own -p/-p output already gave us: Linux truncates `comm` to 15
# characters, so "systemd-resolved" (16 chars) renders as
# "systemd-resolve" -- an exact collision with the *legacy systemd-resolve
# CLI tool's own real name*, confirmed on the field-test host (F7). Uses
# rhook_fs_path() so fixtures can fake /proc/<pid>/exe and /proc/<pid>/cmdline
# the same way they fake /etc/resolv.conf.
rhook_survey_port53_owner() {
	local rhook_pid rhook_exe rhook_cmdline_path
	rhook_pid="$1"
	if [ -z "$rhook_pid" ]; then
		printf 'unknown'
		return 0
	fi
	rhook_exe=$(readlink "$(rhook_fs_path "/proc/$rhook_pid/exe")" 2>/dev/null)
	if [ -n "$rhook_exe" ]; then
		printf '%s' "$rhook_exe"
		return 0
	fi
	rhook_cmdline_path="$(rhook_fs_path "/proc/$rhook_pid/cmdline")"
	if [ -r "$rhook_cmdline_path" ]; then
		rhook_exe=$(tr '\0' '\n' < "$rhook_cmdline_path" 2>/dev/null | head -n 1)
		if [ -n "$rhook_exe" ]; then
			printf '%s' "$rhook_exe"
			return 0
		fi
	fi
	printf 'unknown'
}

# rhook_survey_port53_classify_addr <local_addr>: classifies a single
# listener's bind address per the brief's taxonomy. Deliberately does
# not use the owner binary path here -- "which forwarder" is a separate
# question from "what does the bind address itself imply" (a 0.0.0.0
# bind may be serving a LAN, not necessarily this host's own resolver;
# see the header comment on rhook_survey_port53_summary() for how the
# two combine).
rhook_survey_port53_classify_addr() {
	case "$1" in
		127.0.0.53) printf 'stub' ;;
		127.*|::1|'[::1]') printf 'forwarder' ;;
		0.0.0.0|'*'|::|'[::]') printf 'server' ;;
		*) printf 'other' ;;
	esac
}

# One line per listener plus, when applicable, one BROKEN line: the
# structured form racoon-dns-detect renders. Every listener is reported
# (§C: "more than one listener -> report all of them; do not silently
# pick"), each with pid empty and owner=unknown when the pid could not
# be resolved at all (unprivileged run, or the fallback tool has no pid
# concept -- §C's "degradation without root" requirement). §C: "Record
# pid, resolved binary path, and the bound address/port for every
# listener" -- all four are in this row.
#   LISTENER \t proto \t addr \t port \t pid \t owner_binary \t classification \t tool
#   BROKEN \t <nameserver found in the effective resolv.conf>
rhook_survey_port53_summary() {
	local rhook_line rhook_proto rhook_addr rhook_port rhook_pid rhook_tool
	local rhook_owner rhook_class rhook_reader rhook_ns
	rhook_survey_port53 | while IFS= read -r rhook_line || [ -n "$rhook_line" ]; do
		[ -n "$rhook_line" ] || continue
		rhook_proto=$(printf '%s' "$rhook_line" | cut -f1)
		rhook_addr=$(printf '%s' "$rhook_line" | cut -f2)
		rhook_port=$(printf '%s' "$rhook_line" | cut -f3)
		rhook_pid=$(printf '%s' "$rhook_line" | cut -f4)
		rhook_tool=$(printf '%s' "$rhook_line" | cut -f5)
		rhook_owner=$(rhook_survey_port53_owner "$rhook_pid")
		rhook_class=$(rhook_survey_port53_classify_addr "$rhook_addr")
		printf 'LISTENER\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
			"$rhook_proto" "$rhook_addr" "$rhook_port" "$rhook_pid" "$rhook_owner" "$rhook_class" "$rhook_tool"
	done
	# The BROKEN check needs to know whether there were zero listeners,
	# but the `while` above ran in a pipeline subshell (rhook_survey_port53
	# is itself piped from rhook_survey_port53_raw), so nothing set inside
	# it is visible here -- re-run the (cheap) query directly instead of
	# trying to smuggle a flag out of a subshell.
	if [ -z "$(rhook_survey_port53)" ]; then
		rhook_reader=$(rhook_survey_glibc_reader)
		if [ -r "$rhook_reader" ]; then
			rhook_ns=$(rhook_survey_nameservers "$rhook_reader")
			case ",$rhook_ns," in
				*,127.*,*|*,::1,*)
					printf 'BROKEN\t%s\n' "$rhook_ns"
					;;
			esac
		fi
	fi
}

# --------------------------------------------------------------------------
# NetworkManager D-Bus probe (RcManager, Mode).
#
# NetworkManager ships a D-Bus activation file, so a bare
# `busctl get-property org.freedesktop.NetworkManager ...` call on a name
# nobody currently owns can make dbus-daemon *start* NetworkManager on
# demand -- confirmed in the field on an Ubuntu Bionic box with no
# NetworkManager installed at all: probing this property alone caused it
# to spawn, which then made every later "is NM active" check honestly (and
# wrongly, for that machine) report NetworkManager as the resolver in
# control, and routed DNS setup down the NM-specific path on a system that
# was never supposed to run it. That is exactly the "impacting the
# machine" failure a detection scheme exists to avoid, just via a D-Bus
# mechanism rather than a shell one. systemctl is-active is a pure state
# read with no such side effect, and must run first, always.
#
# File layout cannot be trusted as a substitute either: NM's own
# "rc-manager=symlink" mode writes /etc/resolv.conf as a *plain file*
# whenever it started out as one (the common case on a fresh install), so
# "is /etc/resolv.conf a symlink" cannot distinguish that from
# rc-manager=file. RcManager is the one answer that reflects what NM
# actually decided at runtime, including a compiled-in distro default that
# never appears as an explicit line in NetworkManager.conf.
#
# Per §7 this is kept as *one input* to the survey, never an early return
# that skips the file-based scan above -- both are always performed.
#
# Always exits 0: callers only look at (possibly empty) stdout, never at
# this function's own exit status. A nonzero return from an early guard
# here is exactly the kind of failure that would matter if this were
# called as `var=$(...)` under `set -e` -- and even without set -e (this
# rewrite drops it), callers should not have to special-case this
# function's exit status just to read its output.
rhook_nm_dbus_prop() {
	systemctl is-active --quiet "${RACOON_HOOK_NETWORKMANAGER:-NetworkManager}" 2>/dev/null || return 0
	command -v "$RACOON_HOOK_BUSCTL" >/dev/null 2>&1 || return 0
	"$RACOON_HOOK_BUSCTL" get-property org.freedesktop.NetworkManager \
	    /org/freedesktop/NetworkManager/DnsManager \
	    org.freedesktop.NetworkManager.DnsManager "$1" 2>/dev/null \
	    | sed -n 's/^s "\(.*\)"$/\1/p'
	return 0
}

# Brief 3 §K: is NetworkManager active on this system at all, regardless
# of which backend was classified as *the DNS handler*. NM auto-manages
# any interface it discovers unless specifically excluded (a udev
# NM_UNMANAGED rule, an unmanaged-devices= entry) -- a very common setup
# is NM managing the physical interfaces while systemd-resolved (reached
# directly, backend=resolved) handles DNS, in which case a dummy
# interface this hook creates with a plain `ip link add` still gets
# picked up by NM the moment it appears. Deleting that interface with a
# plain `ip link del` at teardown removes it out from under NM's own
# bookkeeping instead of going through NM's own device-removal path --
# see rhook_build_plan()'s RHOOK_DUMMY_OWNER for what this decides.
#
# A pure state read (`systemctl is-active`), never a D-Bus property probe
# -- rhook_nm_dbus_prop()'s own header comment documents why a bare
# `busctl get-property` call can bus-activate NetworkManager as a side
# effect on a system that does not otherwise run it; this function must
# never do that just to decide who owns an interface it is about to
# create.
rhook_survey_nm_active() {
	"$RACOON_HOOK_SYSTEMCTL" is-active --quiet "${RACOON_HOOK_NETWORKMANAGER:-NetworkManager}" 2>/dev/null
}

# --------------------------------------------------------------------------
# systemd-resolved: tool detection, version, and capability matrix (§6).
#
# Two tools do this job with *different command grammars*: resolvectl
# (verb-based: `resolvectl dns IF a.b.c.d`) and its predecessor
# systemd-resolve (flag-based: `systemd-resolve --interface=IF
# --set-dns=a.b.c.d`). Confirmed against systemd's own NEWS files:
# systemd-resolve gained --set-dns=/--set-domain=/--set-llmnr=/
# --set-mdns=/--set-dnssec=/--set-nta=/--revert in v236; it was renamed to
# resolvectl with a verb-based interface in v239, remaining available
# under the old name as a compatibility alias. Xubuntu Bionic 32-bit -- a
# supported target -- has *neither* resolvectl nor busctl, only
# systemd-resolve: a previous version of this detection assumed a
# resolvectl fallback binary name ("resctl") that does not exist anywhere,
# so the entire resolved path silently no-op'd there, and detection even
# *selected* that path based on probing the non-existent binary. Fixed
# here: probe resolvectl, then systemd-resolve, never resctl.
#
# Capabilities are feature-probed, not version-sniffed (§6 point 7): dns/
# domain/revert/flush-caches are confirmed present in both tools per the
# NEWS entries above. The exact version resolvectl's "default-route"
# subcommand first shipped in could not be confirmed -- checked systemd's
# own NEWS file across the full v234-v260 range (the entire file
# available at the time of this check, not a handful of sampled
# versions), and it is never mentioned there under that name -- so rather
# than assert an unconfirmed "requires vN" cutoff, it is probed directly
# via `resolvectl --help` output.
# UNVERIFIED: resolvectl default-route's introduction version (a full
# NEWS sweep rules out it ever being called out as a NEWS-worthy addition
# by that name, but that's consistent with it either predating v234 or
# simply never having earned its own bullet point -- not the same as a
# confirmed introduction version).
# UNVERIFIED: whether systemd-resolve's --set-dns=/--set-domain= accept
# multiple values per flag occurrence or must be repeated once per value;
# the emitters below repeat the flag once per value, which is the
# standard getopt_long repeatable-option convention and is safe even if
# a single occurrence would also have accepted a space-separated list.
# --------------------------------------------------------------------------

rhook_dns_tool_detect() {
	if command -v "$RACOON_HOOK_RESOLVECTL" >/dev/null 2>&1; then
		printf 'resolvectl'
	elif command -v "$RACOON_HOOK_SYSTEMD_RESOLVE" >/dev/null 2>&1; then
		printf 'systemd-resolve'
	fi
	return 0
}

# `systemctl --version`, first line, second field, e.g.
# "systemd 255 (255.4-1ubuntu8.4)" -> "255".
rhook_systemd_version() {
	"$RACOON_HOOK_SYSTEMCTL" --version 2>/dev/null | awk 'NR==1{print $2; exit}'
}

# rhook_dns_cap <tool> <capability>
# capability: per_link_dns | routing_domains | default_route | revert | flush_caches
# Returns 0 (has it) / 1 (doesn't); prints nothing either way.
rhook_dns_cap() {
	local rhook_tool rhook_cap
	rhook_tool="$1"
	rhook_cap="$2"
	[ -n "$rhook_tool" ] || return 1
	case "$rhook_cap" in
		per_link_dns|routing_domains|revert|flush_caches)
			return 0
			;;
		default_route)
			case "$rhook_tool" in
				resolvectl)
					"$RACOON_HOOK_RESOLVECTL" --help 2>&1 | grep -q 'default-route'
					return $?
					;;
				*)
					return 1
					;;
			esac
			;;
		*)
			return 1
			;;
	esac
}

# --------------------------------------------------------------------------
# Emitters: one function per operation, each with a case-branch per tool
# selecting that tool's grammar. Every branch prints a plain command-line
# string (destined for a plan step's command/undo_command field, later
# run via eval -- see the plan-storage comment on why that is safe here)
# and returns 1 if the tool isn't one of the two known ones. Never build
# one command string and hope it works for whichever tool happens to be
# installed (§6 point 4).
# --------------------------------------------------------------------------

# rhook_dns_emit_set_dns <tool> <iface> <server...>
rhook_dns_emit_set_dns() {
	local rhook_tool rhook_iface rhook_out rhook_srv
	rhook_tool="$1"; rhook_iface="$2"; shift 2
	case "$rhook_tool" in
		resolvectl)
			rhook_out="$RACOON_HOOK_RESOLVECTL dns $rhook_iface"
			for rhook_srv in "$@"; do rhook_out="$rhook_out $rhook_srv"; done
			;;
		systemd-resolve)
			rhook_out="$RACOON_HOOK_SYSTEMD_RESOLVE"
			for rhook_srv in "$@"; do
				rhook_out="$rhook_out --interface=$rhook_iface --set-dns=$rhook_srv"
			done
			;;
		*)
			return 1
			;;
	esac
	printf '%s' "$rhook_out"
}

# rhook_dns_emit_set_domains <tool> <iface> <domain...>
# Domains are passed through exactly as given by the caller; whether they
# carry a leading '~' (routing-only) or not is the plan builder's
# decision (§6/§7.1: only meaningful when the backend actually routes on
# it), not this emitter's.
rhook_dns_emit_set_domains() {
	local rhook_tool rhook_iface rhook_out rhook_dom
	rhook_tool="$1"; rhook_iface="$2"; shift 2
	case "$rhook_tool" in
		resolvectl)
			rhook_out="$RACOON_HOOK_RESOLVECTL domain $rhook_iface"
			for rhook_dom in "$@"; do rhook_out="$rhook_out $rhook_dom"; done
			;;
		systemd-resolve)
			rhook_out="$RACOON_HOOK_SYSTEMD_RESOLVE"
			for rhook_dom in "$@"; do
				rhook_out="$rhook_out --interface=$rhook_iface --set-domain=$rhook_dom"
			done
			;;
		*)
			return 1
			;;
	esac
	printf '%s' "$rhook_out"
}

# rhook_dns_emit_default_route <tool> <iface> <true|false>
# resolvectl only; systemd-resolve never gained an equivalent. Callers
# must check rhook_dns_cap first and skip (report §5.3 SKIPPED with
# reason+impact), not call this blind.
rhook_dns_emit_default_route() {
	local rhook_tool rhook_iface rhook_val
	rhook_tool="$1"; rhook_iface="$2"; rhook_val="$3"
	case "$rhook_tool" in
		resolvectl)
			printf '%s default-route %s %s' "$RACOON_HOOK_RESOLVECTL" "$rhook_iface" "$rhook_val"
			;;
		*)
			return 1
			;;
	esac
}

# rhook_dns_emit_revert <tool> <iface>
rhook_dns_emit_revert() {
	local rhook_tool rhook_iface
	rhook_tool="$1"; rhook_iface="$2"
	case "$rhook_tool" in
		resolvectl)
			printf '%s revert %s' "$RACOON_HOOK_RESOLVECTL" "$rhook_iface"
			;;
		systemd-resolve)
			printf '%s --interface=%s --revert' "$RACOON_HOOK_SYSTEMD_RESOLVE" "$rhook_iface"
			;;
		*)
			return 1
			;;
	esac
}

# rhook_dns_emit_flush_caches <tool>
rhook_dns_emit_flush_caches() {
	case "$1" in
		resolvectl)
			printf '%s flush-caches' "$RACOON_HOOK_RESOLVECTL"
			;;
		systemd-resolve)
			printf '%s --flush-caches' "$RACOON_HOOK_SYSTEMD_RESOLVE"
			;;
		*)
			return 1
			;;
	esac
}

# rhook_dns_emit_clear_dns / rhook_dns_emit_clear_domains <tool> <iface>
#
# Explicit per-setting undo for set_dns/set_domains (§6 point 6). NEVER use
# "~." here: that is the catch-all *routing* domain, meaning "route every
# query with no better match to this link" -- the opposite of clearing it,
# and it promotes a DNS-less link to the system-wide default resolver.
# This is a confirmed, previously-live bug in this hook set's own teardown
# fallback: it produced a total resolution outage on the very path meant
# to prevent one, reported by users as "the VPN killed my internet".
#
# resolvectl's empty-string form (`dns IFACE ""` / `domain IFACE ""`) is
# genuinely valid -- confirmed against resolvectl.c's verb_dns()/
# verb_domain()/call_dns(): an argv of a single empty string is special-
# cased (`strv_equal(dns, STRV_MAKE(""))`) to bypass normal per-value
# parsing and clear the setting. systemd-resolve's flag-based
# --set-dns=""/--set-domain="" is NOT the equivalent, despite looking
# like it should be: confirmed against systemd v237's own
# resolve-tool.c that --set-dns requires a value that parses as an
# address (in_addr_from_string_auto()) and --set-domain requires valid
# domain syntax -- an empty string fails both, and the command errors
# out rather than clearing anything. Found live on a real Bionic host
# (systemd-resolve --interface=racoon0 --set-dns="" / --set-domain=""
# both erroring), not merely inferred from source. --revert is that
# tool's own documented way to clear all per-link settings; confirmed
# idempotent by reading resolved's server-side D-Bus method
# implementation (resolved-link-bus.c's bus_link_method_revert(), called
# via resolved-bus.c's call_link_method()/get_any_link()): it
# unconditionally calls link_flush_settings() and returns success
# regardless of whether anything was actually set on the link, with the
# only error paths being an unknown ifindex or an explicitly unmanaged
# link -- neither applies to a dummy interface this hook set is actively
# tearing down. Calling revert from both this function and
# rhook_dns_emit_clear_domains() when both steps are in the same plan is
# therefore redundant but harmless, not a bug to work around.
rhook_dns_emit_clear_dns() {
	local rhook_tool rhook_iface
	rhook_tool="$1"; rhook_iface="$2"
	case "$rhook_tool" in
		resolvectl)
			printf '%s dns %s ""' "$RACOON_HOOK_RESOLVECTL" "$rhook_iface"
			;;
		systemd-resolve)
			rhook_dns_emit_revert "$rhook_tool" "$rhook_iface"
			;;
		*)
			return 1
			;;
	esac
}

rhook_dns_emit_clear_domains() {
	local rhook_tool rhook_iface
	rhook_tool="$1"; rhook_iface="$2"
	case "$rhook_tool" in
		resolvectl)
			printf '%s domain %s ""' "$RACOON_HOOK_RESOLVECTL" "$rhook_iface"
			;;
		systemd-resolve)
			rhook_dns_emit_revert "$rhook_tool" "$rhook_iface"
			;;
		*)
			return 1
			;;
	esac
}

# rhook_dns_emit_status <tool> <iface>
# Prints the command that dumps that tool's per-link status: `resolvectl
# status <iface>` (bare verb) or `systemd-resolve --status <iface>`
# (confirmed against systemd v237's own src/resolve/resolve-tool.c: MODE_STATUS
# treats trailing positional arguments as interface names/indices, so the
# older flag-based tool accepts the same positional-interface form as the
# newer verb-based one -- this is not a guess).
rhook_dns_emit_status() {
	local rhook_tool rhook_iface
	rhook_tool="$1"; rhook_iface="$2"
	case "$rhook_tool" in
		resolvectl)
			printf '%s status %s' "$RACOON_HOOK_RESOLVECTL" "$rhook_iface"
			;;
		systemd-resolve)
			printf '%s --status %s' "$RACOON_HOOK_SYSTEMD_RESOLVE" "$rhook_iface"
			;;
		*)
			return 1
			;;
	esac
}

# rhook_dns_status_has <tool> <iface> <value>
# §7.4 effectiveness check primitive shared by the DNS-server and domain
# postconditions: does <value> appear anywhere in that link's status
# output? A plain substring search, deliberately not a structural
# line/field parser, because the output format is confirmed to differ
# materially between tool generations:
#   - systemd v237's systemd-resolve --status (confirmed against its own
#     source, src/resolve/resolve-tool.c, status_ifindex()): plain text,
#     one value per line, first line prefixed "DNS Servers:"/"DNS Domain:",
#     continuation lines blank-padded to the same width.
#   - systemd v255's resolvectl status (confirmed against its own source,
#     src/resolve/resolvectl.c): a table_new_vertical()-rendered table
#     with box-drawing characters via dump_list(..., "DNS Servers", ...),
#     not line-oriented text at all.
# UNVERIFIED: the exact byte-for-byte table layout of modern `resolvectl
# status` (box-drawing characters, possible ANSI color codes, exact
# column wrapping via TABLE_STRV_WRAPPED) was not confirmed against a
# live run, nor was the systemd version boundary where the table format
# was introduced -- checked systemd's own NEWS file across the full
# v234-v260 range for it and found nothing (a rendering-format rewrite of
# an existing verb's output is exactly the kind of change NEWS tends not
# to call out at all, unlike a new flag or verb), so this stays open
# rather than being narrowed to a version range. A structural parser
# tuned to either format would
# silently stop matching on the other; a substring search over the
# whole per-link block does not have that failure mode -- an IPv4/IPv6
# address or domain name is not going to appear as a substring of box-
# drawing/ANSI decoration -- so it is the more robust choice given the
# confirmed format divergence, at the cost of being unable to confirm
# *which* field the value came from. Settled by: capturing real output
# from both tool generations and, if the table format proves stable
# enough, adding a stricter per-format parser as a first attempt with
# this substring check retained as the fallback.
rhook_dns_status_has() {
	local rhook_tool rhook_iface rhook_value rhook_cmd
	rhook_tool="$1"; rhook_iface="$2"; rhook_value="$3"
	rhook_cmd=$(rhook_dns_emit_status "$rhook_tool" "$rhook_iface") || return 1
	eval "$rhook_cmd" 2>/dev/null | grep -qF -- "$rhook_value"
}

# --------------------------------------------------------------------------
# Overall backend classification, synthesized from the survey signals
# above. §3.1 lists "resolver backend" as a survey-record field; this
# extends the survey rather than duplicating its logic.
# --------------------------------------------------------------------------

# rhook_survey_classify_backend <configured backend: auto|resolved|networkmanager|resolvconf|dnsmasq|none>
# An explicit (non-"auto") value from hooks.conf is returned unchanged --
# the admin's override always wins. "auto" runs the actual classification.
rhook_survey_classify_backend() {
	local rhook_configured rhook_rc rhook_reader
	rhook_configured="$1"
	case "$rhook_configured" in
		auto) ;;
		*) printf '%s' "$rhook_configured"; return 0 ;;
	esac

	rhook_rc=$(rhook_nm_dbus_prop RcManager)
	case "$rhook_rc" in
		symlink|file|resolvconf|netconfig)
			printf 'networkmanager'
			return 0
			;;
	esac

	if rhook_survey_nss_uses_resolve; then
		printf 'resolved'
		return 0
	fi

	rhook_reader=$(rhook_survey_glibc_reader)
	case "$rhook_reader" in
		*/run/systemd/resolve/stub-resolv.conf|*/run/systemd/resolve/resolv.conf)
			printf 'resolved'
			return 0
			;;
		*/run/NetworkManager/*)
			printf 'networkmanager'
			return 0
			;;
		*/run/resolvconf/resolv.conf|*/etc/resolvconf/run/resolv.conf)
			printf 'resolvconf'
			return 0
			;;
	esac

	# Content-signature fallback for the "rc-manager=symlink wrote a
	# plain file because /etc/resolv.conf started life as one" case,
	# which is indistinguishable from rc-manager=file by path alone (see
	# rhook_nm_dbus_prop's comment) and by definition has no useful
	# RcManager answer if NetworkManager isn't even installed/active.
	if [ -r "$rhook_reader" ]; then
		if grep -Eqi 'generated by network[[:space:]]*manager' "$rhook_reader" 2>/dev/null; then
			printf 'networkmanager'; return 0
		fi
		if grep -Eqi 'generated by resolvconf|dynamic resolv\.conf\(5\)' "$rhook_reader" 2>/dev/null; then
			printf 'resolvconf'; return 0
		fi
		if grep -Eqi 'managed by man:systemd-resolved' "$rhook_reader" 2>/dev/null; then
			printf 'resolved'; return 0
		fi
	fi

	if command -v "$RACOON_HOOK_RESOLVCONF" >/dev/null 2>&1 && [ -e "$(rhook_fs_path /run/resolvconf)" ]; then
		printf 'resolvconf'
		return 0
	fi
	if pgrep -x dnsmasq >/dev/null 2>&1; then
		printf 'dnsmasq'
		return 0
	fi
	printf 'static'
	return 0
}

# NetworkManager's "dns=" setting is a comma-separated list of
# simultaneously active plugins (confirmed in the field:
# "dns-mgr: init: dns=default,systemd-resolved rc-manager=symlink"), not
# one-or-the-other. The D-Bus Mode property reports only the single
# primary resolv.conf-owning plugin and silently drops the rest; the
# merged config text from --print-config has the full list but won't show
# a compiled-in distro default that was never written as an explicit
# line. Union both rather than preferring one.
rhook_nm_dns_mode_union() {
	local rhook_mode_dbus rhook_mode_cfg
	rhook_mode_dbus=$(rhook_nm_dbus_prop Mode)
	rhook_mode_cfg=$("$RACOON_HOOK_NETWORKMANAGER" --print-config 2>/dev/null \
	    | awk -F= '/^\[main\]/{m=1;next} /^\[/{m=0} m && $1 ~ /^[[:space:]]*dns[[:space:]]*$/ {gsub(/[[:space:]]/,"",$2); print $2; exit}')
	printf '%s%s%s' "$rhook_mode_dbus" "${rhook_mode_dbus:+,}" "$rhook_mode_cfg"
}

# --------------------------------------------------------------------------
# Step preconditions/postconditions consulted by run_step(). These read
# RHOOK_BACKEND_RESOLVED/RHOOK_DNS_TOOL/RHOOK_CAP_DEFAULT_ROUTE/
# RHOOK_EXPECT_DNS/RHOOK_EXPECT_DOMAINS, set once by rhook_build_plan() before any step runs
# (run_step's calling convention only passes the step id, not per-step
# context, so shared decisions the plan already made live here as globals
# rather than being re-derived per step).
# --------------------------------------------------------------------------

# Shared by both dummy-interface-creation step types: skipped for the
# networkmanager backend, where nm_dummy_profile creates the interface
# (with its address and DNS baked in) as a single `nmcli connection add`
# instead -- creating it separately first and modifying it afterward is
# exactly the "modify while active" ordering that raced and failed in
# earlier iterations of this hook set.
rhook_precond_create_dummy() {
	[ "$RHOOK_BACKEND_RESOLVED" = "networkmanager" ] && \
		printf 'the networkmanager backend creates its own dummy interface as part of the connection profile'
	return 0
}
rhook_precond_add_addr() {
	rhook_precond_create_dummy
}

rhook_precond_default_route() {
	if [ "$RHOOK_CAP_DEFAULT_ROUTE" != "yes" ]; then
		printf '%s has no default-route capability on this system; VPN DNS may serve queries outside the split domains while the tunnel is up' "${RHOOK_DNS_TOOL:-the detected resolver tool}"
	fi
	return 0
}

# §B.3 (brief 3): unconditional skip -- rhook_plan_dns_resolved() only
# plans a resolved_no_scope step when it has already determined neither
# routing domains nor default-route=no is available to scope this link,
# so there is nothing to gate here beyond stating the exposure plainly
# (the brief's explicit "impact line" requirement).
rhook_precond_resolved_no_scope() {
	printf 'no split-DNS domains from the gateway and %s has no default-route capability on this system -- registering DNS servers with neither would make them the resolver for ALL lookups on this link, not real split-DNS; skipping DNS configuration entirely. Internal names behind the tunnel will not resolve until this is addressed (add split-DNS domains at the gateway, or use a resolver tool with default-route support).' "${RHOOK_DNS_TOOL:-the detected resolver tool}"
}

# §7.4 effectiveness check for the DNS-server step: a step that exited 0
# but produced no observable change (wrote to a link nothing reads, or a
# networkd-managed interface silently refused a link-scoped resolved
# setting) must be reported as failed.
#
# F3 (brief 3): the previous version of this check only special-cased
# `resolvectl` -- gated on `command -v "$RACOON_HOOK_RESOLVECTL"` -- and
# fell through to the file-content check for every other case, including
# the *resolved* backend on a systemd-resolve-only system (no resolvectl
# binary at all, e.g. Ubuntu Bionic/systemd 237). On such a system the
# file-content fallback checks /run/systemd/resolve/stub-resolv.conf,
# which by design only ever contains "nameserver 127.0.0.53" -- it can
# never contain a real per-link server, so every resolved-backend run
# reported FAILED regardless of whether the setting actually applied
# (confirmed live: this false failure is what triggered the F4 reconnect
# loop). Fixed by branching on the *tool* (RHOOK_DNS_TOOL), covering
# both resolvectl and systemd-resolve identically via
# rhook_dns_status_has(), not by which binary happens to also exist.
#
# The nss_uses_resolve() check below implements brief 3 §A's "if
# nsswitch.conf contains a resolve entry, the resolved per-link state is
# authoritative regardless of any file's content": normally
# RHOOK_BACKEND_RESOLVED is already "resolved" whenever nss_uses_resolve
# is true (rhook_survey_classify_backend picks it first, before any file
# heuristic), *unless* hooks.conf explicitly overrides backend to
# something else. In that override case file content is genuinely
# irrelevant to what glibc actually reads, so checking it would let a
# cosmetically-applied-but-functionally-inert configuration report "ok" --
# checking resolved's own per-link status here, even though a different
# backend was configured, correctly reports the mismatch as a failure
# instead.
rhook_postcond_set_dns() {
	local rhook_first rhook_reader
	[ -n "${RHOOK_EXPECT_DNS:-}" ] || return 0
	rhook_first="${RHOOK_EXPECT_DNS%% *}"

	if [ "$RHOOK_BACKEND_RESOLVED" = "resolved" ] || rhook_survey_nss_uses_resolve; then
		if [ -n "$RHOOK_DNS_TOOL" ] && rhook_dns_status_has "$RHOOK_DNS_TOOL" "$RHOOK_DUMMY_IFACE" "$rhook_first"; then
			return 0
		fi
		printf '%s status %s does not list %s as a DNS server for this link' "${RHOOK_DNS_TOOL:-resolvectl/systemd-resolve}" "$RHOOK_DUMMY_IFACE" "$rhook_first"
		return 0
	fi

	if rhook_survey_dns_effective_file "$rhook_first"; then
		return 0
	fi
	rhook_reader=$(rhook_survey_glibc_reader)
	printf '%s is not visible in %s, which is what name resolution actually reads' "$rhook_first" "$rhook_reader"
	return 0
}

# §7.4 effectiveness check for the routing-domain step, new in brief 3
# (previously the set_domains step type had no postcondition registered
# at all). Checks the same per-link status output as rhook_postcond_set_dns
# for the same reason (nss_uses_resolve authoritative-regardless-of-file
# rule applies identically here).
#
# UNVERIFIED: whether a routing-only domain is echoed back in `status`
# output *with* its leading '~' or without -- not confirmed against a
# live resolved instance either way. Tolerates both forms by checking
# for the domain with any leading '~' stripped from the expected value
# before searching, since the bare domain name is a substring of the
# tilde-prefixed form either way.
rhook_postcond_set_domains() {
	local rhook_first rhook_bare
	[ -n "${RHOOK_EXPECT_DOMAINS:-}" ] || return 0
	rhook_first="${RHOOK_EXPECT_DOMAINS%% *}"
	rhook_bare="${rhook_first#\~}"

	if [ -n "$RHOOK_DNS_TOOL" ] && rhook_dns_status_has "$RHOOK_DNS_TOOL" "$RHOOK_DUMMY_IFACE" "$rhook_bare"; then
		return 0
	fi
	printf '%s status %s does not list %s as a domain for this link' "${RHOOK_DNS_TOOL:-resolvectl/systemd-resolve}" "$RHOOK_DUMMY_IFACE" "$rhook_bare"
	return 0
}

# --------------------------------------------------------------------------
# Content builders used inside eval'd plan commands (defined here so
# they're in scope wherever the sourced library is; see the plan-storage
# comment on why embedding validated-only tokens in an eval'd string is
# safe).
# --------------------------------------------------------------------------
rhook_resolvconf_record_content() {
	local rhook_dom rhook_srv
	if [ -n "$RHOOK_DOMAINS" ]; then
		printf 'search'
		for rhook_dom in $RHOOK_DOMAINS; do printf ' %s' "$rhook_dom"; done
		printf '\n'
	fi
	for rhook_srv in $RHOOK_DNS_SERVERS; do
		printf 'nameserver %s\n' "$rhook_srv"
	done
}

# §8 fix: dnsmasq's `server=<ip>` replaces the *global* upstream (every
# query goes to the VPN resolver) and `domain=` is the DHCP/expansion
# domain, unrelated to query routing -- neither is split-DNS. The form
# that actually scopes queries to specific domains is one line per
# domain: `server=/corp.example.com/10.0.12.53`.
rhook_dnsmasq_conf_content() {
	local rhook_dom rhook_srv
	for rhook_dom in $RHOOK_DOMAINS; do
		for rhook_srv in $RHOOK_DNS_SERVERS; do
			printf 'server=/%s/%s\n' "$rhook_dom" "$rhook_srv"
		done
	done
}

# --------------------------------------------------------------------------
# Brief 3 §E: SPD ownership (R2').
#
# Brief 1's R2 ("never touch SPD/SAD") assumed racoon installs its own
# client-side policy once Mode Config hands out an address. Verified
# against this tree's own src/racoon sources, not assumed: SPD generation
# (rmconf->gen_policy / iph2->spidx_gen, consumed only by pk_sendspdadd2()
# in pfkey.c) is wired exclusively into get_proposal_r() in
# isakmp_quick.c, which is called only from quick_r1recv() -- the
# *responder* side of quick mode (the "_r" naming convention, and the
# function's own comment, both confirm this). There is no code path that
# installs an SPD entry for an initiator receiving a Mode Config address.
# Without a policy, the split-include traffic this hook just routed onto
# the tunnel has nothing telling the kernel to encrypt it -- any packet
# reaching the peer's subnet outside of an existing SA triggers a kernel
# ACQUIRE instead, which is the reconnect loop observed in F1/F4.
#
# The hook now installs exactly the SPD entries its own routes correspond
# to, one in/out pair per RHOOK_ROUTES entry, and owns exactly what it
# installed: each entry's undo command is a full spddelete reconstructed
# from the same selector text at plan-build time, journalled to state like
# any other step (never spdflush, never `setkey -F`), torn down through
# rhook_run_step() like any other step. Apply order places this after
# routes and before DNS, so reversing apply order for teardown produces
# the brief's required DNS -> SPD -> routes -> address -> dummy sequence
# without this file needing to know about that ordering explicitly.
#
# Every value interpolated into a spdadd/spddelete line below is either
# already-validated (RHOOK_INTERNAL_ADDR4, RHOOK_ROUTES -- both passed
# through rhook_valid_ipv4()/rhook_validate_cidr_list() in phase1-up.sh
# before rhook_build_plan() ever runs) or must be validated by the caller
# before calling rhook_plan_spd() (LOCAL_ADDR/REMOTE_ADDR/LOCAL_PORT/
# REMOTE_PORT -- raw Mode Config / racoon environment input, R3). setkey's
# stdin grammar has no escaping mechanism: a newline or shell metacharacter
# smuggled into an unvalidated selector would inject arbitrary setkey
# commands here, or -- since rhook_run_step() executes the stored command
# via eval -- arbitrary shell. This is the highest-severity finding in the
# subsystem per the brief; there is no defense-in-depth below beyond that
# validation, so it must not be skipped.
# --------------------------------------------------------------------------

# rhook_spd_tunnel_endpoints <local_addr> <local_port> <remote_addr> <remote_port>
# Builds the esp/tunnel/... ipsec_level string consumed by setkey's -P
# policy_requests grammar (src/libipsec/policy_parse.y's `addresses`
# production, confirmed in this tree to accept both "IPADDRESS-IPADDRESS"
# and "IPADDRESS PORT HYPHEN IPADDRESS PORT" with PORT being
# policy_token.l's bracketed `\[{decstring}\]`). Ports are included only
# when both are known; the bare address-address form is the other half of
# the same grammar production, not a different one, so omitting ports here
# is not a degraded case.
rhook_spd_tunnel_endpoints() {
	local rhook_laddr rhook_lport rhook_raddr rhook_rport
	rhook_laddr="$1"
	rhook_lport="$2"
	rhook_raddr="$3"
	rhook_rport="$4"
	if [ -n "$rhook_lport" ] && [ -n "$rhook_rport" ]; then
		printf 'esp/tunnel/%s[%s]-%s[%s]/require' "$rhook_laddr" "$rhook_lport" "$rhook_raddr" "$rhook_rport"
	else
		printf 'esp/tunnel/%s-%s/require' "$rhook_laddr" "$rhook_raddr"
	fi
}

# rhook_plan_spd: one required in/out pair of spd_entry steps per
# RHOOK_ROUTES entry. A no-op when RHOOK_ROUTES is empty -- the R7
# no-routes-at-all case already planned a required failing no_routes step
# ahead of this call, so rhook_apply_plan() never reaches here in that
# case, but this stays a harmless no-op regardless of call order.
#
# Caller (phase1-up.sh) is expected to have already whitelist-validated
# LOCAL_ADDR/REMOTE_ADDR (rhook_valid_ipv4) and LOCAL_PORT/REMOTE_PORT
# (rhook_valid_port, when present) -- see the §E header comment above.
rhook_plan_spd() {
	local rhook_net rhook_endpoints rhook_endpoints_rev
	local rhook_out_line rhook_out_undo_line rhook_in_line rhook_in_undo_line

	[ -n "$RHOOK_ROUTES" ] || return 0

	rhook_endpoints=$(rhook_spd_tunnel_endpoints "${LOCAL_ADDR:-}" "${LOCAL_PORT:-}" "${REMOTE_ADDR:-}" "${REMOTE_PORT:-}")
	rhook_endpoints_rev=$(rhook_spd_tunnel_endpoints "${REMOTE_ADDR:-}" "${REMOTE_PORT:-}" "${LOCAL_ADDR:-}" "${LOCAL_PORT:-}")

	for rhook_net in $RHOOK_ROUTES; do
		rhook_out_line="spdadd $RHOOK_INTERNAL_ADDR4/32 $rhook_net any -P out ipsec $rhook_endpoints;"
		rhook_out_undo_line="spddelete $RHOOK_INTERNAL_ADDR4/32 $rhook_net any -P out;"
		rhook_in_line="spdadd $rhook_net $RHOOK_INTERNAL_ADDR4/32 any -P in ipsec $rhook_endpoints_rev;"
		rhook_in_undo_line="spddelete $rhook_net $RHOOK_INTERNAL_ADDR4/32 any -P in;"

		rhook_plan_add "spd_out_$rhook_net" spd_entry required \
			"install outbound SPD $RHOOK_INTERNAL_ADDR4/32 -> $rhook_net" \
			"printf '%s\n' '$rhook_out_line' | $RACOON_HOOK_SETKEY -c" \
			"printf '%s\n' '$rhook_out_undo_line' | $RACOON_HOOK_SETKEY -c"

		rhook_plan_add "spd_in_$rhook_net" spd_entry required \
			"install inbound SPD $rhook_net -> $RHOOK_INTERNAL_ADDR4/32" \
			"printf '%s\n' '$rhook_in_line' | $RACOON_HOOK_SETKEY -c" \
			"printf '%s\n' '$rhook_in_undo_line' | $RACOON_HOOK_SETKEY -c"
	done
	return 0
}

# --------------------------------------------------------------------------
# Idempotent dummy-interface creation.
#
# Found live (Ubuntu Bionic roadwarrior, no reboot between test runs):
#   [trace]   command: ip link add "racoon0" type dummy && ip link set "racoon0" up
#   [trace]   output: RTNETLINK answers: File exists
# An incomplete prior teardown -- F2's SIGTERM/script_exec() race
# (doc/dev/v0.9.1-hardening-spec.md §5.6, Issue 1), or simply racoon restarting without a
# clean phase1-down.sh having run first -- left racoon0 already present.
# The unconditional `ip link add ... type dummy` this step used to run
# then failed outright (ip exit 2), a *required* step, halting
# phase1-up.sh before address, routes, SPD or DNS ever applied --
# leaving the interface "hanging" from the prior run AND the new
# connection completely unconfigured.
#
# Verified against real iproute2 behavior (this tree's own dev
# container, iproute2 6.1.0) rather than assumed, and cross-checked
# against iproute2 4.15.0's own source -- the exact release Ubuntu
# Bionic ships -- via ipaddr_list_flush_or_save()/match_link_kind() in
# ipaddress.c, confirming `ip link show dev IFACE type KIND` filtering
# by the link's info_kind existed there too, not only in a newer
# version:
#   - a nonexistent device: `ip link show dev IFACE` (with or without a
#     type filter) exits 1 with `Device "IFACE" does not exist.`
#   - an existing device whose type does NOT match the filter: exits 0
#     with EMPTY output -- the mismatch is silent, not an error, so
#     exit status alone cannot distinguish "wrong type" from "matches";
#     the output must be checked for content.
#   - an existing device whose type DOES match: exits 0 with the normal
#     link listing (non-empty).
#
# Never touches an existing interface this hook set cannot positively
# identify as its own dummy-type creation -- reusing (never deleting or
# reconfiguring) a same-named, wrong-type interface would violate R1
# ("no persistent reconfiguration beyond the VPN session") far more
# seriously than refusing to start.
#
# Known residual scope limit, not fixed here: this assumes a single
# active session owns $RHOOK_DUMMY_IFACE at a time -- the same
# assumption the networkmanager backend's nm_dummy_profile step already
# makes via its own single hardcoded connection name. Two genuinely
# concurrent generations for the same peer (brief 3 §D's overlap
# scenario) sharing one physical dummy interface is a separate,
# pre-existing design question this fix does not attempt to solve; what
# rhook_dummy_iface_lock() below does close is the TOCTOU race in *how*
# they share it (see its own header comment).
# --------------------------------------------------------------------------

# --------------------------------------------------------------------------
# PR #91 review row 24 (comment 5061097437): rhook_ensure_dummy_iface()'s
# check-then-create was a TOCTOU race under concurrent phase1-up.sh runs
# -- two genuinely concurrent invocations (for the same peer, per the
# overlap scenario above, or for two *different* peers: $RHOOK_DUMMY_IFACE
# is one fixed name from hooks.conf, not derived from the peer at all, so
# any two concurrent sessions race on it regardless of which peers they're
# for) could both pass the "does it exist" check before either created the
# interface. Bounded in practice (the idempotent-reuse branch above turns
# the loser's `ip link add` failure into a harmless "already exists,
# reusing" branch, not a crash) but still a real race worth closing since
# closing it is cheap.
#
# mkdir is the only mechanism, deliberately -- flock(1) was tried first
# (file-descriptor form: `exec N>file`, `flock N`, `flock -u N`) and
# worked against util-linux's flock (2.39.3, this tree's own dev
# container), but this project's NetBSD CI job is what actually settled
# the question the original comment here left UNVERIFIED ("whether
# flock(1) ships in NetBSD's base install"): something named `flock` is
# on PATH there, but it does not implement the fd-operating form the
# same way -- `flock -w 20 9` returned failure almost immediately rather
# than actually blocking (confirmed from the CI log's own timestamps:
# both concurrent invocations logged "still held after 20s" within
# about 1.2 real seconds of each other, which a genuine 20-second wait
# cannot do), silently turning the lock into a no-op and reproducing
# exactly the race this function exists to close. Rather than try to
# detect or work around whichever incompatible `flock` that is, this
# drops the dependency entirely and always uses the same mkdir-based
# retry-and-cap lock rhook_state_reset() already relies on above --
# mkdir is atomic on every POSIX filesystem, needs no external tool,
# and a lock held by a process that died mid-section still cannot wedge
# every future connection attempt forever.
# --------------------------------------------------------------------------
rhook_dummy_iface_lock() {
	local rhook_edil_iface rhook_edil_lock rhook_edil_tries
	rhook_edil_iface=$(printf '%s' "$1" | tr -c 'A-Za-z0-9._-' '_')
	rhook_ensure_state_dir
	rhook_edil_lock="$RHOOK_STATE_DIR/dummy-iface.$rhook_edil_iface.lock"

	rhook_edil_tries=0
	while ! mkdir "$rhook_edil_lock.d" 2>/dev/null; do
		rhook_edil_tries=$((rhook_edil_tries + 1))
		if [ "$rhook_edil_tries" -ge 20 ]; then
			rhook_log warn "dummy interface lock for $rhook_edil_iface still held after ${rhook_edil_tries}s -- proceeding without it (a concurrent phase1-up racing for the same dummy interface name may hit the idempotent-reuse path instead of a clean create)"
			break
		fi
		sleep 1
	done
	return 0
}

rhook_dummy_iface_unlock() {
	local rhook_edil_iface rhook_edil_lock
	rhook_edil_iface=$(printf '%s' "$1" | tr -c 'A-Za-z0-9._-' '_')
	rhook_edil_lock="$RHOOK_STATE_DIR/dummy-iface.$rhook_edil_iface.lock"

	rmdir "$rhook_edil_lock.d" 2>/dev/null
	return 0
}

rhook_ensure_dummy_iface() {
	local rhook_edi_iface rhook_edi_rc
	rhook_edi_iface="$1"

	rhook_dummy_iface_lock "$rhook_edi_iface"

	if ! "$RACOON_HOOK_IP" link show dev "$rhook_edi_iface" >/dev/null 2>&1; then
		"$RACOON_HOOK_IP" link add "$rhook_edi_iface" type dummy && "$RACOON_HOOK_IP" link set "$rhook_edi_iface" up
		rhook_edi_rc=$?
		rhook_dummy_iface_unlock "$rhook_edi_iface"
		return $rhook_edi_rc
	fi

	if [ -n "$("$RACOON_HOOK_IP" -o link show dev "$rhook_edi_iface" type dummy 2>/dev/null)" ]; then
		rhook_log warn "dummy interface $rhook_edi_iface already exists -- reusing it rather than failing (a prior session's teardown likely did not complete; see the Admin Guide's Split-DNS & Routing Scripts section, Leftover State After a Non-Clean Stop)"
		"$RACOON_HOOK_IP" link set "$rhook_edi_iface" up
		rhook_edi_rc=$?
		rhook_dummy_iface_unlock "$rhook_edi_iface"
		return $rhook_edi_rc
	fi

	rhook_dummy_iface_unlock "$rhook_edi_iface"
	echo "an interface named $rhook_edi_iface already exists and is not a dummy-type interface phase1-up.sh created -- refusing to touch it (set dummy_iface in hooks.conf to a different name, or resolve the conflict manually)" >&2
	return 1
}

# rhook_cidr_overlaps <cidr1> <cidr2> -- true (0) if the two IPv4 CIDRs'
# address ranges share at least one address. Compares both networks'
# leading bits up to the *shorter* of the two prefix lengths (the only
# prefix length both are guaranteed to agree on if they overlap at all),
# octet by octet -- never combining all 4 octets into one integer the way
# an IP-to-int helper normally would, since e.g. 192.168.0.0's first
# octet alone (192 * 16777216) already exceeds a 32-bit signed integer's
# range, and this project has no confirmed guarantee every supported
# shell's arithmetic is wider than that. Every value handled here (each
# octet 0-255, each mask at most 8 bits) stays trivially within range on
# any integer width.
rhook_cidr_overlaps() {
	local rhook_co_a rhook_co_b rhook_co_lena rhook_co_lenb rhook_co_minlen
	local rhook_co_oldifs rhook_co_full rhook_co_rem rhook_co_mask rhook_co_i
	local rhook_co_ao1 rhook_co_ao2 rhook_co_ao3 rhook_co_ao4
	local rhook_co_bo1 rhook_co_bo2 rhook_co_bo3 rhook_co_bo4

	rhook_co_a="${1%%/*}"; rhook_co_lena="${1#*/}"
	rhook_co_b="${2%%/*}"; rhook_co_lenb="${2#*/}"

	if [ "$rhook_co_lena" -le "$rhook_co_lenb" ]; then
		rhook_co_minlen="$rhook_co_lena"
	else
		rhook_co_minlen="$rhook_co_lenb"
	fi

	rhook_co_oldifs="$IFS"
	IFS=.
	# shellcheck disable=SC2086 # word-splitting on IFS=. is the point
	set -- $rhook_co_a
	IFS="$rhook_co_oldifs"
	rhook_co_ao1="$1"; rhook_co_ao2="$2"; rhook_co_ao3="$3"; rhook_co_ao4="$4"

	rhook_co_oldifs="$IFS"
	IFS=.
	# shellcheck disable=SC2086 # word-splitting on IFS=. is the point
	set -- $rhook_co_b
	IFS="$rhook_co_oldifs"
	rhook_co_bo1="$1"; rhook_co_bo2="$2"; rhook_co_bo3="$3"; rhook_co_bo4="$4"

	rhook_co_full=$((rhook_co_minlen / 8))
	rhook_co_rem=$((rhook_co_minlen % 8))

	rhook_co_i=1
	while [ "$rhook_co_i" -le "$rhook_co_full" ]; do
		case "$rhook_co_i" in
			1) [ "$rhook_co_ao1" -eq "$rhook_co_bo1" ] || return 1 ;;
			2) [ "$rhook_co_ao2" -eq "$rhook_co_bo2" ] || return 1 ;;
			3) [ "$rhook_co_ao3" -eq "$rhook_co_bo3" ] || return 1 ;;
			4) [ "$rhook_co_ao4" -eq "$rhook_co_bo4" ] || return 1 ;;
		esac
		rhook_co_i=$((rhook_co_i + 1))
	done

	if [ "$rhook_co_rem" -gt 0 ] && [ "$rhook_co_full" -lt 4 ]; then
		rhook_co_mask=$(( (255 << (8 - rhook_co_rem)) & 255 ))
		rhook_co_i=$((rhook_co_full + 1))
		case "$rhook_co_i" in
			1) [ $((rhook_co_ao1 & rhook_co_mask)) -eq $((rhook_co_bo1 & rhook_co_mask)) ] || return 1 ;;
			2) [ $((rhook_co_ao2 & rhook_co_mask)) -eq $((rhook_co_bo2 & rhook_co_mask)) ] || return 1 ;;
			3) [ $((rhook_co_ao3 & rhook_co_mask)) -eq $((rhook_co_bo3 & rhook_co_mask)) ] || return 1 ;;
			4) [ $((rhook_co_ao4 & rhook_co_mask)) -eq $((rhook_co_bo4 & rhook_co_mask)) ] || return 1 ;;
		esac
	fi

	return 0
}

# --------------------------------------------------------------------------
# Plan builder (§3.2). Pure construction -- calls rhook_plan_add only,
# never anything that touches the system -- so --dry-run costs nothing to
# support (§3.2: "Building the plan performs no changes").
#
# Expects these already set by the caller, all already past §4 validation:
#   RHOOK_IFACE          - outbound physical interface
#   RHOOK_INTERNAL_ADDR4 - the /32 address assigned by the gateway
#   RHOOK_ROUTES         - space-separated CIDR list: SPLIT_INCLUDE_CIDR
#                          unioned with DNS-server /32 host routes
#   RHOOK_DNS_SERVERS    - space-separated validated IPv4 DNS servers
#   RHOOK_DOMAINS        - space-separated validated domains
#   LOCAL_ADDR/REMOTE_ADDR/LOCAL_PORT/REMOTE_PORT - racoon's own Phase 1
#                          environment, consumed by rhook_plan_spd() for
#                          the SPD tunnel-endpoint selector; validated by
#                          phase1-up.sh (rhook_valid_ipv4/rhook_valid_port)
#                          before rhook_build_plan() is called (§E header
#                          comment above rhook_plan_spd()).
# RHOOK_BACKEND (auto|resolved|networkmanager|resolvconf|dnsmasq|none, from
# hooks.conf) selects/overrides the backend. Sets RHOOK_BACKEND_RESOLVED,
# RHOOK_DNS_TOOL and RHOOK_CAP_DEFAULT_ROUTE as a side effect, consulted by
# the precondition/postcondition functions above and by the report header.
# --------------------------------------------------------------------------
rhook_build_plan() {
	local rhook_net
	local rhook_ci_a rhook_ci_b rhook_ci_a_idx rhook_ci_b_idx

	RHOOK_BACKEND_RESOLVED=$(rhook_survey_classify_backend "$RHOOK_BACKEND")
	RHOOK_DNS_TOOL=$(rhook_dns_tool_detect)
	if rhook_dns_cap "$RHOOK_DNS_TOOL" default_route; then
		RHOOK_CAP_DEFAULT_ROUTE="yes"
	else
		RHOOK_CAP_DEFAULT_ROUTE="no"
	fi
	rhook_log verbose "backend=$RHOOK_BACKEND_RESOLVED dns_tool=${RHOOK_DNS_TOOL:-none} default_route_capable=$RHOOK_CAP_DEFAULT_ROUTE"

	# Brief 3 §K: recorded in state via which undo command actually gets
	# journaled (this codebase's usual "the state file is the record"
	# convention -- see rhook_state_append()'s own header comment) rather
	# than as a separate metadata field. "nm" only ever applies to the
	# create_dummy/dummy_iface step below -- the networkmanager backend's
	# own nm_dummy_profile step already tears itself down via `nmcli
	# connection delete`, never `ip link del`, regardless of this value.
	if rhook_survey_nm_active; then
		RHOOK_DUMMY_OWNER="nm"
	else
		RHOOK_DUMMY_OWNER="iproute"
	fi
	rhook_log verbose "dummy interface owner: $RHOOK_DUMMY_OWNER"

	rhook_plan_reset

	if [ "$RHOOK_DUMMY_OWNER" = "nm" ]; then
		# NetworkManager is running and will very likely auto-manage this
		# interface the moment it appears (its default policy for any
		# interface not excluded by udev/unmanaged-devices=), even though
		# a different backend is handling DNS -- go through NM's own
		# device-removal path first so its bookkeeping stays consistent,
		# falling back to a plain `ip link del` if NM turns out not to
		# actually have claimed it (nmcli device delete failing is not
		# itself an error worth surfacing; the fallback's own exit status
		# is what the step's outcome is judged on), so the interface is
		# never leaked either way.
		rhook_plan_add dummy_iface create_dummy required \
			"create dummy interface $RHOOK_DUMMY_IFACE" \
			"rhook_ensure_dummy_iface \"$RHOOK_DUMMY_IFACE\"" \
			"$RACOON_HOOK_NMCLI device delete \"$RHOOK_DUMMY_IFACE\" >/dev/null 2>&1 || $RACOON_HOOK_IP link del \"$RHOOK_DUMMY_IFACE\""
	else
		rhook_plan_add dummy_iface create_dummy required \
			"create dummy interface $RHOOK_DUMMY_IFACE" \
			"rhook_ensure_dummy_iface \"$RHOOK_DUMMY_IFACE\"" \
			"$RACOON_HOOK_IP link del \"$RHOOK_DUMMY_IFACE\""
	fi

	rhook_plan_add dummy_addr add_addr required \
		"add $RHOOK_INTERNAL_ADDR4/32 to $RHOOK_DUMMY_IFACE" \
		"$RACOON_HOOK_IP addr replace \"$RHOOK_INTERNAL_ADDR4/32\" dev \"$RHOOK_DUMMY_IFACE\"" \
		"$RACOON_HOOK_IP addr del \"$RHOOK_INTERNAL_ADDR4/32\" dev \"$RHOOK_DUMMY_IFACE\""

	# Found live (Ubuntu Bionic and Arch/Manjaro roadwarriors, both with
	# NetworkManager active): `ip route ... src $RHOOK_INTERNAL_ADDR4`
	# below requires that address to already be assigned to *some* local
	# interface -- confirmed directly against the kernel (RTM_NEWROUTE's
	# own prefsrc validation, not an iproute2-side check): `ip route add
	# ... src X` fails with exactly "Error: Invalid prefsrc address."
	# (exit 2) whenever X is not currently configured anywhere on the
	# host, and succeeds the moment it is, regardless of which interface
	# it's on. For every other backend, dummy_iface/dummy_addr above
	# already assigned that address before this point. For
	# networkmanager, they are precondition-skipped (NM creates the
	# interface itself) and the only step that actually assigns the
	# address -- nm_dummy_profile, folded into rhook_plan_dns_networkmanager()
	# -- used to be planned last, inside the DNS section, after routes
	# and SPD. Routes therefore tried to reference an address nothing
	# had assigned yet and failed outright on every real NetworkManager
	# host tested, regardless of which DNS tool it delegates to
	# (systemd-resolve on Bionic, resolvectl on Arch -- the failure never
	# reached DNS-tool-specific code at all). Planning it here instead,
	# right alongside dummy_iface/dummy_addr, fixes that without touching
	# the resolved/resolvconf/dnsmasq/fallback backends' step order or
	# DNS-tool selection at all -- see rhook_plan_dns()'s own comment for
	# why the networkmanager case is a no-op there now.
	#
	# Trade-off, not hidden: nm_dummy_profile bundles interface, address
	# and DNS configuration into one atomic `nmcli connection add`
	# call -- deliberately, since Brief 1's own history found that
	# creating the interface separately and configuring it afterward
	# races NetworkManager's own policy audit ("modify while active").
	# Moving that whole atomic step earlier necessarily moves its
	# teardown later too (state file order follows actual apply order,
	# reversed) -- for this backend only, DNS is no longer the first
	# thing reverted on disconnect (R4), it is now reverted together
	# with the interface, last. Splitting it to preserve R4's ordering
	# exactly is the same "modify while active" race Brief 1 already
	# found and rejected, so this fix keeps the atomic step and accepts
	# the teardown-order trade-off rather than reintroducing that race.
	#
	# Known gap this does not address: if the gateway sends split-include
	# routes but no internal DNS servers at all, RHOOK_DNS_SERVERS is
	# empty and this call is skipped entirely (matching its pre-existing
	# guard), so no interface gets created here either -- routes would
	# still fail in that specific case, unchanged from before this fix.
	if [ "$RHOOK_BACKEND_RESOLVED" = "networkmanager" ] && [ -n "$RHOOK_DNS_SERVERS" ]; then
		rhook_plan_dns_networkmanager
	fi

	# PR #91 review row 29b (comment 5061097437): configuration-hygiene
	# check, not a security boundary -- two split-include ranges
	# overlapping isn't unsafe, just redundant (the overlap only needs
	# routing once), so this warns and proceeds with both rather than
	# rejecting either. Deliberately does not single out or reject
	# 0.0.0.0/0 (an intentional full-tunnel route): it's flagged like any
	# other CIDR only if it overlaps something else offered alongside it,
	# never rejected outright. This project has never taken a position on
	# whether full-tunnel is a supported deployment mode -- nothing in
	# doc/dev/ARCHITECTURE.md addresses it either way -- so an outright
	# prohibition here would be a unilateral product decision this fix
	# does not make; a hooks.conf opt-in/deny flag would be the right
	# shape if the maintainer decides full-tunnel needs deliberate
	# gating, but that is their call, not a default to assume here.
	rhook_ci_a_idx=0
	for rhook_ci_a in $RHOOK_ROUTES; do
		rhook_ci_a_idx=$((rhook_ci_a_idx + 1))
		rhook_ci_b_idx=0
		for rhook_ci_b in $RHOOK_ROUTES; do
			rhook_ci_b_idx=$((rhook_ci_b_idx + 1))
			[ "$rhook_ci_b_idx" -gt "$rhook_ci_a_idx" ] || continue
			if rhook_cidr_overlaps "$rhook_ci_a" "$rhook_ci_b"; then
				rhook_log warn "overlapping split ranges received from gateway: $rhook_ci_a and $rhook_ci_b"
			fi
		done
	done

	# R5: routes stay on the physical interface (that's what actually
	# forwards packets); only src= comes from the dummy-anchored address.
	# shellcheck disable=SC2153 # RHOOK_IFACE is a caller-supplied global input (see header comment above), not a misspelling of the local rhook_iface used by other functions in this file
	for rhook_net in $RHOOK_ROUTES; do
		rhook_plan_add "route_$rhook_net" add_route required \
			"route $rhook_net dev $RHOOK_IFACE src $RHOOK_INTERNAL_ADDR4" \
			"$RACOON_HOOK_IP route replace \"$rhook_net\" dev \"$RHOOK_IFACE\" src \"$RHOOK_INTERNAL_ADDR4\"" \
			"$RACOON_HOOK_IP route del \"$rhook_net\" dev \"$RHOOK_IFACE\" src \"$RHOOK_INTERNAL_ADDR4\""
	done

	if [ -z "$RHOOK_ROUTES" ]; then
		# R7: no hardcoded network fallback. If the gateway sent no
		# split-include networks and no internal DNS servers were
		# provided either (the other source of routes, added above),
		# there is nothing to route through the tunnel -- report that as
		# a failure (subject to the configured failure policy) instead
		# of silently guessing a fallback network that may not even be
		# reachable through this particular gateway.
		rhook_plan_add no_routes no_routes required \
			"determine networks to route through the tunnel" \
			"sh -c 'echo \"gateway sent no split-include networks and no internal DNS servers were provided either -- nothing to route through the tunnel, refusing to guess\" >&2; exit 1'" \
			""
	fi

	rhook_plan_spd

	[ -n "$RHOOK_DNS_SERVERS" ] && rhook_plan_dns
	return 0
}

rhook_plan_dns() {
	case "$RHOOK_BACKEND_RESOLVED" in
		networkmanager)
			# Already planned earlier in rhook_build_plan(), right after
			# dummy_iface/dummy_addr and before routes -- see that call
			# site's own comment for why (routes need the address
			# nm_dummy_profile assigns, and that step is atomic with
			# interface creation). Nothing to do here for this backend.
			;;
		resolved)         rhook_plan_dns_resolved ;;
		resolvconf)       rhook_plan_dns_resolvconf ;;
		dnsmasq)          rhook_plan_dns_dnsmasq ;;
		*)                rhook_plan_dns_fallback ;;
	esac
}

# §0 rule 5 hard-won detail preserved verbatim in spirit: all NM
# properties are supplied in a single `connection add` so the profile is
# fully configured *before* first activation -- modifying ipv4.dns/
# ipv4.dns-search on an already-active profile is rejected by NM's policy
# audit, which is what made earlier iterations of this hook set's
# create-then-modify dummy-device attempts race and fail.
#
# ipv4.dns-priority MUST be a small positive number, never negative:
# NetworkManager treats a negative priority as "exclusive" and drops
# every *other* active connection's DNS servers from the merged
# /etc/resolv.conf entirely -- confirmed in the field, it silently took
# out the physical uplink's own DNS server the moment this profile
# activated. 50 keeps this profile's servers/domains preferred for
# routing-domain matching without excluding anyone else's.
rhook_plan_dns_networkmanager() {
	local rhook_mode rhook_dns_csv rhook_search rhook_dom rhook_apply rhook_undo

	rhook_mode=$(rhook_nm_dns_mode_union)
	rhook_mode="${rhook_mode:-default}"
	rhook_log verbose "NetworkManager dns= mode (Mode property union --print-config): $rhook_mode"
	rhook_dns_csv=$(printf '%s' "$RHOOK_DNS_SERVERS" | tr ' ' ',')

	rhook_search=""
	if [ -n "$RHOOK_DOMAINS" ]; then
		case ",$rhook_mode," in
			*,systemd-resolved,*|*,dnsmasq,*|*,dnsconfd,*)
				# '~domain' marks a *routing* domain: only queries for
				# that domain go to this profile's servers. Without the
				# '~' it is merely a search suffix and does not
				# constrain routing at all.
				for rhook_dom in $RHOOK_DOMAINS; do
					rhook_search="${rhook_search:+$rhook_search,}~$rhook_dom"
				done
				;;
			*)
				rhook_log warn "NetworkManager DNS plugin(s) '$rhook_mode' include no per-domain routing backend; split-DNS domains cannot be isolated -- $RHOOK_DNS_SERVERS will become the resolver for ALL lookups while the tunnel is up"
				rhook_search=$(printf '%s' "$RHOOK_DOMAINS" | tr ' ' ',')
				;;
		esac
	fi

	# ipv6.method: "ignore" not "disabled". Found live on Ubuntu Bionic
	# (NetworkManager 1.10.6): `nmcli connection add ... ipv6.method
	# disabled` fails outright -- "Error: failed to modify ipv6.method:
	# 'disabled' not among [ignore, auto, dhcp, link-local, manual,
	# shared]". Confirmed against that NM version's own source
	# (libnm-core/nm-setting-ip6-config.c): NM_SETTING_IP6_CONFIG_METHOD_
	# DISABLED does not exist there at all -- it was added later. "ignore"
	# has been present since NM's oldest supported releases and is
	# documented (current source, nm-setting-ip6-config.c) as meaning
	# "IPv6 configuration is not done" -- weaker than "disabled" (which
	# additionally turns IPv6 off at the kernel level), since the dummy
	# interface may still pick up a kernel-assigned link-local address,
	# but that's harmless here: this hook never routes IPv6 traffic
	# through it, only anchors an IPv4 address for DNS/route src=.
	rhook_apply="$RACOON_HOOK_NMCLI connection delete racoon-vpn-dns >/dev/null 2>&1; $RACOON_HOOK_IP link del \"$RHOOK_DUMMY_IFACE\" >/dev/null 2>&1; $RACOON_HOOK_NMCLI connection add type dummy ifname \"$RHOOK_DUMMY_IFACE\" con-name racoon-vpn-dns autoconnect no ipv4.method manual ipv4.addresses \"$RHOOK_INTERNAL_ADDR4/32\" ipv4.dns \"$rhook_dns_csv\" ipv4.dns-search \"$rhook_search\" ipv4.dns-priority 50 ipv4.ignore-auto-dns yes ipv4.never-default yes ipv6.method ignore && $RACOON_HOOK_NMCLI connection up racoon-vpn-dns"
	rhook_undo="$RACOON_HOOK_NMCLI connection down racoon-vpn-dns >/dev/null 2>&1; $RACOON_HOOK_NMCLI connection delete racoon-vpn-dns >/dev/null 2>&1"

	rhook_plan_add nm_dns nm_dummy_profile required \
		"create NetworkManager DNS profile on $RHOOK_DUMMY_IFACE (dns=$RHOOK_DNS_SERVERS domains=$RHOOK_DOMAINS)" \
		"$rhook_apply" "$rhook_undo"
}

# §B (brief 3, F4): a DNS server registered on a link with no scoping
# applied yet becomes that link's resolver for every lookup, not just
# the split-DNS domains -- exactly the exposure that produced the F1
# reconnect loop (resolved queried a network address that only existed
# behind the tunnel, which matched a `require` SPD policy with no
# matching SA, triggering an ACQUIRE). Two independent mechanisms can
# scope a link: a routing-only domain (queries for anything else never
# go to this link's servers regardless of default-route), or
# default-route=no (this link is never chosen for a query with no
# better-matching domain). Order the plan so scoping is applied *before*
# servers are registered wherever at least one mechanism is available,
# and skip registering servers entirely when neither is -- see
# rhook_plan_dns_resolved() below for how each case is decided.
rhook_plan_dns_resolved() {
	local rhook_dom rhook_domains_arg rhook_cmd rhook_undo rhook_domains_prefixed
	local rhook_has_domains rhook_has_routing_cap rhook_can_scope rhook_default_route_crit

	rhook_domains_prefixed=""
	rhook_has_routing_cap=0
	if rhook_dns_cap "$RHOOK_DNS_TOOL" routing_domains; then
		rhook_has_routing_cap=1
		for rhook_dom in $RHOOK_DOMAINS; do
			rhook_domains_prefixed="$rhook_domains_prefixed ~$rhook_dom"
		done
	else
		rhook_domains_prefixed=" $RHOOK_DOMAINS"
	fi
	rhook_domains_arg="$rhook_domains_prefixed"

	rhook_has_domains=0
	[ -n "$RHOOK_DOMAINS" ] && rhook_has_domains=1

	# domains scope on their own (routing-only, independent of
	# default-route); absent domains, default-route=no is the only other
	# scoping mechanism, and it is confirmed absent from systemd-resolve
	# (systemd 237 and earlier -- rhook_dns_cap never reports it for that
	# tool; resolvectl only, feature-probed, see §6).
	rhook_can_scope=0
	if [ "$rhook_has_domains" -eq 1 ] && [ "$rhook_has_routing_cap" -eq 1 ]; then
		rhook_can_scope=1
	elif [ "$RHOOK_CAP_DEFAULT_ROUTE" = "yes" ]; then
		rhook_can_scope=1
	fi

	if [ "$rhook_can_scope" -eq 0 ]; then
		# §B.3: neither scoping mechanism is available -- skip DNS
		# configuration on this link entirely rather than register an
		# unscoped server. rhook_precond_resolved_no_scope() always
		# skips this step, and states the resulting exposure explicitly
		# in the reason line (the brief's "impact line" requirement) --
		# criticality is nominal here since a precondition-driven skip
		# never reaches the required/optional pass-fail distinction.
		rhook_plan_add resolved_dns resolved_no_scope optional \
			"configure DNS on $RHOOK_DUMMY_IFACE via $RHOOK_DNS_TOOL" \
			true ""
		return 0
	fi

	# §B.2: scope before servers -- domains and default-route=no (when
	# available) are planned first, DNS servers last, so there is no
	# window in which the link is both populated and default-eligible.
	if [ "$rhook_has_domains" -eq 1 ]; then
		# shellcheck disable=SC2086 # word-splitting into emitter positional args is the point
		rhook_cmd=$(rhook_dns_emit_set_domains "$RHOOK_DNS_TOOL" "$RHOOK_DUMMY_IFACE" $rhook_domains_arg)
		rhook_undo=$(rhook_dns_emit_clear_domains "$RHOOK_DNS_TOOL" "$RHOOK_DUMMY_IFACE")
		rhook_plan_add resolved_domains set_domains required \
			"set routing domain(s)$rhook_domains_arg on $RHOOK_DUMMY_IFACE" \
			"$rhook_cmd" "$rhook_undo"
		RHOOK_EXPECT_DOMAINS="$rhook_domains_arg"
		# default-route is a nice-to-have here: domains alone already
		# scope the link, so a default-route failure does not leave
		# anything unscoped and does not need to block the DNS step.
		rhook_default_route_crit="optional"
	else
		# No domains at all: default-route=no is the *only* scoping
		# mechanism reaching this point (rhook_can_scope already
		# excluded the case where neither is available), so it must
		# actually take effect before servers are registered -- required,
		# not optional, here specifically.
		rhook_default_route_crit="required"
	fi

	# Always planned, regardless of capability: rhook_precond_default_route
	# (§5) is the single place that decides to skip it when the tool
	# can't do it -- rhook_can_scope above already guarantees the
	# capability is present whenever rhook_default_route_crit is
	# "required" (that is the only way its elif branch could have set
	# rhook_can_scope=1 with no domains), so this can never plan a
	# required step the precondition will then skip.
	rhook_cmd=$(rhook_dns_emit_default_route "$RHOOK_DNS_TOOL" "$RHOOK_DUMMY_IFACE" false)
	rhook_plan_add resolved_default_route default_route "$rhook_default_route_crit" \
		"mark $RHOOK_DUMMY_IFACE as non-default-route" \
		"$rhook_cmd" ""

	RHOOK_EXPECT_DNS="$RHOOK_DNS_SERVERS"
	# shellcheck disable=SC2086
	rhook_cmd=$(rhook_dns_emit_set_dns "$RHOOK_DNS_TOOL" "$RHOOK_DUMMY_IFACE" $RHOOK_DNS_SERVERS)
	rhook_undo=$(rhook_dns_emit_clear_dns "$RHOOK_DNS_TOOL" "$RHOOK_DUMMY_IFACE")
	rhook_plan_add resolved_dns set_dns required \
		"set DNS $RHOOK_DNS_SERVERS on $RHOOK_DUMMY_IFACE ($RHOOK_DNS_TOOL)" \
		"$rhook_cmd" "$rhook_undo"
}

rhook_plan_dns_resolvconf() {
	rhook_plan_add resolvconf_dns resolvconf_record required \
		"write resolvconf record for $RHOOK_DUMMY_IFACE.racoon (classic resolvconf merges nameservers with no per-domain routing -- the VPN resolver becomes authoritative for ALL lookups while the tunnel is up, not real split-DNS)" \
		"rhook_resolvconf_record_content | \"\$RACOON_HOOK_RESOLVCONF\" -a \"$RHOOK_DUMMY_IFACE.racoon\"" \
		"\"\$RACOON_HOOK_RESOLVCONF\" -d \"$RHOOK_DUMMY_IFACE.racoon\""
}

rhook_plan_dns_dnsmasq() {
	if [ -z "$RHOOK_DOMAINS" ]; then
		# A global server= line with no domain scope would make the VPN
		# resolver authoritative for every lookup -- not split-DNS, and
		# must be reported as a failure to achieve it, never done anyway.
		rhook_plan_add dnsmasq_no_domains dnsmasq_conf required \
			"configure dnsmasq split-DNS" \
			"sh -c 'echo \"no search domains offered by the gateway -- a dnsmasq server= line with no domain scope would become the resolver for ALL lookups, refusing\" >&2; exit 1'" \
			""
		return 0
	fi
	rhook_plan_add dnsmasq_conf dnsmasq_conf required \
		"write dnsmasq split-DNS config for $RHOOK_DOMAINS" \
		"rhook_dnsmasq_conf_content > /etc/dnsmasq.d/racoon-vpn && chmod 0644 /etc/dnsmasq.d/racoon-vpn && { \"\$RACOON_HOOK_SYSTEMCTL\" reload dnsmasq >/dev/null 2>&1 || \"\$RACOON_HOOK_PKILL\" -HUP -x dnsmasq >/dev/null 2>&1 || true; }" \
		"rm -f /etc/dnsmasq.d/racoon-vpn; \"\$RACOON_HOOK_SYSTEMCTL\" reload dnsmasq >/dev/null 2>&1 || \"\$RACOON_HOOK_PKILL\" -HUP -x dnsmasq >/dev/null 2>&1 || true"
}

# No resolver manager detected at all: the only thing left to do is
# overwrite /etc/resolv.conf directly, which is a full DNS redirect (every
# lookup goes to the VPN resolver), not split-DNS, and must say so.
#
# Brief 3 §I: gated behind hooks.conf's allow_resolv_conf_overwrite,
# default "no". Falling all the way through backend detection to "write
# whatever the VPN gateway says into the one file every application on
# this system reads for name resolution" is the single most invasive
# thing this hook set can do (R1's "no persistent reconfiguration beyond
# the VPN session" already covers *reverting* it, but the overwrite
# itself -- however briefly it lasts -- is still a full redirect an
# operator may not expect from a "split-DNS" hook set landing on a
# system with no supported resolver manager at all, e.g. a minimal
# container image or an unusual distro). Refusing by default and
# requiring an explicit opt-in makes that a deliberate choice rather
# than a silent fallback nobody asked for.
rhook_plan_dns_fallback() {
	if [ "$RHOOK_ALLOW_RESOLV_CONF_OVERWRITE" != "yes" ]; then
		rhook_plan_add fallback_refused fallback_resolv required \
			"configure DNS (no supported resolver manager detected)" \
			"sh -c 'echo \"no supported resolver manager detected (not resolved, NetworkManager, resolvconf, or dnsmasq) -- the only remaining option is overwriting /etc/resolv.conf directly, a full DNS redirect for every lookup on this system, not real split-DNS. Refusing: set allow_resolv_conf_overwrite = yes in hooks.conf to explicitly accept that, or install/enable a supported resolver manager instead.\" >&2; exit 1'" \
			""
		return 0
	fi
	rhook_plan_add fallback_backup fallback_backup optional \
		"back up /etc/resolv.conf" \
		"cp /etc/resolv.conf /etc/resolv.conf.racoon.bak 2>/dev/null || true" \
		""
	rhook_plan_add fallback_dns fallback_resolv required \
		"write /etc/resolv.conf directly (no supported resolver manager detected -- full DNS redirect, not real split-DNS; allow_resolv_conf_overwrite = yes)" \
		"rhook_resolvconf_record_content > /etc/resolv.conf && chmod 0644 /etc/resolv.conf" \
		"[ -f /etc/resolv.conf.racoon.bak ] && mv -f /etc/resolv.conf.racoon.bak /etc/resolv.conf || true"
}
