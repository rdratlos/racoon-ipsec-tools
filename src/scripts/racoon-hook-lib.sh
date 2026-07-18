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
			'') ;;
			*) rhook_log warn "hooks.conf: unknown key '$rhook_k', ignoring" ;;
		esac
	done < "$RHOOK_CONF"
	case "$RHOOK_ON_DNS_FAILURE" in
		abort|warn) ;;
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
			"$RACOON_HOOK_LOGGER" -t "racoon-${RHOOK_HOOK_NAME:-hook}" -- "[$rhook_cat] $rhook_msg" 2>/dev/null || true
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
	mkdir -p "$RHOOK_STATE_DIR" 2>/dev/null
}

# --------------------------------------------------------------------------
# Connection identity.  Racoon's script hooks receive no explicit
# "connection id" -- REMOTE_ADDR/REMOTE_PORT identify the phase1 uniquely
# for a roadwarrior client (one active gateway per racoon instance in the
# supported topology), sanitized to a token safe for use in a filename.
# Recorded verbatim in the state file so phase1-down never has to
# re-derive it either.
# --------------------------------------------------------------------------
rhook_conn_id() {
	printf '%s-%s' "${REMOTE_ADDR:-unknown}" "${REMOTE_PORT:-0}" \
		| tr -c 'A-Za-z0-9._-' '_'
}

rhook_state_file() {
	printf '%s/hook-state.%s' "$RHOOK_STATE_DIR" "$(rhook_conn_id)"
}

# A pre-existing, non-empty state file when phase1-up starts means a prior
# teardown never completed (§3.4: the state file is deleted only after a
# successful teardown). phase1-up must decide what to do about that itself
# -- log and refuse, or archive and proceed -- this only reports the fact.
rhook_state_exists() {
	[ -s "$(rhook_state_file)" ]
}

rhook_state_reset() {
	rhook_ensure_state_dir
	: > "$(rhook_state_file)"
}

rhook_plan_file() {
	printf '%s/plan.%s' "$RHOOK_STATE_DIR" "$(rhook_conn_id)"
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
	RHOOK_REPORT_FILE="$RHOOK_STATE_DIR/report.$(rhook_conn_id).$$"
	: > "$RHOOK_REPORT_FILE" 2>/dev/null
}

rhook_state_append() {
	# $1 id  $2 type  $3 outcome  $4 undo_command
	printf '%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" >> "$(rhook_state_file)"
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
# the caller must stop (apply the failure policy).
# --------------------------------------------------------------------------
rhook_run_step() {
	local rhook_line rhook_id rhook_type rhook_crit rhook_desc rhook_cmd rhook_undo
	local rhook_precond_fn rhook_precond_reason rhook_out rhook_rc
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
			return 0
		fi
	fi

	rhook_log verbose "apply $rhook_id: $rhook_cmd"
	rhook_out=$(eval "$rhook_cmd" 2>&1)
	rhook_rc=$?

	if [ "$rhook_rc" -eq 0 ]; then
		rhook_report_line "[ ok        ] $rhook_desc"
		rhook_log trace "  command: $rhook_cmd"
		rhook_log trace "  output: $rhook_out"
		rhook_state_append "$rhook_id" "$rhook_type" "ok" "$rhook_undo"
		return 0
	fi

	rhook_report_line "[ FAILED    ] $rhook_desc (exit $rhook_rc)"
	rhook_log trace "  command: $rhook_cmd"
	rhook_log trace "  output: $rhook_out"
	rhook_state_append "$rhook_id" "$rhook_type" "failed" ""

	[ "$rhook_crit" = "required" ] && return 1
	return 0
}

# rhook_apply_plan: run every line of the current plan in order through
# run_step().  Stops at the first failed *required* step, marking every
# remaining step "not-attempted" in both the report and the state file.
rhook_apply_plan() {
	local rhook_stopped rhook_line rhook_id rhook_type rhook_desc
	rhook_stopped=0
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
		if ! rhook_run_step "$rhook_line"; then
			rhook_stopped=1
		fi
	done < "$(rhook_plan_file)"
	return "$rhook_stopped"
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

	rhook_ok=$(grep -c '^\[ ok' "$RHOOK_REPORT_FILE" 2>/dev/null || printf 0)
	rhook_failed=$(grep -c '^\[ FAILED' "$RHOOK_REPORT_FILE" 2>/dev/null || printf 0)
	rhook_skipped=$(grep -c '^\[ SKIPPED' "$RHOOK_REPORT_FILE" 2>/dev/null || printf 0)
	rhook_notrun=$(grep -c '^\[ not-run' "$RHOOK_REPORT_FILE" 2>/dev/null || printf 0)

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
			printf 'racoon %s report -- %s\n' "${RHOOK_HOOK_NAME:-hook}" "$rhook_ts"
			[ -n "${RHOOK_REPORT_HEADER:-}" ] && printf '%s\n' "$RHOOK_REPORT_HEADER"
			cat "$RHOOK_REPORT_FILE"
			printf '\n  %s\n' "$rhook_summary"
		} >&2
	fi
	if [ "$rhook_level" -ge 2 ] 2>/dev/null; then
		rhook_trace_write "racoon ${RHOOK_HOOK_NAME:-hook} report -- $rhook_ts"
		[ -n "${RHOOK_REPORT_HEADER:-}" ] && rhook_trace_write "$RHOOK_REPORT_HEADER"
		while IFS= read -r rhook_rline; do
			rhook_trace_write "$rhook_rline"
		done < "$RHOOK_REPORT_FILE"
		rhook_trace_write "$rhook_summary"
	fi

	"$RACOON_HOOK_LOGGER" -t "racoon-${RHOOK_HOOK_NAME:-hook}" -- "$rhook_summary" 2>/dev/null || true

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
# Rejects 0.0.0.0, loopback (127.0.0.0/8) and multicast (224.0.0.0/4) in
# addition to plain address-format validation (§4: "Reject 0.0.0.0,
# loopback, and multicast for DNS servers").
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
			0.0.0.0)
				RHOOK_VALIDATION_REASON="DNS server '$rhook_tok' is 0.0.0.0"
				return 1
				;;
			127.*)
				RHOOK_VALIDATION_REASON="DNS server '$rhook_tok' is a loopback address"
				return 1
				;;
			22[4-9].*|23[0-9].*)
				RHOOK_VALIDATION_REASON="DNS server '$rhook_tok' is a multicast address"
				return 1
				;;
		esac
	done
	printf '%s' "$rhook_list"
	return 0
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
