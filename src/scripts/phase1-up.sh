#!/bin/sh
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (C) 2024-2026 Thomas Reim and the racoon-ipsec-tools contributors
# Part of rdratlos/racoon-ipsec-tools — https://github.com/rdratlos/racoon-ipsec-tools
#
# phase1-up.sh - racoon phase1-up script hook
#
# Called by racoon after Phase 1 + Mode Config negotiation succeeds. This
# script is intentionally thin: it only (1) reads racoon's Mode Config
# environment, (2) whitelist-validates every value from it (R3: Mode
# Config is untrusted peer input), (3) hands the validated values to
# racoon-hook-lib.sh's survey -> plan -> apply -> journal machinery, and
# (4) applies the configured failure policy to its own exit status. All
# detection, planning, execution and state I/O logic lives in
# racoon-hook-lib.sh so phase1-down.sh never has to re-derive a decision
# this script already made.
#
# R2: this script never touches the SAD/SPD (no setkey, no spd.conf) --
# that is racoon's own job, configured via racoon.conf. R1: nothing here
# is a *persistent* system reconfiguration beyond the current VPN session
# (no /etc edits, no service enablement) -- see racoon-hook-lib.sh's
# per-backend plan builders for what "reconfiguration" is limited to.
#
# POSIX sh only (dash / bash / NetBSD /bin/sh); see racoon-hook-lib.sh's
# header for the shared portability rules.

PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin
export PATH

set -u

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
# shellcheck source=racoon-hook-lib.sh
. "$SCRIPT_DIR/racoon-hook-lib.sh"

RHOOK_HOOK_NAME="phase1-up"
rhook_load_config
rhook_trace_init
trap rhook_exit_trap EXIT

# --------------------------------------------------------------------------
# Guard: no Mode Config address assigned. Happens when the gateway rejects
# Mode Config entirely (no address pool, policy deny) -- there is nothing
# to configure and nothing to report as a failure, since no VPN session
# with an internal address was ever established.
# --------------------------------------------------------------------------
if [ -z "${INTERNAL_ADDR4:-}" ] || [ -z "${LOCAL_ADDR:-}" ] || [ -z "${REMOTE_ADDR:-}" ]; then
	rhook_log warn "no Mode Config address assigned (internal=${INTERNAL_ADDR4:-?}) -- nothing to do"
	exit 0
fi

rhook_log step "phase1 up: local=${LOCAL_ADDR}:${LOCAL_PORT:-?} remote=${REMOTE_ADDR}:${REMOTE_PORT:-?} internal=${INTERNAL_ADDR4}"

# --------------------------------------------------------------------------
# §3.4: a non-empty state file at this point means the previous teardown
# for this same connection id never completed (crash, kill -9, or a
# required undo step that itself failed) -- phase1-up must decide what to
# do about that itself, this is not merely informational. Refusing to
# proceed would permanently wedge a roadwarrior client that racoon keeps
# retrying against the same gateway on every reconnect; archiving the
# stale file and starting a fresh plan lets reconnection self-heal, at
# the cost of that abandoned state never being replayed. Logged loudly
# either way so the abandoned undo commands are not silently lost.
# --------------------------------------------------------------------------
if rhook_state_exists; then
	rhook_log warn "a previous teardown for this connection never completed (stale state file) -- archiving it and starting fresh: $(rhook_state_file).stale.$$"
	mv -f "$(rhook_state_file)" "$(rhook_state_file).stale.$$" 2>/dev/null || true
fi
rhook_state_reset

# --------------------------------------------------------------------------
# Outbound physical interface: the one the kernel would actually use to
# reach the gateway right now, not "the default route" (multi-homed
# hosts, or a VPN-on-VPN setup, can differ) and not anything racoon
# exports itself (it doesn't -- confirmed against isakmp.c/isakmp_cfg.c,
# neither sets an interface-name environment variable).
# --------------------------------------------------------------------------
RHOOK_IFACE=$("$RACOON_HOOK_IP" -4 route get "$REMOTE_ADDR" 2>/dev/null \
	| awk '{for (i = 1; i <= NF; i++) if ($i == "dev") { print $(i + 1); exit }}')
if [ -z "$RHOOK_IFACE" ]; then
	rhook_log error "cannot determine outbound interface for $REMOTE_ADDR -- nothing to do"
	exit 0
fi

# --------------------------------------------------------------------------
# §4 / R3: whitelist-validate every Mode Config value before it is used
# for anything. Reject-on-first-bad-element, never partially use a value
# that failed validation.
#
# Delimiter note (verified against this tree's own src/racoon C source,
# not guessed): isakmp_cfg_iplist_to_str() and splitnet_list_2str() both
# join their output with a plain space (isakmp_cfg.c / isakmp_unity.c),
# so INTERNAL_DNS4_LIST and SPLIT_INCLUDE_CIDR/SPLIT_INCLUDE are
# space-separated. INTERNAL_SPLITDNS_DOMAINS, in contrast, is the raw
# UNITY_SPLITDNS_NAME attribute payload copied verbatim from the peer
# with no reformatting (isakmp_unity.c: a straight memcpy) -- the Cisco
# Unity extension this attribute comes from defines it as a
# comma-separated domain list, matching the legacy phase1-up.sh's own
# `tr ',' ' '` treatment of it. DEFAULT_DOMAIN is a single domain, not a
# list, so it has no delimiter to convert.
# --------------------------------------------------------------------------
if ! rhook_valid_ipv4 "$INTERNAL_ADDR4"; then
	rhook_log error "gateway sent an invalid Mode Config internal address '$INTERNAL_ADDR4' -- refusing to configure anything"
	exit 0
fi
RHOOK_INTERNAL_ADDR4="$INTERNAL_ADDR4"

RHOOK_VALIDATE_TMP=$(mktemp "${TMPDIR:-/tmp}/racoon-phase1-up.XXXXXX") || {
	rhook_log error "cannot create a temporary file for input validation -- refusing to configure anything"
	exit 0
}

RHOOK_SPLIT_INCLUDE_RAW="${SPLIT_INCLUDE_CIDR:-${SPLIT_INCLUDE:-}}"
if [ -n "$RHOOK_SPLIT_INCLUDE_RAW" ]; then
	if rhook_validate_cidr_list "$RHOOK_SPLIT_INCLUDE_RAW" > "$RHOOK_VALIDATE_TMP"; then
		RHOOK_ROUTES=$(cat "$RHOOK_VALIDATE_TMP")
	else
		rhook_log error "gateway sent an invalid split-include network list ('$RHOOK_SPLIT_INCLUDE_RAW'): $RHOOK_VALIDATION_REASON -- ignoring split-include entirely"
		RHOOK_ROUTES=""
	fi
else
	RHOOK_ROUTES=""
fi

RHOOK_DNS_RAW="${INTERNAL_DNS4_LIST:-${INTERNAL_DNS4:-}}"
if [ -n "$RHOOK_DNS_RAW" ]; then
	if rhook_validate_dns_list "$RHOOK_DNS_RAW" > "$RHOOK_VALIDATE_TMP"; then
		RHOOK_DNS_SERVERS=$(cat "$RHOOK_VALIDATE_TMP")
	else
		rhook_log error "gateway sent an invalid DNS server list ('$RHOOK_DNS_RAW'): $RHOOK_VALIDATION_REASON -- skipping DNS setup"
		RHOOK_DNS_SERVERS=""
	fi
else
	RHOOK_DNS_SERVERS=""
fi

RHOOK_DOMAINS_RAW="${INTERNAL_SPLITDNS_DOMAINS:-}"
if [ -z "$RHOOK_DOMAINS_RAW" ] && [ -n "${DEFAULT_DOMAIN:-}" ]; then
	RHOOK_DOMAINS_RAW="$DEFAULT_DOMAIN"
fi
# comma -> space (see the delimiter note above); DEFAULT_DOMAIN alone has
# no commas to convert, so this is a no-op in that fallback case.
RHOOK_DOMAINS_RAW=$(printf '%s' "$RHOOK_DOMAINS_RAW" | tr ',' ' ')
if [ -n "$RHOOK_DOMAINS_RAW" ]; then
	if rhook_validate_domain_list "$RHOOK_DOMAINS_RAW" > "$RHOOK_VALIDATE_TMP"; then
		RHOOK_DOMAINS=$(cat "$RHOOK_VALIDATE_TMP")
	else
		rhook_log error "gateway sent an invalid split-DNS domain list ('$RHOOK_DOMAINS_RAW'): $RHOOK_VALIDATION_REASON -- skipping split-DNS domains"
		RHOOK_DOMAINS=""
	fi
else
	RHOOK_DOMAINS=""
fi
rm -f "$RHOOK_VALIDATE_TMP"

# --------------------------------------------------------------------------
# Internal DNS servers must always be reachable over the tunnel, even if
# the gateway's split-include list doesn't happen to cover the resolver's
# subnet (e.g. DNS lives on a management segment kept out of the general
# split-tunnel ACL) -- add a /32 host route for each one, on top of
# whatever split-include already covers, deduplicated. This is additive
# only: it can turn an empty RHOOK_ROUTES non-empty, but never removes
# the R7 "no routes at all" case below when both sources are empty.
# --------------------------------------------------------------------------
for rhook_p1u_dns in $RHOOK_DNS_SERVERS; do
	case " $RHOOK_ROUTES " in
		*" ${rhook_p1u_dns}/32 "*) ;;
		*) RHOOK_ROUTES="${RHOOK_ROUTES:+$RHOOK_ROUTES }${rhook_p1u_dns}/32" ;;
	esac
done

# --------------------------------------------------------------------------
# Build, apply and report (§3.2/§3.3/§5.3). rhook_build_plan() is pure
# construction; rhook_apply_plan() is the only place anything on the
# system actually changes, and it journals each successful step's undo
# command to the state file as it goes (§3.4), so phase1-down.sh never
# has to re-derive what phase1-up.sh actually did versus merely planned.
# --------------------------------------------------------------------------
rhook_build_plan
RHOOK_REPORT_HEADER="backend=$RHOOK_BACKEND_RESOLVED dns_tool=${RHOOK_DNS_TOOL:-none} iface=$RHOOK_IFACE internal=$RHOOK_INTERNAL_ADDR4 routes=${RHOOK_ROUTES:-none} dns=${RHOOK_DNS_SERVERS:-none} domains=${RHOOK_DOMAINS:-none}"
rhook_report_init

rhook_apply_plan
RHOOK_P1U_APPLY_RC=$?

# The configured failure policy (hooks.conf on_dns_failure, R7's "report +
# apply failure policy") governs this script's own exit status only --
# racoon does not tear down an established Phase 1 SA based on a hook's
# exit code, so "abort" here means "make the failure visible to whatever
# is watching this process' exit status" (init supervisor, monitoring),
# not "reject the tunnel". "warn" (the default) always exits 0: routes or
# DNS steps that did apply stay in effect even if a later, non-fatal step
# in the same plan failed.
if [ "$RHOOK_P1U_APPLY_RC" -ne 0 ] && [ "$RHOOK_ON_DNS_FAILURE" = "abort" ]; then
	exit 1
fi
exit 0
