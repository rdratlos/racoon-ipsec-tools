#!/bin/sh
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (C) 2024-2026 Thomas Reim and the racoon-ipsec-tools contributors
#
# test-plan-builder.sh - regression tests for the §3.2 plan builder
# (rhook_build_plan / rhook_plan_dns_*): exact step sequence, criticality,
# and command/undo strings per backend, plus the precondition/postcondition
# functions that gate them. Locks the two bugs already found in this
# codebase in place: ipv4.dns-priority must be a small POSITIVE number
# (never negative -- NM treats negative as "exclusive" and drops every
# other connection's DNS), and DNS-clearing paths must never use "~.".
# Run directly: sh tests/hooks/test-plan-builder.sh

set -u

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
LIB="$SCRIPT_DIR/../../src/racoon/scripts/racoon-hook-lib.sh"

TESTS_RUN=0
TESTS_FAILED=0

fail() { TESTS_FAILED=$((TESTS_FAILED + 1)); echo "FAIL: $1"; }

assert_eq() {
	TESTS_RUN=$((TESTS_RUN + 1))
	if [ "$2" = "$3" ]; then :; else fail "$1 -- expected '$3', got '$2'"; fi
}

assert_contains() {
	# $1 = description  $2 = haystack  $3 = needle (fixed string)
	TESTS_RUN=$((TESTS_RUN + 1))
	case "$2" in
		*"$3"*) ;;
		*) fail "$1 -- '$3' not found in '$2'" ;;
	esac
}

assert_not_contains() {
	TESTS_RUN=$((TESTS_RUN + 1))
	case "$2" in
		*"$3"*) fail "$1 -- '$3' unexpectedly found in '$2'" ;;
		*) ;;
	esac
}

# Extracts field $2 (1-based, per rhook_plan_add's id/type/crit/desc/cmd/undo
# order) of the plan line whose id is $1, from the plan file at $3.
plan_field() {
	awk -F'\t' -v id="$1" -v f="$2" '$1 == id { print $f }' "$3"
}

WORK=$(mktemp -d "${TMPDIR:-/tmp}/racoon-hook-plan.XXXXXX")
trap 'rm -rf "$WORK"' EXIT

mkdir -p "$WORK/bin"
RACOON_HOOK_STATE_DIR="$WORK/run"
RACOON_HOOK_CONF="$WORK/nonexistent-hooks.conf"
export RACOON_HOOK_STATE_DIR RACOON_HOOK_CONF

# shellcheck source=SCRIPTDIR/../../src/racoon/scripts/racoon-hook-lib.sh
# shellcheck disable=SC2034  # REMOTE_ADDR/REMOTE_PORT/RHOOK_* below are read by the sourced library, not this file
. "$LIB"

LOCAL_ADDR="198.51.100.5"
LOCAL_PORT="4500"
REMOTE_ADDR="203.0.113.7"
REMOTE_PORT="500"
RHOOK_IFACE="eth0"
RHOOK_INTERNAL_ADDR4="10.0.12.44"
RHOOK_ROUTES="10.0.12.0/24 192.168.66.0/24"
RHOOK_DNS_SERVERS="10.0.12.53 10.0.12.54"
RHOOK_DOMAINS="corp.example.com internal.example.com"

# ==========================================================================
# Common steps (dummy interface / address / routes) -- shared by every
# backend except networkmanager, which folds them into its own profile.
#
# Brief 3 §K: dummy_iface's own undo command now branches on whether
# NetworkManager is active (rhook_survey_nm_active(), a plain `systemctl
# is-active` state read) -- pinned to an explicit "inactive" stub here
# rather than relying on whatever this test happens to run under, so
# this assertion is hermetic regardless of the host's own systemd/NM
# state. The NM-active branch is exercised separately below.
# ==========================================================================
RHOOK_BACKEND="resolvconf"
RACOON_HOOK_RESOLVCONF="$WORK/bin/resolvconf-absent"
RACOON_HOOK_SYSTEMCTL="$WORK/bin/systemctl-nm-inactive"
cat > "$RACOON_HOOK_SYSTEMCTL" <<'EOF'
#!/bin/sh
exit 3
EOF
chmod +x "$RACOON_HOOK_SYSTEMCTL"
rhook_build_plan
PLAN="$(rhook_plan_file)"

assert_eq "dummy_iface: criticality" "$(plan_field dummy_iface 3 "$PLAN")" "required"
assert_eq "dummy_iface: command" "$(plan_field dummy_iface 5 "$PLAN")" \
	'rhook_ensure_dummy_iface "racoon0"'
assert_eq "dummy_iface: undo (NetworkManager inactive -- plain iproute owner)" "$(plan_field dummy_iface 6 "$PLAN")" \
	'ip link del "racoon0"'
assert_eq "RHOOK_DUMMY_OWNER reflects iproute when NetworkManager is inactive" "$RHOOK_DUMMY_OWNER" "iproute"

# NetworkManager active, but *not* the DNS backend (e.g. it manages the
# physical interfaces while systemd-resolved handles DNS directly) --
# the dummy_iface undo must try NM's own device-removal path first, and
# fall back to a plain `ip link del` only if that fails, so the
# interface is never leaked even if NM turns out not to have actually
# claimed it.
RACOON_HOOK_SYSTEMCTL="$WORK/bin/systemctl-nm-active"
cat > "$RACOON_HOOK_SYSTEMCTL" <<'EOF'
#!/bin/sh
[ "$1" = "is-active" ] && [ "$3" = "NetworkManager" ] && exit 0
exit 3
EOF
chmod +x "$RACOON_HOOK_SYSTEMCTL"
rhook_build_plan
PLAN="$(rhook_plan_file)"
assert_eq "RHOOK_DUMMY_OWNER reflects nm when NetworkManager is active" "$RHOOK_DUMMY_OWNER" "nm"
assert_eq "dummy_iface: undo (NetworkManager active -- nmcli first, ip link del fallback)" \
	"$(plan_field dummy_iface 6 "$PLAN")" \
	'nmcli device delete "racoon0" >/dev/null 2>&1 || ip link del "racoon0"'
assert_eq "dummy_iface: apply command is unaffected by the owner branch" \
	"$(plan_field dummy_iface 5 "$PLAN")" \
	'rhook_ensure_dummy_iface "racoon0"'

RACOON_HOOK_SYSTEMCTL="$WORK/bin/systemctl-nm-inactive"
cat > "$RACOON_HOOK_SYSTEMCTL" <<'EOF'
#!/bin/sh
exit 3
EOF
chmod +x "$RACOON_HOOK_SYSTEMCTL"

assert_eq "dummy_addr: command" "$(plan_field dummy_addr 5 "$PLAN")" \
	'ip addr replace "10.0.12.44/32" dev "racoon0"'
assert_eq "dummy_addr: undo" "$(plan_field dummy_addr 6 "$PLAN")" \
	'ip addr del "10.0.12.44/32" dev "racoon0"'

# R5: routes stay on the physical interface, src= comes from the dummy addr.
assert_eq "route step: command uses physical iface + dummy-anchored src" \
	"$(plan_field 'route_10.0.12.0/24' 5 "$PLAN")" \
	'ip route replace "10.0.12.0/24" dev "eth0" src "10.0.12.44"'
assert_eq "route step: undo" \
	"$(plan_field 'route_10.0.12.0/24' 6 "$PLAN")" \
	'ip route del "10.0.12.0/24" dev "eth0" src "10.0.12.44"'
assert_eq "second route step also present" \
	"$(plan_field 'route_192.168.66.0/24' 3 "$PLAN")" "required"

# --------------------------------------------------------------------------
# Brief 3 §E: one required in/out spd_entry pair per RHOOK_ROUTES entry,
# ports included (both LOCAL_PORT and REMOTE_PORT set above) per
# src/libipsec/policy_parse.y's confirmed bracket-port grammar.
# --------------------------------------------------------------------------
assert_eq "spd_out: criticality" "$(plan_field 'spd_out_10.0.12.0/24' 3 "$PLAN")" "required"
assert_eq "spd_out: command" "$(plan_field 'spd_out_10.0.12.0/24' 5 "$PLAN")" \
	"printf '%s\n' 'spdadd 10.0.12.44/32 10.0.12.0/24 any -P out ipsec esp/tunnel/198.51.100.5[4500]-203.0.113.7[500]/require;' | setkey -c"
assert_eq "spd_out: undo is the exact reconstructed spddelete" \
	"$(plan_field 'spd_out_10.0.12.0/24' 6 "$PLAN")" \
	"printf '%s\n' 'spddelete 10.0.12.44/32 10.0.12.0/24 any -P out;' | setkey -c"
assert_eq "spd_in: criticality" "$(plan_field 'spd_in_10.0.12.0/24' 3 "$PLAN")" "required"
assert_eq "spd_in: command uses the reversed endpoint pair" \
	"$(plan_field 'spd_in_10.0.12.0/24' 5 "$PLAN")" \
	"printf '%s\n' 'spdadd 10.0.12.0/24 10.0.12.44/32 any -P in ipsec esp/tunnel/203.0.113.7[500]-198.51.100.5[4500]/require;' | setkey -c"
assert_eq "spd_in: undo is the exact reconstructed spddelete" \
	"$(plan_field 'spd_in_10.0.12.0/24' 6 "$PLAN")" \
	"printf '%s\n' 'spddelete 10.0.12.0/24 10.0.12.44/32 any -P in;' | setkey -c"
assert_eq "second route's spd_out pair also present" \
	"$(plan_field 'spd_out_192.168.66.0/24' 3 "$PLAN")" "required"

# Endpoint helper directly: bare address-address form when ports are unknown
# (rhook_spd_tunnel_endpoints() treats this as a normal case, not degraded).
assert_eq "tunnel endpoints: bracket-port form when both ports known" \
	"$(rhook_spd_tunnel_endpoints "198.51.100.5" "4500" "203.0.113.7" "500")" \
	"esp/tunnel/198.51.100.5[4500]-203.0.113.7[500]/require"
assert_eq "tunnel endpoints: bare form when a port is missing" \
	"$(rhook_spd_tunnel_endpoints "198.51.100.5" "" "203.0.113.7" "500")" \
	"esp/tunnel/198.51.100.5-203.0.113.7/require"

# spd_entry is not part of the DNS rollback group (persists across a DNS
# failure, like routes -- see rhook_is_dns_group()'s own header comment).
TESTS_RUN=$((TESTS_RUN + 1))
if rhook_is_dns_group spd_entry; then
	fail "spd_entry must not be classified as a DNS-group step type"
fi

# rhook_precond_create_dummy: not skipped for a non-networkmanager backend.
TESTS_RUN=$((TESTS_RUN + 1))
reason=$(rhook_precond_create_dummy)
[ -z "$reason" ] || fail "create_dummy precondition should be empty (not skipped) for backend=resolvconf, got '$reason'"

# ==========================================================================
# networkmanager backend: dummy iface/addr folded into a single `nmcli
# connection add`; must never appear as separate dummy_iface/dummy_addr
# steps (that ordering is exactly what raced against NM's policy audit in
# earlier iterations of this hook set).
# ==========================================================================
RHOOK_BACKEND="networkmanager"
RACOON_HOOK_NETWORKMANAGER="$WORK/bin/nm-print-config"
cat > "$RACOON_HOOK_NETWORKMANAGER" <<'EOF'
#!/bin/sh
[ "$1" = "--print-config" ] && printf '[main]\ndns=default,systemd-resolved\n'
EOF
chmod +x "$RACOON_HOOK_NETWORKMANAGER"
RACOON_HOOK_BUSCTL="$WORK/bin/busctl-inactive"
cat > "$RACOON_HOOK_BUSCTL" <<'EOF'
#!/bin/sh
exit 1
EOF
chmod +x "$RACOON_HOOK_BUSCTL"
RACOON_HOOK_SYSTEMCTL="$WORK/bin/systemctl-nm-inactive"
cat > "$RACOON_HOOK_SYSTEMCTL" <<'EOF'
#!/bin/sh
exit 3
EOF
chmod +x "$RACOON_HOOK_SYSTEMCTL"

rhook_build_plan
PLAN="$(rhook_plan_file)"

# dummy_iface/dummy_addr are still *planned* (single declarative plan, one
# execution point) but must be *skipped at apply time* by their shared
# precondition -- nmcli's own `connection add` creates the interface and
# address as part of the profile, and creating it separately first would
# be exactly the "modify an already-active profile" race that failed in
# earlier iterations of this hook set.
assert_eq "dummy_iface step is still planned (precondition gates it, not the plan)" \
	"$(plan_field dummy_iface 3 "$PLAN")" "required"

# Found live (Ubuntu Bionic and Arch/Manjaro roadwarriors, both with
# NetworkManager active): `ip route ... src $RHOOK_INTERNAL_ADDR4` requires
# that address to already be assigned locally -- confirmed against the
# kernel directly (RTM_NEWROUTE's own prefsrc validation), not merely
# assumed. nm_dns (nm_dummy_profile) is the *only* step that assigns it
# for this backend (dummy_iface/dummy_addr are precondition-skipped), so
# it must appear in the plan file *before* every route_* step, not after
# SPD/DNS as originally implemented -- that ordering bug failed outright
# on both real hosts tested, regardless of DNS tool (systemd-resolve on
# Bionic, resolvectl on Arch).
nm_dns_lineno=$(grep -n '^nm_dns	' "$PLAN" | cut -d: -f1)
TESTS_RUN=$((TESTS_RUN + 1))
if [ -z "$nm_dns_lineno" ]; then
	fail "nm_dns step must be present in the plan"
fi
for rhook_route_id in 'route_10.0.12.0/24' 'route_192.168.66.0/24'; do
	rhook_route_lineno=$(grep -n "^${rhook_route_id}	" "$PLAN" | cut -d: -f1)
	TESTS_RUN=$((TESTS_RUN + 1))
	if [ -z "$rhook_route_lineno" ] || [ -z "$nm_dns_lineno" ] || [ "$nm_dns_lineno" -ge "$rhook_route_lineno" ]; then
		fail "nm_dns (line $nm_dns_lineno) must be planned before $rhook_route_id (line $rhook_route_lineno) -- routes need the address nm_dns assigns"
	fi
done

nm_cmd=$(plan_field nm_dns 5 "$PLAN")
assert_contains "nm profile: dns-priority is 50 (small positive), not negative" "$nm_cmd" "ipv4.dns-priority 50"
assert_not_contains "nm profile: never a negative dns-priority" "$nm_cmd" "dns-priority -"
assert_contains "nm profile: dns csv" "$nm_cmd" 'ipv4.dns "10.0.12.53,10.0.12.54"'
assert_contains "nm profile: routing-only domains (~) since dns= includes systemd-resolved" \
	"$nm_cmd" 'ipv4.dns-search "~corp.example.com,~internal.example.com"'
assert_contains "nm profile: never-default so the physical uplink stays the default route" \
	"$nm_cmd" "ipv4.never-default yes"
assert_contains "nm profile: single connection add call (fully configured before first activation)" \
	"$nm_cmd" "connection add type dummy"
nm_undo=$(plan_field nm_dns 6 "$PLAN")
assert_contains "nm profile undo: tears down the profile" "$nm_undo" "connection delete racoon-vpn-dns"

# rhook_precond_create_dummy: skipped for networkmanager (it makes its own).
TESTS_RUN=$((TESTS_RUN + 1))
reason=$(rhook_precond_create_dummy)
[ -n "$reason" ] || fail "create_dummy precondition should report a skip reason for backend=networkmanager"

# NM plugin list with no per-domain routing backend (e.g. plain "default"):
# search domains must NOT get the '~' routing prefix, and a warning must be
# logged explaining split-DNS cannot be isolated.
cat > "$RACOON_HOOK_NETWORKMANAGER" <<'EOF'
#!/bin/sh
[ "$1" = "--print-config" ] && printf '[main]\ndns=default\n'
EOF
RHOOK_DEBUG_LEVEL=2
rhook_trace_init
rhook_build_plan 2>"$WORK/nm-warn.log"
PLAN="$(rhook_plan_file)"
nm_cmd=$(plan_field nm_dns 5 "$PLAN")
assert_not_contains "nm profile: no ~ prefix when dns= has no per-domain backend" "$nm_cmd" "~corp.example.com"
assert_contains "nm profile: plain domains still passed as search suffixes" "$nm_cmd" 'ipv4.dns-search "corp.example.com,internal.example.com"'
TESTS_RUN=$((TESTS_RUN + 1))
if grep -qi "split-DNS domains cannot be isolated" "$RHOOK_TRACE_FILE" 2>/dev/null || grep -qi "split-DNS domains cannot be isolated" "$WORK/nm-warn.log" 2>/dev/null; then
	:
else
	fail "no-routing-backend case must warn that split-DNS domains cannot be isolated"
fi
RHOOK_DEBUG_LEVEL=0

# ==========================================================================
# systemd-resolved backend: exact resolvectl grammar, routing-domain
# prefixing, and the optional default-route step.
# ==========================================================================
RHOOK_BACKEND="resolved"
mkdir -p "$WORK/bin/resolved-cap"
cat > "$WORK/bin/resolved-cap/resolvectl" <<'EOF'
#!/bin/sh
[ "$1" = "--help" ] && { echo "resolvectl [OPTIONS...] COMMAND ..."; echo "  default-route LINK BOOL   Configure default-route feature"; exit 0; }
exit 0
EOF
chmod +x "$WORK/bin/resolved-cap/resolvectl"
RACOON_HOOK_RESOLVECTL="$WORK/bin/resolved-cap/resolvectl"
PATH="$WORK/bin/resolved-cap:$PATH"

rhook_build_plan
PLAN="$(rhook_plan_file)"

assert_eq "resolved_dns: command" "$(plan_field resolved_dns 5 "$PLAN")" \
	"$RACOON_HOOK_RESOLVECTL dns racoon0 10.0.12.53 10.0.12.54"
assert_eq "resolved_dns: undo uses empty string (never ~.)" "$(plan_field resolved_dns 6 "$PLAN")" \
	"$RACOON_HOOK_RESOLVECTL dns racoon0 \"\""
assert_eq "resolved_domains: command uses ~ routing prefix" "$(plan_field resolved_domains 5 "$PLAN")" \
	"$RACOON_HOOK_RESOLVECTL domain racoon0 ~corp.example.com ~internal.example.com"
assert_eq "resolved_domains: undo clears with empty string" "$(plan_field resolved_domains 6 "$PLAN")" \
	"$RACOON_HOOK_RESOLVECTL domain racoon0 \"\""
assert_eq "resolved_default_route: criticality is optional (domains already scope the link)" "$(plan_field resolved_default_route 3 "$PLAN")" "optional"
assert_eq "resolved_default_route: command" "$(plan_field resolved_default_route 5 "$PLAN")" \
	"$RACOON_HOOK_RESOLVECTL default-route racoon0 false"

# §B.2: scope before servers -- the domains step must appear before the
# dns (servers) step in the plan file's line order, not merely be present
# somewhere in it.
domains_lineno=$(grep -n '^resolved_domains	' "$PLAN" | cut -d: -f1)
dns_lineno=$(grep -n '^resolved_dns	' "$PLAN" | cut -d: -f1)
TESTS_RUN=$((TESTS_RUN + 1))
if [ -z "$domains_lineno" ] || [ -z "$dns_lineno" ] || [ "$domains_lineno" -ge "$dns_lineno" ]; then
	fail "resolved_domains (line $domains_lineno) must be planned before resolved_dns (line $dns_lineno)"
fi

# rhook_precond_default_route: no warning when the tool is capable.
TESTS_RUN=$((TESTS_RUN + 1))
reason=$(rhook_precond_default_route)
[ -z "$reason" ] || fail "default_route precondition should be silent when RHOOK_CAP_DEFAULT_ROUTE=yes, got '$reason'"

# Same backend, a systemd-resolve-only system (Bionic-style, no
# default-route capability): the step must still be planned (single
# execution point, precondition decides skip at apply time -- not omitted
# from the plan), but its precondition must report the capability gap.
RACOON_HOOK_RESOLVECTL="$WORK/bin/resolvectl-absent"
RACOON_HOOK_SYSTEMD_RESOLVE="$WORK/bin/systemd-resolve-present"
cat > "$RACOON_HOOK_SYSTEMD_RESOLVE" <<'EOF'
#!/bin/sh
exit 0
EOF
chmod +x "$RACOON_HOOK_SYSTEMD_RESOLVE"
PATH="$WORK/bin:$PATH"
rhook_build_plan
PLAN="$(rhook_plan_file)"
assert_eq "systemd-resolve: resolved_dns command uses --set-dns grammar" \
	"$(plan_field resolved_dns 5 "$PLAN")" \
	"$RACOON_HOOK_SYSTEMD_RESOLVE --interface=racoon0 --set-dns=10.0.12.53 --interface=racoon0 --set-dns=10.0.12.54"
# --set-dns=""/--set-domain="" are not valid systemd-resolve syntax
# (confirmed against systemd v237's own resolve-tool.c -- found live,
# erroring on a real Bionic host); --revert is the correct undo for
# this tool, confirmed idempotent against resolved's own server-side
# bus_link_method_revert().
assert_eq "systemd-resolve: resolved_dns undo uses --revert, not the invalid --set-dns=\"\"" \
	"$(plan_field resolved_dns 6 "$PLAN")" \
	"$RACOON_HOOK_SYSTEMD_RESOLVE --interface=racoon0 --revert"
assert_eq "systemd-resolve: resolved_domains undo uses --revert, not the invalid --set-domain=\"\"" \
	"$(plan_field resolved_domains 6 "$PLAN")" \
	"$RACOON_HOOK_SYSTEMD_RESOLVE --interface=racoon0 --revert"
TESTS_RUN=$((TESTS_RUN + 1))
reason=$(rhook_precond_default_route)
case "$reason" in
	*"no default-route capability"*) ;;
	*) fail "default_route precondition must explain the capability gap for systemd-resolve, got '$reason'" ;;
esac
RACOON_HOOK_RESOLVECTL="$WORK/bin/resolved-cap/resolvectl"

# rhook_postcond_set_dns: reports no reason when the expected server is
# visible via `resolvectl status`; reports a reason when it is not.
mkdir -p "$WORK/bin/status-ok"
cat > "$WORK/bin/status-ok/resolvectl" <<'EOF'
#!/bin/sh
[ "$1" = "status" ] && { echo "Link 4 (racoon0)"; echo "  DNS Servers: 10.0.12.53 10.0.12.54"; exit 0; }
exit 0
EOF
chmod +x "$WORK/bin/status-ok/resolvectl"
RACOON_HOOK_RESOLVECTL="$WORK/bin/status-ok/resolvectl"
RHOOK_BACKEND_RESOLVED="resolved"
RHOOK_DNS_TOOL="resolvectl"
RHOOK_EXPECT_DNS="10.0.12.53 10.0.12.54"
TESTS_RUN=$((TESTS_RUN + 1))
reason=$(rhook_postcond_set_dns)
[ -z "$reason" ] || fail "postcond_set_dns should be silent when resolvectl status lists the expected server, got '$reason'"

mkdir -p "$WORK/bin/status-empty"
cat > "$WORK/bin/status-empty/resolvectl" <<'EOF'
#!/bin/sh
[ "$1" = "status" ] && { echo "Link 4 (racoon0)"; echo "  DNS Servers: (none)"; exit 0; }
exit 0
EOF
chmod +x "$WORK/bin/status-empty/resolvectl"
RACOON_HOOK_RESOLVECTL="$WORK/bin/status-empty/resolvectl"
TESTS_RUN=$((TESTS_RUN + 1))
reason=$(rhook_postcond_set_dns)
[ -n "$reason" ] || fail "postcond_set_dns must report a reason when the expected server is absent from resolvectl status"

# rhook_postcond_set_domains: same shape, for the domains step.
RACOON_HOOK_RESOLVECTL="$WORK/bin/status-ok/resolvectl"
RHOOK_EXPECT_DOMAINS="~corp.example.com"
mkdir -p "$WORK/bin/status-with-domain"
cat > "$WORK/bin/status-with-domain/resolvectl" <<'EOF'
#!/bin/sh
[ "$1" = "status" ] && { echo "Link 4 (racoon0)"; echo "   DNS Domain: ~corp.example.com"; exit 0; }
exit 0
EOF
chmod +x "$WORK/bin/status-with-domain/resolvectl"
RACOON_HOOK_RESOLVECTL="$WORK/bin/status-with-domain/resolvectl"
TESTS_RUN=$((TESTS_RUN + 1))
reason=$(rhook_postcond_set_domains)
[ -z "$reason" ] || fail "postcond_set_domains should be silent when the domain is visible in status (tilde form), got '$reason'"
RACOON_HOOK_RESOLVECTL="$WORK/bin/status-empty/resolvectl"
TESTS_RUN=$((TESTS_RUN + 1))
reason=$(rhook_postcond_set_domains)
[ -n "$reason" ] || fail "postcond_set_domains must report a reason when the domain is absent from resolvectl status"
RACOON_HOOK_RESOLVECTL="$WORK/bin/resolved-cap/resolvectl"

# ==========================================================================
# §B.2/§B.3: scope-before-servers ordering and the no-scoping-available
# skip, both without any split-DNS domains from the gateway (the only
# way default-route=no becomes the sole scoping mechanism).
# ==========================================================================
RHOOK_DOMAINS_SAVE_B="$RHOOK_DOMAINS"
RHOOK_DOMAINS=""

# No domains, resolvectl (default-route capable): default_route becomes
# required (it is now the only thing that can scope this link), and is
# still planned before the dns step.
RACOON_HOOK_RESOLVECTL="$WORK/bin/resolved-cap/resolvectl"
rhook_build_plan
PLAN="$(rhook_plan_file)"
assert_eq "no domains, default-route capable: default_route criticality is required" \
	"$(plan_field resolved_default_route 3 "$PLAN")" "required"
default_route_lineno=$(grep -n '^resolved_default_route	' "$PLAN" | cut -d: -f1)
dns_lineno=$(grep -n '^resolved_dns	' "$PLAN" | cut -d: -f1)
TESTS_RUN=$((TESTS_RUN + 1))
if [ -z "$default_route_lineno" ] || [ -z "$dns_lineno" ] || [ "$default_route_lineno" -ge "$dns_lineno" ]; then
	fail "resolved_default_route (line $default_route_lineno) must be planned before resolved_dns (line $dns_lineno) when it is the sole scoping mechanism"
fi
TESTS_RUN=$((TESTS_RUN + 1))
if grep -q '^resolved_dns	resolved_no_scope	' "$PLAN"; then
	fail "resolved_dns must not be the unscopable-skip step when default-route capability is available"
fi

# No domains, systemd-resolve (no default-route capability at all):
# neither scoping mechanism is available -- skip DNS configuration
# entirely rather than register an unscoped server.
RACOON_HOOK_RESOLVECTL="$WORK/bin/resolvectl-absent"
RACOON_HOOK_SYSTEMD_RESOLVE="$WORK/bin/systemd-resolve-present"
rhook_build_plan
PLAN="$(rhook_plan_file)"
assert_eq "no domains, no default-route cap: resolved_dns becomes the no-scope skip step" \
	"$(plan_field resolved_dns 2 "$PLAN")" "resolved_no_scope"
TESTS_RUN=$((TESTS_RUN + 1))
if grep -qE '^resolved_(domains|default_route)	' "$PLAN"; then
	fail "no domains step or default_route step should be planned when DNS configuration is skipped entirely"
fi
TESTS_RUN=$((TESTS_RUN + 1))
reason=$(rhook_precond_resolved_no_scope)
case "$reason" in
	*"no split-DNS domains"*"no default-route capability"*"resolver for ALL lookups"*) ;;
	*) fail "resolved_no_scope precondition must state the exposure explicitly (brief 3 'impact line'), got '$reason'" ;;
esac

RACOON_HOOK_RESOLVECTL="$WORK/bin/resolved-cap/resolvectl"
RHOOK_DOMAINS="$RHOOK_DOMAINS_SAVE_B"

# ==========================================================================
# resolvconf backend
# ==========================================================================
RHOOK_BACKEND="resolvconf"
RACOON_HOOK_RESOLVCONF="resolvconf"
rhook_build_plan
PLAN="$(rhook_plan_file)"
resolvconf_cmd=$(plan_field resolvconf_dns 5 "$PLAN")
# shellcheck disable=SC2016  # asserting the literal, unexpanded $RACOON_HOOK_RESOLVCONF text the plan stores -- it is deliberately expanded later, at apply time via eval, not at plan-build time
assert_contains "resolvconf: apply pipes generated content into resolvconf -a" "$resolvconf_cmd" '"$RACOON_HOOK_RESOLVCONF" -a "racoon0.racoon"'
resolvconf_undo=$(plan_field resolvconf_dns 6 "$PLAN")
# shellcheck disable=SC2016
assert_contains "resolvconf: undo calls resolvconf -d" "$resolvconf_undo" '"$RACOON_HOOK_RESOLVCONF" -d "racoon0.racoon"'

content=$(rhook_resolvconf_record_content)
assert_contains "resolvconf content: search line" "$content" "search corp.example.com internal.example.com"
assert_contains "resolvconf content: nameserver lines" "$content" "nameserver 10.0.12.53"

# ==========================================================================
# dnsmasq backend
# ==========================================================================
RHOOK_BACKEND="dnsmasq"
rhook_build_plan
PLAN="$(rhook_plan_file)"
dnsmasq_cmd=$(plan_field dnsmasq_conf 5 "$PLAN")
assert_contains "dnsmasq: writes to /etc/dnsmasq.d/racoon-vpn with 0644" "$dnsmasq_cmd" "chmod 0644 /etc/dnsmasq.d/racoon-vpn"
# shellcheck disable=SC2016  # asserting the literal, unexpanded $RACOON_HOOK_PKILL text (expanded at apply time via eval, not here)
assert_contains "dnsmasq: NetBSD-safe reload uses pkill -x, not killall" "$dnsmasq_cmd" '"$RACOON_HOOK_PKILL" -HUP -x dnsmasq'
assert_not_contains "dnsmasq: never uses killall" "$dnsmasq_cmd" "killall"

dnsmasq_content=$(rhook_dnsmasq_conf_content)
assert_contains "dnsmasq content: scoped server= line, not global" "$dnsmasq_content" "server=/corp.example.com/10.0.12.53"
assert_not_contains "dnsmasq content: never a bare unscoped server= line" "$dnsmasq_content" "
server=10.0.12.53
"

# No domains at all: must refuse (required, always-fails step), never
# silently become a global resolver for every lookup.
RHOOK_DOMAINS_SAVE="$RHOOK_DOMAINS"
RHOOK_DOMAINS=""
rhook_build_plan
PLAN="$(rhook_plan_file)"
assert_eq "dnsmasq no-domains: refusal step is required" "$(plan_field dnsmasq_no_domains 3 "$PLAN")" "required"
TESTS_RUN=$((TESTS_RUN + 1))
refusal_cmd=$(plan_field dnsmasq_no_domains 5 "$PLAN")
if eval "$refusal_cmd" >/dev/null 2>/dev/null; then
	fail "dnsmasq no-domains refusal step must exit non-zero"
fi
RHOOK_DOMAINS="$RHOOK_DOMAINS_SAVE"

# ==========================================================================
# fallback backend (no resolver manager detected at all) -- brief 3 §I:
# gated behind allow_resolv_conf_overwrite, default "no".
# ==========================================================================
RHOOK_BACKEND="none"

# Default (unset / "no"): refused outright, never touches /etc/resolv.conf.
RHOOK_ALLOW_RESOLV_CONF_OVERWRITE="no"
rhook_build_plan
PLAN="$(rhook_plan_file)"
assert_eq "fallback refused by default: required failing step" \
	"$(plan_field fallback_refused 3 "$PLAN")" "required"
TESTS_RUN=$((TESTS_RUN + 1))
refused_cmd=$(plan_field fallback_refused 5 "$PLAN")
if eval "$refused_cmd" >/dev/null 2>/dev/null; then
	fail "fallback refusal step must exit non-zero"
fi
assert_contains "fallback refusal explains the opt-in key" "$refused_cmd" "allow_resolv_conf_overwrite = yes"
TESTS_RUN=$((TESTS_RUN + 1))
if grep -q '^fallback_dns' "$PLAN"; then
	fail "fallback_dns must not be planned when allow_resolv_conf_overwrite is not yes"
fi

# Explicit opt-in: the original backup + overwrite steps are planned.
RHOOK_ALLOW_RESOLV_CONF_OVERWRITE="yes"
rhook_build_plan
PLAN="$(rhook_plan_file)"
assert_eq "fallback_backup: optional" "$(plan_field fallback_backup 3 "$PLAN")" "optional"
assert_eq "fallback_dns: required" "$(plan_field fallback_dns 3 "$PLAN")" "required"
fallback_cmd=$(plan_field fallback_dns 5 "$PLAN")
assert_contains "fallback: scoped chmod 0644, never a global umask" "$fallback_cmd" "chmod 0644 /etc/resolv.conf"
RHOOK_ALLOW_RESOLV_CONF_OVERWRITE="no"

# ==========================================================================
# R7: no hardcoded network fallback. Empty RHOOK_ROUTES (gateway sent no
# split-include networks, and no DNS-server host routes were added either)
# must plan a required, always-failing refusal step -- never invent a
# guessed network to route through the tunnel.
# ==========================================================================
RHOOK_ROUTES_SAVE="$RHOOK_ROUTES"
RHOOK_ROUTES=""
rhook_build_plan
PLAN="$(rhook_plan_file)"
assert_eq "no_routes: refusal step is required" "$(plan_field no_routes 3 "$PLAN")" "required"
TESTS_RUN=$((TESTS_RUN + 1))
no_routes_cmd=$(plan_field no_routes 5 "$PLAN")
if eval "$no_routes_cmd" >/dev/null 2>/dev/null; then
	fail "no_routes refusal step must exit non-zero"
fi
TESTS_RUN=$((TESTS_RUN + 1))
if grep -q '^route_' "$PLAN"; then
	fail "no route_* steps should be planned when RHOOK_ROUTES is empty"
fi
RHOOK_ROUTES="$RHOOK_ROUTES_SAVE"

# A non-empty RHOOK_ROUTES (even if it came only from DNS-server host
# routes, not the gateway's split-include list) must NOT trigger the
# refusal step.
rhook_build_plan
PLAN="$(rhook_plan_file)"
TESTS_RUN=$((TESTS_RUN + 1))
if grep -q '^no_routes	' "$PLAN"; then
	fail "no_routes refusal step must not be planned when RHOOK_ROUTES is non-empty"
fi

# ==========================================================================
# rhook_survey_classify_backend: admin override always wins, "auto" runs
# the actual classification.
# ==========================================================================
assert_eq "explicit config value returned unchanged" "$(rhook_survey_classify_backend networkmanager)" "networkmanager"
assert_eq "explicit 'none' returned unchanged" "$(rhook_survey_classify_backend none)" "none"

RHOOK_FS_ROOT="$WORK/fsroot-static"
mkdir -p "$RHOOK_FS_ROOT/etc"
cat > "$RHOOK_FS_ROOT/etc/resolv.conf" <<'EOF'
nameserver 192.0.2.1
EOF
cat > "$RHOOK_FS_ROOT/etc/nsswitch.conf" <<'EOF'
hosts: files dns
EOF
RACOON_HOOK_BUSCTL="$WORK/bin/busctl-inactive"
RACOON_HOOK_SYSTEMCTL="$WORK/bin/systemctl-nm-inactive"
RACOON_HOOK_RESOLVCONF="$WORK/bin/resolvconf-absent"
assert_eq "auto classification: plain static file, nothing else present" \
	"$(rhook_survey_classify_backend auto)" "static"
RHOOK_FS_ROOT=""

echo ""
echo "$TESTS_RUN checks run, $TESTS_FAILED failed"
[ "$TESTS_FAILED" -eq 0 ]
