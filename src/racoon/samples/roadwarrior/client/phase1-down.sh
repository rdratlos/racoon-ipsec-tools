#!/bin/sh
#
# phase1-down.sh - racoon phase1-down script hook
#
# Called by racoon when Phase 1 tears down (timeout, error, or explicit
# disconnection).  Reverses everything phase1-up.sh installed:
#   1. Flushes SPD policies.
#   2. Removes split routes for internal networks.
#   3. Removes the /32 auxiliary address from the real interface.
#   4. Cleans up DNS configuration (resolvers, split-DNS search domains).
#
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (C) 2024-2026 Thomas Reim and the racoon-ipsec-tools contributors
# Part of rdratlos/racoon-ipsec-tools — https://github.com/rdratlos/racoon-ipsec-tools

PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin
export PATH

set -e

SCRIPT_DIR=$(dirname "$0")
. "${SCRIPT_DIR}/phase1-common.sh"

# --------------------------------------------------------------------------
# Logging — syslog (logger) only.
# --------------------------------------------------------------------------
log() {
	logger -t racoon-phase1-down "$*"
}

# --------------------------------------------------------------------------
# Guard — skip if we never had a Mode Config address (same guard as up.sh).
# --------------------------------------------------------------------------
if [ -z "${INTERNAL_ADDR4:-}" ]; then
	log "No internal address; skipping teardown"
	exit 0
fi

log "phase1 down: internal=${INTERNAL_ADDR4} remote=${REMOTE_ADDR:-?}"

# --------------------------------------------------------------------------
# Determine the outbound interface (must match what up.sh used).
# --------------------------------------------------------------------------
IFACE=""
if [ -n "${REMOTE_ADDR:-}" ]; then
	IFACE=$(ip -4 route get "$REMOTE_ADDR" 2>/dev/null \
	    | awk '{for (i = 1; i <= NF; i++) if ($i == "dev") print $(i + 1)}')
fi
if [ -z "$IFACE" ]; then
	IFACE=$(ip -4 route show default 2>/dev/null | awk '{print $5; exit}')
fi
IFACE="${IFACE:-eth0}"

# --------------------------------------------------------------------------
# Collect the internal networks (must match up.sh for route cleanup).
# --------------------------------------------------------------------------
NETWORKS="${SPLIT_INCLUDE_CIDR:-}"
if [ -z "$NETWORKS" ]; then
	NETWORKS="${SPLIT_INCLUDE:-}"
fi
if [ -z "$NETWORKS" ]; then
	NETWORKS="10.0.12.0/24"
fi

# --------------------------------------------------------------------------
# Flush SPD — remove all IPsec policies to prevent blackholing traffic.
# --------------------------------------------------------------------------
if [ -n "${REMOTE_ADDR:-}" ] && [ -n "${LOCAL_ADDR:-}" ]; then
	setkey -F 2>/dev/null || true
	log "SPD flushed"
fi

# --------------------------------------------------------------------------
# Remove split routes and the /32 auxiliary address.
# --------------------------------------------------------------------------
for net in $NETWORKS; do
	ip route del "$net" dev "$IFACE" src "$INTERNAL_ADDR4" 2>/dev/null || true
done

# Also remove DNS server /32 routes that were installed in up.sh.
DNS_SERVERS="${INTERNAL_DNS4_LIST:-$INTERNAL_DNS4}"
if [ -n "$DNS_SERVERS" ]; then
	for dns in $DNS_SERVERS; do
		ip route del "${dns}/32" dev "$IFACE" src "$INTERNAL_ADDR4" 2>/dev/null || true
	done
	log "DNS server /32 routes removed: $DNS_SERVERS"
fi

ip addr del "${INTERNAL_ADDR4}/32" dev "$IFACE" 2>/dev/null || true
log "Removed routes for: $NETWORKS; removed /32 address from $IFACE"

# --------------------------------------------------------------------------
# Clean up DNS — resolver detection via shared helper (same as up.sh).
# --------------------------------------------------------------------------
RESOLVER=$(detect_resolver)
log "Detected DNS resolver: ${RESOLVER}"

cleanup_systemd_resolved_dns() {
	local ifname="$1"
	local rescmd="resolvectl"
	command -v resolvectl >/dev/null 2>&1 || rescmd="resctl"
	"$rescmd" revert "${ifname}" 2>/dev/null || {
		"$rescmd" dns "${ifname}" "" 2>/dev/null || true
		"$rescmd" domain "${ifname}" "~." 2>/dev/null || true
	}
	log "systemd-resolved DNS reverted for ${ifname}"
}

cleanup_networkmanager_dns() {
	local conn_name vpn_if
	conn_name=$(racoon_vpn_connname)
	vpn_if=$(racoon_vpn0_ifname)

	# Clean teardown: de-activate, then delete the connection profile.
	# The dummy interface is released automatically when the last
	# connection referencing it is deleted.
	nmcli conn down "$conn_name" >/dev/null 2>&1 || true
	nmcli conn delete "$conn_name" >/dev/null 2>&1 || true
	# Force-remove the dummy if NM left it behind.
	ip link del "$vpn_if" >/dev/null 2>&1 || true
	log "NetworkManager VPN dummy $vpn_if removed"
}

cleanup_resolvconf_dns() {
	resolvconf -d "${IFACE}.racoon" 2>/dev/null || true
	log "resolvconf entry removed"
}

cleanup_dnsmasq_dns() {
	rm -f /etc/dnsmasq.d/racoon-vpn
	killall -HUP dnsmasq 2>/dev/null || true
	log "dnsmasq racoon-vpn config removed"
}

cleanup_fallback_dns() {
	if [ -f /etc/resolv.conf.racoon.bak ]; then
		cp /etc/resolv.conf.racoon.bak /etc/resolv.conf
		rm -f /etc/resolv.conf.racoon.bak
		log "/etc/resolv.conf restored from backup"
	else
		log "No resolv.conf backup to restore"
	fi
}

case "$RESOLVER" in
	systemd-resolved)
		cleanup_systemd_resolved_dns "${IFACE}"
		;;
	networkmanager)
		cleanup_networkmanager_dns
		;;
	resolvconf)
		cleanup_resolvconf_dns
		;;
	dnsmasq)
		cleanup_dnsmasq_dns
		;;
	fallback)
		cleanup_fallback_dns
		;;
esac

log "VPN teardown complete"
exit 0