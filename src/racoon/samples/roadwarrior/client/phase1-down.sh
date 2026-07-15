#!/bin/sh
#
# phase1-down.sh - racoon phase1-down script hook
#
# Modern DNS/route cleanup with resolver auto-detection.
# Mirrors the resolver used by phase1-up.sh.
#
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (C) 2024-2026 Thomas Reim and the racoon-ipsec-tools contributors
# Part of rdratlos/racoon-ipsec-tools — https://github.com/rdratlos/racoon-ipsec-tools

PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin
export PATH

set -e

# ---- Logging helper ----
log() {
	echo "$(date '+%Y-%m-%d %H:%M:%S') [phase1-down] $*" >&2
}

# ---- Guard ----
if [ -z "$INTERNAL_ADDR4" ] || [ -z "$INTERNAL_MASK4" ]; then
	log "No internal address configuration; skipping cleanup."
	exit 0
fi

log "Tearing down VPN: addr=${INTERNAL_ADDR4}/${INTERNAL_CIDR4}"

# ---- Detect resolver ----
detect_resolver() {
	if command -v resolvectl >/dev/null 2>&1 || command -v resctl >/dev/null 2>&1; then
		if systemctl is-active --quiet systemd-resolved 2>/dev/null; then
			echo "systemd-resolved"
			return
		fi
	fi
	if command -v nmcli >/dev/null 2>&1; then
		if systemctl is-active --quiet NetworkManager 2>/dev/null; then
			echo "networkmanager"
			return
		fi
	fi
	if command -v resolvconf >/dev/null 2>&1; then
		if [ -e /run/resolvconf ]; then
			echo "resolvconf"
			return
		fi
	fi
	if command -v dnsmasq >/dev/null 2>&1; then
		if pgrep -x dnsmasq >/dev/null 2>&1; then
			echo "dnsmasq"
			return
		fi
	fi
	echo "fallback"
}

RESOLVER=$(detect_resolver)
log "Detected DNS resolver: ${RESOLVER}"

# ---- Determine tunnel interface ----
TUNNEL_IF=""
if [ -d /sys/class/net/tun ]; then
	for iface in /sys/class/net/*; do
		ifname=$(basename "$iface")
		case "$ifname" in
		lo|sit*) continue ;;
		esac
		if [ -d "$iface/tun" ] || [ -L "$iface" ]; then
			TUNNEL_IF="$ifname"
			break
		fi
	done
fi

if [ -z "$TUNNEL_IF" ]; then
	PRIMARY_IF=$(ip -4 route show default 2>/dev/null | awk '{print $5; exit}')
	TUNNEL_IF="${PRIMARY_IF:-eth0}"
fi

# ---- Remove SPD rules ----
if [ -n "$REMOTE_ADDR" ] && [ -n "$LOCAL_ADDR" ]; then
	LOCAL="${LOCAL_ADDR}"
	REMOTE="${REMOTE_ADDR}"
	if [ "x${LOCAL_PORT}" != "x500" ]; then
		LOCAL="${LOCAL}[${LOCAL_PORT}]"
		REMOTE="${REMOTE}[${REMOTE_PORT}]"
	fi

	setkey -F 2>/dev/null || true

	echo "
spddelete ${INTERNAL_ADDR4}/32[any] 0.0.0.0/0[any] any \
	-P out ipsec esp/tunnel/${LOCAL}-${REMOTE}/require;
spddelete 0.0.0.0/0[any] ${INTERNAL_ADDR4}/32[any] any \
	-P in ipsec esp/tunnel/${REMOTE}-${LOCAL}/require;
" | setkey -f - 2>/dev/null || log "Failed to remove SPD rules"
fi

# ---- Remove IP address ----
ip addr del "${INTERNAL_ADDR4}/${INTERNAL_CIDR4}" dev "${TUNNEL_IF}" 2>/dev/null || true
log "Removed ${INTERNAL_ADDR4}/${INTERNAL_CIDR4} from ${TUNNEL_IF}"

# ---- Remove route to remote peer ----
DEFAULT_GW=$(ip -4 route show default 2>/dev/null | awk '{print $3; exit}')
if [ -n "$DEFAULT_GW" ] && [ -n "$REMOTE_ADDR" ]; then
	ip route del "${REMOTE_ADDR}/32" via "${DEFAULT_GW}" 2>/dev/null || true
fi

# ---- Clean up DNS ----
cleanup_systemd_resolved_dns() {
	local ifname="$1"
	local rescmd="resolvectl"
	command -v resolvectl >/dev/null 2>&1 || rescmd="resctl"

	"$rescmd" revert "${ifname}" 2>/dev/null || {
		"$rescmd" dns "${ifname}" "" 2>/dev/null || true
		"$rescmd" domain "${ifname}" "~." 2>/dev/null || true
	}
}

cleanup_networkmanager_dns() {
	local vpn_conn="racoon-vpn"
	if nmcli conn show "$vpn_conn" >/dev/null 2>&1; then
		nmcli conn down "$vpn_conn" >/dev/null 2>&1 || true
		nmcli conn delete "$vpn_conn" >/dev/null 2>&1 || true
	fi
}

cleanup_resolvconf_dns() {
	resolvconf -d "${TUNNEL_IF}.racoon" 2>/dev/null || true
}

cleanup_fallback_dns() {
	# Nothing to clean up for fallback (no persistent state was modified)
	:
}

case "${RESOLVER}" in
systemd-resolved)
	cleanup_systemd_resolved_dns "${TUNNEL_IF}"
	log "Cleaned up systemd-resolved DNS for ${TUNNEL_IF}"
	;;
networkmanager)
	cleanup_networkmanager_dns
	log "Cleaned up NetworkManager DNS"
	;;
resolvconf)
	cleanup_resolvconf_dns
	log "Cleaned up resolvconf DNS"
	;;
dnsmasq)
	cleanup_fallback_dns
	log "No persistent DNS state to clean for dnsmasq"
	;;
fallback)
	log "No persistent DNS state to clean"
	;;
esac

log "VPN teardown complete."
exit 0