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

# --------------------------------------------------------------------------
# Logging — syslog (logger) + stderr
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
# Collect the internal networks (must match up.sh for route cleanup),
# plus the same DNS-server /32 host routes up.sh added on top of them.
# --------------------------------------------------------------------------
NETWORKS="${SPLIT_INCLUDE_CIDR:-}"
if [ -z "$NETWORKS" ]; then
	NETWORKS="${SPLIT_INCLUDE:-}"
fi
if [ -z "$NETWORKS" ]; then
	NETWORKS="10.0.12.0/24"
fi

DNS_SERVERS="${INTERNAL_DNS4_LIST:-$INTERNAL_DNS4}"
TUNNEL_ROUTES="$NETWORKS"
for dns in $DNS_SERVERS; do
	case " $TUNNEL_ROUTES " in
		*" ${dns}/32 "*) ;;  # exact /32 already present, skip
		*) TUNNEL_ROUTES="$TUNNEL_ROUTES ${dns}/32" ;;
	esac
done

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
for net in $TUNNEL_ROUTES; do
	ip route del "$net" dev "$IFACE" src "$INTERNAL_ADDR4" 2>/dev/null || true
done
ip addr del "${INTERNAL_ADDR4}/32" dev "$IFACE" 2>/dev/null || true
log "Removed routes for: $TUNNEL_ROUTES; removed /32 address from $IFACE"

# --------------------------------------------------------------------------
# Clean up DNS — mirror the resolver detection from phase1-up.sh.  The
# authoritative signal is what /etc/resolv.conf actually resolves to, not
# whether a resolvectl/nmcli binary happens to be installed or a service
# happens to be running (see phase1-up.sh for the full rationale).
# --------------------------------------------------------------------------
detect_resolver() {
	local target
	target=$(readlink -f /etc/resolv.conf 2>/dev/null) || target=""

	case "$target" in
		*/run/systemd/resolve/stub-resolv.conf|*/run/systemd/resolve/resolv.conf)
			echo "systemd-resolved"
			return
			;;
		*/run/NetworkManager/resolv.conf)
			echo "networkmanager"
			return
			;;
		*/run/resolvconf/resolv.conf)
			echo "resolvconf"
			return
			;;
	esac

	if command -v resolvectl >/dev/null 2>&1 || command -v resctl >/dev/null 2>&1; then
		if systemctl is-active --quiet systemd-resolved 2>/dev/null; then
			echo "systemd-resolved"
			return
		fi
	fi
	if command -v nmcli >/dev/null 2>&1 && systemctl is-active --quiet NetworkManager 2>/dev/null; then
		echo "networkmanager"
		return
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
	# Tear down the dedicated DNS-only dummy profile created by
	# phase1-up.sh.  This never touches the physical uplink connection,
	# so there is nothing to "restore" there and nothing that can bounce
	# the user's actual network link.
	nmcli connection down "racoon-vpn-dns" >/dev/null 2>&1 || true
	nmcli connection delete "racoon-vpn-dns" >/dev/null 2>&1 || true
	ip link del racoon-dns0 >/dev/null 2>&1 || true
	# Best-effort cleanup of artifacts from older versions of this script
	# that modified the active connection directly or used a "vpn0"/
	# "racoon-vpn" dummy device.
	nmcli connection down "racoon-vpn" >/dev/null 2>&1 || true
	nmcli connection delete "racoon-vpn" >/dev/null 2>&1 || true
	ip link del vpn0 >/dev/null 2>&1 || true
	log "NetworkManager DNS profile removed"
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

# If phase1-up wrote /run/racoon/dns-method (e.g. NM failed and
# fell back to resolv.conf), override RESOLVER so the correct
# cleanup runs.
if [ -f /run/racoon/dns-method ]; then
	UP_METHOD=$(cat /run/racoon/dns-method 2>/dev/null) || true
	case "$UP_METHOD" in
		fallback) RESOLVER="force-fallback" ;;
		networkmanager-active|networkmanager-dummy) RESOLVER="force-networkmanager" ;;
	esac
	rm -f /run/racoon/dns-method
fi

case "$RESOLVER" in
	force-fallback)
		cleanup_fallback_dns
		;;
	force-networkmanager|networkmanager)
		cleanup_networkmanager_dns
		;;
	systemd-resolved)
		cleanup_systemd_resolved_dns "${IFACE}"
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