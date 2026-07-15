#!/bin/sh
#
# phase1-up.sh - racoon phase1-up script hook
#
# Modern DNS/route management with resolver auto-detection.
# Supports: systemd-resolved, NetworkManager, resolvconf, dnsmasq.
#
# Environment variables provided by racoon:
#   LOCAL_ADDR, LOCAL_PORT, REMOTE_ADDR, REMOTE_PORT
#   INTERNAL_ADDR4, INTERNAL_MASK4, INTERNAL_NETMASK4, INTERNAL_CIDR4
#   INTERNAL_DNS4, INTERNAL_DNS4_LIST, INTERNAL_WINS4, INTERNAL_WINS4_LIST
#   DEFAULT_DOMAIN, SPLIT_INCLUDE, SPLIT_INCLUDE_CIDR, SPLIT_LOCAL, SPLIT_LOCAL_CIDR
#   INTERNAL_SPLITDNS_DOMAINS - comma-separated list of DNS search domains for split DNS
#   XAUTH_USER
#
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (C) 2024-2026 Thomas Reim and the racoon-ipsec-tools contributors
# Part of rdratlos/racoon-ipsec-tools — https://github.com/rdratlos/racoon-ipsec-tools

PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin
export PATH

set -e

# ---- Logging helper ----
log() {
	echo "$(date '+%Y-%m-%d %H:%M:%S') [phase1-up] $*" >&2
}

# ---- Guard: only run when we have an internal address ----
if [ -z "$INTERNAL_ADDR4" ] || [ -z "$INTERNAL_MASK4" ]; then
	log "No internal address configuration; skipping."
	exit 0
fi

log "Setting up VPN: addr=${INTERNAL_ADDR4}/${INTERNAL_CIDR4}"

# ---- Determine the VPN interface ----
# Use the tunnel interface created by the kernel, if any.
# Fallback to the primary interface for IP alias.
TUNNEL_IF=""
if [ -d /sys/class/net/tun ]; then
	# Find a tun/tap interface that is not lo
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

# If no tunnel interface, detect the primary outbound interface
if [ -z "$TUNNEL_IF" ]; then
	PRIMARY_IF=$(ip -4 route show default 2>/dev/null | awk '{print $5; exit}')
	TUNNEL_IF="${PRIMARY_IF:-eth0}"
fi

# ---- Assign internal IP ----
ip addr add "${INTERNAL_ADDR4}/${INTERNAL_CIDR4}" dev "${TUNNEL_IF}" 2>/dev/null || true
log "Assigned ${INTERNAL_ADDR4}/${INTERNAL_CIDR4} on ${TUNNEL_IF}"

# ---- Default gateway ----
DEFAULT_GW=$(ip -4 route show default 2>/dev/null | awk '{print $3; exit}')

# ---- Add route to remote peer (before default route change) ----
if [ -n "$DEFAULT_GW" ] && [ -n "$REMOTE_ADDR" ]; then
	ip route replace "${REMOTE_ADDR}/32" via "${DEFAULT_GW}" dev "${TUNNEL_IF}" 2>/dev/null || true
fi

# ---- Detect DNS resolver ----
detect_resolver() {
	if command -v resolvectl >/dev/null 2>&1 || command -v resctl >/dev/null 2>&1; then
		# Check if systemd-resolved is actually running
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

# ---- Parse DNS servers ----
DNS_SERVERS="${INTERNAL_DNS4_LIST:-$INTERNAL_DNS4}"
if [ -z "$DNS_SERVERS" ]; then
	log "No DNS servers provided by server; skipping DNS setup."
	DNS_SERVERS=""
fi

# ---- Apply DNS configuration ----
setup_systemd_resolved_dns() {
	local ifname="$1"
	local dns_list="$2"
	local domains="$3"

	if [ -z "$dns_list" ] && [ -z "$domains" ]; then
		return
	fi

	# Use resolvectl or resctl (Ubuntu < 25.04)
	local rescmd="resolvectl"
	command -v resolvectl >/dev/null 2>&1 || rescmd="resctl"

	if [ -n "$dns_list" ]; then
		# Replace space-separated list with commas for resolvectl
		local dns_csv
		dns_csv=$(echo "$dns_list" | tr ' ' ',')
		"$rescmd" dns "${ifname}" $dns_csv 2>/dev/null || \
			log "resolvectl dns failed for ${ifname}"
	fi

	if [ -n "$domains" ]; then
		# Convert comma-separated to space-separated
		local domains_spc
		domains_spc=$(echo "$domains" | tr ',' ' ')
		"$rescmd" domain "${ifname}" $domains_spc 2>/dev/null || \
			log "resolvectl domain failed for ${ifname}"
	fi

	# Set route-only DNS (only used for VPN split DNS domains)
	if [ -n "$domains" ] && [ -z "$SPLIT_INCLUDE_CIDR" ]; then
		"$rescmd" default-route "${ifname}" false 2>/dev/null || true
	fi
}

setup_networkmanager_dns() {
	local conn_name="$1"
	local dns_list="$2"
	local domains="$3"

	if [ -z "$dns_list" ] && [ -z "$domains" ]; then
		return
	fi

	# Find or create a VPN connection for NM
	local vpn_conn="racoon-vpn"
	if ! nmcli conn show "$vpn_conn" >/dev/null 2>&1; then
		nmcli conn add type dummy ifname vpn0 con-name "$vpn_conn" >/dev/null 2>&1 || {
			log "Failed to create NM VPN connection; falling back."
			return
		}
	fi

	if [ -n "$dns_list" ]; then
		local dns_csv
		dns_csv=$(echo "$dns_list" | tr ' ' ',')
		nmcli conn modify "$vpn_conn" ipv4.dns "$dns_csv" >/dev/null 2>&1 || true
	fi

	if [ -n "$domains" ]; then
		local domains_csv
		domains_csv=$(echo "$domains" | tr ',' ';')
		nmcli conn modify "$vpn_conn" ipv4.dns-search "$domains_csv" >/dev/null 2>&1 || true
	fi

	nmcli conn up "$vpn_conn" >/dev/null 2>&1 || true
}

setup_resolvconf_dns() {
	local dns_list="$1"
	local domains="$2"
	local iface="$3"

	if [ -z "$dns_list" ]; then
		return
	fi

	local resolv_input
	resolv_input="# Generated by racoon phase1-up on $(date)
nameserver"
	for dns in $dns_list; do
		resolv_input="$resolv_input
nameserver ${dns}"
	done
	if [ -n "$domains" ]; then
		local domains_spc
		domains_spc=$(echo "$domains" | tr ',' ' ')
		resolv_input="$resolv_input
search ${domains_spc}"
	fi

	echo "$resolv_input" | resolvconf -a "${iface}.racoon" 2>/dev/null || {
		log "resolvconf failed; falling back to direct resolv.conf"
	}
}

setup_dnsmasq_dns() {
	local dns_list="$1"
	local domains="$2"

	# For dnsmasq, configure via its conf directory
	if [ -d /etc/dnsmasq.d ]; then
		local conf="/etc/dnsmasq.d/racoon-vpn"
		echo "# Generated by racoon phase1-up on $(date)" > "$conf"
		for dns in $dns_list; do
			echo "server=${dns}" >> "$conf"
		done
		if [ -n "$domains" ]; then
			local domains_spc
			domains_spc=$(echo "$domains" | tr ',' ' ')
			echo "domain=${domains_spc}" >> "$conf"
		fi
		killall -HUP dnsmasq 2>/dev/null || true
	fi
}

setup_fallback_dns() {
	local dns_list="$1"
	local domains="$2"

	log "WARNING: No supported DNS resolver found; modifying /etc/resolv.conf directly."
	cp /etc/resolv.conf /etc/resolv.conf.racoon.bak 2>/dev/null || true
	{
		echo "# Generated by racoon phase1-up on $(date)"
		if [ -n "$domains" ]; then
			local domains_spc
			domains_spc=$(echo "$domains" | tr ',' ' ')
			echo "search ${domains_spc}"
		fi
		for dns in $dns_list; do
			echo "nameserver ${dns}"
		done
	} > /etc/resolv.conf
}

# ---- Collect split DNS domains ----
SPLIT_DNS="${INTERNAL_SPLITDNS_DOMAINS:-}"
SEARCH_DOMAINS=""

if [ -n "$SPLIT_DNS" ]; then
	SEARCH_DOMAINS="$SPLIT_DNS"
	log "Split DNS domains: ${SEARCH_DOMAINS}"
elif [ -n "$DEFAULT_DOMAIN" ]; then
	SEARCH_DOMAINS="$DEFAULT_DOMAIN"
	log "Default domain: ${SEARCH_DOMAINS}"
fi

# ---- Apply DNS via detected resolver ----
case "$RESOLVER" in
	systemd-resolved)
		setup_systemd_resolved_dns "${TUNNEL_IF}" "$DNS_SERVERS" "$SEARCH_DOMAINS"
		;;
	networkmanager)
		setup_networkmanager_dns "racoon-vpn" "$DNS_SERVERS" "$SEARCH_DOMAINS"
		;;
	resolvconf)
		setup_resolvconf_dns "$DNS_SERVERS" "$SEARCH_DOMAINS" "${TUNNEL_IF}"
		;;
	dnsmasq)
		setup_dnsmasq_dns "$DNS_SERVERS" "$SEARCH_DOMAINS"
		;;
	fallback)
		setup_fallback_dns "$DNS_SERVERS" "$SEARCH_DOMAINS"
		;;
esac

# ---- Apply split DNS routing ----
if [ -n "$SPLIT_INCLUDE_CIDR" ]; then
	for subnet in $SPLIT_INCLUDE_CIDR; do
		ip route replace "$subnet" via "${INTERNAL_ADDR4}" 2>/dev/null || \
			log "Failed to add route for $subnet"
	done
	log "Applied split include routes from SPLIT_INCLUDE_CIDR"
fi

# ---- Install SPD rules ----
LOCAL="${LOCAL_ADDR}"
REMOTE="${REMOTE_ADDR}"
if [ "$LOCAL_PORT" != "500" ] && [ -n "$LOCAL_PORT" ]; then
	LOCAL="${LOCAL}[${LOCAL_PORT}]"
	REMOTE="${REMOTE}[${REMOTE_PORT}]"
fi

echo "
spdadd ${INTERNAL_ADDR4}/32[any] 0.0.0.0/0[any] any \
	-P out ipsec esp/tunnel/${LOCAL}-${REMOTE}/require;
spdadd 0.0.0.0/0[any] ${INTERNAL_ADDR4}/32[any] any \
	-P in ipsec esp/tunnel/${REMOTE}-${LOCAL}/require;
" | setkey -f - 2>/dev/null || log "Failed to install SPD rules"

log "VPN setup complete."
exit 0