#!/bin/sh
#
# phase1-up.sh - racoon phase1-up script hook
#
# Called by racoon after Phase 1 + Mode Config negotiation succeeds.
# Responsibilities:
#   1. Install split routes so only internal-network traffic enters the tunnel.
#   2. Register the tunnel's SPD policies via setkey.
#   3. Configure DNS (resolvers, split-DNS search domains) per server intent.
#
# Networks to tunnel come from the gateway (SPLIT_INCLUDE_CIDR).  A local
# NETWORKS fallback is provided for gateways that do not send this attribute.
#
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (C) 2024-2026 Thomas Reim and the racoon-ipsec-tools contributors
# Part of rdratlos/racoon-ipsec-tools — https://github.com/rdratlos/racoon-ipsec-tools

PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin
export PATH

set -e

# --------------------------------------------------------------------------
# Logging — syslog (logger) + stderr for easy debugging
# --------------------------------------------------------------------------
log() {
	logger -t racoon-phase1-up "$*"
}

# --------------------------------------------------------------------------
# Guard — bail out early if the gateway did not assign an address.
# This can happen when the server rejects Mode Config (no pool, policy deny).
# --------------------------------------------------------------------------
if [ -z "${INTERNAL_ADDR4:-}" ] || [ -z "${LOCAL_ADDR:-}" ] || [ -z "${REMOTE_ADDR:-}" ]; then
	log "No Mode Config address assigned (internal=${INTERNAL_ADDR4:-?}) -- not installing routes or SPD"
	exit 0
fi

log "phase1 up: local=${LOCAL_ADDR:-?}:${LOCAL_PORT:-?} remote=${REMOTE_ADDR:-?}:${REMOTE_PORT:-?} internal=${INTERNAL_ADDR4}"

# --------------------------------------------------------------------------
# Determine the outbound network interface.
# We need the real interface (wlan0, eth0, …) to pin source-address
# selection and attach the /32 auxiliary address.
# --------------------------------------------------------------------------
IFACE=$(ip -4 route get "$REMOTE_ADDR" 2>/dev/null \
    | awk '{for (i = 1; i <= NF; i++) if ($i == "dev") print $(i + 1)}')
if [ -z "${IFACE:-}" ]; then
	log "Cannot determine outbound interface for $REMOTE_ADDR -- not installing SPD"
	exit 0
fi

# --------------------------------------------------------------------------
# Collect the set of internal networks to route through the tunnel.
# Priority: gateway-sent SPLIT_INCLUDE_CIDR > UNITY internal_nets
#           > hardcoded NETWORKS fallback (for legacy gateways).
# --------------------------------------------------------------------------
NETWORKS="${SPLIT_INCLUDE_CIDR:-}"
if [ -z "$NETWORKS" ]; then
	# Some racoon builds export internal networks via SPLIT_INCLUDE
	NETWORKS="${SPLIT_INCLUDE:-}"
fi
if [ -z "$NETWORKS" ]; then
	# Hardcoded fallback — matches server sample (10.0.12.0/24).
	# Override in your site-local copy or /etc/racoon/overrides.
	NETWORKS="10.0.12.0/24"
	log "WARNING: No split routes from gateway; using hardcoded NETWORKS fallback"
fi

if [ -z "$NETWORKS" ]; then
	log "No internal networks known -- nothing to tunnel"
	exit 0
fi

# --------------------------------------------------------------------------
# Internal DNS servers must always be reachable over the tunnel, even if
# the gateway's split-include list doesn't happen to cover the resolver's
# subnet (e.g. DNS lives on a management segment kept out of the general
# split-tunnel ACL).  Add a /32 host route + SPD pair for each one, on top
# of whatever NETWORKS already covers, so split-DNS can never end up with
# search domains configured but no path to the resolver that serves them.
# --------------------------------------------------------------------------
DNS_SERVERS="${INTERNAL_DNS4_LIST:-$INTERNAL_DNS4}"

TUNNEL_ROUTES="$NETWORKS"
for dns in $DNS_SERVERS; do
	case " $TUNNEL_ROUTES " in
		*" ${dns}/32 "*) ;;  # exact /32 already present, skip
		*) TUNNEL_ROUTES="$TUNNEL_ROUTES ${dns}/32" ;;
	esac
done

# --------------------------------------------------------------------------
# Pin INTERNAL_ADDR4 as a /32 auxiliary address on the real interface,
# and install per-network routes with src=INTERNAL_ADDR4.
#
# Why?  Linux selects the source address from the routing table.  By
# advertising INTERNAL_ADDR4 as a local address and adding explicit src=
# routes, application traffic to internal networks will propose the
# (INTERNAL_ADDR4 → network) selector pair that matches the SPD below.
# Without this, traffic uses the interface's primary address and silently
# bypasses the IPsec tunnel.
# --------------------------------------------------------------------------
ip addr replace "${INTERNAL_ADDR4}/32" dev "$IFACE"
for net in $TUNNEL_ROUTES; do
	ip route replace "$net" dev "$IFACE" src "$INTERNAL_ADDR4"
done
log "internal=${INTERNAL_ADDR4} configured as /32 on $IFACE; routes installed for: $TUNNEL_ROUTES"

# --------------------------------------------------------------------------
# SPD (Security Policy Database) via setkey.
#
# For each internal network (plus DNS host routes above) we install a
# bidirectional pair:
#   outbound: (INTERNAL_ADDR4/32 → net) → tunnel
#   inbound:  (net → INTERNAL_ADDR4/32) → tunnel
#
# We write to spd.conf for human inspection, then pipe to setkey.
# --------------------------------------------------------------------------
LOCAL="${LOCAL_ADDR}"
REMOTE="${REMOTE_ADDR}"
if [ "${LOCAL_PORT:-500}" != "500" ]; then
	# NAT-T in use — encode negotiated ports into tunnel endpoints
	LOCAL="${LOCAL}[${LOCAL_PORT}]"
	REMOTE="${REMOTE}[${REMOTE_PORT}]"
fi

SPD_CONF="/etc/racoon/spd.conf"
umask 077
{
	echo "#!/usr/sbin/setkey -f"
	echo "# Generated by phase1-up.sh on $(date -Is)"
	echo "# DO NOT EDIT — regenerated on every phase1-up"
	echo "spdflush;"
	for net in $TUNNEL_ROUTES; do
		echo "spdadd ${INTERNAL_ADDR4}/32 $net any -P out ipsec esp/tunnel/${LOCAL}-${REMOTE}/require;"
		echo "spdadd $net ${INTERNAL_ADDR4}/32 any -P in  ipsec esp/tunnel/${REMOTE}-${LOCAL}/require;"
	done
} > "$SPD_CONF.new"
mv "$SPD_CONF.new" "$SPD_CONF"

setkey -f "$SPD_CONF"
log "SPD installed ($TUNNEL_ROUTES) via tunnel ${LOCAL}-${REMOTE} (see $SPD_CONF)"

# --------------------------------------------------------------------------
# DNS — detect the system's resolver and configure nameservers +
# split-DNS search domains as instructed by the VPN gateway.
# --------------------------------------------------------------------------
# A resolvectl/nmcli binary being installed does not mean that backend is
# actually managing /etc/resolv.conf -- e.g. NetworkManager is commonly
# active as a service while systemd-resolved (or nothing) owns resolution,
# and vice versa.  The authoritative signal is what /etc/resolv.conf
# itself resolves to; binary/service presence is only a fallback for the
# ambiguous case of a plain, non-symlinked resolv.conf.
#
# NM_DNS_MODE records NetworkManager's configured DNS plugin ("default",
# "systemd-resolved", "dnsmasq", "unbound", "none") when the resolver is
# "networkmanager", so the DNS setup step below knows whether NM is even
# capable of per-domain routing.
NM_DNS_MODE=""

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

	# No symlink to go on (static file, or missing) -- fall back to
	# asking each service whether it is installed *and* running.
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

if [ "$RESOLVER" = "networkmanager" ]; then
	# Ask NetworkManager itself which DNS plugin is active, merging all
	# config files/drop-ins the way NM does.  Only "systemd-resolved" and
	# "dnsmasq" understand per-domain routing domains; "default" writes a
	# flat resolv.conf with no such concept.
	NM_DNS_MODE=$(NetworkManager --print-config 2>/dev/null \
	    | awk -F= '/^\[main\]/{m=1;next} /^\[/{m=0} m && $1 ~ /^[[:space:]]*dns[[:space:]]*$/ {gsub(/[[:space:]]/,"",$2); print $2; exit}')
	NM_DNS_MODE="${NM_DNS_MODE:-default}"
	log "NetworkManager DNS plugin: ${NM_DNS_MODE}"
fi

if [ -z "$DNS_SERVERS" ]; then
	log "No DNS servers from gateway; skipping DNS setup"
fi

# Collect split-DNS search domains (UNITY or Mode Config)
SEARCH_DOMAINS="${INTERNAL_SPLITDNS_DOMAINS:-}"
if [ -z "$SEARCH_DOMAINS" ] && [ -n "${DEFAULT_DOMAIN:-}" ]; then
	SEARCH_DOMAINS="$DEFAULT_DOMAIN"
fi

# ---- resolver-specific setup ----
setup_systemd_resolved_dns() {
	local ifname="$1" dns_list="$2" domains="$3"
	[ -z "$dns_list" ] && [ -z "$domains" ] && return 0
	local rescmd="resolvectl"
	command -v resolvectl >/dev/null 2>&1 || rescmd="resctl"

	if [ -n "$dns_list" ]; then
		local dns_csv; dns_csv=$(echo "$dns_list" | tr ' ' ',')
		"$rescmd" dns "${ifname}" $dns_csv 2>/dev/null || \
			log "resolvectl dns failed for ${ifname}"
	fi
	if [ -n "$domains" ]; then
		local d; d=$(echo "$domains" | tr ',' ' ')
		"$rescmd" domain "${ifname}" $d 2>/dev/null || \
			log "resolvectl domain failed for ${ifname}"
		# route-only: only resolve for these domains, not as default DNS
		"$rescmd" default-route "${ifname}" false 2>/dev/null || true
	fi
}

# Fixed identity for the dedicated NM DNS profile.  Deliberately never the
# real uplink (wlan0/eth0/…): a profile bound to the physical connection
# has to be taken down and reactivated to push new DNS settings, which
# drops the radio/link association carrying both the IKE session and any
# remote administration session using it.  A throwaway dummy interface can
# be created, reconfigured and torn down without ever touching the link
# the user is actually relying on.
NM_DNS_CONN="racoon-vpn-dns"
NM_DNS_IFACE="racoon-dns0"
NM_DNS_ADDR="169.254.66.13/32"

setup_networkmanager_dns() {
	local dns_list="$1" domains="$2"
	[ -z "$dns_list" ] && [ -z "$domains" ] && return 0

	# Clean up any leftover profile from a previous run (crash, kill -9,
	# stale state from an earlier version of this script) so the
	# `connection add` below doesn't fail with "already exists".
	nmcli connection delete "$NM_DNS_CONN" >/dev/null 2>&1 || true
	ip link del "$NM_DNS_IFACE" >/dev/null 2>&1 || true

	local search=""
	if [ -n "$domains" ]; then
		case "$NM_DNS_MODE" in
			systemd-resolved|dnsmasq)
				# '~domain' marks a *routing* domain: only queries for
				# that domain go to this profile's DNS servers, every
				# other lookup keeps using the normal path.  Without
				# the '~' it is merely a search suffix and does not
				# constrain routing at all.
				search=$(echo "$domains" | tr ',' '\n' | sed 's/^/~/' | tr '\n' ',' | sed 's/,$//')
				;;
			*)
				log "WARNING: NetworkManager DNS mode is '${NM_DNS_MODE:-default}', which has no per-domain routing. Split-DNS domains cannot be isolated -- ${dns_list:-the VPN DNS server} will become the resolver for ALL lookups while the tunnel is up. For real split-DNS, set dns=systemd-resolved in NetworkManager.conf."
				search="$domains"
				;;
		esac
	fi

	# All properties are supplied in one `connection add` so the profile
	# is fully configured *before* NM's first auto-activation.  Modifying
	# ipv4.dns/ipv4.dns-search on an already-active profile is rejected
	# by NM's policy audit -- that is what made the earlier dummy-device
	# attempts (create, then modify-while-active) race and fail.
	if ! nmcli connection add type dummy ifname "$NM_DNS_IFACE" \
	    con-name "$NM_DNS_CONN" autoconnect no \
	    ipv4.method manual ipv4.addresses "$NM_DNS_ADDR" \
	    ipv4.dns "$(echo "$dns_list" | tr ' ' ',')" \
	    ipv4.dns-search "$search" \
	    ipv4.dns-priority -1 \
	    ipv4.ignore-auto-dns yes \
	    ipv4.never-default yes \
	    ipv6.method disabled >/dev/null 2>&1
	then
		log "Failed to create NM DNS profile '$NM_DNS_CONN'; falling back to /etc/resolv.conf"
		setup_fallback_dns "$dns_list" "$domains"
		echo "fallback" > /run/racoon/dns-method 2>/dev/null || true
		return
	fi

	if ! nmcli connection up "$NM_DNS_CONN" >/dev/null 2>&1; then
		log "Failed to activate NM DNS profile '$NM_DNS_CONN'; falling back to /etc/resolv.conf"
		nmcli connection delete "$NM_DNS_CONN" >/dev/null 2>&1 || true
		setup_fallback_dns "$dns_list" "$domains"
		echo "fallback" > /run/racoon/dns-method 2>/dev/null || true
		return
	fi

	mkdir -p /run/racoon
	echo "networkmanager-dummy" > /run/racoon/dns-method 2>/dev/null || true
	log "NM DNS profile '$NM_DNS_CONN' active on $NM_DNS_IFACE: dns=$dns_list domains=$domains"
}

setup_resolvconf_dns() {
	local dns_list="$1" domains="$2" iface="$3"
	[ -z "$dns_list" ] && return 0
	{
		echo "# Generated by racoon phase1-up on $(date)"
		[ -n "$domains" ] && echo "search $(echo "$domains" | tr ',' ' ')"
		for dns in $dns_list; do echo "nameserver ${dns}"; done
	} | resolvconf -a "${iface}.racoon" 2>/dev/null || \
		log "resolvconf failed; falling back"
}

setup_dnsmasq_dns() {
	local dns_list="$1" domains="$2"
	[ -d /etc/dnsmasq.d ] || return 0
	{
		echo "# Generated by racoon phase1-up on $(date)"
		for dns in $dns_list; do echo "server=${dns}"; done
		[ -n "$domains" ] && echo "domain=$(echo "$domains" | tr ',' ' ')"
	} > /etc/dnsmasq.d/racoon-vpn
	killall -HUP dnsmasq 2>/dev/null || true
}

setup_fallback_dns() {
	local dns_list="$1" domains="$2"
	log "WARNING: no supported resolver found; writing /etc/resolv.conf directly"
	cp /etc/resolv.conf /etc/resolv.conf.racoon.bak 2>/dev/null || true
	{
		echo "# Generated by racoon phase1-up on $(date)"
		[ -n "$domains" ] && echo "search $(echo "$domains" | tr ',' ' ')"
		for dns in $dns_list; do echo "nameserver ${dns}"; done
	} > /etc/resolv.conf
}

case "$RESOLVER" in
	systemd-resolved)
		setup_systemd_resolved_dns "${IFACE}" "$DNS_SERVERS" "$SEARCH_DOMAINS"
		;;
	networkmanager)
		setup_networkmanager_dns "$DNS_SERVERS" "$SEARCH_DOMAINS"
		;;
	resolvconf)
		setup_resolvconf_dns "$DNS_SERVERS" "$SEARCH_DOMAINS" "${IFACE}"
		;;
	dnsmasq)
		setup_dnsmasq_dns "$DNS_SERVERS" "$SEARCH_DOMAINS"
		;;
	fallback)
		[ -n "$DNS_SERVERS" ] && setup_fallback_dns "$DNS_SERVERS" "$SEARCH_DOMAINS"
		;;
esac

if [ -n "$SEARCH_DOMAINS" ]; then
	log "Split-DNS search domains applied: ${SEARCH_DOMAINS}"
fi

log "VPN setup complete: routes=$TUNNEL_ROUTES dns=${DNS_SERVERS:-none} domains=${SEARCH_DOMAINS:-none}"
exit 0