#!/bin/sh
#
# phase1-common.sh - shared helpers for phase1-up.sh / phase1-down.sh
#
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (C) 2024-2026 Thomas Reim and the racoon-ipsec-tools contributors
# Part of rdratlos/racoon-ipsec-tools — https://github.com/rdratlos/racoon-ipsec-tools

# ---------------------------------------------------------------------------
# resolve_target() — resolve /etc/resolv.conf to its final (non-symlink) file.
#   Returns the absolute path, or /etc/resolv.conf if not a symlink.
# ---------------------------------------------------------------------------
resolve_target() {
	local target="/etc/resolv.conf"
	if [ -L "$target" ]; then
		local link
		link=$(readlink -f "$target" 2>/dev/null) || link=$(readlink "$target")
		[ -n "$link" ] && echo "$link" || echo "$target"
	else
		echo "$target"
	fi
}

# ---------------------------------------------------------------------------
# detect_resolver() — detect the active DNS manager from /etc/resolv.conf's
# real target, not from binary/service presence.  This is the canonical
# source of truth because even if systemd-resolved is installed, the distro
# may have switched to another resolver and only /etc/resolv.conf reflects
# the current arrangement.
#
# Returns one of: systemd-resolved | networkmanager | resolvconf | dnsmasq | fallback
# ---------------------------------------------------------------------------
detect_resolver() {
	local rt
	rt=$(resolve_target)
	case "$rt" in
		/run/systemd/resolve/*)
			echo "systemd-resolved" ;;
		/run/NetworkManager/*)
			echo "networkmanager" ;;
		/run/resolvconf/*)
			echo "resolvconf" ;;
		/lib/systemd/resolve/*)
			# Fallback path used when /run is tmpfs
			echo "systemd-resolved" ;;
		*)
			echo "fallback" ;;
	esac
}

# ---------------------------------------------------------------------------
# validate_nm_dns_backend() — check that NM's dns= setting is compatible
# with split-DNS routing.  NM's dns=default mode cannot do per-domain DNS
# routing; it replaces /etc/resolv.conf wholesale.  Return 0 if OK, 1 if
# dns=default (full-redirect only).
# ---------------------------------------------------------------------------
validate_nm_dns_backend() {
	# Try --print-config first (NM >= 1.22), fall back to reading conf.d.
	local dns_backend
	dns_backend=$(nmcli -t -f dns general print 2>/dev/null) || true
	if [ -n "$dns_backend" ]; then
		case "$dns_backend" in
			systemd-resolved|dnsmasq) return 0 ;;
			default) return 1 ;;
		esac
	else
		# Older NM: check main config file
		if [ -f /etc/NetworkManager/NetworkManager.conf ]; then
			local v
			v=$(grep -E '^\s*dns\s*=' /etc/NetworkManager/NetworkManager.conf 2>/dev/null \
			    | head -n1 | sed 's/.*=\s*//') || true
			case "$v" in
				systemd-resolved|dnsmasq) return 0 ;;
				default|"") return 1 ;;
			esac
		fi
		# Assume OK if we can't determine
		return 0
	fi
}

# ---------------------------------------------------------------------------
# racoon_vpn0_ifname() — return the dummy interface name we use for NM DNS.
# ---------------------------------------------------------------------------
racoon_vpn0_ifname() {
	echo "racoon-vpn0"
}

# ---------------------------------------------------------------------------
# racoon_vpn_connname() — return the NM connection profile name.
# ---------------------------------------------------------------------------
racoon_vpn_connname() {
	echo "racoon-vpn"
}