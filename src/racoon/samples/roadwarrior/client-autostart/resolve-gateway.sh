#!/bin/sh
#
# resolve-gateway.sh -- bridge between a Dynamic-DNS VPN gateway and
# racoon's static, numeric-only configuration.
#
# racoon rejects hostnames in "remote" blocks (str2saddr() resolves with
# AI_NUMERICHOST) -- needs a literal IP. Neither the VPN gateway's
# public address (Dynamic DNS) nor this laptop's own address
# (WLAN/DHCP roaming) is stable, so both are resolved here and baked
# into a generated file:
#
#   /etc/racoon/gateway.conf  -- the "remote <ip> { ... }" block,
#                                 including mode_cfg/xauth_login and
#                                 the phase1-up/phase1-down script hooks
#
# Unlike a pure static-subnet policy setup, this gateway assigns each
# client a mode_cfg pool address (e.g. 192.168.66.20) that isn't known
# until Phase 1 + Mode Config actually completes -- so there is no
# *guaranteed* fixed selector to pre-install a kernel ACQUIRE trap
# policy for ahead of time. This script covers that gap two ways:
#
#   1. It *actively* initiates Phase 1 itself (the "priming" call at
#      the bottom) at boot/on network changes/on a timer, regardless
#      of whether anything is trying to reach the protected networks
#      yet -- this alone already satisfies "reconnect automatically,
#      ready by the time of a connection attempt".
#   2. It also pre-installs a *best-guess* trap policy using the pool
#      address from the last successful session (cached by
#      phase1-up.sh in /var/lib/racoon/internal-addr4), on the
#      observation that this gateway's pool assignment for a single
#      dedicated login is sticky in practice (the same address came
#      back across repeated test connections). If the guess is right,
#      the very first packet toward a protected network triggers a
#      genuine kernel ACQUIRE with a selector the gateway actually
#      accepts -- real on-demand reconnect, no proactive step needed.
#      If the guess is wrong (or there is no cached address yet), the
#      trap still forces Phase 1 to start, and phase1-up.sh corrects
#      the address/routes/SPD once Mode Config completes -- the
#      triggering packet is lost, but the application's own retry
#      (ping repeats, SSSD/autofs have their own retry logic) then
#      succeeds against the now-correct SPD.
#
# See README.md for the full picture.
#
# Run at boot, on every NetworkManager interface-up event, and on a
# timer (to catch a Dynamic DNS change even while the laptop stays on
# the same network).
#
# The explicit routes (for reverse-path filtering, see below) are
# reinstalled on *every* run, unconditionally -- self-healing against
# anything that flushed them (network manager churn, a manual "ip
# route" while debugging). gateway.conf regeneration, racoon's config
# reload and the priming "establish-sa" call, however, only happen when
# the gateway's or the local address actually changed -- no need to
# bounce Phase 1 every 10 minutes just because the timer fired.

set -eu

GATEWAY_FQDN="nepomuc.selfhost.eu"
NETWORKS="192.168.66.0/24 192.168.83.0/24 10.66.0.0/24"

RACOON_DIR="/etc/racoon"
STATE_DIR="/var/lib/racoon"
STATE_FILE="$STATE_DIR/gw-resolve.state"
GATEWAY_CONF="$RACOON_DIR/gateway.conf"
XAUTH_LOGIN_FILE="$RACOON_DIR/xauth-login"   # one line: the XAuth/LDAP username

log() {
    logger -t racoon-gw-resolve "$*" 2>/dev/null || echo "racoon-gw-resolve: $*" >&2
}

mkdir -p "$STATE_DIR"

if [ ! -r "$XAUTH_LOGIN_FILE" ]; then
    log "missing $XAUTH_LOGIN_FILE (one line: the vpnuser LDAP login) -- cannot build gateway.conf"
    exit 0
fi
XAUTH_LOGIN=$(head -n1 "$XAUTH_LOGIN_FILE")

GATEWAY_IP=$(getent ahostsv4 "$GATEWAY_FQDN" 2>/dev/null | awk '{print $1; exit}') || true
if [ -z "${GATEWAY_IP:-}" ]; then
    log "cannot resolve $GATEWAY_FQDN yet, keeping last known config"
    exit 0
fi

ROUTE_INFO=$(ip -4 route get "$GATEWAY_IP" 2>/dev/null)
LOCAL_IP=$(echo "$ROUTE_INFO" | awk '{for (i = 1; i <= NF; i++) if ($i == "src") print $(i + 1)}')
IFACE=$(echo "$ROUTE_INFO" | awk '{for (i = 1; i <= NF; i++) if ($i == "dev") print $(i + 1)}')
if [ -z "${LOCAL_IP:-}" ] || [ -z "${IFACE:-}" ]; then
    log "no route to $GATEWAY_IP yet, keeping last known config"
    exit 0
fi

NEW_STATE="${GATEWAY_IP}/${LOCAL_IP}/${IFACE}"
OLD_STATE=$(cat "$STATE_FILE" 2>/dev/null || true)
ADDR_CHANGED=1
[ "$NEW_STATE" = "$OLD_STATE" ] && ADDR_CHANGED=0

# --- explicit routes to the protected networks: always reinstalled --
#
# Without a route to each protected network via $IFACE, strict
# reverse-path filtering (net.ipv4.conf.*.rp_filter=1, common distro
# default) drops decrypted inbound packets as a "martian source": the
# kernel can find no route that would send a reply back to e.g.
# 10.66.0.6 out the interface it arrived on, so it silently discards
# the packet *after* successful IPsec decapsulation -- ESP byte
# counters in "setkey -D"/"ip -s xfrm state" increase normally,
# XfrmIn* counters in /proc/net/xfrm_stat stay at 0 (decapsulation
# itself is fine), but the packet never reaches the socket. Confirm
# with "sysctl -w net.ipv4.conf.all.log_martians=1" and watch
# "journalctl -k" for "martian source" while pinging.
#
# "ip route replace" (not "add") so re-running this after the
# interface name changed (a different WLAN adapter, roaming) cleanly
# updates rather than erroring out on a duplicate route.
for net in $NETWORKS; do
    ip route replace "$net" dev "$IFACE"
done
log "gateway=$GATEWAY_IP local=$LOCAL_IP dev=$IFACE -- routes to protected networks (re)installed"

# --- best-guess ACQUIRE trap using the last known pool address ------
#
# Refines the plain routes above with an explicit source (so ordinary
# application traffic actually proposes the guessed pool address, per
# the "source address" lesson learned in phase1-up.sh) and installs a
# matching SPD "require" policy -- unconditionally, on every run, so
# it self-heals the same way the rp_filter routes do. Skipped
# gracefully if there is no cached address yet (first-ever connection
# still relies purely on the active priming call below).
GUESS_FILE="$STATE_DIR/internal-addr4"
if [ -r "$GUESS_FILE" ]; then
    GUESS_ADDR=$(head -n1 "$GUESS_FILE")
    if [ -n "${GUESS_ADDR:-}" ]; then
        ip addr replace "${GUESS_ADDR}/32" dev "$IFACE"
        for net in $NETWORKS; do
            ip route replace "$net" dev "$IFACE" src "$GUESS_ADDR"
        done
        {
            echo "#!/usr/sbin/setkey -f"
            echo "# Generated by resolve-gateway.sh on $(date -Is) -- best-guess trap, do not edit by hand"
            echo "spdflush;"
            for net in $NETWORKS; do
                echo "spdadd ${GUESS_ADDR}/32 $net any -P out ipsec esp/tunnel/${LOCAL_IP}-${GATEWAY_IP}/require;"
                echo "spdadd $net ${GUESS_ADDR}/32 any -P in  ipsec esp/tunnel/${GATEWAY_IP}-${LOCAL_IP}/require;"
            done
        } | setkey -c
        log "gateway=$GATEWAY_IP local=$LOCAL_IP dev=$IFACE -- best-guess trap installed for internal=$GUESS_ADDR (from last session)"
    fi
else
    log "no cached pool address yet ($GUESS_FILE missing) -- relying on active priming only until the first successful connection"
fi

if [ "$ADDR_CHANGED" -eq 0 ]; then
    exit 0   # address unchanged -- no need to touch racoon/Phase 1
fi

log "gateway=$GATEWAY_IP local=$LOCAL_IP (was: ${OLD_STATE:-none}) -- address changed, refreshing gateway.conf"

# --- remote block: only rewritten/reloaded when the address changed -
#
# Mirrors vpngateway.racoon.conf's "remote anonymous" block as closely
# as a single named client can: exchange_mode main, asn1dn identities,
# xauth_rsa_client/dh_group 14 (the gateway also offers dh_group 16,
# but 14 is the proposal shared with the iPhone/Mac Cisco IPSec
# clients this gateway is tuned for -- see README.md), mode_cfg on to
# pull the pool address, xauth_login for the XAuth username (the
# password itself lives in /etc/racoon/psk.txt, keyed by that same
# login -- see racoon.conf(5) "xauth_login" and README.md).
umask 077
{
    echo "# Generated by resolve-gateway.sh on $(date -Is) -- do not edit by hand"
    echo "remote $GATEWAY_IP"
    echo "{"
    echo "    exchange_mode           main;"
    echo "    my_identifier            asn1dn;"
    echo "    peers_identifier         asn1dn;"
    echo "    verify_identifier        on;"
    echo "    verify_cert              on;"
    echo ""
    echo "    certificate_type         x509 \"client.crt\" \"client.key\";"
    echo "    ca_type                  x509 \"ca.crt\";"
    echo ""
    echo "    passive                  off;"
    echo "    ike_frag                 on;"
    echo "    nat_traversal             on;"
    echo "    dpd_delay                30;"
    echo "    dpd_retry                 5;"
    echo "    dpd_maxfail                3;"
    echo "    proposal_check             claim;"
    echo "    lifetime                   time 24 hour;"
    echo ""
    echo "    mode_cfg                   on;"
    echo "    xauth_login                \"${XAUTH_LOGIN}\";"
    echo ""
    echo "    script \"/etc/racoon/phase1-up.sh\"   phase1_up;"
    echo "    script \"/etc/racoon/phase1-down.sh\" phase1_down;"
    echo ""
    echo "    proposal {"
    echo "        encryption_algorithm    aes 256;"
    echo "        hash_algorithm          sha256;"
    echo "        authentication_method   xauth_rsa_client;"
    echo "        dh_group                 14;"
    echo "    }"
    echo "}"
} > "$GATEWAY_CONF.new"
mv "$GATEWAY_CONF.new" "$GATEWAY_CONF"

echo "$NEW_STATE" > "$STATE_FILE"

# Make racoon pick up the new/changed remote block.
if pidof racoon >/dev/null 2>&1 && command -v racoonctl >/dev/null 2>&1; then
    racoonctl reload-config >/dev/null 2>&1 || kill -HUP "$(pidof racoon)" 2>/dev/null || true

    # Best-effort: ask racoon to start Phase 1 (+ Mode Config, +
    # phase1-up.sh's SPD install) right away instead of waiting for
    # the best-guess trap above (or an actual application packet) to
    # do it -- this is what makes the tunnel come up within seconds of
    # boot/reconnect even if nothing has tried to use it yet, rather
    # than only reacting once something does. Deliberately NOT
    # "racoonctl vc": that shortcut blocks waiting for the mode_cfg
    # completion event, which is fine in principle here (we *do* use
    # mode_cfg), but it also requires "-u <user>" for the XAuth prompt
    # and would hang this unattended script waiting on a password
    # that's already supplied via xauth_login/psk.txt. The low-level
    # "establish-sa" without "-w" fires the request and returns
    # immediately; the rest of the exchange (Mode Config, XAuth using
    # the configured login/psk.txt password) proceeds inside racoon on
    # its own.
    racoonctl es isakmp inet "$LOCAL_IP" "$GATEWAY_IP" >/dev/null 2>&1 || true
fi

log "done"
