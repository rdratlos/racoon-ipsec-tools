#!/bin/sh
#
# test-roadwarrior-loop.sh -- roadwarrior client integration test
#
# Repeatedly connects to a racoon roadwarrior VPN gateway via racoonctl,
# exercises the tunnel (ping + DNS lookups) and disconnects again, for a
# configurable number of iterations.
#
# racoon itself (and its admin port) must already be running; this script
# only drives it through the unprivileged racoonctl client, plus ping and
# a DNS lookup tool, so it does not need to run as root as long as
# racoonctl's admin socket/port is reachable by the calling user and the
# system ping binary is usable unprivileged (setuid/capability-enabled,
# as is the default on most distributions).
#
# Required environment variables:
#   VPN_GATEWAY           Hostname/IP of the VPN gateway (racoonctl vc/vd target)
#   VPN_USER              Xauth login name passed to "racoonctl vc -u"
#   PING_HOST             Host inside the tunneled network to ping
#   INTERNAL_DNS_SERVER   IP address of the internal DNS server pushed by the VPN
#   INTERNAL_DNS_HOST     Internal-only hostname resolved via INTERNAL_DNS_SERVER
#
# Optional environment variables:
#   VPN_PASSWORD          Xauth password. If unset, racoon.conf is expected to
#                         supply it (e.g. via xauth_login + psk.txt) so that
#                         racoonctl never prompts.
#   EXTERNAL_DNS_HOST     Internet FQDN resolved via the default resolver
#                         (default: www.example.com)
#   LOOP_COUNT            Number of iterations (default: 50)
#   PING_COUNT            Number of pings per iteration (default: 3)
#   CONNECT_TIMEOUT       Seconds to wait for the connection to come up (default: 20)
#   DISCONNECT_TIMEOUT    Seconds to wait for the disconnection to complete (default: 15)
#   ITERATION_DELAY       Seconds to sleep between iterations (default: 5)
#   RACOONCTL             Path to the racoonctl binary (default: racoonctl)
#
# Exit status: 0 if every iteration succeeded, 1 otherwise.

set -u

: "${LOOP_COUNT:=50}"
: "${PING_COUNT:=3}"
: "${CONNECT_TIMEOUT:=20}"
: "${DISCONNECT_TIMEOUT:=15}"
: "${ITERATION_DELAY:=5}"
: "${RACOONCTL:=racoonctl}"
: "${EXTERNAL_DNS_HOST:=www.example.com}"
: "${VPN_PASSWORD:=}"

for var in VPN_GATEWAY VPN_USER PING_HOST INTERNAL_DNS_SERVER INTERNAL_DNS_HOST; do
	eval "val=\${${var}:-}"
	if [ -z "$val" ]; then
		echo "ERROR: required environment variable $var is not set" >&2
		exit 2
	fi
done

# Pick the DNS lookup tool(s) available on this system once, up front.
DNS_DEFAULT_TOOL=""
if command -v resolvectl >/dev/null 2>&1; then
	DNS_DEFAULT_TOOL="resolvectl"
elif command -v systemd-resolve >/dev/null 2>&1; then
	DNS_DEFAULT_TOOL="systemd-resolve"
elif command -v host >/dev/null 2>&1; then
	DNS_DEFAULT_TOOL="host"
elif command -v getent >/dev/null 2>&1; then
	DNS_DEFAULT_TOOL="getent"
elif command -v dig >/dev/null 2>&1; then
	DNS_DEFAULT_TOOL="dig"
elif command -v nslookup >/dev/null 2>&1; then
	DNS_DEFAULT_TOOL="nslookup"
else
	echo "ERROR: no DNS lookup tool found (tried resolvectl, systemd-resolve, host, getent, dig, nslookup)" >&2
	exit 2
fi

DNS_SERVER_TOOL=""
if command -v dig >/dev/null 2>&1; then
	DNS_SERVER_TOOL="dig"
elif command -v host >/dev/null 2>&1; then
	DNS_SERVER_TOOL="host"
elif command -v nslookup >/dev/null 2>&1; then
	DNS_SERVER_TOOL="nslookup"
else
	echo "ERROR: no tool able to query a specific DNS server found (tried dig, host, nslookup)" >&2
	exit 2
fi

log() {
	echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"
}

# Resolve a name using the default/system resolver.
dns_lookup_default() {
	name="$1"
	case "$DNS_DEFAULT_TOOL" in
	resolvectl)	resolvectl query "$name" ;;
	systemd-resolve) systemd-resolve "$name" ;;
	host)		host "$name" ;;
	getent)		getent hosts "$name" ;;
	dig)		dig +short "$name" ;;
	nslookup)	nslookup "$name" ;;
	esac
}

# Resolve a name against a specific DNS server.
dns_lookup_server() {
	name="$1"
	server="$2"
	case "$DNS_SERVER_TOOL" in
	dig)	dig "@${server}" +short "$name" ;;
	host)	host "$name" "$server" ;;
	nslookup) nslookup "$name" "$server" ;;
	esac
}

connect_vpn() {
	set -- vc -u "$VPN_USER" "$VPN_GATEWAY"
	if [ -n "$VPN_PASSWORD" ]; then
		printf '%s\n' "$VPN_PASSWORD" | timeout "$CONNECT_TIMEOUT" "$RACOONCTL" "$@" 2>&1
	else
		timeout "$CONNECT_TIMEOUT" "$RACOONCTL" "$@" </dev/null 2>&1
	fi
}

disconnect_vpn() {
	timeout "$DISCONNECT_TIMEOUT" "$RACOONCTL" vd "$VPN_GATEWAY" </dev/null 2>&1
}

pass=0
fail=0

cleanup() {
	log "Interrupted, attempting to disconnect before exit..."
	disconnect_vpn >/dev/null 2>&1
	exit 130
}
trap cleanup INT TERM

i=1
while [ "$i" -le "$LOOP_COUNT" ]; do
	log "=== Iteration $i/$LOOP_COUNT ==="
	iteration_ok=1

	log "Connecting to VPN gateway $VPN_GATEWAY as $VPN_USER..."
	connect_out=$(connect_vpn)
	echo "$connect_out"
	if echo "$connect_out" | grep -q "VPN connexion established"; then
		log "Connection established."
	else
		log "FAIL: could not establish VPN connection."
		iteration_ok=0
	fi

	if [ "$iteration_ok" -eq 1 ]; then
		log "Pinging $PING_HOST ($PING_COUNT packets)..."
		if ping -c "$PING_COUNT" "$PING_HOST"; then
			log "Ping to $PING_HOST succeeded."
		else
			log "FAIL: ping to $PING_HOST failed."
			iteration_ok=0
		fi

		log "Resolving $INTERNAL_DNS_HOST via internal DNS server $INTERNAL_DNS_SERVER (using $DNS_SERVER_TOOL)..."
		if dns_lookup_server "$INTERNAL_DNS_HOST" "$INTERNAL_DNS_SERVER"; then
			log "Internal DNS lookup succeeded."
		else
			log "FAIL: internal DNS lookup of $INTERNAL_DNS_HOST via $INTERNAL_DNS_SERVER failed."
			iteration_ok=0
		fi

		log "Resolving $EXTERNAL_DNS_HOST via default resolver (using $DNS_DEFAULT_TOOL)..."
		if dns_lookup_default "$EXTERNAL_DNS_HOST"; then
			log "External DNS lookup succeeded."
		else
			log "FAIL: external DNS lookup of $EXTERNAL_DNS_HOST failed."
			iteration_ok=0
		fi
	fi

	log "Disconnecting from VPN gateway $VPN_GATEWAY..."
	disconnect_out=$(disconnect_vpn)
	echo "$disconnect_out"
	if echo "$disconnect_out" | grep -q "Phase 1 deleted"; then
		log "Disconnection confirmed."
	else
		log "FAIL: could not confirm VPN disconnection."
		iteration_ok=0
	fi

	if [ "$iteration_ok" -eq 1 ]; then
		pass=$((pass + 1))
		log "Iteration $i: PASS"
	else
		fail=$((fail + 1))
		log "Iteration $i: FAIL"
	fi

	i=$((i + 1))
	if [ "$i" -le "$LOOP_COUNT" ]; then
		log "Waiting ${ITERATION_DELAY}s before next iteration..."
		sleep "$ITERATION_DELAY"
	fi
done

log "=== Summary: $pass passed, $fail failed, out of $LOOP_COUNT iterations ==="
[ "$fail" -eq 0 ]
