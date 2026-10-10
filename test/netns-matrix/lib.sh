#!/bin/sh
# Shared helpers for the netns matrix (see README.md).
#
# Two network namespaces, rnm-a (192.0.2.1) and rnm-b (192.0.2.2), joined by a
# veth pair. Each namespace gets one "LAN" address on its loopback (10.1.0.1 in
# rnm-a, 10.2.0.1 in rnm-b) so tunnel mode has something to protect without
# needing a dummy device. A racoon instance runs in each namespace; both use
# the host kernel's real IPsec stack.
#
# POSIX sh. No bashisms.

NS_A=${NS_A:-rnm-a}
NS_B=${NS_B:-rnm-b}
IP_A=192.0.2.1
IP_B=192.0.2.2
LAN_A=10.1.0.1
LAN_B=10.2.0.1
PSK=rnm-ci-psk-0123456789abcdef

RNM_OUT=${RNM_OUT:-/tmp/rnm-logs}
RACOON_BIN=${RACOON_BIN:-$(command -v racoon 2>/dev/null || true)}
SETKEY_BIN=${SETKEY_BIN:-$(command -v setkey 2>/dev/null || true)}

# Kernel interface racoon is driving. Today only the PF_KEY backend exists; the
# XFRM backend of RFC 0002 will run the same rows with RNM_BACKEND=xfrm.
RNM_BACKEND=${RNM_BACKEND:-pfkey}

# Per-row result flags, reset by run.sh before every row.
R_FAIL=0
R_SKIP=
R_XFAIL=0

log() { printf '%s\n' "$*"; }

# fail MSG: record a failure for the current row and keep going so one run
# reports every broken assertion, not just the first.
fail() {
	R_FAIL=1
	log "FAIL: $*"
}

# xfail MSG: a documented, expected deviation. The row stays red-capable for
# everything else; see icv_verdict() for how it is kept honest.
xfail() {
	R_XFAIL=1
	log "XFAIL: $*"
	[ "${GITHUB_ACTIONS:-}" = true ] && log "::warning title=Known defect::$*"
	return 0
}

# skip REASON: the row cannot run in this environment. run.sh turns this into
# a failure when RNM_REQUIRE_LIVE=1 (CI), so a skip can never hide a gap.
skip() { R_SKIP=$1; }

# setkey_fail_reason TEXT: classify why `setkey -D` failed, from its output.
# A binary that cannot even start (missing shared library, bad path) must not
# be reported as a kernel without PF_KEY.
setkey_fail_reason() {
	case $1 in
	*"Address family not supported"*|*"Protocol not supported"*)
		echo "PF_KEY unavailable (CONFIG_NET_KEY / af_key): $1" ;;
	*"error while loading shared libraries"*|*"not found"*|*"cannot execute"*|*"Permission denied"*)
		echo "setkey cannot run (installation problem, not the kernel; try ldconfig): $1" ;;
	*)
		echo "setkey -D failed: $1" ;;
	esac
}

# ---------------------------------------------------------------------------
# Environment preflight. Prints the reason and returns 1 when live rows cannot
# run here. RNM_FAKE_UNMET is a test-only hook used by selftest.sh.
# ---------------------------------------------------------------------------
preflight() {
	if [ -n "${RNM_FAKE_UNMET:-}" ]; then
		echo "$RNM_FAKE_UNMET"
		return 1
	fi
	[ "$(id -u)" = 0 ] || { echo "not root"; return 1; }
	for t in ip ping; do
		command -v "$t" >/dev/null 2>&1 || { echo "missing tool: $t"; return 1; }
	done
	[ -n "$RACOON_BIN" ] && [ -x "$RACOON_BIN" ] || { echo "racoon binary not found (set RACOON_BIN)"; return 1; }
	[ -n "$SETKEY_BIN" ] && [ -x "$SETKEY_BIN" ] || { echo "setkey binary not found (set SETKEY_BIN)"; return 1; }

	# Best effort: load what a hosted runner may have as modules.
	modprobe -a af_key esp4 xfrm_user xfrm_algo 2>/dev/null || true

	_pf=rnm-probe
	ip netns del "$_pf" 2>/dev/null || true
	_err=$(ip netns add "$_pf" 2>&1) || { echo "cannot create netns: $_err"; return 1; }
	_rc=0
	_reason=
	# PF_KEY (racoon's only kernel interface today) must work inside a netns.
	_out=$("$RACOON_BIN" -V 2>&1) || {
		_rc=1
		_reason="racoon cannot run (installation problem, not the kernel; try ldconfig): $_out"
	}
	if [ "$_rc" = 0 ]; then
		_out=$(ip netns exec "$_pf" "$SETKEY_BIN" -D 2>&1) || {
			_rc=1
			_reason=$(setkey_fail_reason "$_out")
		}
	fi
	# ESP with an authenticated-truncated algorithm must be installable.
	if [ "$_rc" = 0 ]; then
		_err=$(ip -n "$_pf" xfrm state add src "$IP_A" dst "$IP_B" proto esp \
			spi 0x100 mode transport \
			auth-trunc 'hmac(sha256)' 0x0000000000000000000000000000000000000000000000000000000000000000 128 \
			enc 'cbc(aes)' 0x00000000000000000000000000000000 2>&1) || {
			_rc=1
			_reason="kernel cannot install ESP + hmac(sha256) (esp4/crypto missing?): $_err"
		}
	fi
	ip netns del "$_pf" 2>/dev/null || true
	[ "$_rc" = 0 ] || { echo "$_reason"; return 1; }
	return 0
}

# ---------------------------------------------------------------------------
# Topology
# ---------------------------------------------------------------------------
ns_down() {
	for _ns in "$NS_A" "$NS_B"; do
		if [ -f "$RNM_RUN/$_ns.pid" ]; then
			kill "$(cat "$RNM_RUN/$_ns.pid")" 2>/dev/null || true
		fi
		ip netns del "$_ns" 2>/dev/null || true
	done
}

ns_up() {
	ns_down
	ip netns add "$NS_A" && ip netns add "$NS_B" || return 1
	ip link add rnm-veth-a type veth peer name rnm-veth-b || return 1
	ip link set rnm-veth-a netns "$NS_A" || return 1
	ip link set rnm-veth-b netns "$NS_B" || return 1
	ip -n "$NS_A" addr add "$IP_A/24" dev rnm-veth-a || return 1
	ip -n "$NS_B" addr add "$IP_B/24" dev rnm-veth-b || return 1
	ip -n "$NS_A" link set rnm-veth-a up || return 1
	ip -n "$NS_B" link set rnm-veth-b up || return 1
	ip -n "$NS_A" link set lo up && ip -n "$NS_B" link set lo up || return 1
	# "LAN" addresses live on loopback (no dummy device needed).
	ip -n "$NS_A" addr add "$LAN_A/32" dev lo || return 1
	ip -n "$NS_B" addr add "$LAN_B/32" dev lo || return 1
	ip -n "$NS_A" route add 10.2.0.0/24 via "$IP_B" || return 1
	ip -n "$NS_B" route add 10.1.0.0/24 via "$IP_A" || return 1
	for _ns in "$NS_A" "$NS_B"; do
		ip netns exec "$_ns" sysctl -qw net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.default.rp_filter=0 2>/dev/null || true
	done
	# Underlay sanity: plain connectivity before any IPsec.
	ip netns exec "$NS_A" ping -c 1 -W 2 "$IP_B" >/dev/null 2>&1 || {
		log "underlay ping $IP_A -> $IP_B failed"
		return 1
	}
	return 0
}

# ---------------------------------------------------------------------------
# racoon
# ---------------------------------------------------------------------------
# racoon_start NS CONF LOG: start racoon in NS, wait until it listens on 500.
racoon_start() {
	_ns=$1
	_conf=$2
	_log=$3
	ip netns exec "$_ns" "$RACOON_BIN" -F -f "$_conf" -l "$_log" >"$_log.out" 2>&1 &
	echo $! >"$RNM_RUN/$_ns.pid"
	_i=0
	while [ "$_i" -lt 50 ]; do
		kill -0 "$(cat "$RNM_RUN/$_ns.pid")" 2>/dev/null || {
			log "racoon in $_ns exited during startup:"
			tail -n 20 "$_log.out" "$_log" 2>/dev/null
			return 1
		}
		if ip netns exec "$_ns" ss -uln 2>/dev/null | grep -q ':500 '; then
			return 0
		fi
		sleep 0.2
		_i=$((_i + 1))
	done
	log "racoon in $_ns did not start listening on UDP/500"
	tail -n 20 "$_log.out" "$_log" 2>/dev/null
	return 1
}

# gen_conf SIDE MODE AUTH: print a racoon.conf for SIDE (a|b).
#   MODE transport|tunnel   AUTH sha1|sha256 (phase 2 HMAC)   LIFE seconds
gen_conf() {
	_side=$1
	_mode=$2
	_auth=$3
	_life=$4
	if [ "$_side" = a ]; then
		_me=$IP_A
		_peer=$IP_B
		_lme=10.1.0.0/24
		_lpeer=10.2.0.0/24
	else
		_me=$IP_B
		_peer=$IP_A
		_lme=10.2.0.0/24
		_lpeer=10.1.0.0/24
	fi
	cat <<EOF
path pre_shared_key "$RNM_RUN/psk-$_side.txt";
path pidfile "$RNM_RUN/racoon-$_side.pid";
log debug;
listen {
	isakmp $_me [500];
	adminsock disabled;
}
remote $_peer {
	exchange_mode main;
	my_identifier address $_me;
	nat_traversal off;
	proposal_check obey;
	proposal {
		encryption_algorithm aes 128;
		hash_algorithm sha256;
		authentication_method pre_shared_key;
		dh_group modp2048;
		lifetime time 600 sec;
	}
}
EOF
	if [ "$_mode" = tunnel ]; then
		echo "sainfo address $_lme any address $_lpeer any {"
	else
		echo "sainfo anonymous {"
	fi
	cat <<EOF
	pfs_group modp2048;
	encryption_algorithm aes;
	authentication_algorithm hmac_$_auth;
	# racoon rejects a sainfo without all three algorithm classes
	# (cfparse.y: "no compression algorithm"). IPComp is only negotiated
	# if a policy asks for it; these policies request ESP only.
	compression_algorithm deflate;
	lifetime time $_life sec;
}
EOF
}

# gen_policy SIDE MODE: print setkey policies for SIDE.
gen_policy() {
	_side=$1
	_mode=$2
	echo "flush;"
	echo "spdflush;"
	if [ "$_mode" = tunnel ]; then
		if [ "$_side" = a ]; then
			echo "spdadd 10.1.0.0/24 10.2.0.0/24 any -P out ipsec esp/tunnel/$IP_A-$IP_B/require;"
			echo "spdadd 10.2.0.0/24 10.1.0.0/24 any -P in ipsec esp/tunnel/$IP_B-$IP_A/require;"
		else
			echo "spdadd 10.2.0.0/24 10.1.0.0/24 any -P out ipsec esp/tunnel/$IP_B-$IP_A/require;"
			echo "spdadd 10.1.0.0/24 10.2.0.0/24 any -P in ipsec esp/tunnel/$IP_A-$IP_B/require;"
		fi
	else
		if [ "$_side" = a ]; then
			echo "spdadd $IP_A $IP_B any -P out ipsec esp/transport//require;"
			echo "spdadd $IP_B $IP_A any -P in ipsec esp/transport//require;"
		else
			echo "spdadd $IP_B $IP_A any -P out ipsec esp/transport//require;"
			echo "spdadd $IP_A $IP_B any -P in ipsec esp/transport//require;"
		fi
	fi
}

# stage_pair MODE AUTH LIFE: write configs/policies, install policies, start
# both daemons. Returns 1 on any setup error.
stage_pair() {
	_mode=$1
	_auth=$2
	_life=$3
	for _s in a b; do
		if [ "$_s" = a ]; then
			_ns=$NS_A
			_peer=$IP_B
		else
			_ns=$NS_B
			_peer=$IP_A
		fi
		printf '%s %s\n' "$_peer" "$PSK" >"$RNM_RUN/psk-$_s.txt"
		chmod 600 "$RNM_RUN/psk-$_s.txt"
		gen_conf "$_s" "$_mode" "$_auth" "$_life" >"$RNM_RUN/racoon-$_s.conf"
		gen_policy "$_s" "$_mode" >"$RNM_RUN/policy-$_s.txt"
		ip netns exec "$_ns" "$SETKEY_BIN" -c <"$RNM_RUN/policy-$_s.txt" >"$RNM_RUN/setkey-$_s.out" 2>&1 || {
			log "setkey failed in $_ns:"
			cat "$RNM_RUN/setkey-$_s.out"
			return 1
		}
	done
	racoon_start "$NS_B" "$RNM_RUN/racoon-b.conf" "$RNM_RUN/racoon-b.log" || return 1
	racoon_start "$NS_A" "$RNM_RUN/racoon-a.conf" "$RNM_RUN/racoon-a.log" || return 1
	return 0
}

# ---------------------------------------------------------------------------
# Traffic
# ---------------------------------------------------------------------------
# ping_src_dst: which addresses carry traffic for MODE.
traffic_pair() {
	if [ "$1" = tunnel ]; then
		TP_SRC=$LAN_A
		TP_DST=$LAN_B
	else
		TP_SRC=$IP_A
		TP_DST=$IP_B
	fi
}

# wait_ping NS SRC DST TRIES: the first packets are dropped while IKE
# negotiates, so retry until one echo reply makes it through.
wait_ping() {
	_i=0
	while [ "$_i" -lt "$4" ]; do
		if ip netns exec "$1" ping -I "$2" -c 1 -W 1 "$3" >/dev/null 2>&1; then
			return 0
		fi
		_i=$((_i + 1))
	done
	return 1
}

# ---------------------------------------------------------------------------
# Kernel state inspection (pure parsers are separated so selftest.sh can feed
# them canned output)
# ---------------------------------------------------------------------------

# sad_auth_trunc_bits: read `ip xfrm state` text on stdin, print the truncation
# length of the first "auth-trunc ALG 0xKEY BITS" line for ALG. Prints nothing
# if there is no such line (e.g. legacy "auth ALG", which has no truncation).
sad_auth_trunc_bits() {
	awk -v alg="$1" '
		$1 == "auth-trunc" && $2 == alg { print $4; exit }'
}

# known_icv_bits BACKEND ALG: the wrong ICV length a backend is KNOWN to
# install for ALG (empty when there is no known defect). PF_KEY carries only an
# algorithm id, so Linux applies its own default truncation: 96 bits for
# hmac(sha256) instead of the 128 bits of RFC 4868. Measured on a GitHub-hosted
# runner, kernel 6.17.0-1022-azure.
known_icv_bits() {
	case "$1:$2" in
	pfkey:'hmac(sha256)') echo 96 ;;
	esac
}

# icv_verdict BACKEND XFAIL ALG WANT GOT: print PASS, FAIL, XFAIL or XPASS.
#   XFAIL only if the row opted in (XFAIL=1), the backend has a known defect
#         for ALG, and GOT is exactly that known wrong value.
#   XPASS (reported as a failure) if the row opted in but the ICV is correct,
#         so a fixed defect cannot keep its marker.
#   Anything else that differs from WANT is a plain FAIL.
icv_verdict() {
	_known=$(known_icv_bits "$1" "$3")
	if [ "$5" = "$4" ]; then
		if [ "$2" = 1 ] && [ -n "$_known" ]; then echo XPASS; else echo PASS; fi
		return 0
	fi
	if [ "$2" = 1 ] && [ -n "$_known" ] && [ "$5" = "$_known" ]; then
		echo XFAIL
		return 0
	fi
	echo FAIL
}

# sad_spis: print the sorted ESP SPIs in `ip xfrm state` text on stdin.
sad_spis() {
	awk '$1 == "proto" && $2 == "esp" { for (i = 1; i < NF; i++) if ($i == "spi") print $(i + 1) }' | sort -u
}

# new_spis OLD: read SPIs on stdin, print those not present in the OLD list.
new_spis() {
	while read -r _s; do
		printf '%s\n' "$1" | grep -qxF "$_s" || echo "$_s"
	done
}

# loss_ok PCT MAX: succeed when PCT <= MAX (both may be decimals).
loss_ok() {
	awk -v p="$1" -v m="$2" 'BEGIN { exit !(p + 0 <= m + 0) }'
}

# sad_packets: sum the "(packets)" lifetime counters in `ip -s xfrm state`.
sad_packets() {
	grep -oE '[0-9]+\(packets\)' | sed 's/(packets)//' | awk '{ s += $1 } END { print s + 0 }'
}

# stat_sum FILE NAME...: sum the listed counters from a /proc/net/xfrm_stat dump.
stat_sum() {
	_f=$1
	shift
	awk -v names="$*" '
		BEGIN { n = split(names, a, " "); for (i = 1; i <= n; i++) want[a[i]] = 1 }
		($1 in want) { s += $2 }
		END { print s + 0 }' "$_f"
}

# Counters that indicate a broken data path (integrity, replay, mode, state).
XFRM_ERR_COUNTERS="XfrmInError XfrmInBufferError XfrmInHdrError XfrmInStateProtoError XfrmInStateModeError XfrmInStateSeqError XfrmInStateMismatch XfrmInTmplMismatch XfrmOutError XfrmOutBundleGenError XfrmOutBundleCheckError XfrmOutStateProtoError XfrmOutStateModeError XfrmOutStateSeqError"

xfrm_stat_dump() { ip netns exec "$1" cat /proc/net/xfrm_stat; }

# collect_logs ROW: keep daemon logs and kernel state for artifact upload.
collect_logs() {
	_d="$RNM_OUT/$1"
	mkdir -p "$_d"
	# PSK files are deliberately not copied (and are 0600 root-only anyway).
	cp "$RNM_RUN"/*.log "$RNM_RUN"/*.out "$RNM_RUN"/*.conf "$_d"/ 2>/dev/null || true
	for _f in "$RNM_RUN"/policy-*.txt "$RNM_RUN"/setkey-*.out; do
		[ -f "$_f" ] && cp "$_f" "$_d"/ 2>/dev/null
	done
	for _ns in "$NS_A" "$NS_B"; do
		ip -n "$_ns" xfrm state >"$_d/sad-$_ns.txt" 2>&1 || true
		ip -n "$_ns" xfrm policy >"$_d/spd-$_ns.txt" 2>&1 || true
		xfrm_stat_dump "$_ns" >"$_d/xfrm_stat-$_ns.txt" 2>&1 || true
	done
}
