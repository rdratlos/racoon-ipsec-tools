#!/bin/sh
# kind_psk NAME ARGS: racoon <-> racoon, PSK, main mode, over a real kernel.
#
# ARGS (space separated key=value):
#   mode=transport|tunnel   IPsec mode
#   auth=sha1|sha256        phase 2 HMAC
#   rekey=0|1               1: short SA lifetime, assert a new SA replaces the
#                           old one while traffic keeps flowing
#
# Assertions, all against the live kernel:
#   1. both SADs hold ESP SAs and the negotiated HMAC carries the RFC
#      truncation (hmac(sha1) 96, hmac(sha256) 128)
#   2. traffic really crosses the tunnel: ping succeeds, the ESP packet
#      counters on both sides moved, and no XFRM error counter moved
#   3. (rekey=1) a new SPI appears while a long ping loses little
kind_psk() {
	_name=$1
	_mode=transport
	_auth=sha256
	_rekey=0
	for _kv in $2; do
		case $_kv in
		mode=*) _mode=${_kv#mode=} ;;
		auth=*) _auth=${_kv#auth=} ;;
		rekey=*) _rekey=${_kv#rekey=} ;;
		esac
	done
	case $_auth in
	sha1) _want_trunc=96; _want_alg='hmac(sha1)' ;;
	sha256) _want_trunc=128; _want_alg='hmac(sha256)' ;;
	*) fail "unknown auth=$_auth"; return 0 ;;
	esac
	_life=3600
	[ "$_rekey" = 1 ] && _life=30

	ns_up || { fail "cannot build topology"; return 0; }
	stage_pair "$_mode" "$_auth" "$_life" || { fail "cannot start racoon pair"; return 0; }
	traffic_pair "$_mode"

	# Negotiate: the first packets trigger ACQUIRE -> phase 1 -> phase 2.
	if ! wait_ping "$NS_A" "$TP_SRC" "$TP_DST" 30; then
		fail "no echo reply through the tunnel after 30 tries (negotiation failed?)"
		return 0
	fi
	log "tunnel carries traffic ($_mode, $_want_alg)"

	# 1. SAD content, both sides.
	for _ns in "$NS_A" "$NS_B"; do
		_sad=$(ip -n "$_ns" xfrm state 2>&1)
		_n=$(printf '%s\n' "$_sad" | grep -c 'proto esp')
		[ "$_n" -ge 2 ] || fail "$_ns: expected >=2 ESP SAs, found $_n"
		_bits=$(printf '%s\n' "$_sad" | sad_auth_trunc_bits "$_want_alg")
		if [ -z "$_bits" ]; then
			fail "$_ns: no 'auth-trunc $_want_alg' in SAD (legacy 'auth' attribute or wrong algorithm)"
		elif [ "$_bits" != "$_want_trunc" ]; then
			fail "$_ns: $_want_alg ICV is $_bits bits, expected $_want_trunc"
		else
			log "$_ns: $_want_alg ICV $_bits bits OK"
		fi
	done

	# 2. Data plane: steady traffic, counters moved, no error counters moved.
	xfrm_stat_dump "$NS_A" >"$RNM_RUN/stat-a.before"
	xfrm_stat_dump "$NS_B" >"$RNM_RUN/stat-b.before"
	_pk0a=$(ip -n "$NS_A" -s xfrm state | sad_packets)
	_pk0b=$(ip -n "$NS_B" -s xfrm state | sad_packets)
	if ip netns exec "$NS_A" ping -I "$TP_SRC" -c 20 -i 0.2 -W 1 "$TP_DST" >"$RNM_RUN/ping-steady.out" 2>&1; then
		log "steady ping: $(grep -E 'packet loss' "$RNM_RUN/ping-steady.out")"
	else
		fail "steady ping lost packets: $(grep -E 'packet loss' "$RNM_RUN/ping-steady.out")"
	fi
	_pk1a=$(ip -n "$NS_A" -s xfrm state | sad_packets)
	_pk1b=$(ip -n "$NS_B" -s xfrm state | sad_packets)
	[ "$_pk1a" -gt "$_pk0a" ] || fail "rnm-a ESP packet counter did not move ($_pk0a -> $_pk1a): traffic not using ESP?"
	[ "$_pk1b" -gt "$_pk0b" ] || fail "rnm-b ESP packet counter did not move ($_pk0b -> $_pk1b): traffic not using ESP?"
	xfrm_stat_dump "$NS_A" >"$RNM_RUN/stat-a.after"
	xfrm_stat_dump "$NS_B" >"$RNM_RUN/stat-b.after"
	for _s in a b; do
		_e0=$(stat_sum "$RNM_RUN/stat-$_s.before" $XFRM_ERR_COUNTERS)
		_e1=$(stat_sum "$RNM_RUN/stat-$_s.after" $XFRM_ERR_COUNTERS)
		[ "$_e1" = "$_e0" ] || fail "rnm-$_s: XFRM error counters moved during steady traffic ($_e0 -> $_e1)"
	done

	# 3. Rekey: the SPI set must change while a long ping keeps running.
	if [ "$_rekey" = 1 ]; then
		_spi0=$(ip -n "$NS_A" xfrm state | sad_spis)
		ip netns exec "$NS_A" ping -I "$TP_SRC" -c 100 -i 0.5 -W 1 "$TP_DST" >"$RNM_RUN/ping-rekey.out" 2>&1 &
		_pp=$!
		_i=0
		_new=
		while [ "$_i" -lt 70 ]; do
			_new=$(ip -n "$NS_A" xfrm state | sad_spis | new_spis "$_spi0")
			[ -n "$_new" ] && break
			sleep 1
			_i=$((_i + 1))
		done
		if [ -n "$_new" ]; then
			log "rekey: new SPI(s) appeared after ${_i}s: $(echo "$_new" | tr '\n' ' ')"
		else
			fail "rekey: no new SPI within 70s (SPIs: $(echo "$_spi0" | tr '\n' ' '))"
		fi
		wait "$_pp" 2>/dev/null || true
		_loss=$(sed -n 's/.* \([0-9.]*\)% packet loss.*/\1/p' "$RNM_RUN/ping-rekey.out")
		log "rekey ping loss: ${_loss:-unknown}%"
		loss_ok "${_loss:-100}" 10 || fail "rekey: ping loss ${_loss:-unknown}% exceeds 10%"
		# racoon logs one line per installed direction per negotiation, so a
		# rekey must leave clearly more than the first negotiation's lines.
		_est=$(cat "$RNM_RUN/racoon-a.log" "$RNM_RUN/racoon-b.log" 2>/dev/null | grep -c 'IPsec-SA established')
		[ "$_est" -ge 5 ] || fail "rekey: expected a second IPsec-SA negotiation in the logs (>=5 'IPsec-SA established' lines), saw $_est"
	fi
	return 0
}
