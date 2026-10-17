#!/bin/sh
# Self-test for the netns matrix harness itself. Needs no root, no kernel
# IPsec support and no racoon binary: it feeds the parsers canned output and
# drives run.sh through its guard logic with the RNM_FAKE_UNMET test hook.
#
#   sh selftest.sh
set -u
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
. "$HERE/lib.sh"

ok=0
bad=0
check() { # check DESC COMMAND...  (COMMAND must succeed)
	_d=$1
	shift
	if "$@" >/dev/null 2>&1; then
		ok=$((ok + 1))
		printf 'ok   %s\n' "$_d"
	else
		bad=$((bad + 1))
		printf 'FAIL %s\n' "$_d"
	fi
}
check_not() { # check_not DESC COMMAND...  (COMMAND must fail)
	_d=$1
	shift
	if "$@" >/dev/null 2>&1; then
		bad=$((bad + 1))
		printf 'FAIL %s\n' "$_d"
	else
		ok=$((ok + 1))
		printf 'ok   %s\n' "$_d"
	fi
}
eq() { [ "$1" = "$2" ]; } # eq GOT WANT

# --- canned `ip xfrm state` output (iproute2 format) ------------------------
SAD_128='src 192.0.2.1 dst 192.0.2.2
	proto esp spi 0xc1a2b3c4 reqid 0 mode transport
	replay-window 32 flag af-unspec
	auth-trunc hmac(sha256) 0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef 128
	enc cbc(aes) 0x00112233445566778899aabbccddeeff
src 192.0.2.2 dst 192.0.2.1
	proto esp spi 0x0a0b0c0d reqid 0 mode transport
	auth-trunc hmac(sha256) 0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef 128
	enc cbc(aes) 0x00112233445566778899aabbccddeeff'
# The racoon2 failure: SA installed fine, but with a 96-bit ICV for sha256.
SAD_96=$(printf '%s\n' "$SAD_128" | sed 's/ 128$/ 96/')
# Legacy attribute: no truncation field at all.
SAD_LEGACY=$(printf '%s\n' "$SAD_128" | sed 's/^\tauth-trunc hmac(sha256) \(0x[0-9a-f]*\) 128$/\tauth hmac(sha256) \1/')
SAD_STATS='src 192.0.2.1 dst 192.0.2.2
	proto esp spi 0x00000100 reqid 0 mode transport
	lifetime current:
	  1008(bytes), 12(packets)
	  add 2026-10-10 11:00:00 use 2026-10-10 11:00:01
src 192.0.2.2 dst 192.0.2.1
	proto esp spi 0x00000200 reqid 0 mode transport
	lifetime current:
	  504(bytes), 6(packets)'

check "auth-trunc: sha256 128 bits parsed" eq "$(printf '%s\n' "$SAD_128" | sad_auth_trunc_bits 'hmac(sha256)')" 128
check "auth-trunc: the 96-bit failure is reported as 96" eq "$(printf '%s\n' "$SAD_96" | sad_auth_trunc_bits 'hmac(sha256)')" 96
check "auth-trunc: legacy 'auth' line yields nothing" eq "$(printf '%s\n' "$SAD_LEGACY" | sad_auth_trunc_bits 'hmac(sha256)')" ""
check "auth-trunc: other algorithm yields nothing" eq "$(printf '%s\n' "$SAD_128" | sad_auth_trunc_bits 'hmac(sha1)')" ""

check "spis: two SPIs listed sorted" eq "$(printf '%s\n' "$SAD_128" | sad_spis | tr '\n' ' ')" "0x0a0b0c0d 0xc1a2b3c4 "
check "new_spis: detects a replaced SA" eq "$(printf '0x0a0b0c0d\n0xdeadbeef\n' | new_spis '0x0a0b0c0d
0xc1a2b3c4')" "0xdeadbeef"
check "new_spis: nothing new -> empty" eq "$(printf '0x0a0b0c0d\n' | new_spis '0x0a0b0c0d')" ""

check "sad_packets: sums both SAs" eq "$(printf '%s\n' "$SAD_STATS" | sad_packets)" 18
check "sad_packets: no counters -> 0" eq "$(printf '%s\n' "$SAD_128" | sad_packets)" 0

STAT=$(mktemp)
printf 'XfrmInError             \t0\nXfrmInStateProtoError   \t3\nXfrmOutNoStates         \t9\nXfrmInStateSeqError     \t2\n' >"$STAT"
check "stat_sum: sums only the listed counters" eq "$(stat_sum "$STAT" XfrmInStateProtoError XfrmInStateSeqError)" 5
check "stat_sum: unlisted counters ignored" eq "$(stat_sum "$STAT" XfrmInError)" 0
rm -f "$STAT"

check "loss_ok: 0 <= 10" loss_ok 0 10
check "loss_ok: 9.5 <= 10" loss_ok 9.5 10
check_not "loss_ok: 10.5 > 10" loss_ok 10.5 10
check_not "loss_ok: 100 > 10" loss_ok 100 10

# --- generators --------------------------------------------------------------
RNM_RUN=/tmp/rnm.selftest
CA=$(gen_conf a tunnel sha256 30)
CB=$(gen_conf b tunnel sha256 30)
CT=$(gen_conf a transport sha1 3600)
has() { printf '%s\n' "$1" | grep -qF -- "$2"; } # has TEXT NEEDLE
check "gen_conf: tunnel side a uses 10.1->10.2 sainfo" has "$CA" 'sainfo address 10.1.0.0/24 any address 10.2.0.0/24 any'
check "gen_conf: tunnel side b is mirrored" has "$CB" 'sainfo address 10.2.0.0/24 any address 10.1.0.0/24 any'
check "gen_conf: HMAC follows the auth argument" has "$CA" 'authentication_algorithm hmac_sha256;'
check "gen_conf: lifetime follows the argument" has "$CA" 'lifetime time 30 sec;'
check "gen_conf: transport uses sainfo anonymous" has "$CT" 'sainfo anonymous'
check "gen_conf: transport sha1" has "$CT" 'authentication_algorithm hmac_sha1;'
check "gen_conf: admin socket disabled (two daemons, one filesystem)" has "$CA" 'adminsock disabled;'
# 'adminsock' is only a keyword inside a listen { } block (cftoken.l <S_LST>);
# at top level racoon fails with '"ad" syntax error'. Regression for run #2.
inside_listen() { printf '%s\n' "$1" | awk '/^listen[ \t]*\{/ {in_l=1; next} in_l && /^\}/ {in_l=0; next} /adminsock/ {if (in_l) ok=1; else bad=1} END {exit !(ok && !bad)}'; }
check "gen_conf: adminsock appears only inside the listen block" inside_listen "$CA"
# racoon refuses a sainfo lacking encryption, authentication or compression
# algorithms (cfparse.y). Regression for run #3, where compression_algorithm
# had been removed as a "simplification".
sainfo_complete() { printf '%s\n' "$1" | awk '/^sainfo/ {s=1} s && /encryption_algorithm/ {e=1} s && /authentication_algorithm/ {a=1} s && /compression_algorithm/ {c=1} END {exit !(e && a && c)}'; }
check "gen_conf: tunnel sainfo has enc + auth + compression" sainfo_complete "$CA"
check "gen_conf: transport sainfo has enc + auth + compression" sainfo_complete "$CT"
check "gen_conf: policies request ESP only (no ipcomp)" sh -c "! printf '%s' '$(gen_policy a tunnel)' | grep -q ipcomp"
LEXER="$HERE/../../src/racoon/cftoken.l"
if [ -f "$LEXER" ]; then
	check "contract: cftoken.l still only knows adminsock in S_LST" grep -q '^<S_LST>adminsock' "$LEXER"
	check "contract: cftoken.l knows path pidfile" grep -q '^<S_PTH>pidfile' "$LEXER"
fi
PARSER="$HERE/../../src/racoon/cfparse.y"
if [ -f "$PARSER" ]; then
	check "contract: cfparse.y still requires a compression algorithm" grep -q 'no compression algorithm' "$PARSER"
	check "contract: cfparse.y still requires an exchange mode" grep -q 'no exchange mode specified' "$PARSER"
fi
check "gen_conf: peer address in remote block (a)" has "$CA" "remote $IP_B {"
check "gen_conf: peer address in remote block (b)" has "$CB" "remote $IP_A {"
PA=$(gen_policy a tunnel)
PB=$(gen_policy b tunnel)
check "gen_policy: a out is tunnel a->b" has "$PA" "-P out ipsec esp/tunnel/$IP_A-$IP_B/require"
check "gen_policy: b in mirrors a out" has "$PB" "-P in ipsec esp/tunnel/$IP_A-$IP_B/require"
check "gen_policy: transport has empty tunnel endpoints" has "$(gen_policy a transport)" 'esp/transport//require'

# --- known-defect (XFAIL) logic ----------------------------------------------
V() { icv_verdict "$@"; }
S256='hmac(sha256)'
check "verdict: correct ICV passes" eq "$(V pfkey 0 "$S256" 128 128)" PASS
check "verdict: wrong ICV without the marker is a FAIL" eq "$(V pfkey 0 "$S256" 128 96)" FAIL
check "verdict: the known wrong value with the marker is XFAIL" eq "$(V pfkey 1 "$S256" 128 96)" XFAIL
check "verdict: marker but ICV now correct is XPASS (marker must be removed)" eq "$(V pfkey 1 "$S256" 128 128)" XPASS
check "verdict: marker does NOT excuse a different wrong value" eq "$(V pfkey 1 "$S256" 128 64)" FAIL
check "verdict: marker never excuses the xfrm backend" eq "$(V xfrm 1 "$S256" 128 96)" FAIL
check "verdict: marker with correct ICV on xfrm simply passes" eq "$(V xfrm 1 "$S256" 128 128)" PASS
check "verdict: no known defect for sha1, wrong ICV still FAILs" eq "$(V pfkey 1 'hmac(sha1)' 96 128)" FAIL
check "verdict: no known defect for sha1, correct ICV passes" eq "$(V pfkey 1 'hmac(sha1)' 96 96)" PASS

# Runner accounting for XFAIL, using synthetic kinds (RNM_EXTRA_KINDS hook).
XK=$(mktemp)
cat >"$XK" <<'EOK'
kind_selftest_pass() { return 0; }
kind_selftest_xfail() { xfail "known thing"; }
kind_selftest_fail() { fail "boom"; }
EOK
XC=$(mktemp)
printf 't-pass\tselftest_pass\t-\t-\tn\nt-xfail\tselftest_xfail\t-\t-\tn\nt-fail\tselftest_fail\t-\t-\tn\n' >"$XC"
xr() { RNM_EXTRA_KINDS=$XK RNM_CASES_FILE=$XC RNM_OUT=/tmp/rnm-selftest-out sh "$HERE/run.sh" "$@" 2>&1; }
out=$(xr --cases '^t-xfail '); rc=$?
check "runner: an XFAIL-only run exits 0 and reports xfail=1" sh -c "[ $rc -eq 0 ] && printf '%s' '$out' | grep -q 'pass=0 fail=0 skip=0 xfail=1'"
check "runner: XFAIL is printed, not hidden" sh -c "printf '%s' '$out' | grep -q '^XFAIL t-xfail'"
out=$(xr --cases '^t-xfail ' --min-pass 1); rc=$?
check "runner: XFAIL counts toward --min-pass" eq "$rc" 0
out=$(xr --cases '^t-xfail ' --min-pass 2); rc=$?
check "runner: --min-pass 2 fails with one XFAIL" eq "$rc" 1
out=$(xr --cases 't-xfail|t-fail'); rc=$?
check "runner: a real FAIL next to an XFAIL still fails the run" eq "$rc" 1
out=$(xr); rc=$?
check "runner: mixed run counts pass/fail/xfail separately" sh -c "printf '%s' '$out' | grep -q 'pass=1 fail=1 skip=0 xfail=1'"
rm -f "$XK" "$XC"

# --- preflight diagnosis -----------------------------------------------------
# Regression for the first hosted-runner run: setkey could not load libipsec,
# and that was reported as "PF_KEY unavailable".
r_loader=$(setkey_fail_reason '/usr/local/sbin/setkey: error while loading shared libraries: libipsec.so.0: cannot open shared object file')
r_pfkey=$(setkey_fail_reason 'setkey: pfkey_open: Address family not supported by protocol')
check "diagnosis: loader error is an installation problem" has "$r_loader" 'installation problem'
check_not "diagnosis: loader error is NOT blamed on the kernel" has "$r_loader" 'PF_KEY unavailable'
check "diagnosis: EAFNOSUPPORT is PF_KEY unavailable" has "$r_pfkey" 'PF_KEY unavailable'
check "diagnosis: unknown failure is reported verbatim" has "$(setkey_fail_reason 'boom')" 'setkey -D failed: boom'

# --- runner guards (RNM_FAKE_UNMET simulates a host without PF_KEY/ESP) ------
RUN="sh $HERE/run.sh"
out=$(RNM_FAKE_UNMET='no ESP here' RNM_OUT=/tmp/rnm-selftest-out $RUN --cases '^psk-transport' 2>&1); rc=$?
check "runner: unmet live row is SKIP and exits 0" sh -c "[ $rc -eq 0 ] && printf '%s' '$out' | grep -q 'skip=1'"
out=$(RNM_REQUIRE_LIVE=1 RNM_FAKE_UNMET='no ESP here' RNM_OUT=/tmp/rnm-selftest-out $RUN --cases '^psk-transport' 2>&1); rc=$?
check "runner: RNM_REQUIRE_LIVE=1 turns that SKIP into a FAIL" sh -c "[ $rc -eq 1 ] && printf '%s' '$out' | grep -q 'fail=1'"
out=$(RNM_FAKE_UNMET='no ESP here' RNM_OUT=/tmp/rnm-selftest-out $RUN --cases '^psk-transport' --min-pass 1 2>&1); rc=$?
check "runner: --min-pass fails an all-skip run" eq "$rc" 1
out=$($RUN --shard 1 1 2>&1); rc=$?
check "runner: --shard 1 1 (empty shard) is rejected up front" sh -c "[ $rc -eq 2 ] && printf '%s' '$out' | grep -q 'empty or invalid'"
out=$($RUN --shard 3 3 2>&1); rc=$?
check "runner: --shard 3 3 is rejected up front" sh -c "[ $rc -eq 2 ] && printf '%s' '$out' | grep -q 'empty or invalid'"
RNM_FAKE_UNMET=x $RUN --cases '^no-such-row$' >/dev/null 2>&1; rc=$?
check "runner: empty selection is an error, not a green run" eq "$rc" 2

# Every row lands in exactly one of 3 shards.
seen=
for k in 0 1 2; do
	seen="$seen $(RNM_FAKE_UNMET=x RNM_OUT=/tmp/rnm-selftest-out $RUN --shard $k 3 2>&1 | sed -n 's/^SKIP \([^:]*\):.*/\1/p' | tr '\n' ' ')"
done
want=$(grep -v '^#' "$HERE/cases.tsv" | cut -f1 | sort | tr '\n' ' ')
got=$(printf '%s\n' $seen | sort | tr '\n' ' ')
check "runner: 3 shards cover every row exactly once" eq "$got" "$want"

# Regression: a tab IFS collapses empty columns; '-' must keep columns aligned.
T=$(mktemp)
printf 'colcheck\tpreflight\t-\tlive\tnote\n' >"$T"
out=$(RNM_CASES_FILE=$T RNM_FAKE_UNMET=x RNM_OUT=/tmp/rnm-selftest-out $RUN 2>&1)
check "runner: '-' placeholder keeps the gate column aligned" sh -c "printf '%s' '$out' | grep -q 'SKIP colcheck'"
rm -f "$T"
rm -rf /tmp/rnm-selftest-out

printf '\n%s passed, %s failed\n' "$ok" "$bad"
[ "$bad" -eq 0 ]
