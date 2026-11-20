#!/bin/sh
# netns matrix runner. See README.md.
#
#   sudo RACOON_BIN=... SETKEY_BIN=... sh run.sh [--cases REGEX] [--shard K M]
#                                                [--min-pass N] [--list]
#
# Result model (per row): PASS, FAIL or SKIP.
#   * A kind calls skip REASON when the host cannot run the row.
#   * RNM_REQUIRE_LIVE=1 (set in CI) turns every SKIP of a gate=live row into a
#     FAIL, so a runner that silently lacks PF_KEY/ESP can never go green.
#   * A row can end XFAIL: every assertion held except one DOCUMENTED known
#     defect (see xfail= in cases.tsv and icv_verdict in lib.sh). XFAIL does not
#     fail the run, is always printed, and turns into a FAIL (XPASS) the moment
#     the defect is fixed.
#   * --min-pass N fails the run when fewer than N rows passed or XFAILed.
#   * An empty selection, or an empty shard, is an error, never a green run.
set -u
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
. "$HERE/lib.sh"
for _k in "$HERE"/kinds/*.sh; do
	# shellcheck disable=SC1090
	. "$_k"
done
# Test-only hook (selftest.sh): extra kinds sourced from a file.
if [ -n "${RNM_EXTRA_KINDS:-}" ]; then
	# shellcheck disable=SC1090
	. "$RNM_EXTRA_KINDS"
fi

CASES_FILE=${RNM_CASES_FILE:-$HERE/cases.tsv}
FILTER=
SHARD_K=
SHARD_M=
MIN_PASS=0
LIST=0

usage() {
	cat <<EOF
usage: run.sh [--cases REGEX] [--shard K M] [--min-pass N] [--list]
env:   RACOON_BIN, SETKEY_BIN   binaries under test (default: from PATH)
       RNM_REQUIRE_LIVE=1       SKIP of a gate=live row becomes FAIL (CI)
       RNM_BACKEND=pfkey|xfrm   kernel interface under test (default pfkey)
       RNM_OUT=DIR              where per-row logs are kept (default /tmp/rnm-logs)
EOF
}

while [ $# -gt 0 ]; do
	case $1 in
	--cases) FILTER=$2; shift 2 ;;
	--shard) SHARD_K=$2; SHARD_M=$3; shift 3 ;;
	--min-pass) MIN_PASS=$2; shift 2 ;;
	--list) LIST=1; shift ;;
	-h|--help) usage; exit 0 ;;
	*) usage; exit 2 ;;
	esac
done

# 0 <= K < M, otherwise `idx % M == K` can never match and zero rows would run.
if [ -n "$SHARD_M" ]; then
	if [ "$SHARD_M" -lt 1 ] || [ "$SHARD_K" -ge "$SHARD_M" ] || [ "$SHARD_K" -lt 0 ]; then
		echo "error: --shard $SHARD_K $SHARD_M is empty or invalid (need 0 <= K < M)" >&2
		exit 2
	fi
fi

if [ "$LIST" = 1 ]; then
	grep -v '^#' "$CASES_FILE" | cut -f1
	exit 0
fi

RNM_RUN=$(mktemp -d /tmp/rnm.XXXXXX) || exit 2
export RNM_RUN
# Logs are written by root; make them readable so a non-root artifact
# uploader (actions/upload-artifact) can zip them.
trap 'ns_down; rm -rf "$RNM_RUN"; chmod -R a+rX "$RNM_OUT" 2>/dev/null' EXIT INT TERM
mkdir -p "$RNM_OUT"

pass=0
fail=0
skip=0
xfailed=0
selected=0
idx=0
LIVE_UNMET=
LIVE_CHECKED=0

while IFS="$(printf '\t')" read -r name kind args gate note || [ -n "$name" ]; do
	case $name in ''|\#*) continue ;; esac
	# A tab IFS collapses runs of tabs, so empty columns are written as "-".
	[ "$args" = - ] && args=
	if [ -n "$FILTER" ]; then
		printf '%s %s\n' "$name" "$kind" | grep -Eq "$FILTER" || continue
	fi
	idx=$((idx + 1))
	if [ -n "$SHARD_M" ] && [ $((idx % SHARD_M)) -ne "$SHARD_K" ]; then
		continue
	fi
	selected=$((selected + 1))

	log "=== $name ($kind) ${args:+[$args]} ==="
	R_FAIL=0
	R_SKIP=
	R_XFAIL=0
	_row_skip=

	if [ "$gate" = live ]; then
		if [ "$LIVE_CHECKED" = 0 ]; then
			LIVE_UNMET=$(preflight) || true
			LIVE_CHECKED=1
		fi
		if [ -n "$LIVE_UNMET" ] && [ "$kind" != preflight ]; then
			_row_skip=$LIVE_UNMET
		fi
	fi

	if [ -z "$_row_skip" ]; then
		"kind_$kind" "$name" "$args" || R_FAIL=1
		_row_skip=$R_SKIP
	fi

	if [ -n "$_row_skip" ]; then
		if [ "${RNM_REQUIRE_LIVE:-0}" = 1 ] && [ "$gate" = live ]; then
			log "FAIL $name (cannot run, and RNM_REQUIRE_LIVE=1): $_row_skip"
			fail=$((fail + 1))
		else
			log "SKIP $name: $_row_skip"
			skip=$((skip + 1))
		fi
	elif [ "$R_FAIL" != 0 ]; then
		collect_logs "$name"
		log "FAIL $name (logs: $RNM_OUT/$name)"
		fail=$((fail + 1))
	elif [ "$R_XFAIL" != 0 ]; then
		collect_logs "$name"
		log "XFAIL $name (known defect, see XFAIL lines above; logs: $RNM_OUT/$name)"
		xfailed=$((xfailed + 1))
	else
		collect_logs "$name"
		log "PASS $name"
		pass=$((pass + 1))
	fi
	ns_down
done <"$CASES_FILE"

log "pass=$pass fail=$fail skip=$skip xfail=$xfailed"

if [ "$selected" -eq 0 ]; then
	echo "error: no rows selected (filter='$FILTER' shard='${SHARD_K:-}/${SHARD_M:-}')" >&2
	exit 2
fi
if [ $((pass + xfailed)) -lt "$MIN_PASS" ]; then
	echo "error: only $((pass + xfailed)) rows passed or xfailed, --min-pass requires $MIN_PASS" >&2
	exit 1
fi
[ "$fail" -eq 0 ]
