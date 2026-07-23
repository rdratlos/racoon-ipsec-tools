#!/bin/sh
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (C) 2024-2026 Thomas Reim and the racoon-ipsec-tools contributors
#
# test-dns-emitters.sh - regression tests for the §6 capability matrix and
# resolvectl/systemd-resolve command emitters: tool detection, per-
# capability probing, and exact command-line output per tool. Locks the
# grammar table in place so it cannot silently drift. Run directly:
# sh tests/hooks/test-dns-emitters.sh

set -u

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
LIB="$SCRIPT_DIR/../../src/racoon/scripts/racoon-hook-lib.sh"

TESTS_RUN=0
TESTS_FAILED=0

fail() { TESTS_FAILED=$((TESTS_FAILED + 1)); echo "FAIL: $1"; }

assert_eq() {
	TESTS_RUN=$((TESTS_RUN + 1))
	if [ "$2" = "$3" ]; then
		:
	else
		fail "$1 -- expected '$3', got '$2'"
	fi
}

# --------------------------------------------------------------------------
# Fixture: a bin/ dir with stub resolvectl/systemd-resolve/systemctl.
# --------------------------------------------------------------------------
WORK=$(mktemp -d "${TMPDIR:-/tmp}/racoon-hook-dns-emit.XXXXXX")
trap 'rm -rf "$WORK"' EXIT

mkdir -p "$WORK/both" "$WORK/resolvectl-only" "$WORK/systemd-resolve-only" "$WORK/neither" "$WORK/resolvectl-no-default-route"

cat > "$WORK/both/resolvectl" <<'EOF'
#!/bin/sh
[ "$1" = "--help" ] && { echo "resolvectl [OPTIONS...] COMMAND ..."; echo "  default-route LINK BOOL   Configure default-route feature"; exit 0; }
exit 0
EOF
cp "$WORK/both/resolvectl" "$WORK/resolvectl-only/resolvectl"
cat > "$WORK/resolvectl-no-default-route/resolvectl" <<'EOF'
#!/bin/sh
[ "$1" = "--help" ] && { echo "resolvectl [OPTIONS...] COMMAND ..."; echo "  dns LINK SERVER...       Set per-link DNS servers"; exit 0; }
exit 0
EOF
for f in "$WORK/both/resolvectl" "$WORK/resolvectl-only/resolvectl" "$WORK/resolvectl-no-default-route/resolvectl"; do
	chmod +x "$f"
done

cat > "$WORK/both/systemd-resolve" <<'EOF'
#!/bin/sh
exit 0
EOF
cp "$WORK/both/systemd-resolve" "$WORK/systemd-resolve-only/systemd-resolve"
chmod +x "$WORK/both/systemd-resolve" "$WORK/systemd-resolve-only/systemd-resolve"

cat > "$WORK/systemctl-stub" <<'EOF'
#!/bin/sh
[ "$1" = "--version" ] && { echo "systemd 245 (245.4-4ubuntu3.24)"; echo "+PAM +AUDIT +SELINUX"; exit 0; }
exit 0
EOF
chmod +x "$WORK/systemctl-stub"
for d in both resolvectl-only systemd-resolve-only neither resolvectl-no-default-route; do
	cp "$WORK/systemctl-stub" "$WORK/$d/systemctl"
done

# shellcheck source=SCRIPTDIR/../../src/racoon/scripts/racoon-hook-lib.sh
. "$LIB"

# ==========================================================================
# Tool detection
# ==========================================================================
# Every PATH reassignment below is rebuilt from BASE_PATH (the real,
# original PATH captured once here), never accumulated on top of a
# previous test's already-narrowed PATH -- otherwise an earlier test that
# deliberately hides a tool would silently also hide coreutils
# (sed/awk/grep/cut) that racoon-hook-lib.sh itself needs for later tests.
# --------------------------------------------------------------------------
BASE_PATH="$PATH"

PATH="$WORK/both:$BASE_PATH"
assert_eq "prefers resolvectl when both present" "$(rhook_dns_tool_detect)" "resolvectl"

PATH="$WORK/resolvectl-only:$BASE_PATH"
assert_eq "resolvectl only" "$(rhook_dns_tool_detect)" "resolvectl"

RACOON_HOOK_RESOLVECTL="/nonexistent/resolvectl"
PATH="$WORK/systemd-resolve-only:$BASE_PATH"
assert_eq "falls back to systemd-resolve (Bionic case)" "$(rhook_dns_tool_detect)" "systemd-resolve"

# shellcheck disable=SC2123 # deliberately narrowing PATH to test "tool absent"; restored via BASE_PATH on every subsequent reassignment
PATH="$WORK/neither"
assert_eq "neither tool present -> empty, not a crash" "$(rhook_dns_tool_detect)" ""

# ==========================================================================
# systemd version parsing
# ==========================================================================
PATH="$WORK/both:$BASE_PATH"
RACOON_HOOK_SYSTEMCTL="$WORK/both/systemctl"
assert_eq "systemd version parsed from --version output" "$(rhook_systemd_version)" "245"

# ==========================================================================
# Capability matrix
# ==========================================================================
for cap in per_link_dns routing_domains revert flush_caches; do
	TESTS_RUN=$((TESTS_RUN + 1))
	if rhook_dns_cap resolvectl "$cap"; then :; else fail "resolvectl should have capability '$cap'"; fi
	TESTS_RUN=$((TESTS_RUN + 1))
	if rhook_dns_cap systemd-resolve "$cap"; then :; else fail "systemd-resolve should have capability '$cap'"; fi
done

TESTS_RUN=$((TESTS_RUN + 1))
if rhook_dns_cap "" per_link_dns; then fail "empty tool must not report any capability"; fi

RACOON_HOOK_RESOLVECTL="$WORK/both/resolvectl"
TESTS_RUN=$((TESTS_RUN + 1))
if rhook_dns_cap resolvectl default_route; then :; else fail "resolvectl with default-route in --help should report the capability"; fi

RACOON_HOOK_RESOLVECTL="$WORK/resolvectl-no-default-route/resolvectl"
TESTS_RUN=$((TESTS_RUN + 1))
if rhook_dns_cap resolvectl default_route; then fail "resolvectl without default-route in --help must not report the capability"; fi

TESTS_RUN=$((TESTS_RUN + 1))
if rhook_dns_cap systemd-resolve default_route; then fail "systemd-resolve must never report default_route (no equivalent exists)"; fi
RACOON_HOOK_RESOLVECTL="$WORK/both/resolvectl"

# ==========================================================================
# Emitters -- exact command-line output per tool, locking the grammar
# ==========================================================================
RACOON_HOOK_RESOLVECTL="resolvectl"
RACOON_HOOK_SYSTEMD_RESOLVE="systemd-resolve"

assert_eq "resolvectl: set-dns single server" \
	"$(rhook_dns_emit_set_dns resolvectl wlan0 10.0.12.53)" \
	"resolvectl dns wlan0 10.0.12.53"

assert_eq "resolvectl: set-dns multiple servers, one call" \
	"$(rhook_dns_emit_set_dns resolvectl wlan0 10.0.12.53 10.0.12.54)" \
	"resolvectl dns wlan0 10.0.12.53 10.0.12.54"

assert_eq "systemd-resolve: set-dns single server" \
	"$(rhook_dns_emit_set_dns systemd-resolve wlan0 10.0.12.53)" \
	"systemd-resolve --interface=wlan0 --set-dns=10.0.12.53"

assert_eq "systemd-resolve: set-dns multiple servers, flag repeated" \
	"$(rhook_dns_emit_set_dns systemd-resolve wlan0 10.0.12.53 10.0.12.54)" \
	"systemd-resolve --interface=wlan0 --set-dns=10.0.12.53 --interface=wlan0 --set-dns=10.0.12.54"

assert_eq "resolvectl: routing-only domain (~ prefix passed through)" \
	"$(rhook_dns_emit_set_domains resolvectl wlan0 ~corp.example.com)" \
	"resolvectl domain wlan0 ~corp.example.com"

assert_eq "systemd-resolve: routing-only domain" \
	"$(rhook_dns_emit_set_domains systemd-resolve wlan0 ~corp.example.com)" \
	"systemd-resolve --interface=wlan0 --set-domain=~corp.example.com"

assert_eq "resolvectl: default-route false" \
	"$(rhook_dns_emit_default_route resolvectl wlan0 false)" \
	"resolvectl default-route wlan0 false"

TESTS_RUN=$((TESTS_RUN + 1))
if rhook_dns_emit_default_route systemd-resolve wlan0 false >/dev/null 2>&1; then
	fail "systemd-resolve default-route emitter must fail -- no such capability exists"
fi

assert_eq "resolvectl: revert" \
	"$(rhook_dns_emit_revert resolvectl wlan0)" \
	"resolvectl revert wlan0"

assert_eq "systemd-resolve: revert" \
	"$(rhook_dns_emit_revert systemd-resolve wlan0)" \
	"systemd-resolve --interface=wlan0 --revert"

assert_eq "resolvectl: flush-caches" \
	"$(rhook_dns_emit_flush_caches resolvectl)" \
	"resolvectl flush-caches"

assert_eq "systemd-resolve: flush-caches" \
	"$(rhook_dns_emit_flush_caches systemd-resolve)" \
	"systemd-resolve --flush-caches"

# The critical correctness check from §6 point 6: clearing must use an
# empty string, never "~." (the catch-all routing domain -- a confirmed,
# previously-live bug in this hook set's own fallback).
assert_eq "resolvectl: clear domains uses empty string, not ~." \
	"$(rhook_dns_emit_clear_domains resolvectl wlan0)" \
	'resolvectl domain wlan0 ""'

# systemd-resolve: --set-dns=""/--set-domain="" are NOT valid syntax for
# this tool (confirmed against systemd v237's own resolve-tool.c:
# --set-dns requires a value that parses as an address, --set-domain
# requires valid domain syntax; an empty string fails both) -- found
# live on a real Bionic host, both erroring out rather than clearing
# anything. --revert is this tool's own documented way to clear all
# per-link settings, confirmed idempotent against resolved's server-side
# bus_link_method_revert() (resolved-link-bus.c): it unconditionally
# calls link_flush_settings() and succeeds regardless of prior state.
assert_eq "systemd-resolve: clear domains uses --revert, not the invalid --set-domain=\"\"" \
	"$(rhook_dns_emit_clear_domains systemd-resolve wlan0)" \
	'systemd-resolve --interface=wlan0 --revert'

assert_eq "resolvectl: clear dns uses empty string" \
	"$(rhook_dns_emit_clear_dns resolvectl wlan0)" \
	'resolvectl dns wlan0 ""'

assert_eq "systemd-resolve: clear dns uses --revert, not the invalid --set-dns=\"\"" \
	"$(rhook_dns_emit_clear_dns systemd-resolve wlan0)" \
	'systemd-resolve --interface=wlan0 --revert'

# The emitted string must never literally contain the tilde-dot sequence.
TESTS_RUN=$((TESTS_RUN + 1))
case "$(rhook_dns_emit_clear_domains resolvectl wlan0)" in
	*'~.'*) fail "clear_domains output must never contain the catch-all routing domain '~.'" ;;
esac

# Unknown tool: every emitter must fail cleanly, not silently emit garbage.
for fn in rhook_dns_emit_set_dns rhook_dns_emit_set_domains rhook_dns_emit_revert; do
	TESTS_RUN=$((TESTS_RUN + 1))
	if "$fn" bogus-tool wlan0 x >/dev/null 2>&1; then
		fail "$fn must fail for an unrecognized tool name"
	fi
done
TESTS_RUN=$((TESTS_RUN + 1))
if rhook_dns_emit_flush_caches bogus-tool >/dev/null 2>&1; then
	fail "rhook_dns_emit_flush_caches must fail for an unrecognized tool name"
fi

echo ""
echo "$TESTS_RUN checks run, $TESTS_FAILED failed"
[ "$TESTS_FAILED" -eq 0 ]
