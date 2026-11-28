#!/usr/bin/env bash
# THE ONLY PLACE that knows coi's command line. Calibrate after 00-discover.sh.
# Spec ground rule: the schema/--help win over this file. Override via env.
#
# coi_exec <profile> <cmd...>  run <cmd> in a session of <profile>, non-interactively,
#                              stdout/stderr passed through.
# coi_exec_resume ...          same, re-entering the existing session.
# coi_container                print the container name for session_name t-shared.
COI_BIN="${COI_BIN:-coi}"
INCUS_BIN="${INCUS_BIN:-incus}"
: "${COI_SESSION_SESSION_NAME:=t-shared}"

# Calibrated from coi-help.txt: `coi run -- CMD` runs a command in the sandbox;
# --profile is a global flag. Whether `coi run` reuses a persistent container
# and which slot it gets is NOT yet verified: G1.2 records `coi list` for that.
[[ -n "${COI_EXEC_TEMPLATE:-}" ]]   || COI_EXEC_TEMPLATE="$COI_BIN run --profile {P} -- {CMD}"
[[ -n "${COI_RESUME_TEMPLATE:-}" ]] || COI_RESUME_TEMPLATE="$COI_BIN run --profile {P} -- {CMD}"

_expand() { # template profile cmd-string
  local t="$1"; t="${t//\{P\}/$2}"; t="${t//\{CMD\}/$3}"; bash -c "$t"
}
coi_exec()        { local p="$1"; shift; _expand "$COI_EXEC_TEMPLATE"   "$p" "$(printf '%q ' "$@")"; }
coi_exec_resume() { local p="$1"; shift; _expand "$COI_RESUME_TEMPLATE" "$p" "$(printf '%q ' "$@")"; }
# Container names are coi-<hash>-<slot>, not derived from session_name. So the test container is
# "the container that did not exist when discovery ran" (results/_baseline_containers). Existing
# containers are never used or touched. Override with COI_TEST_CONTAINER.
coi_container() {
  [[ -n "${COI_TEST_CONTAINER:-}" ]] && { echo "$COI_TEST_CONTAINER"; return; }
  "$INCUS_BIN" list -f csv -c n 2>/dev/null | sort | comm -13 "${RESULTS:-.}/_baseline_containers" - | head -1
}
# incus_exec runs only in a Running test container (coi run stops persistent containers after each command).
incus_exec() {
  local c; c="$(coi_container)"
  [[ -n "$c" ]] || { echo "no test container (baseline-diff empty)"; return 3; }
  [[ "$("$INCUS_BIN" list "$c" -f csv -c s 2>/dev/null)" == RUNNING ]] || { echo "test container $c not running"; return 3; }
  "$INCUS_BIN" exec "$c" -- "$@"
}
