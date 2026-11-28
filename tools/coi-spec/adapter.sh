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

# GUESS (unverified): `coi shell --profile P -- CMD`. If coi has no such form,
# set COI_EXEC_TEMPLATE, e.g. 'coi run --profile {P} -- {CMD}'.
[[ -n "${COI_EXEC_TEMPLATE:-}" ]]   || COI_EXEC_TEMPLATE="$COI_BIN shell --profile {P} -- {CMD}"
[[ -n "${COI_RESUME_TEMPLATE:-}" ]] || COI_RESUME_TEMPLATE="$COI_BIN shell --profile {P} --resume -- {CMD}"

_expand() { # template profile cmd-string
  local t="$1"; t="${t//\{P\}/$2}"; t="${t//\{CMD\}/$3}"; bash -c "$t"
}
coi_exec()        { local p="$1"; shift; _expand "$COI_EXEC_TEMPLATE"   "$p" "$(printf '%q ' "$@")"; }
coi_exec_resume() { local p="$1"; shift; _expand "$COI_RESUME_TEMPLATE" "$p" "$(printf '%q ' "$@")"; }
# GUESS: first container whose name contains the session name.
coi_container() { "$INCUS_BIN" list -f csv -c n 2>/dev/null | grep -m1 -- "${COI_CONTAINER_MATCH:-$COI_SESSION_SESSION_NAME}"; }
incus_exec() { local c; c="$(coi_container)"; "$INCUS_BIN" exec "$c" -- "$@"; }
