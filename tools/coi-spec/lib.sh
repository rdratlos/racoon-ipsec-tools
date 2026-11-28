#!/usr/bin/env bash
# Shared helpers for the coi test spec. Source this; do not run it.
# Results: $RESULTS/<ID>.txt in the spec's result-sheet format.
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RESULTS="${COI_RESULTS:-$HERE/results}"
PROFILES="${COI_PROFILES_DIR:-$HOME/.coi/profiles}"
SCRATCH_MOUNT="${COI_SCRATCH_MOUNT:-/tmp/t-mount}"
WORKSPACE="${COI_WORKSPACE:-$PWD}"          # W: scratch project dir, NOT a real repo
mkdir -p "$RESULTS"
# shellcheck source=adapter.sh
. "$HERE/adapter.sh"

_T_ID=""; _T_CMDS=""; _T_OUT=""; _T_DELTA="-"
t_begin() { _T_ID="$1"; _T_CMDS=""; _T_OUT=""; _T_DELTA="${2:--}"; echo "== $1"; }
# t_run <cmd...>: run, log command and raw output (stdout+stderr+rc)
t_run() {
  local out rc
  _T_CMDS+="\$ $*"$'\n'
  out="$("$@" 2>&1)"; rc=$?
  _T_OUT+="\$ $*"$'\n'"$out"$'\n'"[rc=$rc]"$'\n'
  LAST_OUT="$out"; LAST_RC=$rc
  return 0
}
# t_sh '<shell string>': same, for pipelines
t_sh() { t_run bash -c "$1"; }
t_note() { _T_OUT+="# $*"$'\n'; }
# t_end PASS|FAIL|OBSERVED "meaning" "doc impact"
t_end() {
  local f="$RESULTS/$_T_ID.txt"
  {
    echo "ID:            $_T_ID"
    echo "Date/time:     $(date -u +%FT%TZ)"
    echo "coi version:   $(cat "$RESULTS/_build.txt" 2>/dev/null | head -1)"
    echo "Setup delta:   $_T_DELTA"
    echo "Commands run:"; printf '%s' "$_T_CMDS" | sed 's/^/  /'
    echo "Raw output:";   printf '%s' "$_T_OUT"  | sed 's/^/  /'
    echo "Verdict:       $1"
    echo "Meaning:       $2"
    echo "Doc impact:    ${3:--}"
  } > "$f"
  echo "   $1  ($2)"
  printf '%s\t%s\t%s\n' "$_T_ID" "$1" "$2" >> "$RESULTS/_summary.tsv"
}
contains() { [[ "$1" == *"$2"* ]]; }

# write_profile <name> <toml-body>; scratch profiles are always t-*
write_profile() {
  case "$1" in t-*) ;; *) echo "refusing non-scratch profile $1" >&2; return 1;; esac
  mkdir -p "$PROFILES/$1"; printf '%s\n' "$2" > "$PROFILES/$1/config.toml"
}
