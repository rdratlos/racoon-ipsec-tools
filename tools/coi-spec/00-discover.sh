#!/usr/bin/env bash
# Records the build (spec §1) and the CLI surface needed to calibrate adapter.sh.
. "$(dirname "$0")/lib.sh"
d="$RESULTS/discovery"; mkdir -p "$d"
{ $COI_BIN version 2>&1 || $COI_BIN --version 2>&1; } | head -3 > "$RESULTS/_build.txt"
{
  echo "date: $(date -u +%FT%TZ)"; echo "host: $(uname -a)"; . /etc/os-release 2>/dev/null && echo "os: $PRETTY_NAME"
  echo "incus: $($INCUS_BIN --version 2>&1)"
  echo "images:"; $INCUS_BIN image list -f csv -c lfd 2>&1
} >> "$RESULTS/_build.txt"
$COI_BIN --help                > "$d/coi-help.txt"      2>&1
$COI_BIN shell --help          > "$d/coi-shell-help.txt" 2>&1
$COI_BIN schema profile        > "$d/schema-profile.txt" 2>&1
$COI_BIN profile --help        > "$d/profile-help.txt"   2>&1
echo "Saved to $d. Read coi-shell-help.txt, then fix COI_EXEC_TEMPLATE in adapter.sh"
echo "and the table names in tests/fixtures.sh against schema-profile.txt."
echo "Smoke check that the adapter works:"; coi_exec t-base echo adapter-ok 2>&1 | tail -3
