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
for c in run list container trust info file schema attach persist tmux; do $COI_BIN $c --help > "$d/coi-$c-help.txt" 2>&1; done
$COI_BIN list                  > "$d/coi-list.txt"      2>&1
$COI_BIN health                > "$d/coi-health.txt"    2>&1
# Container baseline: tests must never touch containers that exist now (e.g. a real persistent one).
$INCUS_BIN list -f csv -c n 2>/dev/null | sort > "$RESULTS/_baseline_containers"
# Evidence for "Not enough uid/gid available" (coi health failed on it in the first run).
{
  echo "--- /etc/subuid"; cat /etc/subuid 2>&1; echo "--- /etc/subgid"; cat /etc/subgid 2>&1
  echo "--- incus info (idmap)"; $INCUS_BIN info 2>&1 | grep -i -A6 -E 'idmap|uid|gid'
  for c in $(cat "$RESULTS/_baseline_containers"); do
    echo "--- $c"; $INCUS_BIN config show "$c" 2>&1 | grep -i -E 'idmap|isolated|image.description'
  done
} > "$d/idmap.txt" 2>&1
if grep -q 'Not enough uid/gid' "$d/coi-health.txt"; then
  echo "WARNING: coi health could not create containers (uid/gid). New test containers will fail"
  echo "until the idmap range is enlarged. See $d/idmap.txt; do NOT delete existing containers."
fi
# Fixtures must exist before the smoke test (profile t-base is created there).
bash "$HERE/tests/fixtures.sh"
echo "Saved to $d. Send results/ back for calibration."
echo "Smoke check that the adapter works:"; coi_exec t-base echo adapter-ok 2>&1 | tail -3
