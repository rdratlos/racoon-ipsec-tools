#!/usr/bin/env bash
# Usage: run.sh [discover|g1|g2|all|cleanup]   (run from a scratch project dir)
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/lib.sh"
case "${1:-all}" in
  discover) bash "$HERE/00-discover.sh";;
  g1) bash "$HERE/tests/g1.sh";;
  g2) bash "$HERE/tests/g2.sh";;
  all) bash "$HERE/00-discover.sh" && bash "$HERE/tests/g1.sh" && bash "$HERE/tests/g2.sh";;
  cleanup)
    echo "Scratch profiles:"; ls -d "$PROFILES"/t-* 2>/dev/null
    echo "Containers (remove with the command in 'coi --help'):"; $COI_BIN list
    echo "Remove profiles and $SCRATCH_MOUNT? [y/N]"; read -r a
    [[ $a == y ]] && rm -rf "$PROFILES"/t-* "$SCRATCH_MOUNT"; $INCUS_BIN list;;
  *) echo "unknown"; exit 2;;
esac
echo; echo "Summary:"; column -t -s$'\t' "$RESULTS/_summary.tsv" 2>/dev/null
