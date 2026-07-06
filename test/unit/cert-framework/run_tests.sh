#!/usr/bin/env bash
# test/unit/cert-framework/run_tests.sh
#
# Runs every cert-framework unit test script and reports a summary.
# Usage: bash test/unit/cert-framework/run_tests.sh
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

failed_files=()

for t in test_*.sh; do
	echo "=== $t ==="
	if ! bash "$t"; then
		failed_files+=("$t")
	fi
	echo
done

if [ "${#failed_files[@]}" -eq 0 ]; then
	echo "All cert-framework unit tests passed."
	exit 0
else
	echo "FAILED: ${failed_files[*]}"
	exit 1
fi
