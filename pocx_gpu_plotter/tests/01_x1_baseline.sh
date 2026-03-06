#!/usr/bin/env bash
# 01_x1_baseline.sh — X1 compression, 9 warps, escalate=1.
# Compares old plotter vs new GPU plotter byte-for-byte.
set -euo pipefail
source "$(dirname "$0")/lib.sh"

echo "=== Test 01: X1 baseline (9 warps, e=1) ==="

DIR_OLD=$(make_temp_dir)
DIR_NEW=$(make_temp_dir)
trap 'rm -rf "$DIR_OLD" "$DIR_NEW"' EXIT

run_old_plotter "$DIR_OLD" 9 1 1
run_new_plotter_seeded "$DIR_NEW" 9 1 1

OLD_FILE=$(find_plotfile "$DIR_OLD")
NEW_FILE=$(find_plotfile "$DIR_NEW")

if compare_files "$OLD_FILE" "$NEW_FILE"; then
    pass "X1 baseline — files are byte-identical"
else
    fail "X1 baseline — files differ"
    exit 1
fi
