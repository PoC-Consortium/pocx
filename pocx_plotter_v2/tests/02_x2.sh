#!/usr/bin/env bash
# 02_x2.sh — X2 compression, 4 warps, escalate=1.
set -euo pipefail
source "$(dirname "$0")/lib.sh"

echo "=== Test 02: X2 compression (4 warps, e=1) ==="

DIR_OLD=$(make_temp_dir)
DIR_NEW=$(make_temp_dir)
trap 'rm -rf "$DIR_OLD" "$DIR_NEW"' EXIT

run_old_plotter "$DIR_OLD" 4 2 1
run_new_plotter_seeded "$DIR_NEW" 4 2 1

OLD_FILE=$(find_plotfile "$DIR_OLD")
NEW_FILE=$(find_plotfile "$DIR_NEW")

if compare_files "$OLD_FILE" "$NEW_FILE"; then
    pass "X2 compression — files are byte-identical"
else
    fail "X2 compression — files differ"
    exit 1
fi
