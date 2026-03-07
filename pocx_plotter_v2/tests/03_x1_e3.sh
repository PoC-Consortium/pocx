#!/usr/bin/env bash
# 03_x1_e3.sh — X1 compression, 9 warps, escalate=3.
set -euo pipefail
source "$(dirname "$0")/lib.sh"

echo "=== Test 03: X1 with escalation=3 (9 warps) ==="

DIR_OLD=$(make_temp_dir)
DIR_NEW=$(make_temp_dir)
trap 'rm -rf "$DIR_OLD" "$DIR_NEW"' EXIT

run_old_plotter "$DIR_OLD" 9 1 3
run_new_plotter_seeded "$DIR_NEW" 9 1 3

OLD_FILE=$(find_plotfile "$DIR_OLD")
NEW_FILE=$(find_plotfile "$DIR_NEW")

if compare_files "$OLD_FILE" "$NEW_FILE"; then
    pass "X1 e=3 — files are byte-identical"
else
    fail "X1 e=3 — files differ"
    exit 1
fi
