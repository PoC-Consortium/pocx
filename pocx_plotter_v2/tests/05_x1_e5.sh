#!/usr/bin/env bash
# 05_x1_e5.sh — X1 compression, 9 warps, escalate=5 (partial last buffer: 9 = 5+4).
set -euo pipefail
source "$(dirname "$0")/lib.sh"

echo "=== Test 05: X1 with escalation=5 (9 warps, partial flush) ==="

DIR_OLD=$(make_temp_dir)
DIR_NEW=$(make_temp_dir)
trap 'rm -rf "$DIR_OLD" "$DIR_NEW"' EXIT

run_old_plotter "$DIR_OLD" 9 1 5
run_new_plotter_seeded "$DIR_NEW" 9 1 5

OLD_FILE=$(find_plotfile "$DIR_OLD")
NEW_FILE=$(find_plotfile "$DIR_NEW")

if compare_files "$OLD_FILE" "$NEW_FILE"; then
    pass "X1 e=5 partial flush — files are byte-identical"
else
    fail "X1 e=5 partial flush — files differ"
    exit 1
fi
